# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'securerandom'
class Roda
  module RodaPlugins
    # The tus plugin implements a small subset of the tus 1.0.0 protocol for
    # resumable uploads: creation, HEAD requests, and PATCH requests that
    # continue at the client-provided offset.  Upload bytes and metadata are
    # stored on disk in the caller-provided temporary directory.
    #
    # Configure the plugin with a directory and optional maximum upload size:
    #
    #   plugin :tus, dir: '/path/to/tmp/uploads', max_size: 100 * 1024 * 1024
    #
    # Add the request methods to the routes that should replace a manual file
    # concatenation endpoint:
    #
    #   route do |r|
    #     r.post('uploads') { r.tus_upload }
    #     r.is('uploads', String) do |id|
    #       r.tus_upload(id)
    #     end
    #   end
    #
    # Uploads with unknown final length are created with Upload-Defer-Length: 1.
    # Their final Upload-Length is supplied on a later PATCH request.  The
    # plugin never buffers a request body to calculate its length; request
    # input is copied directly to disk in chunks.
    #
    # Expired uploads are not removed automatically.  The application calls
    # the application's +tus_cleanup_expired+ class method when cleanup should
    # run, either with the configured +expires_in+ value or with an explicit
    # interval:
    #
    #   App.tus_cleanup_expired
    #   App.tus_cleanup_expired(24 * 60 * 60)
    module Tus
      TUS_VERSION = '1.0.0'.freeze
      CONTENT_TYPE = 'application/offset+octet-stream'.freeze
      CHUNK_SIZE = 65536
      ID_FORMAT = /\A[0-9a-f]{64}\z/
      HEADERS = if Rack.release >= '3'
        {
          tus_resumable: 'tus-resumable',
          cache_control: 'cache-control',
          upload_length: 'upload-length',
          upload_defer_length: 'upload-defer-length',
          upload_offset: 'upload-offset',
          location: 'location',
        }.freeze
      else
        {
          tus_resumable: 'Tus-Resumable',
          cache_control: 'Cache-Control',
          upload_length: 'Upload-Length',
          upload_defer_length: 'Upload-Defer-Length',
          upload_offset: 'Upload-Offset',
          location: 'Location',
        }.freeze
      end

      # File-backed tus storage. Each upload gets a directory containing the
      # upload data, metadata, and an advisory lock.
      class FileStorage
        class UploadError < StandardError
          attr_reader :status, :offset

          def initialize(status, offset = nil)
            @status = status
            @offset = offset
            super("tus upload error: #{status}")
          end
        end

        def initialize(directory, max_size: nil, expires_in: nil)
          @directory = File.expand_path(directory)
          @max_size = max_size
          @expires_in = expires_in
          FileUtils.mkdir_p(@directory)
        end

        def create(length)
          raise UploadError.new(413) if @max_size && length && length > @max_size

          id = nil
          directory = nil

          loop do
            id = SecureRandom.hex(32)
            directory = upload_directory(id)
            break if Dir.mkdir(directory, 0700)
          end

          File.open(File.join(directory, 'data'), File::RDWR | File::CREAT | File::EXCL, 0600) {}
          metadata = {'offset' => 0, 'length' => length, 'created_at' => Time.now.to_f}
          write_metadata(id, metadata)
          [id, metadata]
        rescue Errno::EEXIST
          retry
        end

        def head(id)
          with_upload(id) do |metadata, data|
            reconcile_data!(metadata, data)
            metadata.dup
          end
        end

        def patch(id, requested_offset, content_length, final_length, input)
          with_upload(id) do |metadata, data|
            current_offset = metadata.fetch('offset')
            current_length = metadata['length']
            if final_length
              if current_length
                raise UploadError.new(409, current_offset) unless current_length == final_length
              else
                raise UploadError.new(409, current_offset) if requested_offset > final_length
                raise UploadError.new(413, current_offset) if @max_size && final_length > @max_size
                metadata['length'] = final_length
              end
            end

            raise UploadError.new(413, current_offset) if @max_size && current_length && current_length > @max_size

            effective_length = current_length || final_length
            reconcile_data!(metadata, data)

            unless current_offset == requested_offset
              raise UploadError.new(409, current_offset)
            end

            remaining_length = if effective_length
              raise UploadError.new(409, current_offset) if requested_offset > effective_length
              effective_length - requested_offset
            elsif @max_size
              raise UploadError.new(413, current_offset) if requested_offset > @max_size
              @max_size - requested_offset
            end

            raise UploadError.new(413, current_offset) if content_length && remaining_length && content_length > remaining_length

            data.seek(current_offset)
            begin
              written = copy_input(input, data, content_length, remaining_length)
              data.flush
              data.fsync

              new_offset = current_offset + written
              metadata['offset'] = new_offset
              commit_upload(id, metadata)
              new_offset
            rescue StandardError
              data.truncate(current_offset)
              raise
            end
          end
        end

        def cleanup_expired(ttl = nil)
          ttl ||= @expires_in
          raise ArgumentError, "an expiration interval is required for tus cleanup" unless ttl

          cutoff = Time.now - ttl
          deleted = []

          Dir.children(@directory).sort.each do |id|
            next unless id =~ ID_FORMAT
            next unless File.directory?(upload_directory(id))

            File.open(lock_path(id), File::RDONLY | File::CREAT, 0600) do |lock|
              lock.flock(File::LOCK_EX)
              metadata = read_metadata(id)
              next unless metadata && metadata['created_at']
              next unless Time.at(metadata['created_at']) <= cutoff

              FileUtils.remove_entry(upload_directory(id), true)
              deleted << id
            end
          rescue Errno::ENOENT, JSON::ParserError, TypeError, ArgumentError
            next
          end

          deleted
        end

        protected

        def commit_upload(id, metadata)
          write_metadata(id, metadata)
        end

        private

        def with_upload(id)
          raise UploadError.new(404) unless id =~ ID_FORMAT
          raise UploadError.new(404) unless File.directory?(upload_directory(id))

          File.open(lock_path(id), File::RDONLY | File::CREAT, 0600) do |lock|
            lock.flock(File::LOCK_EX)
            metadata = read_metadata(id)
            raise UploadError.new(404) unless metadata

            File.open(data_path(id), 'r+b') do |data|
              yield metadata, data
            end
          end
        rescue Errno::ENOENT
          raise UploadError.new(404)
        end

        def copy_input(input, output, content_length, remaining_length)
          written = 0

          loop do
            break if content_length && written == content_length
            break if remaining_length && remaining_length == 0

            limit = CHUNK_SIZE
            limit = content_length - written if content_length
            limit = remaining_length if remaining_length && limit > remaining_length
            chunk = input.read(limit)
            break if chunk.nil? || chunk.empty?

            chunk.force_encoding(Encoding::BINARY)
            output.write(chunk)
            written += chunk.bytesize
            remaining_length -= chunk.bytesize if remaining_length
          end

          if remaining_length == 0 && input.read(1)
            raise UploadError.new(413)
          end

          if content_length && written != content_length
            raise UploadError.new(400)
          end

          written
        end

        def reconcile_data!(metadata, data)
          offset = metadata.fetch('offset')
          size = data.size
          raise UploadError.new(409, offset) if size < offset
          if size > offset
            data.truncate(offset)
            data.flush
            data.fsync
          end
        end

        def read_metadata(id)
          JSON.parse(File.binread(metadata_path(id)))
        rescue Errno::ENOENT
          nil
        end

        def write_metadata(id, metadata)
          directory = upload_directory(id)
          temporary_path = File.join(directory, ".metadata.#{SecureRandom.hex(16)}.tmp")

          File.open(temporary_path, File::WRONLY | File::CREAT | File::EXCL, 0600) do |file|
            file.write(JSON.generate(metadata))
            file.flush
            file.fsync
          end

          File.rename(temporary_path, metadata_path(id))
          File.open(metadata_path(id)) { |file| file.fsync }
          fsync_directory(directory)
        end

        def fsync_directory(path)
          File.open(path) { |file| file.fsync }
        rescue SystemCallError
          nil
        end

        def upload_directory(id)
          File.join(@directory, id)
        end

        def data_path(id)
          File.join(upload_directory(id), 'data')
        end

        def metadata_path(id)
          File.join(upload_directory(id), 'metadata')
        end

        def lock_path(id)
          File.join(upload_directory(id), 'lock')
        end
      end

      def self.configure(app, opts=OPTS)
        storage = opts[:storage]
        unless storage
          raise RodaError, 'the tus plugin requires a :dir option' unless opts[:dir]
          storage = FileStorage.new(
            opts[:dir],
            max_size: opts[:max_size],
            expires_in: opts[:expires_in]
          )
        end

        app.opts[:tus_storage] = storage
      end

      module ClassMethods
        def tus_cleanup_expired(ttl=nil)
          opts[:tus_storage].cleanup_expired(ttl)
        end
      end

      module RequestMethods
        def tus_upload(id=nil)
          case env['REQUEST_METHOD']
          when 'POST'
            tus_create
          when 'HEAD'
            tus_head(id)
          when 'PATCH'
            tus_patch(id)
          else
            tus_halt(405)
          end
        rescue FileStorage::UploadError => error
          tus_halt(error.status, error.offset)
        end

        private

        def tus_create
          tus_require_version!
          length_header = tus_header('Upload-Length')
          deferred = tus_header('Upload-Defer-Length')

          if deferred
            tus_halt(400) unless deferred == '1' && !length_header
            length = nil
          else
            tus_halt(400) unless length_header
            length = tus_integer_header!('Upload-Length')
          end

          id, metadata = roda_class.opts[:tus_storage].create(length)
          tus_halt(201, metadata['offset'], tus_common_headers.merge!(HEADERS[:location] => tus_location(id)))
        end

        def tus_head(id)
          tus_require_version!
          tus_valid_id!(id)
          metadata = roda_class.opts[:tus_storage].head(id)
          headers = tus_common_headers
          headers[HEADERS[:upload_offset]] = metadata.fetch('offset').to_s
          if metadata['length']
            headers[HEADERS[:upload_length]] = metadata['length'].to_s
          else
            headers[HEADERS[:upload_defer_length]] = '1'
          end
          tus_halt(200, nil, headers)
        end

        def tus_patch(id)
          tus_require_version!
          tus_valid_id!(id)
          tus_halt(412) unless env['CONTENT_TYPE'] == CONTENT_TYPE

          offset = tus_integer_header!('Upload-Offset')
          final_length = if tus_header('Upload-Length')
            tus_integer_header!('Upload-Length')
          end
          content_length = if env['CONTENT_LENGTH'] && !env['CONTENT_LENGTH'].empty?
            tus_integer_header!('CONTENT-LENGTH', 'CONTENT_LENGTH')
          end
          input = env['rack.input']
          tus_halt(400) unless input

          new_offset = roda_class.opts[:tus_storage].patch(
            id, offset, content_length, final_length, input
          )
          tus_halt(204, new_offset)
        end

        def tus_require_version!
          tus_halt(412) unless tus_header('Tus-Resumable') == TUS_VERSION
        end

        def tus_integer_header!(name, rack_name = nil)
          value = rack_name ? env[rack_name] : tus_header(name)
          tus_halt(400) unless value && value =~ /\A\d+\z/
          Integer(value, 10)
        end

        def tus_header(name)
          env["HTTP_#{name.upcase.gsub('-', '_')}"]
        end

        def tus_valid_id!(id)
          tus_halt(404) unless id && id =~ ID_FORMAT
        end

        def tus_common_headers
          {
            HEADERS[:tus_resumable] => TUS_VERSION,
            HEADERS[:cache_control] => 'no-store',
          }
        end

        def tus_halt(status, offset=nil, headers=tus_common_headers)
          headers[HEADERS[:upload_offset]] = offset.to_s unless offset.nil?
          halt [status, headers, []]
        end

        def tus_location(id)
          prefix = matched_path
          prefix = nil if prefix == '/'
          location = [prefix, id].compact.join('/')
          location = "/#{location}" unless location.start_with?('/')
          location
        end
      end
    end

    register_plugin(:tus, Tus)
  end
end
