# frozen-string-literal: true

require 'fileutils'
require 'securerandom'

#
class Roda
  module RodaPlugins
    # The tus plugin implements a small subset of the tus resumable upload
    # protocol (https://tus.io), version 1.0.0.  It supports the creation
    # extension (including deferred upload lengths), HEAD requests for
    # querying the current upload offset, and PATCH requests for appending
    # request bodies at a given offset.  Upload data is stored as plain
    # files in a caller-specified temporary directory, so no database is
    # required.
    #
    # This allows applications to replace hand-rolled upload endpoints that
    # manually concatenate uploaded file chunks:
    #
    #   plugin :tus, directory: 'tmp/uploads', max_size: 1024*1024*1024
    #
    #   route do |r|
    #     r.on 'uploads' do
    #       r.tus
    #     end
    #   end
    #
    # With the above, POST /uploads creates a new upload (201 + Location),
    # HEAD /uploads/:id returns the current Upload-Offset, and
    # PATCH /uploads/:id appends the request body at the client-provided
    # Upload-Offset, returning the new offset only after the data has been
    # written to disk and fsynced.
    #
    # Concurrent PATCH requests for the same upload are serialized with a
    # file lock, and only the request whose Upload-Offset matches the
    # current offset is accepted; the others receive a 409 response.
    #
    # Uploads created with Upload-Defer-Length: 1 can have their final
    # Upload-Length confirmed once by a later PATCH request.  The
    # :max_size option is enforced both when a length is declared and
    # while streaming request bodies of deferred-length uploads.
    #
    # Request bodies are streamed to disk in chunks and are only read once;
    # they are never buffered in memory to compute lengths.
    #
    # Metadata (offset/length) is only updated after the data has been
    # written.  If the process exits between writing the data and updating
    # the metadata, the next access to the upload truncates the
    # unacknowledged data tail, so the reported offset always matches the
    # acknowledged bytes on disk.
    #
    # The plugin does not run any background cleanup.  Applications that
    # want to remove stale uploads should explicitly call
    # App.tus_expire_uploads, for example from a cron job or rake task:
    #
    #   App.tus_expire_uploads(Time.now - 24*3600) # => array of deleted ids
    #
    # Options:
    # :directory :: Required.  Directory used to store upload data and
    #               metadata files.  Created if it does not exist.
    # :max_size :: Maximum allowed upload size in bytes.  Enforced when a
    #              length is declared and while streaming deferred-length
    #              uploads.  Unlimited if not given.
    # :chunk_size :: Number of bytes read from the request body per read
    #                when streaming to disk (default 16384).
    module Tus
      # The tus protocol version implemented by this plugin.
      VERSION = '1.0.0'.freeze

      # The tus extensions supported by this plugin.
      EXTENSIONS = 'creation,creation-defer-length'.freeze

      # Error raised for tus protocol and storage failures.  The +status+
      # reader returns the HTTP status code that should be used for the
      # response.
      class Error < StandardError
        # HTTP status code for the error.
        attr_reader :status

        def initialize(status, message)
          @status = status
          super(message)
        end
      end

      # Depend on the all_verbs plugin for head/patch/options support.
      def self.load_dependencies(app, opts=OPTS)
        app.plugin :all_verbs
      end

      # Set the tus directory, max size, and chunk size.
      def self.configure(app, opts=OPTS)
        dir = opts[:directory] or
          raise RodaError, "must provide :directory option when loading the tus plugin"
        app.opts[:tus_directory] = File.expand_path(dir).freeze
        app.opts[:tus_max_size] = opts[:max_size]
        app.opts[:tus_chunk_size] = opts[:chunk_size] || 16384
        FileUtils.mkdir_p(app.opts[:tus_directory])
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :tus_directory)
        RodaPlugins.opt_attr_reader(self, :tus_max_size)
        RodaPlugins.opt_attr_reader(self, :tus_chunk_size)

        # Create a new empty upload with the given final +length+ (nil for
        # a deferred length), and return the upload id.
        def tus_create_upload(length=nil)
          id = SecureRandom.hex(16)
          File.open(_tus_data_path(id), 'wb'){}
          _tus_write_meta(id, offset: 0, length: length, created: Time.now.to_i)
          id
        end

        # Return a metadata hash (+:offset+, +:length+, +:created+) for the
        # upload with the given id, or nil if there is no such upload.
        # Reconciles the data file with the metadata before returning, so
        # the returned offset always matches the acknowledged bytes on disk.
        def tus_upload_info(id)
          _tus_with_lock(id) do
            if meta = _tus_read_meta(id)
              _tus_reconcile(id, meta)
              meta
            end
          end
        end

        # Append the request body +input+ to the upload with the given id,
        # requiring the current offset to be +offset+.  +length+ is the
        # final upload length confirmed by this request (only allowed for
        # deferred-length uploads), or :keep to leave the length unchanged.
        # Streams +input+ to disk in chunks, reading it only once, and
        # publishes the new offset in the metadata only after the data has
        # been written and fsynced.  Returns the new offset.  Raises
        # Tus::Error with an appropriate HTTP status on failure.
        def tus_append_upload(id, offset, input, length: :keep)
          _tus_with_lock(id) do
            meta = _tus_read_meta(id)
            raise Error.new(404, 'upload not found') unless meta
            _tus_reconcile(id, meta)

            if meta[:length] && meta[:offset] >= meta[:length]
              raise Error.new(409, 'upload is already complete')
            end
            unless offset == meta[:offset]
              raise Error.new(409, "incorrect Upload-Offset, current offset is #{meta[:offset]}")
            end

            unless length == :keep
              raise Error.new(400, 'Upload-Length has already been set') if meta[:length]
              if tus_max_size && length > tus_max_size
                raise Error.new(413, 'Upload-Length exceeds maximum upload size')
              end
              if length < meta[:offset]
                raise Error.new(400, 'Upload-Length is smaller than the current offset')
              end
              meta[:length] = length
            end

            cap = meta[:length] || tus_max_size
            remaining = cap - meta[:offset] if cap

            written = 0
            data_path = _tus_data_path(id)
            begin
              File.open(data_path, 'ab') do |f|
                while (chunk = input.read(tus_chunk_size)) && !chunk.empty?
                  written += chunk.bytesize
                  if remaining && written > remaining
                    raise Error.new(413, 'upload exceeds maximum upload length')
                  end
                  f.write(chunk)
                end
                f.fsync
              end
            rescue Exception
              # The metadata still holds the old offset, so truncate the
              # unacknowledged data to keep the disk consistent with it.
              File.truncate(data_path, meta[:offset]) if File.exist?(data_path)
              raise
            end

            meta[:offset] += written
            _tus_write_meta(id, meta)
            meta[:offset]
          end
        end

        # Delete all files for the upload with the given id.  Returns true
        # if an upload was deleted, false otherwise.
        def tus_delete_upload(id)
          return false unless File.exist?(_tus_meta_path(id))
          File.unlink(_tus_data_path(id)) if File.exist?(_tus_data_path(id))
          File.unlink(_tus_meta_path(id))
          File.unlink(_tus_lock_path(id)) if File.exist?(_tus_lock_path(id))
          true
        end

        # Delete all uploads created before the given time (default: 24
        # hours ago), and return an array of the deleted upload ids.  This
        # is never called automatically; applications should call it
        # explicitly when they want to remove stale uploads.
        def tus_expire_uploads(before=(Time.now - 86400))
          deleted = []
          Dir.glob(File.join(tus_directory, '*.meta')).each do |meta_path|
            id = File.basename(meta_path, '.meta')
            next unless id =~ /\A[0-9a-f]{32}\z/
            _tus_with_lock(id) do
              meta = _tus_read_meta(id)
              if meta && meta[:created] < before.to_i
                tus_delete_upload(id)
                deleted << id
              end
            end
          end
          deleted
        end

        private

        def _tus_data_path(id)
          File.join(tus_directory, id)
        end

        def _tus_meta_path(id)
          "#{_tus_data_path(id)}.meta"
        end

        def _tus_lock_path(id)
          "#{_tus_data_path(id)}.lock"
        end

        # Serialize access to the upload with the given id using an
        # exclusive file lock, so concurrent requests cannot both append
        # at the same offset.
        def _tus_with_lock(id)
          File.open(_tus_lock_path(id), File::RDWR|File::CREAT, 0644) do |f|
            f.flock(File::LOCK_EX)
            yield
          end
        end

        def _tus_read_meta(id)
          path = _tus_meta_path(id)
          return unless File.file?(path)
          meta = {}
          File.foreach(path) do |line|
            key, value = line.chomp.split(' ', 2)
            meta[key] = value
          end
          {
            offset: meta['offset'].to_i,
            length: meta['length'] == '-' ? nil : meta['length'].to_i,
            created: meta['created'].to_i
          }
        end

        # Write the metadata atomically via a temporary file and rename, so
        # a crash cannot leave a partially written metadata file.
        def _tus_write_meta(id, meta)
          tmp = "#{_tus_meta_path(id)}.#{Process.pid}.tmp"
          File.open(tmp, 'w') do |f|
            f << "offset #{meta[:offset]}\n"
            f << "length #{meta[:length] || '-'}\n"
            f << "created #{meta[:created]}\n"
            f.fsync
          end
          File.rename(tmp, _tus_meta_path(id))
        end

        # Reconcile the data file with the metadata after a potential
        # crash between writing data and updating the metadata.  Data
        # beyond the acknowledged offset was never published, so truncate
        # it.  If the metadata is ahead of the data file, lower the offset
        # to the actual data size so the client can resume from there.
        def _tus_reconcile(id, meta)
          data_path = _tus_data_path(id)
          size = File.exist?(data_path) ? File.size(data_path) : 0
          if size > meta[:offset]
            File.truncate(data_path, meta[:offset])
          elsif size < meta[:offset]
            meta[:offset] = size
            _tus_write_meta(id, meta)
          end
        end
      end

      module RequestMethods
        # Handle a tus protocol request.  This always halts with a
        # response, so it should be called at the point in the route where
        # the tus endpoint is mounted:
        #
        #   r.on 'uploads' do
        #     r.tus
        #   end
        def tus
          if options?
            headers = {
              'Tus-Resumable'=>Tus::VERSION,
              'Tus-Version'=>Tus::VERSION,
              'Tus-Extension'=>Tus::EXTENSIONS
            }
            if max_size = scope.class.tus_max_size
              headers['Tus-Max-Size'] = max_size.to_s
            end
            _tus_halt(204, headers)
          end

          unless env['HTTP_TUS_RESUMABLE'] == Tus::VERSION
            _tus_halt(412, {'Tus-Version'=>Tus::VERSION})
          end

          if post?
            length = _tus_creation_length
            id = scope.class.tus_create_upload(length)
            _tus_halt(201, {'Location'=>"#{path}/#{id}"})
          end

          is String do |id|
            _tus_halt(404) unless id =~ /\A[0-9a-f]{32}\z/

            if head?
              meta = scope.class.tus_upload_info(id)
              _tus_halt(404) unless meta
              headers = {
                'Upload-Offset'=>meta[:offset].to_s,
                'Cache-Control'=>'no-store'
              }
              if meta[:length]
                headers['Upload-Length'] = meta[:length].to_s
              else
                headers['Upload-Defer-Length'] = '1'
              end
              _tus_halt(200, headers)
            elsif patch?
              unless env['CONTENT_TYPE'] == 'application/offset+octet-stream'
                _tus_halt(415)
              end
              offset = _tus_parse_non_negative_integer(env['HTTP_UPLOAD_OFFSET'])
              _tus_halt(400) unless offset
              length = :keep
              if upload_length = env['HTTP_UPLOAD_LENGTH']
                length = _tus_parse_non_negative_integer(upload_length)
                _tus_halt(400) unless length
              end
              begin
                new_offset = scope.class.tus_append_upload(id, offset, env['rack.input'], length: length)
              rescue Tus::Error => e
                _tus_halt(e.status, {}, e.message)
              end
              _tus_halt(204, {'Upload-Offset'=>new_offset.to_s})
            else
              _tus_halt(405)
            end
          end

          _tus_halt(404)
        end

        private

        # Parse and validate the Upload-Length/Upload-Defer-Length headers
        # for a creation request, halting with an error response if they
        # are invalid.  Returns the upload length, or nil if the length is
        # deferred.
        def _tus_creation_length
          if upload_length = env['HTTP_UPLOAD_LENGTH']
            length = _tus_parse_non_negative_integer(upload_length)
            _tus_halt(400) unless length
            if (max_size = scope.class.tus_max_size) && length > max_size
              _tus_halt(413)
            end
            length
          elsif env['HTTP_UPLOAD_DEFER_LENGTH'] == '1'
            nil
          else
            _tus_halt(400)
          end
        end

        def _tus_parse_non_negative_integer(string)
          string.to_i if string =~ /\A\d+\z/
        end

        # Halt with a response using the given status and headers, adding
        # the Tus-Resumable header required by the protocol.
        def _tus_halt(status, headers={}, body=nil)
          res = response
          res.status = status
          res['Tus-Resumable'] = Tus::VERSION
          headers.each{|k, v| res[k] = v}
          res.write(body) if body
          halt
        end
      end
    end

    register_plugin(:tus, Tus)
  end
end
