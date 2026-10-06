# frozen_string_literal: true

require "securerandom"
require "strscan"
require "uri"

class Roda
  module RodaPlugins
    # The webdav_lock plugin implements a small exclusive WebDAV write-lock
    # layer. Resource storage and lock storage are injected, so the plugin does
    # not depend on a filesystem, database, or external WebDAV service.
    #
    # The lock store must respond to:
    #
    # * active_locks(path, time) :: direct locks on path and active ancestor
    #   infinity locks
    # * active_descendant_locks(path, time) :: active locks rooted at path or
    #   below it
    # * active_lock_for_token(token, time) :: the active lock for a token
    # * create_lock(lock, time) :: create a lock, raising WebdavLock::Conflict
    #   for a conflicting lock
    # * refresh_lock(path, token, expires_at, time) :: refresh the exact lock
    # * unlock_lock(path, token) :: remove and return the exact lock
    #
    # The resource store must respond to exists?(path), etag_for(path), and
    # move(source, destination, overwrite). The move method must be atomic: a
    # falsey return must leave the resource tree unchanged.
    #
    # Possessing a token is only treated as permission to write to a resource
    # covered by that token. A token never grants permission to write unrelated
    # resources.
    module WebdavLock
      DEFAULT_TIMEOUT = 300

      # Raised by a lock store when create_lock finds a conflicting lock.
      class Conflict < StandardError; end

      class MalformedConditionHeader < StandardError; end
      class ExternalConditionUri < StandardError; end

      def self.load_dependencies(app, _opts=OPTS)
        app.plugin :all_verbs
      end

      def self.configure(app, opts=OPTS)
        app.opts[:webdav_lock_resource_store] = opts[:resource_store] if opts.key?(:resource_store)
        app.opts[:webdav_lock_lock_store] = opts[:lock_store] if opts.key?(:lock_store)
        app.opts[:webdav_lock_clock] = opts[:clock] if opts.key?(:clock)
        app.opts[:webdav_lock_default_timeout] = opts[:default_timeout] if opts.key?(:default_timeout)
        app.opts[:webdav_lock_token_generator] = opts[:token_generator] if opts.key?(:token_generator)

        unless app.opts[:webdav_lock_resource_store]
          raise RodaError, "webdav_lock plugin requires :resource_store"
        end
        unless app.opts[:webdav_lock_lock_store]
          raise RodaError, "webdav_lock plugin requires :lock_store"
        end

        app.opts[:webdav_lock_clock] ||= proc { Time.now }
        app.opts[:webdav_lock_default_timeout] ||= DEFAULT_TIMEOUT
        app.opts[:webdav_lock_token_generator] ||= proc { "opaquelocktoken:#{SecureRandom.uuid}" }
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :webdav_lock_resource_store)
        RodaPlugins.opt_attr_reader(self, :webdav_lock_lock_store)
        RodaPlugins.opt_attr_reader(self, :webdav_lock_clock)
        RodaPlugins.opt_attr_reader(self, :webdav_lock_default_timeout)
        RodaPlugins.opt_attr_reader(self, :webdav_lock_token_generator)
      end

      module RequestMethods
        # Route LOCK requests and create or refresh an exclusive write lock.
        def lock(*args, &block)
          return unless webdav_request_method?("LOCK")
          if args.empty?
            always { block ? block.call : webdav_lock_request }
          else
            args << TERM
            if_match(args) { block ? block.call : webdav_lock_request }
          end
        end

        # Route MOVE requests after verifying source, destination, descendant,
        # and ancestor locks. The resource backend is called only after every
        # lock check succeeds.
        def move(*args, &block)
          return unless webdav_request_method?("MOVE")
          if args.empty?
            always { block ? block.call : webdav_move_request }
          else
            args << TERM
            if_match(args) { block ? block.call : webdav_move_request }
          end
        end

        # Route UNLOCK requests.
        def unlock(*args, &block)
          return unless webdav_request_method?("UNLOCK")
          if args.empty?
            always { block ? block.call : webdav_unlock_request }
          else
            args << TERM
            if_match(args) { block ? block.call : webdav_unlock_request }
          end
        end

        # Verify locks and If conditions for PUT or a similar single-resource
        # write handler.
        def webdav_authorize_write!(path=webdav_request_path)
          webdav_authorize_locks!(webdav_active_locks(path), path)
        end

        # Verify locks and If conditions for DELETE on a resource or an entire
        # collection subtree.
        def webdav_authorize_delete!(path=webdav_request_path)
          locks = webdav_active_locks(path) + webdav_active_descendant_locks(path)
          webdav_authorize_locks!(locks.uniq { |lock| lock[:token] }, path, true)
        end

        # Verify all locks involved in MOVE without invoking the resource
        # backend. Use #move for the complete MOVE operation.
        def webdav_authorize_move!(source=webdav_request_path, destination=webdav_destination_path)
          begin
            lists = webdav_parse_if_header
          rescue MalformedConditionHeader, ExternalConditionUri
            halt [400, {}, []]
          end

          source_locks = (webdav_active_locks(source) + webdav_active_descendant_locks(source)).uniq { |lock| lock[:token] }
          destination_locks = webdav_active_locks(destination)
          if webdav_resource_store.exists?(destination)
            destination_locks.concat(webdav_active_descendant_locks(destination))
          end
          destination_locks.uniq! { |lock| lock[:token] }

          if lists.nil?
            halt [423, {}, []] unless source_locks.empty? && destination_locks.empty?
            return
          end

          webdav_authorize_side_locks!(source_locks, lists, source, true)
          webdav_authorize_side_locks!(destination_locks, lists, destination, false)
        end

        private

        def webdav_request_method?(method)
          @env["REQUEST_METHOD"] == method
        end

        def webdav_request_path
          webdav_normalize_path(@env["PATH_INFO"])
        end

        def webdav_normalize_path(path)
          path = Rack::Utils.unescape_path(path.to_s)
          path == "/" ? path : path.chomp("/")
        end

        def webdav_path_contains?(parent, path)
          parent == path || path.start_with?("#{parent}/")
        end

        def webdav_paths_overlap?(first, second)
          webdav_path_contains?(first, second) || webdav_path_contains?(second, first)
        end

        def webdav_current_time
          roda_class.webdav_lock_clock.call
        end

        def webdav_default_timeout
          roda_class.webdav_lock_default_timeout
        end

        def webdav_generate_token
          roda_class.webdav_lock_token_generator.call
        end

        def webdav_lock_store
          roda_class.webdav_lock_lock_store
        end

        def webdav_resource_store
          roda_class.webdav_lock_resource_store
        end

        def webdav_active_locks(path)
          webdav_lock_store.active_locks(path, webdav_current_time)
        end

        def webdav_active_descendant_locks(path)
          webdav_lock_store.active_descendant_locks(path, webdav_current_time)
        end

        def webdav_lock_request
          path = webdav_request_path
          halt [404, {}, []] unless webdav_resource_store.exists?(path)

          body = webdav_read_request_body
          if body.empty?
            webdav_refresh_lock(path)
          else
            webdav_create_lock(path, body)
          end
        end

        def webdav_unlock_request
          token = @env["HTTP_LOCK_TOKEN"].to_s
          match = token.match(/\A<([^>]*)>\z/)
          halt [400, {}, []] unless match
          token = match[1]

          unless webdav_lock_store.unlock_lock(webdav_request_path, token)
            halt [409, {}, []]
          end
          response.status = 204
          nil
        end

        def webdav_move_request
          source = webdav_request_path
          destination = webdav_destination_path
          overwrite = webdav_overwrite_allowed?

          halt [404, {}, []] unless webdav_resource_store.exists?(source)
          halt [400, {}, []] if destination.nil?
          halt [403, {}, []] if source == destination || webdav_path_contains?(source, destination)

          destination_existed = webdav_resource_store.exists?(destination)
          if destination_existed && !overwrite
            halt [412, {}, []]
          end

          webdav_authorize_move!(source, destination)
          unless webdav_resource_store.move(source, destination, overwrite)
            halt [409, {}, []]
          end

          response.status = destination_existed ? 204 : 201
          nil
        end

        def webdav_create_lock(path, body)
          depth = webdav_lock_depth
          timeout = webdav_parse_timeout
          info = webdav_parse_lock_info(body)
          locks = webdav_active_locks(path)
          if depth == "infinity"
            locks.concat(webdav_active_descendant_locks(path))
          end
          webdav_authorize_locks!(locks.uniq { |lock| lock[:token] }, path)

          now = webdav_current_time
          lock = {
            :path => path,
            :token => webdav_generate_token,
            :depth => depth,
            :scope => info[:scope],
            :owner => info[:owner],
            :created_at => now,
            :expires_at => timeout ? now + timeout : nil
          }

          begin
            webdav_lock_store.create_lock(lock, now)
          rescue Conflict
            halt [423, {}, []]
          end

          response.status = 200
          webdav_lock_response(lock)
        end

        def webdav_refresh_lock(path)
          begin
            lists = webdav_parse_if_header
          rescue MalformedConditionHeader, ExternalConditionUri
            halt [400, {}, []]
          end
          halt [412, {}, []] if lists.nil? || lists.empty?

          token = nil
          lists.each do |list|
            list.each do |negative, type, value, tag|
              next if negative || type != :token || tag != nil
              stored = webdav_lock_store.active_lock_for_token(value, webdav_current_time)
              if stored && stored[:path] == path
                token = value
                break
              end
            end
            break if token
          end
          halt [412, {}, []] unless token

          now = webdav_current_time
          timeout = webdav_parse_timeout
          lock = webdav_lock_store.refresh_lock(path, token, timeout ? now + timeout : nil, now)
          halt [412, {}, []] unless lock
          response.status = 200
          webdav_lock_response(lock)
        end

        def webdav_lock_depth
          depth = @env["HTTP_DEPTH"]
          return "infinity" if depth.nil?
          depth = depth.strip.downcase
          halt [400, {}, []] unless depth == "0" || depth == "infinity"
          depth
        end

        def webdav_parse_timeout
          value = @env["HTTP_TIMEOUT"]
          return webdav_default_timeout if value.nil?
          value.split(",").each do |item|
            item = item.strip
            return nil if item.downcase == "infinite"
            if item =~ /\Asecond-(\d+)\z/i
              seconds = $1.to_i
              halt [400, {}, []] if seconds.zero?
              return seconds
            end
          end
          webdav_default_timeout
        end

        def webdav_parse_lock_info(body)
          scope_match = body.match(/<(?:[\w.-]+:)?lockscope\b[^>]*>\s*<(?:[\w.-]+:)?(exclusive|shared)\b/i)
          scope = scope_match ? scope_match[1].downcase : "exclusive"
          halt [400, {}, []] unless scope == "exclusive" || scope == "shared"
          { :scope => scope, :owner => webdav_parse_owner(body) }
        end

        def webdav_parse_owner(body)
          match = body.match(/<(?:[\w.-]+:)?owner\b[^>]*>(.*?)<\/(?:[\w.-]+:)?owner\s*>/im)
          return unless match
          owner = match[1].gsub(/<[^>]*>/m, " ").strip.gsub(/\s+/, " ")
          webdav_xml_unescape(owner)
        end

        def webdav_lock_response(lock)
          expires = lock[:expires_at]
          timeout = expires ? "Second-#{(expires - lock[:created_at]).to_i}" : "Infinite"
          response["Lock-Token"] = "<#{lock[:token]}>"
          response["Content-Type"] = "application/xml; charset=utf-8"
          response.write([
            %(<?xml version="1.0" encoding="utf-8" ?>),
            %(<D:prop xmlns:D="DAV:">),
            %(<D:lockdiscovery><D:activelock>),
            %(<D:locktype><D:write/></D:locktype>),
            %(<D:lockscope><D:#{lock[:scope]}/></D:lockscope>),
            %(<D:depth>#{lock[:depth]}</D:depth>),
            %(<D:owner>#{webdav_xml_escape(lock[:owner].to_s)}</D:owner>),
            %(<D:timeout>#{timeout}</D:timeout>),
            %(<D:locktoken><D:href>#{webdav_xml_escape(lock[:token])}</D:href></D:locktoken>),
            %(<D:lockroot><D:href>#{webdav_xml_escape(lock[:path])}</D:href></D:lockroot>),
            %(</D:activelock></D:lockdiscovery></D:prop>)
          ].join("\n"))
          nil
        end

        def webdav_xml_escape(value)
          value.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
        end

        def webdav_xml_unescape(value)
          value.gsub("&lt;", "<").gsub("&gt;", ">").gsub("&quot;", '"').gsub("&apos;", "'").gsub("&amp;", "&")
        end

        def webdav_read_request_body
          input = @env["rack.input"]
          return "" unless input
          input.rewind if input.respond_to?(:rewind)
          body = input.read.to_s
          input.rewind if input.respond_to?(:rewind)
          body
        end

        def webdav_destination_path
          value = @env["HTTP_DESTINATION"]
          return if value.nil? || value.strip.empty?
          uri = URI.parse(value)
          if uri.host
            same_origin = uri.scheme == scheme && uri.host == host && webdav_uri_port(uri) == port
            return unless same_origin
          end
          return if uri.path.to_s.empty?
          webdav_normalize_path(uri.path)
        rescue URI::InvalidURIError
          nil
        end

        def webdav_overwrite_allowed?
          value = @env["HTTP_OVERWRITE"]
          value.nil? || value.strip.upcase != "F"
        end

        def webdav_authorize_locks!(locks, root, subtree=false)
          begin
            lists = webdav_parse_if_header
          rescue MalformedConditionHeader, ExternalConditionUri
            halt [400, {}, []]
          end

          if lists.nil?
            halt [423, {}, []] unless locks.empty?
            return
          end

          unless locks.all? { |lock| webdav_single_resource_lock_token_listed?(lock, lists, root, subtree) }
            halt [423, {}, []]
          end

          unless lists.any? { |list| webdav_single_condition_list_matches?(list, root, subtree) }
            halt [412, {}, []]
          end
        end

        def webdav_authorize_side_locks!(locks, lists, side_root, untagged_allowed)
          unless lists.any? { |list| webdav_move_condition_list_matches?(list, side_root) }
            halt [412, {}, []]
          end

          unless locks.all? { |lock| webdav_move_lock_token_listed?(lock, lists, side_root, untagged_allowed) }
            halt [423, {}, []]
          end
        end

        def webdav_move_condition_list_matches?(list, side_root)
          list.all? do |negative, type, value, tag|
            next true if tag.nil?
            tag_path = tag || side_root
            relevant = tag_path == side_root || tag_path.start_with?("#{side_root}/") || side_root.start_with?("#{tag_path}/")
            next true unless relevant

            if type == :etag
              etag = webdav_resource_store.etag_for(tag_path)
              next negative ? etag != value : etag == value
            end

            stored = webdav_lock_store.active_lock_for_token(value, webdav_current_time)
            active = stored && (webdav_path_contains?(stored[:path], tag_path) ||
              (tag_path == side_root && webdav_path_contains?(stored[:path], side_root)))
            negative ? !active : active
          end
        end

        def webdav_move_lock_token_listed?(lock, lists, side_root, untagged_allowed)
          lists.any? do |list|
            list.any? do |negative, type, value, tag|
              next false if negative || type != :token || value != lock[:token]
              tag_path = tag
              next false if tag_path.nil? && !untagged_allowed
              tag_path ||= side_root
              if untagged_allowed
                next false unless webdav_paths_overlap?(tag_path, side_root)
              else
                next false unless tag_path == side_root || tag_path.start_with?("#{side_root}/") || side_root.start_with?("#{tag_path}/")
              end
              stored = webdav_lock_store.active_lock_for_token(value, webdav_current_time)
              stored && stored[:path] == lock[:path] &&
                (untagged_allowed ? webdav_path_contains?(side_root, tag_path) || webdav_path_contains?(tag_path, side_root) :
                  (webdav_path_contains?(lock[:path], tag_path) ||
                    (tag_path == side_root && webdav_path_contains?(lock[:path], side_root))))
            end
          end
        end

        def webdav_single_resource_lock_token_listed?(lock, lists, root, subtree)
          lists.any? do |list|
            list.any? do |negative, type, value, tag|
              next false if negative || type != :token || value != lock[:token]
              tag_path = tag || root
              next false unless subtree ? webdav_paths_overlap?(tag_path, root) : webdav_path_contains?(root, tag_path)
              stored = webdav_lock_store.active_lock_for_token(value, webdav_current_time)
              stored && stored[:path] == lock[:path] &&
                (webdav_path_contains?(stored[:path], tag_path) ||
                  (tag_path == root && webdav_path_contains?(root, stored[:path])))
            end
          end
        end

        def webdav_single_condition_list_matches?(list, root, subtree)
          list.all? do |negative, type, value, tag|
            tag_path = tag || root
            relevant = webdav_paths_overlap?(tag_path, root)
            next true if tag && !relevant

            if type == :etag
              etag = webdav_resource_store.etag_for(tag_path)
              next negative ? etag != value : etag == value
            end

            stored = webdav_lock_store.active_lock_for_token(value, webdav_current_time)
            active = stored &&
              (webdav_path_contains?(stored[:path], tag_path) ||
                (subtree && tag_path == root && webdav_path_contains?(root, stored[:path])))
            negative ? !active : active
          end
        end

        def webdav_parse_if_header
          value = @env["HTTP_IF"]
          return if value.nil?
          raise MalformedConditionHeader if value.strip.empty?

          scanner = StringScanner.new(value)
          lists = []
          until scanner.eos?
            scanner.skip(/\s+/)
            break if scanner.eos?

            tag = nil
            if scanner.scan(/<([^>]*)>\s*\(/)
              tag = webdav_parse_condition_uri(scanner[1])
            elsif scanner.scan(/\(/)
            else
              raise MalformedConditionHeader
            end

            conditions = []
            loop do
              scanner.skip(/\s+/)
              if scanner.scan(/\)/)
                break
              elsif scanner.eos?
                raise MalformedConditionHeader
              end

              negative = !scanner.scan(/not\s+/i).nil?
              weak = !scanner.scan(/W\//i).nil?
              if scanner.scan(/"((?:\\.|[^"])*)"/)
                etag = "\"#{scanner[1]}\""
                etag = "W/#{etag}" if weak
                conditions << [negative, :etag, etag, tag]
              elsif !weak && scanner.scan(/<([^>]*)>/)
                conditions << [negative, :token, scanner[1], tag]
              else
                raise MalformedConditionHeader
              end
            end

            raise MalformedConditionHeader if conditions.empty?
            lists << conditions
          end

          raise MalformedConditionHeader if lists.empty?
          lists
        end

        def webdav_parse_condition_uri(value)
          uri = URI.parse(value)
          if uri.host
            same_origin = uri.scheme == scheme &&
              uri.host == host &&
              webdav_uri_port(uri) == port
            raise ExternalConditionUri unless same_origin
          end
          path = uri.path.to_s
          raise MalformedConditionHeader if path.empty?
          webdav_normalize_path(path)
        rescue URI::InvalidURIError
          raise MalformedConditionHeader
        end

        def webdav_uri_port(uri)
          uri.port || (uri.scheme == "https" ? 443 : 80)
        end
      end
    end

    register_plugin(:webdav_lock, WebdavLock)
  end
end
