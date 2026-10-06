# frozen-string-literal: true

require 'strscan'
require 'securerandom'

class Roda
  module RodaPlugins
    # The webdav_lock plugin provides WebDAV class-2 locking support
    # (RFC 4918): LOCK and UNLOCK methods, Depth 0/infinity handling,
    # If-header precondition evaluation (tagged and untagged condition
    # lists), and write-operation enforcement for PUT, DELETE and MOVE
    # handlers.
    #
    # Neither resources nor locks are persisted by the plugin.  Both
    # backends are injected when the plugin is loaded:
    #
    #   plugin :webdav_lock,
    #     lock_store: MyLockStore.new,
    #     resources:  MyResourceBackend.new,
    #     clock:      ->{ Time.now }
    #
    # == Lock store protocol
    #
    # The +:lock_store+ object must implement:
    #
    # create_lock(lock) :: Store the given lock hash.  The hash contains
    #                     :token, :path, :scope ('exclusive'/'shared'),
    #                     :depth (0/Float::INFINITY), :owner, :timeout
    #                     (seconds, or nil for infinite) and :expires_at
    #                     (Time, or nil).
    # get_lock(token) :: Return the stored lock hash for the token, or nil
    #                    if no current (non-expired) lock exists.
    # delete_lock(token) :: Remove the lock with the token.  Return the lock
    #                       hash if removed, nil otherwise.
    # direct_locks(path) :: Return active lock hashes held exactly on path.
    # ancestor_locks(path) :: Return active depth-infinity lock hashes held
    #                         on strict ancestors of path.
    # locks_under(path) :: Return active lock hashes held on strict
    #                      descendants of path (any depth).  Used when
    #                      taking an exclusive LOCK, and when checking a
    #                      MOVE source tree.
    #
    # All query methods must filter out expired locks.  The injected
    # +:clock+ is passed to +create_lock+ via +expires_at+, so a simple
    # store does not need its own clock, but storing +:timeout+ as well
    # makes LOCK refresh straightforward.
    #
    # == Resource backend protocol
    #
    # The +:resources+ object must implement:
    #
    # resource_exists?(path) :: Whether path currently exists.
    # resource_collection?(path) :: Whether path is a collection (RFC 4918
    #                              collection, e.g. a directory).
    #
    # +resource_etag(path)+ may be implemented to support entity-tag
    # conditions in If headers.  +move_tree(src, dst)+ must be implemented
    # to back #webdav_move!; it is only invoked after all lock
    # preconditions have passed, so on failure the resource tree is left
    # untouched.  The lock store may implement +move_locks(src, dst)+ to
    # migrate lock mappings when a tree moves; it is called after
    # +move_tree+.
    #
    # == Request methods
    #
    # r.webdav_lock! :: Handle a LOCK request (create or refresh) and halt
    #                   with the complete response.
    # r.webdav_unlock! :: Handle an UNLOCK request and halt.
    # r.webdav_authorize_write!(path=nil) :: Enforce lock preconditions for
    #                   a PUT or DELETE on the request path.  Halts 423 or
    #                   412 on failure; returns nil on success.
    # r.webdav_move! :: Enforce lock preconditions for a MOVE (source,
    #                   destination and every affected ancestor/subtree
    #                   lock), then call resources.move_tree.  The backend
    #                   is never touched when a precondition fails.
    # r.webdav_locks(path=nil) :: Active locks that protect the path:
    #                   direct locks plus depth-infinity ancestor locks.
    # r.webdav_if_satisfied?(path=nil, move: nil) :: Evaluate the
    #                   request's If header against the given write
    #                   target and return a boolean.  +move+ is [src,
    #                   dst] for a MOVE check.
    module WebdavLock
      INFINITY = 1.0/0.0
      private_constant :INFINITY

      # Options:
      # :lock_store :: Required.  Object implementing the lock store
      #                protocol (see module documentation).
      # :resources :: Required.  Object implementing the resource backend
      #                protocol (see module documentation).
      # :clock :: Object responding to +call+ and returning the current
      #           time.  Defaults to Time.method(:now).  Inject a mutable
      #           clock in tests to make lock expiry deterministic.
      # :default_timeout :: Default lock lifetime in seconds when the
      #                     LOCK request has no Timeout header.  nil means
      #                     locks never expire (the default).
      # :max_timeout :: Upper bound in seconds applied to any requested
      #                 finite timeout.
      def self.configure(app, opts=OPTS)
        app.opts[:webdav_lock_store] = opts[:lock_store] if opts.key?(:lock_store)
        app.opts[:webdav_lock_resources] = opts[:resources] if opts.key?(:resources)
        app.opts[:webdav_lock_clock] = opts[:clock] if opts.key?(:clock)
        app.opts[:webdav_lock_default_timeout] = opts[:default_timeout] if opts.key?(:default_timeout)
        app.opts[:webdav_lock_max_timeout] = opts[:max_timeout] if opts.key?(:max_timeout)
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :webdav_lock_store)
        RodaPlugins.opt_attr_reader(self, :webdav_lock_resources)
        RodaPlugins.opt_attr_reader(self, :webdav_lock_clock)
        RodaPlugins.opt_attr_reader(self, :webdav_lock_default_timeout)
        RodaPlugins.opt_attr_reader(self, :webdav_lock_max_timeout)
      end

      module RequestMethods
        # Handle a LOCK request.  A request with an empty body and an If
        # header refreshes an existing lock; any other body requests a new
        # lock.  Halts with the full response.
        def webdav_lock!
          path = webdav_path
          depth = webdav_lock_depth(path)

          body = body_read
          if body.empty?
            webdav_refresh_lock!(path)
          else
            webdav_create_lock!(path, depth, body)
          end
        end

        # Handle an UNLOCK request.  The Lock-Token header must identify
        # an active lock for the request path.  Halts with the response.
        def webdav_unlock!
          path = webdav_path
          token = webdav_lock_token_header
          webdav_halt(400, 'no-lock-token') unless token

          lock = webdav_lock_store.get_lock(token)
          if lock.nil?
            webdav_halt(409, 'lock-token-matches-request-uri')
          end
          unless webdav_same_path?(lock[:path], path)
            webdav_halt(409, 'lock-token-matches-request-uri')
          end

          webdav_lock_store.delete_lock(token)
          response.status = 204
          halt
        end

        # Enforce locks for a PUT or DELETE on path (defaults to the
        # request path).  Returns nil when the write is allowed, otherwise
        # halts with 423 Locked (no usable If header) or 412 Precondition
        # Failed (If header presented but not satisfied).
        def webdav_authorize_write!(path=nil, subtree: request_method == 'DELETE')
          path ||= webdav_path
          blockers = webdav_write_blockers(path, subtree)
          webdav_enforce!(path, blockers)
        end

        # Validate a MOVE request end to end, then perform it.  Checks the
        # source, destination and their ancestor depth locks (plus locks
        # held inside the source tree) before touching resources, so a
        # failed precondition leaves the resource tree unchanged.
        def webdav_move!
          src = webdav_path
          dst = webdav_destination_path
          webdav_halt(400, 'destination-required') unless dst
          webdav_halt(400, 'bad-request') if webdav_same_path?(src, dst)
          webdav_halt(400, 'bad-request') if webdav_depth_header == '0' && webdav_resources.resource_collection?(src)

          overwrite = webdav_overwrite
          dst_exists = webdav_resources.resource_exists?(dst)
          webdav_halt(412, 'overwrite-allowed') if dst_exists && !overwrite
          webdav_halt(409, 'cannot-modify-protected-property') if dst_exists && webdav_descendant?(dst, src)

          blockers = webdav_move_blockers(src, dst)
          webdav_enforce!([src, dst], blockers)

          webdav_resources.move_tree(src, dst)
          if webdav_lock_store.respond_to?(:move_locks)
            webdav_lock_store.move_locks(src, dst)
          end
          response.status = dst_exists ? 204 : 201
          halt
        end

        # Return the active locks protecting path: direct locks on the path
        # plus depth-infinity locks on strict ancestors.  Locks held by
        # the path itself do not protect its descendants.
        def webdav_locks(path=nil)
          path ||= webdav_path
          locks = webdav_lock_store.direct_locks(path)
          locks + webdav_lock_store.ancestor_locks(path)
        end

        # Evaluate the request's If header for a write to path.  +move+
        # may be set to [src, dst] so tokens are resolved against both
        # resources.  With no If header, a write is allowed only when no
        # active locks protect the affected resources.
        def webdav_if_satisfied?(path=nil, move: nil)
          paths = move || [path || webdav_path]
          blocker_map = move ? webdav_move_blockers(*move) : webdav_write_blockers(paths.first, false)
          if_header = env['HTTP_IF']
          return blocker_map.values.all?(&:empty?) unless if_header

          lists = begin
            WebdavIfParser.parse(if_header)
          rescue WebdavIfParser::ParseError
            return false
          end
          webdav_lists_satisfied?(lists, paths, blocker_map)
        end

        # Backend accessors.  Override these per-subclass/request to select
        # a backend dynamically; by default they use the plugin options.
        def webdav_lock_store
          roda_class.webdav_lock_store or
            raise RodaError, "webdav_lock plugin requires the :lock_store option"
        end

        def webdav_resources
          roda_class.webdav_lock_resources or
            raise RodaError, "webdav_lock plugin requires the :resources option"
        end

        private

        def webdav_create_lock!(path, depth, body)
          unless webdav_resources.resource_exists?(path)
            webdav_halt(409, 'lock-token-matches-request-uri')
          end

          info = webdav_parse_lockinfo(body)
          webdav_halt(400, 'bad-request') unless info
          scope = info[:scope]

          existing = webdav_locks(path)
          if scope == 'exclusive'
            conflicts = existing + webdav_lock_store.locks_under(path)
            webdav_halt(409, 'no-conflicting-lock') unless conflicts.empty?
          elsif existing.any? { |l| l[:scope] == 'exclusive' }
            # An exclusive lock on the resource blocks a new shared lock.
            # The holder may re-lock by presenting its token; without an
            # If header this is 423 Locked.
            blockers = webdav_write_blockers(path, false)
            webdav_enforce!(path, blockers)
          end

          token = "opaquelocktoken:#{SecureRandom.uuid}"
          timeout = webdav_requested_timeout
          expires_at = timeout ? webdav_now + timeout : nil
          lock = {
            token: token,
            path: path,
            scope: scope,
            depth: depth,
            owner: info[:owner],
            timeout: timeout,
            expires_at: expires_at,
          }
          webdav_lock_store.create_lock(lock)

          response.status = 200
          response['Lock-Token'] = "<#{token}>"
          response[RodaResponseHeaders::CONTENT_TYPE] = 'application/xml; charset=utf-8'
          response.write(webdav_lock_prop_xml(lock))
          halt
        end

        def webdav_refresh_lock!(path)
          if_header = env['HTTP_IF']
          webdav_halt(412, 'no-conflicting-lock') unless if_header

          lists = begin
            WebdavIfParser.parse(if_header)
          rescue WebdavIfParser::ParseError
            webdav_halt(400, 'bad-request')
          end

          tokens = webdav_tokens_from_lists(lists, path)
          webdav_halt(412, 'no-conflicting-lock') if tokens.empty?

          timeout = webdav_requested_timeout
          refreshed = []
          tokens.each do |token|
            lock = webdav_lock_store.get_lock(token)
            next unless lock
            next unless webdav_same_path?(lock[:path], path)
            next unless webdav_list_grants_lock?(lists, path, lock)

            updated_lock = lock.dup
            updated_lock[:timeout] = timeout
            updated_lock[:expires_at] = timeout ? webdav_now + timeout : nil
            webdav_lock_store.create_lock(updated_lock)
            refreshed << updated_lock
          end
          webdav_halt(412, 'no-conflicting-lock') if refreshed.empty?

          response.status = 200
          response[RodaResponseHeaders::CONTENT_TYPE] = 'application/xml; charset=utf-8'
          response.write(webdav_lock_prop_xml(refreshed.length == 1 ? refreshed.first : refreshed))
          halt
        end

        # All locks that would prevent a write to path.  DELETE on a
        # collection also locks every lock held in its subtree.
        def webdav_write_blockers(path, subtree)
          blockers = {path => webdav_locks(path)}
          if subtree
            webdav_lock_store.locks_under(path).each do |lock|
              member_path = lock[:path]
              blockers[member_path] ||= webdav_locks(member_path)
              blockers[member_path] << lock unless blockers[member_path].any? { |l| l[:token] == lock[:token] }
            end
          end
          webdav_dedup_blockers(blockers)
        end

        # Locks that would prevent MOVE src -> dst: source side, target
        # side, and locks held within the moved subtree.
        def webdav_move_blockers(src, dst)
          blockers = {src => webdav_locks(src), dst => webdav_locks(dst)}

          # Moving a collection removes every member, so each member lock
          # and every ancestor depth lock protecting a member is checked.
          webdav_lock_store.locks_under(src).each do |lock|
            member_path = lock[:path]
            blockers[member_path] ||= webdav_locks(member_path)
            blockers[member_path] << lock unless blockers[member_path].any? { |l| l[:token] == lock[:token] }
          end

          webdav_dedup_blockers(blockers)
        end

        def webdav_dedup_blockers(blockers)
          blockers.each do |path, locks|
            blockers[path] = locks.uniq { |l| l[:token] }
          end
        end

        # Apply the standard WebDAV enforcement rules.  Halts 423 when a
        # blocker exists without an If header, and 412 when an If header
        # is present but does not satisfy every affected resource.
        def webdav_enforce!(paths, blocker_map)
          paths = Array(paths)
          if_header = env['HTTP_IF']
          if if_header
            lists = begin
              WebdavIfParser.parse(if_header)
            rescue WebdavIfParser::ParseError
              webdav_halt(400, 'bad-request')
            end
          elsif blocker_map.values.all?(&:empty?)
            return nil
          else
            webdav_halt(423, 'locked')
          end

          unless webdav_lists_satisfied?(lists, paths, blocker_map)
            webdav_halt(412, 'no-conflicting-lock')
          end
          nil
        end

        # True if the If condition lists satisfy all blockers.  Each list
        # is an AND-group; separate lists are alternatives (OR).  Tagged
        # lists apply to the tagged resource, untagged lists are tested
        # against each involved resource.
        def webdav_lists_satisfied?(lists, request_paths, blocker_map)
          untagged = lists.reject { |list| list[:tag] }
          tagged = lists.select { |list| list[:tag] }
          all_tokens = blocker_map.values.flatten.map { |l| l[:token] }

          # Every write target is evaluated even when it has no blockers,
          # because entity-tag-only conditions still apply.  Subtree
          # members discovered for a collection DELETE/MOVE are added.
          resource_paths = (request_paths + blocker_map.keys).uniq
          resource_paths.each do |resource_path|
            blockers = blocker_map[resource_path] || []
            resource_tagged = tagged.select do |list|
              tag_path = webdav_resolve_tag(list[:tag])
              tag_path == resource_path
            end

            # Tagged lists for unrelated resources do not apply; only the
            # sets relevant to this resource are considered.
            candidates = untagged.map { |list| [list, all_tokens] } +
              resource_tagged.map { |list| [list, blockers.map { |l| l[:token] }] }

            pass = candidates.any? do |list, accepted_tokens|
              webdav_list_covered?(list, resource_path, blockers, accepted_tokens)
            end
            return false unless pass
          end
          true
        end

        def webdav_list_covered?(list, resource_path, blockers, accepted_tokens)
          conditions = list[:conditions]

          # All blockers on this resource must be unlocked by this list.
          covered = blockers.all? do |lock|
            conditions.any? do |c|
              !c[:negated] && !c[:etag] && c[:token] == lock[:token]
            end
          end
          return false unless covered

          # Every non-negated token presented in the list must be a lock
          # involved in this request (any blocker across the write, e.g.
          # the MOVE destination or a subtree member).  A valid token
          # stored on an unrelated resource grants nothing.
          presented = conditions.reject { |c| c[:negated] || c[:etag] }
          granted = presented.all? do |c|
            lock = webdav_lock_store.get_lock(c[:token])
            next false unless lock
            accepted_tokens.include?(lock[:token])
          end
          return false unless granted

          # A negated token that names one of this resource's blockers
          # cannot authorize the write, even when other conditions pass.
          conditions.each do |c|
            next unless c[:negated] && !c[:etag]
            return false if blockers.any? { |b| b[:token] == c[:token] }
          end

          # Entity-tag conditions are evaluated against the resource.
          conditions.select { |c| c[:etag] }.each do |c|
            etag = webdav_resources.respond_to?(:resource_etag) ? webdav_resources.resource_etag(resource_path) : nil
            match = etag && webdav_etag_equal?(etag, c[:etag])
            return false if c[:negated] ? match : !match
          end

          true
        end

        def webdav_list_grants_lock?(lists, path, lock)
          lists.any? do |list|
            tag_path = list[:tag] ? webdav_resolve_tag(list[:tag]) : path
            next false unless tag_path == path
            list[:conditions].any? { |c| !c[:negated] && !c[:etag] && c[:token] == lock[:token] }
          end
        end

        def webdav_tokens_from_lists(lists, path)
          lists.flat_map do |list|
            tag_path = list[:tag] ? webdav_resolve_tag(list[:tag]) : path
            next [] unless tag_path == path
            list[:conditions].reject { |c| c[:negated] || c[:etag] }.map { |c| c[:token] }
          end.uniq
        end

        # Resolve a tagged-list resource tag against the request host.
        # Returns the tag's path when same-origin, :foreign otherwise.
        def webdav_resolve_tag(tag)
          unless tag.start_with?('/')
            begin
              uri = URI.parse(tag)
            rescue URI::InvalidURIError
              return :foreign
            end
            return :foreign unless webdav_request_host?(uri)
            tag_path = uri.path
          else
            tag_path = tag
          end
          webdav_normalize_path(tag_path)
        end

        def webdav_request_host?(uri)
          request_host = env['HTTP_HOST'] || env['SERVER_NAME']
          return false unless uri.host
          if request_host.to_s.include?(':')
            request_name, request_port = request_host.split(':', 2)
            port = uri.port || (uri.scheme == 'https' ? 443 : 80)
            uri.host == request_name && port.to_s == request_port
          else
            default_port = uri.scheme == 'https' ? 443 : 80
            uri.host == request_host && (uri.port.nil? || uri.port == default_port)
          end
        end

        def webdav_parse_lockinfo(body)
          # lockinfo is a small, fixed-shape XML document; avoid an XML
          # parser dependency by matching the lockscope/locktype element
          # names and owner text directly.
          scope_match = body.match(/<(?:[\w.-]+:)?lockscope\b[^>]*>\s*<(?:[\w.-]+:)?(exclusive|shared)\b/im)
          type_match = body.match(/<(?:[\w.-]+:)?locktype\b[^>]*>\s*<(?:[\w.-]+:)?(\w+)/im)
          return nil unless scope_match
          return nil unless type_match && type_match[1].downcase == 'write'

          scope = scope_match[1].downcase
          owner_match = body.match(/<(?:[\w.-]+:)?owner\b[^>]*>(.*?)<\/(?:[\w.-]+:)?owner>/im)
          owner = nil
          if owner_match
            owner = webdav_unescape_xml(owner_match[1]).gsub(/<[^>]*>/, '').strip
            owner = nil if owner.empty?
          end
          {scope: scope, owner: owner}
        end

        def webdav_lock_depth(path)
          value = webdav_depth_header
          case value
          when nil, '0'
            0
          when 'infinity'
            unless webdav_resources.resource_collection?(path)
              webdav_halt(400, 'bad-request')
            end
            INFINITY
          else
            webdav_halt(400, 'bad-request')
          end
        end

        def webdav_depth_header
          value = env['HTTP_DEPTH']
          value && value.downcase
        end

        def webdav_requested_timeout
          header = env['HTTP_TIMEOUT']
          requested = nil
          if header
            header.split(/,/).each do |part|
              part = part.strip.downcase
              if part.start_with?('second-')
                seconds = part[7..-1].to_i
                next if seconds <= 0
                requested = seconds
                break
              end
            end
          end
          requested ||= roda_class.webdav_lock_default_timeout
          max = roda_class.webdav_lock_max_timeout
          requested = [requested, max].min if requested && max
          requested
        end

        def webdav_lock_token_header
          value = env['HTTP_LOCK_TOKEN']
          return nil unless value
          value = value.strip
          match = value.match(/\A<([^>]+)>/)
          match && match[1]
        end

        def webdav_destination_path
          value = env['HTTP_DESTINATION']
          return nil unless value && !value.empty?
          if value.start_with?('/')
            path = value
          else
            begin
              uri = URI.parse(value)
            rescue URI::InvalidURIError
              return nil
            end
            return nil unless webdav_request_host?(uri)
            path = uri.request_uri
            return nil unless path
          end
          path = path.split('?', 2).first
          webdav_normalize_path(URI::DEFAULT_PARSER.unescape(path))
        end

        def webdav_overwrite
          (env['HTTP_OVERWRITE'] || 'T').upcase != 'F'
        end

        def webdav_now
          clock = roda_class.webdav_lock_clock
          clock ? clock.call : Time.now
        end

        def webdav_path
          webdav_normalize_path(path)
        end

        def webdav_normalize_path(path)
          path = path.squeeze('/')
          path = path.chomp('/') unless path == '/'
          path
        end

        def webdav_same_path?(a, b)
          webdav_normalize_path(a) == webdav_normalize_path(b)
        end

        def webdav_descendant?(parent, child)
          parent == '/' ? child != '/' : child.start_with?(parent + '/')
        end

        def webdav_etag_equal?(a, b)
          webdav_etag_value(a).downcase == webdav_etag_value(b).downcase
        end

        def webdav_etag_value(v)
          v.to_s.sub(/\AW\//i, '').delete('"')
        end

        XML_ENTITIES = {'&amp;' => '&', '&lt;' => '<', '&gt;' => '>', '&quot;' => '"', '&apos;' => "'"}.freeze

        def webdav_unescape_xml(str)
          str.gsub(/&(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);/) do |entity|
            XML_ENTITIES[entity.downcase] ||
              if entity.start_with?('&#x')
                [entity[3..-2].to_i(16)].pack('U')
              else
                [entity[2..-2].to_i].pack('U')
              end
          end
        end

        def webdav_lock_prop_xml(lock_or_locks)
          locks = lock_or_locks.is_a?(Array) ? lock_or_locks : [lock_or_locks]
          parts = locks.map do |lock|
            timeout = if lock[:expires_at]
              "Second-#{[lock[:expires_at] - webdav_now, 0].max.round}"
            else
              'Infinite'
            end
            depth = lock[:depth] == INFINITY ? 'Infinity' : '0'
            owner = lock[:owner] && !lock[:owner].empty? ? "<D:owner>#{Rack::Utils.escape_html(lock[:owner])}</D:owner>" : ''
            <<~XML.gsub(/\n\s*/, '')
              <D:lockdiscovery>
                <D:activelock>
                  <D:locktype><D:write/></D:locktype>
                  <D:lockscope><D:#{lock[:scope]}/></D:lockscope>
                  <D:depth>#{depth}</D:depth>
                  #{owner}
                  <D:timeout>#{timeout}</D:timeout>
                  <D:locktoken><D:href>&lt;#{Rack::Utils.escape_html(lock[:token])}&gt;</D:href></D:locktoken>
                </D:activelock>
              </D:lockdiscovery>
            XML
          end
          %(<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:">#{parts.join}</D:prop>)
        end

        def body_read
          input = env['rack.input']
          input ? input.read.to_s : ''
        end

        def webdav_halt(status, condition)
          body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" \
            "<D:error xmlns:D=\"DAV:\"><D:#{condition}/></D:error>"
          halt [status, {RodaResponseHeaders::CONTENT_TYPE => 'application/xml; charset=utf-8'}, [body]]
        end
      end

      # Tokenizer/parser for the RFC 4918 If header grammar:
      #
      #   If = "If" : ( 1*No-tag-list | 1*Tagged-list )
      #   No-tag-list = List
      #   Tagged-list = Resource-Tag 1*List
      #   List = "(" 1*Condition ")"
      #   Condition = ["Not"] (Resource-Tag | ("[" entity-tag "]"))
      #
      # Returns [{tag: nil|String, conditions: [{negated:, token:, etag:}]}].
      module WebdavIfParser
        class ParseError < StandardError; end

        module_function

        def parse(header)
          scanner = StringScanner.new(header)
          lists = []
          tag = nil

          loop do
            skip_ows(scanner)
            break if scanner.eos?

            if scanner.peek(1) == '<'
              tag = consume_tag(scanner)
            elsif scanner.peek(1) == '('
              lists << {tag: tag, conditions: consume_list(scanner)}
            else
              raise ParseError, "unexpected character at position #{scanner.pos}"
            end
          end

          raise ParseError, 'empty If header' if lists.empty?
          lists
        end

        def consume_list(scanner)
          scanner.getch # "("
          conditions = []
          loop do
            skip_ows(scanner)
            char = scanner.peek(1)
            if char == ')'
              scanner.getch
              raise ParseError, 'empty condition list' if conditions.empty?
              return conditions
            end

            negated = false
            if match_word(scanner, 'not')
              negated = true
              skip_ows(scanner)
            end

            char = scanner.peek(1)
            if char == '<'
              conditions << {negated: negated, token: consume_tag(scanner), etag: nil}
            elsif char == '['
              scanner.getch
              etag = scanner.scan_until(/\]/)
              raise ParseError, 'unterminated entity-tag' unless etag
              conditions << {negated: negated, token: nil, etag: etag.chomp(']').strip}
            else
              raise ParseError, "expected condition at position #{scanner.pos}"
            end
          end
        end

        def consume_tag(scanner)
          tag = scanner.scan(/<[^>]*>/)
          raise ParseError, 'unterminated resource-tag' unless tag
          tag[1..-2]
        end

        def skip_ows(scanner)
          scanner.skip(/[\s]+/)
        end

        def match_word(scanner, word)
          pos = scanner.pos
          matched = scanner.scan(/#{word}(?=[\s()<\[])/i)
          scanner.pos = pos unless matched
          !!matched
        end
      end
    end

    register_plugin(:webdav_lock, WebdavLock)
  end
end
