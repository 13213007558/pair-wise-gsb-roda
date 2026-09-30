# frozen-string-literal: true

require 'json'

#
class Roda
  module RodaPlugins
    # The route_diagnostics plugin records a structured trace of the routing
    # decisions made for a single request, without changing how the request is
    # routed.  When the request is not handled, the trace describes every
    # routing branch that was tried, how much of the path each branch consumed,
    # which matchers were attempted (including each array alternative and hash
    # component), why the closest candidates failed, named-route dispatch, and
    # branches skipped with r.pass.
    #
    # Diagnostics are collected per request, only for requests that opt in,
    # so ordinary requests take the same code path as without the plugin:
    #
    #   plugin :route_diagnostics
    #
    # By default, requests carrying the +X-Roda-Route-Diagnostics+ header get
    # a trace in a response header of the same name when the response is a 404.
    # The trigger, header name, and attachment policy can be configured:
    #
    #   plugin :route_diagnostics,
    #     trigger: proc { |env| env['HTTP_X_RODA_DEBUG'] == '1' },
    #     header:  'X-Route-Debug',
    #     attach:  :always # :not_found (default), :always, or false
    #
    # The same data is stored in the rack environment under
    # +roda.route_diagnostics+ while routing, so before hooks, error handlers,
    # and middleware can inspect it programmatically.  Captured matcher values
    # are copied into the trace only; request captures and params are never
    # modified by collection, and matchers are never invoked again just to
    # explain the result.
    module RouteDiagnostics
      ENV_KEY = 'roda.route_diagnostics'.freeze
      DEFAULT_HEADER = 'X-Roda-Route-Diagnostics'.freeze
      DEFAULT_TRIGGER_HEADER = 'HTTP_X_RODA_ROUTE_DIAGNOSTICS'.freeze
      VERB_METHODS = %w'get post delete head options link patch put trace unlink'.freeze

      def self.load_dependencies(app, _opts=OPTS)
        # These make r.pass and the less common request verbs available so
        # the diagnostic frames can wrap them; both are inert unless used.
        app.plugin :pass
        app.plugin :all_verbs
        app.plugin :named_routes
      end

      def self.configure(app, opts=OPTS)
        rd = app.opts[:route_diagnostics] ? Hash[app.opts[:route_diagnostics]] : {}
        rd[:trigger] = opts[:trigger] if opts.key?(:trigger)
        rd[:header] = opts[:header] if opts.key?(:header)
        rd[:attach] = opts[:attach] if opts.key?(:attach)
        rd[:trigger] ||= lambda { |env| env.key?(DEFAULT_TRIGGER_HEADER) }
        rd[:header] ||= DEFAULT_HEADER
        rd[:attach] = :not_found if rd[:attach].nil?
        app.opts[:route_diagnostics] = rd.freeze
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :route_diagnostics)
      end

      module InstanceMethods
        # Enable the trace when the per-request trigger matches, and attach
        # the finished trace to the response.  The route block itself is run
        # exactly once, regardless of whether diagnostics are enabled.
        def _roda_handle_main_route
          request = @_request
          config = self.class.opts[:route_diagnostics]
          request._route_diagnostics_enable! if config[:trigger].call(request.env)

          res = super

          if (trace = request.route_diagnostics)
            trace.finish!(res[0])
            attach = config[:attach]
            if attach == :always || (attach == :not_found && res[0] == 404)
              res[1][config[:header]] = JSON.generate(json_safe(trace.data))
            end
          end

          res
        end

        private

        def json_safe(obj)
          case obj
          when Hash
            obj.each_with_object({}) { |(k, v), h| h[k.to_s] = json_safe(v) }
          when Array
            obj.map { |v| json_safe(v) }
          when Symbol, Regexp, Class, Module
            obj.inspect
          when String, Integer, Float, true, false, nil
            obj
          else
            begin
              obj.inspect
            rescue StandardError
              '(uninspectable)'
            end
          end
        end
      end

      module RequestMethods
        # The RouteDiagnostics::Trace for this request, or nil if diagnostics
        # were not enabled for the request.
        attr_reader :route_diagnostics

        # Enable routing diagnostics for the current request.  Called
        # automatically when the plugin trigger matches, but can also be
        # invoked explicitly from a before hook.
        def _route_diagnostics_enable!
          @route_diagnostics ||= begin
            trace = Trace.new(self)
            @env[ENV_KEY] = trace.data
            trace
          end
        end

        def is(*args, &block)
          trace = @route_diagnostics
          return super unless trace

          _diag_branch(:is, args) { super }
        end

        def on(*args, &block)
          trace = @route_diagnostics
          return super unless trace

          _diag_branch(:on, args) { super }
        end

        def root(&block)
          trace = @route_diagnostics
          return super unless trace

          _diag_branch(:root, EMPTY_ARRAY) { super }
        end

        VERB_METHODS.each do |verb|
          next unless ::Rack::Request.method_defined?("#{verb}?")
          upcased = verb.to_s.upcase

          class_eval(<<-END, __FILE__, __LINE__ + 1)
            def #{verb}(*args, &block)
              trace = @route_diagnostics
              return super unless trace
              matches = #{upcased.inspect} == @env['REQUEST_METHOD']
              # GET branches also serve HEAD requests when the head plugin
              # makes is_get? accept them.
              matches = (matches || head?) if #{verb == 'get'} && !matches
              if matches
                _diag_branch(:#{verb}, args) { super }
              else
                trace.verb_mismatch(:#{verb}, args)
                nil
              end
            end
          END
        end

        # Distinguish a branch whose matchers succeeded (the block was
        # entered) from one whose matchers failed.  block_result is called
        # for entered blocks immediately before they yield.
        def block_result(result)
          if trace = @route_diagnostics
            trace.mark_block_entered!
          end
          super
        end
        public :block_result

        private

        # Run a routing method inside a trace frame.  The outcome is derived
        # in block_result (every entered, halted block calls it) and in
        # branch_end, without intercepting Roda's :halt control flow.
        def _diag_branch(kind, args)
          frame = @route_diagnostics.branch_start(kind, args)
          @route_diagnostics.branch_end(frame) { yield }
        end

        # Wrap a single matcher dispatch.  The matcher is invoked exactly
        # once; only inputs, result, consumed path, and captures are observed.
        def match(matcher, *rest)
          trace = @route_diagnostics
          return super(matcher, *rest) unless trace && !@_route_diag_in_custom

          trace.match_attempt(matcher) { super(matcher, *rest) }
        end

        # Record individual key/value components of a hash matcher while
        # preserving the base semantics (reset state on failure).
        def _match_hash(hash)
          trace = @route_diagnostics
          return super unless trace

          trace.hash_attempt(hash)
        end

        # Observe custom matcher dispatch (used by the custom_matchers plugin)
        # as a single attempt, without invoking the custom matcher again.
        def unsupported_matcher(matcher)
          trace = @route_diagnostics
          return super unless trace

          if @_route_diag_in_custom
            super
          else
            @_route_diag_in_custom = true
            begin
              trace.match_attempt(matcher) { super }
            ensure
              @_route_diag_in_custom = false
            end
          end
        end

        # Observe an array matcher as one grouped set of attempts.  Each
        # element is observed through #match_attempt when dispatched.
        def _match_array(matcher, *rest)
          trace = @route_diagnostics
          return super(matcher, *rest) unless trace

          trace.array_attempt(matcher) { super(matcher, *rest) }
        end

        # Dispatch to a named route inside a trace frame so entry and
        # fall-through are visible.
        def route(name, namespace=nil)
          trace = @route_diagnostics
          return super unless trace

          frame = trace.route_start(name, namespace)
          trace.branch_end(frame) { super }
        end

        # r.pass skips the current block; flag the active frame so it can be
        # distinguished from a matcher failure.
        def pass
          @route_diagnostics&.send(:pass!)
          super
        end
        public :pass

        # Named routes are dispatched publicly (named_routes plugin).
        public :route
      end

    end

    # Per-request trace collector.  The plain, eventually-frozen Hash exposed
    # by #data is stored in the rack environment and returned with responses.
    class RouteDiagnostics::Trace
      TERM_LABEL = '<terminal (path fully consumed)>'.freeze
      VERB_METHODS = RouteDiagnostics::VERB_METHODS

      attr_reader :data

      def initialize(request)
        @request = request
        @frames = []
        @open_frames = {}
        @array_groups = []
        @seq = 0
        @data = {
          request_method: request.env['REQUEST_METHOD'],
          path: request.path,
          matched: false,
          status: nil,
          branches: [],
          attempts: [],
          closest_candidates: [],
        }
      end

      # Open a frame for a routing branch; the caller closes it with
      # branch_end after observing the :halt control flow itself.
      def branch_start(kind, args)
        push_frame(kind, args, nil)
      end

      # Open a frame for a named-route dispatch.
      def route_start(name, namespace)
        push_frame(:route, EMPTY_ARRAY, namespace ? "#{namespace}:#{name}" : name.to_s)
      end

      # Record a verb call whose path matchers were not evaluated because the
      # request method did not match (Roda's own short-circuit behavior).
      def verb_mismatch(verb, args)
        frame = push_frame(verb, args, nil)
        finish_frame(frame, false)
      end

      # Close the frame when its routing method returns normally.  Handled
      # branches throw :halt past this point; those frames are closed in
      # finish! using the entered marks set by block_result.
      def branch_end(frame, &block)
        result = block ? block.call : nil
        frame[:entered] = true if frame[:node][:kind] == 'route'
        finish_frame(frame, false)
        result
      end

      # Observe one matcher call from RodaRequest#match.
      def match_attempt(matcher)
        before_path = @request.remaining_path
        before_captures = @request.captures.length
        result = yield
        record_attempt(matcher, result, before_path, before_captures)
        result
      end

      # Observe an array matcher, grouping its element attempts so
      # backtracking over earlier alternatives can be annotated.
      def array_attempt(matcher)
        @array_groups.push(matcher)
        yield
      ensure
        @array_groups.pop
      end

      # Observe a hash matcher, recording each key/value component without
      # invoking any component twice.  This mirrors RodaRequest#_match_hash.
      def hash_attempt(hash)
        rp = @request.remaining_path
        captures_len = @request.captures.length
        before_path = rp.dup

        result = hash.all? do |key, value|
          comp_before = @request.remaining_path
          comp_captures = @request.captures.length
          comp_result = @request.send("match_#{key}", value)
          record_hash_component(key, value, comp_result, comp_before, comp_captures)
          comp_result
        end

        unless result
          @request.instance_variable_set(:@remaining_path, rp)
          @request.captures.slice!(captures_len, 10000000)
        end

        record_attempt(hash, result, before_path, captures_len)
        result
      end

      def mark_block_entered!
        # The frame executing the actual block (innermost non-route) is
        # entered; its ancestors are marked handled in close_pending_frames
        # via their children, so that fall-throughs stay distinguishable.
        @frames.reverse_each do |frame|
          next if frame[:node][:kind] == 'route'
          frame[:entered] = true
          frame[:node][:entered] = true
          return
        end
      end

      # Mark the innermost non-route frame as explicitly passed.
      def pass!
        @frames.reverse_each do |frame|
          next if frame[:node][:kind] == 'route'
          frame[:passed] = true
          return
        end
      end

      # Finalize the tree once routing has completed and the response status
      # is known.  No matchers are invoked here.
      def finish!(status)
        close_pending_frames!(@data[:branches], status, @data[:path])
        annotate_backtracking!
        compute_consumed_paths!(@data[:branches])
        @data[:matched] = any_handled?(@data[:branches])
        @data[:status] = status
        @data[:closest_candidates] = closest_candidates unless @data[:matched]
        deep_freeze(@data)
        @data
      end

      # A request is unmatched only on a 404 where no entered branch reached
      # a terminal handler.  An explicit 404 from a handler is handled.
      private

      def any_handled?(nodes)
        nodes.any? { |n| n[:outcome] == 'handled' || any_handled?(n[:children]) }
      end

      def any_entered?(nodes)
        nodes.any? { |n| n[:entered] || any_entered?(n[:children]) }
      end

      # Close frames in push order (innermost last), carrying the deepest
      # entered, halted frame's status decision out to its ancestors.
      def close_pending_frames!(_nodes, _status, _path)
        @open_frames.values.reverse_each do |frame|
          node = frame[:node]
          child_handled = node[:children].any? { |c| c[:outcome] == 'handled' }
          terminal = node[:kind] != 'on' && node[:kind] != 'route' && frame[:entered]
          handled = (frame[:entered] && _status != 404) || (terminal && _status == 404)
          handled = true if child_handled
          node[:remaining_at_close] ||= @request.remaining_path.dup
          node[:halted] = handled
          node[:outcome] = handled ? 'handled' :
            (frame[:passed] ? 'passed' : (node[:kind] == 'route' ? 'fell_through' : 'unfinished'))
          node[:reason] = handled ? nil : reason_for(frame)
        end
        @open_frames.clear
      end

      # consumed_to is the furthest point in the path reached while this
      # frame or any nested frame was being evaluated (including frames the
      # pass plugin restores).  Derived from recorded attempts only.
      def compute_consumed_paths!(nodes)
        nodes.each do |node|
          compute_consumed_paths!(node[:children])
          consumed = [node[:remaining_at_close]]
          mine = @data[:attempts].select { |a| a[:frame_seq] == node[:seq] }
          mine.each { |a| consumed << a[:consumed_to] if a[:consumed_to] }
          node[:children].each { |c| consumed << c[:consumed_to] if c[:consumed_to] }
          node[:consumed_to] = consumed.compact.min_by(&:length)
        end
      end

      def push_frame(kind, args, route_name)
        node = {
          seq: (@seq += 1),
          kind: kind.to_s,
          matcher: describe_args(kind, args),
          at: @request.remaining_path.dup,
          children: [],
        }
        node[:name] = route_name if route_name
        parent = @frames.last
        (parent ? parent[:node][:children] : @data[:branches]) << node
        frame = { node: node, passed: false, parent: parent }
        @frames << frame
        @open_frames[node[:seq]] = frame
        frame
      end

      def finish_frame(frame, halted)
        node = frame[:node]
        node[:remaining_at_close] = @request.remaining_path.dup
        node[:entered] = frame[:entered] ||
          node[:children].any? { |c| c[:entered] || %w'passed handled'.include?(c[:outcome]) }
        node[:halted] = halted
        node[:outcome] = outcome_for(frame, halted)
        node[:reason] = reason_for(frame)
        @frames.delete(frame)
        @open_frames.delete(node[:seq])
      end

      def outcome_for(frame, halted)
        node = frame[:node]
        return 'passed' if frame[:passed]
        return 'handled' if halted
        if frame[:entered]
          node[:kind] == 'route' ? 'fell_through' : 'unfinished'
        else
          'no_match'
        end
      end


      def reason_for(frame)
        node = frame[:node]
        case node[:outcome]
        when 'handled'
          nil
        when 'passed'
          'block called r.pass'
        when 'fell_through'
          if child = node[:children].find { |c| c[:outcome] == 'passed' }
            "named route fell through after a branch called r.pass (#{child[:reason]})"
          else
            'named route returned without handling the request'
          end
        when 'unfinished'
          'branch matched, but no terminal handler inside it matched'
        else
          no_match_reason(node)
        end
      end

      def no_match_reason(node)
        kind = node[:kind]
        if VERB_METHODS.include?(kind)
          mine = @data[:attempts].select { |a| a[:frame_seq] == node[:seq] }
          if failed = failing_attempt(mine)
            describe_failure(failed)
          else
            "request method #{@data[:request_method]} does not match #{kind.upcase}"
          end
        elsif kind == 'root'
          if node[:at] != '/'
            "remaining path #{node[:at].inspect} is not \"/\""
          else
            "request method #{@data[:request_method]} is not GET"
          end
        else
          mine = @data[:attempts].select { |a| a[:frame_seq] == node[:seq] }
          failed = failing_attempt(mine)
          failed ? describe_failure(failed) : 'matchers did not match'
        end
      end

      def failing_attempt(attempts)
        # The request got furthest at the failed attempt with the shortest
        # remaining path (e.g. a custom matcher rejecting the tail segment
        # beats a later array alternative tried from a shallower position).
        attempts.select { |a| !a[:matched] }.min_by do |failed|
          [failed[:at].length, -failed[:seq]]
        end
      end

      def describe_failure(attempt)
        case attempt[:matcher_type]
        when 'terminal'
          "path not fully consumed; #{attempt[:at].inspect} remained"
        when 'string'
          "string #{attempt[:matcher].inspect} not found at #{attempt[:at].inspect}"
        when 'class'
          "class matcher #{attempt[:matcher]} rejected #{attempt[:at].inspect}"
        when 'regexp'
          "regexp #{attempt[:matcher]} did not match #{attempt[:at].inspect}"
        when 'symbol'
          "symbol matcher :#{attempt[:matcher]} did not match #{attempt[:at].inspect}"
        when 'array'
          "none of the #{attempt[:matcher].length} array alternatives matched at #{attempt[:at].inspect}"
        when 'hash'
          "hash matcher #{attempt[:matcher].inspect} was not satisfied"
        when 'set'
          "segment was not in set #{attempt[:matcher].inspect}"
        when 'proc'
          'proc matcher returned a false value'
        when 'custom'
          "custom matcher #{attempt[:matcher]} returned a false value"
        else
          'matcher returned a false value'
        end
      end

      # Mark array element attempts that matched but were later abandoned
      # because following matchers failed (plain arrays stop at the first
      # match, so only backtracking_array can produce these).
      def annotate_backtracking!
        @data[:attempts].each do |attempt|
          next unless attempt[:array_of] && attempt[:matched]
          later_match = @data[:attempts].any? do |a|
            a[:array_of] == attempt[:array_of] &&
              a[:frame_seq] == attempt[:frame_seq] &&
              a[:seq] > attempt[:seq] && a[:matched]
          end
          attempt[:backtracked] = true if later_match
        end
      end

      def record_hash_component(key, value, result, before_path, before_captures)
        captured = @request.captures[before_captures, 100000000] || []
        @data[:attempts] << {
          seq: @data[:attempts].length,
          frame_seq: @frames.last ? @frames.last[:node][:seq] : nil,
          matcher_type: "hash_component:#{key}",
          matcher: describe_matcher(value),
          at: before_path.dup,
          matched: !result.nil? && result != false,
          consumed_to: @request.remaining_path.dup,
          captured: captured.map { |c| copy_capture(c) },
        }
      end

      def closest_candidates
        candidates = []
        collect_candidates(@data[:branches], candidates, 0)
        # Deeper, more specific frames win ties: the is-frame that rejected a
        # specific segment is a better answer than the enclosing on-frame.
        candidates.sort_by! { |c| [-c[:consumed_length], -c[:depth], c[:seq]] }
        candidates.first(10).map do |c|
          {
            kind: c[:kind],
            matcher: c[:matcher],
            name: c[:name],
            at: c[:at],
            consumed_to: c[:consumed_to],
            outcome: c[:outcome],
            reason: c[:reason],
          }
        end
      end

      def collect_candidates(nodes, candidates, depth)
        nodes.each do |node|
          unless node[:outcome] == 'handled'
            candidates << {
              seq: node[:seq],
              kind: node[:kind],
              matcher: node[:matcher],
              name: node[:name],
              at: node[:at],
              consumed_to: node[:consumed_to],
              consumed_length: matched_length(node),
              depth: depth,
              outcome: node[:outcome],
              reason: node[:reason],
            }
          end
          collect_candidates(node[:children], candidates, depth + 1)
        end
      end

      # How much of the original path was consumed up to and inside this
      # node.  Paths inside nested frames are recorded relative to the frame,
      # so a consumed_to of "/x" at depth "/api" means 6 characters consumed
      # of the original path.
      def matched_length(node)
        @data[:path].length - (node[:consumed_to] || node[:at]).length
      end

      def describe_args(kind, args)
        args = args.dup
        if args.last.equal?(Roda::RodaRequest::TERM)
          args.pop
          args.push(TERM_LABEL)
        end
        args.map { |a| describe_matcher(a) }
      end

      def describe_matcher(matcher)
        return TERM_LABEL if matcher.equal?(Roda::RodaRequest::TERM)
        case matcher
        when String, Integer, Symbol, nil, true, false
          matcher
        when Regexp
          matcher.inspect
        when Class
          matcher.name || matcher.inspect
        when Array
          matcher.map { |m| describe_matcher(m) }
        when Hash
          matcher.map { |k, v| [k.to_s, describe_matcher(v)] }.to_h
        when ::Set
          matcher.to_a.map { |m| describe_matcher(m) }
        else
          begin
            matcher.inspect
          rescue StandardError
            '(uninspectable)'
          end
        end
      end

      def matcher_type(matcher)
        return 'terminal' if matcher.equal?(Roda::RodaRequest::TERM)
        case matcher
        when String then 'string'
        when Class then 'class'
        when Regexp then 'regexp'
        when Array then 'array'
        when Hash then 'hash'
        when ::Set then 'set'
        when Symbol then 'symbol'
        when Proc then 'proc'
        else 'custom'
        end
      end

      def record_attempt(matcher, result, before_path, before_captures)
        captured = @request.captures[before_captures, 100000000] || []
        attempt = {
          seq: @data[:attempts].length,
          frame_seq: @frames.last ? @frames.last[:node][:seq] : nil,
          matcher_type: matcher_type(matcher),
          matcher: describe_matcher(matcher),
          at: before_path.dup,
          matched: !result.nil? && result != false,
          consumed_to: @request.remaining_path.dup,
          captured: captured.map { |c| copy_capture(c) },
        }
        attempt[:array_of] = describe_matcher(@array_groups.last) if @array_groups.last
        @data[:attempts] << attempt
        attempt
      end

      def copy_capture(value)
        case value
        when Numeric, Symbol, true, false, nil
          value
        else
          begin
            value.dup
          rescue TypeError
            value
          end
        end
      end

      def deep_freeze(obj)
        case obj
        when Hash
          obj.each_value { |v| deep_freeze(v) }
          obj.freeze
        when Array
          obj.each { |v| deep_freeze(v) }
          obj.freeze
        else
          obj.freeze if obj.respond_to?(:freeze)
        end
      end
    end

    register_plugin(:route_diagnostics, RouteDiagnostics)
  end
end
