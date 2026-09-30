# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The content_security_policy plugin allows you to easily set a Content-Security-Policy
    # header for the application, which modern browsers will use to control access to specific
    # types of page content.
    #
    # You would generally call the plugin with a block to set the default policy:
    #
    #   plugin :content_security_policy do |csp|
    #     csp.default_src :none
    #     csp.img_src :self
    #     csp.style_src :self
    #     csp.script_src :self
    #     csp.font_src :self
    #     csp.form_action :self
    #     csp.base_uri :none
    #     csp.frame_ancestors :none
    #     csp.block_all_mixed_content
    #   end
    #
    # Then, anywhere in the routing tree, you can customize the policy for just that
    # branch or action using the same block syntax:
    #
    #   r.get 'foo' do
    #     content_security_policy do |csp|
    #       csp.object_src :self
    #       csp.add_style_src 'bar.com'
    #     end
    #     # ...
    #   end
    #
    # In addition to using a block, you can also call methods on the object returned
    # by the method:
    #
    #   r.get 'foo' do
    #     content_security_policy.script_src :self, 'example.com', [:nonce, 'foobarbaz']
    #     # ...
    #   end
    #
    # The following methods are available for configuring the content security policy,
    # which specify the setting (substituting _ with -): 
    #
    # * base_uri
    # * child_src
    # * connect_src
    # * default_src
    # * font_src
    # * form_action
    # * frame_ancestors
    # * frame_src
    # * img_src
    # * manifest_src
    # * media_src
    # * object_src
    # * plugin_types
    # * report_to
    # * report_uri
    # * require_sri_for
    # * sandbox
    # * script_src
    # * style_src
    # * worker_src
    #
    # All of these methods support any number of arguments, and each argument should
    # be one of the following types:
    #
    # String :: used verbatim
    # Symbol :: Substitutes +_+ with +-+ and surrounds with <tt>'</tt>
    # Array :: only accepts 2 element arrays, joins elements with +-+ and
    #          surrounds the result with <tt>'</tt>
    #
    # Example:
    #
    #   content_security_policy.script_src :self, :unsafe_eval, 'example.com', [:nonce, 'foobarbaz']
    #   # script-src 'self' 'unsafe-eval' example.com 'nonce-foobarbaz'; 
    #  
    # When calling a method with no arguments, the setting is removed from the policy instead
    # of being left empty, since all of these setting require at least one value.  Likewise,
    # if the policy does not have any settings, the header will not be added.
    #
    # Calling the method overrides any previous setting.  Each of the methods has +add_*+ and
    # +get_*+ methods defined. The +add_*+ method appends to any existing setting, and the +get_*+ method
    # returns the current value for the setting.
    #
    #   content_security_policy.script_src :self, :unsafe_eval
    #   content_security_policy.add_script_src 'example.com', [:nonce, 'foobarbaz']
    #   # script-src 'self' 'unsafe-eval' example.com 'nonce-foobarbaz'; 
    #
    #   content_security_policy.get_script_src
    #   # => [:self, :unsafe_eval, 'example.com', [:nonce, 'foobarbaz']]
    #
    # The clear method can be used to remove all settings from the policy. Empty policies
    # do not set any headers. You can use +response.skip_content_security_policy!+ to skip
    # setting a policy.  This is faster than calling +content_security_policy.clear+, since
    # it does not duplicate the default policy.
    #
    # The following methods to set boolean settings are also defined:
    #
    # * block_all_mixed_content
    # * upgrade_insecure_requests
    #
    # Calling these methods will turn on the related setting.  To turn the setting
    # off again, you can call them with a +false+ argument. There is also a <tt>*?</tt> method
    # for each setting for returning whether the setting is currently enabled.
    #
    # Likewise there is also a +report_only+ method for turning on report only mode (the
    # default is enforcement mode), or turning off report only mode if a false argument
    # is given.  Also, there is a +report_only?+ method for returning whether report only
    # mode is enabled.
    #
    # Policies can also be combined as independent objects.  Unlike overriding a copied
    # policy, combining policies requires the browser to satisfy every policy:
    #
    #   parent = Roda::RodaPlugins::ContentSecurityPolicy::Policy.new do |csp|
    #     csp.default_src :none
    #     csp.script_src :self
    #   end
    #
    #   r.get 'foo' do
    #     combine_content_security_policy do |csp|
    #       csp.default_src :none
    #       csp.script_src :self, 'https://child.example'
    #     end
    #   end
    #
    # Ordinary source lists are normalized and intersected when the combined result is
    # equivalent.  If a policy uses a nonce, hash, 'strict-dynamic', sandbox, or a
    # different default-src fallback, the policies are sent as separate
    # Content-Security-Policy header fields instead of being merged into a broader policy.
    module ContentSecurityPolicy
      RESPONSE_INSTANCE_VARIABLES = [:@content_security_policy, :@skip_content_security_policy].freeze

      # Represents a content security policy.
      class Policy
        FETCH_DIRECTIVES = %w'
        child-src
        connect-src
        default-src
        font-src
        frame-src
        img-src
        manifest-src
        media-src
        object-src
        script-src
        style-src
        worker-src
        '.each(&:freeze).freeze

        SOURCE_LIST_DIRECTIVES = (FETCH_DIRECTIVES + %w'
        base-uri
        form-action
        frame-ancestors
        plugin-types
        ').freeze

        BOOLEAN_DIRECTIVES = %w'block-all-mixed-content upgrade-insecure-requests'.freeze
        EQUAL_VALUE_DIRECTIVES = %w'report-to report-uri'.freeze

        private_constant :FETCH_DIRECTIVES, :SOURCE_LIST_DIRECTIVES, :BOOLEAN_DIRECTIVES, :EQUAL_VALUE_DIRECTIVES

        '
        base-uri
        child-src
        connect-src
        default-src
        font-src
        form-action
        frame-ancestors
        frame-src
        img-src
        manifest-src
        media-src
        object-src
        plugin-types
        report-to
        report-uri
        require-sri-for
        sandbox
        script-src
        style-src
        worker-src
        '.split.each(&:freeze).each do |setting|
          meth = setting.tr('-', '_').freeze

          # Setting method name sets the setting value, or removes it if no args are given.
          define_method(meth) do |*args|
            if setting == 'sandbox'
              if args.empty? || args == [true]
                @opts[setting] = EMPTY_ARRAY
              elsif args == [false]
                @opts.delete(setting)
              else
                @opts[setting] = args.freeze
              end
            elsif args.empty?
              @opts.delete(setting)
            else
              @opts[setting] = args.freeze
            end
            nil
          end

          # add_* method name adds to the setting value, or clears setting if no values
          # are given.
          define_method("add_#{meth}") do |*args|
            unless args.empty?
              @opts[setting] ||= EMPTY_ARRAY
              @opts[setting] += args
              @opts[setting].freeze
            end
            nil
          end

          # get_* method always returns current setting value.
          define_method("get_#{meth}") do
            @opts[setting]
          end
        end

        BOOLEAN_DIRECTIVES.each do |setting|
          meth = setting.tr('-', '_').freeze

          # Setting method name turns on setting if true or no argument given,
          # or removes setting if false is given.
          define_method(meth) do |arg=true|
            if arg
              @opts[setting] = true
            else
              @opts.delete(setting)
            end

            nil
          end

          # *? method returns true or false depending on whether setting is enabled.
          define_method("#{meth}?") do
            !!@opts[setting]
          end
        end

        def initialize
          clear
          yield self if defined?(yield)
        end

        # Combine this policy with one or more independent policies.  Ordinary policies
        # are normalized into an equivalent policy when possible; policies that cannot be
        # merged without changing browser behavior remain separate.
        def combine(*policies)
          self.class.combine(self, *policies)
        end

        # Clear all settings, useful to remove any inherited settings.
        def clear
          @opts = {}
          @report_only = nil
          @header_value = nil
        end

        # Do not allow future modifications to any settings.
        def freeze
          @opts.freeze
          header_value.freeze
          super
        end

        # The header name to use, depends on whether report only mode has been enabled.
        def header_key
          @report_only ? RodaResponseHeaders::CONTENT_SECURITY_POLICY_REPORT_ONLY : RodaResponseHeaders::CONTENT_SECURITY_POLICY
        end

        # The header value to use.
        def header_value
          return @header_value if @header_value

          s = String.new
          @opts.each do |k, vs|
            s << k
            unless vs == true
              vs.each{|v| append_formatted_value(s, v)}
            end
            s << '; '
          end
          @header_value = s
        end

        # Set whether the Content-Security-Policy-Report-Only header instead of the
        # default Content-Security-Policy header.
        def report_only(report=true)
          @report_only = report
        end

        # Whether this policy uses report only mode.
        def report_only?
          !!@report_only
        end

        # Set the current policy in the headers hash.  If no settings have been made
        # in the policy, does not set a header.
        def set_header(headers)
          return if @opts.empty?
          headers[header_key] ||= header_value
        end

        # Whether the policy has any directives.  Report-only mode by itself does not
        # result in a Content-Security-Policy header.
        def empty?
          @opts.empty?
        end

        # Combine independent policies.  See #combine.
        def self.combine(*policies)
          policies = policies.flatten.flat_map do |policy|
            case policy
            when PolicyCollection
              policy.to_a
            when Policy
              policy
            else
              raise RodaError, "cannot combine unsupported CSP policy: #{policy.inspect}"
            end
          end.reject(&:empty?)

          return new if policies.empty?

          report_only = policies.first.report_only?
          unless policies.all?{|policy| policy.report_only? == report_only}
            raise RodaError, "cannot combine enforced and report-only CSP policies"
          end

          merge_helper = allocate
          combined = []
          policies.each do |policy|
            merged = false
            combined.each_with_index do |existing, index|
              if merged_policy = merge_helper.send(:merge_policies, existing, policy)
                combined[index] = merged_policy
                merged = true
                break
              end
            end
            combined << policy.dup unless merged
          end

          case combined.length
          when 0
            new
          when 1
            combined.first.freeze
          else
            PolicyCollection.new(combined).freeze
          end
        end

        private

        # Handle three types of values when formatting the header:
        # String :: used verbatim
        # Symbol :: Substitutes _ with - and surrounds with '
        # Array :: only accepts 2 element arrays, joins them with - and
        #          surrounds them with '
        def append_formatted_value(s, v)
          s << ' ' << formatted_value(v)
        end

        # Make object copy use copy of settings, and remove cached header value.
        def initialize_copy(_)
          super
          @opts = @opts.dup
          @header_value = nil
        end

        # Format a policy value as it appears in a Content-Security-Policy header.
        def formatted_value(v)
          case v
          when String
            v
          when Array
            unless v.length == 2
              raise RodaError, "unsupported CSP value used: #{v.inspect}"
            end
            "'#{v.join('-')}'"
          when Symbol
            "'#{v.to_s.tr('_', '-')}'"
          else
            raise RodaError, "unsupported CSP value used: #{v.inspect}"
          end
        end

        # Return the canonical policy value for a formatted token.
        def canonical_value(v, formatted)
          case v
          when String
            if formatted.start_with?("'") && formatted.end_with?("'")
              formatted[1..-2].tr('-', '_').to_sym
            else
              v
            end
          else
            v
          end
        end

        # Normalize an ordinary source list by removing duplicates and using a stable,
        # lexicographic order.  'none' is exclusive according to CSP semantics.
        def normalized_values(values)
          values_by_token = {}
          values.each do |value|
            formatted = formatted_value(value)
            values_by_token[formatted] ||= canonical_value(value, formatted)
          end

          if values_by_token.key?("'none'")
            [:none]
          else
            values_by_token.keys.sort.map{|key| values_by_token[key]}
          end
        end

        def value_tokens(values)
          normalized_values(values).map{|value| formatted_value(value)}
        end

        def special_value?(value)
          formatted = formatted_value(value)
          case value
          when Array
            name = value.first.to_s.tr('_', '-')
            name == 'nonce' || name.start_with?('sha')
          when Symbol
            value == :strict_dynamic
          else
            formatted == "'strict-dynamic'" || formatted.start_with?("'nonce-", "'sha")
          end
        end

        def special_policy?
          @opts.any? do |directive, values|
            directive == 'sandbox' || (values.is_a?(Array) && values.any?{|value| special_value?(value)})
          end
        end

        # Merge two policies only when the merged policy has exactly the same browser
        # semantics as requiring both policies independently.
        def merge_policies(first, second)
          return if first.send(:special_policy?) || second.send(:special_policy?)

          first_default = first.instance_variable_get(:@opts)['default-src']
          second_default = second.instance_variable_get(:@opts)['default-src']
          if first_default.nil? != second_default.nil?
            return
          end

          policy = Policy.new
          directives = (first.instance_variable_get(:@opts).keys | second.instance_variable_get(:@opts).keys)
          default = first_default || second_default

          directives.each do |directive|
            first_value = first.instance_variable_get(:@opts)[directive]
            second_value = second.instance_variable_get(:@opts)[directive]

            if BOOLEAN_DIRECTIVES.include?(directive)
              policy.public_send(directive.tr('-', '_')) if first_value || second_value
            elsif directive == 'default-src'
              merged_default = merge_source_directive(directive, first_value, second_value, nil)
              return unless merged_default
              policy.default_src(*merged_default)
            elsif SOURCE_LIST_DIRECTIVES.include?(directive)
              merged_values = merge_source_directive(directive, first_value, second_value, default)
              return unless merged_values
              policy.public_send(directive.tr('-', '_'), *merged_values) unless merged_values.empty?
            elsif directive == 'require-sri-for'
              values = [first_value, second_value].compact.flatten.uniq
              policy.require_sri_for(*values)
            elsif EQUAL_VALUE_DIRECTIVES.include?(directive)
              return if first_value != second_value
              policy.public_send(directive.tr('-', '_'), *first_value)
            else
              return
            end
          end

          policy.report_only(true) if first.report_only?
          policy
        end

        def merge_source_directive(directive, first_value, second_value, default)
          first_values = first_value || (FETCH_DIRECTIVES.include?(directive) ? default : nil)
          second_values = second_value || (FETCH_DIRECTIVES.include?(directive) ? default : nil)

          if first_values.nil?
            normalized_values(second_values) if second_values
          elsif second_values.nil?
            normalized_values(first_values)
          else
            first_tokens = value_tokens(first_values)
            second_tokens = value_tokens(second_values)

            if first_tokens.all?{|token| second_tokens.include?(token)}
              normalized_values(first_values)
            elsif second_tokens.all?{|token| first_tokens.include?(token)}
              normalized_values(second_values)
            else
              return
            end
          end
        end

        # Represents a collection of independent content security policies.  Each policy
        # is sent as a separate header field, and the browser must satisfy all of them.
        class PolicyCollection
          include Enumerable

          def initialize(*policies)
            @policies = policies.flatten.map! do |policy|
              unless policy.is_a?(Policy)
                raise RodaError, "unsupported CSP policy used: #{policy.inspect}"
              end
              policy.dup
            end.reject(&:empty?)

            unless @policies.map(&:report_only?).uniq.length <= 1
              raise RodaError, "cannot combine enforced and report-only CSP policies"
            end
          end

          def each(&block)
            @policies.each(&block)
          end

          def combine(*policies)
            Policy.combine(self, *policies)
          end

          def empty?
            @policies.empty?
          end

          def header_key
            @policies.first.header_key
          end

          def header_values
            @policies.map(&:header_value)
          end

          def header_value
            header_values.map{|value| value.sub(/; \z/, '')}.join(', ')
          end

          def report_only?
            !@policies.empty? && @policies.first.report_only?
          end

          def set_header(headers)
            return if empty?
            value = if Rack.release >= '3'
              header_values
            else
              header_value
            end
            headers[header_key] ||= value
          end

          def freeze
            @policies.each(&:freeze)
            @policies.freeze
            super
          end

          private

          def initialize_copy(_)
            super
            @policies = @policies.map(&:dup)
          end
        end
      end


      # Yield the current Content Security Policy to the block.
      def self.configure(app)
        policy = app.opts[:content_security_policy] = if policy = app.opts[:content_security_policy]
          policy.dup
        else
          Policy.new
        end

        yield policy if defined?(yield)
        policy.freeze
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :content_security_policy)
      end

      module InstanceMethods
        # If a block is given, yield the current content security policy.  Returns the
        # current content security policy.
        def content_security_policy
          policy = @_response.content_security_policy
          yield policy if defined?(yield)
          policy
        end

        # Combine the current policy with an independent policy, instead of overriding
        # the policy inherited from the application.  Returns the combined policy.
        def combine_content_security_policy(policy=nil)
          policy ||= Policy.new
          yield policy if defined?(yield)
          @_response.content_security_policy = content_security_policy.combine(policy)
        end
      end

      module ResponseMethods
        # Unset any content security policy when reinitializing
        def initialize
          super
          @content_security_policy &&= nil
        end

        # The current content security policy to be used for this response.
        def content_security_policy
          @content_security_policy ||= roda_class.content_security_policy.dup
        end

        # Set the current policy or independent policy collection.
        attr_writer :content_security_policy

        # Do not set a content security policy header for this response.
        def skip_content_security_policy!
          @skip_content_security_policy = true
        end

        private

        # Set the appropriate content security policy header.
        def set_default_headers
          super
          unless @skip_content_security_policy
            (@content_security_policy || roda_class.content_security_policy).set_header(headers)
          end
        end
      end
    end

    register_plugin(:content_security_policy, ContentSecurityPolicy)
  end
end
