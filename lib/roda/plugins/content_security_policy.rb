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
    # Independent policy objects can be combined with the current policy.  Browsers
    # enforce all combined policies, so this does not override the policy inherited
    # from the parent application:
    #
    #   child_policy = Roda::RodaPlugins::ContentSecurityPolicy::Policy.new do |csp|
    #     csp.script_src :self, 'child.example.com'
    #   end
    #
    #   r.get 'foo' do
    #     combine_content_security_policy(child_policy)
    #     # ...
    #   end
    #
    # You can also build the additional policy inline:
    #
    #   r.get 'foo' do
    #     combine_content_security_policy do |csp|
    #       csp.script_src :self, 'child.example.com'
    #     end
    #     # ...
    #   end
    #
    # Equivalent ordinary source lists are normalized to a single policy when they
    # can be combined safely.  Policies using nonces, hashes, strict-dynamic, or
    # sandbox, or which have different fallback structures, are kept as separate
    # Content-Security-Policy headers instead of being merged into a policy that
    # would allow more than the intersection of the combined policies.
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
    module ContentSecurityPolicy
      RESPONSE_INSTANCE_VARIABLES = [:@content_security_policy, :@skip_content_security_policy].freeze

      LIST_SETTINGS = '
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
        '.split.each(&:freeze).freeze

      BOOLEAN_SETTINGS = %w[block-all-mixed-content upgrade-insecure-requests].each(&:freeze).freeze
      FETCH_SOURCE_LIST_SETTINGS = '
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
        '.split.each(&:freeze).freeze
      NON_FETCH_SOURCE_LIST_SETTINGS = %w[base-uri form-action frame-ancestors].each(&:freeze).freeze
      SOURCE_LIST_SETTINGS = (FETCH_SOURCE_LIST_SETTINGS + NON_FETCH_SOURCE_LIST_SETTINGS).freeze
      TOKEN_LIST_SETTINGS = %w[plugin-types report-to report-uri require-sri-for].each(&:freeze).freeze
      private_constant :LIST_SETTINGS, :BOOLEAN_SETTINGS, :FETCH_SOURCE_LIST_SETTINGS,
        :NON_FETCH_SOURCE_LIST_SETTINGS, :SOURCE_LIST_SETTINGS, :TOKEN_LIST_SETTINGS

      # Represents a content security policy.
      class Policy
        LIST_SETTINGS.each do |setting|
          meth = setting.tr('-', '_').freeze

          # Setting method name sets the setting value, or removes it if no args are given.
          define_method(meth) do |*args|
            if args.empty?
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

        BOOLEAN_SETTINGS.each do |setting|
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

        # Combine the receiver with one or more independent policies.  Returns a
        # single policy when the combination is provably equivalent, otherwise
        # returns a PolicySet that emits separate headers.
        def combine(*policies, &block)
          Policy.combine(self, *policies, &block)
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

        # Whether the policy has any configured settings.
        def empty?
          @opts.empty?
        end

        # Combine independent policies without allowing the result to grant more
        # access than the policies grant collectively.
        def self.combine(*policies)
          if block_given?
            policy = new
            yield policy
            policies << policy
          end

          policies = policies.flat_map do |policy|
            case policy
            when PolicySet
              policy.policies
            else
              policy
            end
          end.reject(&:empty?).map(&:dup)

          return new if policies.empty?
          return policies.first if policies.length == 1
          return PolicySet.new(policies) unless policies.map(&:report_only?).uniq.length == 1

          mergeable, merged = combined_settings(policies)
          return PolicySet.new(policies) unless mergeable

          policy = new
          merged.each do |setting, value|
            if BOOLEAN_SETTINGS.include?(setting)
              policy.public_send(setting.tr('-', '_'))
            else
              policy.public_send(setting.tr('-', '_'), *value)
            end
          end
          policy.report_only if policies.first.report_only?
          policy
        end

        def self.combined_settings(policies)
          settings = {}
          all_settings = policies.flat_map{|policy| policy.instance_variable_get(:@opts).keys}.uniq

          all_settings.each do |setting|
            opts_list = policies.map{|policy| policy.instance_variable_get(:@opts)}
            values = opts_list.map{|opts| opts[setting]}

            if BOOLEAN_SETTINGS.include?(setting)
              settings[setting] = true if values.any?
              next
            end

            if setting == 'sandbox'
              return [false]
            end

            if FETCH_SOURCE_LIST_SETTINGS.include?(setting)
              fallback_types = opts_list.map do |opts|
                if opts.key?(setting)
                  :explicit
                elsif setting != 'default-src' && opts.key?('default-src')
                  :default
                else
                  :unrestricted
                end
              end
              next if fallback_types.all?(:unrestricted)
              return [false] unless fallback_types.uniq.length == 1

              source_values = opts_list.map{|opts| opts[setting] || opts['default-src']}
              return [false] if special_source_list?(source_values.flatten)

              combined_value = combined_source_list(source_values)
              return [false] unless combined_value
              settings[setting] = combined_value
            elsif NON_FETCH_SOURCE_LIST_SETTINGS.include?(setting)
              source_values = values.compact
              next if source_values.empty?
              return [false] if special_source_list?(source_values.flatten)

              combined_value = combined_source_list(source_values)
              return [false] unless combined_value
              settings[setting] = combined_value
            elsif TOKEN_LIST_SETTINGS.include?(setting)
              source_values = values.compact
              next if source_values.empty?
              canonical_values = source_values.map{|value| canonical_source_list(value)}
              return [false] unless canonical_values.map(&:first).uniq.length == 1
              settings[setting] = canonical_values.first.map(&:last)
            end
          end

          [true, settings]
        end
        private_class_method :combined_settings

        def self.special_source_list?(values)
          values.any? do |value|
            case value
            when Array
              true
            when Symbol
              value == :strict_dynamic || value.to_s.start_with?('nonce_', 'sha256_', 'sha384_', 'sha512_')
            when String
              value == 'strict-dynamic' || value == "'strict-dynamic'" ||
                value.start_with?("'nonce-", "'sha256-", "'sha384-", "'sha512-")
            else
              true
            end
          end
        end
        private_class_method :special_source_list?

        def self.combined_source_list(value_lists)
          canonical_lists = value_lists.map{|values| canonical_source_list(values)}
          return [:none] if canonical_lists.any?{|list| list.map(&:first) == ["'none'"]}

          tokens = canonical_lists.first.map(&:first)
          canonical_lists[1..-1].each do |list|
            tokens &= list.map(&:first)
          end
          return if tokens.empty?

          tokens.map do |token|
            canonical_lists.each do |list|
              item = list.assoc(token)
              break item.last if item
            end
          end
        end
        private_class_method :combined_source_list

        def self.canonical_source_list(values)
          values.map do |value|
            [formatted_value(value), value]
          end.uniq(&:first).sort_by(&:first)
        end
        private_class_method :canonical_source_list

        def self.formatted_value(value)
          s = String.new
          Policy.new.send(:append_formatted_value, s, value)
          s[1..-1]
        end
        private_class_method :formatted_value

        private

        # Handle three types of values when formatting the header:
        # String :: used verbatim
        # Symbol :: Substitutes _ with - and surrounds with '
        # Array :: only accepts 2 element arrays, joins them with - and
        #          surrounds them with '
        def append_formatted_value(s, v)
          case v
          when String
            s << ' ' << v
          when Array
            case v.length
            when 2
              s << " '" << v.join('-') << "'"
            else
              raise RodaError, "unsupported CSP value used: #{v.inspect}"
            end
          when Symbol
            s << " '" << v.to_s.tr('_', '-') << "'"
          else
            raise RodaError, "unsupported CSP value used: #{v.inspect}"
          end
        end

        # Make object copy use copy of settings, and remove cached header value.
        def initialize_copy(_)
          super
          @opts = @opts.dup
          @header_value = nil
        end
      end

      # Represents policies that must all be enforced by the browser.
      class PolicySet
        attr_reader :policies

        def initialize(policies)
          @policies = policies.reject(&:empty?).freeze
        end

        # Combine the receiver with one or more independent policies.
        def combine(*policies, &block)
          Policy.combine(self, *policies, &block)
        end

        # Whether any policy in the set has configured settings.
        def empty?
          @policies.empty?
        end

        # Set a separate header for each policy.  Policies with different report
        # modes use their respective enforcement or report-only header.
        def set_header(headers)
          @policies.group_by(&:header_key).each do |header_key, policies|
            headers[header_key] ||= if policies.length == 1
              policies.first.header_value
            else
              policies.map(&:header_value)
            end
          end
        end

        # Do not allow future modifications to any policies.
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

        # Combine the current content security policy with an independent policy.
        # If no policy is given, the block is used to build one.
        def combine_content_security_policy(policy=nil, &block)
          policies = [content_security_policy]
          policies << policy if policy
          @_response.content_security_policy = Policy.combine(*policies, &block)
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

        # Set the content security policy or policy set for this response.
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
