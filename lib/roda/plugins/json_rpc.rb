# frozen_string_literal: true

class Roda
  module RodaPlugins
    # The json_rpc plugin adds an optional JSON-RPC 2.0 endpoint to a Roda
    # application. RPC methods must be explicitly registered; arbitrary methods
    # on registered objects are never callable through the method name.
    #
    #   plugin :json_rpc
    #
    #   json_rpc_method "add" do |a, b|
    #     a + b
    #   end
    #
    #   json_rpc_method "echo", lambda { |message:| message }
    #
    #   route do |r|
    #     r.post "rpc" do
    #       r.json_rpc
    #     end
    #   end
    #
    # Both positional and named JSON-RPC parameters are supported. Named
    # parameters use the Ruby method's parameter names, including required and
    # optional keyword arguments. Positional arrays cannot supply keywords.
    #
    # Notifications do not produce a response. Exceptions raised while executing
    # a notification method can be reported locally using the
    # +:notification_error_handler+ option:
    #
    #   plugin :json_rpc, notification_error_handler: proc { |exception|
    #     warn exception.message
    #   }
    #
    # The +:methods+ option accepts a hash of method names and callables. The
    # +:parser+, +:serializer+, and +:content_type+ options can customize JSON
    # handling and the response content type.
    module JsonRpc
      VERSION = "2.0".freeze
      CONTENT_TYPE = "application/json".freeze

      PARSE_ERROR_CODE = -32700
      INVALID_REQUEST_CODE = -32600
      METHOD_NOT_FOUND_CODE = -32601
      INVALID_PARAMS_CODE = -32602
      INTERNAL_ERROR_CODE = -32603

      PARSE_ERROR_MESSAGE = "Parse error".freeze
      INVALID_REQUEST_MESSAGE = "Invalid Request".freeze
      METHOD_NOT_FOUND_MESSAGE = "Method not found".freeze
      INVALID_PARAMS_MESSAGE = "Invalid params".freeze
      INTERNAL_ERROR_MESSAGE = "Internal error".freeze

      # Base error used for JSON-RPC protocol errors.
      class Error < RodaError
        attr_reader :code, :data

        def initialize(code, message, data=nil)
          @code = code
          @data = data
          super(message)
        end
      end

      class ParseError < Error
        def initialize(data=nil)
          super(PARSE_ERROR_CODE, PARSE_ERROR_MESSAGE, data)
        end
      end

      class InvalidRequestError < Error
        def initialize(data=nil)
          super(INVALID_REQUEST_CODE, INVALID_REQUEST_MESSAGE, data)
        end
      end

      class MethodNotFoundError < Error
        def initialize(data=nil)
          super(METHOD_NOT_FOUND_CODE, METHOD_NOT_FOUND_MESSAGE, data)
        end
      end

      class InvalidParamsError < Error
        def initialize(data=nil)
          super(INVALID_PARAMS_CODE, INVALID_PARAMS_MESSAGE, data)
        end
      end

      class InternalError < Error
        def initialize(data=nil)
          super(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MESSAGE, data)
        end
      end

      def self.load_dependencies(app, opts=OPTS, &_)
        app.plugin :_json
      end

      def self.configure(app, opts=OPTS, &block)
        app.opts[:json_rpc_methods] ||= {}
        configured_methods = opts[:methods]
        if configured_methods
          configured_methods.each do |name, handler|
            app.json_rpc_method(name, handler)
          end
        end
        app.opts[:json_rpc_parser] = opts[:parser] || app.json_rpc_parser || app.json_parser
        app.opts[:json_rpc_serializer] = opts[:serializer] || app.json_rpc_serializer || app.json_serializer
        app.opts[:json_rpc_content_type] = opts[:content_type] || app.json_rpc_content_type || CONTENT_TYPE

        hook = if opts[:notification_error_handler]
          opts[:notification_error_handler]
        elsif opts[:error_handler]
          opts[:error_handler]
        elsif block
          block
        else
          app.json_rpc_notification_error_handler
        end
        app.opts[:json_rpc_notification_error_handler] = hook
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :json_rpc_methods)
        RodaPlugins.opt_attr_reader(self, :json_rpc_parser)
        RodaPlugins.opt_attr_reader(self, :json_rpc_serializer)
        RodaPlugins.opt_attr_reader(self, :json_rpc_content_type)
        RodaPlugins.opt_attr_reader(self, :json_rpc_notification_error_handler)

        # Register a callable JSON-RPC method. Either pass a callable object or
        # provide a block. Method names are stored in an explicit registry.
        def json_rpc_method(name, callable=nil, &block)
          if callable && block
            raise RodaError, "JSON-RPC method #{name.inspect} cannot use both a callable and a block"
          end
          handler = callable || block
          unless name.is_a?(String) || name.is_a?(Symbol)
            raise RodaError, "JSON-RPC method name must be a String or Symbol"
          end
          unless handler.respond_to?(:call)
            raise RodaError, "JSON-RPC method #{name.inspect} must be callable"
          end

          json_rpc_methods[name.to_s] = handler
          nil
        end
        # Install a local handler for exceptions raised by notification methods.
        def json_rpc_notification_error(&block)
          unless block.respond_to?(:call)
            raise RodaError, "JSON-RPC notification error handler must be callable"
          end
          opts[:json_rpc_notification_error_handler] = block
          nil
        end

        def freeze
          json_rpc_methods.freeze
          super
        end
      end

      module RequestMethods
        # Dispatch the request body as a JSON-RPC 2.0 request or batch. Valid
        # notifications halt with 204 and an empty body; all other valid RPC
        # requests halt with a JSON response body.
        def json_rpc
          dispatcher = JsonRpcDispatcher.new(
            roda_class.json_rpc_methods,
            roda_class.json_rpc_parser,
            roda_class.json_rpc_serializer,
            roda_class.json_rpc_notification_error_handler
          )
          result = dispatcher.dispatch(_json_rpc_request_body)

          if result.nil?
            response.status = 204
            response.headers.delete(RodaResponseHeaders::CONTENT_TYPE)
            throw :halt, response.finish
          end

          response.status = 200
          response[RodaResponseHeaders::CONTENT_TYPE] = roda_class.json_rpc_content_type
          response.write(result)
          throw :halt, response.finish
        end
        private

        def _json_rpc_request_body
          input = @env["rack.input"]
          input ? input.read : String.new
        end
      end

      # Internal dispatcher. It is kept as a plain object so method lookup uses
      # only the explicit registry and never Object#method or public_send.
      class JsonRpcDispatcher
        def initialize(methods, parser, serializer, notification_error_handler)
          @methods = methods
          @parser = parser
          @serializer = serializer
          @notification_error_handler = notification_error_handler
        end

        def dispatch(body)
          begin
            request = parse_request(body)
          rescue ParseError => error
            return serialize(error_response(nil, error))
          end

          if request.is_a?(Array)
            dispatch_batch(request)
          else
            response = dispatch_member(request)
            serialize(response) unless response.nil?
          end
        end

        private

        def parse_request(body)
          @parser.call(body)
        rescue StandardError, ScriptError
          raise ParseError.new
        end

        def dispatch_batch(requests)
          return serialize(error_response(nil, InvalidRequestError.new)) unless valid_batch?(requests)

          responses = []
          requests.each do |request|
            response = dispatch_member(request)
            responses << response unless response.nil?
          end

          return nil if responses.empty?
          serialize(responses)
        end

        def dispatch_member(request)
          notification = valid_request?(request) && !request.key?("id")

          unless valid_request?(request)
            return error_response(nil, InvalidRequestError.new)
          end

          name = request["method"]
          id = request["id"]
          handler = @methods[name]

          unless handler
            return nil if notification
            return error_response(id, MethodNotFoundError.new)
          end

          arguments = JsonRpcArguments.new(handler, request["params"])
          arguments.bind

          result = invoke(handler, arguments)
          return nil if notification
          success_response(id, result)
        rescue InvalidParamsError
          if notification
            report_notification_error($!)
          end
          return nil if notification
          error_response(id_for(request), $!)
        rescue StandardError => error
          handle_internal_error(request, notification, error)
        end

        if RUBY_VERSION >= "2.7"
          def invoke(handler, arguments)
            handler.call(*arguments.positional, **arguments.keywords)
          end
        # simplecov:disable
        else
          def invoke(handler, arguments)
            if arguments.keywords.empty?
              handler.call(*arguments.positional)
            else
              handler.call(*arguments.positional, **arguments.keywords)
            end
          end
        end
        # simplecov:enable

        def handle_internal_error(request, notification, error)
          if notification
            report_notification_error(error)
            nil
          else
            error_response(id_for(request), InternalError.new)
          end
        end

        def report_notification_error(error)
          return unless @notification_error_handler
          begin
            @notification_error_handler.call(error)
          rescue StandardError
          end
        end

        def valid_batch?(requests)
          requests.is_a?(Array) && !requests.empty?
        end

        def valid_request?(request)
          return false unless request.is_a?(Hash)
          return false unless request[VERSION_KEY] == VERSION
          return false unless request["method"].is_a?(String)
          return false unless !request.key?("params") || valid_params?(request["params"])
          return false unless !request.key?("id") || valid_id?(request["id"])
          true
        end

        def valid_params?(params)
          params.is_a?(Array) || params.is_a?(Hash)
        end

        def valid_id?(id)
          id.nil? || id.is_a?(String) || id.is_a?(Numeric)
        end

        def id_for(request)
          request.is_a?(Hash) ? request["id"] : nil
        end

        def success_response(id, result)
          {
            VERSION_KEY => VERSION,
            "result" => result,
            "id" => id
          }
        end

        def error_response(id, error)
          {
            VERSION_KEY => VERSION,
            "error" => {
              "code" => error.code,
              "message" => error.message
            },
            "id" => id
          }
        end

        def serialize(response)
          @serializer.call(response)
        end

        VERSION_KEY = "jsonrpc".freeze
      end

      # Binds JSON-RPC array or object parameters to a Ruby callable. Binding
      # errors raise InvalidParamsError before the method body is entered, so an
      # ArgumentError raised inside a method remains an internal error.
      class JsonRpcArguments
        attr_reader :positional, :keywords

        def initialize(handler, params)
          @handler = handler
          @params = params || {}
          @positional = []
          @keywords = {}
        end

        def bind
          if @params.is_a?(Array)
            bind_positional_array
          else
            reject_duplicate_named_params
            bind_named_params
          end
          self
        end

        private

        def bind_positional_array
          parameters = callable_parameters
          required = 0
          optional = 0
          rest = false

          parameters.each do |type, name|
            case type
            when :req
              required += 1
            when :opt
              optional += 1
            when :rest
              rest = true unless name.nil?
            when :keyreq
              invalid_params!
            end
          end

          if @params.length < required
            invalid_params!
          end
          if !rest && @params.length > required + optional
            invalid_params!
          end

          @positional = @params.dup
        end

        def bind_named_params
          parameters = callable_parameters
          consumed = {}
          omitted_positional = false

          parameters.each do |type, name|
            case type
            when :req, :opt
              next if name.nil?
              if supplied?(name)
                invalid_params! if type == :opt && omitted_positional
                @positional << parameter_value(name, consumed)
              elsif type == :req
                invalid_params!
              else
                omitted_positional = true
              end
            when :rest
              if name && supplied?(name)
                invalid_params! if omitted_positional
                value = parameter_value(name, consumed)
                invalid_params! unless value.is_a?(Array)
                @positional.concat(value)
              end
            when :keyreq
              invalid_params! unless supplied?(name)
              @keywords[name] = parameter_value(name, consumed) if supplied?(name)
            when :key
              @keywords[name] = parameter_value(name, consumed) if supplied?(name)
            when :keyrest
              @keyrest = true
            end
          end

          unless @keyrest
            @params.each_key do |key|
              normalized = normalized_key_name(key)
              invalid_params! unless consumed[normalized]
            end
          else
            @params.each do |key, value|
              normalized = normalized_key_name(key)
              next if consumed[normalized]
              @keywords[key.to_sym] = value
            end
          end
        end

        def supplied?(name)
          string_name = name.to_s
          symbol_name = name.to_sym
          @params.key?(string_name) || @params.key?(symbol_name)
        end

        def reject_duplicate_named_params
          names = {}
          @params.each_key do |key|
            normalized = key.is_a?(Symbol) ? key.to_s : key
            invalid_params! if names.key?(normalized)
            names[normalized] = true
          end
        end

        def parameter_value(name, consumed)
          string_name = name.to_s
          if @params.key?(string_name)
            consumed[string_name] = true
            @params[string_name]
          else
            symbol_name = name.to_sym
            consumed[string_name] = true
            @params[symbol_name]
          end
        end

        def normalized_key_name(key)
          case key
          when String
            key
          when Symbol
            key.to_s
          else
            invalid_params!
          end
        end

        def callable_parameters
          @handler.parameters
        end

        def invalid_params!
          raise InvalidParamsError.new
        end
      end

      private_constant :JsonRpcDispatcher, :JsonRpcArguments
    end

    register_plugin(:json_rpc, JsonRpc)
    register_plugin(:jsonrpc, JsonRpc)
  end
end
