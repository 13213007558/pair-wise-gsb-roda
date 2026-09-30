# frozen_string_literal: true

class Roda
  module RodaPlugins
    # The json_rpc plugin provides an optional JSON-RPC 2.0 endpoint.
    # Methods must be registered explicitly before they can be dispatched:
    #
    #   class App < Roda
    #     plugin :json_rpc
    #
    #     json_rpc_method(:add) do |a, b|
    #       a + b
    #     end
    #
    #     route do |r|
    #       r.post 'rpc' do
    #         r.json_rpc
    #       end
    #     end
    #   end
    #
    # External callable objects can also be registered. The registry does not
    # expose arbitrary methods by name, so only registered methods are callable.
    # Both JSON-RPC positional and named parameters are supported, including
    # binding named parameters to Ruby keyword arguments.
    module JsonRpc
      PARSE_ERROR = -32700
      INVALID_REQUEST = -32600
      METHOD_NOT_FOUND = -32601
      INVALID_PARAMS = -32602
      INTERNAL_ERROR = -32603

      InvalidParameters = Class.new(Exception)

      def self.load_dependencies(app, opts=OPTS)
        app.plugin :_json
      end

      # Options:
      # :parser :: Object responding to call(str) used to parse JSON.
      # :serializer :: Object responding to call(object) used for responses.
      # :error_handler :: Callable that receives exceptions raised while
      #                   invoking notification methods. Notifications have no
      #                   client response.
      def self.configure(app, opts=OPTS)
        app.opts[:json_rpc_methods] ||= {}
        app.opts[:json_rpc_parser] = opts[:parser] || app.json_rpc_parser || app.json_parser
        app.opts[:json_rpc_serializer] = opts[:serializer] || app.json_rpc_serializer || app.json_serializer
        app.opts[:json_rpc_error_handler] = opts[:error_handler] || app.json_rpc_error_handler
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :json_rpc_methods)
        RodaPlugins.opt_attr_reader(self, :json_rpc_parser)
        RodaPlugins.opt_attr_reader(self, :json_rpc_serializer)
        RodaPlugins.opt_attr_reader(self, :json_rpc_error_handler)

        def inherited(subclass)
          super
          subclass.opts[:json_rpc_methods] = json_rpc_methods.dup
        end

        def freeze
          json_rpc_methods.freeze
          super
        end

        # Register a JSON-RPC method. Blocks run in the Roda routing scope.
        # Other callables are invoked directly.
        def json_rpc_method(name, callable=nil, &block)
          callable ||= block
          unless callable.respond_to?(:call)
            raise RodaError, "JSON-RPC method #{name.inspect} must be callable"
          end

          method_name = name.to_s
          previous = json_rpc_methods[method_name]
          if previous.is_a?(Symbol) && private_instance_methods(false).include?(previous)
            remove_method(previous)
          end

          json_rpc_methods[method_name] = if block
            method_name = roda_method_name("json_rpc_method")
            define_method(method_name, &block)
            private method_name
            alias_method method_name, method_name
            method_name
          else
            callable
          end
        end
      end

      # Validates JSON-RPC parameters against a Proc or Method signature and
      # only then invokes it. This keeps ArgumentError raised inside the
      # method separate from JSON-RPC parameter binding errors.
      class Binder
        def initialize(callable)
          @callable = callable
          @required = []
          @optional_names = []
          @rest = false
          @required_keywords = []
          @optional_keywords = []
          @keyword_rest = false

          callable.parameters.each do |type, name|
            case type
            when :req
              @required << name
            when :opt
              @optional_names << name
            when :rest
              @rest = true
            when :keyreq
              @required_keywords << name
            when :key
              @optional_keywords << name
            when :keyrest
              @keyword_rest = true
            end
          end
        end

        def call(params)
          case params
          when Array
            call_with_positional_parameters(params)
          when Hash
            call_with_named_parameters(params)
          else
            raise_invalid_parameters
          end
        end

        private

        def call_with_positional_parameters(arguments)
          minimum = @required.length
          maximum = minimum + @optional_names.length unless @rest
          if arguments.length < minimum || (maximum && arguments.length > maximum)
            raise_invalid_parameters
          end

          @callable.call(*arguments)
        end

        def call_with_named_parameters(parameters)
          values = positional_values(parameters)
          raise_invalid_parameters unless parameters.length == values.length
          arguments = positional_arguments(values)
          keywords = keyword_arguments(values)
          raise_invalid_parameters unless arguments && keywords

          @callable.call(*arguments, **keywords)
        end

        def positional_values(parameters)
          values = {}
          @required.each do |name|
            values[name] = parameters[name.to_s] if name && parameters.key?(name.to_s)
          end

          @optional_names.each do |name|
            values[name] = parameters[name.to_s] if name && parameters.key?(name.to_s)
          end

          @required_keywords.each do |name|
            values[name] = parameters[name.to_s] if parameters.key?(name.to_s)
          end

          @optional_keywords.each do |name|
            values[name] = parameters[name.to_s] if parameters.key?(name.to_s)
          end

          if @keyword_rest
            parameters.each do |name, value|
              values[name.to_sym] = value
            end
          end

          values
        end

        def positional_arguments(values)
          arguments = []

          @required.each do |name|
            return unless name && values.key?(name)
            arguments << values.delete(name)
          end

          @optional_names.each_with_index do |name, index|
            next unless values.key?(name)
            return if index > 0 && @optional_names[0...index].any? { |previous_name| !values.key?(previous_name) }
            arguments << values.delete(name)
          end

          arguments
        end

        def keyword_arguments(values)
          keywords = {}

          @required_keywords.each do |name|
            return unless values.key?(name)
            keywords[name] = values.delete(name)
          end

          @optional_keywords.each do |name|
            keywords[name] = values.delete(name) if values.key?(name)
          end

          if @keyword_rest
            values.each { |name, value| keywords[name] = value }
            values.clear
          end

          keywords if values.empty?
        end

        def raise_invalid_parameters
          raise InvalidParameters
        end
      end

      module RequestMethods
        # Dispatch the request body using the JSON-RPC 2.0 protocol.
        def json_rpc
          request_data = begin
            roda_class.json_rpc_parser.call(_json_rpc_read_body)
          rescue StandardError
            throw :halt, _json_rpc_finish(_json_rpc_error(PARSE_ERROR, "Parse error"))
          end

          notification_errors = []
          result = if request_data.is_a?(Array)
            _json_rpc_batch(request_data, notification_errors)
          else
            _json_rpc_request(request_data, notification_errors)
          end

          notification_errors.each do |error|
            _json_rpc_notification_error(error)
          end

          if result
            throw :halt, _json_rpc_finish(result)
          else
            throw :halt, [204, {}, []]
          end
        end

        private

        def _json_rpc_read_body
          input = @env["rack.input"]
          body = input.read if input
          input.rewind if input.respond_to?(:rewind)
          body.to_s
        end

        def _json_rpc_batch(requests, notification_errors)
          return _json_rpc_error(INVALID_REQUEST, "Invalid Request") if requests.empty?

          responses = requests.map do |request|
            _json_rpc_request(request, notification_errors)
          end.compact
          responses unless responses.empty?
        end

        def _json_rpc_request(request, notification_errors=[])
          return _json_rpc_error(INVALID_REQUEST, "Invalid Request") unless valid_json_rpc_request?(request)

          id = request["id"]
          notification = !request.key?("id")
          callable = roda_class.json_rpc_methods[request["method"]]

          unless callable
            return if notification
            return _json_rpc_error(METHOD_NOT_FOUND, "Method not found", id)
          end

          result = _json_rpc_invoke(callable, request.fetch("params", []))
          return if notification
          {"jsonrpc" => "2.0", "result" => result, "id" => id}
        rescue InvalidParameters
          return if notification
          _json_rpc_error(INVALID_PARAMS, "Invalid params", id)
        rescue StandardError => error
          notification_errors << error if notification
          return if notification
          _json_rpc_error(INTERNAL_ERROR, "Internal error", id)
        end

        def valid_json_rpc_request?(request)
          request.is_a?(Hash) &&
            request["jsonrpc"] == "2.0" &&
            request["method"].is_a?(String) &&
            (!request.key?("params") || request["params"].is_a?(Array) || request["params"].is_a?(Hash)) &&
            (!request.key?("id") || request["id"].is_a?(String) || request["id"].is_a?(Integer) || request["id"].nil?)
        end

        def _json_rpc_invoke(callable, params)
          reflection = if callable.is_a?(Symbol)
            scope.method(callable)
          elsif callable.respond_to?(:parameters)
            callable
          else
            callable.method(:call)
          end

          Binder.new(reflection).call(params)
        end

        def _json_rpc_error(code, message, id=nil)
          {"jsonrpc" => "2.0", "error" => {"code" => code, "message" => message}, "id" => id}
        end

        def _json_rpc_finish(payload)
          response.status = 200
          response[RodaResponseHeaders::CONTENT_TYPE] = "application/json"
          response.write(roda_class.json_rpc_serializer.call(payload))
          response.finish
        end

        def _json_rpc_notification_error(error)
          hook = roda_class.json_rpc_error_handler
          hook.call(error) if hook
        end
      end
    end

    register_plugin(:json_rpc, JsonRpc)
  end
end
