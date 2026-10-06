# frozen-string-literal: true

require 'json'

class Roda
  module RodaPlugins
    # The siren plugin adds support for expressing backend resources as
    # Siren hypermedia entities (https://github.com/kevinswiber/siren), served
    # with the application/vnd.siren+json content type.
    #
    # It covers both sides of the representation contract:
    #
    # entities :: Return a Siren entity from a route block using
    #            <tt>r.siren_entity</tt> and it is serialized automatically.
    #            Entities can have a +class+, +properties+, navigational
    #            +links+, embedded sub-entities (both represented and linked),
    #            and available +actions+.
    # actions :: Shared action definitions are registered with the class-level
    #            +siren_action+ DSL.  Each action contains a list of typed
    #            fields.  The same field definitions are used when rendering the
    #            action and when decoding a submission with
    #            <tt>r.siren_submission</tt>, so the client and the server agree
    #            on the shape of the data.
    #
    # Example:
    #
    #   plugin :siren
    #
    #   siren_action "add-order-item" do
    #     method "POST"
    #     href   "/orders/1/items"
    #     field  "sku", type: "text"
    #     field  "quantity", type: "number"
    #     field  "tags", type: "text", multiple: true
    #     field  "gift_wrap", type: "checkbox"
    #   end
    #
    #   route do |r|
    #     r.get "orders", Integer do |id|
    #       r.siren_entity do
    #         klass "order"
    #         properties id: id, total: 42.5
    #
    #         link rel: "self", href: "/orders/#{id}"
    #
    #         entity rel: ["item"], href: "/items/3", klass: "item"
    #         entity rel: ["item"] do
    #           klass "item"
    #           properties sku: "ABC"
    #           action "add-order-item"
    #         end
    #
    #         action "add-order-item"
    #       end
    #     end
    #
    #     r.post "orders", Integer, "items" do
    #       values = r.siren_submission("add-order-item")
    #       values.inspect
    #     end
    #   end
    #
    # Typed field decoding distinguishes three submission states:
    #
    # absent :: The key is not part of the submission at all.  Checkbox fields
    #           decode as +false+, +multiple+ fields decode as an empty array,
    #           and all other fields are omitted from the decoded hash.
    # explicit null :: The key is present with a JSON +null+ (or an empty value
    #           for a +multiple+ field).  Checkbox and +multiple+ fields decode
    #           as +nil+ when given an explicit null.
    # present :: The key is present with a value, which is decoded according to
    #           the field type (+number+, +integer+, +checkbox+, single/multiple
    #           select, and so on).
    #
    # Navigational links, embedded sub-entities, and actions are always kept in
    # separate sections of the Siren document; the plugin never places an action
    # target into the links section.
    #
    # This plugin only handles the representation contract.  It does not define
    # any database models or persistence behavior.
    module Siren
      CONTENT_TYPE = 'application/vnd.siren+json'.freeze

      # Default handler used when a submission cannot be decoded (bad JSON body,
      # value that does not match the declared type, and so on).  Halts with 400.
      DEFAULT_ERROR_HANDLER = proc{|r| r.halt [400, {}, []]}

      MATCH_METHOD = RUBY_VERSION >= '2.4' ? :match? : :match
      private_constant :MATCH_METHOD

      # Regexp matching JSON request bodies, including the siren content type.
      JSON_CONTENT_TYPE_REGEXP = /\Aapplication\/(?:vnd\.siren\+)?json\b/i
      private_constant :JSON_CONTENT_TYPE_REGEXP

      # Raised when a Siren action submission cannot be decoded.
      class Error < StandardError; end

      # Raised when an unknown Siren action is referenced.
      class UnknownAction < Error
        def initialize(name)
          super("unknown siren action: #{name.inspect}")
        end
      end

      def self.load_dependencies(app, opts=RodaPlugins::OPTS)
        app.plugin :custom_block_results
      end

      # Options:
      # :parser :: A callable used to parse JSON submission bodies.  Receives
      #            the request body string and returns the parsed data.  Defaults
      #            to +JSON.method(:parse)+.
      # :error_handler :: A proc called with the request object when a
      #                   submission cannot be decoded.  It should halt the
      #                   request.  By default it halts with a 400 response.
      # :content_type_regexp :: Regexp used to detect JSON request bodies when
      #                         decoding submissions.  Defaults to accepting both
      #                         application/json and application/vnd.siren+json.
      def self.configure(app, opts=RodaPlugins::OPTS)
        unless app.opts[:siren_actions]
          app.opts[:siren_actions] = {}

          [SirenEntity, SubEntity, LinkedSubEntity].each do |klass|
            app.handle_block_result(klass) do |entity|
              @_response[RodaResponseHeaders::CONTENT_TYPE] ||= CONTENT_TYPE
              entity.to_json
            end
          end
        end

        app.opts[:siren_parser] = opts[:parser] if opts.has_key?(:parser)
        if opts.has_key?(:error_handler)
          app.opts[:siren_error_handler] = opts[:error_handler]
        end
        if opts.has_key?(:content_type_regexp)
          app.opts[:siren_content_type_regexp] = opts[:content_type_regexp]
        end
      end

      # A single typed field in a Siren action.  Field definitions drive both
      # action rendering and submission decoding.
      class FieldDefinition
        # The field name, rendered as the Siren field +name+.
        attr_reader :name

        # The Siren field type (+text+, +number+, +checkbox+, ...).
        attr_reader :type

        # Whether the field accepts multiple values (rendered as +multiple+).
        attr_reader :multiple

        # Whether the checkbox field is checked by default.
        attr_reader :checked

        # The selectable option values, rendered as a Siren +options+ array.
        attr_reader :options

        def initialize(name, opts=RodaPlugins::OPTS)
          @name = name.to_s
          @type = opts[:type] ? opts[:type].to_s : nil
          @title = opts[:title]
          @value = opts[:value] if opts.has_key?(:value)
          @multiple = opts[:multiple] ? true : false
          @checked = opts[:checked] ? true : false
          @options = normalize_options(opts[:options]) if opts.has_key?(:options)
        end

        # Render the field as the Siren field hash.
        def to_h
          h = {"name" => @name}
          h["type"] = @type if @type
          h["title"] = @title if @title
          h["value"] = @value if defined?(@value)
          h["options"] = @options if @options
          h["multiple"] = true if @multiple
          h["checked"] = true if @checked
          h
        end

        # Decode the raw submitted value for this field. +raw_present+ indicates
        # whether the key was part of the submission at all, which is what allows
        # absent checkboxes to be distinguished from explicit null values.
        def decode(raw, raw_present)
          if @type == "checkbox"
            decode_checkbox(raw, raw_present)
          elsif @multiple
            decode_multiple(raw, raw_present)
          else
            return nil unless raw_present
            value = cast(raw)
            validate_option(value)
            value
          end
        end

        private

        # An unchecked checkbox is omitted by HTML form submissions, so an absent
        # key means false.  An explicit null means the client knowingly sent no
        # value and stays nil.
        def decode_checkbox(raw, raw_present)
          return false unless raw_present
          return nil if raw.nil?

          checked = truthy_checkbox?(raw)
          if checked && defined?(@value)
            @value
          else
            checked
          end
        end

        # A multiple field maps absence to an empty array, explicit null to nil,
        # an array to its decoded members, and a scalar to a one element array.
        def decode_multiple(raw, raw_present)
          return [] unless raw_present
          return nil if raw.nil?

          values = raw.is_a?(Array) ? raw : [raw]
          values.map!{|value| cast(value)}
          values.each{|value| validate_option(value)}
          values
        end

        def truthy_checkbox?(raw)
          case raw
          when true then true
          when false, nil then false
          when "true", "on", "1", "checked" then true
          when "false", "off", "0", "" then false
          else
            !!(raw && (!raw.respond_to?(:empty?) || !raw.empty?))
          end
        end

        # Convert a raw scalar value according to the declared field type.
        def cast(raw)
          return raw if raw.nil?

          case @type
          when "number"
            begin
              Float(raw)
            rescue ArgumentError, TypeError
              raise Error, "invalid number submitted for field #{@name.inspect}: #{raw.inspect}"
            end
          when "integer"
            begin
              Integer(raw)
            rescue ArgumentError, TypeError
              raise Error, "invalid integer submitted for field #{@name.inspect}: #{raw.inspect}"
            end
          when "checkbox"
            truthy_checkbox?(raw)
          else
            raw
          end
        end

        def validate_option(value)
          return unless @options && !value.nil?
          allowed = @options.any? do |option|
            option_value = option["value"]
            option_value.equal?(value) || option_value == value
          end
          unless allowed
            message = "value #{value.inspect} is not an allowed option for field #{@name.inspect}"
            raise Error, message
          end
        end

        # Siren options are hashes with value/title keys.  Plain values are
        # accepted in the DSL and expanded into {"value" => value}.
        def normalize_options(options)
          Array(options).map do |option|
            case option
            when Hash
              h = {}
              option.each{|k, v| h[k.to_s] = v}
              h
            else
              {"value" => option}
            end
          end
        end
      end

      # A registered or inline action definition, independent of a request.
      class ActionDefinition
        attr_accessor :name, :method_name, :media_type

        def initialize(name)
          @name = name.to_s
          @method_name = "GET"
          @media_type = "application/x-www-form-urlencoded"
          @fields = []
        end

        # DSL used by both the class-level +siren_action+ block and inline
        # action blocks passed to <tt>entity.action</tt>.
        def field(name, opts=RodaPlugins::OPTS)
          @fields << FieldDefinition.new(name, opts)
          self
        end

        def method(name)
          @method_name = name.to_s.upcase
          self
        end

        def type(media_type)
          @media_type = media_type
          self
        end

        # DSL accessor.  With a string argument it sets a static href, with a
        # block it sets a proc evaluated in request scope, and with nothing it
        # returns the configured href.
        def href(value=nil, &block)
          if block
            @href = block
            self
          elsif value
            @href = value
            self
          else
            @href
          end
        end

        # DSL accessor.  With an argument it sets the title, without one it
        # returns it.
        def title(title=nil)
          if title
            @title = title
            self
          else
            @title
          end
        end

        # Render the action as the Siren action hash. +resolved_href+ is the
        # href after evaluating any request level proc.
        def to_action(resolved_href)
          h = {"name" => @name, "href" => resolved_href}
          h["title"] = @title if @title
          h["method"] = @method_name if @method_name
          h["type"] = @media_type if @media_type
          h["fields"] = @fields.map(&:to_h) unless @fields.empty?
          h
        end

        # Decode a raw submitted hash into Ruby values using the action fields.
        def decode(raw_submission)
          decoded = {}
          @fields.each do |field|
            key = field.name
            present = raw_submission.has_key?(key)
            next unless present || field.type == "checkbox" || field.multiple
            decoded[key] = field.decode(raw_submission[key], present)
          end
          decoded
        end

        # Duplicate the definition including its fields, used when an inline
        # block customizes a registered action for a single request.
        def initialize_copy(_)
          super
          @fields = @fields.map(&:dup)
        end
      end

      # Base class for all Siren entities, so route blocks returning one are
      # automatically serialized.  SirenEntity is a represented root entity,
      # SubEntity is a full embedded entity, and LinkedSubEntity is an embedded
      # link to another entity.
      module SirenJson
        def to_json(*)
          ::JSON.generate(to_h)
        end
      end

      class SirenEntity
        include SirenJson

        def initialize
          @classes = []
          @properties = nil
          @links = []
          @entities = []
          @actions = []
          @title = nil
        end

        # Writable entity title, used by the entity DSL.
        attr_writer :title

        # Render the entity as a Siren compliant hash.
        def to_h
          h = {}
          h["class"] = @classes unless @classes.empty?
          h["title"] = @title if @title
          h["properties"] = @properties if @properties
          h["entities"] = @entities unless @entities.empty?
          h["links"] = @links unless @links.empty?
          h["actions"] = @actions unless @actions.empty?
          h
        end

      end

      # A fully represented embedded sub-entity (+rel+ plus an entity body).
      class SubEntity < SirenEntity
        attr_accessor :rels

        def to_h
          h = {"rel" => @rels}
          h.merge!(super)
          h
        end
      end

      # An embedded sub-entity expressed as a link (+rel+, +href+, optional
      # +class+) rather than an inline representation.
      class LinkedSubEntity
        include SirenJson

        def initialize(rels, href, classes)
          @rels = rels
          @href = href
          @classes = classes
        end

        def to_h
          h = {"rel" => @rels, "href" => @href}
          h["class"] = @classes unless @classes.empty?
          h
        end
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :siren_content_type_regexp)

        # The proc called when a submission cannot be decoded.
        def siren_error_handler!
          @opt_siren_error_handler || DEFAULT_ERROR_HANDLER
        end

        # Regexp used to detect JSON bodies in submissions.
        def siren_content_type_regexp_or_default
          @opt_siren_content_type_regexp || JSON_CONTENT_TYPE_REGEXP
        end

        # The callable used to parse JSON submission bodies.
        def siren_parser
          @opt_siren_parser || ::JSON.method(:parse)
        end

        # Hash of registered Siren action definitions keyed by action name.
        def siren_actions
          opts[:siren_actions]
        end

        # Register a named Siren action.  The block uses the
        # RodaPlugins::Siren::ActionDefinition DSL (+method+, +href+, +type+,
        # +field+).  +href+ may be a string or a proc evaluated in request
        # scope, which allows route captures to be used:
        #
        #   siren_action "add-item" do
        #     method "POST"
        #     href { "/orders/#{captures[0]}/items" }
        #     field "sku", type: "text"
        #   end
        def siren_action(name, &block)
          definition = ActionDefinition.new(name)
          definition.instance_exec(&block)
          siren_actions[definition.name] = definition
          definition
        end

        # Freeze the action registry when freezing the app.
        def freeze
          siren_actions.freeze
          super
        end
      end

      module RequestMethods
        # Build a Siren root entity.  The block is evaluated using the entity
        # DSL (+klass+, +properties+, +link+, +entity+, +action+).  Returns the
        # built RodaPlugins::Siren::SirenEntity, which is serialized
        # automatically when returned from a route block.
        def siren_entity(&block)
          entity = SirenEntity.new
          SirenEntityDSL.new(entity, self).instance_exec(&block)
          entity
        end

        # Resolve a Siren action for rendering inside an entity.  If a block is
        # given it is evaluated against a copy of the registered action (or a
        # brand new action when no registered action exists), allowing request
        # specific hrefs or extra fields:
        #
        #   r.siren_action("add-item")
        #   r.siren_action("add-item") { href "/orders/#{id}/items" }
        def siren_action(name, &block)
          definition = resolve_siren_action(name, block)
          render_siren_action(definition)
        end

        # Decode a Siren action submission using the named action's typed
        # fields.  Parses JSON or form bodies and returns a hash of decoded
        # Ruby values keyed by field name.
        #
        # A block can be given instead of a name to use an ad hoc action
        # definition for decoding.
        def siren_submission(name=nil, &block)
          definition = resolve_siren_action(name, block)
          raw = raw_siren_submission
          definition.decode(raw)
        rescue Error
          roda_class.siren_error_handler!.call(self)
          raise
        end

        private

        # Look up a registered action, copy it, and apply the optional inline
        # block to the copy.
        def resolve_siren_action(name, block)
          if name.nil?
            raise ArgumentError, "siren action name or block required" unless block
            return ActionDefinition.new("inline").tap{|definition| definition.instance_exec(&block)}
          end

          key = name.to_s
          registered = roda_class.siren_actions[key] or raise UnknownAction.new(key)
          definition = registered.dup
          definition.instance_exec(&block) if block
          definition
        end

        # Evaluate an action definition's href and return its rendered hash.
        # href procs run in request scope so route captures are available.
        def render_siren_action(definition)
          href = definition.href
          href = instance_exec(&href) if href.respond_to?(:call)
          definition.to_action(href)
        end

        # Return the raw submitted values, parsing the request body as JSON for
        # JSON/siren content types and using POST params otherwise.
        def raw_siren_submission
          content_type = self.content_type
          if @env["REQUEST_METHOD"] == "GET" || @env["REQUEST_METHOD"] == "HEAD"
            self.GET.dup
          elsif content_type &&
                roda_class.siren_content_type_regexp_or_default.send(MATCH_METHOD, content_type)
            parse_siren_json_body
          else
            self.POST.dup
          end
        end

        def parse_siren_json_body
          input = @env["rack.input"]
          return {} unless input

          str = read_siren_input(input)
          return {} if str.nil? || str.empty?

          begin
            parsed = roda_class.siren_parser.call(str)
          rescue
            raise Error, "unable to parse siren action submission body"
          end

          unless parsed.is_a?(Hash)
            raise Error, "siren action submission body must be a JSON object"
          end
          parsed
        end

        if Rack.release >= '3'
          def read_siren_input(input)
            input.read
          end
        else
          def read_siren_input(input)
            input.rewind
            str = input.read
            input.rewind
            str
          end
        end
      end

      # DSL available inside an +r.siren_entity+ block.  The +entity+ method
      # nests another DSL for embedded represented entities.
      class SirenEntityDSL
        def initialize(entity, request)
          @entity = entity
          @request = request
          init_entity(entity)
        end

        # Set the Siren +class+ array.  Accepts one or more class names.
        def klass(*classes)
          @entity_classes.concat(classes.flatten.map(&:to_s))
          self
        end

        # Set (or merge into) the entity +properties+ hash.
        def properties(hash=RodaPlugins::OPTS)
          @entity_properties ||= @entity.instance_variable_set(:@properties, {})
          @entity_properties.merge!(hash)
          self
        end

        # Set the entity +title+.
        def title(title)
          @entity.title = title
          self
        end

        # Add a navigational Siren link:
        #
        #   link rel: "self", href: "/orders/1"
        #   link rel: ["order", "collection"], href: "/orders"
        #
        # Links are rendered only in the entity's +links+ section; action
        # targets must use #action and embedded links must use #entity.
        def link(opts)
          link = {"rel" => normalize_rels(opts[:rel]), "href" => opts[:href]}
          link["title"] = opts[:title] if opts.has_key?(:title)
          link["type"] = opts[:type] if opts.has_key?(:type)
          @entity_links << link
          self
        end

        # Add an embedded sub-entity.  With a block this is a fully represented
        # sub-entity:
        #
        #   entity rel: "item" do
        #     klass "order-item"
        #     properties sku: "ABC"
        #   end
        #
        # Without a block (when +href+ is given) this is an embedded link:
        #
        #   entity rel: ["item"], href: "/items/3", klass: "item"
        def entity(opts=RodaPlugins::OPTS, &block)
          rels = normalize_rels(opts[:rel])

          if block
            sub_entity = SubEntity.new
            sub_entity.rels = rels
            classes = Array(opts[:klass]).map(&:to_s)
            SirenEntityDSL.new(sub_entity, @request).instance_exec(&block)
            sub_entity.instance_variable_get(:@classes).concat(classes)
            @entity_entities << sub_entity
          else
            classes = Array(opts[:klass]).map(&:to_s)
            @entity_entities << LinkedSubEntity.new(rels, opts[:href], classes)
          end
          self
        end

        # Add a Siren action.  Uses a registered action definition, optionally
        # customized with a block.  Actions are rendered only in the +actions+
        # section, never as links.
        def action(name, &block)
          @entity_actions << @request.send(:siren_action, name, &block)
          self
        end

        private

        def init_entity(entity)
          @entity_classes = entity.instance_variable_get(:@classes)
          @entity_properties = nil
          @entity_links = entity.instance_variable_get(:@links)
          @entity_entities = entity.instance_variable_get(:@entities)
          @entity_actions = entity.instance_variable_get(:@actions)
        end

        def normalize_rels(rels)
          Array(rels).flatten.map(&:to_s)
        end
      end

    end
  end
end

Roda::RodaPlugins.register_plugin(:siren, Roda::RodaPlugins::Siren)
