# frozen-string-literal: true

require 'date'
require 'time'

class Roda
  module RodaPlugins
    # The siren plugin allows routes to return entities using the
    # {Siren hypermedia format}[https://github.com/kevinswiber/siren],
    # served with the +application/vnd.siren+json+ content type.  The
    # plugin only handles the representation contract; it does not add
    # any database models or other persistence behavior.
    #
    # Entities are built with the +siren_entity+ method, and are
    # automatically converted to JSON when used as the return value of
    # a route block:
    #
    #   plugin :siren
    #
    #   route do |r|
    #     r.on "orders", Integer do |id|
    #       r.get true do
    #         siren_entity(:class=>['order'], :properties=>{'id'=>id, 'status'=>'open'}) do |order|
    #           order.link(:rel=>['self'], :href=>"/orders/#{id}")
    #           order.link(:rel=>['documentation'], :href=>"/docs/orders", :type=>'text/html')
    #
    #           order.entity(:rel=>['customer'], :class=>['customer'], :properties=>{'name'=>'Alice'})
    #           order.entity(:rel=>['item'], :class=>['item'], :href=>"/items/9")
    #
    #           order.action(update_order_action(id))
    #         end
    #       end
    #
    #       r.post "update" do
    #         values = siren_decode(update_order_action(id))
    #         # ...
    #       end
    #     end
    #   end
    #
    # == Links and Actions
    #
    # Links and actions are kept in separate collections, and are
    # serialized to separate +links+ and +actions+ keys in the siren
    # representation.  Use links for navigation, such as +self+ and
    # +documentation+ relations, and use actions for operations the
    # client can perform on the entity.  Documentation links and
    # action links should not be mixed: clients look up documentation
    # by link relation in +links+, and operations by action name in
    # +actions+.
    #
    # == Sub-entities
    #
    # Embedded sub-entities are added with +entity+ on an entity.  A
    # sub-entity can be an embedded representation (with its own class,
    # properties, links, and actions), or an embedded link (with only
    # +rel+, +class+, and +href+).  Sub-entities must have a +rel+
    # option describing their relation to the parent entity.
    #
    # == Actions and Typed Fields
    #
    # Actions are built with +siren_action+ (or +action+ on an entity),
    # and define typed fields using +field+:
    #
    #   def update_order_action(id)
    #     siren_action(:name=>'update-order', :method=>'POST',
    #                  :href=>"/orders/#{id}/update", :type=>'application/json') do |action|
    #       action.field(:name=>'status', :type=>'text')
    #       action.field(:name=>'quantity', :type=>'number')
    #       action.field(:name=>'tags', :type=>'select', :multiple=>true)
    #       action.field(:name=>'gift_wrap', :type=>'checkbox')
    #       action.field(:name=>'note', :type=>'text', :nullable=>true)
    #     end
    #   end
    #
    # The same action field definitions used to generate the siren
    # representation are also used to decode submissions, via
    # +siren_decode+ (or Action#decode with a params hash):
    #
    #   values = siren_decode(update_order_action(id))
    #
    # +siren_decode+ uses the request body parsed as JSON if the
    # request's content type includes +json+, and uses the request's
    # form params otherwise.  It returns a hash keyed by field name
    # symbol, with values converted to Ruby objects based on the field
    # types:
    #
    # +number+ :: Integer for integral values, Float for other numeric values
    # +range+ :: Integer
    # +checkbox+ :: true or false
    # +date+ :: Date
    # +datetime+, +datetime-local+ :: Time
    # other types (text, select, etc.) :: String
    #
    # Decoding distinguishes between multiple values, absent
    # checkboxes, and explicit null values:
    #
    # * Fields with :multiple=>true (such as multi-selects) decode to
    #   an array of values.  If no values are submitted for the field,
    #   it decodes to an empty array, since browsers do not submit
    #   multi-selects with no selected options.
    # * Checkbox fields decode to false if not submitted, since
    #   browsers do not submit unchecked checkboxes.
    # * An explicit null value (only possible with JSON submissions)
    #   decodes to nil, but only for fields defined with
    #   :nullable=>true; for other fields a DecodeError is raised.
    #   This is distinct from the field not being submitted at all,
    #   in which case the field is not included in the returned hash
    #   (unless it is a checkbox or multiple field).
    #
    # If a submitted value cannot be decoded for the related field, a
    # Roda::RodaPlugins::Siren::DecodeError is raised, with
    # DecodeError#field_name and DecodeError#reason methods giving
    # more information about the error.  You can rescue this error
    # globally and return an appropriate 4xx response to the client.
    #
    # By default, entities are served with the
    # +application/vnd.siren+json+ content type.  You can change this
    # using the :content_type option when loading the plugin:
    #
    #   plugin :siren, :content_type=>'application/x-siren+json'
    module Siren
      # The default content type used for siren responses.
      CONTENT_TYPE = 'application/vnd.siren+json'.freeze

      # Sentinel used to distinguish a field that was not submitted at
      # all from a field submitted with an explicit null value.
      ABSENT = Object.new
      private_constant :ABSENT

      # Exception class raised when decoding a submitted action field
      # value fails.
      class DecodeError < ArgumentError
        # The name of the action field whose value could not be decoded.
        attr_reader :field_name

        # The reason the value could not be decoded.
        attr_reader :reason

        def initialize(field_name, reason)
          @field_name = field_name
          @reason = reason
          super("invalid value for siren action field #{field_name}: #{reason}")
        end
      end

      def self.load_dependencies(app, opts=OPTS)
        app.plugin :_json
        app.plugin :custom_block_results
      end

      # Set the content type used for siren responses, and register
      # siren entities as a supported block result.
      def self.configure(app, opts=OPTS)
        app.opts[:siren_content_type] = (opts[:content_type] || CONTENT_TYPE).freeze
        app.custom_block_results[Entity] = :handle_siren_block_result
      end

      # A siren link, used for navigation relations such as +self+ and
      # +documentation+.  Links are for navigation only; operations on
      # the entity should be defined as actions instead.
      class Link
        # The link relations, an array of strings.
        attr_reader :rels

        # The URI the link points to.
        attr_reader :href

        def initialize(opts={})
          @rels = Array(opts.delete(:rel)).map(&:to_s)
          raise ArgumentError, ':rel option is required' if @rels.empty?
          @href = opts.delete(:href)
          raise ArgumentError, ':href option is required' unless @href
          @title = opts.delete(:title)
          @type = opts.delete(:type)
          @classes = Array(opts.delete(:class))
          raise ArgumentError, "unknown options: #{opts.keys.join(', ')}" unless opts.empty?
        end

        # A hash representation of the link, for inclusion in a siren
        # entity representation.
        def to_h
          h = {:rel=>@rels, :href=>@href}
          h[:class] = @classes unless @classes.empty?
          h[:title] = @title if @title
          h[:type] = @type if @type
          h
        end
      end

      # A single typed field of a siren action.  The field definition
      # is used both to generate the siren action representation and
      # to decode submitted values for the action.
      class Field
        # Submitted checkbox values considered checked.
        CHECKBOX_TRUE_VALUES = %w'true 1 on yes'.freeze
        private_constant :CHECKBOX_TRUE_VALUES

        # Submitted checkbox values considered unchecked.
        CHECKBOX_FALSE_VALUES = %w'false 0 off no'.freeze
        private_constant :CHECKBOX_FALSE_VALUES

        # The name of the field.
        attr_reader :name

        # The siren type of the field (e.g. text, number, checkbox,
        # select), as a string.
        attr_reader :type

        # The current value advertised for the field, if any.
        attr_reader :value

        def initialize(opts={})
          @name = opts.delete(:name)
          raise ArgumentError, ':name option is required' unless @name
          @name = @name.to_s
          @type = (opts.delete(:type) || 'text').to_s
          @value = opts.delete(:value)
          @multiple = opts.delete(:multiple) ? true : false
          @nullable = opts.delete(:nullable) ? true : false
          @title = opts.delete(:title)
          @classes = Array(opts.delete(:class))
          raise ArgumentError, "unknown options: #{opts.keys.join(', ')}" unless opts.empty?
        end

        # Whether the field accepts multiple values, such as a
        # multi-select.
        def multiple?
          @multiple
        end

        # Whether an explicit null value is accepted for the field.
        def nullable?
          @nullable
        end

        # Whether the field is a checkbox field.
        def checkbox?
          @type == 'checkbox'
        end

        # A hash representation of the field, for inclusion in a siren
        # action representation.
        def to_h
          h = {:name=>@name, :type=>@type}
          h[:class] = @classes unless @classes.empty?
          h[:title] = @title if @title
          h[:value] = @value unless @value.nil?
          h[:multiple] = true if @multiple
          h
        end

        # Decode the submitted value for the field into the related
        # Ruby value.  +value+ should be the submitted value, or the
        # ABSENT sentinel if the field was not submitted.  Returns the
        # ABSENT sentinel for fields that were not submitted and have
        # no defined absence semantics.  Raises DecodeError if the
        # submitted value is invalid for the field.
        def decode_value(value)
          if ABSENT.equal?(value)
            # Browsers do not submit unchecked checkboxes, and do not
            # submit multi-selects with no selected options.
            return false if checkbox?
            return [] if multiple?
            return ABSENT
          end

          if value.nil?
            # An explicit null value (only possible with JSON
            # submissions) is distinct from the field not being
            # submitted at all.
            return nil if nullable?
            raise DecodeError.new(@name, 'null value submitted for non-nullable field')
          end

          if multiple?
            unless value.is_a?(Array)
              raise DecodeError.new(@name, "expected array of values, got: #{value.inspect}")
            end
            return value.map{|element| coerce_scalar(element)}
          end

          return coerce_checkbox(value) if checkbox?

          coerce_scalar(value)
        end

        private

        def coerce_checkbox(value)
          case value
          when true, false
            value
          when *CHECKBOX_TRUE_VALUES
            true
          when '', *CHECKBOX_FALSE_VALUES
            false
          else
            raise DecodeError.new(@name, "invalid checkbox value: #{value.inspect}")
          end
        end

        def coerce_scalar(value)
          case @type
          when 'number'
            coerce_number(value)
          when 'range'
            coerce_integer(value)
          when 'date'
            coerce_date(value)
          when 'datetime', 'datetime-local'
            coerce_time(value)
          else
            coerce_string(value)
          end
        end

        def coerce_string(value)
          unless value.is_a?(String)
            raise DecodeError.new(@name, "expected string, got: #{value.inspect}")
          end
          value
        end

        def coerce_integer(value)
          case value
          when Integer
            value
          when /\A[+-]?\d+\z/
            Integer(value, 10)
          else
            raise DecodeError.new(@name, "invalid integer: #{value.inspect}")
          end
        end

        def coerce_number(value)
          case value
          when Integer, Float
            value
          when /\A[+-]?\d+\z/
            Integer(value, 10)
          when /\A[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?\z/
            Float(value)
          else
            raise DecodeError.new(@name, "invalid number: #{value.inspect}")
          end
        end

        def coerce_date(value)
          unless value.is_a?(String)
            raise DecodeError.new(@name, "invalid date: #{value.inspect}")
          end
          begin
            Date.iso8601(value)
          rescue ArgumentError
            raise DecodeError.new(@name, "invalid date: #{value.inspect}")
          end
        end

        def coerce_time(value)
          unless value.is_a?(String)
            raise DecodeError.new(@name, "invalid time: #{value.inspect}")
          end
          begin
            Time.iso8601(value)
          rescue ArgumentError
            raise DecodeError.new(@name, "invalid time: #{value.inspect}")
          end
        end
      end

      # A siren action, describing an operation the client can perform
      # on the entity.  The action's typed field definitions are used
      # both to generate the siren action representation and to decode
      # submissions for the action.
      class Action
        # The action name.  Clients look actions up by name, so this
        # should be unique within the entity.
        attr_reader :name

        # The HTTP method used when submitting the action, if set.
        attr_reader :method

        # The URI the action is submitted to.
        attr_reader :href

        # The action's typed fields, an array of Field instances.
        attr_reader :fields

        def initialize(opts={}, &block)
          @name = opts.delete(:name)
          raise ArgumentError, ':name option is required' unless @name
          @name = @name.to_s
          @href = opts.delete(:href)
          raise ArgumentError, ':href option is required' unless @href
          @method = opts.delete(:method)
          @type = opts.delete(:type)
          @title = opts.delete(:title)
          @classes = Array(opts.delete(:class))
          raise ArgumentError, "unknown options: #{opts.keys.join(', ')}" unless opts.empty?
          @fields = []
          block.call(self) if block
        end

        # Add a typed field to the action.  See Field for the
        # supported options.  Returns the Field instance created.
        def field(opts={})
          field = Field.new(opts)
          @fields << field
          field
        end

        # Decode the submitted params for the action into a hash of
        # Ruby values, keyed by field name symbol.  +params+ should be
        # a hash with string or symbol keys, such as the request's
        # form params or a parsed JSON request body.  Raises
        # DecodeError if a submitted value is invalid for the related
        # field.
        def decode(params)
          unless params.is_a?(Hash)
            raise ArgumentError, "params must be a Hash, got: #{params.inspect}"
          end

          values = {}
          @fields.each do |field|
            value = field.decode_value(fetch_value(params, field.name))
            values[field.name.to_sym] = value unless ABSENT.equal?(value)
          end
          values
        end

        # A hash representation of the action, for inclusion in a
        # siren entity representation.
        def to_h
          h = {:name=>@name, :href=>@href}
          h[:class] = @classes unless @classes.empty?
          h[:method] = @method if @method
          h[:title] = @title if @title
          h[:type] = @type if @type
          h[:fields] = @fields.map(&:to_h) unless @fields.empty?
          h
        end

        private

        # Retrieve the submitted value for the field with the given
        # name, or the ABSENT sentinel if no value was submitted.
        def fetch_value(params, name)
          if params.key?(name)
            params[name]
          elsif params.key?(name.to_sym)
            params[name.to_sym]
          else
            ABSENT
          end
        end
      end

      # A siren entity, with a class, properties, links, actions, and
      # embedded sub-entities.  When used as the return value of a
      # route block, it is serialized to JSON and served with the
      # siren content type.
      class Entity
        # The entity's properties hash.
        attr_reader :properties

        # The entity's relations to its parent entity, an array of
        # strings.  Only set for sub-entities.
        attr_reader :rels

        # The entity's links, an array of Link instances.
        attr_reader :links

        # The entity's actions, an array of Action instances.
        attr_reader :actions

        # The entity's embedded sub-entities, an array of Entity
        # instances.
        attr_reader :entities

        def initialize(opts={})
          @classes = Array(opts.delete(:class))
          @properties = opts.delete(:properties)
          @title = opts.delete(:title)
          @rels = Array(opts.delete(:rel)).map(&:to_s)
          @href = opts.delete(:href)
          raise ArgumentError, "unknown options: #{opts.keys.join(', ')}" unless opts.empty?
          @links = []
          @actions = []
          @entities = []
        end

        # Add a navigation link to the entity.  Accepts either a Link
        # instance or an options hash for Link.new.  Do not use links
        # for operations on the entity; use actions for those.
        # Returns the Link instance.
        def link(opts={})
          link = opts.is_a?(Link) ? opts : Link.new(opts)
          @links << link
          link
        end

        # Add an action to the entity.  Accepts either an Action
        # instance or an options hash for Action.new (with a block
        # for defining fields).  Returns the Action instance.
        def action(opts={}, &block)
          action = opts.is_a?(Action) ? opts : Action.new(opts, &block)
          @actions << action
          action
        end

        # Add an embedded sub-entity to the entity.  Accepts either an
        # Entity instance or an options hash for Entity.new (with a
        # block for further building).  Sub-entities must have a
        # :rel option.  Returns the Entity instance.
        def entity(opts={}, &block)
          if opts.is_a?(Entity)
            entity = opts
          else
            entity = Entity.new(opts)
            block.call(entity) if block
          end
          raise ArgumentError, 'sub-entities must have a :rel option' if entity.rels.empty?
          @entities << entity
          entity
        end

        # A hash representation of the entity, used as the basis for
        # the JSON siren representation.
        def to_h
          h = {}
          h[:class] = @classes unless @classes.empty?
          h[:properties] = @properties if @properties
          h[:entities] = @entities.map(&:to_h) unless @entities.empty?
          h[:links] = @links.map(&:to_h) unless @links.empty?
          h[:actions] = @actions.map(&:to_h) unless @actions.empty?
          h[:rel] = @rels unless @rels.empty?
          h[:href] = @href if @href
          h[:title] = @title if @title
          h
        end
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :siren_content_type)
      end

      module InstanceMethods
        # Build a siren entity.  When used as the return value of a
        # route block, the entity is serialized to JSON and served
        # with the siren content type.  Options:
        # :class :: An array (or single value) of classes for the entity.
        # :properties :: A hash of the entity's properties.
        # :title :: A descriptive title for the entity.
        def siren_entity(opts={})
          entity = Entity.new(opts)
          yield entity if block_given?
          entity
        end

        # Build a standalone siren action, which can be added to
        # entities with Entity#action, and used to decode submissions
        # with siren_decode.  See Action for the supported options.
        def siren_action(opts={}, &block)
          Action.new(opts, &block)
        end

        # Build a standalone siren link, which can be added to
        # entities with Entity#link.  See Link for the supported
        # options.
        def siren_link(opts={})
          Link.new(opts)
        end

        # Decode the submitted values for the given action, based on
        # the action's typed field definitions.  Uses the request body
        # parsed as JSON if the request's content type includes
        # +json+, and the request's form params otherwise.  Returns a
        # hash keyed by field name symbol.  Raises DecodeError if a
        # submitted value is invalid for the related field.
        def siren_decode(action)
          action.decode(siren_submitted_params)
        end

        # Handle a siren entity block result by serializing it to JSON
        # and using the siren content type for the response.
        def handle_siren_block_result(entity)
          @_response[RodaResponseHeaders::CONTENT_TYPE] ||= self.class.siren_content_type
          self.class.json_serializer.call(entity.to_h)
        end

        private

        # The submitted params to use for siren action decoding.
        def siren_submitted_params
          request = @_request
          content_type = request.content_type
          if content_type && content_type.include?('json')
            body = request.body.read
            body.empty? ? {} : self.class.json_parser.call(body)
          else
            request.params
          end
        end
      end
    end

    register_plugin(:siren, Siren)
  end
end
