# frozen-string-literal: true

require 'base64'
require 'openssl'

#
class Roda
  module RodaPlugins
    # The http_message_signatures plugin verifies RFC 9421 HTTP Message
    # Signatures on incoming requests.  It is designed for applications
    # that receive signed callbacks or webhooks and need to authenticate
    # the sender and the integrity of the request before processing it.
    #
    # The plugin supports the +Signature-Input+ and +Signature+ HTTP
    # fields and the +hmac-sha256+ and +ed25519+ signature algorithms.
    # The verification policy and key resolution are explicitly provided
    # by the application via plugin options; the plugin makes no trust
    # decisions on its own.
    #
    # = Usage
    #
    # Provide a +:key_resolver+ when loading the plugin, and call
    # +check_http_message_signature!+ inside the routes that require a
    # valid signature.  Code after the check is only reached when the
    # request signature verified successfully:
    #
    #   CALLBACK_KEYS = {
    #     'billing-hmac' => ENV['BILLING_CALLBACK_HMAC_SECRET'],
    #     'partner-ed25519' => ENV['PARTNER_ED25519_PUBLIC_KEY']
    #   }
    #
    #   plugin :http_message_signatures,
    #     key_resolver: proc{|keyid, params, request| CALLBACK_KEYS[keyid] },
    #     required_components: ['@method', '@path', 'content-digest'],
    #     max_age: 300
    #
    #   route do |r|
    #     r.post 'callback' do
    #       signature = check_http_message_signature!
    #       # Only reached when the request has a valid signature.
    #       # signature.keyid identifies the verified signer.
    #       # ...
    #     end
    #   end
    #
    # = Options
    #
    # [+:key_resolver+ (required)] A callable called with the signature's
    #   +keyid+ parameter (nil if the signature has none), a hash of the
    #   signature parameters (with symbol keys such as +:created+,
    #   +:expires+, +:nonce+, +:tag+, and +:alg+), and the current
    #   request.  It must return the key material to verify with, or nil
    #   if the key is unknown (which fails verification).  For
    #   +hmac-sha256+, return the shared secret.  For +ed25519+, return
    #   the 32 byte raw public key, a PEM/DER encoded public key, or an
    #   OpenSSL::PKey::PKey.
    # [+:algorithms+] The signature algorithms allowed during
    #   verification.  Defaults to +hmac-sha256+ and +ed25519+.
    # [+:default_algorithm+] The algorithm to assume when the signature
    #   does not include an +alg+ parameter.  By default, signatures
    #   without an +alg+ parameter are rejected as unsupported.
    # [+:max_age+] Maximum age of a signature in seconds, based on its
    #   +created+ parameter.  Signatures older than this fail
    #   verification, as do signatures without a +created+ parameter.
    #   Not checked by default.
    # [+:clock_skew+] Clock skew tolerance in seconds used when checking
    #   the +created+ and +expires+ parameters.  Defaults to 60.
    # [+:now+] A callable returning the current time, used for all time
    #   based checks.  Defaults to <tt>proc{Time.now}</tt>.  Override
    #   this in tests to control signature expiration.
    # [+:required_components+] An array of component identifiers (such as
    #   <tt>'@method'</tt> or <tt>'content-digest'</tt>) that every
    #   verified signature must cover.  Component identifiers without
    #   parameters can be given as plain names.  Empty by default.
    # [+:trusted_forwarded+] Whether to derive +@scheme+, +@authority+,
    #   and +@target-uri+ from the +Forwarded+ header.  See the
    #   "Proxies" section below.  Disabled by default.
    #
    # = Failure handling
    #
    # +check_http_message_signature!+ distinguishes three failure types,
    # using separate exception classes (all subclasses of
    # HTTPMessageSignatures::Error):
    #
    # [SignatureMissing (401)] The request does not contain the
    #   Signature-Input or Signature fields, or no entry exists for the
    #   requested signature label.
    # [SignatureUnsupported (400)] The signature cannot be parsed, or
    #   uses an algorithm, covered component, or component parameter
    #   that is not supported.
    # [SignatureVerificationFailed (403)] The signature is well formed
    #   and supported, but does not verify.  This includes unknown keys,
    #   expired signatures, and signatures that do not cover the
    #   required components.
    #
    # By default, an empty response with the status shown above is
    # returned.  Error responses never contain key or signature
    # material.  You can customize the response by passing a block when
    # loading the plugin.  The block is called with the request and the
    # error:
    #
    #   plugin :http_message_signatures, key_resolver: resolver do |request, error|
    #     response.status = 403
    #     'invalid signature'
    #   end
    #
    # For lower level handling, call +r.verify_http_message_signature+
    # directly, which raises the exceptions above instead of returning
    # an error response.
    #
    # = Covered components
    #
    # The plugin constructs the signature base as specified in RFC 9421
    # section 2.5, and supports:
    #
    # * The derived components +@method+, +@target-uri+, +@authority+,
    #   +@scheme+, +@request-target+, +@path+, +@query+, and
    #   +@query-param+ (with the +name+ parameter).
    # * Header field components, including fields sent multiple times
    #   (combined with <tt>", "</tt> as specified).
    # * The +sf+ component parameter, which reparses and reserializes
    #   the field as a structured field.
    # * The +key+ component parameter, which selects a member of a
    #   dictionary structured field.
    #
    # Trailer fields (+tr+), byte sequence wrapping (+bs+), and
    # response-only components (+@status+, +req+) are not supported and
    # are rejected as unsupported.
    #
    # = Proxies
    #
    # Which signature components are trustworthy depends on how the
    # request reached the application:
    #
    # * +@method+, +@path+, +@query+, +@query-param+, +@request-target+,
    #   and all header field components are taken directly from the
    #   request as received by the Rack server.  If a proxy rewrote the
    #   path or query before the request reached the application, a
    #   signature over the original values will (correctly) fail to
    #   verify.
    # * +@authority+ uses the +Host+ header, which is client controlled
    #   unless a trusted proxy overwrites it.  Consider validating it
    #   with the host_authorization plugin.
    # * +@scheme+ and +@target-uri+ use +rack.url_scheme+, which behind
    #   a TLS terminating proxy reflects the internal hop, not the
    #   scheme the client used.  The original scheme and authority are
    #   only available if a trusted proxy records them.
    #
    # By default, the plugin never looks at the +Forwarded+ header,
    # because clients can forge it.  If the application runs behind a
    # trusted proxy that strips client supplied +Forwarded+ headers and
    # adds its own element, you can opt in to using it:
    #
    #   plugin :http_message_signatures, key_resolver: resolver,
    #     trusted_forwarded: true
    #
    # With +:trusted_forwarded+ set to true, the rightmost +Forwarded+
    # element (the one added by the proxy closest to the application) is
    # used for +@scheme+, +@authority+, and +@target-uri+.  You can also
    # set it to an integer N to use the Nth element from the right, for
    # deployments with a known number of trusted proxies.  Do not enable
    # this unless your proxy sanitizes the header, otherwise clients can
    # choose the authority and scheme their signature is verified
    # against.
    #
    # = Security
    #
    # * Keys and signature values are never included in exception
    #   messages or error responses.
    # * HMAC comparison is constant time.
    # * Use +max_age+ (and require +created+ via the signature policy of
    #   your callback provider) to limit replay of captured signatures.
    module HTTPMessageSignatures
      # Base class for HTTP message signature verification errors.
      class Error < RodaError; end

      # Raised when the request does not contain the signature data
      # needed for verification, such as the Signature-Input or
      # Signature fields, or an entry for the requested signature label.
      class SignatureMissing < Error; end

      # Raised when the signature uses an algorithm, covered component,
      # or component parameter that is not supported, or when the
      # signature fields cannot be parsed.
      class SignatureUnsupported < Error; end

      # Raised when the signature is well formed and supported, but does
      # not verify.  This includes unknown keys, expired signatures,
      # signatures that do not cover required components, and invalid
      # signature values.
      class SignatureVerificationFailed < Error; end

      # Information about a successfully verified signature, returned by
      # verify_http_message_signature and check_http_message_signature!.
      #
      # [label] The signature label that was verified.
      # [keyid] The signature's keyid parameter (nil if not present).
      # [algorithm] The signature algorithm that was used.
      # [covered_components] The component identifiers covered by the
      #   signature, in their canonical serialized form.
      # [params] The signature parameters, as a hash with symbol keys.
      VerifiedSignature = Struct.new(:label, :keyid, :algorithm, :covered_components, :params)

      # Signature algorithms allowed during verification, unless
      # overridden with the :algorithms option.
      DEFAULT_ALGORITHMS = %w[hmac-sha256 ed25519].freeze

      # Default time source, can be overridden with the :now option.
      NOW = proc{Time.now}

      # Minimal RFC 8941 structured fields parser and serializer, used
      # for parsing the Signature-Input and Signature fields and for
      # canonical reserialization of structured field components.
      module StructuredFields
        # Raised when a structured field value cannot be parsed.
        ParseError = Class.new(StandardError)

        # A byte sequence structured field value.
        class ByteSequence
          # The raw bytes of the byte sequence.
          attr_reader :bytes

          def initialize(bytes)
            @bytes = bytes
          end

          def ==(other)
            other.is_a?(ByteSequence) && other.bytes == bytes
          end
          alias eql? ==
        end

        KEY_REGEXP = /\A[a-z*][a-z0-9_.*-]*/
        TOKEN_REGEXP = /\A[A-Za-z*][0-9A-Za-z!#$%&'*+.\/:^_\x60|~-]*/
        NUMBER_REGEXP = /\A-?[0-9]{1,15}(\.[0-9]{1,3})?/

        class << self
          # Parse a complete structured fields dictionary.  Returns an
          # array of [key, value] pairs, where each value is an item or
          # inner list (see parse_item).
          def parse_dictionary(input)
            members = []
            s = skip_ows(input)
            until s.empty?
              key, s = parse_key(s)
              if s[0] == '='
                value, s = parse_item_or_inner_list(s[1..-1].to_s)
              else
                parameters, s = parse_parameters(s)
                value = [true, parameters]
              end
              members.each do |existing_key, _|
                if existing_key == key
                  raise ParseError, 'duplicate dictionary key'
                end
              end
              members << [key, value]
              s = skip_ows(s)
              break if s.empty?
              unless s[0] == ','
                raise ParseError, 'expected comma in dictionary'
              end
              s = skip_ows(s[1..-1].to_s)
              if s.empty?
                raise ParseError, 'trailing comma in dictionary'
              end
            end
            members
          end

          # Parse a complete structured fields list.  Returns an array
          # of items and inner lists (see parse_item).
          def parse_list(input)
            items = []
            s = skip_ows(input)
            until s.empty?
              item, s = parse_item_or_inner_list(s)
              items << item
              s = skip_ows(s)
              break if s.empty?
              unless s[0] == ','
                raise ParseError, 'expected comma in list'
              end
              s = skip_ows(s[1..-1].to_s)
              if s.empty?
                raise ParseError, 'trailing comma in list'
              end
            end
            items
          end

          # Parse a complete structured fields item.  Returns the item
          # as a [bare_value, parameters] pair, where parameters is an
          # array of [key, value] pairs.
          def parse_item_string(input)
            item, s = parse_item(skip_ows(input))
            unless skip_ows(s).empty?
              raise ParseError, 'trailing characters after item'
            end
            item
          end

          # Serialize an item or inner list.
          def serialize(value)
            if value[0].is_a?(Array)
              serialize_inner_list(value)
            else
              serialize_item(value)
            end
          end

          # Serialize a parsed dictionary.
          def serialize_dictionary(dictionary)
            dictionary.map do |key, value|
              if value[0] == true && value[1].empty?
                key
              else
                "#{key}=#{serialize(value)}"
              end
            end.join(', ')
          end

          # Serialize a parsed list.
          def serialize_list(list)
            list.map{|item| serialize(item)}.join(', ')
          end

          # Serialize an inner list, given as a [items, parameters] pair.
          def serialize_inner_list(inner_list)
            "(#{inner_list[0].map{|item| serialize_item(item)}.join(' ')})#{serialize_parameters(inner_list[1])}"
          end

          # Serialize an item, given as a [bare_value, parameters] pair.
          def serialize_item(item)
            "#{serialize_bare_item(item[0])}#{serialize_parameters(item[1])}"
          end

          # Serialize item or inner list parameters.
          def serialize_parameters(parameters)
            parameters.map do |key, value|
              if value == true
                ";#{key}"
              else
                ";#{key}=#{serialize_bare_item(value)}"
              end
            end.join
          end

          # Serialize a bare item value (Integer, Float, String, Symbol
          # token, ByteSequence, or boolean).
          def serialize_bare_item(value)
            case value
            when Integer
              value.to_s
            when Float
              serialize_decimal(value)
            when Symbol
              value.to_s
            when ByteSequence
              ":#{Base64.strict_encode64(value.bytes)}:"
            when String
              "\"#{value.gsub(/["\\]/){|char| "\\#{char}"}}\""
            when true
              '?1'
            when false
              '?0'
            else
              raise ParseError, 'unsupported structured field value'
            end
          end

          private

          def parse_item_or_inner_list(s)
            if s[0] == '('
              parse_inner_list(s)
            else
              parse_item(s)
            end
          end

          def parse_inner_list(s)
            items = []
            s = s[1..-1].to_s
            loop do
              s = s.sub(/\A +/, '')
              if s[0] == ')'
                s = s[1..-1].to_s
                break
              end
              raise ParseError, 'unterminated inner list' if s.empty?
              item, s = parse_item(s)
              items << item
              unless s =~ /\A[ )]/
                raise ParseError, 'invalid inner list'
              end
            end
            parameters, s = parse_parameters(s)
            [[items, parameters], s]
          end

          def parse_item(s)
            bare, s = parse_bare_item(s)
            parameters, s = parse_parameters(s)
            [[bare, parameters], s]
          end

          def parse_parameters(s)
            parameters = []
            while s[0] == ';'
              s = s.sub(/\A; */, '')
              key, s = parse_key(s)
              value = true
              if s[0] == '='
                value, s = parse_bare_item(s[1..-1].to_s)
              end
              parameters.each do |existing_key, _|
                if existing_key == key
                  raise ParseError, 'duplicate parameter key'
                end
              end
              parameters << [key, value]
            end
            [parameters, s]
          end

          def parse_key(s)
            unless s =~ KEY_REGEXP
              raise ParseError, 'invalid key'
            end
            key = $~[0]
            [key, s[key.length..-1].to_s]
          end

          def parse_bare_item(s)
            case s[0]
            when '-', '0'..'9'
              parse_number(s)
            when '"'
              parse_string(s)
            when ':'
              parse_byte_sequence(s)
            when '?'
              parse_boolean(s)
            when 'a'..'z', 'A'..'Z', '*'
              parse_token(s)
            else
              raise ParseError, 'invalid item'
            end
          end

          def parse_number(s)
            unless s =~ NUMBER_REGEXP
              raise ParseError, 'invalid number'
            end
            number = $~[0]
            rest = s[number.length..-1].to_s
            if rest =~ /\A[0-9.]/
              raise ParseError, 'invalid number'
            end
            if number.include?('.')
              [number.to_f, rest]
            else
              [number.to_i, rest]
            end
          end

          def parse_string(s)
            output = String.new
            index = 1
            while index < s.length
              char = s[index]
              if char == '\\'
                index += 1
                char = s[index]
                unless char == '"' || char == '\\'
                  raise ParseError, 'invalid escape in string'
                end
                output << char
              elsif char == '"'
                return [output, s[index + 1..-1].to_s]
              elsif char < "\x20" || char == "\x7f"
                raise ParseError, 'invalid character in string'
              else
                output << char
              end
              index += 1
            end
            raise ParseError, 'unterminated string'
          end

          def parse_token(s)
            unless s =~ TOKEN_REGEXP
              raise ParseError, 'invalid token'
            end
            token = $~[0]
            [token.to_sym, s[token.length..-1].to_s]
          end

          def parse_byte_sequence(s)
            unless s =~ /\A:([A-Za-z0-9+\/=]*):/
              raise ParseError, 'invalid byte sequence'
            end
            [ByteSequence.new(Base64.decode64($1)), s[$~[0].length..-1].to_s]
          end

          def parse_boolean(s)
            if s.start_with?('?1')
              [true, s[2..-1].to_s]
            elsif s.start_with?('?0')
              [false, s[2..-1].to_s]
            else
              raise ParseError, 'invalid boolean'
            end
          end

          def serialize_decimal(value)
            rounded = (value * 1000).round
            int = (rounded / 1000.0).truncate
            frac = rounded.abs % 1000
            frac_string = frac.to_s.rjust(3, '0').sub(/0*\z/, '')
            frac_string = '0' if frac_string.empty?
            "#{int}.#{frac_string}"
          end

          def skip_ows(s)
            s.sub(/\A[ \t]+/, '')
          end
        end
      end

      # Configure the http_message_signatures plugin.  See the module
      # documentation for the supported options.
      def self.configure(app, opts=OPTS, &block)
        key_resolver = opts[:key_resolver]
        unless key_resolver.respond_to?(:call)
          raise RodaError, 'http_message_signatures plugin requires a callable :key_resolver option'
        end

        algorithms = (opts[:algorithms] || DEFAULT_ALGORITHMS).map{|algorithm| algorithm.to_s}.freeze
        required_components = (opts[:required_components] || EMPTY_ARRAY).map{|component| component.to_s}.freeze
        default_algorithm = opts[:default_algorithm]
        default_algorithm = default_algorithm.to_s if default_algorithm

        app.opts[:http_message_signatures] = {
          key_resolver: key_resolver,
          algorithms: algorithms,
          max_age: opts[:max_age],
          clock_skew: opts[:clock_skew] || 60,
          now: opts[:now] || NOW,
          required_components: required_components,
          default_algorithm: default_algorithm,
          trusted_forwarded: opts[:trusted_forwarded] || false
        }.freeze

        app.define_roda_method(:http_message_signature_error, :any, &block) if block
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :http_message_signatures, name: :http_message_signature_config)
      end

      module InstanceMethods
        # Verify the HTTP message signature for the current request, and
        # return a HTTPMessageSignatures::VerifiedSignature for it.  If
        # verification fails, halt request processing with an error
        # response: 401 if the signature is missing, 400 if the
        # signature is unsupported, and 403 if the signature does not
        # verify.  Code after this check is only reached when the
        # request signature verified successfully.
        def check_http_message_signature!(label=nil)
          request = @_request
          begin
            request.verify_http_message_signature(label)
          rescue HTTPMessageSignatures::Error => error
            request.on{http_message_signature_error(request, error)}
          end
        end

        private

        # Action taken when HTTP message signature verification fails.
        # Sets an appropriate error status and returns an empty body.
        # Error responses must not contain key or signature material.
        def http_message_signature_error(_request, error)
          @_response.status =
            case error
            when HTTPMessageSignatures::SignatureMissing
              401
            when HTTPMessageSignatures::SignatureUnsupported
              400
            else
              403
            end
          nil
        end
      end

      module RequestMethods
        # Verify the HTTP message signature for the request, and return
        # a HTTPMessageSignatures::VerifiedSignature for it.  +label+ is
        # the signature label to verify; if not given, the request must
        # contain exactly one signature.  Raises SignatureMissing if the
        # request does not contain a usable signature,
        # SignatureUnsupported if the signature cannot be verified
        # because it uses unsupported features, and
        # SignatureVerificationFailed if the signature does not verify.
        def verify_http_message_signature(label=nil)
          config = roda_class.http_message_signature_config

          input_header = @env['HTTP_SIGNATURE_INPUT']
          signature_header = @env['HTTP_SIGNATURE']
          unless input_header
            raise SignatureMissing, 'request does not contain a Signature-Input field'
          end
          unless signature_header
            raise SignatureMissing, 'request does not contain a Signature field'
          end

          inputs = _http_signature_parse{StructuredFields.parse_dictionary(input_header)}
          signatures = _http_signature_parse{StructuredFields.parse_dictionary(signature_header)}

          if label
            label = label.to_s
          elsif inputs.length == 1
            label = inputs[0][0]
          elsif inputs.empty?
            raise SignatureMissing, 'request does not contain any signatures'
          else
            raise SignatureMissing, 'request contains multiple signatures, specify the label of the signature to verify'
          end

          input_value = _http_signature_assoc(inputs, label)
          unless input_value
            raise SignatureMissing, "request does not contain a Signature-Input entry for #{label}"
          end
          signature_value = _http_signature_assoc(signatures, label)
          unless signature_value
            raise SignatureMissing, "request does not contain a Signature entry for #{label}"
          end

          signature_bytes = signature_value[0]
          unless signature_bytes.is_a?(StructuredFields::ByteSequence)
            raise SignatureUnsupported, "Signature entry for #{label} is not a byte sequence"
          end

          unless input_value[0].is_a?(Array)
            raise SignatureUnsupported, "Signature-Input entry for #{label} is not an inner list"
          end
          components = input_value[0]
          signature_params = input_value[1]

          components.each do |component|
            unless component[0].is_a?(String)
              raise SignatureUnsupported, 'covered component identifiers must be strings'
            end
          end

          params = {}
          signature_params.each do |param_name, param_value|
            params[param_name.to_sym] = param_value.is_a?(Symbol) ? param_value.to_s : param_value
          end

          algorithm = params[:alg]
          algorithm = algorithm.to_s if algorithm
          unless algorithm
            algorithm = config[:default_algorithm]
            unless algorithm
              raise SignatureUnsupported, 'signature does not specify an algorithm'
            end
          end
          unless config[:algorithms].include?(algorithm)
            raise SignatureUnsupported, "unsupported signature algorithm: #{algorithm}"
          end

          _http_signature_check_timing(config, params)

          covered_components = components.map{|component| StructuredFields.serialize_item(component)}
          config[:required_components].each do |required|
            unless covered_components.include?(required) || covered_components.include?(StructuredFields.serialize_item([required, []]))
              raise SignatureVerificationFailed, "signature does not cover required component: #{required}"
            end
          end

          base = _http_signature_base(components, signature_params)

          keyid = params[:keyid]
          key = config[:key_resolver].call(keyid, params, self)
          unless key
            raise SignatureVerificationFailed, 'unable to resolve signature verification key'
          end

          verified =
            case algorithm
            when 'hmac-sha256'
              expected = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, key, base)
              _http_signature_secure_compare(expected, signature_bytes.bytes)
            when 'ed25519'
              _http_signature_verify_ed25519(key, signature_bytes.bytes, base)
            else
              raise SignatureUnsupported, "unsupported signature algorithm: #{algorithm}"
            end

          unless verified
            raise SignatureVerificationFailed, 'signature verification failed'
          end

          VerifiedSignature.new(label, keyid, algorithm, covered_components, params)
        end

        private

        # Yield to the block, converting structured field parse errors
        # into SignatureUnsupported errors.
        def _http_signature_parse
          yield
        rescue StructuredFields::ParseError => error
          raise SignatureUnsupported, "unable to parse structured field value: #{error.message}"
        end

        # Return the value for +key+ in an array of key/value pairs, or
        # nil if there is no entry for the key.
        def _http_signature_assoc(pairs, key)
          pairs.each do |pair_key, pair_value|
            return pair_value if pair_key == key
          end
          nil
        end

        # Check the created and expires signature parameters against the
        # configured time source and signature policy.
        def _http_signature_check_timing(config, params)
          created = params[:created]
          expires = params[:expires]
          if created && !created.is_a?(Integer)
            raise SignatureUnsupported, 'created signature parameter must be an integer'
          end
          if expires && !expires.is_a?(Integer)
            raise SignatureUnsupported, 'expires signature parameter must be an integer'
          end

          now = config[:now].call.to_i
          skew = config[:clock_skew]

          if expires && now > expires + skew
            raise SignatureVerificationFailed, 'signature has expired'
          end

          max_age = config[:max_age]
          if created
            if created > now + skew
              raise SignatureVerificationFailed, 'signature was created in the future'
            end
            if max_age && now - created > max_age
              raise SignatureVerificationFailed, 'signature is older than the maximum allowed age'
            end
          elsif max_age
            raise SignatureVerificationFailed, 'signature does not contain a created parameter'
          end
        end

        # Constant time comparison of two strings.
        def _http_signature_secure_compare(a, b)
          a.bytesize == b.bytesize && Rack::Utils.secure_compare(a, b)
        end

        # Verify an ed25519 signature over the signature base, using the
        # given key material.
        def _http_signature_verify_ed25519(key, signature, base)
          public_key =
            case key
            when OpenSSL::PKey::PKey
              key
            when String
              if key.bytesize == 32
                unless OpenSSL::PKey.respond_to?(:new_raw_public_key)
                  raise SignatureUnsupported, 'raw Ed25519 public keys require openssl 3.0 or later'
                end
                OpenSSL::PKey.new_raw_public_key('ED25519', key)
              else
                OpenSSL::PKey.read(key)
              end
            else
              raise SignatureVerificationFailed, 'unsupported Ed25519 key material'
            end
          public_key.verify(nil, signature, base)
        rescue OpenSSL::OpenSSLError
          false
        end

        # Build the signature base for the covered components, as
        # specified in RFC 9421 section 2.5.
        def _http_signature_base(components, signature_params)
          lines = components.map do |component|
            "#{StructuredFields.serialize_item(component)}: #{_http_signature_component_value(component)}"
          end
          lines << "\"@signature-params\": #{StructuredFields.serialize_inner_list([components, signature_params])}"
          lines.join("\n")
        end

        # The value for a single covered component.
        def _http_signature_component_value(component)
          name = component[0]
          if name[0] == '@'
            _http_signature_derived_component(name, component[1])
          else
            _http_signature_field_component(name, component[1])
          end
        end

        # The value for a derived (@-prefixed) component.
        def _http_signature_derived_component(name, params)
          if name == '@query-param'
            return _http_signature_query_param_component(params)
          end

          unless params.empty?
            raise SignatureUnsupported, "derived component #{name} does not accept parameters"
          end

          case name
          when '@method'
            @env['REQUEST_METHOD'] || raise(SignatureUnsupported, 'request method is not available')
          when '@target-uri'
            "#{_http_signature_scheme}://#{_http_signature_authority}#{_http_signature_request_target}"
          when '@authority'
            _http_signature_authority
          when '@scheme'
            _http_signature_scheme
          when '@request-target'
            _http_signature_request_target
          when '@path'
            _http_signature_path
          when '@query'
            query = @env['QUERY_STRING'].to_s
            query.empty? ? '?' : "?#{query}"
          when '@status'
            raise SignatureUnsupported, '@status is only valid when verifying responses'
          else
            raise SignatureUnsupported, "unsupported derived component: #{name}"
          end
        end

        # The value for an @query-param component.
        def _http_signature_query_param_component(params)
          param_name = nil
          params.each do |key, value|
            if key == 'name'
              param_name = value
            else
              raise SignatureUnsupported, "unsupported @query-param parameter: #{key}"
            end
          end
          unless param_name.is_a?(String)
            raise SignatureUnsupported, '@query-param requires a string name parameter'
          end

          values = []
          @env['QUERY_STRING'].to_s.split('&', -1).each do |pair|
            next if pair.empty?
            name, _, value = pair.partition('=')
            if _http_signature_percent_decode(name) == param_name
              values << _http_signature_percent_decode(value)
            end
          end

          if values.empty?
            raise SignatureUnsupported, "query parameter is not present: #{param_name}"
          elsif values.length > 1
            raise SignatureUnsupported, "query parameter is present multiple times: #{param_name}"
          end
          values[0]
        end

        # Percent-decode a query parameter name or value.
        def _http_signature_percent_decode(value)
          value.gsub(/%([0-9A-Fa-f]{2})/){$1.hex.chr}
        end

        # The value for a header field component.
        def _http_signature_field_component(name, params)
          sf = false
          key_name = nil
          params.each do |param_name, param_value|
            case param_name
            when 'sf'
              sf = true
            when 'key'
              key_name = param_value
            when 'bs', 'tr', 'req'
              raise SignatureUnsupported, "unsupported component parameter: #{param_name}"
            end
          end

          if sf && key_name
            raise SignatureUnsupported, 'sf and key component parameters cannot be combined'
          end

          if key_name.is_a?(Symbol)
            key_name = key_name.to_s
          elsif key_name && !key_name.is_a?(String)
            raise SignatureUnsupported, 'key component parameter must be a string'
          end

          value = _http_signature_field_value(name)
          unless value
            raise SignatureUnsupported, "component field is not present in the request: #{name}"
          end

          if key_name
            dictionary = _http_signature_parse{StructuredFields.parse_dictionary(value)}
            member = _http_signature_assoc(dictionary, key_name)
            unless member
              raise SignatureUnsupported, "dictionary key is not present in #{name} field: #{key_name}"
            end
            StructuredFields.serialize(member)
          elsif sf
            _http_signature_reserialize_structured_field(value)
          else
            value
          end
        end

        # The combined value for the named header field, or nil if the
        # field is not present in the request.  Multiple field lines are
        # combined with ", " as specified in RFC 9421 section 2.1.
        def _http_signature_field_value(name)
          env_key =
            case name.downcase
            when 'content-type'
              'CONTENT_TYPE'
            when 'content-length'
              'CONTENT_LENGTH'
            else
              "HTTP_#{name.upcase.tr('-', '_')}"
            end
          value = @env[env_key]
          return nil unless value
          value.split("\n", -1).map{|line| line.strip}.join(', ')
        end

        # Reparse and canonically reserialize a structured field value,
        # trying the dictionary, list, and item types in turn.
        def _http_signature_reserialize_structured_field(value)
          begin
            return StructuredFields.serialize_dictionary(StructuredFields.parse_dictionary(value))
          rescue StructuredFields::ParseError
          end

          begin
            return StructuredFields.serialize_list(StructuredFields.parse_list(value))
          rescue StructuredFields::ParseError
          end

          begin
            return StructuredFields.serialize_item(StructuredFields.parse_item_string(value))
          rescue StructuredFields::ParseError
          end

          raise SignatureUnsupported, 'field value is not a valid structured field'
        end

        # The scheme to use for the @scheme and @target-uri components.
        def _http_signature_scheme
          forwarded = _http_signature_trusted_forwarded_element
          if forwarded && (proto = forwarded['proto'])
            proto
          else
            @env['rack.url_scheme'] || raise(SignatureUnsupported, 'request scheme is not available')
          end
        end

        # The authority to use for the @authority and @target-uri
        # components.
        def _http_signature_authority
          forwarded = _http_signature_trusted_forwarded_element
          if forwarded && (host = forwarded['host'])
            host
          elsif (host = @env['HTTP_HOST'])
            host
          elsif (server_name = @env['SERVER_NAME'])
            port = @env['SERVER_PORT'].to_s
            if port.empty? || port == _http_signature_default_port
              server_name
            else
              "#{server_name}:#{port}"
            end
          else
            raise SignatureUnsupported, 'request authority is not available'
          end
        end

        # The default port for the request scheme.
        def _http_signature_default_port
          @env['rack.url_scheme'] == 'https' ? '443' : '80'
        end

        # The parsed Forwarded header element to derive original request
        # components from, or nil if the Forwarded header is not trusted
        # or not present.  The Forwarded header is only considered when
        # the :trusted_forwarded option is set, since clients can
        # otherwise forge it.
        def _http_signature_trusted_forwarded_element
          setting = roda_class.http_message_signature_config[:trusted_forwarded]
          return nil unless setting
          header = @env['HTTP_FORWARDED']
          return nil unless header

          elements = header.split(',', -1)
          element = setting == true ? elements[-1] : elements[-setting.to_i]
          return nil unless element

          pairs = {}
          element.split(';', -1).each do |pair|
            key, sep, value = pair.partition('=')
            next if sep.empty?
            key = key.strip.downcase
            value = value.strip
            if value.length >= 2 && value[0] == '"' && value[-1] == '"'
              value = value[1..-2].gsub(/\\(.)/){$1}
            end
            pairs[key] = value
          end
          pairs
        end

        # The request target (path and query) for @request-target.
        def _http_signature_request_target
          target = _http_signature_path
          query = @env['QUERY_STRING'].to_s
          query.empty? ? target : "#{target}?#{query}"
        end

        # The path for @path.
        def _http_signature_path
          path = "#{@env['SCRIPT_NAME']}#{@env['PATH_INFO']}"
          path.empty? ? '/' : path
        end
      end
    end

    register_plugin(:http_message_signatures, HTTPMessageSignatures)
  end
end
