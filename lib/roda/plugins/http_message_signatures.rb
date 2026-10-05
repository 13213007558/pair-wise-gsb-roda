# frozen-string-literal: true

require 'base64'
require 'openssl'

class Roda
  module RodaPlugins
    # The http_message_signatures plugin verifies HTTP Message Signatures
    # (RFC 9421) on incoming requests.  It is designed for applications
    # that receive signed callbacks or webhooks, and need to authenticate
    # the sender and the integrity of the request before the routing tree
    # handles it.
    #
    # The plugin supports the +hmac-sha256+ and +ed25519+ algorithms.
    # Verification policy and key resolution are always provided
    # explicitly by the application; the plugin never guesses keys and
    # never accepts signatures it was not configured to verify.
    #
    # = Example
    #
    #   class App < Roda
    #     KEYS = {
    #       'billing-callbacks' => {algorithm: 'hmac-sha256', key: ENV.fetch('CALLBACK_HMAC_SECRET')},
    #       'partner-service' => {algorithm: 'ed25519', key: ENV.fetch('PARTNER_ED25519_PUBLIC_KEY')},
    #     }
    #
    #     plugin :http_message_signatures,
    #       key_resolver: proc{|keyid, algorithm| KEYS[keyid]},
    #       required_components: %w"@method @path @authority content-digest",
    #       max_age: 300
    #
    #     route do |r|
    #       r.post 'callbacks', String do |provider|
    #         # Halts the request with an error response unless it carries
    #         # a valid HTTP message signature.  The rest of the route
    #         # block only runs for requests that verified successfully.
    #         verify_http_message_signature!
    #
    #         signature = http_message_signature
    #         handle_callback(provider, signature.keyid, r.body.read)
    #         'ok'
    #       end
    #     end
    #   end
    #
    # = Options
    #
    # The following options are supported when loading the plugin:
    #
    # :key_resolver :: Required.  A callable called with the signature's
    #                  +keyid+ and +alg+ parameters (either may be +nil+),
    #                  returning the key material for the signature, or
    #                  +nil+ if the key is unknown.  It can return the key
    #                  material directly, or a hash with +:algorithm+ and
    #                  +:key+ entries to pin the algorithm allowed for the
    #                  key.  For +hmac-sha256+, the key is the raw secret
    #                  as a string.  For +ed25519+, the key is the 32 byte
    #                  raw public key, the base64 encoding of it, a PEM
    #                  encoded public key, or an OpenSSL::PKey::PKey
    #                  instance.
    # :required_components :: An array of component names (such as
    #                  +@method+ or +content-digest+) that every verified
    #                  signature must cover.  Signatures that do not cover
    #                  all required components are rejected.  Empty by
    #                  default.
    # :max_age :: Maximum age in seconds of a signature, based on its
    #                  +created+ signature parameter.  When set, signatures
    #                  without a +created+ parameter are rejected.
    #                  Default: 300.  Set to +nil+ to disable.
    # :future_tolerance :: Number of seconds a signature's +created+
    #                  parameter is allowed to be in the future, to allow
    #                  for clock skew.  Default: 60.
    # :require_expires :: Reject signatures without an +expires+ signature
    #                  parameter.  Signatures with +expires+ are always
    #                  rejected once expired.  Default: false.
    # :clock :: A callable returning the current time (a +Time+ or an
    #                  integer), used for all freshness checks.  Inject a
    #                  custom clock in tests.
    #                  Default: <tt>proc{Time.now}</tt>.
    # :trusted_forwarding :: Controls whether forwarding headers are
    #                  trusted when deriving the +@scheme+, +@authority+,
    #                  and +@target-uri+ components.  See the Proxies
    #                  section below.  Default: false (forwarding headers
    #                  are ignored).
    # :sf_field_types :: A hash mapping lowercased field names to their
    #                  structured field type (+:item+, +:list+, or
    #                  +:dictionary+), used when verifying components with
    #                  the +sf+ parameter.  Types are auto-detected for
    #                  fields not listed.
    # :algorithms :: The signature algorithms that are accepted.
    #                  Default: <tt>%w'hmac-sha256 ed25519'</tt>.
    # :label :: The signature label to verify when the verification
    #                  methods are not given one.  By default, requests
    #                  must contain exactly one signature, or the label
    #                  must be passed to the verification methods.
    # :missing_status :: Response status used when the request has no
    #                  usable signature.  Default: 401.
    # :unsupported_status :: Response status used when the signature uses
    #                  an algorithm, key, component, or parameter the
    #                  application does not support.  Default: 400.
    # :invalid_status :: Response status used when signature verification
    #                  fails.  Default: 401.
    #
    # = Request methods
    #
    # verify_http_message_signature!(label=nil) :: Verifies the request's
    #                  signature.  Returns a VerificationResult on success.
    #                  On failure, halts the request with an error
    #                  response, so route block code after the call only
    #                  runs for verified requests.
    # http_message_signature_verified?(label=nil) :: Whether the request's
    #                  signature verifies, without halting.
    # http_message_signature :: The VerificationResult for the request, if
    #                  verification succeeded.
    # http_message_signature_error :: The error raised by the last
    #                  verification attempt, if any.
    #
    # = Errors
    #
    # Verification failures are reported using distinct error classes, all
    # inheriting from HTTPMessageSignatures::Error:
    #
    # SignatureMissingError :: The request does not contain a usable
    #                  signature (no Signature-Input or Signature header,
    #                  or no entry for the expected label).
    # SignatureUnsupportedError :: The signature uses an algorithm, key,
    #                  component, or component parameter the application
    #                  does not support, or the signature input is
    #                  malformed.
    # SignatureVerificationError :: The signature is well formed and
    #                  supported, but is expired, violates the
    #                  verification policy, or does not match the request.
    #
    # Error messages never include key material or signature bytes, and
    # the default error responses have empty bodies, so sensitive material
    # does not leak into error pages.  The error is available via
    # +http_message_signature_error+ for logging.
    #
    # = Custom failure responses
    #
    # By default, failed verification halts with an empty response using
    # the status for the error class.  Pass a block when loading the
    # plugin to customize the response.  The block is called with the
    # error in the scope of the request:
    #
    #   plugin :http_message_signatures, key_resolver: resolver do |error|
    #     response.status = 403
    #     'signature check failed'
    #   end
    #
    # = Proxies
    #
    # Requests may be rewritten by proxies before they reach the
    # application, which affects which original components can be
    # verified:
    #
    # * Header components, +@method+, and +@query+ are taken from the Rack
    #   environment and reflect the request as received by the server.
    #   Repeated header fields are combined with <tt>", "</tt> by the
    #   server, matching RFC 9421 field combination.
    # * +@path+ and +@request-target+ are derived from
    #   SCRIPT_NAME/PATH_INFO and the query string.  If a proxy decodes,
    #   normalizes, or rewrites the path, the original value is lost and
    #   these components cannot be verified; do not require them in that
    #   case.
    # * +@scheme+ and +@authority+ reflect the local connection
    #   (rack.url_scheme, the Host header, SERVER_NAME/SERVER_PORT).  When
    #   a proxy terminates TLS or rewrites the Host header, the original
    #   scheme and authority are only available from forwarding headers
    #   set by the proxy.
    #
    # Forwarding headers (Forwarded, X-Forwarded-Host, X-Forwarded-Proto)
    # are ignored by default, because clients can forge them.  Only enable
    # them if the application is behind a trusted proxy that sets them and
    # strips client-supplied values:
    #
    #   # Trust Forwarded/X-Forwarded-* headers:
    #   plugin :http_message_signatures, key_resolver: resolver,
    #     trusted_forwarding: true
    #
    #   # Or derive the original scheme and authority yourself:
    #   plugin :http_message_signatures, key_resolver: resolver,
    #     trusted_forwarding: proc{|env| MyProxy.original_scheme_and_authority(env)}
    #
    # The proc form is called with the Rack environment and must return a
    # <tt>[scheme, authority]</tt> pair (either entry may be +nil+).
    #
    # = Security considerations
    #
    # * Keep a fresh +created+ requirement (the default +:max_age+), and
    #   consider requiring coverage of +@method+, +@path+, +@authority+,
    #   and +content-digest+ via +:required_components+, so signatures
    #   cannot be replayed against other endpoints or with other bodies.
    # * The plugin does not verify the Content-Digest itself; if the
    #   signature covers +content-digest+, check the digest against the
    #   request body in the route.
    # * ed25519 support requires an OpenSSL version with raw Ed25519 key
    #   support (OpenSSL 1.1.1+); hmac-sha256 works on all supported
    #   versions.
    module HTTPMessageSignatures
      # Base class for all errors raised by the http_message_signatures
      # plugin.
      class Error < StandardError; end

      # Raised when the request does not contain a usable signature.
      class SignatureMissingError < Error; end

      # Raised when the signature uses algorithms, keys, components, or
      # parameters that are not supported, or the signature input is
      # malformed.
      class SignatureUnsupportedError < Error; end

      # Raised when the signature is well formed and supported, but does
      # not verify, is expired, or violates the verification policy.
      class SignatureVerificationError < Error; end

      # The result of a successful signature verification.  Contains
      # metadata about the verified signature; it never contains key
      # material or signature bytes.
      class VerificationResult
        # The label of the verified signature.
        attr_reader :label

        # The keyid signature parameter, if present.
        attr_reader :keyid

        # The signature algorithm that was verified.
        attr_reader :algorithm

        # The covered component identifiers of the signature, as
        # serialized strings (e.g. +"@method"+, +"@query-param";name="Pet"+).
        attr_reader :covered_components

        # The created signature parameter, if present.
        attr_reader :created

        # The expires signature parameter, if present.
        attr_reader :expires

        # The nonce signature parameter, if present.
        attr_reader :nonce

        # The tag signature parameter, if present.
        attr_reader :tag

        def initialize(label, keyid, algorithm, covered_components, created, expires, nonce, tag)
          @label = label
          @keyid = keyid
          @algorithm = algorithm
          @covered_components = covered_components
          @created = created
          @expires = expires
          @nonce = nonce
          @tag = tag
        end

        # A verification result is only created for verified signatures.
        def verified?
          true
        end
      end

      # A minimal RFC 8941 structured field parser and serializer, used
      # for parsing the Signature-Input and Signature headers, and for
      # canonicalizing structured field component values.
      module StructuredField
        # Raised when a structured field value cannot be parsed.
        ParseError = Class.new(StandardError)

        # Represents a structured field token.
        class Token < String; end

        # Represents a structured field byte sequence (decoded content).
        class ByteSequence < String; end

        # A structured field item: a bare value and an ordered list of
        # [key, value] parameters.
        Item = Struct.new(:value, :params)

        # A structured field inner list: a list of items and an ordered
        # list of [key, value] parameters.
        InnerList = Struct.new(:items, :params)

        # A structured field list: an array of Item and InnerList members.
        class List < Array; end

        # A structured field dictionary: an ordered array of
        # [key, Item|InnerList] pairs.
        class Dictionary < Array; end

        TOKEN_CHAR = /\A[!#$%&'*+\-.^_|\x60~0-9A-Za-z:\/]\z/
        KEY_START = /\A[a-z*]\z/
        KEY_CHAR = /\A[a-z0-9_.\-*]\z/
        B64_CHAR = /\A[A-Za-z0-9+\/=]\z/
        B64_RE = /\A[A-Za-z0-9+\/]*={0,2}\z/

        # Parse the given string as a structured field of the given type
        # (+:item+, +:list+, or +:dictionary+).  Raises ParseError if the
        # input is invalid.
        def self.parse(input, type)
          Parser.new(input).parse(type)
        end

        # Serialize a parsed structured field value (Item, InnerList,
        # List, or Dictionary) to its canonical form.
        def self.serialize(member)
          case member
          when InnerList
            serialize_inner_list(member)
          when Item
            serialize_item(member)
          when Dictionary
            serialize_dictionary(member)
          when List
            serialize_list(member)
          else
            raise ArgumentError, "cannot serialize #{member.class}"
          end
        end

        # Serialize a structured field item.
        def self.serialize_item(item)
          out = String.new(serialize_bare_item(item.value))
          out << serialize_parameters(item.params)
          out
        end

        # Serialize a structured field inner list.
        def self.serialize_inner_list(inner)
          out = String.new('(')
          out << inner.items.map{|item| serialize_item(item)}.join(' ')
          out << ')'
          out << serialize_parameters(inner.params)
          out
        end

        # Serialize a structured field list.
        def self.serialize_list(list)
          list.map{|member| serialize(member)}.join(', ')
        end

        # Serialize a structured field dictionary.
        def self.serialize_dictionary(dict)
          dict.map do |key, value|
            if value.is_a?(InnerList)
              String.new(key) << '=' << serialize_inner_list(value)
            elsif value.value == true
              String.new(key) << serialize_parameters(value.params)
            else
              String.new(key) << '=' << serialize_item(value)
            end
          end.join(', ')
        end

        # Serialize structured field parameters.
        def self.serialize_parameters(params)
          out = String.new
          params.each do |key, value|
            out << ';' << key
            out << '=' << serialize_bare_item(value) unless value == true
          end
          out
        end

        # Serialize a structured field bare item.
        def self.serialize_bare_item(value)
          case value
          when Integer
            value.to_s
          when Float
            format('%.3f', value)
          when Token
            value
          when ByteSequence
            String.new(':') << [value].pack('m0') << ':'
          when String
            serialize_string(value)
          when true
            '?1'
          when false
            '?0'
          else
            raise ArgumentError, "cannot serialize #{value.class}"
          end
        end

        # Serialize a structured field string.
        def self.serialize_string(str)
          out = String.new('"')
          str.each_char do |c|
            out << "\\" if c == '"' || c == "\\"
            out << c
          end
          out << '"'
          out
        end

        # Recursive descent structured field parser.
        class Parser
          def initialize(input)
            @s = input.to_s.dup.force_encoding(Encoding::BINARY)
            @i = 0
            @len = @s.length
          end

          def parse(type)
            skip_sp
            result =
              case type
              when :list
                parse_list
              when :dictionary
                parse_dictionary
              when :item
                parse_item
              else
                raise ArgumentError, "unknown structured field type: #{type}"
              end
            skip_sp
            raise ParseError, 'trailing characters after structured field' unless eof?
            result
          end

          private

          def eof?
            @i >= @len
          end

          def peek
            @s[@i]
          end

          def skip_sp
            @i += 1 while !eof? && peek == ' '
          end

          def skip_ows
            @i += 1 while !eof? && (peek == ' ' || peek == "\t")
          end

          def expect(char)
            raise ParseError, "expected #{char}" if eof? || peek != char
            @i += 1
          end

          def parse_list
            members = List.new
            until eof?
              members << parse_item_or_inner_list
              skip_ows
              break if eof?
              expect(',')
              skip_ows
              raise ParseError, 'empty list member' if eof? || peek == ','
            end
            members
          end

          def parse_dictionary
            dict = Dictionary.new
            seen = {}
            until eof?
              key = parse_key
              raise ParseError, "duplicate dictionary key: #{key}" if seen[key]
              seen[key] = true
              value =
                if !eof? && peek == '='
                  @i += 1
                  parse_item_or_inner_list
                else
                  Item.new(true, parse_parameters)
                end
              dict << [key, value]
              skip_ows
              break if eof?
              expect(',')
              skip_ows
              raise ParseError, 'empty dictionary member' if eof? || peek == ','
            end
            dict
          end

          def parse_item_or_inner_list
            if peek == '('
              parse_inner_list
            else
              parse_item
            end
          end

          def parse_item
            Item.new(parse_bare_item, parse_parameters)
          end

          def parse_inner_list
            expect('(')
            items = []
            loop do
              skip_sp
              raise ParseError, 'unterminated inner list' if eof?
              if peek == ')'
                @i += 1
                break
              end
              items << parse_item
              raise ParseError, 'invalid inner list' if eof? || (peek != ' ' && peek != ')')
            end
            InnerList.new(items, parse_parameters)
          end

          def parse_parameters
            params = []
            seen = {}
            while !eof? && peek == ';'
              @i += 1
              skip_sp
              key = parse_key
              raise ParseError, "duplicate parameter: #{key}" if seen[key]
              seen[key] = true
              value = true
              if !eof? && peek == '='
                @i += 1
                value = parse_bare_item
              end
              params << [key, value]
            end
            params
          end

          def parse_bare_item
            raise ParseError, 'missing bare item' if eof?
            case peek
            when '"'
              parse_string
            when ':'
              parse_byte_sequence
            when '?'
              parse_boolean
            when '-', '0'..'9'
              parse_number
            when 'a'..'z', 'A'..'Z', '*'
              parse_token
            else
              raise ParseError, "unexpected character in bare item: #{peek}"
            end
          end

          def parse_number
            start = @i
            @i += 1 if peek == '-'
            int_digits = 0
            while !eof? && peek >= '0' && peek <= '9'
              @i += 1
              int_digits += 1
            end
            raise ParseError, 'invalid number' if int_digits == 0
            if !eof? && peek == '.'
              @i += 1
              frac_digits = 0
              while !eof? && peek >= '0' && peek <= '9'
                @i += 1
                frac_digits += 1
              end
              raise ParseError, 'invalid decimal' if frac_digits == 0
              if int_digits > 12 || frac_digits > 3
                raise ParseError, 'too many digits in decimal'
              end
              @s[start...@i].to_f
            else
              raise ParseError, 'too many digits in integer' if int_digits > 15
              @s[start...@i].to_i
            end
          end

          def parse_string
            expect('"')
            out = String.new
            until eof?
              c = peek
              @i += 1
              case c
              when '"'
                return out
              when "\\"
                raise ParseError, 'invalid escape in string' if eof?
                c = peek
                @i += 1
                unless c == '"' || c == "\\"
                  raise ParseError, 'invalid escape in string'
                end
                out << c
              else
                raise ParseError, 'invalid character in string' if c < ' ' || c > '~'
                out << c
              end
            end
            raise ParseError, 'unterminated string'
          end

          def parse_token
            start = @i
            @i += 1
            @i += 1 while !eof? && peek =~ TOKEN_CHAR
            Token.new(@s[start...@i])
          end

          def parse_byte_sequence
            expect(':')
            start = @i
            @i += 1 while !eof? && peek =~ B64_CHAR
            raise ParseError, 'unterminated byte sequence' if eof?
            b64 = @s[start...@i]
            expect(':')
            unless b64.length % 4 == 0 && b64 =~ B64_RE
              raise ParseError, 'invalid byte sequence'
            end
            ByteSequence.new(Base64.strict_decode64(b64))
          end

          def parse_boolean
            expect('?')
            raise ParseError, 'invalid boolean' if eof?
            c = peek
            @i += 1
            return true if c == '1'
            return false if c == '0'
            raise ParseError, 'invalid boolean'
          end

          def parse_key
            raise ParseError, 'invalid key' if eof? || peek !~ KEY_START
            start = @i
            @i += 1
            @i += 1 while !eof? && peek =~ KEY_CHAR
            @s[start...@i]
          end
        end
      end
    end
  end
end
