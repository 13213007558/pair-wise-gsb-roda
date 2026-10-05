require_relative "../spec_helper"
require "base64"
require "openssl"

describe "http_message_signatures plugin" do
  # RFC 9421 Appendix B.1.4 shared HMAC key (test-shared-secret)
  HMAC_SECRET = Base64.decode64("uzvJfB4u3N0Jy4T7NZ75N9sZuIa3zqTMDdMGRM2xJ1Q=").freeze

  # RFC 9421 Appendix B.1.3 Ed25519 keys (test-key-ed25519)
  ED25519_PRIVATE_KEY = OpenSSL::PKey.read(Base64.decode64("MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF"))
  ED25519_PUBLIC_KEY = Base64.decode64("JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=").freeze

  # RFC 9421 Appendix B.2 example Content-Digest field value
  CONTENT_DIGEST = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:".freeze

  # Rack environment matching the RFC 9421 Appendix B.2 example request
  RFC_ENV = {
    "REQUEST_METHOD" => "POST",
    "PATH_INFO" => "/foo",
    "QUERY_STRING" => "param=Value&Pet=dog",
    "HTTP_HOST" => "example.com",
    "HTTP_DATE" => "Tue, 20 Apr 2021 02:07:55 GMT",
    "CONTENT_TYPE" => "application/json",
    "HTTP_CONTENT_DIGEST" => CONTENT_DIGEST,
    "CONTENT_LENGTH" => "18"
  }.freeze

  # created parameter value used by the RFC 9421 Appendix B.2 examples
  CREATED = 1618884473

  def signed_app(opts={}, &block)
    key_resolver = opts.delete(:key_resolver){proc{|keyid, _, _| keyid == "test-shared-secret" ? HMAC_SECRET : nil}}
    app(:bare) do
      plugin :http_message_signatures, {key_resolver: key_resolver}.merge(opts)
      route(&block)
    end
  end

  def callback_app(opts={})
    signed_app(opts) do |r|
      r.post "callback" do
        signature = check_http_message_signature!
        "verified #{signature.keyid}"
      end
    end
  end

  def hmac_signature(base)
    Base64.strict_encode64(OpenSSL::HMAC.digest("SHA256", HMAC_SECRET, base))
  end

  def ed25519_signature(base)
    Base64.strict_encode64(ED25519_PRIVATE_KEY.sign(nil, base))
  end

  def callback_env(input, signature, extra={})
    {
      "REQUEST_METHOD" => "POST",
      "PATH_INFO" => "/callback",
      "HTTP_SIGNATURE_INPUT" => "sig1=#{input}",
      "HTTP_SIGNATURE" => "sig1=:#{signature}:"
    }.merge(extra)
  end

  it "requires a callable :key_resolver option" do
    proc{app.plugin :http_message_signatures}.must_raise Roda::RodaError
    proc{app.plugin :http_message_signatures, key_resolver: nil}.must_raise Roda::RodaError
    proc{app.plugin :http_message_signatures, key_resolver: "secret"}.must_raise Roda::RodaError
  end

  it "verifies the RFC 9421 Appendix B.2.4 hmac-sha256 vector" do
    # The RFC 9421 Appendix B.2.4 example does not include an alg
    # parameter, so a default algorithm is configured.
    signed_app(now: proc{Time.at(CREATED)}, default_algorithm: "hmac-sha256") do |r|
      r.post "foo" do
        signature = check_http_message_signature!
        "verified #{signature.keyid}"
      end
    end
    # The signature value is HMAC-SHA256 over the RFC 9421 Appendix
    # B.2.4 signature base, keyed with the Appendix B.1.4 shared key.
    env = RFC_ENV.merge(
      "HTTP_SIGNATURE_INPUT" => 'sig-b24=("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-shared-secret"',
      "HTTP_SIGNATURE" => "sig-b24=:205VjYdFG2NUhkTZN9Pixwkp5wOu/dL+Hvk9Lu9BvOQ=:"
    )
    status(env).must_equal 200
    body(env).must_equal "verified test-shared-secret"
  end

  it "constructs the RFC 9421 Appendix B.2.1 signature base (minimal coverage)" do
    signed_app(now: proc{Time.at(CREATED)}, default_algorithm: "hmac-sha256",
               key_resolver: proc{|*| HMAC_SECRET}) do |r|
      r.post "foo" do
        check_http_message_signature!
        "verified"
      end
    end
    # HMAC-SHA256 over the RFC 9421 Appendix B.2.1 signature base,
    # which consists of only the "@signature-params" line.
    env = RFC_ENV.merge(
      "HTTP_SIGNATURE_INPUT" => 'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnzmecx"',
      "HTTP_SIGNATURE" => "sig-b21=:FaYcZPuU1idv5mn+iH/hTTHtmKrIcOL5g7FSCBoBwC4=:"
    )
    status(env).must_equal 200
  end

  it "constructs the RFC 9421 Appendix B.2.2 signature base (selective components)" do
    signed_app(now: proc{Time.at(CREATED)}, default_algorithm: "hmac-sha256",
               key_resolver: proc{|*| HMAC_SECRET}) do |r|
      r.post "foo" do
        check_http_message_signature!
        "verified"
      end
    end
    # HMAC-SHA256 over the RFC 9421 Appendix B.2.2 signature base,
    # exercising "@query-param";name="Pet" component identifier
    # serialization and query parameter selection.
    env = RFC_ENV.merge(
      "HTTP_SIGNATURE_INPUT" => 'sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
      "HTTP_SIGNATURE" => "sig-b22=:PX5RhkgmvID29fx/pBeaCBuWL3jPWiqzirqOwgsUVHs=:"
    )
    status(env).must_equal 200
  end

  it "constructs the RFC 9421 Appendix B.2.3 signature base (full coverage)" do
    signed_app(now: proc{Time.at(CREATED)}, default_algorithm: "hmac-sha256",
               key_resolver: proc{|*| HMAC_SECRET}) do |r|
      r.post "foo" do
        check_http_message_signature!
        "verified"
      end
    end
    # HMAC-SHA256 over the RFC 9421 Appendix B.2.3 signature base,
    # covering the date field and the @query derived component.
    env = RFC_ENV.merge(
      "HTTP_SIGNATURE_INPUT" => 'sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
      "HTTP_SIGNATURE" => "sig-b23=:l1m6O5mt1/JtkWZrIi+kG5mRckmnFz7CEeJPLdh8XRg=:"
    )
    status(env).must_equal 200
  end

  it "verifies an ed25519 signature using the RFC 9421 Appendix B.1.3 key" do
    signed_app(now: proc{Time.at(CREATED)},
               key_resolver: proc{|keyid, _, _| keyid == "test-key-ed25519" ? ED25519_PUBLIC_KEY : nil}) do |r|
      r.post "foo" do
        signature = check_http_message_signature!
        "verified #{signature.keyid}"
      end
    end
    # Ed25519 signature over the signature base for the RFC 9421
    # Appendix B.2 example request, made with the Appendix B.1.3
    # private key (Ed25519 is deterministic, so this is a fixed vector).
    env = RFC_ENV.merge(
      "HTTP_SIGNATURE_INPUT" => 'sig1=("@method" "@authority" "@path" "content-digest");created=1618884473;keyid="test-key-ed25519";alg="ed25519"',
      "HTTP_SIGNATURE" => "sig1=:+AR15WygAd+8fsj2ptnUAgO5HQhsFEQQUneH2/TLA2tsyEZE3ZWx3SaD/N8xEBXFxvTkgBrt3zOk4q4Skl+nBA==:"
    )
    status(env).must_equal 200
    body(env).must_equal "verified test-key-ed25519"
  end

  it "supports ed25519 keys in raw, DER, PEM, and PKey form" do
    [
      ED25519_PUBLIC_KEY,
      ED25519_PRIVATE_KEY.public_to_der,
      ED25519_PRIVATE_KEY.public_to_pem,
      OpenSSL::PKey.read(ED25519_PRIVATE_KEY.public_to_der)
    ].each do |key|
      signed_app(now: proc{Time.at(CREATED)}, key_resolver: proc{|*| key}) do |r|
        r.post "callback" do
          check_http_message_signature!
          "verified"
        end
      end
      input = '("@method" "@path");created=1618884473;keyid="k";alg="ed25519"'
      base = [
        '"@method": POST',
        '"@path": /callback',
        '"@signature-params": ("@method" "@path");created=1618884473;keyid="k";alg="ed25519"'
      ].join("\n")
      status(callback_env(input, ed25519_signature(base))).must_equal 200
    end
  end

  it "only reaches the route block when verification succeeds" do
    reached = []
    signed_app do |r|
      r.post "callback" do
        check_http_message_signature!
        reached << true
        "verified"
      end
    end
    status("REQUEST_METHOD" => "POST", "PATH_INFO" => "/callback").must_equal 401
    reached.must_equal []

    input = '("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base))).must_equal 200
    reached.must_equal [true]
  end

  it "returns 401 when the signature is missing" do
    callback_app
    env = {"REQUEST_METHOD" => "POST", "PATH_INFO" => "/callback"}
    status(env).must_equal 401
    body(env).must_equal ""

    env["HTTP_SIGNATURE_INPUT"] = 'sig1=("@method");created=1618884473;keyid="k";alg="hmac-sha256"'
    status(env).must_equal 401

    env.delete("HTTP_SIGNATURE_INPUT")
    env["HTTP_SIGNATURE"] = "sig1=:eA==:"
    status(env).must_equal 401
  end

  it "returns 400 when the signature is unsupported" do
    callback_app
    # unsupported algorithm
    status(callback_env('("@method");created=1618884473;keyid="k";alg="rsa-pss-sha512"', "eA==")).must_equal 400
    # missing alg parameter without a default algorithm
    status(callback_env('("@method");created=1618884473;keyid="k"', "eA==")).must_equal 400
    # malformed Signature-Input
    status(callback_env('("@method";created=', "eA==")).must_equal 400
    # Signature entry is not a byte sequence
    status(callback_env('("@method");created=1618884473;keyid="k";alg="hmac-sha256"', "eA==").merge("HTTP_SIGNATURE" => "sig1=1")).must_equal 400
    # response-only derived component
    status(callback_env('("@status");created=1618884473;keyid="k";alg="hmac-sha256"', "eA==")).must_equal 400
    # unknown derived component
    status(callback_env('("@unknown");created=1618884473;keyid="k";alg="hmac-sha256"', "eA==")).must_equal 400
    # unsupported component parameter
    status(callback_env('("date";tr);created=1618884473;keyid="k";alg="hmac-sha256"', "eA==")).must_equal 400
    # covered field not present in the request
    status(callback_env('("x-missing");created=1618884473;keyid="k";alg="hmac-sha256"', "eA==")).must_equal 400
  end

  it "returns 403 when the signature does not verify" do
    callback_app
    input = '("@method" "@path");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      '"@path": /callback',
      '"@signature-params": ("@method" "@path");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    # signature computed over different data
    status(callback_env(input, hmac_signature("different base"))).must_equal 403
    # unknown key
    status(callback_env('("@method" "@path");created=1618884473;keyid="unknown";alg="hmac-sha256"', hmac_signature(base))).must_equal 403
    # valid signature
    status(callback_env(input, hmac_signature(base))).must_equal 200
  end

  it "returns 403 when a covered header is modified after signing" do
    callback_app
    input = '("@method" "x-api-version");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      '"x-api-version": 1',
      '"@signature-params": ("@method" "x-api-version");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    env = callback_env(input, hmac_signature(base), "HTTP_X_API_VERSION" => "2")
    status(env).must_equal 403
    env["HTTP_X_API_VERSION"] = "1"
    status(env).must_equal 200
  end

  it "distinguishes missing, unsupported, and failed signatures with separate errors" do
    signed_app do |r|
      r.post "callback" do
        begin
          r.verify_http_message_signature
          "none"
        rescue Roda::RodaPlugins::HTTPMessageSignatures::Error => e
          e.class.name.split("::").last
        end
      end
    end
    body("REQUEST_METHOD" => "POST", "PATH_INFO" => "/callback").must_equal "SignatureMissing"
    body(callback_env('("@method");created=1618884473;keyid="k";alg="rsa-pss-sha512"', "eA==")).must_equal "SignatureUnsupported"
    input = '("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    body(callback_env(input, hmac_signature("tampered"))).must_equal "SignatureVerificationFailed"
  end

  it "passes the keyid, signature parameters, and request to the key resolver" do
    received = []
    resolver = proc{|keyid, params, request| received << [keyid, params, request]; HMAC_SECRET}
    signed_app(key_resolver: resolver) do |r|
      r.post "callback" do
        check_http_message_signature!
        "verified"
      end
    end
    input = '("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256";nonce="abc"'
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256";nonce="abc"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base))).must_equal 200
    keyid, params, request = received[0]
    keyid.must_equal "test-shared-secret"
    params[:created].must_equal 1618884473
    params[:alg].must_equal "hmac-sha256"
    params[:nonce].must_equal "abc"
    request.must_be_kind_of Roda::RodaRequest
  end

  it "supports restricting algorithms with the :algorithms option" do
    callback_app(algorithms: %w[ed25519])
    input = '("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base))).must_equal 400
  end

  it "supports a :default_algorithm for signatures without an alg parameter" do
    callback_app(default_algorithm: "hmac-sha256")
    input = '("@method");created=1618884473;keyid="test-shared-secret"'
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");created=1618884473;keyid="test-shared-secret"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base))).must_equal 200
  end

  it "uses the :now option for time based checks" do
    input = '("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    env = callback_env(input, hmac_signature(base))

    callback_app(now: proc{Time.at(CREATED + 100)}, max_age: 60)
    status(env).must_equal 403

    callback_app(now: proc{Time.at(CREATED + 30)}, max_age: 60)
    status(env).must_equal 200

    callback_app(now: proc{Time.at(CREATED - 120)})
    status(env).must_equal 403

    callback_app(now: proc{Time.at(CREATED - 30)})
    status(env).must_equal 200
  end

  it "rejects expired signatures" do
    input = '("@method");created=1618884473;expires=1618884503;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");created=1618884473;expires=1618884503;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    env = callback_env(input, hmac_signature(base))

    callback_app(now: proc{Time.at(CREATED)})
    status(env).must_equal 200

    callback_app(now: proc{Time.at(CREATED + 1000)})
    status(env).must_equal 403
  end

  it "requires a created parameter when :max_age is used" do
    input = '("@method");keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    callback_app(max_age: 60)
    status(callback_env(input, hmac_signature(base))).must_equal 403
  end

  it "enforces the :required_components option" do
    callback_app(required_components: ["@method", "content-digest"])
    input = '("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base))).must_equal 403

    input = '("@method" "content-digest");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@method": POST',
      "\"content-digest\": #{CONTENT_DIGEST}",
      '"@signature-params": ("@method" "content-digest");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base), "HTTP_CONTENT_DIGEST" => CONTENT_DIGEST)).must_equal 200
  end

  it "combines repeated field lines when building the signature base" do
    callback_app
    input = '("x-dupe");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"x-dupe": a, b',
      '"@signature-params": ("x-dupe");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    # Multiple field lines (newline separated in the Rack environment)
    status(callback_env(input, hmac_signature(base), "HTTP_X_DUPE" => "a\nb")).must_equal 200
    # Already combined field value
    status(callback_env(input, hmac_signature(base), "HTTP_X_DUPE" => "a, b")).must_equal 200
  end

  it "supports the sf component parameter" do
    callback_app
    input = '("x-tokens";sf);created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"x-tokens";sf: ("a" "b");foo=bar',
      '"@signature-params": ("x-tokens";sf);created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    # Non-canonical spacing is normalized by reserialization
    status(callback_env(input, hmac_signature(base), "HTTP_X_TOKENS" => '( "a"   "b" );foo=bar')).must_equal 200
    # Invalid structured field
    status(callback_env(input, hmac_signature(base), "HTTP_X_TOKENS" => '"unterminated')).must_equal 400
  end

  it "supports the key component parameter" do
    callback_app
    input = '("x-dict";key="b");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"x-dict";key="b": 2',
      '"@signature-params": ("x-dict";key="b");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base), "HTTP_X_DICT" => "a=1, b=2")).must_equal 200
    # Missing dictionary member
    status(callback_env(input, hmac_signature(base), "HTTP_X_DICT" => "a=1")).must_equal 400
  end

  it "selects and percent-decodes query parameters" do
    callback_app
    input = '("@query-param";name="a b");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@query-param";name="a b": x+y',
      '"@signature-params": ("@query-param";name="a b");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base), "QUERY_STRING" => "a%20b=x%2By")).must_equal 200
    # Missing parameter
    status(callback_env(input, hmac_signature(base), "QUERY_STRING" => "c=d")).must_equal 400
    # Duplicated parameter
    status(callback_env(input, hmac_signature(base), "QUERY_STRING" => "a%20b=1&a%20b=2")).must_equal 400
  end

  it "supports the @target-uri, @request-target, @scheme, and @query derived components" do
    callback_app
    input = '("@target-uri" "@request-target" "@scheme" "@query");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@target-uri": https://example.com/callback?a=1',
      '"@request-target": /callback?a=1',
      '"@scheme": https',
      '"@query": ?a=1',
      '"@signature-params": ("@target-uri" "@request-target" "@scheme" "@query");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    env = callback_env(input, hmac_signature(base),
      "QUERY_STRING" => "a=1", "HTTP_HOST" => "example.com", "rack.url_scheme" => "https")
    status(env).must_equal 200
  end

  it "uses a lone question mark for @query when the query string is empty" do
    callback_app
    input = '("@query");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@query": ?',
      '"@signature-params": ("@query");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    status(callback_env(input, hmac_signature(base))).must_equal 200
  end

  it "does not trust the Forwarded header by default" do
    callback_app
    input = '("@scheme" "@authority");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@scheme": http',
      '"@authority": example.com',
      '"@signature-params": ("@scheme" "@authority");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    env = callback_env(input, hmac_signature(base),
      "HTTP_HOST" => "example.com", "rack.url_scheme" => "http",
      "HTTP_FORWARDED" => "for=192.0.2.1;proto=https;host=forged.example")
    status(env).must_equal 200
  end

  it "uses the Forwarded header when :trusted_forwarded is enabled" do
    callback_app(trusted_forwarded: true)
    input = '("@scheme" "@authority");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@scheme": https',
      '"@authority": api.example.com',
      '"@signature-params": ("@scheme" "@authority");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    env = callback_env(input, hmac_signature(base),
      "HTTP_HOST" => "internal:8080", "rack.url_scheme" => "http",
      "HTTP_FORWARDED" => 'for=192.0.2.1;proto=https;host="api.example.com"')
    status(env).must_equal 200
  end

  it "uses the given Forwarded element from the right when :trusted_forwarded is an integer" do
    callback_app(trusted_forwarded: 2)
    input = '("@scheme" "@authority");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    base = [
      '"@scheme": https',
      '"@authority": api.example.com',
      '"@signature-params": ("@scheme" "@authority");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    env = callback_env(input, hmac_signature(base),
      "HTTP_HOST" => "internal:8080", "rack.url_scheme" => "http",
      "HTTP_FORWARDED" => "proto=https;host=api.example.com, for=10.0.0.1;proto=http;host=internal")
    status(env).must_equal 200
  end

  it "verifies the requested label when multiple signatures are present" do
    signed_app do |r|
      r.post "callback" do
        signature = check_http_message_signature!("sig2")
        "verified #{signature.label}"
      end
    end
    base = [
      '"@method": POST',
      '"@signature-params": ("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    ].join("\n")
    env = {
      "REQUEST_METHOD" => "POST",
      "PATH_INFO" => "/callback",
      "HTTP_SIGNATURE_INPUT" => 'sig1=("@method");created=1618884473;keyid="unknown";alg="hmac-sha256", sig2=("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"',
      "HTTP_SIGNATURE" => "sig1=:eA==:, sig2=:#{hmac_signature(base)}:"
    }
    status(env).must_equal 200
    body(env).must_equal "verified sig2"

    # Multiple signatures without a requested label are ambiguous
    signed_app do |r|
      r.post "callback" do
        check_http_message_signature!
        "verified"
      end
    end
    status(env).must_equal 401
  end

  it "does not include key or signature material in error responses" do
    callback_app
    input = '("@method");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
    env = callback_env(input, hmac_signature("tampered base"))
    status(env).must_equal 403
    body(env).must_equal ""
    body(env).wont_include HMAC_SECRET
    body(env).wont_include hmac_signature("tampered base")
  end

  it "supports a custom error block" do
    app(:bare) do
      plugin :http_message_signatures, key_resolver: proc{|*| nil} do |request, error|
        response.status = 422
        "custom #{error.class.name.split('::').last}"
      end
      route do |r|
        r.post "callback" do
          check_http_message_signature!
          "verified"
        end
      end
    end
    env = {"REQUEST_METHOD" => "POST", "PATH_INFO" => "/callback"}
    status(env).must_equal 422
    body(env).must_equal "custom SignatureMissing"
  end
end
