require_relative "../spec_helper"

describe "json_rpc plugin" do
  before do
    calls = @calls = []
    notification_errors = @notification_errors = []

    app(:bare) do
      plugin :json_rpc, :error_handler => proc { |error| notification_errors << error }

      json_rpc_method(:add, lambda { |left, right|
        calls << [:add, left, right]
        left + right
      })

      json_rpc_method(:greet, lambda { |first:, last: "Smith"| "#{first} #{last}" })
      json_rpc_method(:splat, lambda { |*values| values })
      json_rpc_method(:keywords, lambda { |**keywords| keywords })
      json_rpc_method(:notify, lambda { calls << :notify })
      json_rpc_method(:bad_arguments) { |value| value.fetch(:required) }
      json_rpc_method(:boom, lambda { |_| raise ArgumentError, "inside method" })
      json_rpc_method(:echo_keyword) { |value:| value }

      route do |r|
        r.post "rpc" do
          r.json_rpc
        end
      end
    end
  end

  def post_json_rpc(data, raw: false, content_type: "application/json")
    body = raw ? data : JSON.generate(data)
    response = req("/rpc",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => content_type,
      "rack.input" => rack_input(body))
    unless response.is_a?(Array) && response.length == 3
      raise "unexpected response: #{response.inspect}"
    end
    response
  end

  def post_json_rpc_json(data, raw: false)
    response = post_json_rpc(data, raw: raw)
    parsed = JSON.parse(response[2].to_enum.to_a.join)
    [response[0], response[1], parsed]
  end

  it "handles a successful positional request and preserves numeric, string, and null ids" do
    status, headers, body = post_json_rpc_json({
      "jsonrpc" => "2.0", "method" => "add", "params" => [2, 3], "id" => 7})
    status.must_equal 200
    headers[RodaResponseHeaders::CONTENT_TYPE].must_equal "application/json"
    body.must_equal("jsonrpc" => "2.0", "result" => 5, "id" => 7)

    _status, _headers, string_body = post_json_rpc_json({
      "jsonrpc" => "2.0", "method" => "add", "params" => [1, 4], "id" => "seven"})
    string_body["id"].must_equal "seven"
    string_body["result"].must_equal 5

    _status, _headers, null_body = post_json_rpc_json({
      "jsonrpc" => "2.0", "method" => "add", "params" => [1, 4], "id" => nil})
    null_body["id"].must_be_nil
  end

  it "binds named parameters to required and optional keyword arguments" do
    _status, _headers, body = post_json_rpc_json({
      "jsonrpc" => "2.0",
      "method" => "greet",
      "params" => {"first" => "Jane"},
      "id" => 1})
    body["result"].must_equal "Jane Smith"

    _status, _headers, body = post_json_rpc_json({
      "jsonrpc" => "2.0",
      "method" => "greet",
      "params" => {"first" => "Jane", "last" => "Doe"},
      "id" => 2})
    body["result"].must_equal "Jane Doe"

    _status, _headers, body = post_json_rpc_json({
      "jsonrpc" => "2.0",
      "method" => "keywords",
      "params" => {"enabled" => true, "count" => 3},
      "id" => 3})
    body["result"].must_equal("enabled" => true, "count" => 3)
  end

  it "binds named parameters to named positional arguments and supports rest parameters" do
    _status, _headers, body = post_json_rpc_json({
      "jsonrpc" => "2.0",
      "method" => "add",
      "params" => {"left" => 8, "right" => 9},
      "id" => 1})
    body["result"].must_equal 17

    _status, _headers, body = post_json_rpc_json({
      "jsonrpc" => "2.0", "method" => "splat", "params" => [1, 2, 3], "id" => 2})
    body["result"].must_equal [1, 2, 3]
  end

  it "binds named parameters to keyword arguments in inline blocks" do
    _status, _headers, body = post_json_rpc_json({
      "jsonrpc" => "2.0",
      "method" => "echo_keyword",
      "params" => {"value" => "ok"},
      "id" => 1})
    body["result"].must_equal "ok"
  end

  it "returns no response for a single notification" do
    status, _headers, response_body = post_json_rpc({"jsonrpc" => "2.0", "method" => "notify"})
    status.must_equal 204
    response_body.to_enum.to_a.must_equal []
    @calls.must_equal [:notify]
  end

  it "returns no response for a batch containing only notifications" do
    status, _headers, response_body = post_json_rpc([
      {"jsonrpc" => "2.0", "method" => "notify"},
      {"jsonrpc" => "2.0", "method" => "add", "params" => [1, 2]}
    ])

    status.must_equal 204
    response_body.to_enum.to_a.must_equal []
    @calls.must_equal [:notify, [:add, 1, 2]]
  end

  it "processes every batch member and preserves response order and ids" do
    status, _headers, body = post_json_rpc_json([
      {"jsonrpc" => "2.0", "method" => "add", "params" => [1, 2], "id" => 1},
      {"jsonrpc" => "2.0", "method" => "notify"},
      {"jsonrpc" => "2.0", "method" => "boom", "params" => [1]},
      "not-json-rpc",
      {"jsonrpc" => "2.0", "method" => "missing", "id" => "2"},
      {"jsonrpc" => "2.0", "method" => "add", "params" => [1], "id" => nil},
      {"jsonrpc" => "2.0", "method" => "bad_arguments", "params" => [{}], "id" => "3"},
      {"jsonrpc" => "2.0", "method" => "greet", "params" => {"last" => "Doe"}, "id" => 4},
      {"jsonrpc" => "2.0", "method" => "add", "params" => [3, 4], "id" => 5}
    ])

    status.must_equal 200
    body.map { |response| [response["id"], response["error"] && response["error"]["code"]] }.must_equal [
      [1, nil],
      [nil, -32600],
      ["2", -32601],
      [nil, -32602],
      ["3", -32603],
      [4, -32602],
      [5, nil]
    ]
    body[0]["result"].must_equal 3
    body[-1]["result"].must_equal 7
    @calls.must_equal [[:add, 1, 2], :notify, [:add, 3, 4]]
    @notification_errors.map(&:class).must_equal [ArgumentError]
  end

  it "returns parse and invalid request errors with a null id" do
    _status, _headers, body = post_json_rpc_json("{", raw: true)
    body.must_equal("jsonrpc" => "2.0", "error" => {"code" => -32700, "message" => "Parse error"}, "id" => nil)

    _status, _headers, body = post_json_rpc_json({"method" => "add", "id" => 1})
    body["id"].must_be_nil
    body["error"]["code"].must_equal(-32600)

    _status, _headers, body = post_json_rpc_json([])
    body["id"].must_be_nil
    body["error"]["code"].must_equal(-32600)

    _status, _headers, body = post_json_rpc_json({"jsonrpc" => "2.0", "method" => "add", "params" => 5, "id" => 1})
    body["error"]["code"].must_equal(-32600)

    _status, _headers, body = post_json_rpc_json({"jsonrpc" => "2.0", "method" => "add", "id" => true})
    body["error"]["code"].must_equal(-32600)
  end

  it "distinguishes parameter binding errors from ArgumentError raised inside a method" do
    _status, _headers, binding_body = post_json_rpc_json({
      "jsonrpc" => "2.0", "method" => "add", "params" => [1], "id" => 1})
    binding_body["error"]["code"].must_equal(-32602)

    _status, _headers, unknown_body = post_json_rpc_json({
      "jsonrpc" => "2.0",
      "method" => "greet",
      "params" => {"first" => "A", "unknown" => true},
      "id" => 2})
    unknown_body["error"]["code"].must_equal(-32602)

    _status, _headers, internal_body = post_json_rpc_json({
      "jsonrpc" => "2.0", "method" => "boom", "params" => [1], "id" => 3})
    internal_body["error"]["code"].must_equal(-32603)

    _status, _headers, internal_argument_body = post_json_rpc_json({
      "jsonrpc" => "2.0",
      "method" => "bad_arguments",
      "params" => [{}],
      "id" => 4})
    internal_argument_body["error"]["code"].must_equal(-32603)
    @notification_errors.must_be :empty?
  end

  it "does not expose arbitrary methods and sends notification exceptions to the local hook" do
    _status, _headers, body = post_json_rpc_json({"jsonrpc" => "2.0", "method" => "class", "id" => 1})
    body["error"]["code"].must_equal(-32601)

    post_json_rpc({"jsonrpc" => "2.0", "method" => "boom", "params" => [1]})
    @notification_errors.length.must_equal 1
    @notification_errors.first.must_be_instance_of ArgumentError
  end

  it "supports custom parser and serializer callables" do
    app(:bare) do
      plugin :json_rpc,
        :parser => proc { |body| JSON.parse(body) },
        :serializer => proc { |object| JSON.generate(object).upcase }

      json_rpc_method(:add, lambda { |a, b| a + b })

      route do |r|
        r.post("rpc") { r.json_rpc }
      end
    end

    _status, _headers, response_body = post_json_rpc({
      "jsonrpc" => "2.0", "method" => "add", "params" => [2, 5], "id" => 1})
    response_body.to_enum.to_a.join.must_equal({"jsonrpc" => "2.0", "result" => 7, "id" => 1}.to_json.upcase)
  end
end
