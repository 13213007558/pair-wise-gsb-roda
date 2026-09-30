require_relative "../spec_helper"
require "json"

describe "json_rpc plugin" do
  def rpc_app(&block)
    app(:bare) do
      plugin :json_rpc
      class_exec(&block) if block
      route do |r|
        r.post "rpc" do
          r.json_rpc
        end
      end
    end
  end

  def rpc_request(payload, content_type="application/json")
    body = payload.is_a?(String) ? payload : JSON.generate(payload)
    req("/rpc", "REQUEST_METHOD" => "POST",
        "CONTENT_TYPE" => content_type,
        "rack.input" => rack_input(body))
  end

  def rpc_json(payload, content_type="application/json")
    response = rpc_request(payload, content_type)
    JSON.parse(response[2].to_enum(:each).to_a.join)
  end

  it "supports a single positional call" do
    rpc_app do
      json_rpc_method("add", proc { |a, b| a + b })
    end

    response = rpc_request({
      "jsonrpc" => "2.0",
      "method" => "add",
      "params" => [2, 3],
      "id" => 7
    })

    response[0].must_equal 200
    response[1]["Content-Type"].must_equal "application/json"
    JSON.parse(response[2].to_enum(:each).to_a.join).must_equal(
      "jsonrpc" => "2.0",
      "result" => 5,
      "id" => 7
    )
  end

  it "supports named positional arguments and Ruby keyword arguments" do
    calls = []
    rpc_app do
      json_rpc_method("positional") do |left, right|
        calls << [left, right]
        left * right
      end
      json_rpc_method("keywords", lambda { |enabled:, count: 1| [enabled, count] })
    end

    positional = rpc_json(
      "jsonrpc" => "2.0",
      "method" => "positional",
      "params" => {"left" => 4, "right" => 5},
      "id" => "one"
    )
    keywords = rpc_json(
      "jsonrpc" => "2.0",
      "method" => "keywords",
      "params" => {"enabled" => true, "count" => 3},
      "id" => "two"
    )
    defaults = rpc_json(
      "jsonrpc" => "2.0",
      "method" => "keywords",
      "params" => {"enabled" => false},
      "id" => nil
    )

    positional.must_equal("jsonrpc" => "2.0", "result" => 20, "id" => "one")
    keywords.must_equal("jsonrpc" => "2.0", "result" => [true, 3], "id" => "two")
    defaults.must_equal("jsonrpc" => "2.0", "result" => [false, 1], "id" => nil)
    calls.must_equal [[4, 5]]
  end

  it "preserves positional defaults when named parameters omit trailing arguments" do
    rpc_app do
      json_rpc_method("defaults") { |required, optional = 2| [required, optional] }
      json_rpc_method("variadic") { |first, *rest| [first, rest] }
    end

    defaults = rpc_json(
      "jsonrpc" => "2.0",
      "method" => "defaults",
      "params" => {"required" => 1},
      "id" => 1
    )
    variadic = rpc_json(
      "jsonrpc" => "2.0",
      "method" => "variadic",
      "params" => {"first" => 1, "rest" => [2, 3]},
      "id" => 2
    )
    gap = rpc_json(
      "jsonrpc" => "2.0",
      "method" => "defaults",
      "params" => {"optional" => 3},
      "id" => 3
    )

    defaults["result"].must_equal [1, 2]
    variadic["result"].must_equal [1, [2, 3]]
    gap["error"]["code"].must_equal(-32602)
  end

  it "accepts numeric string and null ids, but not malformed ids" do
    rpc_app do
      json_rpc_method("value", proc { |value| value })
    end

    float = rpc_json("jsonrpc" => "2.0", "method" => "value", "params" => [1], "id" => 1.5)
    string = rpc_json("jsonrpc" => "2.0", "method" => "value", "params" => [2], "id" => "id")
    null = rpc_json("jsonrpc" => "2.0", "method" => "value", "params" => [3], "id" => nil)
    missing = rpc_request("jsonrpc" => "2.0", "method" => "value", "params" => [4])

    float["id"].must_equal 1.5
    string["id"].must_equal "id"
    null.must_include "id"
    null["id"].must_be_nil
    missing[0].must_equal 204
    missing[2].to_enum(:each).to_a.must_equal []
  end

  it "supports symbol method names and symbol parameter keys" do
    rpc_app do
      json_rpc_method(:echo) { |value:| value }
    end

    result = rpc_json(
      "jsonrpc" => "2.0",
      "method" => "echo",
      "params" => {:value => "ok"},
      "id" => 9
    )

    result.must_equal("jsonrpc" => "2.0", "result" => "ok", "id" => 9)
  end

  it "accepts methods through the methods option" do
    app(:bare) do
      plugin :json_rpc, methods: {"configured" => proc { |value| value }}
      route do |r|
        r.post { r.json_rpc }
      end
    end

    configured = rpc_json("jsonrpc" => "2.0", "method" => "configured", "params" => [7], "id" => 1)

    configured["result"].must_equal 7
  end

  it "returns a parse error for malformed JSON" do
    rpc_app
    result = rpc_json("{")

    result.must_equal(
      "jsonrpc" => "2.0",
      "error" => {"code" => -32700, "message" => "Parse error"},
      "id" => nil
    )
  end

  it "returns invalid request errors without echoing malformed ids" do
    rpc_app

    result = rpc_json({
      "jsonrpc" => "1.0",
      "method" => "missing",
      "id" => {"unexpected" => true}
    })

    result.must_equal(
      "jsonrpc" => "2.0",
      "error" => {"code" => -32600, "message" => "Invalid Request"},
      "id" => nil
    )
  end

  it "uses distinct errors for unknown methods, binding failures, and handler exceptions" do
    rpc_app do
      json_rpc_method("requires") { |needed:| needed }
      json_rpc_method("boom") { raise ArgumentError, "inside the method" }
    end

    unknown = rpc_json("jsonrpc" => "2.0", "method" => "missing", "id" => 1)
    invalid = rpc_json("jsonrpc" => "2.0", "method" => "requires", "params" => [], "id" => 2)
    internal = rpc_json("jsonrpc" => "2.0", "method" => "boom", "id" => 3)

    unknown["error"]["code"].must_equal(-32601)
    invalid["error"]["code"].must_equal(-32602)
    internal["error"].must_equal("code" => -32603, "message" => "Internal error")
  end

  it "returns an empty response for a pure notification batch" do
    calls = []
    rpc_app do
      json_rpc_method("record") { |value| calls << value }
    end

    response = rpc_request([
      {"jsonrpc" => "2.0", "method" => "record", "params" => ["a"]},
      {"jsonrpc" => "2.0", "method" => "record", "params" => ["b"]}
    ])

    response[0].must_equal 204
    response[2].to_enum(:each).to_a.must_equal []
    calls.must_equal ["a", "b"]
  end

  it "supports a plugin block as the local notification error hook" do
    errors = []
    app(:bare) do
      plugin(:json_rpc) { |error| errors << error }
      json_rpc_method("broken") { raise "notification failed" }
      route do |r|
        r.post { r.json_rpc }
      end
    end

    response = req("REQUEST_METHOD" => "POST", "rack.input" => rack_input(JSON.generate(
      "jsonrpc" => "2.0", "method" => "broken"
    )))

    response[0].must_equal 204
    errors.map(&:message).must_equal ["notification failed"]
  end

  it "continues after a failure and preserves successful ids and error order" do
    calls = []
    errors = []
    rpc_app do
      plugin :json_rpc, notification_error_handler: proc { |error| errors << error }
      json_rpc_method("ok") do |value|
        calls << [:ok, value]
        value
      end
      json_rpc_method("notice") do
        calls << :notice
      end
      json_rpc_method("requires") { |needed:| needed }
      json_rpc_method("broken") do
        calls << :broken
        raise RuntimeError, "handler failure"
      end
      json_rpc_method("broken_notice") do
        calls << :broken_notice
        raise RuntimeError, "notification failure"
      end
    end

    result = rpc_json([
      {"jsonrpc" => "2.0", "method" => "ok", "params" => {"value" => 1}, "id" => 10},
      {"jsonrpc" => "2.0", "method" => "notice"},
      42,
      {"jsonrpc" => "2.0", "method" => "requires", "params" => {}, "id" => "11"},
      {"jsonrpc" => "2.0", "method" => "broken", "id" => nil},
      {"jsonrpc" => "2.0", "method" => "ok", "params" => [2], "id" => 12},
      {"jsonrpc" => "2.0", "method" => "broken_notice"}
    ])

    result.must_equal([
      {"jsonrpc" => "2.0", "result" => 1, "id" => 10},
      {"jsonrpc" => "2.0", "error" => {"code" => -32600, "message" => "Invalid Request"}, "id" => nil},
      {"jsonrpc" => "2.0", "error" => {"code" => -32602, "message" => "Invalid params"}, "id" => "11"},
      {"jsonrpc" => "2.0", "error" => {"code" => -32603, "message" => "Internal error"}, "id" => nil},
      {"jsonrpc" => "2.0", "result" => 2, "id" => 12}
    ])
    calls.must_equal [[:ok, 1], :notice, :broken, [:ok, 2], :broken_notice]
    errors.map(&:class).must_equal [RuntimeError]
    errors.first.message.must_equal "notification failure"
  end

  it "does not expose arbitrary object methods" do
    rpc_app do
      json_rpc_method("registered", proc { "yes" })
    end

    registered = rpc_json("jsonrpc" => "2.0", "method" => "registered", "id" => 1)
    unknown = rpc_json("jsonrpc" => "2.0", "method" => "object_id", "id" => 2)

    registered["result"].must_equal "yes"
    unknown["error"]["code"].must_equal(-32601)
  end

  it "continues a notification batch when the local error hook itself raises" do
    handled = []
    rpc_app do
      plugin :json_rpc, notification_error_handler: proc { |error|
        handled << error.message
        raise "hook failure"
      }
      json_rpc_method("first") { raise "one" }
      json_rpc_method("second") { handled << "two" }
    end

    response = rpc_request([
      {"jsonrpc" => "2.0", "method" => "first"},
      {"jsonrpc" => "2.0", "method" => "second"}
    ])

    response[0].must_equal 204
    handled.must_equal ["one", "two"]
  end

  it "rejects empty batches and invalid parameter containers" do
    rpc_app do
      json_rpc_method("noop") { nil }
    end

    empty = rpc_json([])
    invalid_params = rpc_json(
      "jsonrpc" => "2.0",
      "method" => "noop",
      "params" => "bad",
      "id" => 4
    )

    empty["error"]["code"].must_equal(-32600)
    invalid_params["error"]["code"].must_equal(-32600)
  end
end
