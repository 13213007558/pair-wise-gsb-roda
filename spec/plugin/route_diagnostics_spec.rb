require_relative "../spec_helper"

describe "route_diagnostics plugin" do
  def diag(path, env={})
    env = env.dup
    env['HTTP_X_RODA_ROUTE_DIAGNOSTICS'] = '1'
    status, headers, body = req(path, env)
    [status, JSON.parse(headers['X-Roda-Route-Diagnostics']), body]
  end

  it "does not add a trace header unless the request opts in" do
    app(:route_diagnostics) do |r|
      r.is("foo") { "foo" }
    end

    status, headers, _ = req("/missing")
    status.must_equal 404
    headers['X-Roda-Route-Diagnostics'].must_be_nil
  end

  it "records nested on/is branches, consumed paths, and terminal failure" do
    app(:route_diagnostics) do |r|
      r.on "api" do
        r.is "users", Integer do |id|
          "user #{id}"
        end
      end
    end

    status, trace, _ = diag("/api/users/x")
    status.must_equal 404
    trace["request_method"].must_equal "GET"
    trace["path"].must_equal "/api/users/x"
    trace["matched"].must_equal false

    on_node = trace["branches"].first
    on_node["kind"].must_equal "on"
    on_node["matcher"].must_equal ["api"]
    on_node["at"].must_equal "/api/users/x"
    on_node["outcome"].must_equal "unfinished"
    on_node["reason"].must_include "no terminal handler"
    on_node["consumed_to"].must_equal "/x"

    is_node = on_node["children"].first
    is_node["kind"].must_equal "is"
    is_node["at"].must_equal "/users/x"
    is_node["outcome"].must_equal "no_match"
    is_node["reason"].must_include "Integer"

    attempts = trace["attempts"]
    attempts.map { |a| a["matcher"] }.must_equal ["api", "users", "Integer"]
    attempts.last["matched"].must_equal false
    attempts.last["at"].must_equal "/x"

    candidates = trace["closest_candidates"]
    is_candidate = candidates.find { |c| c["kind"] == "is" }
    is_candidate["reason"].must_include "Integer"
  end

  it "traces the array alternative actually tried (plain arrays stop at first match)" do
    app(:route_diagnostics) do |r|
      r.is ["posts", "posts/all"], Integer do |p, id|
        "#{p} #{id}"
    end
    end

    _, trace, _ = diag("/posts/abc")
    element_attempts = trace["attempts"].select { |a| a["array_of"] }
    element_attempts.map { |a| [a["matcher"], a["matched"], a["at"]] }.must_equal [
      ["posts", true, "/posts/abc"],
    ]
    element_attempts.none? { |a| a["backtracked"] }.must_equal true
    # The first array element matched, so the remaining matcher (Integer)
    # is the one that rejected the request.
    trace["closest_candidates"].first["reason"].must_include "Integer"
  end

  it "marks backtracked array alternatives with the backtracking_array plugin" do
    app(:bare) do
      plugin :backtracking_array
      plugin :route_diagnostics
      route do |r|
        r.is ["a", "a/b"], Integer do |p, id|
          "#{p} #{id}"
        end
      end
    end

    _, trace, _ = diag("/a/b/x")
    elements = trace["attempts"].select { |a| a["array_of"] }
    first = elements.find { |a| a["matcher"] == "a" }
    second = elements.find { |a| a["matcher"] == "a/b" }
    first["matched"].must_equal true
    first["backtracked"].must_equal true
    second["matched"].must_equal true
    second["backtracked"].must_be_nil
  end

  it "records named route entry, fall-through, and pass explicitly" do
    app(:bare) do
      plugin :route_diagnostics
      route("v1") do |r|
        r.is "widgets", :id do |id|
          r.pass if id == "skip"
          "widget #{id}"
        end
      end

      route do |r|
        r.on "v1" do
          r.route "v1"
        end
      end
    end

    _, trace, _ = diag("/v1/widgets/skip")
    route_node = trace["branches"].first["children"].first
    route_node["kind"].must_equal "route"
    route_node["name"].must_equal "v1"
    route_node["outcome"].must_equal "fell_through"
    route_node["reason"].must_include "r.pass"

    is_node = route_node["children"].first
    is_node["outcome"].must_equal "passed"
    is_node["reason"].must_equal "block called r.pass"
    is_node["consumed_to"].must_equal ""
    id_attempt = trace["attempts"].find { |a| a["matcher_type"] == "symbol" }
    id_attempt["captured"].must_equal ["skip"]
  end

  it "distinguishes a method mismatch from a path mismatch" do
    app(:route_diagnostics) do |r|
      r.get "secret" do
        "shh"
      end
    end

    _, trace, _ = diag("/secret", "REQUEST_METHOD" => "POST")
    node = trace["branches"].first
    node["kind"].must_equal "get"
    node["outcome"].must_equal "no_match"
    node["reason"].must_equal "request method POST does not match GET"
    trace["attempts"].must_be_empty
  end

  it "records custom matcher rejection and invokes it the same times on/off" do
    counter = { calls: 0 }
    digits = Object.new
    def digits.inspect; "<digits>"; end

    app(:bare) do
      plugin :custom_matchers
      plugin :route_diagnostics
      c = counter
      custom_matcher(digits.class) do |m|
        c[:calls] += 1
        if remaining_path =~ /\A\/\d+(?=\/|\z)/
          consume(/\A\/(\d+)(?=\/|\z)/)
          true
        end
      end
      route do |r|
        r.is "items", digits do
          "item"
        end
      end
    end

    plain_status, _, plain_body = req("/items/abc")
    plain_calls = counter[:calls]
    plain_status.must_equal 404
    plain_calls.must_equal 1

    diag_status, trace, diag_body = diag("/items/abc")
    diag_status.must_equal plain_status
    diag_body.to_a.must_equal plain_body.to_a
    counter[:calls].must_equal 2

    custom_attempt = trace["attempts"].find { |a| a["matcher_type"] == "custom" }
    custom_attempt["matched"].must_equal false
    custom_attempt["at"].must_equal "/abc"
    trace["closest_candidates"].first["reason"].must_include "custom matcher"
  end

  it "keeps status, body, and matcher call counts identical with diagnostics on" do
    counter = { calls: 0 }

    app(:bare) do
      plugin :backtracking_array
      plugin :custom_matchers
      plugin :route_diagnostics
      c = counter
      digits = Object.new
      custom_matcher(digits.class) do |_m|
        c[:calls] += 1
        if remaining_path =~ /\A\/\d+(?=\/|\z)/
          consume(/\A\/(\d+)(?=\/|\z)/)
          true
        end
      end
      route do |r|
        r.is ["n", "m"], digits do |_, id|
          "n #{id}"
        end
      end
    end

    path = "/n/abc"
    plain_status, _, plain_body = req(path)
    plain = counter.dup
    diag_status, _, diag_body = diag(path)
    diag_status.must_equal plain_status
    diag_body.to_a.must_equal plain_body.to_a
    counter[:calls].must_equal plain[:calls] * 2
    plain[:calls].must_equal 1
  end

  it "does not write diagnostic captures back into request captures or params" do
    app(:route_diagnostics) do |r|
      r.is "u", Integer do |id|
        "u #{id}"
      end
    end

    _, trace, _ = diag("/u/notanint")
    attempt = trace["attempts"].find { |a| a["matcher"] == "Integer" }
    attempt["captured"].must_equal []
  end

  it "records individual hash matcher components (e.g. rejected params)" do
    app(:bare) do
      plugin :param_matchers
      plugin :route_diagnostics
      route do |r|
        r.is "search", param: "q" do |q|
          "search #{q}"
        end
      end
    end

    _, trace, _ = diag("/search")
    hash_attempt = trace["attempts"].find { |a| a["matcher_type"] == "hash" }
    hash_attempt["matched"].must_equal false
    component = trace["attempts"].find { |a| a["matcher_type"] == "hash_component:param" }
    component["matched"].must_equal false
    component["at"].must_equal ""
    trace["closest_candidates"].first["reason"].must_include "hash"
  end

  it "records an entered on branch that never reaches a terminal handler" do
    app(:route_diagnostics) do |r|
      r.on "api" do
        r.is "other" do
          "other"
        end
      end
    end

    _, trace, _ = diag("/api/missing")
    node = trace["branches"].first
    node["kind"].must_equal "on"
    node["entered"].must_equal true
    node["outcome"].must_equal "unfinished"
    node["consumed_to"].must_equal "/missing"
  end

  it "ranks the branch that consumed the most path as the closest candidate" do
    app(:route_diagnostics) do |r|
      r.on "a" do
        r.is "b", "c" do
          "abc"
        end
      end
      r.on "x" do
        r.is "y" do
          "xy"
        end
      end
    end

    _, trace, _ = diag("/a/b/z")
    trace["closest_candidates"].first["matcher"].must_equal ["b", "c"]
  end

  it "supports custom trigger, header name, and :always attachment" do
    app(:bare) do
      plugin :route_diagnostics,
        trigger: proc { |env| env["HTTP_X_DEBUG"] == "yes" },
        header: "X-Route-Debug",
        attach: :always
      route do |r|
        r.is("foo") { "foo" }
      end
    end

    status, headers, _ = req("/foo", "HTTP_X_DEBUG" => "yes")
    status.must_equal 200
    trace = JSON.parse(headers["X-Route-Debug"])
    trace["matched"].must_equal true
    trace["status"].must_equal 200

    _, without, _ = req("/foo")
    without["X-Route-Debug"].must_be_nil
  end
end
