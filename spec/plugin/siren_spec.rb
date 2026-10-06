require_relative "../spec_helper"
require "json"

describe "siren plugin" do
  def siren_json_app
    app(:bare) do
      plugin :siren

      siren_action "add-order-item" do
        method "POST"
        href { "/orders/#{captures[0]}/items" }
        type "application/vnd.siren+json"
        field "sku", type: "text"
        field "quantity", type: "integer"
        field "unit_price", type: "number"
        field "status", type: "text",
          options: [{value: "new", title: "New"},
                    {value: "backordered", title: "Backordered"}]
        field "tags", type: "text", multiple: true
        field "gift_wrap", type: "checkbox", value: "wrapped"
      end

      route do |r|
        r.get "orders", Integer do |id|
          r.siren_entity do
            klass "order"
            properties id: id, currency: "USD", total: 42.5
            link rel: "self", href: "/orders/#{id}"
            link rel: ["order", "collection"], href: "/orders"
            entity rel: ["item"], href: "/orders/#{id}/items/3", klass: "order-item"
            entity rel: ["item"] do
              klass "order-item"
              properties sku: "ABC-123", quantity: 2
              link rel: "self", href: "/orders/#{id}/items/1"
              action "add-order-item"
            end
            action "add-order-item"
          end
        end

        r.post "orders", Integer, "items" do
          r.siren_submission("add-order-item").inspect
        end
      end
    end
  end

  before do
    siren_json_app
  end

  def siren_get(path="/orders/1")
    req(path, "HTTP_ACCEPT" => "application/vnd.siren+json")
  end

  it "serves entities with the siren content type" do
    status, headers, _ = siren_get
    status.must_equal 200
    headers[RodaResponseHeaders::CONTENT_TYPE].must_equal "application/vnd.siren+json"
  end

  it "renders classes, properties, links, sub entities, and actions" do
    _, _, body = siren_get
    entity = JSON.parse(body_to_s(body))

    entity["class"].must_equal ["order"]
    entity["properties"].must_equal("id" => 1, "currency" => "USD", "total" => 42.5)

    entity["links"].must_equal [
      {"rel" => ["self"], "href" => "/orders/1"},
      {"rel" => ["order", "collection"], "href" => "/orders"},
    ]

    linked, represented = entity["entities"]
    linked.must_equal("rel" => ["item"], "href" => "/orders/1/items/3", "class" => ["order-item"])
    represented["class"].must_equal ["order-item"]
    represented["properties"].must_equal("sku" => "ABC-123", "quantity" => 2)
    represented["links"].must_equal [{"rel" => ["self"], "href" => "/orders/1/items/1"}]

    represented["actions"].length.must_equal 1
    entity["actions"].length.must_equal 1
  end

  it "keeps document links, embedded links, and actions in separate sections" do
    _, _, body = siren_get
    entity = JSON.parse(body_to_s(body))

    action_href = "/orders/1/items"
    entity["links"].each{|link| link["href"].wont_equal action_href}
    linked = entity["entities"].first
    linked.keys.sort.must_equal ["class", "href", "rel"]
    represented = entity["entities"].last
    represented["links"].each{|link| link["href"].wont_equal action_href}

    action = entity["actions"].first
    action["name"].must_equal "add-order-item"
    action["href"].must_equal action_href
    action["method"].must_equal "POST"
    action["type"].must_equal "application/vnd.siren+json"
  end

  it "renders typed fields with options and multiple" do
    _, _, body = siren_get
    entity = JSON.parse(body_to_s(body))
    fields = entity["actions"].first["fields"]
    by_name = fields.each_with_object({}){|field, h| h[field["name"]] = field}

    by_name["sku"].must_equal("name" => "sku", "type" => "text")
    by_name["quantity"].must_equal("name" => "quantity", "type" => "integer")
    by_name["unit_price"].must_equal("name" => "unit_price", "type" => "number")
    by_name["tags"].must_equal("name" => "tags", "type" => "text", "multiple" => true)
    by_name["gift_wrap"].must_equal(
      "name" => "gift_wrap", "type" => "checkbox", "value" => "wrapped")
    by_name["status"]["options"]
      .must_equal [
        {"value" => "new", "title" => "New"},
        {"value" => "backordered", "title" => "Backordered"},
      ]
  end

  it "decodes a submission taken from a nested entity action into Ruby values" do
    _, _, body = siren_get
    entity = JSON.parse(body_to_s(body))
    nested_action = entity["entities"].last["actions"].first
    nested_action["href"].must_equal "/orders/1/items"

    submission = {
      "sku" => "ABC-123",
      "quantity" => 7,
      "unit_price" => 3.5,
      "status" => "new",
      "tags" => %w[sale fragile],
    }.to_json

    status, _, response_body = req(nested_action["href"],
      "REQUEST_METHOD" => nested_action["method"],
      "CONTENT_TYPE" => nested_action["type"],
      "rack.input" => rack_input(submission))

    status.must_equal 200
    decoded = eval(response_body_string(response_body))
    decoded.must_equal(
      "sku" => "ABC-123",
      "quantity" => 7,
      "unit_price" => 3.5,
      "status" => "new",
      "tags" => ["sale", "fragile"],
      "gift_wrap" => false,
    )
    decoded["quantity"].must_be_kind_of Integer
    decoded["unit_price"].must_be_kind_of Float
  end

  it "distinguishes absent checkboxes from explicit null values" do
    _, _, body = siren_get
    entity = JSON.parse(body_to_s(body))
    action = entity["actions"].first

    without_checkbox = {"sku" => "X", "gift_wrap" => nil}.to_json
    _, _, response_body = req(action["href"],
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input(without_checkbox))
    decoded = eval(response_body_string(response_body))
    decoded["gift_wrap"].must_be_nil

    absent_checkbox = {"sku" => "X"}.to_json
    _, _, response_body = req(action["href"],
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input(absent_checkbox))
    decoded = eval(response_body_string(response_body))
    decoded["gift_wrap"].must_equal false

    checked = {"gift_wrap" => true}.to_json
    _, _, response_body = req(action["href"],
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input(checked))
    decoded = eval(response_body_string(response_body))
    decoded["gift_wrap"].must_equal "wrapped"
  end

  it "distinguishes absent, empty, explicit null, and scalar multiple values" do
    post = lambda do |payload|
      _, _, response_body = req("/orders/1/items",
        "REQUEST_METHOD" => "POST",
        "CONTENT_TYPE" => "application/vnd.siren+json",
        "rack.input" => rack_input(payload.to_json))
      eval(response_body_string(response_body))
    end

    post.call({})["tags"].must_equal []
    post.call({"tags" => nil})["tags"].must_be_nil
    post.call({"tags" => []})["tags"].must_equal []
    post.call({"tags" => "single"})["tags"].must_equal ["single"]
  end

  it "rejects values that do not match the typed fields with a 400" do
    response = req("/orders/1/items",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input({"quantity" => "many"}.to_json))
    response.first.must_equal 400

    response = req("/orders/1/items",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input({"status" => "unknown"}.to_json))
    response.first.must_equal 400

    response = req("/orders/1/items",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input("not json"))
    response.first.must_equal 400
  end

  it "rejects JSON bodies that are not objects with a 400" do
    response = req("/orders/1/items",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input("[1, 2]"))
    response.first.must_equal 400
  end

  it "supports ad hoc action definitions for decoding" do
    @app.route do |r|
      r.post "adhoc" do
        values = r.siren_submission do
          method "POST"
          href "/adhoc"
          field "count", type: "integer"
          field "enabled", type: "checkbox"
        end
        values.inspect
      end
    end

    _, _, response_body = req("/adhoc",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input({"count" => "3", "enabled" => true}.to_json))
    decoded = eval(response_body_string(response_body))
    decoded.must_equal("count" => 3, "enabled" => true)
  end

  it "can be configured multiple times and keeps decoding submissions" do
    app.plugin :siren
    _, _, response_body = req("/orders/1/items",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input({"quantity" => 9}.to_json))
    decoded = eval(response_body_string(response_body))
    decoded["quantity"].must_equal 9
  end

  it "decodes url encoded form submissions using the same field definitions" do
    status, _, response_body = req("/orders/1/items",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/x-www-form-urlencoded",
      "rack.input" => rack_input("sku=X&quantity=4&unit_price=2.5&tags[]=a&tags[]=b&gift_wrap=on"))
    status.must_equal 200
    decoded = eval(response_body_string(response_body))
    decoded.must_equal(
      "sku" => "X",
      "quantity" => 4,
      "unit_price" => 2.5,
      "tags" => %w[a b],
      "gift_wrap" => "wrapped",
    )
  end

  it "supports inline action customization with request specific hrefs" do
    @app.route do |r|
      r.get "custom" do
        r.siren_entity do
          klass "root"
          action "add-order-item" do
            href "/custom/items"
          end
        end
      end
    end

    _, _, body = req("/custom")
    entity = JSON.parse(body_to_s(body))
    entity["actions"].first["href"].must_equal "/custom/items"
  end

  it "uses query params for GET actions and omits empty sections" do
    @app.route do |r|
      r.get "empty" do
        r.siren_entity do
          action "add-order-item" do
            method "GET"
            href "/orders/1/search"
          end
        end
      end

      r.get "orders", Integer, "search" do
        r.siren_submission("add-order-item").inspect
      end
    end

    _, _, body = req("/empty")
    entity = JSON.parse(body_to_s(body))
    entity.keys.must_equal ["actions"]

    _, _, search_body = req("/orders/1/search", "QUERY_STRING" => "sku=ABC&quantity=2")
    decoded = eval(response_body_string(search_body))
    decoded.must_equal("sku" => "ABC", "quantity" => 2, "tags" => [], "gift_wrap" => false)
  end

  it "supports a custom error handler and parser" do
    app(:bare) do
      plugin :siren, parser: proc{|s| JSON.parse(s)},
                    error_handler: proc{|r| r.halt [422, {}, ["bad submission"]]}
      siren_action "strict" do
        href "/strict"
        field "quantity", type: "integer"
      end
      route do |r|
        r.post("strict") { r.siren_submission("strict").inspect }
      end
    end

    status, _, body = req("/strict",
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/vnd.siren+json",
      "rack.input" => rack_input("{bad"))
    status.must_equal 422
    response_body_string(body).must_equal "bad submission"
  end

  it "works when the application is frozen" do
    app.freeze
    status, headers, body = req("/orders/1")
    status.must_equal 200
    headers[RodaResponseHeaders::CONTENT_TYPE].must_equal "application/vnd.siren+json"
    JSON.parse(body_to_s(body))["class"].must_equal ["order"]
  end

  it "raises when referencing an unregistered action while rendering" do
    @app.route do |r|
      r.get "bad" do
        r.siren_entity do
          action "missing"
        end
      end
    end

    proc{req("/bad")}.must_raise Roda::RodaPlugins::Siren::UnknownAction
  end

  private

  def body_to_s(body)
    response_body_string(body)
  end

  def response_body_string(body)
    body.each.to_a.join
  end
end
