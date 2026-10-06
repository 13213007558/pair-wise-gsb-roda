require_relative "../spec_helper"
require 'date'
require 'json'

Roda::RodaPlugins.load_plugin(:siren)

describe "siren plugin" do
  def json_body(path='/', env={})
    JSON.parse(body(path, env))
  end

  def form_env(query)
    {'REQUEST_METHOD'=>'POST', 'CONTENT_TYPE'=>'application/x-www-form-urlencoded', 'rack.input'=>rack_input(query)}
  end

  def json_env(hash)
    {'REQUEST_METHOD'=>'POST', 'CONTENT_TYPE'=>'application/json', 'rack.input'=>rack_input(JSON.dump(hash))}
  end

  before do
    app(:bare) do
      plugin :siren
      plugin :json

      def update_order_action(id)
        siren_action(:name=>'update-order', :method=>'POST',
                     :href=>"/orders/#{id}/update", :type=>'application/json') do |action|
          action.field(:name=>'status', :type=>'text')
          action.field(:name=>'quantity', :type=>'number')
          action.field(:name=>'ship_date', :type=>'date', :nullable=>true)
          action.field(:name=>'tags', :type=>'select', :multiple=>true)
          action.field(:name=>'gift_wrap', :type=>'checkbox')
          action.field(:name=>'note', :type=>'text', :nullable=>true)
        end
      end

      route do |r|
        r.on 'orders', Integer do |id|
          r.get true do
            siren_entity(:class=>['order'], :properties=>{'id'=>id, 'status'=>'open'}, :title=>"Order #{id}") do |order|
              order.link(:rel=>['self'], :href=>"/orders/#{id}")
              order.link(:rel=>['documentation'], :href=>'/docs/orders', :type=>'text/html')

              order.entity(:rel=>['customer'], :class=>['customer'], :properties=>{'name'=>'Alice'}) do |customer|
                customer.link(:rel=>['self'], :href=>'/customers/1')
              end
              order.entity(:rel=>['item'], :class=>['item'], :href=>'/items/9')

              order.action(update_order_action(id))
            end
          end

          r.post 'update' do
            begin
              siren_decode(update_order_action(id))
            rescue Roda::RodaPlugins::Siren::DecodeError => e
              response.status = 400
              {'error'=>e.reason, 'field'=>e.field_name}
            end
          end
        end
      end
    end
  end

  it "should use the siren content type for entity responses" do
    header(RodaResponseHeaders::CONTENT_TYPE, '/orders/1').must_equal 'application/vnd.siren+json'
  end

  it "should serialize entity class, properties, and title" do
    order = json_body('/orders/1')
    order['class'].must_equal ['order']
    order['properties'].must_equal({'id'=>1, 'status'=>'open'})
    order['title'].must_equal 'Order 1'
  end

  it "should keep documentation links separate from action links" do
    order = json_body('/orders/1')

    order['links'].must_equal [
      {'rel'=>['self'], 'href'=>'/orders/1'},
      {'rel'=>['documentation'], 'href'=>'/docs/orders', 'type'=>'text/html'}
    ]

    actions = order['actions']
    actions.length.must_equal 1
    actions[0]['name'].must_equal 'update-order'
    actions[0]['method'].must_equal 'POST'
    actions[0]['href'].must_equal '/orders/1/update'
    actions.map{|a| a['href']}.wont_include '/docs/orders'

    fields = actions[0]['fields'].map{|f| [f['name'], f['type']]}
    fields.must_equal [
      ['status', 'text'],
      ['quantity', 'number'],
      ['ship_date', 'date'],
      ['tags', 'select'],
      ['gift_wrap', 'checkbox'],
      ['note', 'text']
    ]
    actions[0]['fields'][3]['multiple'].must_equal true
  end

  it "should serialize embedded sub-entities" do
    entities = json_body('/orders/1')['entities']
    entities.length.must_equal 2

    customer = entities[0]
    customer['rel'].must_equal ['customer']
    customer['class'].must_equal ['customer']
    customer['properties'].must_equal({'name'=>'Alice'})
    customer['links'].must_equal [{'rel'=>['self'], 'href'=>'/customers/1'}]

    item = entities[1]
    item['rel'].must_equal ['item']
    item['class'].must_equal ['item']
    item['href'].must_equal '/items/9'
  end

  it "should require sub-entities to have a rel" do
    entity = Roda::RodaPlugins::Siren::Entity.new
    lambda{entity.entity(:class=>['customer'])}.must_raise(ArgumentError)
  end

  it "should decode form submissions, distinguishing absent checkbox and multi-select" do
    values = json_body('/orders/1/update', form_env('status=shipped&quantity=2'))
    values.must_equal({'status'=>'shipped', 'quantity'=>2, 'tags'=>[], 'gift_wrap'=>false})
  end

  it "should decode submitted checkbox and multi-select values" do
    values = json_body('/orders/1/update', form_env('status=shipped&quantity=2&gift_wrap=on&tags[]=a&tags[]=b&note=fragile&ship_date=2026-10-08'))
    values.must_equal({
      'status'=>'shipped',
      'quantity'=>2,
      'ship_date'=>'2026-10-08',
      'tags'=>['a', 'b'],
      'gift_wrap'=>true,
      'note'=>'fragile'
    })
  end

  it "should decode JSON submissions with explicit null values" do
    values = json_body('/orders/1/update', json_env(
      'status'=>'shipped', 'quantity'=>3, 'note'=>nil, 'ship_date'=>nil, 'gift_wrap'=>true, 'tags'=>['a']
    ))
    values.must_equal({
      'status'=>'shipped',
      'quantity'=>3,
      'ship_date'=>nil,
      'tags'=>['a'],
      'gift_wrap'=>true,
      'note'=>nil
    })
  end

  it "should return an error for null values submitted to non-nullable fields" do
    env = json_env('status'=>nil)
    status('/orders/1/update', env).must_equal 400
    json_body('/orders/1/update', json_env('status'=>nil))['field'].must_equal 'status'
  end

  it "should return an error for values that do not match the field type" do
    status('/orders/1/update', json_env('quantity'=>'abc')).must_equal 400
    json_body('/orders/1/update', json_env('quantity'=>'abc'))['field'].must_equal 'quantity'

    status('/orders/1/update', json_env('tags'=>'a')).must_equal 400
    json_body('/orders/1/update', json_env('tags'=>'a'))['field'].must_equal 'tags'
  end

  it "should support taking an action from a nested order response and submitting legal values" do
    order = json_body('/orders/2')
    order['entities'].map{|e| e['rel']}.must_equal [['customer'], ['item']]

    action = order['actions'].find{|a| a['name'] == 'update-order'}
    action.wont_be_nil

    payload = {}
    action['fields'].each do |field|
      case field['name']
      when 'status' then payload['status'] = 'shipped'
      when 'quantity' then payload['quantity'] = 5
      when 'ship_date' then payload['ship_date'] = '2026-10-08'
      when 'tags' then payload['tags'] = ['gift', 'fragile']
      when 'gift_wrap' then payload['gift_wrap'] = true
      when 'note' then payload['note'] = nil
      end
    end

    env = {'REQUEST_METHOD'=>action['method'], 'CONTENT_TYPE'=>action['type'], 'rack.input'=>rack_input(JSON.dump(payload))}
    values = json_body(action['href'], env)
    values.must_equal({
      'status'=>'shipped',
      'quantity'=>5,
      'ship_date'=>'2026-10-08',
      'tags'=>['gift', 'fragile'],
      'gift_wrap'=>true,
      'note'=>nil
    })
  end

  it "should support a custom content type" do
    app(:bare) do
      plugin :siren, :content_type=>'application/x-siren+json'
      route{|r| r.is('e'){ siren_entity(:class=>['x']) } }
    end
    header(RodaResponseHeaders::CONTENT_TYPE, '/e').must_equal 'application/x-siren+json'
    json_body('/e').must_equal({'class'=>['x']})
  end

  it "should work when subclassing" do
    @app = Class.new(app)
    app.route{|r| siren_entity(:class=>['x']) }
    header(RodaResponseHeaders::CONTENT_TYPE).must_equal 'application/vnd.siren+json'
    json_body.must_equal({'class'=>['x']})
  end
end

describe "siren action decoding" do
  def decode_action
    action = Roda::RodaPlugins::Siren::Action.new(:name=>'a', :href=>'/a')
    yield action
    action
  end

  it "should decode values to ruby objects based on field types" do
    action = decode_action do |a|
      a.field(:name=>'int', :type=>'number')
      a.field(:name=>'float', :type=>'number')
      a.field(:name=>'range', :type=>'range')
      a.field(:name=>'date', :type=>'date')
      a.field(:name=>'time', :type=>'datetime-local')
      a.field(:name=>'text', :type=>'text')
    end

    values = action.decode('int'=>'4', 'float'=>'1.5', 'range'=>'-2', 'date'=>'2026-10-08',
                           'time'=>'2026-10-08T10:30:00Z', 'text'=>'foo')
    values[:int].must_equal 4
    values[:float].must_equal 1.5
    values[:range].must_equal(-2)
    values[:date].must_equal Date.new(2026, 10, 8)
    values[:time].must_equal Time.utc(2026, 10, 8, 10, 30, 0)
    values[:text].must_equal 'foo'
  end

  it "should accept JSON scalar values for typed fields" do
    action = decode_action do |a|
      a.field(:name=>'int', :type=>'number')
      a.field(:name=>'float', :type=>'number')
      a.field(:name=>'check', :type=>'checkbox')
    end

    values = action.decode('int'=>4, 'float'=>1.5, 'check'=>true)
    values.must_equal({:int=>4, :float=>1.5, :check=>true})
  end

  it "should decode checkbox values" do
    action = decode_action{|a| a.field(:name=>'check', :type=>'checkbox')}
    action.decode('check'=>'on')[:check].must_equal true
    action.decode('check'=>'1')[:check].must_equal true
    action.decode('check'=>'0')[:check].must_equal false
    action.decode('check'=>'')[:check].must_equal false
    action.decode('check'=>false)[:check].must_equal false
    action.decode({})[:check].must_equal false
    lambda{action.decode('check'=>'maybe')}.must_raise(Roda::RodaPlugins::Siren::DecodeError)
  end

  it "should decode multiple values to arrays, and absent multiple fields to empty arrays" do
    action = decode_action do |a|
      a.field(:name=>'tags', :type=>'select', :multiple=>true)
      a.field(:name=>'nums', :type=>'number', :multiple=>true)
    end

    action.decode({}).must_equal({:tags=>[], :nums=>[]})
    action.decode('tags'=>['a', 'b'], 'nums'=>['1', '2']).must_equal({:tags=>['a', 'b'], :nums=>[1, 2]})
    lambda{action.decode('tags'=>'a')}.must_raise(Roda::RodaPlugins::Siren::DecodeError)
  end

  it "should distinguish explicit null values from absent fields" do
    action = decode_action do |a|
      a.field(:name=>'nullable', :type=>'text', :nullable=>true)
      a.field(:name=>'required', :type=>'text')
    end

    action.decode('nullable'=>nil, 'required'=>'x').must_equal({:nullable=>nil, :required=>'x'})
    action.decode('required'=>'x').must_equal({:required=>'x'})
    lambda{action.decode('required'=>nil)}.must_raise(Roda::RodaPlugins::Siren::DecodeError)
  end

  it "should accept symbol keys in params" do
    action = decode_action{|a| a.field(:name=>'status', :type=>'text')}
    action.decode(:status=>'x').must_equal({:status=>'x'})
  end

  it "should raise DecodeError with field_name and reason for invalid values" do
    action = decode_action{|a| a.field(:name=>'quantity', :type=>'number')}
    error = lambda{action.decode('quantity'=>'abc')}.must_raise(Roda::RodaPlugins::Siren::DecodeError)
    error.field_name.must_equal 'quantity'
    error.reason.must_equal 'invalid number: "abc"'
  end

  it "should raise for non-hash params" do
    action = decode_action{|a| a.field(:name=>'status')}
    lambda{action.decode(['status'])}.must_raise(ArgumentError)
  end
end
