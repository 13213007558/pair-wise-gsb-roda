require_relative "../spec_helper"
require_relative "../../lib/roda/plugins/sse"
require 'timeout'

describe "sse plugin" do
  class HandoffLock
    def initialize(waiting)
      @waiting = waiting
      @lock = Queue.new
      @lock << :open
    end

    def synchronize
      @waiting << :waiting if Thread.current[:sse_publisher]
      @lock.pop
      begin
        yield
      ensure
        @lock << :open
      end
    end
  end

  class ManualClock
    def initialize
      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @now = 0
      @sleeps = Queue.new
    end

    def now
      @mutex.synchronize { @now }
    end

    def wait(condition, mutex, timeout)
      mutex.sleep(0.001)
      @sleeps << true
      condition.wait(mutex, 0.001)
    end

    def advance(seconds, count=1)
      count.times { @sleeps.pop }
      @mutex.synchronize do
        @now += seconds
        @condition.broadcast
      end
    end
  end

  def sse_bus(opts={})
    Roda::RodaPlugins::Sse::Bus.new(opts)
  end

  def event_id(bus, channel, sequence, generation=nil)
    generation ||= bus.instance_variable_get(:@generation)
    ["1:#{generation}:#{sequence}:#{channel}"].pack('m0')
  end

  def collect_stream(result, clock, heartbeat=nil)
    chunks = []
    stream = Roda::RodaPlugins::Sse::Stream.new(
      result,
      :heartbeat => heartbeat,
      :clock => clock
    )
    thread = Thread.new do
      stream.each { |chunk| chunks << chunk }
    end
    [stream, thread, chunks]
  end

  def wait_for_waiting(subscription)
    Timeout.timeout(1) do
      sleep 0.001 until subscription.waiting?
    end
  end

  it "publishes and encodes SSE events" do
    bus = sse_bus
    event = bus.publish('notices', 'hello', :event => 'notice', :retry => 5000)

    event.to_s.must_equal \
      "event: notice\nid: #{event.id}\ndata: hello\nretry: 5000\n\n"
  end

  it "rejects invalid limits and heartbeat intervals" do
    proc { sse_bus(:history_size => 0) }.must_raise Roda::RodaError
    proc { sse_bus(:pending_events_size => 0) }.must_raise Roda::RodaError
    proc { sse_bus(:heartbeat => 0) }.must_raise Roda::RodaError
    bus = sse_bus(:heartbeat => false)
    bus.clock.must_equal Roda::RodaPlugins::Sse::MonotonicClock
  end

  it "replays only events after Last-Event-ID before live events" do
    bus = sse_bus
    first = bus.publish('notices', 'first')
    bus.publish('notices', 'second')
    bus.publish('notices', 'third')

    result = bus.subscribe('notices', first.id)
    stream, thread, chunks = collect_stream(result, Roda::RodaPlugins::Sse::MonotonicClock)
    bus.publish('notices', 'fourth')
    wait_for_waiting(result.subscription)
    stream.close
    thread.join

    chunks.must_equal [
      "id: #{event_id(bus, 'notices', 2)}\ndata: second\n\n",
      "id: #{event_id(bus, 'notices', 3)}\ndata: third\n\n",
      "id: #{event_id(bus, 'notices', 4)}\ndata: fourth\n\n"
    ]
  end

  it "does not duplicate an event published at the replay/live handoff" do
    bus = sse_bus
    first = bus.publish('notices', 'first')
    channel = bus.send(:channel_state, 'notices')
    publisher_waiting = Queue.new
    channel.instance_variable_set(:@mutex, HandoffLock.new(publisher_waiting))
    result = nil
    handoff_event = nil
    publisher = nil

    subscriber = Thread.new do
      result = bus.subscribe('notices', first.id) do
        publisher = Thread.new do
          Thread.current[:sse_publisher] = true
          handoff_event = bus.publish('notices', 'handoff')
        end
        publisher_waiting.pop
      end
    end
    subscriber.join
    publisher.join

    result.events.must_equal []
    stream, output_thread, chunks = collect_stream(result, Roda::RodaPlugins::Sse::MonotonicClock)
    stream.close
    output_thread.join

    chunks.must_equal [
      "id: #{handoff_event.id}\ndata: handoff\n\n"
    ]
  end

  it "resets when the cursor is invalid" do
    bus = sse_bus
    bus.publish('notices', 'first')

    result = bus.subscribe('notices', 'not-an-sse-id')

    result.status.must_equal :reset
    result.reason.must_equal :invalid_cursor
    result.reset_event.event.must_equal 'sse-reset'
    result.reset_event.data.must_equal 'invalid_cursor'
    chunks = []
    stream = Roda::RodaPlugins::Sse::Stream.new(
      result,
      :heartbeat => nil,
      :clock => Roda::RodaPlugins::Sse::MonotonicClock
    )
    thread = Thread.new do
      stream.each { |chunk| chunks << chunk }
    end
    result.subscription.close
    thread.join

    chunks.must_equal [
      "event: sse-reset\nid: #{result.reset_event.id}\ndata: invalid_cursor\n\n"
    ]
  end

  it "resets when the cursor belongs to another channel" do
    bus = sse_bus
    event = bus.publish('alerts', 'first')

    result = bus.subscribe('notices', event.id)

    result.status.must_equal :reset
    result.reason.must_equal :wrong_channel
    result.subscription.close
  end

  it "resets when the cursor is from a previous process generation" do
    bus = sse_bus(:generation => 'current')
    old_id = event_id(bus, 'notices', 1, 'previous')
    bus.publish('notices', 'first')

    result = bus.subscribe('notices', old_id)

    result.status.must_equal :reset
    result.reason.must_equal :unknown_generation
    result.subscription.close
  end

  it "resets when the cursor has been evicted" do
    bus = sse_bus(:history_size => 2)
    old = bus.publish('notices', 'old')
    3.times { |number| bus.publish('notices', number.to_s) }

    result = bus.subscribe('notices', old.id)

    result.status.must_equal :reset
    result.reason.must_equal :cursor_evicted
    result.subscription.close
  end

  it "closes only the slow subscription and continues delivering to others" do
    bus = sse_bus(:pending_events_size => 3)
    slow = bus.subscribe('notices', nil, :pending_events_size => 2)
    fast = bus.subscribe('notices')

    3.times { |number| bus.publish('notices', number.to_s) }

    slow.subscription.closed?.must_equal true
    slow.subscription.close_reason.must_equal :slow_consumer
    fast.subscription.closed?.must_equal false
    fast.subscription.instance_variable_get(:@queue).first.data.must_equal '0'
    fast.subscription.close
  end

  it "cleans up disconnected waiting tasks" do
    bus = sse_bus
    result = bus.subscribe('notices')
    stream, thread, _ = collect_stream(result, Roda::RodaPlugins::Sse::MonotonicClock)
    wait_for_waiting(result.subscription)

    stream.close
    thread.join

    result.subscription.closed?.must_equal true
    bus.publish('notices', 'after-close')
    channel = bus.send(:channel_state, 'notices')
    channel.instance_variable_get(:@subscriptions).must_equal []
  end

  it "uses a controllable clock to send heartbeats" do
    clock = ManualClock.new
    bus = sse_bus(:clock => clock)
    result = bus.subscribe('notices')
    stream, thread, chunks = collect_stream(result, clock, 10)
    wait_for_waiting(result.subscription)

    clock.advance(10)
    Timeout.timeout(1) { sleep 0.001 until chunks.include?(": heartbeat\n\n") }
    stream.close
    thread.join

    chunks.must_equal [": heartbeat\n\n"]
  end

  it "provides an SSE route using Last-Event-ID" do
    clock = ManualClock.new
    bus = Roda::RodaPlugins::Sse::Bus.new(:clock => clock, :heartbeat => false)
    app(:bare) do
      plugin :sse, :bus => bus
      route do |r|
        r.get 'events', String do |channel|
          sse_stream(channel)
        end
      end
    end

    first = bus.publish('notices', 'first')
    live = bus.publish('notices', 'second')
    status, headers, body = req('/events/notices', 'HTTP_LAST_EVENT_ID' => first.id)

    status.must_equal 200
    headers[RodaResponseHeaders::CONTENT_TYPE].must_equal 'text/event-stream'
    headers[RodaResponseHeaders::CACHE_CONTROL].must_equal 'no-cache'
    accel_header = defined?(Rack::Headers) && Rack::Headers.is_a?(Class) ? 'x-accel-buffering' : 'X-Accel-Buffering'
    headers[accel_header].must_equal 'no'

    chunks = []
    thread = Thread.new do
      body.each { |chunk| chunks << chunk }
    end
    bus.publish('notices', 'third')
    Timeout.timeout(1) { sleep 0.001 until chunks.length == 2 }
    body.close
    thread.join

    chunks.must_equal [
      "id: #{live.id}\ndata: second\n\n",
      "id: #{event_id(bus, 'notices', 3)}\ndata: third\n\n"
    ]
  end
end unless ENV['LINT']
