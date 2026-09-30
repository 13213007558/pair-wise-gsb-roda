require_relative "../spec_helper"

# Controllable monotonic clock, so heartbeat scheduling can be
# tested without real sleeping.
class SSEFakeClock
  def initialize
    @now = 0.0
  end

  def call
    @now
  end

  def advance(seconds)
    @now += seconds
  end
end

describe "sse plugin" do
  def sse_app(opts={})
    app(:bare) do
      plugin :sse, opts

      route do |r|
        r.on "events", String do |channel|
          r.get do
            sse(channel)
          end
        end
      end
    end
  end

  def cursor_for(channel, id)
    "#{app.sse_opts[:epoch]}:#{channel}:#{id}"
  end

  def drain(body, count)
    chunks = []
    body.each do |chunk|
      chunks << chunk
      body.close if chunks.size >= count
    end
    chunks
  end

  def wait_for
    100.times do
      return if yield
      sleep 0.01
    end
    flunk "timed out waiting for condition"
  end

  it "streams published events with monotonic id cursors" do
    unless_lint do
    sse_app
    s, h, b = req('/events/a')
    s.must_equal 200
    h[RodaResponseHeaders::CONTENT_TYPE].must_equal 'text/event-stream'
    h['Cache-Control'].must_equal 'no-cache'

    app.sse_publish('a', 'one').must_equal 1
    app.sse_publish('a', 'two', 'greeting').must_equal 2

    chunks = drain(b, 2)
    chunks[0].must_equal "id: #{cursor_for('a', 1)}\ndata: one\n\n"
    chunks[1].must_equal "event: greeting\nid: #{cursor_for('a', 2)}\ndata: two\n\n"
    end
  end

  it "formats multi-line event data as multiple data lines" do
    sse_app
    channel = app.sse_channel('a')
    channel.format([1, "foo\nbar\n", nil]).must_equal "id: #{cursor_for('a', 1)}\ndata: foo\ndata: bar\n\n"
  end

  it "replays missed events before live events when Last-Event-ID is valid" do
    unless_lint do
    sse_app
    app.sse_publish('a', 'one')
    app.sse_publish('a', 'two')
    app.sse_publish('a', 'three')

    s, _h, b = req('/events/a', 'HTTP_LAST_EVENT_ID'=>cursor_for('a', 1))
    s.must_equal 200
    app.sse_publish('a', 'four')

    drain(b, 3).must_equal [
      "id: #{cursor_for('a', 2)}\ndata: two\n\n",
      "id: #{cursor_for('a', 3)}\ndata: three\n\n",
      "id: #{cursor_for('a', 4)}\ndata: four\n\n",
    ]
    end
  end

  it "does not replay events when no Last-Event-ID is given" do
    unless_lint do
    sse_app
    app.sse_publish('a', 'one')
    s, _h, b = req('/events/a')
    s.must_equal 200
    app.sse_publish('a', 'two')
    drain(b, 1).must_equal ["id: #{cursor_for('a', 2)}\ndata: two\n\n"]
    end
  end

  it "returns a reset response when the cursor has been evicted from the buffer" do
    unless_lint do
    sse_app(:buffer_size=>2)
    4.times{|i| app.sse_publish('a', "event#{i + 1}")}

    status('/events/a', 'HTTP_LAST_EVENT_ID'=>cursor_for('a', 1)).must_equal 409
    body('/events/a', 'HTTP_LAST_EVENT_ID'=>cursor_for('a', 1)).must_equal 'reset'

    # A cursor just inside the buffer window is still valid
    s, _h, b = req('/events/a', 'HTTP_LAST_EVENT_ID'=>cursor_for('a', 2))
    s.must_equal 200
    drain(b, 2).must_equal [
      "id: #{cursor_for('a', 3)}\ndata: event3\n\n",
      "id: #{cursor_for('a', 4)}\ndata: event4\n\n",
    ]
    end
  end

  it "returns a reset response for cursors from other channels, other epochs, or the future" do
    sse_app
    app.sse_publish('a', 'one')

    status('/events/a', 'HTTP_LAST_EVENT_ID'=>cursor_for('b', 1)).must_equal 409
    status('/events/a', 'HTTP_LAST_EVENT_ID'=>"otherepoch:a:1").must_equal 409
    status('/events/a', 'HTTP_LAST_EVENT_ID'=>cursor_for('a', 99)).must_equal 409
    status('/events/a', 'HTTP_LAST_EVENT_ID'=>'garbage').must_equal 409
    body('/events/a', 'HTTP_LAST_EVENT_ID'=>'garbage').must_equal 'reset'
  end

  it "delivers events published during the replay/live handoff exactly once" do
    entered = Queue.new
    proceed = Queue.new
    sse_app(:handoff_hook=>proc{|channel| entered << true; proceed.pop})
    app.sse_publish('a', 'one')
    channel = app.sse_channel('a')

    result = nil
    subscriber = Thread.new{result = channel.subscribe(1)}
    entered.pop # the subscription is now inside the handoff, holding the channel lock
    publisher = Thread.new{channel.publish('two')}
    proceed << true
    subscriber.join
    publisher.join

    subscription, missed = result
    missed.must_equal []
    subscription.pop(0).must_equal [2, 'two', nil]
    subscription.pop(0).must_be_nil
  end

  it "disconnects slow subscribers without affecting other subscribers" do
    sse_app(:subscriber_limit=>2)
    channel = app.sse_channel('a')
    slow, = channel.subscribe
    fast, = channel.subscribe

    channel.publish('one')
    fast.pop(0)[1].must_equal 'one'
    channel.publish('two')
    fast.pop(0)[1].must_equal 'two'
    slow.closed?.must_equal false
    channel.publish('three')
    fast.pop(0)[1].must_equal 'three'

    slow.closed?.must_equal true
    fast.closed?.must_equal false
    channel.subscriber_count.must_equal 1

    # The slow subscriber drains what was queued before being disconnected
    slow.pop(0)[1].must_equal 'one'
    slow.pop(0)[1].must_equal 'two'
    slow.pop(0).must_be_nil

    # Other subscribers continue receiving events
    channel.publish('four')
    fast.pop(0)[1].must_equal 'four'
  end

  it "wakes up and cleans up waiting tasks when unsubscribing" do
    sse_app
    channel = app.sse_channel('a')
    subscription, = channel.subscribe

    waiter = Thread.new{subscription.pop}
    Thread.pass until waiter.status == 'sleep'

    channel.unsubscribe(subscription)
    waiter.value.must_be_nil
    subscription.closed?.must_equal true
    channel.subscriber_count.must_equal 0
  end

  it "unsubscribes when the stream is closed" do
    unless_lint do
    sse_app
    _s, _h, b = req('/events/a')
    channel = app.sse_channel('a')
    channel.subscriber_count.must_equal 1
    streamer = Thread.new{b.each{}}
    b.close
    streamer.join(5)
    channel.subscriber_count.must_equal 0
    end
  end

  it "sends heartbeats when idle, using the configured clock" do
    unless_lint do
    clock = SSEFakeClock.new
    sse_app(:heartbeat_interval=>5, :clock=>clock)
    _s, _h, b = req('/events/a')

    # Advance past the heartbeat deadline before the stream starts,
    # so the heartbeat is emitted without any real waiting.
    clock.advance(12)

    chunks = []
    streamer = Thread.new{b.each{|chunk| chunks << chunk}}
    wait_for{chunks.size >= 1}
    chunks.must_equal [": heartbeat\n\n"]

    app.sse_publish('a', 'one')
    wait_for{chunks.size >= 2}
    b.close
    streamer.join(5)
    chunks[1].must_equal "id: #{cursor_for('a', 1)}\ndata: one\n\n"
    end
  end

  it "does not send heartbeats when events keep the stream busy" do
    unless_lint do
    clock = SSEFakeClock.new
    sse_app(:heartbeat_interval=>5, :clock=>clock)
    _s, _h, b = req('/events/a')
    app.sse_publish('a', 'one')
    clock.advance(12)
    drain(b, 1).must_equal ["id: #{cursor_for('a', 1)}\ndata: one\n\n"]
    end
  end
end
