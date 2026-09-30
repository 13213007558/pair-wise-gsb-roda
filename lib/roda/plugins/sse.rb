# frozen-string-literal: true

require 'securerandom'

#
class Roda
  module RodaPlugins
    # The sse plugin adds support for Server-Sent Events with
    # reconnection replay.  It keeps an in-process, bounded ring
    # buffer of recent events per channel, assigns each event a
    # monotonic id, and when a client reconnects with a
    # +Last-Event-ID+ header, replays the events still present in
    # the buffer before switching to the live stream:
    #
    #   plugin :sse
    #
    #   route do |r|
    #     r.on "events", String do |channel|
    #       r.get do
    #         sse(channel)
    #       end
    #     end
    #   end
    #
    # Events are published from anywhere using the class-level
    # +sse_publish+ method:
    #
    #   App.sse_publish("chat", "hello")                # data only
    #   App.sse_publish("chat", "hello", "greeting")    # with event name
    #
    # No external message broker is used; all state is kept in
    # memory, so events published between the disconnect and the
    # reconnect are only replayed if they are still inside the
    # per-channel buffer window.
    #
    # Each event is sent with an +id:+ line containing a cursor of
    # the form <tt>epoch:channel:id</tt>.  The epoch is generated
    # when the plugin is loaded, so cursors from before a process
    # restart are recognized.  If a reconnecting client presents a
    # cursor that has been evicted from the buffer, belongs to a
    # different channel, comes from a previous process epoch, or is
    # otherwise invalid, the request is rejected with a
    # <tt>409 Conflict</tt> response with a body of "reset", so the
    # client knows it must resynchronize instead of silently missing
    # events.
    #
    # The handoff between replay and the live stream is atomic: an
    # event published while a subscriber is being registered is
    # delivered exactly once, either in the replayed backlog or in
    # the live stream, never both and never neither.
    #
    # Each subscriber has its own bounded queue of pending events.
    # A slow subscriber that falls behind the configured limit is
    # disconnected (its stream ends after the already queued events
    # are drained) without affecting other subscribers, and its
    # waiting tasks are woken up and cleaned up.  When the client
    # disconnects, the subscription is removed via the stream
    # callback.
    #
    # If no event has been sent to a subscriber within the heartbeat
    # interval, an SSE comment line (<tt>": heartbeat"</tt>) is sent
    # to keep the connection alive.  The clock used for heartbeat
    # scheduling can be replaced for testing.
    #
    # Options:
    # :buffer_size :: Maximum number of recent events kept per
    #                 channel for replay (default: 100).
    # :subscriber_limit :: Maximum number of undelivered events
    #                      queued per subscriber before the
    #                      subscriber is disconnected (default: 16).
    # :heartbeat_interval :: Seconds between heartbeats when the
    #                        connection is idle; nil disables
    #                        heartbeats (default: 15).
    # :clock :: Callable returning monotonic time in seconds, used
    #           for heartbeat scheduling (default:
    #           Process.clock_gettime(Process::CLOCK_MONOTONIC)).
    # :epoch :: The process epoch used in event cursors (default:
    #           randomly generated when the plugin is loaded).
    # :handoff_hook :: Test seam.  If given, called with the channel
    #                  while the channel lock is held during
    #                  subscription, after the subscriber has been
    #                  registered and before the replay backlog is
    #                  snapshotted.  This allows tests to synchronize
    #                  a concurrent publish with the handoff.
    #
    # This plugin depends on the streaming plugin.
    module SSE
      # A named channel that events are published to and subscribers
      # consume.  Keeps the bounded ring buffer of recent events and
      # the set of current subscribers.
      class Channel
        # The name of the channel.
        attr_reader :name

        def initialize(name, opts) # :nodoc:
          @name = name
          @epoch = opts[:epoch]
          @buffer_size = opts[:buffer_size]
          @subscriber_limit = opts[:subscriber_limit]
          @clock = opts[:clock]
          @handoff_hook = opts[:handoff_hook]
          @mutex = Mutex.new
          @events = []
          @next_id = 1
          @subscribers = {}
        end

        # Publish an event with the given data and optional event
        # name.  Buffers the event for replay and pushes it to all
        # current subscribers.  Subscribers that have fallen behind
        # their pending limit are disconnected.  Returns the
        # monotonic id assigned to the event.
        def publish(data, event=nil)
          @mutex.synchronize do
            id = @next_id
            @next_id += 1
            record = [id, data, event]
            @events << record
            @events.shift while @events.size > @buffer_size
            @subscribers.each_key do |subscription|
              subscription.push(record)
            end
            @subscribers.delete_if{|subscription,| subscription.closed?}
            id
          end
        end

        # The number of current subscribers.
        def subscriber_count
          @mutex.synchronize{@subscribers.size}
        end

        # Parse a Last-Event-ID cursor for this channel.  Returns
        # the event id as an Integer, or :reset if the cursor is
        # malformed, belongs to a different channel, or was issued
        # by a previous process epoch.
        def parse_cursor(cursor)
          if /\A([^:]+):(.+):(\d+)\z/ =~ cursor.to_s && $1 == @epoch && $2 == @name
            $3.to_i
          else
            :reset
          end
        end

        # Subscribe to the channel.  +last_id+ should be the id of
        # the last event the subscriber received, or nil to only
        # receive new events.  Registration of the subscriber and
        # snapshotting of missed events happen atomically while
        # holding the channel lock, so an event published during the
        # handoff is delivered exactly once.
        #
        # Returns an array containing the Subscription and an array
        # of missed event records (which have already been queued on
        # the subscription, ahead of any live events).  Returns
        # :reset if +last_id+ refers to an event that is no longer
        # in the buffer window or is otherwise invalid.
        def subscribe(last_id=nil)
          @mutex.synchronize do
            if last_id
              latest = @next_id - 1
              oldest = @events.empty? ? @next_id : @events[0][0]
              return :reset if last_id > latest || last_id < oldest - 1
            end

            subscription = Subscription.new(@subscriber_limit, @clock)
            @subscribers[subscription] = true

            # Test seam, see the :handoff_hook plugin option.
            @handoff_hook.call(self) if @handoff_hook

            missed = []
            if last_id
              @events.each{|record| missed << record if record[0] > last_id}
            end
            subscription.backlog(missed)

            [subscription, missed]
          end
        end

        # Remove the subscription from the channel and wake up any
        # tasks waiting for events on it.
        def unsubscribe(subscription)
          @mutex.synchronize{@subscribers.delete(subscription)}
          subscription.close
          nil
        end

        # Format an event record as an SSE payload, including the
        # event cursor in the +id:+ field.
        def format(record)
          id, data, event = record
          buf = String.new
          buf << "event: #{event}\n" if event
          buf << "id: #{@epoch}:#{@name}:#{id}\n"
          data.to_s.each_line{|line| buf << "data: #{line.chomp}\n"}
          buf << "\n"
          buf
        end
      end

      # The receiving side of a channel subscription.  Holds a
      # bounded queue of pending event records.
      class Subscription
        # The time the subscription was created, according to the
        # configured clock.  Used as the starting point for
        # heartbeat scheduling.
        attr_reader :created_at

        def initialize(limit, clock) # :nodoc:
          @limit = limit
          @queue = []
          @mutex = Mutex.new
          @condition = ConditionVariable.new
          @closed = false
          @created_at = clock.call
        end

        # Queue an event record for delivery.  Called by the channel
        # while holding the channel lock.  If the pending limit has
        # been reached, the subscriber is considered slow and is
        # disconnected, so that other subscribers are not affected.
        def push(record)
          @mutex.synchronize do
            next if @closed
            if @queue.size >= @limit
              @closed = true
              @condition.broadcast
            else
              @queue << record
              @condition.signal
            end
          end
          nil
        end

        # Queue already buffered event records being replayed.
        # These are not subject to the pending limit, as they
        # represent the replay backlog and not a slow consumer.
        def backlog(records)
          @mutex.synchronize do
            @queue.concat(records) unless @closed
          end
          nil
        end

        # Remove and return the next pending event record.  If no
        # record is pending, waits up to +timeout+ seconds (or
        # indefinitely if +timeout+ is nil).  Returns nil if no
        # record is available within the timeout, or if the
        # subscription has been closed and drained.
        def pop(timeout=nil)
          @mutex.synchronize do
            if @queue.empty? && !@closed && (timeout.nil? || timeout > 0)
              @condition.wait(@mutex, timeout)
            end
            @queue.shift
          end
        end

        # Close the subscription, waking up any tasks waiting in
        # #pop.  Records already queued can still be drained.
        def close
          @mutex.synchronize do
            @closed = true
            @condition.broadcast
          end
          nil
        end

        # Whether the subscription has been closed, either because
        # the subscriber was too slow or because it was
        # unsubscribed.
        def closed?
          @mutex.synchronize{@closed}
        end
      end

      def self.load_dependencies(app, opts=OPTS)
        app.plugin :streaming
      end

      def self.configure(app, opts=OPTS)
        sse_opts = (app.opts[:sse] ||= {})
        sse_opts[:buffer_size] = (opts[:buffer_size] || sse_opts[:buffer_size] || 100).freeze
        sse_opts[:subscriber_limit] = (opts[:subscriber_limit] || sse_opts[:subscriber_limit] || 16).freeze
        if opts.key?(:heartbeat_interval)
          sse_opts[:heartbeat_interval] = opts[:heartbeat_interval]
        elsif !sse_opts.key?(:heartbeat_interval)
          sse_opts[:heartbeat_interval] = 15
        end
        sse_opts[:clock] = opts[:clock] || sse_opts[:clock] || lambda{Process.clock_gettime(Process::CLOCK_MONOTONIC)}
        sse_opts[:epoch] = (opts[:epoch] || sse_opts[:epoch] || SecureRandom.hex(8)).freeze
        sse_opts[:handoff_hook] = opts[:handoff_hook] || sse_opts[:handoff_hook]
        sse_opts[:channels] ||= {}
        sse_opts[:channels_mutex] ||= Mutex.new
      end

      module ClassMethods
        # The options hash for the sse plugin.
        def sse_opts
          opts[:sse]
        end

        # The SSE channel with the given name, creating it if it
        # does not yet exist.
        def sse_channel(name)
          sse_opts[:channels_mutex].synchronize do
            sse_opts[:channels][name] ||= SSE::Channel.new(name, sse_opts)
          end
        end

        # Publish an event with the given data and optional event
        # name to the channel with the given name, creating the
        # channel if it does not yet exist.  Returns the monotonic
        # id assigned to the event.
        def sse_publish(channel, data, event=nil)
          sse_channel(channel).publish(data, event)
        end
      end

      module InstanceMethods
        # Serve a Server-Sent Events stream for the channel with the
        # given name.  If the request includes a valid Last-Event-ID
        # header, events missed since the given cursor that are still
        # in the channel's buffer are sent before live events.  If
        # the cursor is invalid (evicted, for a different channel,
        # from a previous process epoch, or malformed), halts with a
        # 409 response with a body of "reset".
        def sse(channel_name)
          channel = self.class.sse_channel(channel_name)
          last_event_id = env['HTTP_LAST_EVENT_ID']

          subscription = nil
          if last_event_id && !last_event_id.empty?
            last_id = channel.parse_cursor(last_event_id)
            if last_id != :reset
              result = channel.subscribe(last_id)
              subscription = result[0] unless result == :reset
            end
            unless subscription
              response = @_response
              response.status = 409
              response[RodaResponseHeaders::CONTENT_TYPE] = 'text/plain'
              throw :halt, response.finish_with_body(['reset'])
            end
          else
            subscription = channel.subscribe[0]
          end

          response = @_response
          response[RodaResponseHeaders::CONTENT_TYPE] = 'text/event-stream'
          response['Cache-Control'] = 'no-cache'
          stream(:callback=>proc{channel.unsubscribe(subscription)}) do |out|
            _sse_pump(channel, subscription, out)
          end
        end

        private

        # Send queued events to the stream, waiting for new events
        # and emitting heartbeats when idle, until the subscription
        # is closed and drained.
        def _sse_pump(channel, subscription, out)
          opts = self.class.sse_opts
          clock = opts[:clock]
          interval = opts[:heartbeat_interval]
          last_activity = subscription.created_at

          loop do
            if interval
              deadline = last_activity + interval
              remaining = deadline - clock.call
              record = subscription.pop(remaining > 0 ? remaining : 0)
            else
              record = subscription.pop
            end

            if record
              out << channel.format(record)
              last_activity = clock.call if interval
            elsif subscription.closed?
              break
            elsif interval && clock.call >= deadline
              out << ": heartbeat\n\n"
              last_activity = clock.call
            end
          end
        end
      end
    end

    register_plugin(:sse, SSE)
  end
end

