# frozen_string_literal: true

require 'securerandom'

#
class Roda
  module RodaPlugins
    # The sse plugin provides in-process Server-Sent Events support with
    # bounded replay. Events receive opaque identifiers whose embedded sequence
    # is monotonically increasing independently for each channel. Reconnecting
    # EventSource clients send the last identifier in the Last-Event-ID request
    # header, and events retained in the channel's event ring are delivered
    # before live events.
    #
    #   plugin :sse
    #
    #   route do |r|
    #     r.get 'events', String do |channel|
    #       sse_stream(channel)
    #     end
    #
    #     r.post 'events', String do |channel|
    #       sse_publish(channel, request.body.read)
    #     end
    #   end
    #
    # When the cursor has been evicted, belongs to another channel, or was
    # issued by a previous process generation, the stream receives an
    # +sse-reset+ event before live events. State remains in the process, so no
    # external message broker is required.
    #
    # Options:
    # :bus :: Shared Sse::Bus instance to use.
    # :history_size :: Number of events retained per channel (default: 100).
    # :pending_events_size :: Maximum queued live events per connection before
    #                         that slow connection is closed (default: 10).
    # :heartbeat :: Heartbeat interval in seconds, or false to disable
    #               (default: 15).
    module Sse
      # A single Server-Sent Event.
      class Event
        # The opaque identifier sent as the SSE +id+ field.
        attr_reader :id

        # The SSE event type, if provided.
        attr_reader :event

        # The event data.
        attr_reader :data

        # The suggested client reconnect wait, in milliseconds.
        attr_reader :retry_wait

        # The per-channel monotonically increasing sequence number.
        attr_reader :sequence

        def initialize(id, data, sequence, opts=OPTS)
          @id = id
          @data = data
          @sequence = sequence
          @event = opts[:event]
          @retry_wait = opts[:retry]

          if @event && @event.to_s =~ /[\r\n]/
            raise RodaError, "SSE event names cannot contain newlines"
          end
        end

        # Return the SSE wire representation.
        def to_s
          lines = []
          lines << "event: #{event}" if event
          lines << "id: #{id}"
          Array(data).each do |part|
            part.to_s.split(/\r\n|\r|\n/).each do |line|
              lines << "data: #{line}"
            end
          end
          lines << "retry: #{@retry_wait}" if @retry_wait
          lines.join("\n") << "\n\n"
        end
      end

      # Bounded event and subscriber state for one channel.
      class Channel
        attr_reader :last_sequence

        def initialize(history_size)
          @history_size = history_size
          @mutex = Mutex.new
          @events = []
          @subscriptions = []
          @last_sequence = 0
        end

        def synchronize(&block)
          @mutex.synchronize(&block)
        end

        def next_sequence!
          @last_sequence += 1
        end

        # Add an event to the bounded ring and deliver it to live subscribers.
        # Slow or closed subscribers are removed without blocking publishers.
        def publish(event)
          @events << event
          @events.shift if @events.length > @history_size

          slow = {}
          @subscriptions.each do |subscription|
            slow[subscription.object_id] = true unless subscription.push(event)
          end
          @subscriptions.delete_if { |subscription| slow[subscription.object_id] }
          event
        end

        # Atomically select replay events and add the live subscription.
        def subscribe(subscription, last_sequence=nil)
          events = if last_sequence
            @events.select { |event| event.sequence > last_sequence }
          else
            EMPTY_ARRAY
          end

          @subscriptions << subscription
          events
        end

        def unsubscribe(subscription)
          @mutex.synchronize { @subscriptions.delete(subscription) }
        end

        def oldest_sequence
          event = @events.first
          event.sequence if event
        end

        private

        def events_after(sequence)
          @events.select { |event| event.sequence > sequence }
        end
      end

      # Bounded per-connection queue.
      class Subscription
        attr_reader :close_reason

        def initialize(bus, channel, limit)
          @bus = bus
          @channel = channel
          @limit = limit
          @mutex = Mutex.new
          @condition = ConditionVariable.new
          @queue = []
          @closed = false
          @waiting = false
          @close_reason = nil
        end

        def closed?
          @mutex.synchronize { @closed }
        end

        def waiting?
          @mutex.synchronize { @waiting }
        end

        # Enqueue without blocking. Returns false when this subscription is
        # closed or has reached its independent pending-event limit.
        def push(event)
          @mutex.synchronize do
            next false if @closed

            if @queue.length >= @limit
              close_locked(:slow_consumer)
              next false
            end

            @queue << event
            @condition.signal
            true
          end
        end

        # Return an event, +:heartbeat+ when the heartbeat timeout elapses, or
        # nil when the subscription is closed and drained.
        def pop(clock, heartbeat)
          @mutex.synchronize do
            if @queue.empty? && !@closed
              @waiting = true
              begin
                if heartbeat
                  deadline = clock.now + heartbeat
                  while @queue.empty? && !@closed && clock.now < deadline
                    clock.wait(@condition, @mutex, deadline - clock.now)
                  end
                else
                  @condition.wait(@mutex)
                end
              ensure
                @waiting = false
              end
            end

            event = @queue.shift
            return event if event
            return :heartbeat if heartbeat && !@closed
            nil
          end
        end

        def close(reason=:closed)
          should_unsubscribe = false

          @mutex.synchronize do
            return if @closed
            close_locked(reason)
            should_unsubscribe = true
          end

          @bus.unsubscribe(@channel, self) if should_unsubscribe
        end

        private

        def close_locked(reason)
          @closed = true
          @close_reason = reason
          @condition.broadcast
        end
      end

      # Result returned by Bus#subscribe.
      class Result
        # +:live+ for a usable cursor, +:reset+ for an unusable cursor.
        attr_reader :status

        # Machine-readable reset reason.
        attr_reader :reason

        # Replay events to send before live events.
        attr_reader :events

        # Reset event to send before replay/live data.
        attr_reader :reset_event

        # The live subscription.
        attr_reader :subscription

        def initialize(status, subscription, events=EMPTY_ARRAY, reason=nil, reset_event=nil)
          @status = status
          @subscription = subscription
          @events = events
          @reason = reason
          @reset_event = reset_event
        end

        def reset?
          status == :reset
        end
      end

      # Rack body that writes replay events and then live events.
      class Stream
        def initialize(result, opts=OPTS)
          @result = result
          @heartbeat = opts[:heartbeat]
          @clock = opts[:clock]
        end

        def each
          yield @result.reset_event.to_s if @result.reset?
          @result.events.each { |event| yield event.to_s }

          subscription = @result.subscription
          while item = subscription.pop(@clock, @heartbeat)
            if item == :heartbeat
              yield ": heartbeat\n\n"
            else
              yield item.to_s
            end
          end
        ensure
          close
        end

        def close
          @result.subscription.close
        end
      end

      # Default heartbeat clock. Monotonic time prevents time changes from
      # causing immediate or skipped heartbeats.
      module MonotonicClock
        if defined?(Process::CLOCK_MONOTONIC)
          def self.now
            Process.clock_gettime(Process::CLOCK_MONOTONIC)
          end
        else
          def self.now
            Time.now.to_f
          end
        end

        def self.wait(condition, mutex, timeout)
          condition.wait(mutex, timeout)
        end
      end

      def self.configure(app, opts=OPTS)
        app.opts[:sse_bus] = opts[:bus] if opts[:bus]
        app.opts[:sse_history_size] = opts[:history_size] if opts.key?(:history_size)
        app.opts[:sse_pending_events_size] = opts[:pending_events_size] if opts.key?(:pending_events_size)
        if opts.key?(:heartbeat)
          heartbeat = opts[:heartbeat]
          if heartbeat && heartbeat != false
            heartbeat = Float(heartbeat)
            raise RodaError, "heartbeat must be positive" unless heartbeat > 0
          end
          app.opts[:sse_heartbeat] = heartbeat
        end

        app.opts[:sse_history_size] ||= 100
        app.opts[:sse_pending_events_size] ||= 10
        app.opts[:sse_heartbeat] = 15 unless app.opts.key?(:sse_heartbeat)
        app.opts[:sse_bus] ||= Bus.new(
          :history_size => app.opts[:sse_history_size],
          :pending_events_size => app.opts[:sse_pending_events_size],
          :heartbeat => app.opts[:sse_heartbeat]
        )
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :sse_bus)
      end

      module InstanceMethods
        # Publish data to an in-process SSE channel.
        def sse_publish(channel, data, opts=OPTS)
          self.class.sse_bus.publish(channel, data, opts)
        end

        # Immediately halt with an SSE response for a channel.
        def sse_stream(channel, opts=OPTS)
          response[RodaResponseHeaders::CONTENT_TYPE] = 'text/event-stream'
          response[RodaResponseHeaders::CACHE_CONTROL] = 'no-cache'
          response[accel_buffering_header] = 'no'

          bus = self.class.sse_bus
          result = bus.subscribe(channel, @_request.env['HTTP_LAST_EVENT_ID'], opts)
          heartbeat = opts.key?(:heartbeat) ? opts[:heartbeat] : self.class.opts[:sse_heartbeat]
          stream = Stream.new(
            result,
            :heartbeat => heartbeat || nil,
            :clock => bus.clock
          )
          throw :halt, @_response.finish_with_body(stream)
        end

        private

        if defined?(Rack::Headers) && Rack::Headers.is_a?(Class)
          def accel_buffering_header
            'x-accel-buffering'
          end
        else
          def accel_buffering_header
            'X-Accel-Buffering'
          end
        end
      end

      # In-process bounded SSE bus.
      class Bus
        # :generation is primarily useful for tests simulating a process
        # restart, while :clock accepts an object with +now+ and
        # +wait(condition, mutex, timeout)+ methods.
        attr_reader :clock

        def initialize(opts=OPTS)
          @history_size = positive_option(opts, :history_size, 100)
          @pending_events_size = positive_option(opts, :pending_events_size, 10)
          @heartbeat = heartbeat_option(opts[:heartbeat], 15)
          @generation = opts[:generation] || SecureRandom.hex(16)
          @clock = opts[:clock] || MonotonicClock
          @mutex = Mutex.new
          @channels = {}
        end

        # Publish an event and send it to all currently connected subscribers.
        def publish(channel, data, opts=OPTS)
          channel = channel.to_s
          event = nil

          synchronize_channel(channel) do |channel_state|
            sequence = channel_state.next_sequence!
            event = Event.new(encode_cursor(channel, sequence), data, sequence, opts)
            channel_state.publish(event)
          end

          event
        end

        # Connect to a channel. Replay selection and live registration occur
        # atomically, ensuring an event published at handoff is delivered once.
        def subscribe(channel, last_event_id=nil, opts=OPTS, &block)
          channel = channel.to_s
          result = nil

          synchronize_channel(channel) do |channel_state|
            status, reason, sequence = cursor_status(channel, channel_state, last_event_id)
            limit = positive_option(opts, :pending_events_size, @pending_events_size)
            subscription = Subscription.new(self, channel, limit)
            reset_event = nil
            replay_events = EMPTY_ARRAY

            if status == :reset
              reset_sequence = channel_state.last_sequence
              reset_event = Event.new(
                encode_cursor(channel, reset_sequence),
                reason.to_s,
                reset_sequence,
                :event => 'sse-reset'
              )
            elsif sequence
              replay_events = channel_state.send(:events_after, sequence)
            end

            block.call(status, reason, sequence) if block
            replay_events = channel_state.subscribe(subscription, sequence)
            result = Result.new(status, subscription, replay_events, reason, reset_event)
          end

          result
        end

        def unsubscribe(channel, subscription)
          channel_state = @mutex.synchronize { @channels[channel.to_s] }
          channel_state.unsubscribe(subscription) if channel_state
        end

        private

        def positive_option(opts, key, default)
          value = opts.key?(key) ? opts[key] : default
          value = Integer(value)
          raise RodaError, "#{key} must be positive" unless value > 0
          value
        end

        def heartbeat_option(value, default)
          value = default unless value
          return if value == false || value.nil?

          value = Float(value)
          raise RodaError, "heartbeat must be positive" unless value > 0
          value
        end

        def channel_state(name)
          @mutex.synchronize { @channels[name] ||= Channel.new(@history_size) }
        end

        def synchronize_channel(name)
          state = channel_state(name)
          state.synchronize { yield(state) }
        end

        def cursor_status(channel, channel_state, last_event_id)
          return :live, nil, nil if last_event_id.nil? || last_event_id.to_s.empty?

          cursor = decode_cursor(last_event_id)
          return :reset, :invalid_cursor, nil unless cursor

          generation, cursor_channel, sequence = cursor
          return :reset, :unknown_generation, nil unless generation == @generation
          return :reset, :wrong_channel, nil unless cursor_channel == channel

          oldest = channel_state.oldest_sequence
          if oldest && sequence < oldest
            return :reset, :cursor_evicted, nil
          end

          if sequence < 0 || sequence > channel_state.last_sequence
            return :reset, :invalid_cursor, nil
          end

          [:live, nil, sequence]
        end

        def encode_cursor(channel, sequence)
          ["1:#{@generation}:#{sequence}:#{channel}"].pack('m0')
        end

        def decode_cursor(value)
          value = value.to_s
          return unless value =~ /\A[A-Za-z0-9+\/]+=*\z/

          payload = value.unpack1('m0')
          parts = payload.split(':', 4)
          return unless parts.length == 4 && parts[0] == '1'
          return unless parts[2] =~ /\A(?:0|[1-9][0-9]*)\z/

          sequence = parts[2].to_i
          [parts[1], parts[3], sequence]
        rescue ArgumentError
          nil
        end
      end

    end
    register_plugin(:sse, Sse)
  end
end
