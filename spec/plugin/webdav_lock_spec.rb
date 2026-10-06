require_relative "../spec_helper"

class WebdavLockSpecClock
  attr_accessor :time

  def initialize(time=0)
    @time = time
  end

  def call
    @time
  end
end

class WebdavLockSpecLockStore
  def initialize(clock)
    @clock = clock
    @locks = []
    @mutex = Mutex.new
  end

  def active_locks(path, time)
    synchronize do
      active_locks_unlocked(path, time)
    end
  end

  def active_descendant_locks(path, time)
    synchronize do
      active_descendant_locks_unlocked(path, time)
    end
  end

  def active_lock_for_token(token, time)
    synchronize do
      @locks.find { |lock| lock[:token] == token && active?(lock, time) }
    end
  end

  def create_lock(lock, time)
    synchronize do
      conflicts = active_locks_unlocked(lock[:path], time)
      if lock[:depth] == "infinity"
        conflicts.concat(active_descendant_locks_unlocked(lock[:path], time))
      end
      raise Roda::RodaPlugins::WebdavLock::Conflict unless conflicts.empty?
      @locks << lock.dup
      lock
    end
  end

  def refresh_lock(path, token, expires_at, _time)
    synchronize do
      lock = @locks.find { |entry| entry[:path] == path && entry[:token] == token }
      return unless lock
      lock[:expires_at] = expires_at
      lock.dup
    end
  end

  def unlock_lock(path, token)
    synchronize do
      index = @locks.index { |lock| lock[:path] == path && lock[:token] == token }
      return unless index
      @locks.delete_at(index)
    end
  end

  def all_locks
    synchronize { @locks.map(&:dup) }
  end

  private

  def synchronize(&block)
    @mutex.synchronize(&block)
  end

  def active_locks_unlocked(path, time)
    @locks.select do |lock|
      active?(lock, time) &&
          (lock[:path] == path ||
            (lock[:depth] == "infinity" && path != lock[:path] && path.start_with?("#{lock[:path]}/")))
    end
  end

  def active_descendant_locks_unlocked(path, time)
    @locks.select do |lock|
      active?(lock, time) &&
        (lock[:path] == path || lock[:path].start_with?("#{path}/"))
    end
  end

  def active?(lock, time)
    lock[:expires_at].nil? || lock[:expires_at] > time
  end
end unless defined?(WebdavLockSpecLockStore)

class WebdavLockSpecResourceStore
  attr_reader :move_attempts
  attr_accessor :force_move_failure

  def initialize(paths, etags={})
    @paths = paths
    @etags = etags
    @move_attempts = 0
  end

  def exists?(path)
    @paths.key?(path)
  end

  def collection?(path)
    @paths[path] == :collection
  end

  def etag_for(path)
    @etags[path]
  end

  def move(source, destination, overwrite)
    @move_attempts += 1
    return false if @force_move_failure
    old_paths = @paths.dup
    moved = {}
    replacing_collection = collection?(destination)

    @paths.each_key do |path|
      next if replacing_collection && (path == destination || path.start_with?("#{destination}/"))
      if path == source
        moved[destination] = @paths[path]
      elsif path.start_with?("#{source}/")
        moved["#{destination}#{path[source.length, path.length]}"] = @paths[path]
      else
        moved[path] = @paths[path]
      end
    end

    if !overwrite && old_paths.key?(destination)
      return false
    end

    @paths.replace(moved)
    true
  rescue
    @paths.replace(old_paths)
    false
  end

  def snapshot
    @paths.dup
  end
end

describe "webdav_lock plugin" do
  before do
    @clock = WebdavLockSpecClock.new(100)
    @lock_store = WebdavLockSpecLockStore.new(@clock)
    @resource_store = WebdavLockSpecResourceStore.new(
      { "/" => :collection, "/file" => "file", "/other" => "other",
        "/dir" => :collection, "/dir/child" => "child", "/anc" => :collection,
        "/target" => :collection, "/target/inside" => "inside" },
      "/file" => '"v1"'
    )
    lock_store = @lock_store
    resource_store = @resource_store
    clock = @clock
    token_number = [0]

    app(:bare) do
      plugin :webdav_lock,
        :resource_store => resource_store,
        :lock_store => lock_store,
        :clock => clock,
        :token_generator => proc { "urn:uuid:token-#{token_number[0] += 1}" },
        :default_timeout => 60

      route do |r|
        r.put do
          r.webdav_authorize_write!
          "updated"
        end

        r.delete do
          r.webdav_authorize_delete!
          "deleted"
        end

        r.lock
        r.unlock
        r.move
        "ok"
      end
    end
  end

  def lockinfo(scope="exclusive")
    <<-XML
      <?xml version="1.0"?>
      <D:lockinfo xmlns:D="DAV:">
        <D:lockscope><D:#{scope}/></D:lockscope>
        <D:locktype><D:write/></D:locktype>
        <D:owner>owner</D:owner>
      </D:lockinfo>
    XML
  end

  def conditions(*tokens)
    "(#{tokens.map { |token| "<#{token}>" }.join(' ')})"
  end

  def lock(path, depth="0", timeout="Second-60")
    env = {
      "REQUEST_METHOD" => "LOCK",
      "HTTP_DEPTH" => depth,
      "HTTP_TIMEOUT" => timeout,
      "rack.input" => rack_input(lockinfo)
    }
    response = req(path, env)
    [response[0], response[1]["Lock-Token"].to_s.delete("<>"), response]
  end

  it "creates and removes depth 0 locks" do
    status, token, response = lock("/file")
    status.must_equal 200
    token.must_equal "urn:uuid:token-1"
    response[1]["Content-Type"].must_equal "application/xml; charset=utf-8"
    response[2].to_enum.to_a.join.must_include "<D:href>urn:uuid:token-1</D:href>"

    req("/file", "REQUEST_METHOD" => "PUT", "rack.input" => rack_input).first.must_equal 423
    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => conditions(token), "rack.input" => rack_input).first.must_equal 200

    req("/file", "REQUEST_METHOD" => "UNLOCK", "HTTP_LOCK_TOKEN" => "<#{token}>").first.must_equal 204
    req("/file", "REQUEST_METHOD" => "PUT", "rack.input" => rack_input).first.must_equal 200
  end

  it "does not treat a token for one resource as authority for another resource" do
    _, token, _ = lock("/file")

    req("/other", "REQUEST_METHOD" => "PUT", "HTTP_IF" => conditions(token), "rack.input" => rack_input).first.must_equal 412
  end

  it "supports tagged and untagged condition lists" do
    _, token, _ = lock("/file")
    tagged = "</file>#{conditions(token)}"

    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => tagged, "rack.input" => rack_input).first.must_equal 200
    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => "</other>#{conditions(token)}", "rack.input" => rack_input).first.must_equal 423
  end

  it "evaluates ETag conditions" do
    _, token, _ = lock("/file")

    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => "(\"v1\" <#{token}>)", "rack.input" => rack_input).first.must_equal 200
    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => "(\"v2\" <#{token}>)", "rack.input" => rack_input).first.must_equal 412
  end

  it "uses depth infinity locks to protect descendants" do
    _, token, _ = lock("/dir", "infinity")

    req("/dir/child", "REQUEST_METHOD" => "PUT", "rack.input" => rack_input).first.must_equal 423
    req("/dir/child", "REQUEST_METHOD" => "PUT", "HTTP_IF" => conditions(token), "rack.input" => rack_input).first.must_equal 200
    req("/dir", "REQUEST_METHOD" => "DELETE").first.must_equal 423
  end

  it "uses descendant locks to protect a deleted subtree" do
    _, token, _ = lock("/dir/child", "0")

    req("/dir", "REQUEST_METHOD" => "DELETE").first.must_equal 423
    req("/dir", "REQUEST_METHOD" => "DELETE", "HTTP_IF" => conditions(token)).first.must_equal 200
  end

  it "expires locks using the injected clock" do
    _, token, _ = lock("/file", "0", "Second-10")
    @clock.time = 109

    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => conditions(token), "rack.input" => rack_input).first.must_equal 200
  end

  it "refreshes an existing lock" do
    _, token, _ = lock("/file", "0", "Second-10")
    @clock.time = 105
    status = req("/file", "REQUEST_METHOD" => "LOCK", "HTTP_IF" => conditions(token), "HTTP_TIMEOUT" => "Second-20", "rack.input" => rack_input).first
    status.must_equal 200

    @clock.time = 120
    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => conditions(token), "rack.input" => rack_input).first.must_equal 200
    @clock.time = 126
    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => conditions(token), "rack.input" => rack_input).first.must_equal 412
  end

  it "requires matching lock roots for UNLOCK" do
    _, token, _ = lock("/file")

    req("/other", "REQUEST_METHOD" => "UNLOCK", "HTTP_LOCK_TOKEN" => "<#{token}>").first.must_equal 409
    req("/file", "REQUEST_METHOD" => "UNLOCK", "HTTP_LOCK_TOKEN" => token).first.must_equal 400
    @lock_store.all_locks.length.must_equal 1
  end

  it "moves only after source, target, descendant, and ancestor locks are authorized" do
    _, source_token, _ = lock("/dir/child", "0")
    _, target_token, _ = lock("/target", "0")
    before = @resource_store.snapshot

    req("/dir", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/target").first.must_equal 423
    req("/dir", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/target", "HTTP_IF" => conditions(source_token)).first.must_equal 423
    @resource_store.snapshot.must_equal before
    @resource_store.move_attempts.must_equal 0

    move_conditions = "#{conditions(source_token)} </target>#{conditions(target_token)}"
    status = req("/dir", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/target",
      "HTTP_IF" => move_conditions).first
    status.must_equal 204
    @resource_store.exists?("/target/child").must_equal true
    @resource_store.exists?("/dir/child").must_equal false
  end

  it "does not let a source subtree token authorize a destination ancestor lock" do
    _, source_token, _ = lock("/dir", "infinity")
    _, ancestor_token, _ = lock("/anc", "infinity")
    before = @resource_store.snapshot

    req("/dir/child", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/anc/moved").first.must_equal 423
    req("/dir/child", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/anc/moved", "HTTP_IF" => conditions(source_token)).first.must_equal 423
    @resource_store.snapshot.must_equal before
    @resource_store.move_attempts.must_equal 0
    req("/dir/child", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/anc/moved",
      "HTTP_IF" => "#{conditions(source_token)} </anc/moved>#{conditions(ancestor_token)}").first.must_equal 201
  end

  it "requires a token for a lock below an existing MOVE destination collection" do
    _, inside_token, _ = lock("/target/inside", "0")
    before = @resource_store.snapshot

    req("/other", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/target").first.must_equal 423
    req("/other", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/target",
      "HTTP_IF" => "</target/inside>#{conditions(inside_token)}").first.must_equal 204
    @resource_store.snapshot.wont_equal before
  end

  it "requires the same ancestor token for both MOVE sides" do
    _, root_token, _ = lock("/anc", "infinity")

    req("/other", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/anc/moved",
      "HTTP_IF" => conditions(root_token)).first.must_equal 423
    req("/other", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/anc/moved",
      "HTTP_IF" => "#{conditions(root_token)} </anc/moved>#{conditions(root_token)}").first.must_equal 201
  end

  it "does not attempt a MOVE when Overwrite F protects an existing destination" do
    before = @resource_store.snapshot
    req("/other", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/target", "HTTP_OVERWRITE" => "F").first.must_equal 412
    @resource_store.move_attempts.must_equal 0
    @resource_store.snapshot.must_equal before
  end

  it "leaves the resource tree unchanged when the injected MOVE backend fails" do
    @resource_store.force_move_failure = true
    before = @resource_store.snapshot
    req("/file", "REQUEST_METHOD" => "MOVE", "HTTP_DESTINATION" => "/moved").first.must_equal 409
    @resource_store.move_attempts.must_equal 1
    @resource_store.snapshot.must_equal before
  end

  it "rejects unsupported Depth and zero Timeout values for LOCK" do
    req("/file", "REQUEST_METHOD" => "LOCK", "HTTP_DEPTH" => "1", "rack.input" => rack_input(lockinfo)).first.must_equal 400
    req("/file", "REQUEST_METHOD" => "LOCK", "HTTP_TIMEOUT" => "Second-0", "rack.input" => rack_input(lockinfo)).first.must_equal 400
    @lock_store.all_locks.must_be :empty?
  end

  it "rejects malformed and cross-origin tagged condition URIs" do
    _, token, _ = lock("/file")

    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => "<#{conditions(token)}", "rack.input" => rack_input).first.must_equal 400
    req("/file", "REQUEST_METHOD" => "PUT", "HTTP_IF" => "<http://evil.example/file>#{conditions(token)}", "rack.input" => rack_input).first.must_equal 400
  end
end
