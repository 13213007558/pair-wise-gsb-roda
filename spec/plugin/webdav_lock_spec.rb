require_relative "../spec_helper"

describe "webdav_lock plugin" do
  # Mutable clock so lock expiry is deterministic.
  class TestClock
    attr_accessor :time
    def initialize(time)
      @time = time
    end
    def call
      @time
    end
  end

  class MemoryLockStore
    def initialize(clock)
      @clock = clock
      @locks = {}
    end

    def create_lock(lock)
      prune
      @locks[lock[:token]] = lock.dup
      lock
    end

    def get_lock(token)
      prune
      lock = @locks[token]
      lock && lock.dup
    end

    def delete_lock(token)
      prune
      lock = @locks.delete(token)
      lock && lock.dup
    end

    def direct_locks(path)
      prune
      @locks.values.select { |l| normalize(l[:path]) == normalize(path) }.map(&:dup)
    end

    def ancestor_locks(path)
      prune
      path = normalize(path)
      @locks.values.select do |l|
        l[:depth].infinite? && path != normalize(l[:path]) && path.start_with?(prefix(l[:path]))
      end.map(&:dup)
    end

    def locks_under(path)
      prune
      path = normalize(path)
      @locks.values.select do |l|
        p = normalize(l[:path])
        p != path && p.start_with?(prefix(path))
      end.map(&:dup)
    end

    def move_locks(src, dst)
      src = normalize(src)
      dst = normalize(dst)
      @locks.each_value do |lock|
        path = normalize(lock[:path])
        if path == src
          lock[:path] = dst
        elsif path.start_with?(prefix(src))
          lock[:path] = dst + path[src.length..-1]
        end
      end
    end

    private

    def prune
      now = @clock.time
      @locks.delete_if { |_, l| l[:expires_at] && now >= l[:expires_at] }
    end

    def normalize(path)
      path = path.squeeze('/')
      path = path.chomp('/') unless path == '/'
      path
    end

    def prefix(path)
      path = normalize(path)
      path == '/' ? '/' : path + '/'
    end
  end

  class MemoryResources
    def initialize(entries)
      @entries = entries
      @etags = {}
      @moves = []
    end

    attr_reader :moves

    def resource_exists?(path)
      @entries.key?(normalize(path))
    end

    def resource_collection?(path)
      @entries[normalize(path)] == :collection
    end

    def resource_etag(path)
      @etags[normalize(path)]
    end

    def set_etag(path, etag)
      @etags[normalize(path)] = etag
    end

    def move_tree(src, dst)
      @moves << [normalize(src), normalize(dst)]
      src = normalize(src)
      dst = normalize(dst)
      moved = {}
      @entries.each do |path, kind|
        if path == src
          moved[dst] = kind
        elsif path.start_with?(prefix(src))
          moved[dst + path[src.length..-1]] = kind
        else
          moved[path] = kind
        end
      end
      @entries.replace(moved)
    end

    def snapshot
      @entries.dup
    end

    private

    def normalize(path)
      path = path.squeeze('/')
      path = path.chomp('/') unless path == '/'
      path
    end

    def prefix(path)
      path = normalize(path)
      path == '/' ? '/' : path + '/'
    end
  end

  LOCKINFO = <<~XML
    <?xml version="1.0" encoding="utf-8"?>
    <D:lockinfo xmlns:D="DAV:">
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:locktype><D:write/></D:locktype>
      <D:owner>alice</D:owner>
    </D:lockinfo>
  XML

  SHARED_LOCKINFO = LOCKINFO.sub('<D:exclusive/>', '<D:shared/>')

  def setup_backends(opts={})
    @clock = TestClock.new(Time.utc(2026, 1, 1, 12, 0, 0)) unless @clock
    @lock_store = MemoryLockStore.new(@clock) unless @lock_store
    @resources = MemoryResources.new(
      '/' => :collection,
      '/dir' => :collection,
      '/dir/file' => :resource,
      '/dir/child' => :collection,
      '/dir/child/grand' => :resource,
      '/other' => :resource
    ) unless @resources
    build_app(opts)
    [@clock, @lock_store, @resources]
  end

  def build_app(opts={})
    clock = @clock
    lock_store = @lock_store
    resources = @resources

    app(:bare) do
      plugin :webdav_lock, {lock_store: lock_store, resources: resources, clock: clock}.merge!(opts)

      route do |r|
        r.on do
          case r.request_method
          when 'LOCK'
            r.webdav_lock!
          when 'UNLOCK'
            r.webdav_unlock!
          when 'PUT'
            r.webdav_authorize_write!
            response.status = 204
            nil
          when 'DELETE'
            r.webdav_authorize_write!(nil, subtree: true)
            response.status = 204
            nil
          when 'MOVE'
            r.webdav_move!
          when 'GET'
            'get-ok'
          else
            response.status = 405
            'method-not-allowed'
          end
        end
      end
    end
  end

  def before_setup
    super
    @clock = @lock_store = @resources = nil
    @clock, @lock_store, @resources = setup_backends
  end

  def lock(path, body: LOCKINFO, depth: nil, timeout: nil)
    env = {'REQUEST_METHOD' => 'LOCK', 'HTTP_HOST' => 'example.org', 'rack.input' => rack_input(body)}
    env['HTTP_DEPTH'] = depth if depth
    env['HTTP_TIMEOUT'] = timeout if timeout
    req(path, env)
  end

  def lock_token(path, **kwargs)
    response = lock(path, **kwargs)
    response[0].must_equal 200
    token_for(response)
  end

  def unlock(path, token)
    req(path, 'REQUEST_METHOD' => 'UNLOCK', 'HTTP_HOST' => 'example.org', 'HTTP_LOCK_TOKEN' => "<#{token}>")
  end

  def token_for(response)
    response[1]['Lock-Token'].gsub(/[<>]/, '')
  end

  def put(path, extra={})
    req(path, {'REQUEST_METHOD' => 'PUT', 'HTTP_HOST' => 'example.org'}.merge!(extra))
  end

  def delete(path, extra={})
    req(path, {'REQUEST_METHOD' => 'DELETE', 'HTTP_HOST' => 'example.org'}.merge!(extra))
  end

  def move(src, dst, extra={})
    req(src, {'REQUEST_METHOD' => 'MOVE', 'HTTP_HOST' => 'example.org', 'HTTP_DESTINATION' => dst}.merge!(extra))
  end

  def if_header(tokens)
    "(#{tokens.map { |t| "<#{t}>" }.join(' ')})"
  end

  # -- LOCK / UNLOCK -----------------------------------------------------

  it "creates an exclusive lock and returns a lock token and prop xml" do
    status, headers, body_parts = lock('/dir/file')
    status.must_equal 200
    token = headers['Lock-Token']
    token.must_match(/\A<opaquelocktoken:[0-9a-f-]+>\z/)
    body = body_parts.to_a.join
    body.must_include('<D:exclusive/>')
    body.must_include('<D:depth>0</D:depth>')
    body.must_include('<D:owner>alice</D:owner>')
    body.must_include("<D:href>#{Rack::Utils.escape_html(token)}</D:href>")
  end

  it "supports depth infinity locks on collections" do
    status, headers, body_parts = lock('/dir', depth: 'infinity')
    status.must_equal 200
    body = body_parts.to_a.join
    body.must_include('<D:depth>Infinity</D:depth>')
    token = token_for([status, headers, body_parts])
    @lock_store.get_lock(token)[:depth].must_equal(Float::INFINITY)
  end

  it "defaults depth to 0 and refuses infinity on non-collection resources" do
    status, _, _ = lock('/dir/file')
    status.must_equal 200

    status, = lock('/other', depth: 'infinity')
    status.must_equal 400
  end

  it "returns 409 when locking a nonexistent resource" do
    status, = lock('/missing')
    status.must_equal 409
  end

  it "returns 400 for a malformed lockinfo body" do
    status, = lock('/dir/file', body: 'not xml')
    status.must_equal 400
  end

  it "returns 400 for an unsupported Depth value" do
    status, = lock('/dir', depth: '1')
    status.must_equal 400
  end

  it "refreshes a lock presented in an untagged If list" do
    token = lock_token('/dir/file', timeout: 'Second-100')
    @clock.time += 60
    response = req('/dir/file',
      'REQUEST_METHOD' => 'LOCK', 'HTTP_HOST' => 'example.org',
      'rack.input' => rack_input(''),
      'HTTP_IF' => "(<#{token}>)",
      'HTTP_TIMEOUT' => 'Second-200')
    response[0].must_equal 200
    refreshed = @lock_store.get_lock(token)
    refreshed[:expires_at].must_equal @clock.time + 200
  end

  it "refreshes a lock presented in a tagged If list" do
    token = lock_token('/dir/file')
    response = req('/dir/file',
      'REQUEST_METHOD' => 'LOCK', 'HTTP_HOST' => 'example.org',
      'rack.input' => rack_input(''),
      'HTTP_IF' => "<http://example.org/dir/file> (<#{token}>)")
    response[0].must_equal 200
  end

  it "does not refresh a token that belongs to a different resource" do
    token = lock_token('/other')
    response = req('/dir/file',
      'REQUEST_METHOD' => 'LOCK', 'HTTP_HOST' => 'example.org',
      'rack.input' => rack_input(''),
      'HTTP_IF' => "(<#{token}>)")
    response[0].must_equal 412
  end

  it "returns 412 when refreshing without a token" do
    response = req('/dir/file',
      'REQUEST_METHOD' => 'LOCK', 'HTTP_HOST' => 'example.org',
      'rack.input' => rack_input(''))
    response[0].must_equal 412
  end

  it "unlocks with a matching Lock-Token header" do
    token = lock_token('/dir/file')
    status, = unlock('/dir/file', token)
    status.must_equal 204
    @lock_store.get_lock(token).must_be_nil
  end

  it "returns 409 when unlocking with an unknown token" do
    status, = unlock('/dir/file', 'opaquelocktoken:nope')
    status.must_equal 409
  end

  it "returns 409 when the unlock token is held by a different resource" do
    token = lock_token('/other')
    status, = unlock('/dir/file', token)
    status.must_equal 409
    @lock_store.get_lock(token).wont_be_nil
  end

  it "returns 400 when UNLOCK has no Lock-Token header" do
    status, = req('/dir/file', 'REQUEST_METHOD' => 'UNLOCK')
    status.must_equal 400
  end

  it "expires locks according to the injected clock" do
    token = lock_token('/dir/file', timeout: 'Second-60')
    @clock.time += 30
    @lock_store.get_lock(token).wont_be_nil
    @clock.time += 31
    @lock_store.get_lock(token).must_be_nil
    put('/dir/file')[0].must_equal 204
  end

  it "applies default and max timeouts" do
    @lock_store = MemoryLockStore.new(@clock)
    build_app(default_timeout: 30, max_timeout: 100)
    token = lock_token('/other')
    @lock_store.get_lock(token)[:timeout].must_equal 30

    @lock_store = MemoryLockStore.new(@clock)
    build_app(max_timeout: 100)
    token = lock_token('/other', timeout: 'Second-500')
    @lock_store.get_lock(token)[:timeout].must_equal 100
  end

  it "allows a shared lock over another shared lock but not an exclusive one" do
    first = lock_token('/dir/file', body: SHARED_LOCKINFO)
    second = lock('/dir/file', body: SHARED_LOCKINFO)
    second[0].must_equal 200

    status, = lock('/dir/file')
    status.must_equal 409
    @lock_store.get_lock(first).wont_be_nil
  end

  it "returns 409 when taking an exclusive lock over a locked subtree" do
    child_token = lock_token('/dir/file')
    status, = lock('/dir', depth: 'infinity')
    status.must_equal 409
    @lock_store.get_lock(child_token).wont_be_nil
  end

  # -- PUT / DELETE enforcement -----------------------------------------

  it "blocks PUT on a locked resource with 423 when no If header is sent" do
    lock_token('/dir/file')
    put('/dir/file')[0].must_equal 423
  end

  it "allows PUT when the proper lock token is presented" do
    token = lock_token('/dir/file')
    put('/dir/file', 'HTTP_IF' => if_header([token]))[0].must_equal 204
  end

  it "does not treat a token for another resource as write permission" do
    lock_token('/dir/file')
    other_token = lock_token('/other')
    put('/dir/file', 'HTTP_IF' => if_header([other_token]))[0].must_equal 412
  end

  it "allows GET on a locked resource without a token" do
    lock_token('/dir/file')
    req('/dir/file')[0].must_equal 200
  end

  it "enforces depth-infinity ancestor locks for member resources" do
    ancestor = lock_token('/dir', depth: 'infinity')
    put('/dir/file')[0].must_equal 423
    put('/dir/child/grand', 'HTTP_IF' => if_header([ancestor]))[0].must_equal 204
  end

  it "does not enforce a depth-0 lock of an ancestor on a child" do
    lock_token('/dir', depth: '0')
    put('/dir/file')[0].must_equal 204
  end

  it "returns 412 for a wrong token in the If header" do
    lock_token('/dir/file')
    put('/dir/file', 'HTTP_IF' => "(<opaquelocktoken:does-not-exist>)")[0].must_equal 412
  end

  it "enforces every lock in a subtree when DELETE removes a collection" do
    root_token = lock_token('/dir/child', depth: 'infinity', body: SHARED_LOCKINFO)
    member_token = lock_token('/dir/child/grand', body: SHARED_LOCKINFO)
    # The root token alone does not unlock a directly locked member.
    delete('/dir/child', 'HTTP_IF' => if_header([root_token]))[0].must_equal 412
    # Both tokens in one list (AND) unlock the whole subtree.
    delete('/dir/child', 'HTTP_IF' => if_header([root_token, member_token]))[0].must_equal 204
  end

  it "supports multiple alternative untagged lists" do
    token = lock_token('/dir/file')
    # First alternative fails (unknown token), second passes (OR).
    put('/dir/file', 'HTTP_IF' => "(<opaquelocktoken:nope>) (<#{token}>)")[0].must_equal 204
  end

  it "supports tagged lists for a specific resource" do
    token = lock_token('/dir/file')
    status = put('/dir/file',
      'HTTP_IF' => "<http://example.org/dir/file> (<#{token}>)")
    status[0].must_equal 204
  end

  it "does not accept a tagged list for a different resource" do
    lock_token('/dir/file')
    token = lock_token('/other')
    put('/dir/file',
      'HTTP_IF' => "<http://example.org/other> (<#{token}>)")[0].must_equal 412
  end

  it "rejects a tag for a different host" do
    token = lock_token('/dir/file')
    put('/dir/file',
      'HTTP_IF' => "<http://evil.example/dir/file> (<#{token}>)")[0].must_equal 412
  end

  it "returns 400 for a malformed If header" do
    lock_token('/dir/file')
    put('/dir/file', 'HTTP_IF' => 'not a condition list')[0].must_equal 400
  end

  it "supports negated and entity-tag conditions" do
    @resources.set_etag('/dir/file', '"v1"')
    # Unlocked resource: a matching positive etag passes.
    put('/dir/file', 'HTTP_IF' => '(["v1"])')[0].must_equal 204
    # A non-matching positive etag fails.
    put('/dir/file', 'HTTP_IF' => '(["v2"])')[0].must_equal 412
    # A negated token for a token that is not held here passes.
    put('/dir/file', 'HTTP_IF' => '(Not <opaquelocktoken:unknown>)')[0].must_equal 204

    token = lock_token('/dir/file')
    # Negating the very lock that protects the resource fails.
    put('/dir/file', 'HTTP_IF' => "(Not <#{token}>)")[0].must_equal 412
    # Matching etag together with the lock token passes.
    put('/dir/file',
      'HTTP_IF' => "(<#{token}>) ([\"v1\"])")[0].must_equal 204
  end

  # -- MOVE -------------------------------------------------------------

  it "moves an unlocked tree" do
    before = @resources.snapshot
    status, = move('/dir/file', 'http://example.org/moved')
    status.must_equal 201
    @resources.resource_exists?('/moved').must_equal true
    @resources.resource_exists?('/dir/file').must_equal false
    @resources.moves.must_equal [['/dir/file', '/moved']]
  end

  it "requires tokens for the source and destination independently" do
    src_token = lock_token('/dir/file')
    dst_token = lock_token('/other')

    move('/dir/file', 'http://example.org/other')[0].must_equal 423
    # Source token alone is not enough: destination is also locked.
    move('/dir/file', 'http://example.org/other',
      'HTTP_IF' => if_header([src_token]))[0].must_equal 412
    # Both tokens required in a single AND list.
    status, = move('/dir/file', 'http://example.org/other',
      'HTTP_IF' => if_header([src_token, dst_token]))
    status.must_equal 204
  end

  it "requires an ancestor depth lock token for the destination" do
    ancestor = lock_token('/dir', depth: 'infinity')
    status, = move('/other', 'http://example.org/dir/imported')
    status.must_equal 423
    status, = move('/other', 'http://example.org/dir/imported',
      'HTTP_IF' => if_header([ancestor]))
    status.must_equal 201
  end

  it "requires tokens for locked members of the moved subtree" do
    member_token = lock_token('/dir/child/grand')
    # Moving /dir tree without the member token is rejected.
    move('/dir', 'http://example.org/moved-dir')[0].must_equal 423
    status, = move('/dir', 'http://example.org/moved-dir',
      'HTTP_IF' => if_header([member_token]))
    status.must_equal 201
    @resources.resource_exists?('/moved-dir/child/grand').must_equal true
  end

  it "does not touch the resource tree when a precondition fails" do
    lock_token('/other')
    snapshot = @resources.snapshot
    move('/dir/file', 'http://example.org/other')[0].must_equal 423
    @resources.snapshot.must_equal snapshot
    @resources.moves.must_be :empty?
  end

  it "rejects a missing Destination header" do
    req('/dir/file', 'REQUEST_METHOD' => 'MOVE', 'HTTP_HOST' => 'example.org')[0].must_equal 400
  end

  it "rejects a cross-host Destination" do
    move('/dir/file', 'http://evil.example/there')[0].must_equal 400
  end

  it "honors Overwrite: F against an existing destination" do
    move('/dir/file', 'http://example.org/other', 'HTTP_OVERWRITE' => 'F')[0].must_equal 412
  end

  it "moves locks with the resource tree" do
    token = lock_token('/dir/file', timeout: 'Second-100')
    status, = move('/dir/file', 'http://example.org/moved',
      'HTTP_IF' => if_header([token]))
    status.must_equal 201
    moved = @lock_store.get_lock(token)
    moved[:path].must_equal '/moved'
    # The moved lock still protects the new location.
    put('/moved')[0].must_equal 423
    # The old location is free.
    put('/dir/file')[0].must_equal 204
  end

  it "accepts an origin-relative Destination" do
    status, = move('/dir/file', '/moved')
    status.must_equal 201
    @resources.resource_exists?('/moved').must_equal true
  end

  it "returns 400 for a malformed Lock-Token header on UNLOCK" do
    status, = req('/dir/file',
      'REQUEST_METHOD' => 'UNLOCK', 'HTTP_LOCK_TOKEN' => 'opaquelocktoken:x')
    status.must_equal 400
  end

  it "keeps the tree unchanged when a destination ancestor lock is missing" do
    ancestor = lock_token('/dir', depth: 'infinity')
    snapshot = @resources.snapshot
    status, = move('/other', 'http://example.org/dir/imported')
    status.must_equal 423
    @resources.snapshot.must_equal snapshot
    @resources.moves.must_be :empty?
    # An unrelated token (e.g. a lock elsewhere) still fails and moves nothing.
    other = lock_token('/other')
    status, = move('/other', 'http://example.org/dir/imported',
      'HTTP_IF' => if_header([other]))
    status.must_equal 412
    @resources.snapshot.must_equal snapshot
  end

  it "moves the tree when all actually-locked members present tokens" do
    member = lock_token('/dir/child/grand')
    status, = move('/dir', 'http://example.org/moved-dir',
      'HTTP_IF' => if_header([member]))
    status.must_equal 201
    @resources.resource_exists?('/moved-dir/child/grand').must_equal true
  end

  it "evaluates origin-relative tagged lists" do
    token = lock_token('/dir/file')
    status = put('/dir/file', 'HTTP_IF' => "</dir/file> (<#{token}>)")
    status[0].must_equal 204
  end

  it "does not let a subtree member token substitute for the source lock" do
    src_token = lock_token('/dir', depth: 'infinity', body: SHARED_LOCKINFO)
    member_token = lock_token('/dir/child/grand', body: SHARED_LOCKINFO)
    snapshot = @resources.snapshot
    status, = move('/dir', 'http://example.org/moved-dir',
      'HTTP_IF' => if_header([member_token]))
    status.must_equal 412
    @resources.snapshot.must_equal snapshot
    # Both locks are required.
    status, = move('/dir', 'http://example.org/moved-dir',
      'HTTP_IF' => if_header([src_token, member_token]))
    status.must_equal 201
  end
end
