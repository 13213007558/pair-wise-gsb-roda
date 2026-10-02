require_relative "../spec_helper"
require "fileutils"
require "json"
require "rbconfig"
require "tmpdir"

class TrackingIO
  attr_reader :reads, :rewinds

  def initialize(data, chunk_size = nil)
    @io = StringIO.new(data.b)
    @chunk_size = chunk_size
    @reads = 0
    @rewinds = 0
  end

  def read(length = nil)
    @reads += 1
    @io.read(@chunk_size || length)
  end

  def rewind
    @rewinds += 1
    @io.rewind
  end

  def gets(*args)
    @io.gets(*args)
  end

  def each
    @io.each { |line| yield line }
  end

  def close
    @io.close
  end
end

class GatedIO
  def initialize(data, gate, events)
    @io = StringIO.new(data.b)
    @gate = gate
    @events = events
  end

  def read(length)
    data = @io.read(length)
    @events << :read
    @gate.pop
    data
  end

  def gets(*args)
    @io.gets(*args)
  end

  def each
    @io.each { |line| yield line }
  end

  def close
    @io.close
  end
end

describe "tus plugin" do
  def tus_app(**opts)
    @dir ||= Dir.mktmpdir
    directory = @dir
    app(:bare) do
      plugin :tus, opts.merge(dir: directory)

      route do |r|
        r.post "" do
          r.tus_upload
        end

        r.is String do |id|
          r.tus_upload(id)
        end
      end
    end
  end

  def tus_headers(extra = {})
    {
      "HTTP_TUS_RESUMABLE" => "1.0.0",
      "rack.input" => rack_input,
    }.merge(extra)
  end

  def create_upload(length = 10, extra = {})
    env = {
      "REQUEST_METHOD" => "POST",
      "HTTP_UPLOAD_LENGTH" => length.to_s,
      "rack.input" => rack_input,
    }
    env.delete("HTTP_UPLOAD_LENGTH") unless length
    status, headers, _body = req("/", tus_headers(env.merge(extra)))
    location = response_header(headers, "Location")
    [status, location && File.basename(location)]
  end

  def patch_upload(id, data, offset, extra = {})
    env = {
      "REQUEST_METHOD" => "PATCH",
      "CONTENT_TYPE" => "application/offset+octet-stream",
      "HTTP_UPLOAD_OFFSET" => offset.to_s,
      "CONTENT_LENGTH" => data.bytesize.to_s,
      "rack.input" => rack_input(data),
    }
    req("/#{id}", tus_headers(env.merge(extra)))
  end

  def patch_upload_without_content_length(id, data, offset, extra = {})
    env = {
      "REQUEST_METHOD" => "PATCH",
      "CONTENT_TYPE" => "application/offset+octet-stream",
      "HTTP_UPLOAD_OFFSET" => offset.to_s,
      "rack.input" => rack_input(data),
    }
    req("/#{id}", tus_headers(env.merge(extra)))
  end

  def head_upload(id, extra = {})
    req("/#{id}", tus_headers("REQUEST_METHOD" => "HEAD").merge(extra))
  end

  def data_file(id)
    File.join(@dir, id, "data")
  end

  def metadata_file(id)
    File.join(@dir, id, "metadata")
  end

  def response_header(headers, name)
    headers.fetch(name) do
      matched = headers.each_key.find do |key|
        key.is_a?(String) && key.downcase == name.downcase
      end
      headers[matched]
    end
  end

  after do
    FileUtils.remove_entry(@dir, true) if @dir
  end

  it "creates, reports, patches, and resumes uploads" do
    tus_app
    status, id = create_upload(5)
    status.must_equal 201
    id.must_match(/\A[0-9a-f]{64}\z/)

    status, headers, _body = head_upload(id)
    status.must_equal 200
    response_header(headers, "Upload-Offset").must_equal "0"
    response_header(headers, "Upload-Length").must_equal "5"

    status, headers, _body = patch_upload(id, "he", 0)
    status.must_equal 204
    response_header(headers, "Upload-Offset").must_equal "2"
    File.binread(data_file(id)).must_equal "he"

    status, headers, _body = patch_upload(id, "llo", 2)
    status.must_equal 204
    response_header(headers, "Upload-Offset").must_equal "5"

    status, headers, _body = head_upload(id)
    status.must_equal 200
    response_header(headers, "Upload-Offset").must_equal "5"
    response_header(headers, "Upload-Length").must_equal "5"
    File.binread(data_file(id)).must_equal "hello"
  end

  it "rejects a patch whose offset does not match the committed offset" do
    tus_app
    _, id = create_upload(5)

    status, _headers, _body = patch_upload(id, "he", 0)
    status.must_equal 204

    status, headers, _body = patch_upload(id, "x", 1)
    status.must_equal 409
    response_header(headers, "Upload-Offset").must_equal "2"
    File.binread(data_file(id)).must_equal "he"
  end

  it "validates tus headers and upload paths" do
    tus_app
    _, id = create_upload(5)

    status, _headers, _body = req("/",
      "REQUEST_METHOD" => "POST",
      "rack.input" => rack_input
    )
    status.must_equal 412

    status, _headers, _body = head_upload("..")
    status.must_equal 404

    status, _headers, _body = head_upload("missing")
    status.must_equal 404

    status, _headers, _body = req("/#{id}",
      "REQUEST_METHOD" => "PATCH",
      "CONTENT_TYPE" => "text/plain",
      "HTTP_TUS_RESUMABLE" => "1.0.0",
      "HTTP_UPLOAD_OFFSET" => "0",
      "CONTENT_LENGTH" => "0",
      "rack.input" => rack_input
    )
    status.must_equal 412
  end

  it "supports deferred length and final length confirmation" do
    tus_app(max_size: 10)
    status, id = create_upload(nil, "HTTP_UPLOAD_DEFER_LENGTH" => "1")
    status.must_equal 201

    status, headers, _body = patch_upload(id, "he", 0)
    status.must_equal 204
    response_header(headers, "Upload-Offset").must_equal "2"

    status, headers, _body = patch_upload(id, "", 2,
      "HTTP_UPLOAD_LENGTH" => "5",
      "CONTENT_LENGTH" => "0"
    )
    status.must_equal 204
    response_header(headers, "Upload-Offset").must_equal "2"

    status, headers, _body = head_upload(id)
    response_header(headers, "Upload-Offset").must_equal "2"
    response_header(headers, "Upload-Length").must_equal "5"

    status, headers, _body = patch_upload(id, "l", 3)
    status.must_equal 409

    status, _headers, _body = patch_upload(id, "llo", 2)
    status.must_equal 204

    status, headers, _body = head_upload(id)
    status.must_equal 200
    response_header(headers, "Upload-Offset").must_equal "5"
    response_header(headers, "Upload-Length").must_equal "5"
    File.binread(data_file(id)).must_equal "hello"
  end

  it "enforces maximum and final lengths without buffering the body" do
    tus_app(max_size: 10)

    status, id = create_upload(11)
    status.must_equal 413
    id.must_be_nil

    _, id = create_upload(nil, "HTTP_UPLOAD_DEFER_LENGTH" => "1")
    input = TrackingIO.new("too-large")
    status, _headers, _body = patch_upload(id, "", 0,
      "HTTP_UPLOAD_LENGTH" => "11",
      "CONTENT_LENGTH" => "9",
      "rack.input" => input
    )
    status.must_equal 413
    input.reads.must_equal 0

    input = TrackingIO.new("12345678901")
    status, _headers, _body = patch_upload_without_content_length(id, "12345678901", 0,
      "rack.input" => input
    )
    status.must_equal 413
    File.binread(data_file(id)).must_equal ""

    input = TrackingIO.new("123456")
    status, _headers, _body = patch_upload(id, "", 0,
      "HTTP_UPLOAD_LENGTH" => "5",
      "CONTENT_LENGTH" => "6",
      "rack.input" => input
    )
    status.must_equal 413
    input.reads.must_equal 0
  end

  it "reads each request body once and forwards it directly to disk" do
    tus_app
    _, id = create_upload(100)
    input = TrackingIO.new("abc")

    status, _headers, _body = patch_upload(id, "ignored", 0,
      "CONTENT_LENGTH" => "3",
      "rack.input" => input
    )

    status.must_equal 204
    input.reads.must_equal 1
    input.rewinds.must_equal 0
    File.binread(data_file(id)).must_equal "abc"
  end

  it "accepts only the request whose patch starts at the current offset" do
    tus_app
    _, id = create_upload(5)
    gate = Queue.new
    events = Queue.new
    first = Thread.new do
      req("/#{id}", tus_headers(
        "REQUEST_METHOD" => "PATCH",
        "CONTENT_TYPE" => "application/offset+octet-stream",
        "HTTP_UPLOAD_OFFSET" => "0",
        "CONTENT_LENGTH" => "2",
        "rack.input" => GatedIO.new("ab", gate, events)
      ))
    end

    events.pop.must_equal :read
    second_input = TrackingIO.new("cd")
    second = Thread.new do
      patch_upload(id, "cd", 0, "rack.input" => second_input)
    end

    sleep 0.05
    gate << nil
    status, headers, _body = first.value
    status.must_equal 204
    response_header(headers, "Upload-Offset").must_equal "2"

    status, headers, _body = second.value
    status.must_equal 409
    response_header(headers, "Upload-Offset").must_equal "2"
    second_input.reads.must_equal 0
    File.binread(data_file(id)).must_equal "ab"
  end

  it "recovers when killed after data is synced but before metadata is committed" do
    tus_app
    _, id = create_upload(nil, "HTTP_UPLOAD_DEFER_LENGTH" => "1")
    signal = File.join(@dir, "crashed")
    spec_dir = File.expand_path("../..", __dir__)

    child_code = <<-'RUBY'
      $LOAD_PATH.unshift(File.expand_path("lib", ENV.fetch("SPEC_DIR")))
      require "roda"
      require "roda/plugins/tus"
      require "fileutils"
      require "stringio"

      storage_class = Class.new(Roda::RodaPlugins::Tus::FileStorage) do
        def commit_upload(*)
          FileUtils.touch(ENV.fetch("SIGNAL_PATH"))
          Process.kill("KILL", Process.pid)
        end
      end

      app = Class.new(Roda) do
        plugin :tus, storage: storage_class.new(ENV.fetch("UPLOAD_DIR"))
        route do |r|
          r.post("") { r.tus_upload }
          r.is(String) { |upload_id| r.tus_upload(upload_id) }
        end
      end

      env = {
        "REQUEST_METHOD" => "PATCH",
        "PATH_INFO" => "/#{ENV.fetch("UPLOAD_ID")}",
        "SCRIPT_NAME" => "",
        "CONTENT_TYPE" => "application/offset+octet-stream",
        "CONTENT_LENGTH" => "5",
        "HTTP_TUS_RESUMABLE" => "1.0.0",
        "HTTP_UPLOAD_OFFSET" => "0",
        "rack.input" => StringIO.new("hello"),
        "rack.errors" => StringIO.new,
      }
      app.call(env)
      sleep
    RUBY

    pid = spawn(
      {
        "SPEC_DIR" => spec_dir,
        "SIGNAL_PATH" => signal,
        "UPLOAD_DIR" => @dir,
        "UPLOAD_ID" => id,
      },
      RbConfig.ruby,
      "-e",
      child_code,
      :out => File::NULL,
      :err => File::NULL
    )

    deadline = Time.now + 5
    sleep 0.01 until File.file?(signal) || Time.now > deadline
    File.file?(signal).must_equal true
    _pid, process_status = Process.wait2(pid)
    process_status.signaled?.must_equal true

    File.binread(data_file(id)).must_equal "hello"
    JSON.parse(File.binread(metadata_file(id)))["offset"].must_equal 0

    status, headers, _body = head_upload(id)
    status.must_equal 200
    response_header(headers, "Upload-Offset").must_equal "0"
    File.binread(data_file(id)).must_equal ""

    status, headers, _body = patch_upload(id, "hello", 0)
    status.must_equal 204
    response_header(headers, "Upload-Offset").must_equal "5"
    File.binread(data_file(id)).must_equal "hello"

    status, headers, _body = head_upload(id)
    status.must_equal 200
    response_header(headers, "Upload-Offset").must_equal "5"
    File.binread(data_file(id)).bytesize.must_equal 5
  end

  it "only removes expired uploads when cleanup is called explicitly" do
    tus_app(expires_in: 60)
    _, old_id = create_upload(5)
    _, new_id = create_upload(5)

    metadata = JSON.parse(File.binread(metadata_file(old_id)))
    metadata["created_at"] = Time.now.to_f - 120
    File.binwrite(metadata_file(old_id), JSON.generate(metadata))

    @app.tus_cleanup_expired.must_equal [old_id]
    File.directory?(File.join(@dir, old_id)).must_equal false
    File.directory?(File.join(@dir, new_id)).must_equal true
  end
end
