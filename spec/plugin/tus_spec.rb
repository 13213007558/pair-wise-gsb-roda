require_relative "../spec_helper"
require 'fileutils'
require 'rbconfig'
require 'tmpdir'

describe "tus plugin" do
  # rack.input replacement that can only be read once, in chunks, and
  # raises if the application tries to buffer or rewind it.
  class ReadOnceInput
    def initialize(data)
      @io = StringIO.new(data)
    end

    def read(length=nil, outbuf=nil)
      raise 'request body must be read in chunks' unless length
      @io.read(length)
    end

    def gets
      @io.gets
    end

    def each(&block)
      @io.each(&block)
    end

    def close
      @io.close
    end

    def rewind
      raise 'request body must only be read once'
    end
  end

  before do
    @dir = Dir.mktmpdir('roda-tus')
  end

  after do
    FileUtils.remove_entry(@dir) if @dir && File.exist?(@dir)
  end

  def tus_app(opts={})
    dir = @dir
    app(:bare) do
      plugin :tus, {directory: dir}.merge(opts)
      route do |r|
        r.on 'uploads' do
          r.tus
        end
      end
    end
  end

  def tus_env(method, path, headers={}, body=nil)
    env = {'REQUEST_METHOD'=>method, 'PATH_INFO'=>path, 'HTTP_TUS_RESUMABLE'=>'1.0.0'}
    headers.each{|k, v| env[k] = v}
    if body
      env['rack.input'] = body.is_a?(String) ? rack_input(body) : body
      env['CONTENT_TYPE'] ||= 'application/offset+octet-stream'
    end
    env
  end

  def tus_post(headers={})
    req(tus_env('POST', '/uploads', headers))
  end

  def tus_create(headers={'HTTP_UPLOAD_LENGTH'=>'100'})
    status, res_headers, = tus_post(headers)
    status.must_equal 201
    File.basename(res_headers['Location'])
  end

  def tus_head(id)
    req(tus_env('HEAD', "/uploads/#{id}"))
  end

  def tus_patch(id, offset, data, headers={})
    req(tus_env('PATCH', "/uploads/#{id}",
      {'HTTP_UPLOAD_OFFSET'=>offset.to_s, 'CONTENT_TYPE'=>'application/offset+octet-stream'}.merge(headers),
      data))
  end

  def data_size(id)
    File.size(File.join(@dir, id))
  end

  it "requires the :directory option" do
    proc do
      app(:bare) do
        plugin :tus
        route{}
      end
    end.must_raise Roda::RodaError
  end

  it "creates uploads with a declared length and answers HEAD" do
    tus_app
    status, headers, = tus_post('HTTP_UPLOAD_LENGTH'=>'100')
    status.must_equal 201
    headers['Tus-Resumable'].must_equal '1.0.0'
    id = File.basename(headers['Location'])
    headers['Location'].must_equal "/uploads/#{id}"
    data_size(id).must_equal 0

    status, headers, = tus_head(id)
    status.must_equal 200
    headers['Tus-Resumable'].must_equal '1.0.0'
    headers['Upload-Offset'].must_equal '0'
    headers['Upload-Length'].must_equal '100'
    headers['Cache-Control'].must_equal 'no-store'
  end

  it "rejects invalid creation requests" do
    tus_app(max_size: 50)
    tus_post[0].must_equal 400
    tus_post('HTTP_UPLOAD_LENGTH'=>'abc')[0].must_equal 400
    tus_post('HTTP_UPLOAD_DEFER_LENGTH'=>'2')[0].must_equal 400
    tus_post('HTTP_UPLOAD_LENGTH'=>'51')[0].must_equal 413
    env = tus_env('POST', '/uploads', 'HTTP_UPLOAD_LENGTH'=>'10')
    env.delete('HTTP_TUS_RESUMABLE')
    status, headers, = req(env)
    status.must_equal 412
    headers['Tus-Version'].must_equal '1.0.0'
  end

  it "answers OPTIONS with the supported tus capabilities" do
    tus_app(max_size: 50)
    status, headers, = req(tus_env('OPTIONS', '/uploads'))
    status.must_equal 204
    headers['Tus-Resumable'].must_equal '1.0.0'
    headers['Tus-Version'].must_equal '1.0.0'
    headers['Tus-Extension'].must_equal 'creation,creation-defer-length'
    headers['Tus-Max-Size'].must_equal '50'
  end

  it "returns 404 for unknown or invalid upload ids and 405 for unsupported methods" do
    tus_app
    tus_head('0'*32)[0].must_equal 404
    tus_head('../../etc/passwd')[0].must_equal 404
    id = tus_create
    req(tus_env('GET', "/uploads/#{id}"))[0].must_equal 405
    req(tus_env('GET', '/uploads'))[0].must_equal 404
  end

  it "appends PATCH bodies at the matching offset and publishes the new offset" do
    tus_app
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'10')

    status, headers, = tus_patch(id, 0, 'abcd')
    status.must_equal 204
    headers['Upload-Offset'].must_equal '4'
    headers['Tus-Resumable'].must_equal '1.0.0'

    status, headers, = tus_patch(id, 4, 'efghij')
    status.must_equal 204
    headers['Upload-Offset'].must_equal '10'

    status, headers, = tus_head(id)
    status.must_equal 200
    headers['Upload-Offset'].must_equal '10'
    headers['Upload-Offset'].to_i.must_equal data_size(id)
    File.binread(File.join(@dir, id)).must_equal 'abcdefghij'
  end

  it "rejects PATCH requests with a mismatched offset" do
    tus_app
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'10')
    tus_patch(id, 0, 'abcd')[0].must_equal 204

    tus_patch(id, 0, 'XX')[0].must_equal 409
    data_size(id).must_equal 4

    _, headers, = tus_head(id)
    headers['Upload-Offset'].must_equal '4'
    headers['Upload-Offset'].to_i.must_equal data_size(id)
  end

  it "accepts only the request matching the current offset when two requests contend" do
    tus_app
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'20')

    results = 2.times.map do
      Thread.new{tus_patch(id, 0, 'A'*10)[0]}
    end.map(&:value)
    results.sort.must_equal [204, 409]

    data_size(id).must_equal 10
    _, headers, = tus_head(id)
    headers['Upload-Offset'].must_equal '10'
    headers['Upload-Offset'].to_i.must_equal data_size(id)
  end

  it "rejects PATCH requests for completed uploads, invalid offsets, and wrong content types" do
    tus_app
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'4')
    tus_patch(id, 0, 'abcd')[0].must_equal 204
    tus_patch(id, 4, 'ef')[0].must_equal 409

    id = tus_create('HTTP_UPLOAD_LENGTH'=>'10')
    env = tus_env('PATCH', "/uploads/#{id}", 'CONTENT_TYPE'=>'application/offset+octet-stream')
    req(env)[0].must_equal 400
    env = tus_env('PATCH', "/uploads/#{id}", 'CONTENT_TYPE'=>'text/plain', 'HTTP_UPLOAD_OFFSET'=>'0')
    req(env)[0].must_equal 415
  end

  it "rejects PATCH bodies exceeding the declared length without changing the offset" do
    tus_app
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'5')
    tus_patch(id, 0, 'abcdef')[0].must_equal 413
    data_size(id).must_equal 0
    _, headers, = tus_head(id)
    headers['Upload-Offset'].must_equal '0'
  end

  it "streams the request body to disk, reading it only once in chunks" do
    tus_app(chunk_size: 4)
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'10')
    status, headers, = tus_patch(id, 0, ReadOnceInput.new('abcdefghij'))
    status.must_equal 204
    headers['Upload-Offset'].must_equal '10'
    File.binread(File.join(@dir, id)).must_equal 'abcdefghij'
  end

  it "supports deferred lengths with a one-time length confirmation" do
    tus_app(max_size: 50)
    status, headers, = tus_post('HTTP_UPLOAD_DEFER_LENGTH'=>'1')
    status.must_equal 201
    id = File.basename(headers['Location'])

    _, headers, = tus_head(id)
    headers['Upload-Defer-Length'].must_equal '1'
    headers['Upload-Length'].must_be_nil
    headers['Upload-Offset'].must_equal '0'

    status, headers, = tus_patch(id, 0, 'A'*10)
    status.must_equal 204
    headers['Upload-Offset'].must_equal '10'

    # Confirming a length above the maximum is rejected.
    tus_patch(id, 10, '', 'HTTP_UPLOAD_LENGTH'=>'51')[0].must_equal 413

    # Confirming a length below the current offset is rejected.
    tus_patch(id, 10, '', 'HTTP_UPLOAD_LENGTH'=>'5')[0].must_equal 400

    # Confirm the final length while appending data.
    status, headers, = tus_patch(id, 10, 'B'*10, 'HTTP_UPLOAD_LENGTH'=>'30')
    status.must_equal 204
    headers['Upload-Offset'].must_equal '20'

    _, headers, = tus_head(id)
    headers['Upload-Length'].must_equal '30'
    headers['Upload-Defer-Length'].must_be_nil

    # The length cannot be changed once set.
    tus_patch(id, 20, '', 'HTTP_UPLOAD_LENGTH'=>'40')[0].must_equal 400

    # Appending past the confirmed length is rejected.
    tus_patch(id, 20, 'C'*11)[0].must_equal 413
    data_size(id).must_equal 20

    tus_patch(id, 20, 'C'*10)[0].must_equal 204
    _, headers, = tus_head(id)
    headers['Upload-Offset'].must_equal '30'
    headers['Upload-Offset'].to_i.must_equal data_size(id)
    tus_patch(id, 30, '')[0].must_equal 409
  end

  it "enforces the maximum size while streaming deferred-length uploads" do
    tus_app(max_size: 50)
    id = tus_create('HTTP_UPLOAD_DEFER_LENGTH'=>'1')
    tus_patch(id, 0, 'A'*60)[0].must_equal 413
    data_size(id).must_equal 0
    _, headers, = tus_head(id)
    headers['Upload-Offset'].must_equal '0'
  end

  it "recovers to a consistent state when the process exits between data write and metadata update" do
    tus_app
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'100')
    tus_patch(id, 0, 'A'*10)[0].must_equal 204

    # Simulate a process that appended 5 bytes to the data file and
    # fsynced, but exited before publishing the new offset.
    script = "File.open(File.join(ARGV[0], ARGV[1]), 'ab'){|f| f.write('B'*5); f.fsync}; exit!(0)"
    system(RbConfig.ruby, '-e', script, @dir, id, out: File::NULL, err: File::NULL) or
      raise 'subprocess simulating crash failed'
    data_size(id).must_equal 15

    # HEAD must not report the unacknowledged bytes, and the disk state
    # is truncated back to the acknowledged offset.
    status, headers, = tus_head(id)
    status.must_equal 200
    headers['Upload-Offset'].must_equal '10'
    data_size(id).must_equal 10

    # The upload can be resumed from the recovered offset.
    tus_patch(id, 10, 'B'*5)[0].must_equal 204
    _, headers, = tus_head(id)
    headers['Upload-Offset'].must_equal '15'
    headers['Upload-Offset'].to_i.must_equal data_size(id)
  end

  it "recovers when the metadata is ahead of the data on disk" do
    tus_app
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'100')
    tus_patch(id, 0, 'A'*10)[0].must_equal 204

    # Simulate lost data: the data file is shorter than the metadata offset.
    script = "File.truncate(File.join(ARGV[0], ARGV[1]), 4); exit!(0)"
    system(RbConfig.ruby, '-e', script, @dir, id, out: File::NULL, err: File::NULL) or
      raise 'subprocess simulating data loss failed'

    _, headers, = tus_head(id)
    headers['Upload-Offset'].must_equal '4'
    headers['Upload-Offset'].to_i.must_equal data_size(id)
  end

  it "ignores leftover temporary metadata files from interrupted writes" do
    tus_app
    id = tus_create('HTTP_UPLOAD_LENGTH'=>'100')
    tus_patch(id, 0, 'A'*10)[0].must_equal 204
    File.write(File.join(@dir, "#{id}.meta.99999.tmp"), "offset 3\n")

    _, headers, = tus_head(id)
    headers['Upload-Offset'].must_equal '10'
    data_size(id).must_equal 10
  end

  it "deletes uploads only when the application explicitly expires them" do
    tus_app
    id = tus_create
    other = tus_create

    @app.tus_expire_uploads(Time.now - 3600).must_equal []
    File.exist?(File.join(@dir, id)).must_equal true

    @app.tus_expire_uploads(Time.now + 1).sort.must_equal [id, other].sort
    File.exist?(File.join(@dir, id)).must_equal false
    File.exist?(File.join(@dir, "#{id}.meta")).must_equal false
    tus_head(id)[0].must_equal 404
  end
end
