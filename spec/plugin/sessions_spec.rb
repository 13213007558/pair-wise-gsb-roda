require_relative "../spec_helper"
require_relative "../../lib/roda/plugins/_base64"

base64 = Roda::RodaPlugins::Base64_
SHARD_PROBE_OFFSET = 20

[true, false].each do |per_cookie_cipher_secret|
  describe "sessions plugin with per_cookie_cipher_secret: #{per_cookie_cipher_secret}" do 
    include CookieJar

    def req(path, opts={})
      @errors ||= StringIO.new
      super(path, opts.merge('rack.errors'=>@errors))
    end

    def errors
      @errors.rewind
      e = @errors.read.split("\n")
      @errors.rewind
      @errors.truncate(0)
      e
    end

    before do
      app(:bare) do
        plugin :sessions, :secret=>'1'*64, :per_cookie_cipher_secret=>per_cookie_cipher_secret
        route do |r|
          if r.GET['sut']
            session
            env['roda.session.updated_at'] -= r.GET['sut'].to_i if r.GET['sut']
          end
          r.get('s', String, String){|k, v| v.force_encoding('UTF-8'); session[k] = v}
          r.get('swc', String, String, String, String) do |k, v, ck, cv|
            Rack::Utils.set_cookie_header!(response.headers, ck, cv)
            v.force_encoding('UTF-8')
            session[k] = v
          end
          r.get('g',  String){|k| session[k].to_s}
          r.get('e', String){|k| session; env[k].to_a.join('-')}
          r.get('sct'){|i| session; env['roda.session.created_at'].to_s}
          r.get('ssct', Integer){|i| session; (env['roda.session.created_at'] -= i).to_s}
          r.get('ssct2', Integer, String, String){|i, k, v| session[k] = v; (env['roda.session.created_at'] -= i).to_s}
          r.get('sc'){session.clear; 'c'}
          r.get('cs', String, String){|k, v| clear_session; session[k] = v}
          r.get('cat'){t = r.session_created_at; t.strftime("%F") if t}
          r.get('uat'){t = r.session_updated_at; t.strftime("%F") if t}
          ''
        end
      end
    end

    it "requires appropriate :secret option" do
      proc{app(:bare){plugin :sessions}}.must_raise Roda::RodaError
      proc{app(:bare){plugin :sessions, :secret=>Object.new}}.must_raise Roda::RodaError
      proc{app(:bare){plugin :sessions, :secret=>'1'*63}}.must_raise Roda::RodaError
    end

    it "has session store data between requests" do
      req('/').must_equal [200, {RodaResponseHeaders::CONTENT_TYPE=>"text/html", RodaResponseHeaders::CONTENT_LENGTH=>"0"}, [""]]
      body('/s/foo/bar').must_equal 'bar'
      body('/g/foo').must_equal 'bar'

      body('/s/foo/baz').must_equal 'baz'
      body('/g/foo').must_equal 'baz'

      body("/s/foo/\u1234".b).must_equal "\u1234"
      body("/g/foo").must_equal "\u1234"

      errors.must_equal []
    end

    it "supports :env_key for the env key to use for the session" do
      body('/s/foo/bar').must_equal 'bar'
      body('/e/rack.session').must_equal 'foo-bar'
      body('/e/roda.session').must_equal ''
      @app.plugin(:sessions, :env_key=>'roda.session')
      body('/e/rack.session').must_equal ''
      body('/e/roda.session').must_equal 'foo-bar'
      body('/s/foo/baz').must_equal 'baz'
      body('/e/roda.session').must_equal 'foo-baz'
    end

    it "supports loading sessions created when per_cookie_cipher_secret: #{!per_cookie_cipher_secret} " do
      req('/').must_equal [200, {RodaResponseHeaders::CONTENT_TYPE=>"text/html", RodaResponseHeaders::CONTENT_LENGTH=>"0"}, [""]]
      body('/s/foo/bar').must_equal 'bar'
      body('/g/foo').must_equal 'bar'

      app.plugin :sessions, :per_cookie_cipher_secret=>!per_cookie_cipher_secret

      body('/s/foo/baz').must_equal 'baz'
      body('/g/foo').must_equal 'baz'

      errors.must_equal []
    end

    it "allows accessing session creation and last update times" do
      status('/cat').must_equal 404
      status('/uat').must_equal 404
      status('/s/foo/bar').must_equal 200
      body('/cat').must_equal Date.today.strftime("%F")
      body('/uat').must_equal Date.today.strftime("%F")
      status('/ssct2/172800/bar/baz').must_equal 200
      body('/cat').must_equal((Date.today - 2).strftime("%F"))
    end

    it "does not add Set-Cookie header if session does not change, unless outside :skip_within seconds" do
      req('/').must_equal [200, {RodaResponseHeaders::CONTENT_TYPE=>"text/html", RodaResponseHeaders::CONTENT_LENGTH=>"0"}, [""]]
      _, h, b = req('/s/foo/bar')
      h[RodaResponseHeaders::SET_COOKIE].must_match(/\Aroda.session/)
      b.must_equal ["bar"]
      req('/g/foo').must_equal [200, {RodaResponseHeaders::CONTENT_TYPE=>"text/html", RodaResponseHeaders::CONTENT_LENGTH=>"3"}, ["bar"]]
      req('/s/foo/bar').must_equal [200, {RodaResponseHeaders::CONTENT_TYPE=>"text/html", RodaResponseHeaders::CONTENT_LENGTH=>"3"}, ["bar"]]

      _, h, b = req('/s/foo/baz')
      h[RodaResponseHeaders::SET_COOKIE].must_match(/\Aroda.session/)
      b.must_equal ["baz"]
      req('/g/foo').must_equal [200, {RodaResponseHeaders::CONTENT_TYPE=>"text/html", RodaResponseHeaders::CONTENT_LENGTH=>"3"}, ["baz"]]

      req('/g/foo', 'QUERY_STRING'=>'sut=3500').must_equal [200, {RodaResponseHeaders::CONTENT_TYPE=>"text/html", RodaResponseHeaders::CONTENT_LENGTH=>"3"}, ["baz"]]
      _, h, b = req('/g/foo', 'QUERY_STRING'=>'sut=3700')
      h[RodaResponseHeaders::SET_COOKIE].must_match(/\Aroda.session/)
      b.must_equal ["baz"]

      @app.plugin(:sessions, :skip_within=>3800)
      req('/g/foo', 'QUERY_STRING'=>'sut=3700').must_equal [200, {RodaResponseHeaders::CONTENT_TYPE=>"text/html", RodaResponseHeaders::CONTENT_LENGTH=>"3"}, ["baz"]]
      _, h, b = req('/g/foo', 'QUERY_STRING'=>'sut=3900')
      h[RodaResponseHeaders::SET_COOKIE].must_match(/\Aroda.session/)
      b.must_equal ["baz"]

      errors.must_equal []
    end

    it "removes session cookie when session is submitted but empty after request" do
      body('/s/foo/bar').must_equal 'bar'
      body('/sct').to_i
      body('/g/foo').must_equal 'bar'

      _, h, b = req('/sc')

      # Parameters can come in any order, and only the final parameter may omit the ;
      ['roda.session=', 'max-age=0', 'path=/'].each do |param|
        h[RodaResponseHeaders::SET_COOKIE].must_match(/#{Regexp.escape(param)}(;|\z)/)
      end
      h[RodaResponseHeaders::SET_COOKIE].must_match(/expires=Thu, 01 Jan 1970 00:00:00 (-0000|GMT)(;|\z)/)

      b.must_equal ['c']

      errors.must_equal []
    end

    it "removes session cookie even when max-age and expires are in cookie options" do
      app.plugin :sessions, :cookie_options=>{:max_age=>'1000', :expires=>Time.now+1000}
      body('/s/foo/bar').must_equal 'bar'
      body('/sct').to_i
      body('/g/foo').must_equal 'bar'

      _, h, b = req('/sc')

      # Parameters can come in any order, and only the final parameter may omit the ;
      ['roda.session=', 'max-age=0', 'path=/'].each do |param|
        h[RodaResponseHeaders::SET_COOKIE].must_match(/#{Regexp.escape(param)}(;|\z)/)
      end
      h[RodaResponseHeaders::SET_COOKIE].must_match(/expires=Thu, 01 Jan 1970 00:00:00 (-0000|GMT)(;|\z)/)

      b.must_equal ['c']

      errors.must_equal []
    end

    it "sets new session create time when clear_session is called even when session is not empty when serializing" do
      body('/s/foo/bar').must_equal 'bar'
      sct = body('/sct').to_i
      body('/g/foo').must_equal 'bar'
      body('/sct').to_i.must_equal sct
      body('/ssct/10').to_i.must_equal(sct - 10)

      body('/cs/foo/baz').must_equal 'baz'
      body('/sct').to_i.must_be :>=, sct

      errors.must_equal []
    end

    it "should include HttpOnly and secure cookie options appropriately" do
      h = header(RodaResponseHeaders::SET_COOKIE, '/s/foo/bar')
      h.must_match(/; HttpOnly/i)
      h.wont_include('; secure')

      h = header(RodaResponseHeaders::SET_COOKIE, '/s/foo/baz', 'HTTPS'=>'on')
      h.must_match(/; HttpOnly/i)
      h.must_include('; secure')

      @app.plugin(:sessions, :cookie_options=>{})
      h = header(RodaResponseHeaders::SET_COOKIE, '/s/foo/bar')
      h.must_match(/; HttpOnly/i)
      h.wont_include('; secure')
    end

    it "should merge :cookie_options options into the default cookie options" do
      @app.plugin(:sessions, :cookie_options=>{:secure=>true})
      h = header(RodaResponseHeaders::SET_COOKIE, '/s/foo/bar')
      h.must_match(/; HttpOnly/i)
      h.must_include('; path=/')
      h.must_include('; secure')
    end

    it "handles secret rotation using :old_secret option" do
      body('/s/foo/bar').must_equal 'bar'
      body('/g/foo').must_equal 'bar'

      old_cookie = @cookie
      @app.plugin(:sessions, :secret=>'2'*64, :old_secret=>'1'*64)
      body('/g/foo', 'QUERY_STRING'=>'sut=3700').must_equal 'bar'

      @app.plugin(:sessions, :secret=>'2'*64, :old_secret=>nil)
      body('/g/foo', 'QUERY_STRING'=>'sut=3700').must_equal 'bar'

      @cookie = old_cookie
      body('/g/foo').must_equal ''
      errors.must_equal ["Not decoding session: HMAC invalid"]

      proc{app(:bare){plugin :sessions, :old_secret=>'1'*63}}.must_raise Roda::RodaError
      proc{app(:bare){plugin :sessions, :old_secret=>Object.new}}.must_raise Roda::RodaError
    end

    it "handles secret rotation using :old_secret option when also changing :per_cookie_cipher_secret option" do
      body('/s/foo/bar').must_equal 'bar'
      body('/g/foo').must_equal 'bar'

      old_cookie = @cookie
      @app.plugin(:sessions, :secret=>'2'*64, :old_secret=>'1'*64, :per_cookie_cipher_secret=>!per_cookie_cipher_secret)

      body('/g/foo', 'QUERY_STRING'=>'sut=3700').must_equal 'bar'

      @app.plugin(:sessions, :secret=>'2'*64, :old_secret=>nil)
      body('/g/foo', 'QUERY_STRING'=>'sut=3700').must_equal 'bar'

      @cookie = old_cookie
      body('/g/foo').must_equal ''
      errors.must_equal ["Not decoding session: HMAC invalid"]

      proc{app(:bare){plugin :sessions, :old_secret=>'1'*63}}.must_raise Roda::RodaError
      proc{app(:bare){plugin :sessions, :old_secret=>Object.new}}.must_raise Roda::RodaError
    end

    it "pads data by default to make it more difficult to guess session contents based on size" do
      long = "bar"*35

      _, h1, b = req('/s/foo/bar')
      b.must_equal ['bar']
      _, h2, b = req('/s/foo/bar', 'QUERY_STRING'=>'sut=3700')
      b.must_equal ['bar']
      _, h3, b = req('/s/foo/bar2')
      b.must_equal ['bar2']
      _, h4, b = req("/s/foo/#{long}")
      b.must_equal [long]
      h1[RodaResponseHeaders::SET_COOKIE].length.must_equal h2[RodaResponseHeaders::SET_COOKIE].length
      h1[RodaResponseHeaders::SET_COOKIE].wont_equal h2[RodaResponseHeaders::SET_COOKIE]
      h1[RodaResponseHeaders::SET_COOKIE].length.must_equal h3[RodaResponseHeaders::SET_COOKIE].length
      h1[RodaResponseHeaders::SET_COOKIE].wont_equal h3[RodaResponseHeaders::SET_COOKIE]
      h1[RodaResponseHeaders::SET_COOKIE].length.wont_equal h4[RodaResponseHeaders::SET_COOKIE].length

      @app.plugin(:sessions, :pad_size=>256)

      _, h1, b = req('/s/foo/bar')
      b.must_equal ['bar']
      _, h2, b = req('/s/foo/bar', 'QUERY_STRING'=>'sut=3700')
      b.must_equal ['bar']
      _, h3, b = req('/s/foo/bar2')
      b.must_equal ['bar2']
      _, h4, b = req("/s/foo/#{long}")
      b.must_equal [long]
      h1[RodaResponseHeaders::SET_COOKIE].length.must_equal h2[RodaResponseHeaders::SET_COOKIE].length
      h1[RodaResponseHeaders::SET_COOKIE].wont_equal h2[RodaResponseHeaders::SET_COOKIE]
      h1[RodaResponseHeaders::SET_COOKIE].length.must_equal h3[RodaResponseHeaders::SET_COOKIE].length
      h1[RodaResponseHeaders::SET_COOKIE].wont_equal h3[RodaResponseHeaders::SET_COOKIE]
      h1[RodaResponseHeaders::SET_COOKIE].length.must_equal h4[RodaResponseHeaders::SET_COOKIE].length
      h1[RodaResponseHeaders::SET_COOKIE].wont_equal h4[RodaResponseHeaders::SET_COOKIE]

      @app.plugin(:sessions, :pad_size=>nil)

      _, h1, b = req('/s/foo/bar')
      b.must_equal ['bar']
      _, h2, b = req('/s/foo/bar', 'QUERY_STRING'=>'sut=3700')
      b.must_equal ['bar']
      _, h3, b = req('/s/foo/bar2')
      b.must_equal ['bar2']
      h1[RodaResponseHeaders::SET_COOKIE].length.must_equal h2[RodaResponseHeaders::SET_COOKIE].length
      h1[RodaResponseHeaders::SET_COOKIE].wont_equal h2[RodaResponseHeaders::SET_COOKIE]
      if !defined?(JRUBY_VERSION) || JRUBY_VERSION.to_r >= Rational('9.2')
        h1[RodaResponseHeaders::SET_COOKIE].length.wont_equal h3[RodaResponseHeaders::SET_COOKIE].length
      end

      proc{@app.plugin(:sessions, :pad_size=>0)}.must_raise Roda::RodaError
      proc{@app.plugin(:sessions, :pad_size=>1)}.must_raise Roda::RodaError
      proc{@app.plugin(:sessions, :pad_size=>Object.new)}.must_raise Roda::RodaError

      errors.must_equal []
    end

    deprecated "compresses data over a certain size by default" do
      long = 'b'*8192
      proc{body("/s/foo/#{long}")}.must_raise Roda::RodaPlugins::Sessions::CookieTooLarge

      @app.plugin(:sessions, :gzip_over=>8000)
      body("/s/foo/#{long}").must_equal long
      body("/g/foo", 'QUERY_STRING'=>'sut=3700').must_equal long

      @app.plugin(:sessions, :gzip_over=>15000)
      proc{body("/g/foo", 'QUERY_STRING'=>'sut=3700')}.must_raise Roda::RodaPlugins::Sessions::CookieTooLarge

      errors.must_equal []
    end

    it "raises CookieTooLarge if cookie value is too large" do
      @app.plugin(:sessions, :pad_size=>nil)
      bytes = 1502
      bytes -= 16 if per_cookie_cipher_secret
      # Results in 4100 byte cookie value, fails earlier
      proc{req("/s/foo/#{SecureRandom.hex(bytes)}")}.must_raise Roda::RodaPlugins::Sessions::CookieTooLarge
    end

    it "raises CookieTooLarge if cookie value is too large" do
      @app.plugin(:sessions, :pad_size=>nil)
      bytes = 1500
      bytes -= 16 if per_cookie_cipher_secret
      # Results in 4092 byte cookie value, but browser 4K limit includes
      # cookie name and attributes, fails later
      proc{req("/s/foo/#{SecureRandom.hex(bytes)}")}.must_raise Roda::RodaPlugins::Sessions::CookieTooLarge
    end

    it "handles large cookies that are under 4K limit" do
      @app.plugin(:sessions, :pad_size=>nil)
      bytes = 1481
      bytes -= 16 if per_cookie_cipher_secret
      cookie_size = Array(header(RodaResponseHeaders::SET_COOKIE, "/s/foo/#{SecureRandom.hex(bytes)}")).join.bytesize
      cookie_size.must_be :>, (Rack.release < "2" ? 4078 : 4090)
      cookie_size.must_be :<=, 4096
    end

    it "applies 4K limit to single cookie and not multiple cookies" do
      @app.plugin(:sessions, :pad_size=>nil)
      bytes = 1481
      bytes -= 16 if per_cookie_cipher_secret
      cookie_size = Array(header(RodaResponseHeaders::SET_COOKIE, "/swc/foo/#{SecureRandom.hex(bytes)}/bar/#{"1"*2000}")).join.bytesize
      cookie_size.must_be :>, (Rack.release < "2" ? 6078 : 6090)
      cookie_size.must_be :<=, 6112
    end

    it "ignores session cookies if session exceeds max time since create" do
      body("/s/foo/bar").must_equal 'bar'
      body("/g/foo").must_equal 'bar'

      @app.plugin(:sessions, :max_seconds=>-1)
      body("/g/foo").must_equal ''
      errors.must_equal ["Not returning session: maximum session time expired"]

      @app.plugin(:sessions, :max_seconds=>10)
      body("/s/foo/bar").must_equal 'bar'
      body("/g/foo").must_equal 'bar'

      errors.must_equal []
    end

    it "ignores session cookies if session exceeds max idle time since update" do
      body("/s/foo/bar").must_equal 'bar'
      body("/g/foo").must_equal 'bar'

      @app.plugin(:sessions, :max_idle_seconds=>-1)
      body("/g/foo").must_equal ''
      errors.must_equal ["Not returning session: maximum session idle time expired"]

      @app.plugin(:sessions, :max_idle_seconds=>10)
      body("/s/foo/bar").must_equal 'bar'
      body("/g/foo").must_equal 'bar'

      errors.must_equal []
    end

    it "supports :serializer and :parser options to override serializer/deserializer" do
      body('/s/foo/bar').must_equal 'bar'

      @app.plugin(:sessions, :parser=>proc{|s| JSON.parse("{#{s[1...-1].reverse}}")})
      body('/g/rab').must_equal 'oof'

      @app.plugin(:sessions, :serializer=>proc{|s| s.to_json.upcase})

      body('/s/foo/baz').must_equal 'baz'
      body('/g/ZAB').must_equal 'OOF'

      errors.must_equal []
    end

    it "logs session decoding errors to rack.errors" do
      body('/s/foo/bar').must_equal 'bar'
      c = @cookie.dup
      k = c.split('=', 2)[0] + '='

      @cookie[20] = '!'
      body('/g/foo').must_equal ''
      errors.must_equal ["Unable to decode session: invalid base64"]

      @cookie = k+base64.urlsafe_encode64('')
      body('/g/foo').must_equal ''
      errors.must_equal ["Unable to decode session: no data"]

      @cookie = k+base64.urlsafe_encode64("\0" * 60)
      body('/g/foo').must_equal ''
      errors.must_equal ["Unable to decode session: data too short"]

      @cookie = k+base64.urlsafe_encode64("\1" * 92)
      body('/g/foo').must_equal ''
      errors.must_equal ["Unable to decode session: data too short"]

      @cookie = k+base64.urlsafe_encode64('1'*75)
      body('/g/foo').must_equal ''
      errors.must_equal ["Unable to decode session: version marker unsupported"]

      @cookie = k+base64.urlsafe_encode64("\0"*75)
      body('/g/foo').must_equal ''
      errors.must_equal ["Not decoding session: HMAC invalid"]
    end
  end

  describe "sessions plugin" do 
    include CookieJar

    def req(path, opts={})
      @errors ||= StringIO.new
      super(path, opts.merge('rack.errors'=>@errors))
    end

    def errors
      @errors.rewind
      e = @errors.read.split("\n")
      @errors.rewind
      @errors.truncate(0)
      e
    end

    deprecated "supports transparent upgrade from Rack::Session::Cookie with default HMAC and coder" do
      app(:bare) do
        use Rack::Session::Cookie, :secret=>'1'
        plugin :middleware_stack
        route do |r|
          r.get('s', String, String){|k, v| session[k] = {:a=>v}; v}
          r.get('g',  String){|k| session[k].inspect}
          ''
        end
      end

      _, h, b = req('/s/foo/bar')
      (h[RodaResponseHeaders::SET_COOKIE] =~ /\A(rack\.session=.*); path=\/; HttpOnly\z/i).must_equal 0
      c = $1
      b.must_equal ['bar']
      _, h, b = req('/g/foo')
      h[RodaResponseHeaders::SET_COOKIE].must_be_nil
      [['{:a=>"bar"}'], ['{a: "bar"}']].must_include b

      @app.plugin :sessions, :secret=>'1'*64,
                  :upgrade_from_rack_session_cookie_secret=>'1'
      @app.middleware_stack.remove{|m, *| m == Rack::Session::Cookie}

      @cookie = c.dup
      @cookie.slice!(15)
      body('/g/foo').must_equal 'nil'
      errors.must_equal ["Not decoding Rack::Session::Cookie session: HMAC invalid"]

      @cookie = c.split('--', 2)[0]
      body('/g/foo').must_equal 'nil'
      errors.must_equal ["Not decoding Rack::Session::Cookie session: invalid format"]

      @cookie = c.split('--', 2)[0][13..-1]
      @cookie = Rack::Utils.unescape(@cookie).unpack('m')[0]
      @cookie[2] = "^"
      @cookie = [@cookie].pack('m')
      cookie = String.new
      cookie << 'rack.session=' << @cookie << '--' << OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, '1', @cookie)
      @cookie = cookie
      body('/g/foo').must_equal 'nil'
      errors.must_equal ["Error decoding Rack::Session::Cookie session: not base64 encoded marshal dump"]

      @cookie = c
      _, h, b = req('/g/foo')
      h[RodaResponseHeaders::SET_COOKIE].must_match(/\Aroda\.session=(.*); path=\/; HttpOnly(; SameSite=Lax)?\nrack\.session=; path=\/; max-age=0; expires=Thu, 01 Jan 1970 00:00:00/mi)
      [['{"a"=>"bar"}'], ['{"a" => "bar"}']].must_include b

      @app.plugin :sessions, :cookie_options=>{:path=>'/foo'}, :upgrade_from_rack_session_cookie_options=>{}
      @cookie = c
      _, h, b = req('/g/foo')
      h[RodaResponseHeaders::SET_COOKIE].must_match(/\Aroda\.session=(.*); path=\/foo; HttpOnly(; SameSite=Lax)?\nrack\.session=; path=\/foo; max-age=0; expires=Thu, 01 Jan 1970 00:00:00/mi)
      [['{"a"=>"bar"}'], ['{"a" => "bar"}']].must_include b

      @app.plugin :sessions, :upgrade_from_rack_session_cookie_options=>{:path=>'/baz'}
      @cookie = c
      _, h, b = req('/g/foo')
      h[RodaResponseHeaders::SET_COOKIE].must_match(/\Aroda\.session=(.*); path=\/foo; HttpOnly(; SameSite=Lax)?\nrack\.session=; path=\/baz; max-age=0; expires=Thu, 01 Jan 1970 00:00:00/mi)
      [['{"a"=>"bar"}'], ['{"a" => "bar"}']].must_include b

      @app.plugin :sessions, :upgrade_from_rack_session_cookie_key=>'quux.session'
      @cookie = c.sub(/\Arack/, 'quux')
      _, h, b = req('/g/foo')
      h[RodaResponseHeaders::SET_COOKIE].must_match(/\Aroda\.session=(.*); path=\/foo; HttpOnly(; SameSite=Lax)?\nquux\.session=; path=\/baz; max-age=0; expires=Thu, 01 Jan 1970 00:00:00/mi)
      [['{"a"=>"bar"}'], ['{"a" => "bar"}']].must_include b
    end
  end if Rack.release < '2.3'

  describe "sessions plugin with :split_cookies" do
    include CookieJar

    def _req(app, env)
      env['HTTP_COOKIE'] = jar_header unless jar_header.empty?
      a = super
      sync_cookie_jar(a[1])
      @last_headers = a[1]
      a
    end

    def last_set_cookie_lines(headers=nil)
      Array((headers || @last_headers)[RodaResponseHeaders::SET_COOKIE]).flat_map{|h| h.split("\n")}
    end

    def req(path, opts={})
      @errors ||= StringIO.new
      super(path, opts.merge('rack.errors'=>@errors))
    end

    def errors
      @errors.rewind
      e = @errors.read.split("\n")
      @errors.rewind
      @errors.truncate(0)
      e
    end

    # Parse Set-Cookie response headers into set cookies and expired cookie names.
    def sync_cookie_jar(headers)
      @jar ||= {}
      Array(headers[RodaResponseHeaders::SET_COOKIE]).flat_map{|h| h.split("\n")}.each do |cookie|
        name, rest = cookie.split('=', 2)
        _, attrs = rest.split(';', 2)
        if attrs && attrs =~ /max-age=0/i
          @jar.delete(name)
        else
          @jar[name] = rest.split(';', 2).first
        end
      end
    end

    def jar_header
      @jar.map{|name, value| "#{name}=#{value}"}.join('; ')
    end

    before do
      @jar = {}
      app(:bare) do
        plugin :sessions, :secret=>'1'*64, :split_cookies=>true, :pad_size=>nil
        route do |r|
          r.get('s', String, String){|k, v| v.force_encoding('UTF-8'); session[k] = v}
          r.get('g', String){|k| session[k].to_s}
          r.get('sc'){session.clear; 'c'}
          r.get('cs', String, String){|k, v| clear_session; session[k] = v}
          r.get('len'){session['foo'].to_s.bytesize.to_s}
          ''
        end
      end
    end

    # Find a value length that results in exactly the given number of shard cookies.
    def value_length_for_shard_count(count)
      probe = Class.new(Roda) do
        plugin :sessions, :secret=>'1'*64, :split_cookies=>true, :pad_size=>nil
        route do |r|
          r.get('s', String, String){|k, v| v.force_encoding('BINARY'); session[k] = v}
        end
      end

      low = 1
      high = 10000
      loop do
        env = req_env('PATH_INFO'=>"/s/foo/#{'a'*high}")
        _, headers, _ = probe.call(env)
        lines = Array(headers[RodaResponseHeaders::SET_COOKIE]).flat_map{|h| h.split("\n")}
        names = lines.map{|l| l.split('=', 2).first}
        break if names.size >= count
        low = high
        high *= 2
      end

      while low < high
        mid = (low + high) / 2
        env = req_env('PATH_INFO'=>"/s/foo/#{'a'*mid}")
        _, headers, _ = probe.call(env)
        lines = Array(headers[RodaResponseHeaders::SET_COOKIE]).flat_map{|h| h.split("\n")}
        names = lines.map{|l| l.split('=', 2).first}
        if names.size < count
          low = mid + 1
        else
          high = mid
        end
      end

      # high is the first length producing at least count; scan forward a
      # little to get a length safely in the middle of the count-shard range.
      length = high
      loop do
        env = req_env('PATH_INFO'=>"/s/foo/#{'a'*(length + 200)}")
        _, headers, _ = probe.call(env)
        names = Array(headers[RodaResponseHeaders::SET_COOKIE]).flat_map{|h| h.split("\n")}.map{|l| l.split('=', 2).first}
        break if names.size != count
        length += 200
      end
      length
    end

    it "validates :max_cookie_chunks and :max_session_size options" do
      proc{app(:bare){plugin :sessions, :secret=>'1'*64, :split_cookies=>true, :max_cookie_chunks=>1}}.must_raise Roda::RodaError
      proc{app(:bare){plugin :sessions, :secret=>'1'*64, :split_cookies=>true, :max_cookie_chunks=>256}}.must_raise Roda::RodaError
      proc{app(:bare){plugin :sessions, :secret=>'1'*64, :split_cookies=>true, :max_cookie_chunks=>'3'}}.must_raise Roda::RodaError
      proc{app(:bare){plugin :sessions, :secret=>'1'*64, :split_cookies=>true, :max_session_size=>0}}.must_raise Roda::RodaError
      proc{app(:bare){plugin :sessions, :secret=>'1'*64, :split_cookies=>true, :max_session_size=>'100'}}.must_raise Roda::RodaError
    end

    it "stores large sessions across multiple cookies and small sessions in a single cookie" do
      _, headers, body = req('/s/foo/bar')
      body.must_equal ['bar']
      lines = last_set_cookie_lines(headers)
      lines.size.must_equal 1
      lines.first.must_match(/\Aroda\.session=/)
      body('/g/foo').must_equal 'bar'
      errors.must_equal []

      two = value_length_for_shard_count(2)
      _, headers, body = req("/s/foo/#{'a' * two}")
      lines = last_set_cookie_lines(headers)
      lines = lines.reject{|l| l =~ /max-age=0/i}
      names = lines.map{|l| l.split('=', 2).first}.sort
      names.must_equal ['roda.session.0', 'roda.session.1']
      lines.each{|line| line.bytesize.must_be :<, 4096}
      body('/len').must_equal two.to_s
      errors.must_equal []
    end

    it "uses the same cookie options for every shard and each shard stays under 4096 bytes" do
      @app.plugin(:sessions, :cookie_options=>{:domain=>'example.com', :same_site=>:strict})
      length = value_length_for_shard_count(3)
      _, headers, _ = req("/s/foo/#{'b'*length}")
      lines = last_set_cookie_lines(headers)
      lines.size.must_be :>=, 3
      lines.each do |line|
        line.must_match(/domain=example\.com/i)
        line.must_match(/samesite=strict/i)
        line.must_match(/path=\//i)
        line.must_match(/httponly/i)
        line.bytesize.must_be :<, 4096
      end
      lines.map{|l| l.split(';', 2).last}.uniq.size.must_equal 1
    end

    it "keeps supporting existing single-cookie sessions" do
      single = Class.new(Roda) do
        plugin :sessions, :secret=>'1'*64
        route do |r|
          r.get('s', String, String){|k, v| session[k] = v}
          r.get('g', String){|k| session[k].to_s}
        end
      end

      env = req_env('PATH_INFO'=>'/s/foo/bar')
      _, headers, _ = single.call(env)
      line = Array(headers[RodaResponseHeaders::SET_COOKIE]).flat_map{|h| h.split("\n")}.first
      @jar = {}
      name, rest = line.split('=', 2)
      @jar[name] = rest.split(';', 2).first

      body('/g/foo').must_equal 'bar'
      errors.must_equal []
    end

    it "expires an old single-cookie value when submitted alongside valid shards" do
      # First create a valid shard set in the normal jar.
      length = value_length_for_shard_count(2)
      req("/s/foo/#{'p'*length}")
      shard_jar = @jar.dup

      # Also create a legacy single cookie with a different app using the same key.
      single = Class.new(Roda) do
        plugin :sessions, :secret=>'1'*64
        route do |r|
          r.get('s', String, String){|k, v| session[k] = v}
        end
      end
      env = req_env('PATH_INFO'=>'/s/old/value')
      _, headers, _ = single.call(env)
      line = Array(headers[RodaResponseHeaders::SET_COOKIE]).flat_map{|h| h.split("\n")}.first
      name, rest = line.split('=', 2)
      shard_jar[name] = rest.split(';', 2).first

      @jar = shard_jar
      _, headers, _ = req('/s/foo/bar')
      lines = last_set_cookie_lines(headers)
      # Shards win on read; the rewrite is a single small cookie replacing the
      # legacy base value, and the leftover shard cookies are expired.
      written = lines.reject{|l| l =~ /max-age=0/i}.map{|l| l.split('=', 2).first}
      expired = lines.select{|l| l =~ /max-age=0/i}.map{|l| l.split('=', 2).first}
      written.must_equal ['roda.session']
      expired.sort.must_equal ['roda.session.0', 'roda.session.1']
      body('/g/foo').must_equal 'bar'
    end

    it "expires a legacy base cookie when valid shards are submitted and the session is cleared" do
      length = value_length_for_shard_count(2)
      req("/s/foo/#{'p'*length}")
      shard_jar = @jar.dup
      @jar['roda.session'] = 'legacy'

      _, headers, _ = req('/sc')
      lines = last_set_cookie_lines(headers)
      expired = lines.map{|l| l.split('=', 2).first}.sort
      expired.must_equal ['roda.session', 'roda.session.0', 'roda.session.1']
    end

    it "does not accept a shard set missing a shard, and cleans up the leftover shards on the next write" do
      length = value_length_for_shard_count(2)
      req("/s/foo/#{'c'*length}")
      @jar.delete('roda.session.1')

      body('/g/foo').must_equal ''
      errors.must_equal ["Not decoding session: expected 2 session shards, received 1"]

      _, headers, body = req('/s/bar/value')
      lines = last_set_cookie_lines(headers)
      expired = lines.select{|l| l =~ /max-age=0/i}.map{|l| l.split('=', 2).first}
      expired.must_include 'roda.session.0'
      body.must_equal ['value']
      body('/g/bar').must_equal 'value'
    end

    it "does not accept duplicate shard numbers" do
      length = value_length_for_shard_count(3)
      req("/s/foo/#{'d'*length}")
      @jar['roda.session.2'] = @jar['roda.session.1']

      body('/g/foo').must_equal ''
      errors.first.must_include 'does not match cookie name index'
    end

    it "does not accept shards mixed from different writes" do
      length = value_length_for_shard_count(2)
      req("/s/foo/#{'e'*length}")
      first = @jar.dup
      req("/s/foo/#{'f'*length}")
      @jar['roda.session.1'] = first['roda.session.1']

      body('/g/foo').must_equal ''
      errors.first.must_include 'different writes'
    end

    it "rejects shards that do not form an intact, HMAC-valid session" do
      length = value_length_for_shard_count(2)
      req("/s/foo/#{'g'*length}")
      value = @jar['roda.session.0']
      shard = Roda::RodaPlugins::Base64_.urlsafe_decode64(value)
      # Flip a byte in the shard data portion (after the 11 byte shard header)
      shard.setbyte(SHARD_PROBE_OFFSET, shard.getbyte(SHARD_PROBE_OFFSET) ^ 0xff)
      @jar['roda.session.0'] = Roda::RodaPlugins::Base64_.urlsafe_encode64(shard)

      body('/g/foo').must_equal ''
      errors.first.must_include 'HMAC invalid'
    end

    it "expires extra shards when shrinking from five shards to two" do
      five = value_length_for_shard_count(5)
      _, headers, _ = req("/s/foo/#{'h'*five}")
      five_lines = last_set_cookie_lines(headers)
      five_lines.size.must_equal 5
      old_names = five_lines.map{|l| l.split('=', 2).first}.sort
      old_names.must_equal (0...5).map{|i| "roda.session.#{i}"}
      body('/len').must_equal five.to_s

      two = value_length_for_shard_count(2)
      old_jar = @jar.dup
      _, headers, _ = req("/s/foo/#{'i'*two}")
      lines = last_set_cookie_lines(headers)
      set = lines.reject{|l| l =~ /max-age=0/i}
      expired = lines.select{|l| l =~ /max-age=0/i}.map{|l| l.split('=', 2).first}.sort
      set_names = set.map{|l| l.split('=', 2).first}.sort
      set_names.must_equal ['roda.session.0', 'roda.session.1']
      expired.must_equal ['roda.session.2', 'roda.session.3', 'roda.session.4']
      set.each{|l| l.bytesize.must_be :<, 4096}

      # Update the jar to the post-shrink response first.
      sync_cookie_jar(headers)
      new_jar = @jar.dup

      # The stale shards alone cannot restore a partial session.
      @jar = old_jar.select{|name, _| ['roda.session.2', 'roda.session.3', 'roda.session.4'].include?(name)}
      body('/g/foo').must_equal ''
      errors.wont_be :empty?

      # The new two-shard session is intact.
      @jar = new_jar
      body('/len').must_equal two.to_s
      errors.must_equal []
    end

    it "expires all shards when the session is cleared with clear_session or session.clear" do
      length = value_length_for_shard_count(3)
      req("/s/foo/#{'j'*length}")
      @jar.keys.size.must_equal 3

      _, headers, _ = req('/sc')
      lines = last_set_cookie_lines(headers)
      expired = lines.map{|l| l.split('=', 2).first}.sort
      expired.must_equal ['roda.session.0', 'roda.session.1', 'roda.session.2']
      @jar.must_equal({})

      req("/s/foo/#{'k'*length}")
      _, headers, _ = req('/cs/bar/baz')
      lines = last_set_cookie_lines(headers)
      expired = lines.select{|l| l =~ /max-age=0/i}.map{|l| l.split('=', 2).first}.sort
      expired.must_equal ['roda.session.0', 'roda.session.1', 'roda.session.2']
    end

    it "expires submitted shards when the session has expired" do
      length = value_length_for_shard_count(2)
      req("/s/foo/#{'l'*length}")
      @app.plugin(:sessions, :max_idle_seconds=>-1)

      _, headers, _ = req('/g/foo')
      lines = last_set_cookie_lines(headers)
      expired = lines.map{|l| l.split('=', 2).first}.sort
      expired.must_equal ['roda.session.0', 'roda.session.1']
      errors.must_equal ["Not returning session: maximum session idle time expired"]
    end

    it "raises CookieTooLarge when exceeding the chunk or total size limits" do
      @app.plugin(:sessions, :max_cookie_chunks=>2)
      proc{req("/s/foo/#{'m'*12000}")}.must_raise Roda::RodaPlugins::Sessions::CookieTooLarge

      app(:bare) do
        plugin :sessions, :secret=>'1'*64, :split_cookies=>true, :pad_size=>nil, :max_session_size=>1000
        route do |r|
          r.get('s', String, String){|k, v| session[k] = v}
        end
      end
      proc{req("/s/foo/#{'n'*6000}")}.must_raise Roda::RodaPlugins::Sessions::CookieTooLarge
    end
  end
end
