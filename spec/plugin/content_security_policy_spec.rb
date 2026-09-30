require_relative "../spec_helper"

describe "content_security_policy plugin" do 
  it "does not add header if no options are set" do
    app(:content_security_policy){|_| 'a'}
    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/a").must_be_nil
  end

  it "sets Content-Security-Policy header" do
    app(:bare) do
      plugin :content_security_policy do |csp|
        csp.default_src :self
        csp.img_src :self, 'example.com'
        csp.style_src [:sha256, 'abc']
      end

      route do |r|
        r.get 'ro' do
          content_security_policy.report_only
          ''
        end

        r.get 'nro' do
          content_security_policy.report_only
          content_security_policy.report_only(false)
          content_security_policy.report_only?.inspect
        end

        r.get 'get' do
          content_security_policy.get_default_src.inspect
        end

        r.get 'add' do
          content_security_policy.add_default_src('foo.com', 'bar.com')
          ''
        end

        r.get 'empty' do
          content_security_policy.add_default_src
          ''
        end

        r.get 'set' do
          content_security_policy.default_src('foo.com', 'bar.com')
          ''
        end

        r.get 'bool' do
          content_security_policy.block_all_mixed_content
          content_security_policy.upgrade_insecure_requests(false)
          content_security_policy.block_all_mixed_content?.inspect
        end

        r.get 'block' do
          content_security_policy do |csp|
            csp.block_all_mixed_content
            csp.add_default_src('foo.com', 'bar.com')
            csp.img_src :none
            csp.style_src
            csp.report_only
          end
          ''
        end

        r.get 'clear' do
          content_security_policy do |csp|
            csp.clear
            csp.add_default_src('foo.com', 'bar.com')
          end
          ''
        end

        'a'
      end
    end

    v = "default-src 'self'; img-src 'self' example.com; style-src 'sha256-abc'; "

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/a").must_equal v

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/nro").must_equal v
    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY_REPORT_ONLY, "/nro").must_be_nil
    body("/nro").must_equal 'false'

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY_REPORT_ONLY, "/ro").must_equal v
    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/ro").must_be_nil

    body('/get').must_equal '[:self]'

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/add").must_equal "default-src 'self' foo.com bar.com; img-src 'self' example.com; style-src 'sha256-abc'; "

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/empty").must_equal "default-src 'self'; img-src 'self' example.com; style-src 'sha256-abc'; "

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/set").must_equal "default-src foo.com bar.com; img-src 'self' example.com; style-src 'sha256-abc'; "

    body('/bool').must_equal 'true'
    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/bool").must_equal "default-src 'self'; img-src 'self' example.com; style-src 'sha256-abc'; block-all-mixed-content; "

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY_REPORT_ONLY, "/block").must_equal "default-src 'self' foo.com bar.com; img-src 'none'; block-all-mixed-content; "

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/clear").must_equal "default-src foo.com bar.com; "
  end

  it "raises error for unsupported CSP values" do
    app{|_|}
    proc{app.plugin(:content_security_policy){|csp| csp.default_src Object.new}}.must_raise Roda::RodaError
    proc{app.plugin(:content_security_policy){|csp| csp.default_src []}}.must_raise Roda::RodaError
    proc{app.plugin(:content_security_policy){|csp| csp.default_src [:a]}}.must_raise Roda::RodaError
    proc{app.plugin(:content_security_policy){|csp| csp.default_src [:a, :b, :c]}}.must_raise Roda::RodaError
  end

  it "supports all documented settings" do
    app(:content_security_policy) do |r|
      content_security_policy.send(r.path[1..-1], :self)
    end

    '
    base_uri
    child_src
    connect_src
    default_src
    font_src
    form_action
    frame_ancestors
    frame_src
    img_src
    manifest_src
    media_src
    object_src
    plugin_types
    report_to
    report_uri
    require_sri_for
    sandbox
    script_src
    style_src
    worker_src
    '.split.each do |setting|
      header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, "/#{setting}").must_equal "#{setting.tr('_', '-')} 'self'; "
    end
  end

  it "does not override existing heading" do
    app(:content_security_policy) do |r|
      content_security_policy.default_src :self
      response[RodaResponseHeaders::CONTENT_SECURITY_POLICY] = "default_src 'none';"
      ''
    end
    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY).must_equal "default_src 'none';"
  end

  it "combines independent policies without granting the parent policy's permissions" do
    child_policy = Roda::RodaPlugins::ContentSecurityPolicy::Policy.new do |csp|
      csp.script_src 'parent.example.com', 'object.example.com'
    end

    app(:bare) do
      plugin :content_security_policy do |csp|
        csp.default_src :none
        csp.img_src :self, 'parent.example.com'
        csp.script_src 'parent.example.com', 'duplicate.example.com', 'duplicate.example.com'
      end

      route do |r|
        r.get 'override' do
          content_security_policy.script_src :self, 'child.example.com'
          ''
        end

        r.get 'combined' do
          combine_content_security_policy do |csp|
            csp.script_src 'parent.example.com', 'child.example.com', 'duplicate.example.com'
          end
          ''
        end

        r.get 'object' do
          combine_content_security_policy(child_policy)
          ''
        end

        r.get 'nonce' do
          combine_content_security_policy do |csp|
            csp.script_src 'parent.example.com', [:nonce, 'token']
          end
          ''
        end

        r.get 'hash' do
          combine_content_security_policy do |csp|
            csp.script_src 'parent.example.com', [:sha256, 'abc']
          end
          ''
        end

        r.get 'strict' do
          combine_content_security_policy do |csp|
            csp.script_src 'parent.example.com', :strict_dynamic
          end
          ''
        end

        r.get 'sandbox' do
          combine_content_security_policy do |csp|
            csp.sandbox 'allow-scripts'
          end
          ''
        end

        r.get 'fallback' do
          combine_content_security_policy do |csp|
            csp.script_src 'parent.example.com', 'child.example.com'
            csp.img_src :self, 'parent.example.com', 'child.example.com'
          end
          ''
        end

        ''
      end
    end

    policies = ->(path) { Array(header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, path)) }
    directive_sources = ->(policy, directive) do
      match = /(?:^|; )#{Regexp.escape(directive)} ([^;]+)/.match(policy)
      match ? match[1].split : nil
    end
    allows = ->(policy_values, directive, source) do
      policy_values.all? do |policy|
        sources = directive_sources.call(policy, directive) || directive_sources.call(policy, 'default-src')
        next false unless sources
        sources.include?(source)
      end
    end

    override_header = header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, '/override')
    refute_match(/script-src[^;]*parent\.example\.com/, override_header)

    combined_values = policies.call('/combined')
    combined_values.length.must_equal 2
    assert_equal combined_values.first, "default-src 'none'; img-src 'self' parent.example.com; script-src parent.example.com duplicate.example.com duplicate.example.com; "

    resource_expectations = {
      "'self'" => false,
      'parent.example.com' => true,
      'child.example.com' => false,
      'other.example.com' => false
    }

    parent_values = policies.call('/')
    resource_expectations.each do |source, expected|
      allows.call(parent_values, 'script-src', source).must_equal expected
      allows.call(combined_values, 'script-src', source).must_equal expected
    end

    object_values = policies.call('/object')
    object_values.length.must_equal 2
    allows.call(object_values, 'script-src', 'object.example.com').must_equal false
    allows.call(object_values, 'script-src', 'parent.example.com').must_equal true

    %w'/nonce /hash /strict /sandbox /fallback'.each do |path|
      values = policies.call(path)
      values.length.must_equal 2
      allows.call(values, 'script-src', 'child.example.com').must_equal false
    end

    policies.call('/nonce').last.must_include "'nonce-token'"
    policies.call('/hash').last.must_include "'sha256-abc'"
    policies.call('/strict').last.must_include "'strict-dynamic'"
    policies.call('/sandbox').last.must_include "sandbox allow-scripts;"
  end

  it "supports combining independent policy objects and normalizes equivalent lists" do
    app(:content_security_policy){|_| ''}
    parent = Roda::RodaPlugins::ContentSecurityPolicy::Policy.new do |csp|
      csp.script_src 'parent.example.com', 'shared.example.com'
    end
    child = Roda::RodaPlugins::ContentSecurityPolicy::Policy.new do |csp|
      csp.script_src 'shared.example.com', 'child.example.com'
    end
    other = Roda::RodaPlugins::ContentSecurityPolicy::Policy.new do |csp|
      csp.img_src 'another.example.com'
    end
    boolean = Roda::RodaPlugins::ContentSecurityPolicy::Policy.new do |csp|
      csp.block_all_mixed_content
    end

    combined = parent.combine(child)
    combined.must_be_kind_of Roda::RodaPlugins::ContentSecurityPolicy::Policy
    combined.header_value.must_equal "script-src shared.example.com; "

    combined_set = parent.combine(child, other)
    combined_set.must_be_kind_of Roda::RodaPlugins::ContentSecurityPolicy::PolicySet

    combined_boolean = child.combine(boolean)
    combined_boolean.must_be_kind_of Roda::RodaPlugins::ContentSecurityPolicy::PolicySet
    assert combined_boolean.policies.any?{|policy| policy.header_value.include?('block-all-mixed-content')}
  end

  it "should not set header when using response.skip_content_security_policy!" do
    app(:bare) do
      plugin :content_security_policy do |csp|
       csp.default_src :self
      end

      route do |r|
        response.skip_content_security_policy!
        ''
      end
    end
    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY).must_be_nil
  end

  it "works with error_handler" do
    app(:bare) do
      plugin(:error_handler){|_| ''}
      plugin :content_security_policy do |csp|
        csp.default_src :self
        csp.img_src :self, 'example.com'
        csp.style_src [:sha256, 'abc']
      end

      route do |r|
        r.get 'a' do
          content_security_policy.default_src 'foo.com'
          raise
        end

        raise
      end
    end

    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY).must_equal "default-src 'self'; img-src 'self' example.com; style-src 'sha256-abc'; "

    # Don't include updates before the error
    header(RodaResponseHeaders::CONTENT_SECURITY_POLICY, '/a').must_equal "default-src 'self'; img-src 'self' example.com; style-src 'sha256-abc'; "
  end
end
