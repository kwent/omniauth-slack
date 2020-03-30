require 'helper'
require 'omniauth-slack'

OmniAuth.logger.level = 1

class StrategyTest < StrategyTestCase
  include OAuth2StrategyTests
end

class ClientTest < StrategyTestCase
  test "has correct Slack site" do
    assert_equal "https://slack.com", strategy.client.site
  end

  test "has correct authorize url" do
    assert_equal "/oauth/v2/authorize", strategy.client.options[:authorize_url]
  end

  test "has correct token url" do
    assert_equal "/api/oauth.v2.access", strategy.client.options[:token_url]
  end

  test "has correct auth_scheme" do
    assert_equal :basic_auth, strategy.client.options[:auth_scheme]
  end
  
  test 'request logs api call' do
    OAuth2::Client.class_eval do
      def request(*args)
        {simple: 'hash'}
      end
    end
    @client = strategy.client
    OmniAuth.logger.expects(:send).with(){|*params| assert_equal :debug, params[0]}
    @client.request(:get, 'http://test-url')
  end
  
  test 'request adds api response to raw_info hash' do
    OAuth2::Client.class_eval do
      def request(*args)
        {simple: 'hash'}
      end
    end
    @client = strategy.client
    @client.request(:get, 'http://test-url')
    assert_equal( {'test-url' => {simple: 'hash'}}, strategy.send(:raw_info) )
  end
end

class CallbackUrlTest < StrategyTestCase
  test "returns the default callback url" do
    url_base = "http://auth.request.com"
    @request.stubs(:url).returns("#{url_base}/some/page")
    strategy.stubs(:script_name).returns("") # as not to depend on Rack env
    assert_equal "#{url_base}/auth/slack/callback", strategy.callback_url
  end

  test "returns path from callback_path option" do
    @options = { :callback_path => "/auth/slack/done"}
    url_base = "http://auth.request.com"
    @request.stubs(:url).returns("#{url_base}/page/path")
    strategy.stubs(:script_name).returns("") # as not to depend on Rack env
    assert_equal "#{url_base}/auth/slack/done", strategy.callback_url
  end
end

class UidTest < StrategyTestCase
  def setup
    super
    #strategy.stubs(:identity).returns("user" => {"id" => "U123"}, "team" => {"id" => "T456"})
    strategy.stubs(:auth).returns("user" => {"id" => "U123"}, "team" => {"id" => "T456"})
  end

  test "returns the user ID from user_identity" do
    assert_equal "U123-T456", strategy.uid
  end
end

class CredentialsTest < StrategyTestCase
  def setup
    super
    @access_token = stub("OAuth2::AccessToken")
    @access_token.stubs(:token)
    @access_token.stubs(:expires?)
    @access_token.stubs(:expires_at)
    @access_token.stubs(:refresh_token)
    @access_token.stubs(:[])
    @access_token.stubs(:params)
    strategy.stubs(:access_token).returns(@access_token)
  end

  test "returns a Hash" do
    assert_kind_of Hash, strategy.credentials
  end

  test "returns the token" do
    @access_token.stubs(:token).returns("123")
    assert_equal "123", strategy.credentials["token"]
  end

  test "returns the expiry status" do
    @access_token.stubs(:expires?).returns(true)
    assert strategy.credentials["expires"]

    @access_token.stubs(:expires?).returns(false)
    refute strategy.credentials["expires"]
  end

  test "returns the refresh token and expiry time when expiring" do
    ten_mins_from_now = (Time.now + 600).to_i
    @access_token.stubs(:expires?).returns(true)
    @access_token.stubs(:refresh_token).returns("321")
    @access_token.stubs(:expires_at).returns(ten_mins_from_now)
    assert_equal "321", strategy.credentials["refresh_token"]
    assert_equal ten_mins_from_now, strategy.credentials["expires_at"]
  end

  test "does not return the refresh token when test is nil and expiring" do
    @access_token.stubs(:expires?).returns(true)
    @access_token.stubs(:refresh_token).returns(nil)
    assert_nil strategy.credentials["refresh_token"]
    refute_has_key "refresh_token", strategy.credentials
  end

  test "does not return the refresh token when not expiring" do
    @access_token.stubs(:expires?).returns(false)
    @access_token.stubs(:refresh_token).returns("XXX")
    assert_nil strategy.credentials["refresh_token"]
    refute_has_key "refresh_token", strategy.credentials
  end
end

class IdentityTest < StrategyTestCase

  def setup
    super
    @access_token = stub("OAuth2::AccessToken")
    @access_token.stubs(:[])
    @access_token.stubs(:params)
    @access_token.stubs(:token)
    strategy.stubs(:access_token).returns(@access_token)
    strategy.stubs(:has_scope?).returns true
  end

  test "performs a GET to https://slack.com/api/users.identity" do
    @access_token.expects(:get).with("/api/users.identity", {:headers => {"X-Slack-User" => nil}})
      .returns(stub_everything("OAuth2::Response"))
    strategy.identity
  end

end

class SkipInfoTest < StrategyTestCase

  test 'info should not include extended info when skip_info is specified' do
    @options = { skip_info: true }
    #strategy.stubs(:identity).returns({})
    strategy.stubs(:auth).returns({})
    assert_equal %w(name email user_id team_name team_id image), strategy.info.keys.map(&:to_s)
  end

end

class AuthorizeParamsTest < StrategyTestCase

  test 'returns OmniAuth::Strategy::Options hash' do
    assert_kind_of OmniAuth::Strategy::Options, strategy.authorize_params
  end
  
  test 'forwards request params (scope, team, redirect_uri) to slack' do
    strategy.request.params['scope'] = 'test-scope'
    strategy.request.params['team'] = 'test-team'
    strategy.request.params['redirect_uri'] = 'http://my-test-uri/auth/callback'
    assert_equal 'test-scope', strategy.authorize_params['scope']
    assert_equal 'test-team', strategy.authorize_params['team']
    assert_equal 'http://my-test-uri/auth/callback', strategy.authorize_params['redirect_uri']
  end
  
end

class InitializeTest < StrategyTestCase

  test 'sets @main_semaphore with a new Mutex' do
    assert_kind_of Mutex, strategy.instance_variable_get(:@main_semaphore)
  end
  
  test 'sets @semaphores with empty hash' do
    assert_equal( {}, strategy.instance_variable_get(:@semaphores) )
  end

end

class SemaphoreTest < StrategyTestCase

  def setup
    super
    
    def strategy.test_method
      send :semaphore
    end
  end

  test 'synchronized management of method-specific mutexes' do
    strategy.test_method
    assert_kind_of Mutex, strategy.instance_variable_get(:@semaphores)['test_method']
  end

end

class ActiveMethodsTest < StrategyTestCase

  test 'with no settings, returns all defined api methods' do
    assert_equal %w(apps_permissions_users_list identity user_info user_profile team_info bot_info),
      strategy.send(:active_methods)
  end
  
  test 'with :include_data, returns only included methods' do
    strategy.options[:include_data] = %w(identity team_info)
    assert_equal %w(identity team_info),
      strategy.send(:active_methods)    
  end

  test 'with :exclude_data, returns all but excluded methods' do
    strategy.options[:exclude_data] = %w(identity team_info)
    assert_equal %w(apps_permissions_users_list user_info user_profile bot_info),
      strategy.send(:active_methods)    
  end

end

class IsNotExcluded < StrategyTestCase

  def setup
    super
    
    def identity
      strategy.send 'is_not_excluded?'
    end
  end

  test 'returns true if calling method is in active-methods' do
    assert_equal true, identity
  end
  
  test 'returns false if calling method is not in active-methods' do
    strategy.options[:exclude_data] = 'identity'
    assert_equal false, identity
  end

end
