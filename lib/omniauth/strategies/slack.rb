require 'omniauth/strategies/oauth2'
require 'thread'
require 'uri'

module OmniAuth
  module Strategies
    
    class Slack < OmniAuth::Strategies::OAuth2
      option :name, 'slack'

      option :authorize_options, [:scope, :team, :user_scope, :team_domain, :redirect_uri]

      option :client_options, {
        site: 'https://slack.com',
        authorize_url: '/oauth/v2/authorize',
        token_url: '/api/oauth.v2.access',
        auth_scheme: :basic_auth
      }
      
      option :auth_token_params, {
        mode: :query,
        param_name: 'token'
      }
      
      option :preload_data_with_threads, 0
      
      option :include_data, []
      
      option :exclude_data, []
      
      option :additional_data, {}
      
      # User ID is not guaranteed to be globally unique across all Slack users.
      # The combination of user ID and team ID, on the other hand, is guaranteed
      # to be globally unique.
      uid { "#{user_id}-#{team_id}" }
      
      credentials do
        {
          token: auth['token'],
          scope: (is_app_token? ? all_scopes : auth['scope']),
          expires: false
        }
      end

      info do
      
        unless skip_info?
          define_additional_data
          semaphore
        end
        
        num_threads = options.preload_data_with_threads.to_i
        
        if num_threads > 0 && !skip_info?
          preload_data_with_threads(num_threads)
        end
      
        # Start with only what we can glean from the authorization response.
        hash = { 
          name: auth['user'].to_h['name'],
          email: auth['user'].to_h['email'],
          user_id: user_id,
          team_name: auth['team_name'] || auth['team'].to_h['name'],
          team_id: team_id,
          image: auth['team'].to_h['image_48']
        }

        # Now add everything else, using further calls to the api, if necessary.
        unless skip_info?
          %w(first_name last_name phone skype avatar_hash real_name real_name_normalized).each do |key|
            hash[key.to_sym] = (
              user_info['user'].to_h['profile'] ||
              user_profile['profile']
            ).to_h[key]
          end

          %w(deleted status color tz tz_label tz_offset is_admin is_owner is_primary_owner is_restricted is_ultra_restricted is_bot has_2fa).each do |key|
            hash[key.to_sym] = user_info['user'].to_h[key]
          end

          more_info = {
            image: (
              hash[:image] ||
              user_identity.to_h['image_48'] ||
              user_info['user'].to_h['profile'].to_h['image_48'] ||
              user_profile['profile'].to_h['image_48']
              ),
            name:(
              hash[:name] ||
              user_identity['name'] ||
              user_info['user'].to_h['real_name'] ||
              user_profile['profile'].to_h['real_name']
              ),
            email:(
              hash[:email] ||
              user_identity.to_h['email'] ||
              user_info['user'].to_h['profile'].to_h['email'] ||
              user_profile['profile'].to_h['email']
              ),
            team_name:(
              hash[:team_name] ||
              team_identity.to_h['name'] ||
              team_info['team'].to_h['name']
              ),
            team_domain:(
              auth['team'].to_h['domain'] ||
              team_identity.to_h['domain'] ||
              team_info['team'].to_h['domain']
              ),
            team_image:(
              auth['team'].to_h['image_44'] ||
              team_identity.to_h['image_44'] ||
              team_info['team'].to_h['icon'].to_h['image_44']
              ),
            team_email_domain:(
              team_info['team'].to_h['email_domain']
              ),
            nickname:(
              user_info.to_h['user'].to_h['name'] ||
              auth['user'].to_h['name'] ||
              user_identity.to_h['name']
              ),
          }
          
          hash.merge!(more_info)
        end
        hash
      end

      extra do
        {
          scopes_requested: (env['omniauth.params'] && env['omniauth.params']['scope']) || \
            (env['omniauth.strategy'] && env['omniauth.strategy'].options && env['omniauth.strategy'].options.scope),
          web_hook_info: web_hook_info,
          bot_info: auth['bot'] || bot_info['bot'],
          auth: auth,
          identity: identity,
          user_info: user_info,
          user_profile: user_profile,
          team_info: team_info,
          apps_permissions_users_list: apps_permissions_users_list,
          additional_data: get_additional_data,
          raw_info: @raw_info
        }
      end

      
      # Pass on certain authorize_params to the Slack authorization GET request.
      # See https://github.com/omniauth/omniauth/issues/390
      def authorize_params
        super.tap do |params|
          %w(scope user_scope team redirect_uri).each do |v|
            if !request.params[v].to_s.empty?
              params[v.to_sym] = request.params[v]
            end
          end
          log(:debug, "Authorize_params #{params.to_h}")
        end
      end
      
      # Get a new OAuth2::Client and define custom behavior.
      # * overrides previous omniauth-strategies-oauth2 :client definition.
      #
      # * Log API requests with OmniAuth.logger
      # * Add API responses to @raw_info hash
      # * Set auth site uri with custom subdomain (if provided).
      #
      def client
        new_client = super
        
        team_domain = request.params['team_domain'] || options[:team_domain]
        if !team_domain.to_s.empty?
          site_uri = URI.parse(options[:client_options]['site'])
          site_uri.host = "#{team_domain}.slack.com"
          new_client.site = site_uri.to_s
          log(:debug, "Oauth site uri with custom team_domain #{site_uri}")
        end
        
        st_raw_info = raw_info
        new_client.define_singleton_method(:request) do |*args|
          OmniAuth.logger.send(:debug, "(slack) API request #{args[0..1]}; in thread #{Thread.current.object_id}.")
          request_output = super(*args)
          uri = args[1].to_s.gsub(/^.*\/([^\/]+)/, '\1') # use single-quote or double-back-slash for replacement.
          st_raw_info[uri.to_s]= request_output
          request_output
        end
        
        new_client
      end

      # Dropping query_string from callback_url prevents some errors in call to /api/oauth.v2.access.
      def callback_url
        full_host + script_name + callback_path
      end

      def identity
        return {} unless !skip_info? && has_scope?(identity: ['identity.basic','identity:read:user']) && is_not_excluded?
        semaphore.synchronize {
          @identity_raw ||= access_token.get('/api/users.identity', headers: {'X-Slack-User' => user_id})
          @identity ||= @identity_raw.parsed
        }
      end
      
      
      private
      
      def initialize(*args)
        super
        @main_semaphore = Mutex.new
        @semaphores = {}
      end
      
      # Get a mutex specific to the calling method.
      # This operation is synchronized with its own mutex.
      def semaphore(method_name = caller[0][/`([^']*)'/, 1])
        @main_semaphore.synchronize {
          @semaphores[method_name] ||= Mutex.new
        }
      end
      
      def active_methods
        @active_methods ||= (
          includes = [options.include_data].flatten.compact
          excludes = [options.exclude_data].flatten.compact unless includes.size > 0
          method_list = %w(apps_permissions_users_list identity user_info user_profile team_info bot_info)  #.concat(options[:additional_data].keys)
          if includes.size > 0
            method_list.keep_if {|m| includes.include?(m.to_s) || includes.include?(m.to_s.to_sym)}
          elsif excludes.size > 0
            method_list.delete_if {|m| excludes.include?(m.to_s) || excludes.include?(m.to_s.to_sym)}
          end
          log :debug, "Activated API calls: #{method_list}."
          log :debug, "Activated additional_data calls: #{options.additional_data.keys}."
          method_list
        )
      end
      
      def is_not_excluded?(method_name = caller[0][/`([^']*)'/, 1])
        active_methods.include?(method_name.to_s) || active_methods.include?(method_name.to_s.to_sym)
      end
      
      # Preload additional api calls with a pool of threads.
      def preload_data_with_threads(num_threads)
        return unless num_threads > 0
        preload_methods = active_methods.concat(options[:additional_data].keys)
        log :info, "Preloading (#{preload_methods.size}) data requests using (#{num_threads}) threads."
        work_q = Queue.new
        preload_methods.each{|x| work_q.push x }
        workers = num_threads.to_i.times.map do
          Thread.new do
            begin
              while x = work_q.pop(true)
                log :debug, "Preloading #{x}."
                send x
              end
            rescue ThreadError
            end
          end
        end
        workers.map(&:join); "ok"
      end
      
      # Define methods for addional data from :additional_data option
      def define_additional_data
        hash = options[:additional_data]
        if !hash.to_h.empty?
          hash.each do |k,v|
            define_singleton_method(k) do
              instance_variable_get(:"@#{k}") || 
              instance_variable_set(:"@#{k}", v.respond_to?(:call) ? v.call(env) : v)
            end
          end
        end
      end
      
      def get_additional_data
        if skip_info?
          {}
        else
          options[:additional_data].inject({}) do |hash,tupple|
            hash[tupple[0].to_s] = send(tupple[0].to_s)
            hash
          end
        end
      end

      # Parsed data returned from /slack/oauth.v2.access api call.
      def auth
        @auth ||= access_token.params.to_h.merge({'token' => access_token.token})
      end

      def user_identity
        @user_identity ||= identity['user'].to_h
      end

      def team_identity
        @team_identity ||= identity['team'].to_h
      end

      def user_info
        return {} unless !skip_info? && has_scope?(identity: 'users:read', team: 'users:read') && is_not_excluded?
        semaphore.synchronize {
          @user_info_raw ||= access_token.get('/api/users.info', params: {user: user_id}, headers: {'X-Slack-User' => user_id})
          @user_info ||= @user_info_raw.parsed
        }
      end
      
      def user_profile
        return {} unless !skip_info? && has_scope?(identity: 'users.profile:read', team: 'users.profile:read') && is_not_excluded?
        semaphore.synchronize {
          @user_profile_raw ||= access_token.get('/api/users.profile.get', params: {user: user_id}, headers: {'X-Slack-User' => user_id})
          @user_profile ||= @user_profile_raw.parsed
        }
      end

      def team_info
        return {} unless !skip_info? && has_scope?(identity: 'team:read', team: 'team:read') && is_not_excluded?
        semaphore.synchronize {
          @team_info_raw ||= access_token.get('/api/team.info')
          @team_info ||= @team_info_raw.parsed
        }
      end

      def web_hook_info
        return {} unless auth.key? 'incoming_webhook'
        auth['incoming_webhook']
      end
      
      def bot_info
        return {} unless !skip_info? && has_scope?(identity: 'users:read') && is_not_excluded?
        semaphore.synchronize {
          @bot_info_raw ||= access_token.get('/api/bots.info')
          @bot_info ||= @bot_info_raw.parsed
        }
      end
      
      def user_id
        auth['user_id'] || auth['user'].to_h['id'] || auth['authorizing_user'].to_h['user_id']
      end
      
      def team_id
        auth['team_id'] || auth['team'].to_h['id']
      end
      
      # API call to get user permissions for workspace token.
      # This is needed because workspace token 'sign-in-with-slack' is missing scopes
      # in the :scope field (acknowledged issue in developer preview).
      #
      # Returns [<id>: <resource>]
      def apps_permissions_users_list
        return {} unless !skip_info? && is_app_token? && is_not_excluded?
        semaphore.synchronize {
          @apps_permissions_users_list_raw ||= access_token.get('/api/apps.permissions.users.list')
          @apps_permissions_users_list ||= @apps_permissions_users_list_raw.parsed['resources'].inject({}){|h,i| h[i['id']] = i; h}
        }
      end
      
      def raw_info
        @raw_info ||= {}
      end
      
      # Is this a workspace app token?
      def is_app_token?
        auth['token_type'].to_s == 'app'
      end
      
      # Scopes come from at least 3 different places now.
      # * The classic :scope field (string)
      # * New workshop token :scopes field (hash)
      # * Separate call to apps.permissions.users.list (array)
      #
      # This returns hash of workspace scopes, with classic & new identity scopes in :identity.
      # Lists of scopes are in array form.
      def all_scopes
        @all_scopes ||=
        {'identity' => (auth['scope'] || apps_permissions_users_list[user_id].to_h['scopes'].to_a.join(',')).to_s.split(',')}
        .merge(auth['scopes'].to_h)
      end
      
      # Determine if given scopes exist in current authorization.
      # Scopes is hash where
      #   key == scope type <identity|app_hope|team|channel|group|mpim|im>
      #   val == array or string of individual scopes.
      def has_scope?(**scopes_hash)
        scopes_hash.detect do |section, scopes|
          test_scopes = case
            when scopes.is_a?(String); scopes.split(',')
            when scopes.is_a?(Array); scopes
            else raise "Scope must be a string or array"
          end
          test_scopes.detect do |scope|
            all_scopes[section.to_s].to_a.include?(scope.to_s)
          end
        end
      end
      
      def self.ad_hoc_client(client_id, client_key, token)
        puts default_options['client_options'].to_yaml
        ::OAuth2::AccessToken.new(
          ::OAuth2::Client.new(
            client_id,
            client_key,
            default_options['client_options'].map{|k,v| [k.to_sym, v]}.to_h
          ),
          token
        )
      end
      
    end
  end
end

