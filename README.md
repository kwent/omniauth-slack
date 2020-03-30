⚠   **_WARNING_**: You are viewing the README of the ginjo fork of omniauth-slack.

To view the original omniauth-slack from [@kmrshntr](https://github.com/kmrshntr), go [here](https://github.com/kmrshntr/omniauth-slack).

# OmniAuth::Slack

This Gem contains the Slack strategy for OmniAuth and supports most features of
the [Slack OAuth2 authorization API](https://api.slack.com/docs/oauth), including both the
[Sign in with Slack](https://api.slack.com/docs/sign-in-with-slack) and
[Add to Slack](https://api.slack.com/docs/slack-button) approval flows.

This Gem supports Slack "classic" apps and tokens as well as the developer preview of [Workspace apps and tokens](https://api.slack.com/workspace-apps-preview).


## Before You Begin

You should have already installed OmniAuth into your app; if not, read the [OmniAuth README](https://github.com/intridea/omniauth) to get started.

Now sign into the [Slack application dashboard](https://api.slack.com/applications) and create an application. Take note of your API keys.


## Using This Strategy

First start by adding this gem to your Gemfile:

```ruby
gem 'ginjo-omniauth-slack'
```

Or specify the latest HEAD version from the ginjo repository:

```ruby
gem 'ginjo-omniauth-slack', git: 'https://github.com/ginjo/omniauth-slack'
```

Next, tell OmniAuth about this provider. For a Rails app, your `config/initializers/omniauth.rb` file should look like this:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :slack, 'API_KEY', 'API_SECRET', scope: 'string-of-scopes'
end
```

Replace `'API_KEY'` and `'API_SECRET'` with the appropriate values you obtained [earlier](https://api.slack.com/applications).
Replace `'string-of-scopes'` with a comma (or space) separated string of Slack API scopes.


For a [Sinatra](http://sinatrarb.com/) app:

```ruby
require 'sinatra'
require 'omniauth-slack'

use OmniAuth::Builder do |env|
  provider :slack,
    ENV['SLACK_OAUTH_KEY_WS'],
    ENV['SLACK_OAUTH_SECRET_WS'],
    scope: 'string-of-scopes'
end
```


If you are using [Devise](https://github.com/plataformatec/devise) then it will look like this:

```ruby
Devise.setup do |config|
  # other stuff...

  config.omniauth :slack, ENV['SLACK_APP_ID'], ENV['SLACK_APP_SECRET'], scope: 'string-of-scopes'

  # other stuff...
end
```


To manually install and require the gem:
```bash
# shell
gem install ginjo-omniauth-slack
````

```ruby
# ruby
require 'omniauth-slack'
```


## Scopes
Slack lets you choose from a [few different scopes](https://api.slack.com/docs/oauth-scopes#scopes).
*Here's another [table of Slack scopes](https://api.slack.com/scopes) showing classic and new app compatibility.*

**Important:** You cannot request both `identity` scopes and regular scopes in a single authorization request.

If you need to combine "Add to Slack" scopes with those used for "Sign in with Slack", you should configure two providers:

```ruby
provider :slack, 'API_KEY', 'API_SECRET', scope: 'identity.basic', name: :sign_in_with_slack
provider :slack, 'API_KEY', 'API_SECRET', scope: 'team:read,users:read,identify,bot'
```

Use the first provider to sign users in and the second to add the application, and deeper capabilities, to their team.

Sign-in-with-Slack handles quick authorization of users with minimally scoped requests.
Deeper scope authorizations are acquired with further passes through the Add-to-Slack authorization process.

This works because Slack scopes are additive: Once you successfully authorize a scope, the token will possess that scope forever, regardless of what flow or scopes are requested at future authorizations.

Removal of scope requires revocation of the token.


## Authentication Options

Authentication options are specified in the provider block, as shown above, and all are optional except for `:scope`.
You will need to specify at least one scope to get a successful authentication and authorization.

Some of these options can also be given at runtime in the authorization request url.

`scope`, `team`, `team_domain`, and `redirect_uri` can be given at runtime. `scope`, `team`, and `redirect_uri` will be passed directly through to Slack in the OAuth GET request:

```ruby
https://slack.com/oauth/v2/authorize?scope=identity.basic,identity.email&team=team-id&redirect_uri=https://different.subdomain/different/callback/path
```

`team_domain` will be inserted into the GET request as a subdomain `https://team-domain.slack.com/oauth/v2/authorize`.

More information on provider and authentication options can be found in omniauth-slack's supporting gems [omniauth](https://github.com/omniauth/omniauth), [oauth2](https://github.com/oauth-xx/oauth2), and [omniauth-oauth2](https://github.com/omniauth/omniauth-oauth2).


### Scope
*required*

```ruby
:scope => 'string-of-comma-or-space-separated-scopes'
```

Specify the scopes you would like to add to the token during this authorization request.

  
### Team
*optional*

```ruby
:team => 'team-id'
  # and/or
:team_domain => 'team-subdomain'
```

> If you don't pass a team param, the user will be allowed to choose which team they are authenticating against. Passing this param ensures the user will auth against an account on that particular team.

If you need to ensure that the users use the team whose team_id is 'XXXXXXXX', you can do so by passing `:team` option in your `config/initializers/omniauth.rb` like this:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :slack, 'API_KEY', 'API_SECRET', scope: 'identify,read,post', team: 'XXXXXXXX'
end
```

If your user is not already signed in to the Slack team that you specify, they will be asked to provide the team domain first.

Another (possibly undocumented) way to specify team is by passing in the `:team_domain` parameter.
In contrast to setting `:team`, setting `:team_domain` will force authentication against the specified team (credentials permitting of course), even if the user is not signed in to that team.
However, if you are already signed in to that team, specifying the `:team_domain` alone will not let you skip the Slack authorization dialog, as is possible when you specify `:team`.

Sign in behavior with team settings and signed in state can be confusing. Here is a breakdown based on Slack documentation and observations while using this gem.


#### Team settings and sign in state vs Slack OAuth behavior. 

| Setting and state | Will authenticate against specific team | Will skip authorization approval<br>-<br>*The elusive unobtrusive<br>[Sign in with Slack](https://api.slack.com/docs/sign-in-with-slack)* |
| --- | :---: | :---: |
| using `:team`, already signed in | :heavy_check_mark: | :heavy_check_mark: |
| using `:team`, not signed in |   | :heavy_check_mark: |
| using `:team_domain`, already signed in | :heavy_check_mark: |   |
| using `:team_domain`, not signed in | :heavy_check_mark: |   |
| using `:team` and `:team_domain`, already signed in | :heavy_check_mark: | :heavy_check_mark: |
| using `:team` and `:team_domain`, not signed in |   | :heavy_check_mark: |
| using no team parameters |   |   |

*Slack's authorization process will only skip the authorization approval step, if in addition to the above settings and state, ALL of the following conditions are met:*

* Token has at least one identity scope previously approved.
* Current authorization is requesting at least one identity scope.
* Current authorization is not requesting any scopes that the token does not already have.
* Current authorization is not requesting any non-identity scopes (but it's ok if the token already has non-identity scopes).


### Redirect URI
*optional*

```ruby
:redirect_uri => 'https://<defaults-to-the-app-origin-host-and-port>/auth/slack/callback'
```

*This setting overrides the `:callback_path` setting.*

Set a custom redirect URI in your app, where Slack will redirect-to with an authorization code.
The redirect URI, whether default or custom, MUST match a registered redirect URI in [your app settings on api.slack.com](https://api.slack.com/apps).
See the [Slack OAuth docs](https://api.slack.com/docs/oauth) for more details on Redirect URI registration and matching rules.


### Callback Path 
*optional*

```ruby
:callback_path => '/auth/slack/callback'
```

*This setting is ignored if `:redirect_uri` is set.*

Set a custom callback path (path only, not the full URI) for Slack to redirect-to with an authorization code. This will be appended to the default redirect URI only. If you wish to specify a custom redirect URI with a custom callback path, just include both in the `:redirect_uri` setting.


### Skip Info 
*optional*

```ruby
:skip_info => false
```

Skip building the `InfoHash` section of the `AuthHash` object.

If set, only a single api request will be made for each authorization. The response of that authorization request may or may not contain user and email data.


### Include/Exclude Data
*optional*

```ruby
  :include_data => %w(identity user_info user_profile)
  
  # or
  
  :exclude_data => %w(user_info team_info bot_info)
```
*These options are ignored if `:skip_info => true` is set.*

Specify which API calls to include or exclude after the initial authorization call.
This will affect what data you see in the AuthHash object. These two options are mutually exclusive. Use one or the other but not both. If neither option is declared, all API calls will be made (depending on scope and permissions).

The currently available calls are:

* identity
* user_info
* user_profile
* team_info
* bot_info


### Preload Data with Threads
*optional*

```ruby
:preload_data_with_threads => 0
```
*This option is ignored if `:skip_info => true` is set.*

With passed integer > 0, omniauth-slack preloads the basic identity-and-info API call responses, from Slack, using *<#integer>* pooled threads.

The default `0` skips this feature and only loads those API calls if required, scoped, and authorized, to build the AuthHash.

```ruby
provider :slack, key, secret, :preload_data_with_threads => 2
```

More threads can potentially give a quicker callback phase.
The caveat is an increase in concurrent request load on Slack, possibly affecting rate limits.


### Additional Data
*experimental*

This experimental feature allows additional API calls to be made during the omniauth-slack callback phase.
Provide a hash of `{<name>: <proc-that-receives-env>}`, and the result will be attached as a hash
under `additional_data` in the `extra` section of the `AuthHash`.

```ruby
provider :slack, key, secret,
  additional_data: {
    channels: proc{|env| env['omniauth.strategy'].access_token.get('/api/conversations.list').parsed['channels'] },
    resources: proc{|env| env['omniauth.strategy'].access_token.get('/api/apps.permissions.resources.list').parsed }
  }
```


## Workspace Apps and Tokens
This gem provides support for Slack's developer preview of [Workspace apps](https://api.slack.com/workspace-apps-preview). There are some important differences between Slack's classic apps and the new Workspace apps. The main points to be aware of when using omniauth-slack with Workspace Apps are:

* Workspace app tokens are issued as a single token per team. There are no user or bot tokens. All Workspace app API calls are made with the Workspace token. Calls that act on behalf of a user or bot are made with the same token.

* The available api calls and the scopes required to access them are different in Workspace apps. See Slack's docs on [Scopes](https://api.slack.com/scopes) and [Methods](https://api.slack.com/methods/workspace-tokens) for more details.

* The OmniAuth::AuthHash.credentials.scope object, returned from a successful authentication, is a hash with each value containing an array of scopes. See below for an example.


## Auth Hash

The AuthHash from this gem has the standard components of an `OmniAuth::AuthHash` object, with some additional data added to the `:info` and `:extra` sections.

If the scopes allow, additional api calls *may* be made to gather additional user and team info, unless the `:skip_info => true` is set.

The `:extra` section contains the parsed data from each of the api calls made during the authorization.
Also included is a `:raw_info` hash, which in turn contains the raw response object from each of the api calls.

The `:extra` section also contains `:scopes_requested`, which are the scopes requested during the current authorization.

See [this gist for an example AuthHash](https://gist.github.com/ginjo/3105cf4e975996c9032bb4725f949cd2) from a workspace token with a mix of identity scopes and regular app scopes applied.

See <https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema> for more info on the auth_hash schema.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
