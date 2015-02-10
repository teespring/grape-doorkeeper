module GrapeDoorkeeper
  # OAuth 2.0 authorization for Grape APIs.

  class Middleware < Grape::Middleware::Base
    include GrapeDoorkeeper::Helpers

    def before
      doorkeeper_authorize! if protected_endpoint?
    end

    def doorkeeper_authorize!(*scopes)
      check_token!
      env['api.token'] = doorkeeper_token
    end

    def endpoint
      @endpoint ||= env['api.endpoint']
    end

    def check_token!
      unless valid_doorkeeper_token?(*scopes)
        token_error!(401, 'invalid_token') unless doorkeeper_token
        token_error!(401, 'expired_token') unless doorkeeper_token.accessible?
        token_error!(403, 'insufficient_scope') unless token.includes_scope?(scopes)
      end
    end

    def scopes
      @scopes ||= endpoint.options[:route_options][:scopes] ||
        options[:scopes] ||
         Doorkeeper.configuration.default_scopes
    end

    def action
      @action ||= (endpoint.namespace.split('/')[1] || endpoint.options[:path].first).to_sym
    end

    def request
      @request ||= GrapeDoorkeeper::Request.new(env)
    end

    def protected_endpoint?
      if endpoint.options[:route_options].key?(:authenticate)
        endpoint.options[:route_options][:authenticate]
      else
        permitted_actions = options[:only]
        except_actions = options[:except]

        (permitted_actions && Array.wrap(permitted_actions).include?(action.to_sym)) ||
          !(except_actions && Array.wrap(except_actions).include?(action.to_sym))
      end
    end

    def token_error!(status, error)
      throw :error,
            message:  {error: error},
            status: status,
            headers: {
              'Content-Type' => 'application/json',
              'X-Accepted-OAuth-Scopes' => scopes,
              'WWW-Authenticate' => "OAuth realm='#{options[:realm]}', error='#{error}'"
            }.reject { |k,v| v.nil? }
    end
  end
end
