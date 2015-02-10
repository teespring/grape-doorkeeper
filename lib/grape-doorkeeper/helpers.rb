module GrapeDoorkeeper
  module Helpers
    extend ActiveSupport::Concern

    included do
      include Doorkeeper::Helpers::Controller
    end

    def doorkeeper_token
      @doorkeeper_token ||= Doorkeeper::OAuth::Token.authenticate(
        request, *Doorkeeper.configuration.access_token_methods
      )
    end

    def valid_doorkeeper_token?(*scopes)
      doorkeeper_token && doorkeeper_token.acceptable?(scopes)
    end
  end
end
