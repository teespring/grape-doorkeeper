module GrapeDoorkeeper
  class Request < ::Grape::Request
    def authorization
      headers['Authorization']
    end

    def parameters
      params
    end
  end
end

