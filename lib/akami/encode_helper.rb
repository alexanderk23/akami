module Akami
  module EncodeHelper
    def decode(data)
      Base64.decode64(data.gsub(/\s*/, ''))
    end
    def encode(data)
      Base64.encode64(data).gsub(/\s*/, '')
    end
  end
end
