require 'base64'
require 'openssl'
require 'date'

module LegacyFernet
  class Generator
    attr_accessor :data, :payload

    def initialize(secret, encrypt)
      @secret  = Secret.new(secret, encrypt)
      @encrypt = encrypt
      @payload = ''
      @data    = {}
    end

    def generate
      yield self if block_given?
      data.merge!(:issued_at => DateTime.now.to_s)

      if encrypt?
        iv = encrypt_data!
        @payload = "#{base64(data)}|#{base64(iv)}"
      else
        @payload = base64(LegacyFernet::OkJson.encode(stringify_hash_keys(data)))
      end

      mac = OpenSSL::HMAC.hexdigest('sha256', payload, signing_key)
      "#{payload}|#{mac}"
    end

    def inspect
      "#<LegacyFernet::Generator @secret=[masked] @data=#{@data.inspect}>"
    end
    alias to_s inspect

    def data
      @data ||= {}
    end

  private
    attr_reader :secret

    def encrypt_data!
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      iv         = cipher.random_iv
      cipher.iv  = iv
      cipher.key = encryption_key
      @data = cipher.update(LegacyFernet::OkJson.encode(stringify_hash_keys(data))) + cipher.final
      iv
    end

    def base64(chars)
      Base64.urlsafe_encode64(chars)
    end

    def encryption_key
      @secret.encryption_key
    end

    def signing_key
      @secret.signing_key
    end

    def encrypt?
      @encrypt
    end

    def stringify_hash_keys(hash)
      hash.inject({}) do |result, (k, v)|
        result[k.to_s] = v
      result
      end
    end
  end
end
