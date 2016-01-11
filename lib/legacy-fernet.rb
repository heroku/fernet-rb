require 'legacy-fernet/version'
require 'legacy-fernet/generator'
require 'legacy-fernet/verifier'
require 'legacy-fernet/secret'
require 'legacy-fernet/configuration'
require 'legacy-fernet/okjson'

if RUBY_VERSION == '1.8.7'
  require 'shim/base64'
end

LegacyFernet::Configuration.run

module LegacyFernet
  def self.generate(secret, encrypt = Configuration.encrypt, &block)
    Generator.new(secret, encrypt).generate(&block)
  end

  def self.verify(secret, token, encrypt = Configuration.encrypt, &block)
    Verifier.new(secret, encrypt).verify_token(token, &block)
  end

  def self.verifier(secret, token, encrypt = Configuration.encrypt)
    Verifier.new(secret, encrypt).tap do |v|
      v.verify_token(token)
    end
  end
end
