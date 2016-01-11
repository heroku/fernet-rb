require 'legacy-fernet'
require 'spec_helper'

describe LegacyFernet do
  after { LegacyFernet::Configuration.run }

  let(:token_data) do
    { :email => 'harold@heroku.com', :id => '123', :arbitrary => 'data' }
  end

  let(:secret)     { 'JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }
  let(:bad_secret) { 'badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }

  it 'can verify tokens it generates' do
    token = LegacyFernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(
      LegacyFernet.verify(secret, token) do |verifier|
        verifier.data['email'] == 'harold@heroku.com'
      end
    ).to be true
  end

  it 'fails with a bad secret' do
    token = LegacyFernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(
      LegacyFernet.verify(bad_secret, token) do |verifier|
        verifier.data['email'] == 'harold@heroku.com'
      end
    ).to be false
  end

  it 'fails with a bad custom verification' do
    token = LegacyFernet.generate(secret) do |generator|
      generator.data = { :email => 'harold@heroku.com' }
    end

    expect(
      LegacyFernet.verify(secret, token) do |verifier|
        verifier.data['email'] == 'lol@heroku.com'
      end
    ).to be false
  end

  it 'fails if the token is too old' do
    token = LegacyFernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(
      LegacyFernet.verify(secret, token) do |verifier|
        verifier.ttl = 1

        def verifier.now
          now = DateTime.now
          DateTime.new(now.year, now.month, now.day, now.hour,
                       now.min, now.sec + 2, now.offset)
        end
        true
      end
    ).to be false
  end

  it 'verifies without a custom verification' do
    token = LegacyFernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(LegacyFernet.verify(secret, token)).to be true
  end

  it 'can ignore TTL enforcement' do
    token = LegacyFernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(
      LegacyFernet.verify(secret, token) do |verifier|
        def verifier.now
          Time.now + 99999999999
        end
        verifier.enforce_ttl = false
        true
      end
    ).to be true
  end

  it 'can ignore TTL enforcement via global config' do
    LegacyFernet::Configuration.run do |config|
      config.enforce_ttl = false
    end

    token = LegacyFernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(
      LegacyFernet.verify(secret, token) do |verifier|
        def verifier.now
          Time.now + 99999999999
        end
        true
      end
    ).to be true
  end

  it 'generates without custom data' do
    token = LegacyFernet.generate(secret)

    expect(LegacyFernet.verify(secret, token)).to be true
  end

  it 'can encrypt the payload' do
    token = LegacyFernet.generate(secret, true) do |generator|
      generator.data['password'] = 'password1'
    end

    expect(Base64.decode64(token)).not_to match /password1/

    LegacyFernet.verify(secret, token) do |verifier|
      expect(verifier.data['password']).to eq('password1')
    end
  end

  it 'does not encrypt when asked nicely' do
    token = LegacyFernet.generate(secret, false) do |generator|
      generator.data['password'] = 'password1'
    end

    expect(Base64.decode64(token)).to match /password1/

    LegacyFernet.verify(secret, token, false) do |verifier|
      expect(verifier.data['password']).to eq('password1')
    end
  end

  it 'can disable encryption via global configuration' do
    LegacyFernet::Configuration.run { |c| c.encrypt = false }
    token = LegacyFernet.generate(secret) do |generator|
      generator.data['password'] = 'password1'
    end

    expect(Base64.decode64(token)).to match /password1/

    LegacyFernet.verify(secret, token) do |verifier|
      expect(verifier.data['password']).to eq('password1')
    end
  end

  it 'returns the unencrypted message upon verify' do
    token = LegacyFernet.generate(secret) do |generator|
      generator.data['password'] = 'password1'
    end

    verifier = LegacyFernet.verifier(secret, token)
    expect(verifier.valid?).to be true
    expect(verifier.data['password']).to eq('password1')
  end
end
