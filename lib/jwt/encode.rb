# frozen_string_literal: true

require_relative 'algos'
require_relative 'claims_validator'

# JWT::Encode module
module JWT
  # Encoding logic for JWT
  class Encode
    ALG_KEY = 'alg'

    def initialize(options)
      @payload          = options[:payload]
      @key              = options[:key]
      @algorithm        = resolve_algorithm(options[:algorithm])
      @headers          = options[:headers].transform_keys(&:to_s)
      @headers[ALG_KEY] = @algorithm.alg
      @detached         = options[:detached]

      # add b64 claim to crit as per RFC7797 proposed standard
      unless encode_payload?
        @headers['crit'] ||= []
        @headers['crit'] << 'b64' unless @headers['crit'].include?('b64')
      end
    end

    def segments
      validate_claims!

      parts = []
      parts << encoded_header
      parts << (@detached ? '' : encoded_payload)
      parts << encoded_signature

      combine(*parts)
    end

    private

    def resolve_algorithm(algorithm)
      return algorithm if Algos.implementation?(algorithm)

      Algos.create(algorithm)
    end

    def encoded_header
      @encoded_header ||= encode_header
    end

    def encoded_payload
      @encoded_payload ||= encode_payload
    end

    def encoded_signature
      @encoded_signature ||= encode_signature
    end

    def encoded_header_and_payload
      @encoded_header_and_payload ||= combine(encoded_header, encoded_payload)
    end

    def encode_header
      encode_data(@headers)
    end

    def encode_payload
      # if b64 header is present and false, do not encode payload as per RFC7797 proposed standard
      encode_payload? ? encode_data(@payload) : prepare_unencoded_payload
    end

    def encode_payload?
      # if b64 header is left out, default to true as per RFC7797 proposed standard
      @headers['b64'].nil? || !!@headers['b64']
    end

    def prepare_unencoded_payload
      json = @payload.to_json

      raise(JWT::InvalidUnencodedPayload, 'An unencoded payload cannot contain period/dot characters (i.e. ".").') if json.include?('.')

      json
    end

    def signature
      @algorithm.sign(data: encoded_header_and_payload, signing_key: @key)
    end

    def validate_claims!
      return unless @payload.is_a?(Hash)

      ClaimsValidator.new(@payload).validate!
    end

    def encode_signature
      ::JWT::Base64.url_encode(signature)
    end

    def encode_data(data)
      ::JWT::Base64.url_encode(JWT::JSON.generate(data))
    end

    def combine(*parts)
      parts.join('.')
    end
  end
end
