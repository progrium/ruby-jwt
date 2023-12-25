# frozen_string_literal: true

module JWT
  module JWK
    class KeyBase
      def self.inherited(klass)
        super
        ::JWT::JWK.classes << klass
      end

      def initialize(options, params = {})
        options ||= {}

        @parameters = params.transform_keys(&:to_sym) # Uniform interface

        # For backwards compatibility, kid_generator may be specified in the parameters
        options[:kid_generator] ||= @parameters.delete(:kid_generator)

        # Make sure the key has a kid
        kid_generator = options[:kid_generator] || ::JWT.configuration.jwk.kid_generator
        self[:kid] ||= kid_generator.new(self).generate

        enrich_key(options) if options[:enrich_key]
      end

      def kid
        self[:kid]
      end

      def hash
        self[:kid].hash
      end

      def [](key)
        @parameters[key.to_sym]
      end

      def []=(key, value)
        @parameters[key.to_sym] = value
      end

      def ==(other)
        other.is_a?(::JWT::JWK::KeyBase) && self[:kid] == other[:kid]
      end

      alias eql? ==

      def <=>(other)
        return nil unless other.is_a?(::JWT::JWK::KeyBase)

        self[:kid] <=> other[:kid]
      end

      private

      attr_reader :parameters

      KEY_USAGES_SIG  = ['Digital Signature', 'Non Repudiation', 'Content Commitment', 'Key Cert Sign', 'CRL Sign'].freeze
      KEY_USAGES_ENC  = ['Key Encipherment', 'Data Encipherment', 'Key Agreement'].freeze
      KEY_OPS_VERIFY  = ['Digital Signature', 'Key Cert Sign', 'CRL Sign'].freeze
      KEY_OPS_ENCRYPT = ['Data Encipherment'].freeze
      KEY_OPS_WRAPKEY = ['Key Encipherment'].freeze

      # Tries to derive additional key parameters from a certificate chain while maintaining semantic consistency
      # Does not as of now validate the chain
      def enrich_key(options)
        certs = fetch_certificates(options)
        if certs
          add_thumbprints(certs.first)
          add_key_operations(certs.first)
          add_private_key_operations
          add_usages(certs.first)
        end
        add_default_algorithm
      end

      # Try to find certificates. TODO: Suitably validate chain
      def fetch_certificates(options)
        certs = self[:x5c]&.map { |c| OpenSSL::X509::Certificate.new(::Base64.strict_decode64(c)) }
        certs = options[:x5u_handler].call(self[:x5u]) if self[:x5u] && options[:x5u_handler]
        certs if certs&.first
      end

      # Extract certificate key usages
      def certificate_usages(certificate)
        certificate.extensions&.find { |ext| ext.oid == 'keyUsage' }&.value&.split("\n")
      end

      # Set standard thumbprint parameters
      def add_thumbprints(certificate)
        self[:x5t]        ||= ::Base64.urlsafe_encode64(OpenSSL::Digest.new('SHA1',   certificate.to_der).to_s)
        self[:'x5t#S256'] ||= ::Base64.urlsafe_encode64(OpenSSL::Digest.new('SHA256', certificate.to_der).to_s)
      end

      # Set standard use parameter
      # C.t. RFC 5280, Section 4.2.1.3
      # We do not care about encipherOnly and decipherOnly for the `use` param
      def add_usages(certificate)
        key_usages = certificate_usages(certificate)
        self[:use] ||= 'sig' unless (KEY_USAGES_SIG & [*key_usages]).empty?
        self[:use] ||= 'enc' unless (KEY_USAGES_ENC & [*key_usages]).empty?
      end

      # Tries to add a suitable key_ops parameter
      def add_key_operations(certificate)
        key_usages = certificate_usages(certificate)
        self[:key_ops] ||= ['verify']  unless ([*key_usages] & KEY_OPS_VERIFY).empty? # sign
        self[:key_ops] ||= ['encrypt'] unless ([*key_usages] & KEY_OPS_ENCRYPT).empty? # decrypt
        self[:key_ops] ||= ['wrapKey'] unless ([*key_usages] & KEY_OPS_WRAPKEY).empty? # unwrapKey
      end

      # Adds the private counterpart to key operations for private keys
      def add_private_key_operations
        return unless private? && self[:key_ops]

        self[:key_ops] << {
          'verify' => 'sign',
          'encrypt' => 'decrypt',
          'wrapKey' => 'unwrapKey'
        }[self[:key_ops].first]
        self[:key_ops].uniq!
      end

      # Adds a default algorithm to each key, depending on the type.
      def add_default_algorithm
        return unless self[:use] == 'sig' # Only signing algorithms supported

        self[:alg] = {
          'RSA' => 'RS512',
          'EC' => 'ES512',
          'oct' => 'HS512'
        }[self[:kty]]
      end
    end
  end
end
