module JWT
  module Algos
    module None
      # Unsecured JWT
      module_function

      SUPPORTED = %w[none].freeze

      def sign(to_sign)
        raise EncodeError, 'Signing key not supported for Unsecured JWT' if to_sign.key
        ''
      end

      def verify(to_verify)
        raise VerificationError, 'Signing key not supported for Unsecured JWT' if to_verify.public_key
        raise VerificationError, 'Signature should be empty for Unsecured JWT' unless to_verify.signature == ''
        true
      end
    end
  end
end
