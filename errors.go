package sigre

import (
	"errors"
	"fmt"
)

var (
	// ErrMissingSignature is returned when no HTTP signature is found in the message.
	ErrMissingSignature = errors.New("missing signature")
	// ErrInvalidSignatureAlgorithm is returned when the algorithm parameter is invalid
	// or incompatible with the chosen pseudo-headers.
	ErrInvalidSignatureAlgorithm = errors.New("invalid signature algorithm")
	// ErrUnsupportedHashAlgorithm is returned when the hash algorithm is not supported.
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")
	// ErrUnsupportedKeyFormat is returned when the key type is not supported.
	ErrUnsupportedKeyFormat = errors.New("unsupported key format")
	// ErrSignatureExpired is returned when the (expires) timestamp has passed.
	ErrSignatureExpired = errors.New("signature expired")
	// ErrVerification is returned when cryptographic signature verification fails.
	ErrVerification = errors.New("verification error")
	// ErrMissingSharedSecret is returned when HMAC verification is attempted without a secret.
	ErrMissingSharedSecret = errors.New("missing shared secret for HMAC")
	// ErrMissingPrivateKey is returned when signing is attempted without a private key.
	ErrMissingPrivateKey = errors.New("missing private key")
	// ErrMissingPublicKey is returned when verification is attempted without a public key.
	ErrMissingPublicKey = errors.New("missing public key")
	// ErrAlgorithmMismatch is returned when trusted algorithm metadata conflicts with
	// the verification key kind or the received algorithm parameter.
	ErrAlgorithmMismatch = errors.New("algorithm mismatch for the given key")
	// ErrInvalidCreationTime is returned when (created) violates a configured time policy.
	ErrInvalidCreationTime = errors.New("invalid signature creation time")
	// ErrRequiredHeaderMissing is returned when a required field is absent from the
	// effective signed-header list.
	ErrRequiredHeaderMissing = errors.New("required header not listed in signature parameters")
	// ErrKeyIDMismatch is returned when the received keyId differs from trusted key metadata.
	ErrKeyIDMismatch = errors.New("signature keyId does not match trusted key metadata")
	// ErrInvalidKeyMetadata is returned when trusted key metadata is incomplete or unsupported.
	ErrInvalidKeyMetadata = errors.New("invalid trusted key metadata")
	// ErrInvalidVerificationOptions is returned when verification options contain an invalid value.
	ErrInvalidVerificationOptions = errors.New("invalid verification options")
	// ErrInvalidDate is returned when a signed Date value violates the configured freshness policy.
	ErrInvalidDate = errors.New("invalid signed Date header")
)

// SigreError wraps an internal error with package context.
type SigreError struct {
	Err error
}

func wrapSigreError(err error) error {
	if err == nil {
		return nil
	}
	var se *SigreError
	if errors.As(err, &se) {
		return err
	}
	return &SigreError{Err: err}
}

func (e *SigreError) Unwrap() error {
	return e.Err
}

func (e *SigreError) Error() string {
	return fmt.Sprintf("sigre error: %s", e.Err)
}
