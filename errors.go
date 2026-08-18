package sigre

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidHTTPMessage is returned when a request, response, or parsed
	// signature is nil, incomplete, or not valid for the requested operation.
	ErrInvalidHTTPMessage = errors.New("invalid HTTP message")
	// ErrMissingSignature is returned when no HTTP signature is found in the message.
	ErrMissingSignature = errors.New("missing signature")
	// ErrSignatureSourceConflict is returned when more than one selected Cavage
	// signature source is present.
	ErrSignatureSourceConflict = errors.New("conflicting signature sources")
	// ErrInvalidSignatureParameters is returned when the Cavage signature
	// parameters are malformed, duplicated, incomplete, or contain invalid Base64.
	ErrInvalidSignatureParameters = errors.New("invalid signature parameters")
	// ErrInvalidSignatureAlgorithm is returned when a wire algorithm representation
	// is invalid or disabled, a trusted AlgorithmID is disallowed, or an algorithm
	// is incompatible with the chosen pseudo-headers.
	ErrInvalidSignatureAlgorithm = errors.New("invalid signature algorithm")
	// ErrUnsupportedKeyFormat is returned when a recognized key has an invalid format or length.
	ErrUnsupportedKeyFormat = errors.New("unsupported key format")
	// ErrInvalidExpirationTime is returned when an expires parameter is missing,
	// malformed, or outside the supported time range.
	ErrInvalidExpirationTime = errors.New("invalid signature expiration time")
	// ErrSignatureExpired is returned when a valid expires value is older than
	// the permitted boundary.
	ErrSignatureExpired = errors.New("signature expired")
	// ErrVerification is returned when cryptographic signature verification fails.
	ErrVerification = errors.New("verification error")
	// ErrMissingSharedSecret is returned when HMAC signing or verification is attempted without a secret.
	ErrMissingSharedSecret = errors.New("missing shared secret for HMAC")
	// ErrMissingPrivateKey is returned when signing is attempted without a private key.
	ErrMissingPrivateKey = errors.New("missing private key")
	// ErrMissingPublicKey is returned when verification is attempted without a public key.
	ErrMissingPublicKey = errors.New("missing public key")
	// ErrAlgorithmMismatch is returned when trusted algorithm metadata conflicts with
	// the signing or verification key kind, or with a received algorithm parameter.
	ErrAlgorithmMismatch = errors.New("algorithm mismatch for the given key")
	// ErrInvalidCreationTime is returned when a required (created) parameter is
	// missing, malformed, too far in the future, or older than MaxSignatureAge.
	ErrInvalidCreationTime = errors.New("invalid signature creation time")
	// ErrRequiredHeaderMissing is returned when a field required by the caller or
	// by a configured time policy is absent from the effective signed-header list.
	ErrRequiredHeaderMissing = errors.New("required header not listed in signature parameters")
	// ErrSignedHeaderMissing is returned when a field listed in the effective
	// signed-header list is absent from the HTTP message.
	ErrSignedHeaderMissing = errors.New("signed header missing from HTTP message")
	// ErrKeyIDMismatch is returned when the received keyId differs from trusted key metadata.
	ErrKeyIDMismatch = errors.New("signature keyId does not match trusted key metadata")
	// ErrInvalidKeyMetadata is returned when trusted key metadata is incomplete or unsupported.
	ErrInvalidKeyMetadata = errors.New("invalid trusted key metadata")
	// ErrInvalidVerificationOptions is returned when verification options contain an invalid value.
	ErrInvalidVerificationOptions = errors.New("invalid verification options")
	// ErrInvalidDate is returned when a signed Date value violates the configured freshness policy.
	ErrInvalidDate = errors.New("invalid signed Date header")
	// ErrInvalidSignaturePlacement is returned when a signing placement is invalid
	// or would make the Cavage signature source ambiguous.
	ErrInvalidSignaturePlacement = errors.New("invalid signature placement")
	// ErrInvalidSigningOptions is returned when signing options are inconsistent
	// or select a wire representation that is incompatible with the trusted algorithm.
	ErrInvalidSigningOptions = errors.New("invalid signing options")
)

// SigreError wraps an internal error with package context.
type SigreError struct {
	// Err is the wrapped error. Use [errors.Is] or [errors.As] to inspect it.
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

// Unwrap returns the error wrapped with sigre package context.
func (e *SigreError) Unwrap() error {
	return e.Err
}

// Error returns the wrapped error message with sigre package context.
func (e *SigreError) Error() string {
	return fmt.Sprintf("sigre error: %s", e.Err)
}
