package sigre

import (
	"errors"
	"fmt"
)

// Use [errors.Is] to match errors against these sentinels. An error usually
// matches exactly one sentinel. Signing options that select a strict, legacy,
// or hs2019-with-SHA-256 representation incompatible with the trusted algorithm
// produce errors matching both [ErrInvalidSigningOptions] and
// [ErrInvalidSignatureAlgorithm]. The same applies when a signing algorithm
// label is incompatible with the chosen pseudo-headers. Failures in the
// cryptographic signing operation itself do not match any of these sentinels.
//
// Underlying errors included only as message text cannot be inspected with
// [errors.Is] or [errors.As]. The message text following a sentinel is not part
// of the compatibility guarantee; callers must not use it to classify errors.
var (
	// ErrInvalidHTTPMessage is returned when a request, response, or parsed
	// signature is nil, incomplete, or not valid for the requested operation.
	ErrInvalidHTTPMessage = errors.New("invalid HTTP message")
	// ErrMissingSignature is returned when no signature is found in the sources
	// selected for parsing. In the Cavage format, it is returned when no signature
	// candidate is found in the request sources selected by RequestSignatureSource
	// or in a response Signature field.
	ErrMissingSignature = errors.New("missing signature")
	// ErrSignatureSourceConflict is returned when the selected request sources or
	// a response Signature field contain more than one Cavage signature candidate.
	ErrSignatureSourceConflict = errors.New("conflicting signature sources")
	// ErrInvalidSignatureParameters is returned when signature parameters are
	// invalid or required parameters are missing. In the Cavage format, it is
	// returned when the parameters are malformed, duplicated, incomplete, or
	// contain invalid Base64.
	ErrInvalidSignatureParameters = errors.New("invalid signature parameters")
	// ErrInvalidSignatureAlgorithm is returned when a signature algorithm or its
	// representation is invalid or not permitted. In the Cavage format, it is
	// returned when a wire algorithm representation is invalid or disabled, a
	// trusted AlgorithmID is disallowed, an algorithm is incompatible with the
	// chosen pseudo-headers, or RequireAlgorithm is set and the algorithm parameter
	// is omitted.
	ErrInvalidSignatureAlgorithm = errors.New("invalid signature algorithm")
	// ErrUnsupportedKeyFormat is returned when a recognized key has an invalid format or length.
	ErrUnsupportedKeyFormat = errors.New("unsupported key format")
	// ErrInvalidExpirationTime is returned when expires is malformed or outside
	// the supported time range, or is missing while (expires) is signed.
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
	// ErrInvalidCreationTime is returned when a created parameter is malformed,
	// out of range, too far in the future, or older than MaxSignatureAge, or when
	// (created) is signed without a created parameter.
	ErrInvalidCreationTime = errors.New("invalid signature creation time")
	// ErrRequiredHeaderMissing is returned when a field required by the caller or
	// by a configured time policy is absent from the effective signed-header list,
	// or when RequireExplicitHeaders is set and the headers parameter is omitted.
	ErrRequiredHeaderMissing = errors.New("required header not listed in signature parameters")
	// ErrSignedHeaderMissing is returned when a field listed in the effective
	// signed-header list is absent from the HTTP message. A missing signed Date
	// field is reported as ErrInvalidDate when MaxDateAge is positive.
	ErrSignedHeaderMissing = errors.New("signed header missing from HTTP message")
	// ErrKeyIDMismatch is returned when the received keyId differs from trusted key metadata.
	ErrKeyIDMismatch = errors.New("signature keyId does not match trusted key metadata")
	// ErrInvalidKeyMetadata is returned when trusted key metadata is incomplete or unsupported.
	ErrInvalidKeyMetadata = errors.New("invalid trusted key metadata")
	// ErrInvalidVerificationOptions is returned when verification options contain an invalid value or conflicting values.
	ErrInvalidVerificationOptions = errors.New("invalid verification options")
	// ErrInvalidDate is returned when MaxDateAge is positive and the signed Date
	// field is missing, has multiple values, is malformed, or differs from the
	// current time by more than MaxDateAge.
	ErrInvalidDate = errors.New("invalid signed Date header")
	// ErrInvalidSignaturePlacement is returned when a signing placement is invalid
	// or would make the Cavage signature source ambiguous.
	ErrInvalidSignaturePlacement = errors.New("invalid signature placement")
	// ErrInvalidSigningOptions is returned when signing options are inconsistent
	// or select a wire representation that is incompatible with the trusted algorithm.
	ErrInvalidSigningOptions = errors.New("invalid signing options")
)

// Error wraps an internal error with package context.
// When an exported function or method reports an operation failure, the
// returned non-nil error is always an *Error.
type Error struct {
	// Err is the wrapped error. Use [errors.Is] or [errors.As] to inspect it.
	Err error
}

func wrapError(err error) error {
	if err == nil {
		return nil
	}
	var se *Error
	if errors.As(err, &se) {
		return err
	}
	return &Error{Err: err}
}

// Unwrap returns the error wrapped with sigre package context.
func (e *Error) Unwrap() error {
	return e.Err
}

// Error returns the wrapped error message with sigre package context.
func (e *Error) Error() string {
	return fmt.Sprintf("sigre error: %s", e.Err)
}
