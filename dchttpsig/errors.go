package dchttpsig

import (
	"errors"
)

var (
	ErrInvalidSignatureAlgorithm = errors.New("invalid signature algorithm")
	ErrUnsupportedHashAlgorithm  = errors.New("unsupported hash algorithm")
	ErrUnsupportedKeyFormat      = errors.New("unsupported key format")
	ErrSignatureExpired          = errors.New("signature expired")
	ErrVerification              = errors.New("verification error")
	ErrMissingSharedSecret       = errors.New("missing shared secret for HMAC")
	ErrMissingPrivateKey         = errors.New("missing private key")
	ErrMissingPublicKey          = errors.New("missing public key")
	ErrAlgorithmMismatch         = errors.New("algorithm mismatch for the given key")
	ErrInvalidCreationTime       = errors.New("signature creation time is outside allowed clock skew")
	ErrRequiredHeaderMissing     = errors.New("required header not listed in signature parameters")
)
