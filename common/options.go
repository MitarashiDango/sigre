package common

import (
	"crypto"
	"time"
)

type SignOptions struct {
	KeyId             string
	PrivateKey        crypto.PrivateKey // For asymmetric algorithms
	SharedSecret      []byte            // For HMAC
	SignTargetHeaders []string          // Headers to include in the signature string
	SignType          SignType
	HashAlgorithm     crypto.Hash      // Hash algorithm (e.g., crypto.SHA256), ignored for Ed25519 signing
	Expiry            int64            // Expiration time in seconds from creation
	SignatureHeader   string           // Header name for the signature (e.g., "Signature" or "Authorization")
	NowFunc           func() time.Time // For debugging and testing
}

type VerifyOptions struct {
	PublicKey        crypto.PublicKey // For asymmetric algorithms
	SharedSecret     []byte           // For HMAC
	AllowedClockSkew time.Duration    // For validating (created) and (expires)
	RequiredHeaders  []string         // To enforce presence of certain headers in the signature parameters
	NowFunc          func() time.Time // For debugging and testing
}
