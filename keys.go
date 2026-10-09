package sigre

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"math"
)

// TrustedKeyMetadata binds an opaque wire keyId to one trusted algorithm.
// The caller supplies this metadata from trusted configuration for signing
// or verification; it must not be derived from a received algorithm parameter.
// An empty KeyID or an unsupported Algorithm is rejected with
// [ErrInvalidKeyMetadata].
type TrustedKeyMetadata struct {
	// KeyID is serialized or compared byte-for-byte without normalization.
	// Signing also rejects a KeyID containing a byte that cannot appear in an
	// HTTP field value.
	KeyID string
	// Algorithm uniquely fixes the key kind, hash, and RSA padding where applicable.
	Algorithm AlgorithmID
}

// VerificationKey contains trusted metadata and an asymmetric public key.
// An HMAC [AlgorithmID] causes [ErrAlgorithmMismatch]; use [HMACVerificationKey]
// for HMAC verification.
type VerificationKey struct {
	// Metadata binds the received keyId to the only permitted verification algorithm.
	Metadata TrustedKeyMetadata
	// PublicKey is a *[rsa.PublicKey], *[ecdsa.PublicKey], or [ed25519.PublicKey]
	// matching Metadata.Algorithm; *[ed25519.PublicKey] is also accepted. A nil
	// key or a zero-length Ed25519 key causes [ErrMissingPublicKey], a key of
	// another kind causes [ErrAlgorithmMismatch], and a malformed key or an ECDSA
	// key on a curve that crypto/ecdsa does not support causes [ErrUnsupportedKeyFormat].
	PublicKey crypto.PublicKey
}

// HMACVerificationKey contains trusted metadata and an HMAC shared secret.
// A non-HMAC [AlgorithmID] causes [ErrAlgorithmMismatch].
type HMACVerificationKey struct {
	// Metadata binds the received keyId to the only permitted HMAC algorithm.
	Metadata TrustedKeyMetadata
	// Secret is the non-empty shared secret used for HMAC verification.
	// An empty Secret causes [ErrMissingSharedSecret].
	Secret []byte
}

// SigningKey contains trusted metadata and an asymmetric private key.
// Metadata.Algorithm determines the key kind, hash, and RSA padding.
// An HMAC [AlgorithmID] causes [ErrAlgorithmMismatch]; use [HMACSigningKey]
// for HMAC signing.
type SigningKey struct {
	// Metadata binds the wire keyId to the only algorithm used for signing.
	Metadata TrustedKeyMetadata
	// PrivateKey is a *[rsa.PrivateKey], *[ecdsa.PrivateKey], or [ed25519.PrivateKey]
	// matching Metadata.Algorithm; *[ed25519.PrivateKey] is also accepted. An ECDSA
	// key may use any curve that crypto/ecdsa supports, independent of the hash
	// selected by Metadata.Algorithm. A nil key or a zero-length Ed25519 key causes
	// [ErrMissingPrivateKey], a key of another kind causes [ErrAlgorithmMismatch],
	// and a malformed key or an ECDSA key on a curve that crypto/ecdsa does not
	// support causes [ErrUnsupportedKeyFormat].
	PrivateKey crypto.PrivateKey
}

// HMACSigningKey contains trusted metadata and an HMAC shared secret.
// Metadata.Algorithm determines the HMAC hash.
// A non-HMAC [AlgorithmID] causes [ErrAlgorithmMismatch].
type HMACSigningKey struct {
	// Metadata binds the wire keyId to the only HMAC algorithm used for signing.
	Metadata TrustedKeyMetadata
	// Secret is the non-empty shared secret used for HMAC signing.
	// An empty Secret causes [ErrMissingSharedSecret].
	Secret []byte
}

func normalizeEd25519PrivateKey(key crypto.PrivateKey) crypto.PrivateKey {
	privateKey, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return key
	}
	if privateKey == nil {
		return ed25519.PrivateKey(nil)
	}
	return *privateKey
}

func validatePrivateKey(key crypto.PrivateKey, expected algorithmKeyKind) error {
	switch expected {
	case algorithmKeyRSA:
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires RSA, private key is %T", ErrAlgorithmMismatch, key)
		}
		if privateKey == nil {
			return ErrMissingPrivateKey
		}
		if privateKey.N == nil || privateKey.D == nil {
			return fmt.Errorf("%w: invalid RSA private key", ErrUnsupportedKeyFormat)
		}
	case algorithmKeyECDSA:
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires ECDSA, private key is %T", ErrAlgorithmMismatch, key)
		}
		if privateKey == nil {
			return ErrMissingPrivateKey
		}
		// Intentionally inspect the deprecated X, Y, and D fields: SignASN1 and
		// PrivateKey.Bytes can panic when key fields are nil.
		if privateKey.Curve == nil || privateKey.X == nil || privateKey.Y == nil || privateKey.D == nil {
			return fmt.Errorf("%w: invalid ECDSA private key", ErrUnsupportedKeyFormat)
		}
		if _, err := privateKey.Bytes(); err != nil {
			return fmt.Errorf("%w: invalid ECDSA private key", ErrUnsupportedKeyFormat)
		}
	case algorithmKeyEd25519:
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires Ed25519, private key is %T", ErrAlgorithmMismatch, key)
		}
		if len(privateKey) == 0 {
			return ErrMissingPrivateKey
		}
		if len(privateKey) != ed25519.PrivateKeySize {
			return fmt.Errorf("%w: invalid Ed25519 private key length %d", ErrUnsupportedKeyFormat, len(privateKey))
		}
	default:
		return fmt.Errorf("%w: SigningKey received a non-asymmetric AlgorithmID", ErrAlgorithmMismatch)
	}
	return nil
}

func normalizeEd25519PublicKey(key crypto.PublicKey) crypto.PublicKey {
	publicKey, ok := key.(*ed25519.PublicKey)
	if !ok {
		return key
	}
	if publicKey == nil {
		return ed25519.PublicKey(nil)
	}
	return *publicKey
}

func isMissingPublicKey(key crypto.PublicKey) bool {
	if key == nil {
		return true
	}
	switch publicKey := key.(type) {
	case *rsa.PublicKey:
		return publicKey == nil
	case *ecdsa.PublicKey:
		return publicKey == nil
	case ed25519.PublicKey:
		return len(publicKey) == 0
	default:
		return false
	}
}

func validateVerificationPublicKey(key crypto.PublicKey, expected algorithmKeyKind) error {
	switch expected {
	case algorithmKeyRSA:
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires RSA, public key is %T", ErrAlgorithmMismatch, key)
		}
		if publicKey.N == nil || publicKey.N.Sign() <= 0 || publicKey.N.Bit(0) == 0 || publicKey.E < 2 || publicKey.E&1 == 0 || publicKey.E > math.MaxInt32 {
			return fmt.Errorf("%w: invalid RSA public key", ErrUnsupportedKeyFormat)
		}
	case algorithmKeyECDSA:
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires ECDSA, public key is %T", ErrAlgorithmMismatch, key)
		}
		// Intentionally inspect the deprecated X and Y fields: VerifyASN1 and
		// PublicKey.Bytes can panic when key fields are nil.
		if publicKey.Curve == nil || publicKey.X == nil || publicKey.Y == nil {
			return fmt.Errorf("%w: invalid ECDSA public key", ErrUnsupportedKeyFormat)
		}
		if _, err := publicKey.Bytes(); err != nil {
			return fmt.Errorf("%w: invalid ECDSA public key", ErrUnsupportedKeyFormat)
		}
	case algorithmKeyEd25519:
		publicKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires Ed25519, public key is %T", ErrAlgorithmMismatch, key)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: invalid Ed25519 public key length %d", ErrUnsupportedKeyFormat, len(publicKey))
		}
	default:
		return fmt.Errorf("%w: asymmetric verification received a non-public-key AlgorithmID", ErrAlgorithmMismatch)
	}
	return nil
}
