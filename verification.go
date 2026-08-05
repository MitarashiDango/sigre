package sigre

import (
	"crypto"
	"fmt"
	"time"
)

// AlgorithmID identifies one complete cryptographic verification algorithm.
// Each value fixes the key type, hash function, and RSA padding where applicable.
// The zero value is invalid.
type AlgorithmID uint16

const (
	// AlgorithmRSAPKCS1v15SHA512 identifies RSA PKCS #1 v1.5 with SHA-512.
	AlgorithmRSAPKCS1v15SHA512 AlgorithmID = iota + 1
	// AlgorithmRSAPKCS1v15SHA256 identifies RSA PKCS #1 v1.5 with SHA-256.
	AlgorithmRSAPKCS1v15SHA256
	// AlgorithmECDSASHA512 identifies ECDSA with SHA-512 and an ASN.1 signature.
	AlgorithmECDSASHA512
	// AlgorithmECDSASHA256 identifies ECDSA with SHA-256 and an ASN.1 signature.
	AlgorithmECDSASHA256
	// AlgorithmEd25519 identifies plain Ed25519 over the un-hashed signing string.
	AlgorithmEd25519
	// AlgorithmHMACSHA512 identifies HMAC with SHA-512.
	AlgorithmHMACSHA512
	// AlgorithmHMACSHA256 identifies HMAC with SHA-256.
	AlgorithmHMACSHA256
)

// TrustedKeyMetadata binds an opaque key identifier to one trusted algorithm.
// KeyID is compared with the received keyId byte-for-byte without normalization.
type TrustedKeyMetadata struct {
	KeyID     string
	Algorithm AlgorithmID
}

// VerificationKey contains trusted metadata and an asymmetric public key.
type VerificationKey struct {
	Metadata  TrustedKeyMetadata
	PublicKey crypto.PublicKey
}

// HMACVerificationKey contains trusted metadata and an HMAC shared secret.
type HMACVerificationKey struct {
	Metadata TrustedKeyMetadata
	Secret   []byte
}

// CavageVerificationOptions configures Cavage HTTP signature verification.
// Passing nil is equivalent to the strict zero value: only active draft-12
// algorithms are accepted, omitted algorithm and headers parameters are accepted,
// omitted headers means (created), and no application age policy is added.
type CavageVerificationOptions struct {
	// RequiredHeaders adds application-required fields to the effective signed-header list.
	RequiredHeaders []string
	// AllowedAlgorithms further restricts the trusted algorithms accepted by the application.
	// It never selects the verification algorithm.
	AllowedAlgorithms []AlgorithmID
	// RequireAlgorithm rejects a signature that omits the algorithm parameter.
	RequireAlgorithm bool
	// RequireExplicitHeaders rejects a signature that omits the headers parameter.
	RequireExplicitHeaders bool
	// MaxSignatureAge limits the elapsed time since signed (created). A positive value
	// requires (created) in the effective signed-header list and a valid created parameter.
	// Zero disables this policy. The inclusive boundary is evaluated as a time.Duration
	// without truncation to whole seconds.
	MaxSignatureAge time.Duration
	// MaxDateAge limits the absolute difference between a single valid signed Date value and
	// the verifier's current time. A positive value requires exactly one Date value and date
	// in the effective signed-header list. It applies equally to past and future Date values,
	// includes the exact boundary, and is evaluated without truncation to whole seconds.
	// Zero disables it.
	MaxDateAge time.Duration

	// Compatibility contains explicit relaxations of the strict draft-12 behaviour.
	Compatibility *CavageVerificationCompatibility
}

// CavageVerificationCompatibility configures explicit interoperability relaxations.
type CavageVerificationCompatibility struct {
	// AllowedCreatedFutureSkew permits (created) up to this duration in the future.
	// The exact boundary is accepted without truncating the duration to whole seconds.
	AllowedCreatedFutureSkew time.Duration
	// AllowedExpiredSkew permits (expires) up to this duration in the past.
	// The exact boundary is accepted without truncating the duration to whole seconds.
	AllowedExpiredSkew time.Duration
	// AllowedLegacyAlgorithms explicitly enables the corresponding deprecated SHA-256
	// algorithms and their wire labels.
	AllowedLegacyAlgorithms []AlgorithmID
	// ExtensionAlgorithms maps an exact wire label to one trusted algorithm. The mapped
	// AlgorithmID must equal the AlgorithmID in trusted key metadata.
	ExtensionAlgorithms map[string]AlgorithmID
	// AllowHS2019WithSHA256 permits the Fediverse hs2019 interpretation only for
	// RSA PKCS #1 v1.5 with SHA-256.
	AllowHS2019WithSHA256 bool
}

type algorithmKeyKind uint8

const (
	algorithmKeyRSA algorithmKeyKind = iota + 1
	algorithmKeyECDSA
	algorithmKeyEd25519
	algorithmKeyHMAC
)

type verificationAlgorithm struct {
	id      AlgorithmID
	keyKind algorithmKeyKind
	hash    crypto.Hash
}

func verificationAlgorithmFor(id AlgorithmID) (verificationAlgorithm, error) {
	switch id {
	case AlgorithmRSAPKCS1v15SHA512:
		return verificationAlgorithm{id: id, keyKind: algorithmKeyRSA, hash: crypto.SHA512}, nil
	case AlgorithmRSAPKCS1v15SHA256:
		return verificationAlgorithm{id: id, keyKind: algorithmKeyRSA, hash: crypto.SHA256}, nil
	case AlgorithmECDSASHA512:
		return verificationAlgorithm{id: id, keyKind: algorithmKeyECDSA, hash: crypto.SHA512}, nil
	case AlgorithmECDSASHA256:
		return verificationAlgorithm{id: id, keyKind: algorithmKeyECDSA, hash: crypto.SHA256}, nil
	case AlgorithmEd25519:
		return verificationAlgorithm{id: id, keyKind: algorithmKeyEd25519}, nil
	case AlgorithmHMACSHA512:
		return verificationAlgorithm{id: id, keyKind: algorithmKeyHMAC, hash: crypto.SHA512}, nil
	case AlgorithmHMACSHA256:
		return verificationAlgorithm{id: id, keyKind: algorithmKeyHMAC, hash: crypto.SHA256}, nil
	default:
		return verificationAlgorithm{}, fmt.Errorf("%w: unsupported AlgorithmID %d", ErrInvalidKeyMetadata, id)
	}
}

func isStrictCavageAlgorithm(id AlgorithmID) bool {
	switch id {
	case AlgorithmRSAPKCS1v15SHA512, AlgorithmECDSASHA512, AlgorithmEd25519, AlgorithmHMACSHA512:
		return true
	default:
		return false
	}
}

func isLegacyCavageAlgorithm(id AlgorithmID) bool {
	switch id {
	case AlgorithmRSAPKCS1v15SHA256, AlgorithmECDSASHA256, AlgorithmHMACSHA256:
		return true
	default:
		return false
	}
}
