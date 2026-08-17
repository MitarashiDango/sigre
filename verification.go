package sigre

import (
	"crypto"
	"fmt"
	"strings"
	"time"
)

// AlgorithmID identifies one complete signature or MAC algorithm.
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

// TrustedKeyMetadata binds an opaque wire keyId to one trusted algorithm.
// The caller constructs this metadata from trusted configuration after resolving
// a received keyId; a received algorithm parameter never constructs it.
type TrustedKeyMetadata struct {
	// KeyID is serialized or compared byte-for-byte without normalization.
	KeyID string
	// Algorithm uniquely fixes the key kind, hash, and RSA padding where applicable.
	Algorithm AlgorithmID
}

// VerificationKey contains trusted metadata and an asymmetric public key.
type VerificationKey struct {
	// Metadata binds the received keyId to the only permitted verification algorithm.
	Metadata TrustedKeyMetadata
	// PublicKey is an RSA, ECDSA, or Ed25519 public key matching Metadata.Algorithm.
	PublicKey crypto.PublicKey
}

// HMACVerificationKey contains trusted metadata and an HMAC shared secret.
type HMACVerificationKey struct {
	// Metadata binds the received keyId to the only permitted HMAC algorithm.
	Metadata TrustedKeyMetadata
	// Secret is the non-empty shared secret used for HMAC verification.
	Secret []byte
}

// CavageRequestSignatureSource selects the Cavage signature field parsed from
// an HTTP request. The zero value selects only the Signature field.
type CavageRequestSignatureSource uint8

const (
	// CavageRequestSignatureSourceSignature parses only the Signature field.
	CavageRequestSignatureSourceSignature CavageRequestSignatureSource = iota
	// CavageRequestSignatureSourceAuthorization parses only Authorization values
	// whose authentication scheme is Signature.
	CavageRequestSignatureSourceAuthorization
	// CavageRequestSignatureSourceSignatureOrAuthorization accepts either source
	// and rejects a request containing candidates in both sources.
	CavageRequestSignatureSourceSignatureOrAuthorization
)

// CavageVerificationOptions configures Cavage HTTP signature verification.
// Passing nil is equivalent to the strict zero value: only
// AlgorithmRSAPKCS1v15SHA512, AlgorithmECDSASHA512, AlgorithmEd25519, and
// AlgorithmHMACSHA512 are accepted; omitted algorithm and headers parameters
// are accepted; omitted headers means (created); and no application age policy
// is added. A SHA-256 AlgorithmID must be listed in AllowedAlgorithms, and a
// deprecated label additionally requires AllowedLegacyAlgorithms.
type CavageVerificationOptions struct {
	// RequestSignatureSource selects the request field parsed as a Cavage
	// signature. It does not affect response parsing, which always uses Signature.
	RequestSignatureSource CavageRequestSignatureSource
	// RequiredHeaders requires each field to already be in the effective
	// signed-header list. It never adds a field to that list.
	RequiredHeaders []string
	// AllowedAlgorithms is the complete set of trusted algorithms accepted by the
	// application when non-empty. Nil or empty selects the four strict defaults.
	// It never selects the verification algorithm or enables a wire label.
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
	// Now supplies the current time used by ParseRequest and ParseResponse. It is
	// called exactly once when a valid time comparison is required and is not
	// called otherwise. Nil uses time.Now.
	Now func() time.Time

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
	// AllowedLegacyAlgorithms explicitly enables the corresponding deprecated
	// SHA-256 wire labels. Each AlgorithmID must also appear in AllowedAlgorithms.
	AllowedLegacyAlgorithms []AlgorithmID
	// ExtensionAlgorithms maps an exact wire label to one trusted algorithm. The
	// mapped AlgorithmID must also be allowed and must equal trusted key metadata.
	ExtensionAlgorithms map[string]AlgorithmID
	// AllowHS2019WithSHA256 permits the Fediverse hs2019 interpretation only for
	// RSA PKCS #1 v1.5 with SHA-256. That AlgorithmID must also be allowed.
	AllowHS2019WithSHA256 bool
}

type algorithmKeyKind uint8

const (
	algorithmKeyRSA algorithmKeyKind = iota + 1
	algorithmKeyECDSA
	algorithmKeyEd25519
	algorithmKeyHMAC
)

type algorithmDefinition struct {
	id      AlgorithmID
	keyKind algorithmKeyKind
	hash    crypto.Hash
}

func algorithmDefinitionFor(id AlgorithmID) (algorithmDefinition, error) {
	switch id {
	case AlgorithmRSAPKCS1v15SHA512:
		return algorithmDefinition{id: id, keyKind: algorithmKeyRSA, hash: crypto.SHA512}, nil
	case AlgorithmRSAPKCS1v15SHA256:
		return algorithmDefinition{id: id, keyKind: algorithmKeyRSA, hash: crypto.SHA256}, nil
	case AlgorithmECDSASHA512:
		return algorithmDefinition{id: id, keyKind: algorithmKeyECDSA, hash: crypto.SHA512}, nil
	case AlgorithmECDSASHA256:
		return algorithmDefinition{id: id, keyKind: algorithmKeyECDSA, hash: crypto.SHA256}, nil
	case AlgorithmEd25519:
		return algorithmDefinition{id: id, keyKind: algorithmKeyEd25519}, nil
	case AlgorithmHMACSHA512:
		return algorithmDefinition{id: id, keyKind: algorithmKeyHMAC, hash: crypto.SHA512}, nil
	case AlgorithmHMACSHA256:
		return algorithmDefinition{id: id, keyKind: algorithmKeyHMAC, hash: crypto.SHA256}, nil
	default:
		return algorithmDefinition{}, fmt.Errorf("%w: unsupported AlgorithmID %d", ErrInvalidKeyMetadata, id)
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

func isReservedCavageAlgorithmLabel(label string) bool {
	switch label {
	case hs2019, "rsa-sha1", "rsa-sha256", "ecdsa-sha256", "hmac-sha256":
		return true
	default:
		return false
	}
}

func legacyAlgorithmID(label string) (AlgorithmID, bool) {
	switch label {
	case "rsa-sha256":
		return AlgorithmRSAPKCS1v15SHA256, true
	case "ecdsa-sha256":
		return AlgorithmECDSASHA256, true
	case "hmac-sha256":
		return AlgorithmHMACSHA256, true
	default:
		return 0, false
	}
}

func legacyAlgorithmLabel(id AlgorithmID) (string, bool) {
	switch id {
	case AlgorithmRSAPKCS1v15SHA256:
		return "rsa-sha256", true
	case AlgorithmECDSASHA256:
		return "ecdsa-sha256", true
	case AlgorithmHMACSHA256:
		return "hmac-sha256", true
	default:
		return "", false
	}
}

func legacyAlgorithmFamily(label string) string {
	switch {
	case strings.HasPrefix(label, "rsa"):
		return "rsa"
	case strings.HasPrefix(label, "hmac"):
		return "hmac"
	case strings.HasPrefix(label, "ecdsa"):
		return "ecdsa"
	default:
		return ""
	}
}
