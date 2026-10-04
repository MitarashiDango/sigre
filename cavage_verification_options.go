package sigre

import "time"

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
// AlgorithmRSAPKCS1v15SHA512, AlgorithmECDSAASN1SHA512, AlgorithmEd25519, and
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
	// Zero disables this policy. The exact boundary is accepted without
	// truncation to whole seconds.
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
	// Otherwise, [NewCavageVerifier] returns [ErrInvalidVerificationOptions].
	AllowedLegacyAlgorithms []AlgorithmID
	// ExtensionAlgorithms maps an exact wire label to one trusted algorithm. The
	// mapped AlgorithmID must also be allowed; otherwise, [NewCavageVerifier]
	// returns [ErrInvalidVerificationOptions]. [CavageVerifier.Verify] and
	// [CavageVerifier.VerifyHMAC] check that it equals the trusted key's AlgorithmID.
	ExtensionAlgorithms map[string]AlgorithmID
	// AllowHS2019WithSHA256 permits the Fediverse hs2019 interpretation only for
	// RSA PKCS #1 v1.5 with SHA-256. That AlgorithmID must also be allowed.
	// Otherwise, [NewCavageVerifier] returns [ErrInvalidVerificationOptions].
	AllowHS2019WithSHA256 bool
}
