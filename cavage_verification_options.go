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
// [AlgorithmRSAPKCS1v15SHA512], [AlgorithmECDSAASN1SHA512], [AlgorithmEd25519], and
// [AlgorithmHMACSHA512] are accepted; omitted algorithm and headers parameters
// are accepted; omitted headers means (created); and no application age policy
// is added. A SHA-256 AlgorithmID must be listed in AllowedAlgorithms, and a
// deprecated label additionally requires
// [CavageVerificationCompatibility.AllowedLegacyAlgorithms].
// The created and expires parameters are checked whenever present, even if
// (created) or (expires) is not signed.
//
// A received algorithm label is accepted only if it is hs2019 with a permitted
// algorithm, a deprecated label enabled by
// [CavageVerificationCompatibility.AllowedLegacyAlgorithms], or a label in
// [CavageVerificationCompatibility.ExtensionAlgorithms]. Labels are case-sensitive;
// any other label causes parsing to fail with [ErrInvalidSignatureAlgorithm].
// Labels starting with rsa, hmac, or ecdsa also cause [ErrInvalidSignatureAlgorithm]
// if (created) or (expires) is signed.
type CavageVerificationOptions struct {
	// RequestSignatureSource selects the request field parsed as a Cavage
	// signature. It does not affect response parsing, which always uses Signature.
	RequestSignatureSource CavageRequestSignatureSource
	// RequiredHeaders requires each field to already be in the effective
	// signed-header list; otherwise, parsing fails with [ErrRequiredHeaderMissing].
	// It never adds a field to that list. Names are case-insensitive and follow the
	// field-name rules of [CavageSigningOptions.AdditionalHeaders]. Invalid names
	// are rejected by [NewCavageVerifier] with [ErrInvalidVerificationOptions].
	RequiredHeaders []string
	// AllowedAlgorithms is the complete set of trusted algorithms accepted by the
	// application when non-empty. Nil or empty selects the four strict defaults.
	// It never selects the verification algorithm or enables a wire label.
	// An unsupported [AlgorithmID] causes [NewCavageVerifier] to fail with
	// [ErrInvalidVerificationOptions].
	AllowedAlgorithms []AlgorithmID
	// RequireAlgorithm rejects a signature that omits the algorithm parameter
	// with [ErrInvalidSignatureAlgorithm].
	RequireAlgorithm bool
	// RequireExplicitHeaders rejects a signature that omits the headers parameter
	// with [ErrRequiredHeaderMissing].
	RequireExplicitHeaders bool
	// MaxSignatureAge limits the elapsed time since signed (created). A positive value
	// requires (created) in the effective signed-header list and a valid created parameter.
	// Zero disables this policy. The exact boundary is accepted without
	// truncation to whole seconds.
	// A negative value is invalid. With a positive limit, parsing fails with
	// [ErrRequiredHeaderMissing] if (created) is not signed, or with
	// [ErrInvalidCreationTime] if the age exceeds the limit.
	MaxSignatureAge time.Duration
	// MaxDateAge limits the absolute difference between a single valid signed Date value and
	// the verifier's current time. A positive value requires exactly one Date value and date
	// in the effective signed-header list. It applies equally to past and future Date values,
	// includes the exact boundary, and is evaluated without truncation to whole seconds.
	// Zero disables it. A negative value is invalid. With a positive limit,
	// parsing fails with [ErrRequiredHeaderMissing] if date is not signed, or with
	// [ErrInvalidDate] if Date is missing, has multiple values, has an invalid
	// format, or differs from the current time by more than the limit.
	// Accepted formats are those of [http.ParseTime].
	MaxDateAge time.Duration
	// Now supplies the current time for the created, expires, and Date checks of
	// [CavageVerifier.ParseRequest] and [CavageVerifier.ParseResponse]. It is called
	// at most once per parse, only after all checks that do not depend on the
	// current time have passed, and only when a created or expires parameter is
	// present or MaxDateAge is positive. [NewCavageVerifier], [CavageVerifier.Verify],
	// and [CavageVerifier.VerifyHMAC] never call it. Nil uses [time.Now].
	Now func() time.Time

	// Compatibility contains explicit relaxations of the strict draft-12 behavior.
	Compatibility *CavageVerificationCompatibility
}

// CavageVerificationCompatibility configures explicit interoperability relaxations.
type CavageVerificationCompatibility struct {
	// AllowedCreatedFutureSkew permits created up to this duration in the future.
	// The exact boundary is accepted without truncating the duration to whole seconds.
	// Zero rejects every future created value with [ErrInvalidCreationTime].
	// A negative value is invalid.
	AllowedCreatedFutureSkew time.Duration
	// AllowedExpiredSkew permits expires up to this duration in the past.
	// The exact boundary is accepted without truncating the duration to whole seconds.
	// Zero rejects a signature with [ErrSignatureExpired] as soon as the current
	// time is later than expires. A negative value is invalid.
	AllowedExpiredSkew time.Duration
	// AllowedLegacyAlgorithms explicitly enables the corresponding deprecated
	// SHA-256 wire labels. Each AlgorithmID must also appear in AllowedAlgorithms.
	// Otherwise, [NewCavageVerifier] returns [ErrInvalidVerificationOptions].
	AllowedLegacyAlgorithms []AlgorithmID
	// ExtensionAlgorithms maps an exact wire label to one trusted algorithm. The
	// mapped AlgorithmID must also be allowed; otherwise, [NewCavageVerifier]
	// returns [ErrInvalidVerificationOptions]. [CavageVerifier.Verify] and
	// [CavageVerifier.VerifyHMAC] check that it equals the trusted key's AlgorithmID.
	// Labels follow the Label restrictions of [CavageExtensionAlgorithm]; an
	// invalid label causes [NewCavageVerifier] to fail with [ErrInvalidVerificationOptions].
	ExtensionAlgorithms map[string]AlgorithmID
	// AllowHS2019WithSHA256 permits the Fediverse hs2019 interpretation only for
	// RSA PKCS #1 v1.5 with SHA-256. That AlgorithmID must also be allowed.
	// Otherwise, [NewCavageVerifier] returns [ErrInvalidVerificationOptions].
	AllowHS2019WithSHA256 bool
}
