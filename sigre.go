// Package sigre signs and verifies HTTP requests and responses using the wire
// format defined by draft-cavage-http-signatures-12. That Internet-Draft is
// expired and archived and is not an IETF standard. Package sigre does not
// implement RFC 9421 HTTP Message Signatures, whose fields and signature-base
// construction differ from the Cavage format.
//
// Create signatures with [NewCavageSigner] and the SignRequest, SignResponse,
// SignRequestWithHMAC, or SignResponseWithHMAC methods on [CavageSigner]. Every
// signing call receives a [SigningKey] or [HMACSigningKey] and an explicit
// [CavageSignaturePlacement].
//
// Construct a [CavageVerifier], parse a received signature with ParseRequest or
// ParseResponse, resolve the snapshot's KeyID to a trusted [VerificationKey] or
// [HMACVerificationKey], and then call Verify or VerifyHMAC. KeyID is an opaque,
// attacker-controlled wire value. The trusted [TrustedKeyMetadata.Algorithm]
// selects exactly one cryptographic algorithm; the received algorithm parameter
// is used only for consistency checks.
//
// Nil options use the defaults documented in [CavageSigningOptions] and
// [CavageVerificationOptions].
//
// Application policy such as required signed fields and maximum age is
// configured separately from explicit interoperability relaxations. Package
// sigre does not compute or verify a body Digest, retrieve keys, validate the
// relationship between a key and a principal, prevent replay, make
// authorization decisions, or provide transport security. Callers must perform
// those operations where their protocol requires them. A network key resolver
// must constrain schemes and origins, redirects, DNS and IP destinations,
// timeouts, response sizes, concurrency, caching, and TLS validation.
package sigre

const (
	// Authorization is the HTTP header used for Authorization: Signature placement.
	Authorization = "Authorization"
	// Signature is the HTTP header used for direct Cavage signature placement.
	Signature = "Signature"
)
