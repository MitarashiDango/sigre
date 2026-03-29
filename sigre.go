// Package sigre provides HTTP message signing and verification.
//
// It currently implements draft-cavage-http-signatures-12 via [CavageSigner].
// RFC9421 (https://datatracker.ietf.org/doc/html/rfc9421) support is planned.
//
// To verify a signed HTTP request or response, call [NewRequestVerifier] or
// [NewResponseVerifier]; the returned [Verifier] detects the scheme automatically.
// For Cavage-specific features such as a custom time source, use
// [NewCavageRequestVerifier] or [NewCavageResponseVerifier] directly.
package sigre

import (
	"crypto"
	"fmt"
	"net/http"
	"time"
)

// SignatureType identifies the HTTP signature scheme present in a message.
type SignatureType int

const (
	Unsigned             SignatureType = iota
	CavageHTTPSignatures               // draft-cavage-http-signatures-12
	RFC9421                            // TODO: not yet implemented
)

// HTTP header name constants used in signature processing.
const (
	Authorization   = "Authorization"
	Signature       = "Signature"
	SignatureInput  = "Signature-Input"
	AcceptSignature = "Accept-Signature"
)

// VerifyOptions configures signature verification behaviour.
// Passing nil is equivalent to passing a zero-value VerifyOptions.
type VerifyOptions struct {
	// AllowedClockSkew sets the tolerance window for (created) and (expires) checks.
	// A zero value disables the "too old" check while still rejecting future (created) timestamps.
	AllowedClockSkew time.Duration
	// RequiredHeaders lists header names that must appear in the signature's headers parameter.
	RequiredHeaders []string
}

// Verifier verifies an HTTP message signature.
type Verifier interface {
	// KeyId returns the key identifier from the signature parameters.
	KeyId() string
	// Verify checks an asymmetric signature (RSA, ECDSA, Ed25519) against key.
	// Returns an error if the signature was created with HMAC; use [Verifier.VerifyHMAC] instead.
	Verify(key crypto.PublicKey, opts *VerifyOptions) error
	// VerifyHMAC checks an HMAC signature against secret.
	// Returns an error if the signature was created with an asymmetric algorithm; use [Verifier.Verify] instead.
	VerifyHMAC(secret []byte, opts *VerifyOptions) error
}

// NewRequestVerifier creates a [Verifier] for req.
// It detects the signature scheme automatically from the request headers.
// Returns an error if no recognisable signature is present.
//
// To access Cavage-specific fields such as [CavageVerifier.Now], use
// [NewCavageRequestVerifier] instead.
func NewRequestVerifier(req *http.Request) (Verifier, error) {
	hf := GetSignatureHeaderFields(req.Header)
	switch hf.GetSignatureType() {
	case CavageHTTPSignatures:
		return NewCavageRequestVerifier(req)
	case RFC9421:
		return nil, &SigreError{Err: fmt.Errorf("RFC9421 verifier not implemented")}
	default:
		return nil, &SigreError{Err: ErrMissingSignature}
	}
}

// NewResponseVerifier creates a [Verifier] for res.
// It detects the signature scheme automatically from the response headers.
// Returns an error if no recognisable signature is present.
//
// To access Cavage-specific fields such as [CavageVerifier.Now], use
// [NewCavageResponseVerifier] instead.
func NewResponseVerifier(res *http.Response) (Verifier, error) {
	hf := GetSignatureHeaderFields(res.Header)
	switch hf.GetSignatureType() {
	case CavageHTTPSignatures:
		return NewCavageResponseVerifier(res)
	case RFC9421:
		return nil, &SigreError{Err: fmt.Errorf("RFC9421 verifier not implemented")}
	default:
		return nil, &SigreError{Err: ErrMissingSignature}
	}
}
