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
	"fmt"
	"net/http"
)

// SignatureType identifies the HTTP signature scheme present in a message.
type SignatureType int

const (
	Unsigned             SignatureType = iota
	CavageHTTPSignatures               // draft-cavage-http-signatures-12
	RFC9421                            // HTTP Message Signatures; verification is not implemented yet.
)

// HTTP header name constants used in signature processing.
const (
	Authorization   = "Authorization"
	Signature       = "Signature"
	SignatureInput  = "Signature-Input"
	AcceptSignature = "Accept-Signature"
)

// Verifier verifies an HTTP message signature.
type Verifier interface {
	// KeyId returns the key identifier from the signature parameters.
	KeyId() string
	// Verify checks an asymmetric signature against a trusted key and algorithm.
	// Returns an error if the signature was created with HMAC; use [Verifier.VerifyHMAC] instead.
	Verify(key VerificationKey, opts *CavageVerificationOptions) error
	// VerifyHMAC checks an HMAC signature against a trusted secret and algorithm.
	// Returns an error if the signature was created with an asymmetric algorithm; use [Verifier.Verify] instead.
	VerifyHMAC(key HMACVerificationKey, opts *CavageVerificationOptions) error
}

// NewRequestVerifier creates a [Verifier] for req.
// It detects the signature scheme automatically from the request headers.
// Returns an error if no recognisable signature is present.
//
// To access Cavage-specific fields such as [CavageVerifier.Now], use
// [NewCavageRequestVerifier] instead.
func NewRequestVerifier(req *http.Request) (Verifier, error) {
	if _, _, err := cavageSignatureValue(req.Header); err != nil {
		return nil, wrapSigreError(err)
	}
	hf := GetSignatureHeaderFields(req.Header)
	switch hf.GetSignatureType() {
	case CavageHTTPSignatures:
		return NewCavageRequestVerifier(req)
	case RFC9421:
		return nil, wrapSigreError(fmt.Errorf("RFC9421 verifier not implemented"))
	default:
		return nil, wrapSigreError(ErrMissingSignature)
	}
}

// NewResponseVerifier creates a [Verifier] for res.
// It detects the signature scheme automatically from the response headers.
// Returns an error if no recognisable signature is present.
//
// To access Cavage-specific fields such as [CavageVerifier.Now], use
// [NewCavageResponseVerifier] instead.
func NewResponseVerifier(res *http.Response) (Verifier, error) {
	if _, _, err := cavageSignatureValue(res.Header); err != nil {
		return nil, wrapSigreError(err)
	}
	hf := GetSignatureHeaderFields(res.Header)
	switch hf.GetSignatureType() {
	case CavageHTTPSignatures:
		return NewCavageResponseVerifier(res)
	case RFC9421:
		return nil, wrapSigreError(fmt.Errorf("RFC9421 verifier not implemented"))
	default:
		return nil, wrapSigreError(ErrMissingSignature)
	}
}
