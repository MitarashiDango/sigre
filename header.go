package sigre

import (
	"net/http"
	"strings"
)

// SignatureHeaderFields holds the signature-related header values extracted from an HTTP message.
type SignatureHeaderFields struct {
	Signature       string
	SignatureInput  string
	AcceptSignature string
}

// GetSignatureHeaderFields extracts signature-related header values from h.
// The Signature field is populated from the "Signature" header when present, or from
// an "Authorization: Signature ..." header as a fallback.
func GetSignatureHeaderFields(h http.Header) *SignatureHeaderFields {
	hf := new(SignatureHeaderFields)

	if v := h.Get(Signature); v != "" {
		hf.Signature = v
	} else if v := h.Get(Authorization); v != "" && strings.HasPrefix(v, Signature+" ") {
		hf.Signature = strings.TrimSpace(strings.TrimPrefix(v, Signature+" "))
	}

	if v := h.Get(SignatureInput); v != "" {
		hf.SignatureInput = v
	}

	if v := h.Get(AcceptSignature); v != "" {
		hf.AcceptSignature = v
	}

	return hf
}

// GetSignatureType determines the HTTP signature scheme from the header fields.
// Both Signature and Signature-Input present indicates RFC9421.
// Signature alone (or via Authorization) indicates draft-cavage-http-signatures-12.
func (hf *SignatureHeaderFields) GetSignatureType() SignatureType {
	if hf.SignatureInput != "" && hf.Signature != "" {
		return RFC9421
	}
	if hf.Signature != "" {
		return CavageHTTPSignatures
	}
	return Unsigned
}
