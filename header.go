package sigre

import (
	"fmt"
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
// The Signature field is populated from exactly one "Signature" header value or one
// "Authorization: Signature ..." value. It is empty when Cavage signature placement
// is ambiguous.
func GetSignatureHeaderFields(h http.Header) *SignatureHeaderFields {
	hf := new(SignatureHeaderFields)

	if signature, present, err := cavageSignatureValue(h); err == nil && present {
		hf.Signature = signature
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

func cavageSignatureValue(h http.Header) (signature string, present bool, err error) {
	signatureValues := h.Values(Signature)
	if len(signatureValues) > 1 {
		return "", false, fmt.Errorf("ambiguous Cavage signature: multiple Signature header values are present")
	}

	var authorizationSignature string
	var authorizationSignaturePresent bool
	for _, value := range h.Values(Authorization) {
		params, ok := cavageAuthorizationParams(value)
		if !ok {
			continue
		}
		if authorizationSignaturePresent {
			return "", false, fmt.Errorf("ambiguous Cavage signature: multiple Authorization Signature values are present")
		}
		authorizationSignaturePresent = true
		authorizationSignature = params
	}

	if len(signatureValues) == 1 && authorizationSignaturePresent {
		return "", false, fmt.Errorf("ambiguous Cavage signature: Signature and Authorization Signature are both present")
	}
	if len(signatureValues) == 1 {
		return signatureValues[0], true, nil
	}
	if authorizationSignaturePresent {
		return authorizationSignature, true, nil
	}
	return "", false, nil
}

func cavageAuthorizationParams(value string) (string, bool) {
	pos := 0
	for pos < len(value) && isCavageTokenByte(value[pos]) {
		pos++
	}
	if pos == 0 || !strings.EqualFold(value[:pos], Signature) {
		return "", false
	}
	if pos == len(value) {
		return "", true
	}
	if value[pos] != ' ' {
		return "", false
	}
	for pos < len(value) && value[pos] == ' ' {
		pos++
	}
	return trimCavageOWS(value[pos:]), true
}
