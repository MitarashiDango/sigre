package sigre

import (
	"fmt"
	"net/http"
	"strings"
)

type cavageSignatureCandidate struct {
	value     string
	placement CavageSignaturePlacement
}

func requestCavageSignatureCandidate(h http.Header, source CavageRequestSignatureSource) (cavageSignatureCandidate, error) {
	switch source {
	case CavageRequestSignatureSourceSignature:
		return cavageSignatureHeaderCandidate(h)
	case CavageRequestSignatureSourceAuthorization:
		return cavageAuthorizationSignatureCandidate(h)
	case CavageRequestSignatureSourceSignatureOrAuthorization:
		signature, signatureErr := cavageSignatureHeaderCandidate(h)
		authorization, authorizationErr := cavageAuthorizationSignatureCandidate(h)
		if signatureErr != nil || authorizationErr != nil || signature.placement != 0 && authorization.placement != 0 {
			return cavageSignatureCandidate{}, fmt.Errorf("%w: multiple selected Cavage signature values are present", ErrSignatureSourceConflict)
		}
		if signature.placement != 0 {
			return signature, nil
		}
		return authorization, nil
	default:
		return cavageSignatureCandidate{}, fmt.Errorf("%w: unsupported request signature source %d", ErrInvalidVerificationOptions, source)
	}
}

func cavageSignatureHeaderCandidate(h http.Header) (cavageSignatureCandidate, error) {
	values := h.Values(HeaderSignature)
	if len(values) > 1 {
		return cavageSignatureCandidate{}, fmt.Errorf("%w: multiple Signature field values are present", ErrSignatureSourceConflict)
	}
	if len(values) == 0 {
		return cavageSignatureCandidate{}, nil
	}
	return cavageSignatureCandidate{value: values[0], placement: CavageSignaturePlacementSignature}, nil
}

func cavageAuthorizationSignatureCandidate(h http.Header) (cavageSignatureCandidate, error) {
	var candidate cavageSignatureCandidate
	for _, value := range h.Values(HeaderAuthorization) {
		params, ok := cavageAuthorizationParams(value)
		if !ok {
			continue
		}
		if candidate.placement != 0 {
			return cavageSignatureCandidate{}, fmt.Errorf("%w: multiple Authorization: Signature values are present", ErrSignatureSourceConflict)
		}
		candidate = cavageSignatureCandidate{
			value:     params,
			placement: CavageSignaturePlacementAuthorization,
		}
	}
	return candidate, nil
}

func cavageAuthorizationParams(value string) (string, bool) {
	pos := 0
	for pos < len(value) && isCavageTokenByte(value[pos]) {
		pos++
	}
	if pos == 0 || !strings.EqualFold(value[:pos], HeaderSignature) {
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
