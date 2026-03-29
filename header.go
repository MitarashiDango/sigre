package sigre

import (
	"net/http"
	"strings"

	"github.com/MitarashiDango/sigre/common"
)

type SignatureHeaderFields struct {
	Signature       string
	SignatureInput  string
	AcceptSignature string
}

func GetSignatureHeaderFields(header http.Header) *SignatureHeaderFields {
	hf := new(SignatureHeaderFields)

	if v := header.Get(Signature); v != "" {
		hf.Signature = v
	} else if v := header.Get(Authorization); v != "" && strings.HasPrefix(v, Signature+" ") {
		hf.Signature = strings.TrimSpace(strings.TrimPrefix(v, Signature+" "))
	}

	if v := header.Get(SignatureInput); v != "" {
		hf.SignatureInput = v
	}

	if v := header.Get(AcceptSignature); v != "" {
		hf.AcceptSignature = v
	}

	return hf
}

func (hf *SignatureHeaderFields) GetSignatureType() common.SignatureType {
	// RFC9421 uses both Signature and Signature-Input
	if hf.SignatureInput != "" && hf.Signature != "" {
		return RFC9421
	}

	if hf.Signature != "" {
		return CavageHTTPSignatures
	}

	return Unsigned
}
