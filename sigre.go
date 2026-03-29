package sigre

import (
	"fmt"
	"net/http"

	"github.com/MitarashiDango/sigre/common"
	"github.com/MitarashiDango/sigre/dchttpsig"
)

const (
	Unsigned             common.SignatureType = iota
	CavageHTTPSignatures                      // draft-cavage-http-signatures-12
	RFC9421                                   // TODO そのうち実装する
)

const (
	Authorization   = common.Authorization
	Signature       = common.Signature
	SignatureInput  = common.SignatureInput
	AcceptSignature = "Accept-Signature"
)

type SignOptions = common.SignOptions
type VerifyOptions = common.VerifyOptions

type Verifier interface {
	Verify(verifyOption *VerifyOptions) error
	KeyId() string
}

func SignRequest(req *http.Request, signOption *SignOptions) error {
	if signOption.SignatureType == CavageHTTPSignatures {
		err := dchttpsig.SignRequest(req, signOption)
		if err != nil {
			return &SigreError{Err: err}
		}
		return nil
	}

	// RFC9421 not implemented
	if signOption.SignatureType == RFC9421 {
		return &SigreError{Err: fmt.Errorf("RFC9421 signer not implemented")}
	}

	return &SigreError{Err: fmt.Errorf("unsupported sign type: %v", signOption.SignatureType)}
}

func SignResponse(res *http.Response, signOption *SignOptions) error {
	if signOption.SignatureType == CavageHTTPSignatures {
		err := dchttpsig.SignResponse(res, signOption)
		if err != nil {
			return &SigreError{Err: err}
		}
		return nil
	}

	// RFC9421 not implemented
	if signOption.SignatureType == RFC9421 {
		return &SigreError{Err: fmt.Errorf("RFC9421 signer not implemented")}
	}

	return &SigreError{Err: fmt.Errorf("unsupported sign type for response: %v", signOption.SignatureType)}
}

func NewRequestVerifier(req *http.Request) (Verifier, error) {
	hf := GetSignatureHeaderFields(req.Header)
	signatureType := hf.GetSignatureType()

	if signatureType == CavageHTTPSignatures {
		verifier, err := dchttpsig.NewRequestVerifier(req, hf.Signature)
		if err != nil {
			return nil, &SigreError{Err: err}
		}

		return verifier, nil
	}

	// RFC9421 not implemented
	if signatureType == RFC9421 {
		return nil, &SigreError{Err: fmt.Errorf("RFC9421 verifier not implemented")}
	}

	return nil, &SigreError{Err: ErrMissingSignature}
}

func NewResponseVerifier(res *http.Response) (Verifier, error) {
	hf := GetSignatureHeaderFields(res.Header)
	signatureType := hf.GetSignatureType()

	if signatureType == CavageHTTPSignatures {
		verifier, err := dchttpsig.NewResponseVerifier(res, hf.Signature)
		if err != nil {
			return nil, &SigreError{Err: err}
		}

		return verifier, nil
	}

	// RFC9421 not implemented
	if signatureType == RFC9421 {
		return nil, &SigreError{Err: fmt.Errorf("RFC9421 verifier not implemented")}
	}

	return nil, &SigreError{Err: ErrMissingSignature}
}
