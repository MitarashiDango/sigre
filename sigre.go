package sigre

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MitarashiDango/sigre/common"
	"github.com/MitarashiDango/sigre/dchttpsig"
)

const (
	Unsigned             common.SignType = iota
	CavageHTTPSignatures                 // draft-cavage-http-signatures-12
	RFC9421                              // TODO そのうち実装する
)

const (
	Authorization  = common.Authorization
	Signature      = common.Signature
	SignatureInput = common.SignatureInput
)

type SignOptions = common.SignOptions
type VerifyOptions = common.VerifyOptions

type Verifier interface {
	Verify(verifyOption *VerifyOptions) error
	KeyId() string
}

func SignRequest(req *http.Request, signOption *SignOptions) error {
	if signOption.SignType == CavageHTTPSignatures {
		err := dchttpsig.SignRequest(req, signOption)
		if err != nil {
			return &SigreError{Err: err}
		}
		return nil
	}

	// RFC9421 not implemented
	if signOption.SignType == RFC9421 {
		return &SigreError{Err: fmt.Errorf("RFC9421 signer not implemented")}
	}

	return &SigreError{Err: fmt.Errorf("unsupported sign type: %v", signOption.SignType)}
}

func SignResponse(res *http.Response, signOption *SignOptions) error {
	if signOption.SignType == CavageHTTPSignatures {
		err := dchttpsig.SignResponse(res, signOption)
		if err != nil {
			return &SigreError{Err: err}
		}
		return nil
	}

	// RFC9421 not implemented
	if signOption.SignType == RFC9421 {
		return &SigreError{Err: fmt.Errorf("RFC9421 signer not implemented")}
	}

	return &SigreError{Err: fmt.Errorf("unsupported sign type for response: %v", signOption.SignType)}
}

func NewRequestVerifier(req *http.Request) (Verifier, error) {
	signType, signatureParamString, _ := getSignTypeAndParams(req.Header)

	if signType == CavageHTTPSignatures {
		verifier, err := dchttpsig.NewRequestVerifier(req, signatureParamString)
		if err != nil {
			return nil, &SigreError{Err: err}
		}

		return verifier, nil
	}

	// RFC9421 not implemented
	if signType == RFC9421 {
		return nil, &SigreError{Err: fmt.Errorf("RFC9421 verifier not implemented")}
	}

	return nil, &SigreError{Err: ErrMissingSignature}
}

func NewResponseVerifier(res *http.Response) (Verifier, error) {
	signType, signatureParamString, _ := getSignTypeAndParams(res.Header)

	if signType == CavageHTTPSignatures {
		verifier, err := dchttpsig.NewResponseVerifier(res, signatureParamString)
		if err != nil {
			return nil, &SigreError{Err: err}
		}

		return verifier, nil
	}

	// RFC9421 not implemented
	if signType == RFC9421 {
		return nil, &SigreError{Err: fmt.Errorf("RFC9421 verifier not implemented")}
	}

	return nil, &SigreError{Err: ErrMissingSignature}
}

func getSignTypeAndParams(header http.Header) (signType common.SignType, params string, input string) {
	signatureString := header.Get(common.Signature)
	signatureInputString := header.Get(common.SignatureInput)

	// RFC9421 uses both Signature and Signature-Input
	if signatureInputString != "" && signatureString != "" {
		return RFC9421, signatureString, signatureInputString
	}

	if signatureString != "" {
		return CavageHTTPSignatures, signatureString, ""
	}

	authorizationHeaderValue := header.Get(common.Authorization)
	if strings.HasPrefix(authorizationHeaderValue, "Signature ") {
		trimmedParams := strings.TrimPrefix(authorizationHeaderValue, "Signature ")
		return CavageHTTPSignatures, strings.TrimSpace(trimmedParams), ""
	}

	return Unsigned, "", ""
}
