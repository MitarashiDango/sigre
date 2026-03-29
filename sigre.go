package sigre

import (
	"crypto"
	"fmt"
	"net/http"
	"time"
)

type SignatureType int

const (
	Unsigned             SignatureType = iota
	CavageHTTPSignatures               // draft-cavage-http-signatures-12
	RFC9421                            // TODO そのうち実装する
)

const (
	Authorization   = "Authorization"
	Signature       = "Signature"
	SignatureInput  = "Signature-Input"
	AcceptSignature = "Accept-Signature"
)

type SignOptions struct {
	KeyId             string
	PrivateKey        crypto.PrivateKey // For asymmetric algorithms
	SharedSecret      []byte            // For HMAC
	SignTargetHeaders []string          // Headers to include in the signature string
	SignatureType     SignatureType
	HashAlgorithm     crypto.Hash      // Hash algorithm (e.g., crypto.SHA256), ignored for Ed25519 signing
	Expiry            int64            // Expiration time in seconds from creation
	SignatureHeader   string           // Header name for the signature (e.g., "Signature" or "Authorization")
	NowFunc           func() time.Time // For debugging and testing
}

type VerifyOptions struct {
	PublicKey        crypto.PublicKey // For asymmetric algorithms
	SharedSecret     []byte           // For HMAC
	AllowedClockSkew time.Duration    // For validating (created) and (expires)
	RequiredHeaders  []string         // To enforce presence of certain headers in the signature parameters
	NowFunc          func() time.Time // For debugging and testing
}

type Verifier interface {
	Verify(verifyOption *VerifyOptions) error
	KeyId() string
}

func SignRequest(req *http.Request, signOption *SignOptions) error {
	if signOption.SignatureType == CavageHTTPSignatures {
		err := SignRequestWithCavageHTTPSignatures(req, signOption)
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
		err := SignResponseWithCavageHTTPSignatures(res, signOption)
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
		verifier, err := NewCavageHTTPSignaturesVerifierFromRequest(req, hf.Signature)
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
		verifier, err := NewCavageHTTPSignaturesVerifierFromResponse(res, hf.Signature)
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
