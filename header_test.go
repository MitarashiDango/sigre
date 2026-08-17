package sigre_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/MitarashiDango/sigre"
)

const sourcePolicyCavageParameters = `keyId="source-key",signature="c2ln",headers="x-test"`

func sourcePolicyRequest(header http.Header) *http.Request {
	return &http.Request{
		Method:     http.MethodGet,
		RequestURI: "/resource",
		Host:       "example.test",
		Header:     header,
	}
}

func TestCavageRequestSignatureSource(t *testing.T) {
	tests := []struct {
		name      string
		source    sigre.CavageRequestSignatureSource
		header    http.Header
		placement sigre.CavageSignaturePlacement
		wantErr   error
	}{
		{
			name:      "zero value selects Signature",
			header:    http.Header{"Signature": {sourcePolicyCavageParameters}, "X-Test": {"value"}},
			placement: sigre.CavageSignaturePlacementSignature,
		},
		{
			name:      "zero value ignores malformed Authorization",
			header:    http.Header{"Signature": {sourcePolicyCavageParameters}, "Authorization": {`Signature keyId="bad"`, `Signature keyId="also-bad"`}, "X-Test": {"value"}},
			placement: sigre.CavageSignaturePlacementSignature,
		},
		{
			name:      "Authorization selects mixed-case Signature scheme",
			source:    sigre.CavageRequestSignatureSourceAuthorization,
			header:    http.Header{"Authorization": {"sIgNaTuRe " + sourcePolicyCavageParameters}, "X-Test": {"value"}},
			placement: sigre.CavageSignaturePlacementAuthorization,
		},
		{
			name:      "Authorization ignores malformed and multiple Signature fields",
			source:    sigre.CavageRequestSignatureSourceAuthorization,
			header:    http.Header{"Signature": {"not Cavage", "also not Cavage"}, "Authorization": {"Signature " + sourcePolicyCavageParameters}, "X-Test": {"value"}},
			placement: sigre.CavageSignaturePlacementAuthorization,
		},
		{
			name:      "either selects Signature",
			source:    sigre.CavageRequestSignatureSourceSignatureOrAuthorization,
			header:    http.Header{"Signature": {sourcePolicyCavageParameters}, "Authorization": {"Bearer token"}, "X-Test": {"value"}},
			placement: sigre.CavageSignaturePlacementSignature,
		},
		{
			name:      "either selects Authorization",
			source:    sigre.CavageRequestSignatureSourceSignatureOrAuthorization,
			header:    http.Header{"Authorization": {"Signature " + sourcePolicyCavageParameters}, "X-Test": {"value"}},
			placement: sigre.CavageSignaturePlacementAuthorization,
		},
		{
			name:    "either rejects both candidates before parsing",
			source:  sigre.CavageRequestSignatureSourceSignatureOrAuthorization,
			header:  http.Header{"Signature": {"malformed"}, "Authorization": {"Signature malformed"}, "X-Test": {"value"}},
			wantErr: sigre.ErrSignatureSourceConflict,
		},
		{
			name:    "selected Signature rejects multiple values",
			header:  http.Header{"Signature": {sourcePolicyCavageParameters, sourcePolicyCavageParameters}, "X-Test": {"value"}},
			wantErr: sigre.ErrSignatureSourceConflict,
		},
		{
			name:    "selected Authorization rejects multiple candidates",
			source:  sigre.CavageRequestSignatureSourceAuthorization,
			header:  http.Header{"Authorization": {"Signature " + sourcePolicyCavageParameters, "signature " + sourcePolicyCavageParameters}, "X-Test": {"value"}},
			wantErr: sigre.ErrSignatureSourceConflict,
		},
		{
			name:    "selected source is missing",
			source:  sigre.CavageRequestSignatureSourceAuthorization,
			header:  http.Header{"Signature": {sourcePolicyCavageParameters}, "X-Test": {"value"}},
			wantErr: sigre.ErrMissingSignature,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := sigre.NewCavageVerifier(&sigre.CavageVerificationOptions{RequestSignatureSource: test.source})
			if err != nil {
				t.Fatalf("NewCavageVerifier() failed: %v", err)
			}
			signature, err := verifier.ParseRequest(sourcePolicyRequest(test.header))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ParseRequest() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr != nil {
				assertSigreError(t, err)
				return
			}
			if signature.Placement() != test.placement {
				t.Fatalf("Placement() = %d, want %d", signature.Placement(), test.placement)
			}
		})
	}
}

func TestCavageAuthorizationCoexistsWithRFC9421Fields(t *testing.T) {
	header := http.Header{
		"Authorization":   {"Signature " + sourcePolicyCavageParameters},
		"Signature":       {"sig1=:YWJj:"},
		"Signature-Input": {`sig1=("@method");created=1618884473`},
		"X-Test":          {"value"},
	}
	verifier, err := sigre.NewCavageVerifier(&sigre.CavageVerificationOptions{
		RequestSignatureSource: sigre.CavageRequestSignatureSourceAuthorization,
	})
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	signature, err := verifier.ParseRequest(sourcePolicyRequest(header))
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	if signature.Placement() != sigre.CavageSignaturePlacementAuthorization {
		t.Fatalf("Placement() = %d, want Authorization", signature.Placement())
	}
}

func TestCavageResponseAlwaysUsesSignature(t *testing.T) {
	verifier, err := sigre.NewCavageVerifier(&sigre.CavageVerificationOptions{
		RequestSignatureSource: sigre.CavageRequestSignatureSourceAuthorization,
	})
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	response := &http.Response{Header: http.Header{
		"Signature":       {sourcePolicyCavageParameters},
		"Authorization":   {"Signature malformed", "Signature also-malformed"},
		"Signature-Input": {`sig1=("@status");created=1618884473`},
		"X-Test":          {"value"},
	}}
	signature, err := verifier.ParseResponse(response)
	if err != nil {
		t.Fatalf("ParseResponse() failed: %v", err)
	}
	if signature.Placement() != sigre.CavageSignaturePlacementSignature {
		t.Fatalf("Placement() = %d, want Signature", signature.Placement())
	}

	response.Header.Del("Signature")
	if _, err := verifier.ParseResponse(response); !errors.Is(err, sigre.ErrMissingSignature) {
		t.Fatalf("Authorization unexpectedly supplied a response signature: %v", err)
	}
	response.Header["Signature"] = []string{sourcePolicyCavageParameters, "malformed"}
	if _, err := verifier.ParseResponse(response); !errors.Is(err, sigre.ErrSignatureSourceConflict) {
		t.Fatalf("multiple response Signature values error = %v", err)
	}
}

func TestCavageVerifierNilMessages(t *testing.T) {
	verifier, err := sigre.NewCavageVerifier(nil)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	if _, err := verifier.ParseRequest(nil); !errors.Is(err, sigre.ErrInvalidHTTPMessage) {
		t.Fatalf("ParseRequest(nil) error = %v", err)
	}
	if _, err := verifier.ParseResponse(nil); !errors.Is(err, sigre.ErrInvalidHTTPMessage) {
		t.Fatalf("ParseResponse(nil) error = %v", err)
	}
	if _, err := verifier.ParseRequest(&http.Request{}); !errors.Is(err, sigre.ErrMissingSignature) {
		t.Fatalf("nil Header request error = %v", err)
	}
	if _, err := verifier.ParseResponse(&http.Response{}); !errors.Is(err, sigre.ErrMissingSignature) {
		t.Fatalf("nil Header response error = %v", err)
	}
}

func assertSigreError(t *testing.T, err error) {
	t.Helper()
	var packageError *sigre.SigreError
	if !errors.As(err, &packageError) {
		t.Fatalf("error %v is not wrapped by *SigreError", err)
	}
}
