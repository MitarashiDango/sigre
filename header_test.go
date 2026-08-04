package sigre_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/MitarashiDango/sigre"
)

func TestGetSignatureHeaderFields(t *testing.T) {
	tests := []struct {
		name          string
		header        http.Header
		wantSignature string
		wantSigInput  string
		wantAcceptSig string
	}{
		{
			name:   "empty headers",
			header: http.Header{},
		},
		{
			name: "Signature header only",
			header: http.Header{
				"Signature": []string{"sig1=:abc123:"},
			},
			wantSignature: "sig1=:abc123:",
		},
		{
			name: "Authorization header with Signature prefix",
			header: http.Header{
				"Authorization": []string{"Signature sig1=:abc123:"},
			},
			wantSignature: "sig1=:abc123:",
		},
		{
			name: "Signature header and Authorization Signature are ambiguous",
			header: http.Header{
				"Signature":     []string{"sig1=:direct:"},
				"Authorization": []string{"Signature sig1=:fromauth:"},
			},
			wantSignature: "",
		},
		{
			name: "Authorization auth-scheme is case insensitive",
			header: http.Header{
				"Authorization": []string{"sIgNaTuRe sig1=:abc123:"},
			},
			wantSignature: "sig1=:abc123:",
		},
		{
			name: "Signature header with non-Signature Authorization is not ambiguous",
			header: http.Header{
				"Signature":     []string{"sig1=:direct:"},
				"Authorization": []string{"Bearer some-token"},
			},
			wantSignature: "sig1=:direct:",
		},
		{
			name: "Authorization without Signature prefix is ignored",
			header: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			wantSignature: "",
		},
		{
			name: "Authorization starting with Signature but no space is ignored",
			header: http.Header{
				"Authorization": []string{"Signaturesig1=:abc123:"},
			},
			wantSignature: "",
		},
		{
			name: "TrimSpace is applied after removing Authorization prefix",
			header: http.Header{
				"Authorization": []string{"Signature   sig1=:abc123:  "},
			},
			wantSignature: "sig1=:abc123:",
		},
		{
			name: "multiple Signature header values are ambiguous",
			header: http.Header{
				"Signature": []string{"sig1=:first:", "sig2=:second:"},
			},
			wantSignature: "",
		},
		{
			name: "multiple Authorization Signature values are ambiguous",
			header: http.Header{
				"Authorization": []string{"Signature sig1=:first:", "signature sig2=:second:"},
			},
			wantSignature: "",
		},
		{
			name: "Signature-Input header only",
			header: http.Header{
				"Signature-Input": []string{`sig1=("@method" "@path");created=1618884473`},
			},
			wantSigInput: `sig1=("@method" "@path");created=1618884473`,
		},
		{
			name: "both Signature and Signature-Input present",
			header: http.Header{
				"Signature":       []string{"sig1=:abc123:"},
				"Signature-Input": []string{`sig1=("@method");created=1618884473`},
			},
			wantSignature: "sig1=:abc123:",
			wantSigInput:  `sig1=("@method");created=1618884473`,
		},
		{
			name: "Accept-Signature header only",
			header: http.Header{
				"Accept-Signature": []string{`sig1=("@method" "@path")`},
			},
			wantAcceptSig: `sig1=("@method" "@path")`,
		},
		{
			name: "both Accept-Signature and Signature present",
			header: http.Header{
				"Signature":        []string{"sig1=:abc123:"},
				"Accept-Signature": []string{`sig1=("@method")`},
			},
			wantSignature: "sig1=:abc123:",
			wantAcceptSig: `sig1=("@method")`,
		},
		{
			name: "all headers present",
			header: http.Header{
				"Signature":        []string{"sig1=:abc123:"},
				"Signature-Input":  []string{`sig1=("@method" "@path");created=1618884473`},
				"Accept-Signature": []string{`sig1=("@method" "@path")`},
			},
			wantSignature: "sig1=:abc123:",
			wantSigInput:  `sig1=("@method" "@path");created=1618884473`,
			wantAcceptSig: `sig1=("@method" "@path")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sigre.GetSignatureHeaderFields(tt.header)

			if got == nil {
				t.Fatal("GetSignatureHeaderFields() returned nil")
			}
			if got.Signature != tt.wantSignature {
				t.Errorf("Signature = %q, want %q", got.Signature, tt.wantSignature)
			}
			if got.SignatureInput != tt.wantSigInput {
				t.Errorf("SignatureInput = %q, want %q", got.SignatureInput, tt.wantSigInput)
			}
			if got.AcceptSignature != tt.wantAcceptSig {
				t.Errorf("AcceptSignature = %q, want %q", got.AcceptSignature, tt.wantAcceptSig)
			}
		})
	}
}

func TestCavageVerifierRejectsAmbiguousSignaturePlacement(t *testing.T) {
	const validParams = `keyId=key,signature=c2ln`
	testCases := []struct {
		name          string
		header        http.Header
		wantMissing   bool
		wantMalformed bool
		wantConflict  bool
	}{
		{
			name:   "Signature header",
			header: http.Header{"Signature": []string{validParams}},
		},
		{
			name:   "Authorization Signature with mixed case scheme",
			header: http.Header{"Authorization": []string{"sIgNaTuRe " + validParams}},
		},
		{
			name: "Signature header with Bearer Authorization",
			header: http.Header{
				"Signature":     []string{validParams},
				"Authorization": []string{"Bearer token"},
			},
		},
		{
			name:        "Bearer Authorization without Cavage signature",
			header:      http.Header{"Authorization": []string{"Bearer token"}},
			wantMissing: true,
		},
		{
			name:          "invalid Base64",
			header:        http.Header{"Signature": []string{`keyId=key,signature="not@base64"`}},
			wantMalformed: true,
		},
		{
			name: "both Cavage placements",
			header: http.Header{
				"Signature":     []string{validParams},
				"Authorization": []string{"Signature " + validParams},
			},
			wantConflict: true,
		},
		{
			name:         "multiple Signature header values",
			header:       http.Header{"Signature": []string{validParams, validParams}},
			wantConflict: true,
		},
		{
			name:         "multiple Authorization Signature values",
			header:       http.Header{"Authorization": []string{"Signature " + validParams, "signature " + validParams}},
			wantConflict: true,
		},
	}

	constructors := []struct {
		name string
		run  func(http.Header) error
	}{
		{
			name: "generic request",
			run: func(header http.Header) error {
				req, err := http.NewRequest("GET", "https://example.test/", nil)
				if err != nil {
					return err
				}
				req.Header = header
				_, err = sigre.NewRequestVerifier(req)
				return err
			},
		},
		{
			name: "Cavage request",
			run: func(header http.Header) error {
				req, err := http.NewRequest("GET", "https://example.test/", nil)
				if err != nil {
					return err
				}
				req.Header = header
				_, err = sigre.NewCavageRequestVerifier(req)
				return err
			},
		},
		{
			name: "generic response",
			run: func(header http.Header) error {
				_, err := sigre.NewResponseVerifier(&http.Response{Header: header})
				return err
			},
		},
		{
			name: "Cavage response",
			run: func(header http.Header) error {
				_, err := sigre.NewCavageResponseVerifier(&http.Response{Header: header})
				return err
			},
		},
	}

	for _, constructor := range constructors {
		for _, tc := range testCases {
			t.Run(constructor.name+"/"+tc.name, func(t *testing.T) {
				err := constructor.run(tc.header.Clone())
				switch {
				case tc.wantConflict:
					if err == nil || !strings.Contains(err.Error(), "ambiguous Cavage signature") {
						t.Fatalf("expected ambiguous placement error, got: %v", err)
					}
				case tc.wantMissing:
					if !errors.Is(err, sigre.ErrMissingSignature) {
						t.Fatalf("expected ErrMissingSignature, got: %v", err)
					}
				case tc.wantMalformed:
					if err == nil || !strings.Contains(err.Error(), "invalid 'signature' value") {
						t.Fatalf("expected invalid Base64 error, got: %v", err)
					}
				default:
					if err != nil {
						t.Fatalf("unexpected verifier construction error: %v", err)
					}
				}
			})
		}
	}
}

func TestSignatureHeaderFields_GetSignatureType(t *testing.T) {
	tests := []struct {
		name     string
		hf       *sigre.SignatureHeaderFields
		wantType sigre.SignatureType
	}{
		{
			name:     "Unsigned when both Signature and SignatureInput are empty",
			hf:       &sigre.SignatureHeaderFields{},
			wantType: sigre.Unsigned,
		},
		{
			name: "CavageHTTPSignatures when only Signature is set",
			hf: &sigre.SignatureHeaderFields{
				Signature: "sig1=:abc123:",
			},
			wantType: sigre.CavageHTTPSignatures,
		},
		{
			name: "Unsigned when only SignatureInput is set",
			hf: &sigre.SignatureHeaderFields{
				SignatureInput: `sig1=("@method");created=1618884473`,
			},
			wantType: sigre.Unsigned,
		},
		{
			name: "RFC9421 when both Signature and SignatureInput are set",
			hf: &sigre.SignatureHeaderFields{
				Signature:      "sig1=:abc123:",
				SignatureInput: `sig1=("@method");created=1618884473`,
			},
			wantType: sigre.RFC9421,
		},
		{
			name: "Unsigned when only AcceptSignature is set",
			hf: &sigre.SignatureHeaderFields{
				AcceptSignature: `sig1=("@method")`,
			},
			wantType: sigre.Unsigned,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.hf.GetSignatureType()
			if got != tt.wantType {
				t.Errorf("GetSignatureType() = %v, want %v", got, tt.wantType)
			}
		})
	}
}
