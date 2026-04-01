// header_test.go
package sigre_test

import (
	"net/http"
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
		// --- Signature ---
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
			name: "Signature header takes priority over Authorization",
			header: http.Header{
				"Signature":     []string{"sig1=:direct:"},
				"Authorization": []string{"Signature sig1=:fromauth:"},
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
		// --- Signature-Input ---
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
		// --- Accept-Signature ---
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
		// --- All fields ---
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
