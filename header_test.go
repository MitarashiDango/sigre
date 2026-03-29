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
			name:   "空のヘッダー",
			header: http.Header{},
		},
		// --- Signature ---
		{
			name: "Signatureヘッダーのみ存在する場合",
			header: http.Header{
				"Signature": []string{"sig1=:abc123:"},
			},
			wantSignature: "sig1=:abc123:",
		},
		{
			name: "AuthorizationヘッダーにSignatureプレフィックスがある場合",
			header: http.Header{
				"Authorization": []string{"Signature sig1=:abc123:"},
			},
			wantSignature: "sig1=:abc123:",
		},
		{
			name: "SignatureヘッダーがAuthorizationより優先される",
			header: http.Header{
				"Signature":     []string{"sig1=:direct:"},
				"Authorization": []string{"Signature sig1=:fromauth:"},
			},
			wantSignature: "sig1=:direct:",
		},
		{
			name: "AuthorizationのプレフィックスがSignatureでない場合は無視される",
			header: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			wantSignature: "",
		},
		{
			name: "AuthorizationがSignatureで始まるがスペースがない場合は無視される",
			header: http.Header{
				"Authorization": []string{"Signaturesig1=:abc123:"},
			},
			wantSignature: "",
		},
		{
			name: "Authorizationのプレフィックス除去後にTrimSpaceが適用される",
			header: http.Header{
				"Authorization": []string{"Signature   sig1=:abc123:  "},
			},
			wantSignature: "sig1=:abc123:",
		},
		// --- Signature-Input ---
		{
			name: "Signature-Inputヘッダーのみ存在する場合",
			header: http.Header{
				"Signature-Input": []string{`sig1=("@method" "@path");created=1618884473`},
			},
			wantSigInput: `sig1=("@method" "@path");created=1618884473`,
		},
		{
			name: "SignatureとSignature-Inputが両方存在する場合",
			header: http.Header{
				"Signature":       []string{"sig1=:abc123:"},
				"Signature-Input": []string{`sig1=("@method");created=1618884473`},
			},
			wantSignature: "sig1=:abc123:",
			wantSigInput:  `sig1=("@method");created=1618884473`,
		},
		// --- Accept-Signature ---
		{
			name: "Accept-Signatureヘッダーのみ存在する場合",
			header: http.Header{
				"Accept-Signature": []string{`sig1=("@method" "@path")`},
			},
			wantAcceptSig: `sig1=("@method" "@path")`,
		},
		{
			name: "Accept-SignatureとSignatureが両方存在する場合",
			header: http.Header{
				"Signature":        []string{"sig1=:abc123:"},
				"Accept-Signature": []string{`sig1=("@method")`},
			},
			wantSignature: "sig1=:abc123:",
			wantAcceptSig: `sig1=("@method")`,
		},
		// --- 全フィールド ---
		{
			name: "全ヘッダーが揃っている場合",
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
				t.Fatal("GetSignatureHeaderFields() が nil を返しました")
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
			name:     "SignatureもSignatureInputも空の場合はUnsigned",
			hf:       &sigre.SignatureHeaderFields{},
			wantType: sigre.Unsigned,
		},
		{
			name: "Signatureのみセットされている場合はCavageHTTPSignatures",
			hf: &sigre.SignatureHeaderFields{
				Signature: "sig1=:abc123:",
			},
			wantType: sigre.CavageHTTPSignatures,
		},
		{
			name: "SignatureInputのみセットされている場合はUnsigned",
			hf: &sigre.SignatureHeaderFields{
				SignatureInput: `sig1=("@method");created=1618884473`,
			},
			wantType: sigre.Unsigned,
		},
		{
			name: "SignatureとSignatureInputが両方セットされている場合はRFC9421",
			hf: &sigre.SignatureHeaderFields{
				Signature:      "sig1=:abc123:",
				SignatureInput: `sig1=("@method");created=1618884473`,
			},
			wantType: sigre.RFC9421,
		},
		{
			name: "AcceptSignatureのみセットされている場合はUnsigned",
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
