package sigre_test

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

func newSignerPolicyRequest(t *testing.T) *http.Request {
	t.Helper()
	req := newTestRequest(t, http.MethodPost, "https://example.com/signer?fixed=1", "body")
	req.Header.Set("Date", testFixedTime.Format(http.TimeFormat))
	req.Header.Set("Digest", "SHA-256=present-but-not-implicitly-signed")
	req.Header.Set("X-Extra", "extra value")
	return req
}

func newSignerPolicyResponse() *http.Response {
	return &http.Response{Header: http.Header{
		"Date":    []string{testFixedTime.Format(http.TimeFormat)},
		"Digest":  []string{"SHA-256=present-but-not-implicitly-signed"},
		"X-Extra": []string{"extra value"},
	}}
}

func signerPolicyParameter(t *testing.T, value, name string) (string, bool) {
	t.Helper()
	prefix := name + "="
	start := strings.Index(value, prefix)
	if start < 0 || start > 0 && value[start-1] != ',' {
		return "", false
	}
	start += len(prefix)
	if start >= len(value) {
		t.Fatalf("parameter %q has no value in %q", name, value)
	}
	if value[start] != '"' {
		end := strings.IndexByte(value[start:], ',')
		if end < 0 {
			return value[start:], true
		}
		return value[start : start+end], true
	}

	start++
	var result strings.Builder
	for i := start; i < len(value); i++ {
		switch value[i] {
		case '\\':
			i++
			if i >= len(value) {
				t.Fatalf("parameter %q has an incomplete escape in %q", name, value)
			}
			result.WriteByte(value[i])
		case '"':
			return result.String(), true
		default:
			result.WriteByte(value[i])
		}
	}
	t.Fatalf("parameter %q is unterminated in %q", name, value)
	return "", false
}

func signerPolicySignatureBytes(t *testing.T, value string) []byte {
	t.Helper()
	encoded, ok := signerPolicyParameter(t, value, "signature")
	if !ok {
		t.Fatalf("signature parameter missing from %q", value)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatalf("signature is not valid Base64: %v", err)
	}
	return signature
}

func assertSignerPolicyHMAC(t *testing.T, value, signingString string, secret []byte) {
	t.Helper()
	mac := hmac.New(sha512.New, secret)
	if _, err := mac.Write([]byte(signingString)); err != nil {
		t.Fatalf("failed to calculate independent HMAC: %v", err)
	}
	if !hmac.Equal(signerPolicySignatureBytes(t, value), mac.Sum(nil)) {
		t.Fatalf("generated HMAC does not cover %q", signingString)
	}
}

func TestCavageSignerStrictZeroValueWireFormat(t *testing.T) {
	secret := []byte(testHMACSecret)
	now := time.Date(2026, 8, 4, 4, 0, 0, 0, time.UTC)
	signer := &sigre.CavageSigner{Now: func() time.Time { return now }}

	t.Run("request", func(t *testing.T) {
		for _, opts := range []*sigre.CavageSigningOptions{nil, {}} {
			req := newSignerPolicyRequest(t)
			key := fixedHMACSigningKey("strict-request", sigre.AlgorithmHMACSHA512, secret)
			if err := signer.SignRequestWithHMAC(req, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
				t.Fatalf("strict request signing failed: %v", err)
			}
			value := req.Header.Get(sigre.Signature)
			if algorithm, _ := signerPolicyParameter(t, value, "algorithm"); algorithm != "hs2019" {
				t.Fatalf("algorithm = %q, want hs2019", algorithm)
			}
			if headers, _ := signerPolicyParameter(t, value, "headers"); headers != "(request-target) (created)" {
				t.Fatalf("headers = %q, want strict request defaults", headers)
			}
			if created, _ := signerPolicyParameter(t, value, "created"); created != "1785816000" {
				t.Fatalf("created = %q, want 1785816000", created)
			}
			if _, present := signerPolicyParameter(t, value, "expires"); present {
				t.Fatalf("strict request unexpectedly contains expires: %s", value)
			}
			for _, name := range []string{"host", "date", "digest", "content-type", "content-length"} {
				if strings.Contains(value, name) {
					t.Fatalf("strict request implicitly included %q: %s", name, value)
				}
			}
			assertSignerPolicyHMAC(t, value, "(request-target): post /signer?fixed=1\n(created): 1785816000", secret)

			req.RequestURI = req.URL.RequestURI()
			verifier, err := sigre.NewCavageRequestVerifier(req)
			if err != nil {
				t.Fatalf("NewCavageRequestVerifier() failed: %v", err)
			}
			verifier.Now = func() time.Time { return now }
			if err := verifier.VerifyHMAC(fixedHMACVerificationKey("strict-request", sigre.AlgorithmHMACSHA512, secret), nil); err != nil {
				t.Fatalf("strict request verification failed: %v", err)
			}
		}
	})

	t.Run("response", func(t *testing.T) {
		for _, opts := range []*sigre.CavageSigningOptions{nil, {}} {
			res := newSignerPolicyResponse()
			key := fixedHMACSigningKey("strict-response", sigre.AlgorithmHMACSHA512, secret)
			if err := signer.SignResponseWithHMAC(res, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
				t.Fatalf("strict response signing failed: %v", err)
			}
			value := res.Header.Get(sigre.Signature)
			if algorithm, _ := signerPolicyParameter(t, value, "algorithm"); algorithm != "hs2019" {
				t.Fatalf("algorithm = %q, want hs2019", algorithm)
			}
			if _, present := signerPolicyParameter(t, value, "headers"); present {
				t.Fatalf("strict response must omit headers: %s", value)
			}
			if created, _ := signerPolicyParameter(t, value, "created"); created != "1785816000" {
				t.Fatalf("created = %q, want 1785816000", created)
			}
			if _, present := signerPolicyParameter(t, value, "expires"); present {
				t.Fatalf("strict response unexpectedly contains expires: %s", value)
			}
			assertSignerPolicyHMAC(t, value, "(created): 1785816000", secret)

			verifier, err := sigre.NewCavageResponseVerifier(res)
			if err != nil {
				t.Fatalf("NewCavageResponseVerifier() failed: %v", err)
			}
			verifier.Now = func() time.Time { return now }
			if err := verifier.VerifyHMAC(fixedHMACVerificationKey("strict-response", sigre.AlgorithmHMACSHA512, secret), nil); err != nil {
				t.Fatalf("strict response verification failed: %v", err)
			}
		}
	})
}

func TestCavageSignerStrictAlgorithmsAcrossRequestAndResponse(t *testing.T) {
	rsaPrivateKey := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	ecdsaPrivateKey := parseECDSAPrivateKey(t, testECDSAPrivateKeyPEM)
	ed25519PrivateKey := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	secret := []byte(testHMACSecret)

	tests := []struct {
		name       string
		algorithm  sigre.AlgorithmID
		privateKey crypto.PrivateKey
		publicKey  crypto.PublicKey
		secret     []byte
	}{
		{name: "RSA SHA-512", algorithm: sigre.AlgorithmRSAPKCS1v15SHA512, privateKey: rsaPrivateKey, publicKey: &rsaPrivateKey.PublicKey},
		{name: "ECDSA SHA-512", algorithm: sigre.AlgorithmECDSASHA512, privateKey: ecdsaPrivateKey, publicKey: &ecdsaPrivateKey.PublicKey},
		{name: "Ed25519", algorithm: sigre.AlgorithmEd25519, privateKey: ed25519PrivateKey, publicKey: ed25519PrivateKey.Public()},
		{name: "HMAC SHA-512", algorithm: sigre.AlgorithmHMACSHA512, secret: secret},
	}

	for _, tt := range tests {
		for _, messageType := range []string{"request", "response"} {
			t.Run(tt.name+"/"+messageType, func(t *testing.T) {
				signer := &sigre.CavageSigner{Now: func() time.Time { return testFixedTime }}
				if messageType == "request" {
					req := newSignerPolicyRequest(t)
					var err error
					if tt.secret != nil {
						err = signer.SignRequestWithHMAC(req, fixedHMACSigningKey("active-key", tt.algorithm, tt.secret), sigre.CavageSignaturePlacementSignature, nil)
					} else {
						err = signer.SignRequest(req, fixedSigningKey("active-key", tt.algorithm, tt.privateKey), sigre.CavageSignaturePlacementSignature, nil)
					}
					if err != nil {
						t.Fatalf("request signing failed: %v", err)
					}
					req.RequestURI = req.URL.RequestURI()
					verifier, err := sigre.NewCavageRequestVerifier(req)
					if err != nil {
						t.Fatalf("request verifier construction failed: %v", err)
					}
					verifier.Now = func() time.Time { return testFixedTime }
					if tt.secret != nil {
						err = verifier.VerifyHMAC(fixedHMACVerificationKey("active-key", tt.algorithm, tt.secret), nil)
					} else {
						err = verifier.Verify(fixedPublicVerificationKey("active-key", tt.algorithm, tt.publicKey), nil)
					}
					if err != nil {
						t.Fatalf("request verification failed: %v", err)
					}
					return
				}

				res := newSignerPolicyResponse()
				var err error
				if tt.secret != nil {
					err = signer.SignResponseWithHMAC(res, fixedHMACSigningKey("active-key", tt.algorithm, tt.secret), sigre.CavageSignaturePlacementSignature, nil)
				} else {
					err = signer.SignResponse(res, fixedSigningKey("active-key", tt.algorithm, tt.privateKey), sigre.CavageSignaturePlacementSignature, nil)
				}
				if err != nil {
					t.Fatalf("response signing failed: %v", err)
				}
				verifier, err := sigre.NewCavageResponseVerifier(res)
				if err != nil {
					t.Fatalf("response verifier construction failed: %v", err)
				}
				verifier.Now = func() time.Time { return testFixedTime }
				if tt.secret != nil {
					err = verifier.VerifyHMAC(fixedHMACVerificationKey("active-key", tt.algorithm, tt.secret), nil)
				} else {
					err = verifier.Verify(fixedPublicVerificationKey("active-key", tt.algorithm, tt.publicKey), nil)
				}
				if err != nil {
					t.Fatalf("response verification failed: %v", err)
				}
			})
		}
	}
}

func TestCavageSignerKeyAndPlacementValidation(t *testing.T) {
	rsaPrivateKey := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	ecdsaPrivateKey := parseECDSAPrivateKey(t, testECDSAPrivateKeyPEM)
	secret := []byte(testHMACSecret)

	tests := []struct {
		name    string
		wantErr error
		run     func(*http.Request) error
	}{
		{
			name:    "empty KeyID",
			wantErr: sigre.ErrInvalidKeyMetadata,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequest(req, fixedSigningKey("", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPrivateKey), sigre.CavageSignaturePlacementSignature, nil)
			},
		},
		{
			name:    "unsafe KeyID",
			wantErr: sigre.ErrInvalidKeyMetadata,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequest(req, fixedSigningKey("unsafe\nkey", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPrivateKey), sigre.CavageSignaturePlacementSignature, nil)
			},
		},
		{
			name:    "zero AlgorithmID",
			wantErr: sigre.ErrInvalidKeyMetadata,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequest(req, fixedSigningKey("key", 0, rsaPrivateKey), sigre.CavageSignaturePlacementSignature, nil)
			},
		},
		{
			name:    "nil private key",
			wantErr: sigre.ErrMissingPrivateKey,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequest(req, fixedSigningKey("key", sigre.AlgorithmRSAPKCS1v15SHA512, nil), sigre.CavageSignaturePlacementSignature, nil)
			},
		},
		{
			name:    "private key kind mismatch",
			wantErr: sigre.ErrAlgorithmMismatch,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequest(req, fixedSigningKey("key", sigre.AlgorithmRSAPKCS1v15SHA512, ecdsaPrivateKey), sigre.CavageSignaturePlacementSignature, nil)
			},
		},
		{
			name:    "HMAC AlgorithmID in SigningKey",
			wantErr: sigre.ErrAlgorithmMismatch,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequest(req, fixedSigningKey("key", sigre.AlgorithmHMACSHA512, rsaPrivateKey), sigre.CavageSignaturePlacementSignature, nil)
			},
		},
		{
			name:    "empty HMAC secret",
			wantErr: sigre.ErrMissingSharedSecret,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequestWithHMAC(req, fixedHMACSigningKey("key", sigre.AlgorithmHMACSHA512, nil), sigre.CavageSignaturePlacementSignature, nil)
			},
		},
		{
			name:    "asymmetric AlgorithmID in HMACSigningKey",
			wantErr: sigre.ErrAlgorithmMismatch,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequestWithHMAC(req, fixedHMACSigningKey("key", sigre.AlgorithmRSAPKCS1v15SHA512, secret), sigre.CavageSignaturePlacementSignature, nil)
			},
		},
		{
			name:    "zero placement",
			wantErr: sigre.ErrInvalidSignaturePlacement,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequest(req, fixedSigningKey("key", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPrivateKey), 0, nil)
			},
		},
		{
			name:    "unknown placement",
			wantErr: sigre.ErrInvalidSignaturePlacement,
			run: func(req *http.Request) error {
				return sigre.NewCavageSigner().SignRequest(req, fixedSigningKey("key", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPrivateKey), 99, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newSignerPolicyRequest(t)
			err := tt.run(req)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
			if req.Header.Get(sigre.Signature) != "" || strings.HasPrefix(req.Header.Get(sigre.Authorization), "Signature ") {
				t.Fatal("signer wrote a signature after rejecting the key or placement")
			}
		})
	}
}

func TestCavageSignerSignedHeaderOptions(t *testing.T) {
	privateKey := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	key := fixedSigningKey("header-key", sigre.AlgorithmEd25519, privateKey)
	signer := &sigre.CavageSigner{Now: func() time.Time { return testFixedTime }}

	t.Run("AdditionalHeaders appends to request defaults", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		opts := &sigre.CavageSigningOptions{AdditionalHeaders: []string{"X-Extra"}}
		if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		headers, _ := signerPolicyParameter(t, req.Header.Get(sigre.Signature), "headers")
		if headers != "(request-target) (created) x-extra" {
			t.Fatalf("headers = %q", headers)
		}
	})

	t.Run("AdditionalHeaders appends to effective response default", func(t *testing.T) {
		res := newSignerPolicyResponse()
		opts := &sigre.CavageSigningOptions{AdditionalHeaders: []string{"X-Extra"}}
		if err := signer.SignResponse(res, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		headers, _ := signerPolicyParameter(t, res.Header.Get(sigre.Signature), "headers")
		if headers != "(created) x-extra" {
			t.Fatalf("headers = %q", headers)
		}
	})

	t.Run("ExactHeaders completely replaces defaults", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
			ExactHeaders: []string{"Date", sigre.RequestTarget},
		}}
		if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		headers, _ := signerPolicyParameter(t, req.Header.Get(sigre.Signature), "headers")
		if headers != "date (request-target)" {
			t.Fatalf("headers = %q", headers)
		}
		if _, present := signerPolicyParameter(t, req.Header.Get(sigre.Signature), "created"); present {
			t.Fatal("ExactHeaders unexpectedly retained (created)")
		}
	})

	t.Run("OmitHeaders signs effective created", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{OmitHeaders: true}}
		if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		value := req.Header.Get(sigre.Signature)
		if _, present := signerPolicyParameter(t, value, "headers"); present {
			t.Fatalf("headers was not omitted: %s", value)
		}
		if _, present := signerPolicyParameter(t, value, "created"); !present {
			t.Fatalf("created is missing: %s", value)
		}
	})

	t.Run("response OmitHeaders retains the strict wire form", func(t *testing.T) {
		strictResponse := newSignerPolicyResponse()
		if err := signer.SignResponse(strictResponse, key, sigre.CavageSignaturePlacementSignature, nil); err != nil {
			t.Fatalf("strict response signing failed: %v", err)
		}
		omittedResponse := newSignerPolicyResponse()
		opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{OmitHeaders: true}}
		if err := signer.SignResponse(omittedResponse, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("OmitHeaders response signing failed: %v", err)
		}
		if strictResponse.Header.Get(sigre.Signature) != omittedResponse.Header.Get(sigre.Signature) {
			t.Fatal("response OmitHeaders did not preserve the strict wire form")
		}
	})

	invalidOptions := []struct {
		name string
		opts *sigre.CavageSigningOptions
	}{
		{name: "empty ExactHeaders", opts: &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{ExactHeaders: []string{}}}},
		{name: "AdditionalHeaders and ExactHeaders", opts: &sigre.CavageSigningOptions{AdditionalHeaders: []string{"x-extra"}, Compatibility: &sigre.CavageSigningCompatibility{ExactHeaders: []string{"date"}}}},
		{name: "AdditionalHeaders and OmitHeaders", opts: &sigre.CavageSigningOptions{AdditionalHeaders: []string{"x-extra"}, Compatibility: &sigre.CavageSigningCompatibility{OmitHeaders: true}}},
		{name: "ExactHeaders and OmitHeaders", opts: &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{ExactHeaders: []string{"date"}, OmitHeaders: true}}},
		{name: "duplicate default", opts: &sigre.CavageSigningOptions{AdditionalHeaders: []string{sigre.Created}}},
		{name: "duplicate AdditionalHeaders", opts: &sigre.CavageSigningOptions{AdditionalHeaders: []string{"X-Extra", "x-extra"}}},
		{name: "duplicate ExactHeaders", opts: &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{ExactHeaders: []string{"Date", "date"}}}},
	}
	for _, tt := range invalidOptions {
		t.Run(tt.name, func(t *testing.T) {
			req := newSignerPolicyRequest(t)
			if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, tt.opts); !errors.Is(err, sigre.ErrInvalidSigningOptions) {
				t.Fatalf("error = %v, want ErrInvalidSigningOptions", err)
			}
		})
	}

	t.Run("missing normal header is rejected", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		opts := &sigre.CavageSigningOptions{AdditionalHeaders: []string{"X-Missing"}}
		err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts)
		if err == nil || !strings.Contains(err.Error(), "missing header") {
			t.Fatalf("error = %v, want missing header", err)
		}
	})
}

func TestCavageSignerExpiresAfter(t *testing.T) {
	privateKey := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	key := fixedSigningKey("expires-key", sigre.AlgorithmEd25519, privateKey)
	now := time.Unix(100, 900_000_000)
	signer := &sigre.CavageSigner{Now: func() time.Time { return now }}

	t.Run("duration is added before Unix conversion", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		opts := &sigre.CavageSigningOptions{
			ExpiresAfter: 200 * time.Millisecond,
			Compatibility: &sigre.CavageSigningCompatibility{
				ExactHeaders: []string{sigre.RequestTarget, sigre.Created, sigre.Expires},
			},
		}
		if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		value := req.Header.Get(sigre.Signature)
		if created, _ := signerPolicyParameter(t, value, "created"); created != "100" {
			t.Fatalf("created = %q, want 100", created)
		}
		if expires, _ := signerPolicyParameter(t, value, "expires"); expires != "101" {
			t.Fatalf("expires = %q, want 101", expires)
		}
	})

	tests := []struct {
		name string
		opts *sigre.CavageSigningOptions
	}{
		{
			name: "expires header without duration",
			opts: &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
				ExactHeaders: []string{sigre.Created, sigre.Expires},
			}},
		},
		{
			name: "duration without expires header",
			opts: &sigre.CavageSigningOptions{ExpiresAfter: time.Second},
		},
		{
			name: "negative duration",
			opts: &sigre.CavageSigningOptions{ExpiresAfter: -time.Nanosecond},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newSignerPolicyRequest(t)
			if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, tt.opts); !errors.Is(err, sigre.ErrInvalidSigningOptions) {
				t.Fatalf("error = %v, want ErrInvalidSigningOptions", err)
			}
		})
	}
}

func TestCavageSignerAlgorithmFieldCompatibility(t *testing.T) {
	rsaPrivateKey := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	ecdsaPrivateKey := parseECDSAPrivateKey(t, testECDSAPrivateKeyPEM)
	secret := []byte(testHMACSecret)
	signer := &sigre.CavageSigner{Now: func() time.Time { return testFixedTime }}

	t.Run("SHA-256 algorithms require explicit compatibility", func(t *testing.T) {
		tests := []struct {
			name string
			sign func(*http.Request) error
		}{
			{
				name: "RSA",
				sign: func(req *http.Request) error {
					return signer.SignRequest(req, fixedSigningKey("sha256-key", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPrivateKey), sigre.CavageSignaturePlacementSignature, nil)
				},
			},
			{
				name: "ECDSA",
				sign: func(req *http.Request) error {
					return signer.SignRequest(req, fixedSigningKey("sha256-key", sigre.AlgorithmECDSASHA256, ecdsaPrivateKey), sigre.CavageSignaturePlacementSignature, nil)
				},
			},
			{
				name: "HMAC",
				sign: func(req *http.Request) error {
					return signer.SignRequestWithHMAC(req, fixedHMACSigningKey("sha256-key", sigre.AlgorithmHMACSHA256, secret), sigre.CavageSignaturePlacementSignature, nil)
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.sign(newSignerPolicyRequest(t))
				if !errors.Is(err, sigre.ErrInvalidSigningOptions) || !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
					t.Fatalf("error = %v, want signing-options and signature-algorithm sentinels", err)
				}
			})
		}
	})

	t.Run("algorithm omission keeps the trusted SHA-256 algorithm", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
			AlgorithmField: sigre.AlgorithmFieldOmitted,
		}}
		key := fixedHMACSigningKey("omitted-key", sigre.AlgorithmHMACSHA256, secret)
		if err := signer.SignRequestWithHMAC(req, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		value := req.Header.Get(sigre.Signature)
		if _, present := signerPolicyParameter(t, value, "algorithm"); present {
			t.Fatalf("algorithm was not omitted: %s", value)
		}
		req.RequestURI = req.URL.RequestURI()
		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("verifier construction failed: %v", err)
		}
		verifier.Now = func() time.Time { return testFixedTime }
		verificationOptions := &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{
			AllowedLegacyAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmHMACSHA256},
		}}
		if err := verifier.VerifyHMAC(fixedHMACVerificationKey("omitted-key", sigre.AlgorithmHMACSHA256, secret), verificationOptions); err != nil {
			t.Fatalf("omitted algorithm verification failed: %v", err)
		}
	})

	t.Run("legacy labels are explicit and algorithm-specific", func(t *testing.T) {
		tests := []struct {
			name      string
			algorithm sigre.AlgorithmID
			label     string
			sign      func(*http.Request, *sigre.CavageSigningOptions) error
		}{
			{
				name: "RSA", algorithm: sigre.AlgorithmRSAPKCS1v15SHA256, label: "rsa-sha256",
				sign: func(req *http.Request, opts *sigre.CavageSigningOptions) error {
					return signer.SignRequest(req, fixedSigningKey("legacy-key", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPrivateKey), sigre.CavageSignaturePlacementSignature, opts)
				},
			},
			{
				name: "ECDSA", algorithm: sigre.AlgorithmECDSASHA256, label: "ecdsa-sha256",
				sign: func(req *http.Request, opts *sigre.CavageSigningOptions) error {
					return signer.SignRequest(req, fixedSigningKey("legacy-key", sigre.AlgorithmECDSASHA256, ecdsaPrivateKey), sigre.CavageSignaturePlacementSignature, opts)
				},
			},
			{
				name: "HMAC", algorithm: sigre.AlgorithmHMACSHA256, label: "hmac-sha256",
				sign: func(req *http.Request, opts *sigre.CavageSigningOptions) error {
					return signer.SignRequestWithHMAC(req, fixedHMACSigningKey("legacy-key", sigre.AlgorithmHMACSHA256, secret), sigre.CavageSignaturePlacementSignature, opts)
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := newSignerPolicyRequest(t)
				opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
					AlgorithmField: sigre.AlgorithmFieldLegacy,
					ExactHeaders:   []string{sigre.RequestTarget, "Date"},
				}}
				if err := tt.sign(req, opts); err != nil {
					t.Fatalf("signing failed: %v", err)
				}
				if label, _ := signerPolicyParameter(t, req.Header.Get(sigre.Signature), "algorithm"); label != tt.label {
					t.Fatalf("algorithm = %q, want %q", label, tt.label)
				}
				if _, present := signerPolicyParameter(t, req.Header.Get(sigre.Signature), "created"); present {
					t.Fatal("legacy signature unexpectedly contains created")
				}
			})
		}
	})

	t.Run("legacy request and response require explicit fields", func(t *testing.T) {
		key := fixedSigningKey("legacy-key", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPrivateKey)
		for _, tt := range []struct {
			name       string
			isResponse bool
			headers    []string
		}{
			{name: "request requires ExactHeaders", headers: nil},
			{name: "request requires request-target", headers: []string{"date"}},
			{name: "request requires date", headers: []string{sigre.RequestTarget}},
			{name: "response requires date", isResponse: true, headers: []string{"x-extra"}},
		} {
			t.Run(tt.name, func(t *testing.T) {
				opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
					AlgorithmField: sigre.AlgorithmFieldLegacy,
					ExactHeaders:   tt.headers,
				}}
				var err error
				if tt.isResponse {
					err = signer.SignResponse(newSignerPolicyResponse(), key, sigre.CavageSignaturePlacementSignature, opts)
				} else {
					err = signer.SignRequest(newSignerPolicyRequest(t), key, sigre.CavageSignaturePlacementSignature, opts)
				}
				if !errors.Is(err, sigre.ErrInvalidSigningOptions) {
					t.Fatalf("error = %v, want ErrInvalidSigningOptions", err)
				}
			})
		}

		res := newSignerPolicyResponse()
		opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
			AlgorithmField: sigre.AlgorithmFieldLegacy,
			ExactHeaders:   []string{"date"},
		}}
		if err := signer.SignResponse(res, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("legacy response signing failed: %v", err)
		}
		if label, _ := signerPolicyParameter(t, res.Header.Get(sigre.Signature), "algorithm"); label != "rsa-sha256" {
			t.Fatalf("response algorithm = %q", label)
		}
	})

	t.Run("legacy does not synthesize Date", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		req.Header.Del("Date")
		opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
			AlgorithmField: sigre.AlgorithmFieldLegacy,
			ExactHeaders:   []string{sigre.RequestTarget, "date"},
		}}
		err := signer.SignRequest(req, fixedSigningKey("legacy-key", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPrivateKey), sigre.CavageSignaturePlacementSignature, opts)
		if err == nil || !strings.Contains(err.Error(), "missing header") {
			t.Fatalf("error = %v, want missing Date", err)
		}
		if req.Header.Get("Date") != "" {
			t.Fatal("signer synthesized Date")
		}
	})

	t.Run("Fediverse hs2019 SHA-256 is RSA-only", func(t *testing.T) {
		opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
			AlgorithmField: sigre.AlgorithmFieldHS2019WithSHA256,
		}}
		req := newSignerPolicyRequest(t)
		key := fixedSigningKey("fediverse-key", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPrivateKey)
		if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("RSA signing failed: %v", err)
		}
		if label, _ := signerPolicyParameter(t, req.Header.Get(sigre.Signature), "algorithm"); label != "hs2019" {
			t.Fatalf("algorithm = %q, want hs2019", label)
		}
		req.RequestURI = req.URL.RequestURI()
		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("verifier construction failed: %v", err)
		}
		verifier.Now = func() time.Time { return testFixedTime }
		verificationOptions := &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{AllowHS2019WithSHA256: true}}
		if err := verifier.Verify(fixedPublicVerificationKey("fediverse-key", sigre.AlgorithmRSAPKCS1v15SHA256, &rsaPrivateKey.PublicKey), verificationOptions); err != nil {
			t.Fatalf("Fediverse signature verification failed: %v", err)
		}

		err = signer.SignRequest(newSignerPolicyRequest(t), fixedSigningKey("key", sigre.AlgorithmECDSASHA256, ecdsaPrivateKey), sigre.CavageSignaturePlacementSignature, opts)
		if !errors.Is(err, sigre.ErrInvalidSigningOptions) {
			t.Fatalf("ECDSA error = %v, want ErrInvalidSigningOptions", err)
		}
		err = signer.SignRequestWithHMAC(newSignerPolicyRequest(t), fixedHMACSigningKey("key", sigre.AlgorithmHMACSHA256, secret), sigre.CavageSignaturePlacementSignature, opts)
		if !errors.Is(err, sigre.ErrInvalidSigningOptions) {
			t.Fatalf("HMAC error = %v, want ErrInvalidSigningOptions", err)
		}
	})
}

func TestCavageSignerExtensionAlgorithm(t *testing.T) {
	privateKey := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	key := fixedSigningKey("extension-key", sigre.AlgorithmRSAPKCS1v15SHA512, privateKey)
	signer := &sigre.CavageSigner{Now: func() time.Time { return testFixedTime }}

	t.Run("exact label-to-AlgorithmID binding", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		opts := &sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
			Extension: &sigre.ExtensionAlgorithm{Label: "example-rsa512", Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512},
		}}
		if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		if label, _ := signerPolicyParameter(t, req.Header.Get(sigre.Signature), "algorithm"); label != "example-rsa512" {
			t.Fatalf("algorithm = %q", label)
		}
		req.RequestURI = req.URL.RequestURI()
		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("verifier construction failed: %v", err)
		}
		verifier.Now = func() time.Time { return testFixedTime }
		verificationOptions := &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{
			ExtensionAlgorithms: map[string]sigre.AlgorithmID{"example-rsa512": sigre.AlgorithmRSAPKCS1v15SHA512},
		}}
		if err := verifier.Verify(fixedPublicVerificationKey("extension-key", sigre.AlgorithmRSAPKCS1v15SHA512, &privateKey.PublicKey), verificationOptions); err != nil {
			t.Fatalf("extension verification failed: %v", err)
		}
	})

	invalid := []struct {
		name          string
		compatibility sigre.CavageSigningCompatibility
	}{
		{name: "empty label", compatibility: sigre.CavageSigningCompatibility{Extension: &sigre.ExtensionAlgorithm{Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512}}},
		{name: "zero AlgorithmID", compatibility: sigre.CavageSigningCompatibility{Extension: &sigre.ExtensionAlgorithm{Label: "example", Algorithm: 0}}},
		{name: "mismatched AlgorithmID", compatibility: sigre.CavageSigningCompatibility{Extension: &sigre.ExtensionAlgorithm{Label: "example", Algorithm: sigre.AlgorithmECDSASHA512}}},
		{name: "known hs2019 label", compatibility: sigre.CavageSigningCompatibility{Extension: &sigre.ExtensionAlgorithm{Label: "hs2019", Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512}}},
		{name: "known legacy label", compatibility: sigre.CavageSigningCompatibility{Extension: &sigre.ExtensionAlgorithm{Label: "rsa-sha256", Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512}}},
		{name: "extension and omitted mode", compatibility: sigre.CavageSigningCompatibility{AlgorithmField: sigre.AlgorithmFieldOmitted, Extension: &sigre.ExtensionAlgorithm{Label: "example", Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512}}},
		{name: "rsa prefix with created", compatibility: sigre.CavageSigningCompatibility{Extension: &sigre.ExtensionAlgorithm{Label: "rsa-custom", Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512}}},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			req := newSignerPolicyRequest(t)
			opts := &sigre.CavageSigningOptions{Compatibility: &tt.compatibility}
			if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts); !errors.Is(err, sigre.ErrInvalidSigningOptions) {
				t.Fatalf("error = %v, want ErrInvalidSigningOptions", err)
			}
		})
	}

	t.Run("rsa prefix also rejects expires", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		opts := &sigre.CavageSigningOptions{
			ExpiresAfter: time.Second,
			Compatibility: &sigre.CavageSigningCompatibility{
				ExactHeaders: []string{sigre.RequestTarget, sigre.Expires},
				Extension:    &sigre.ExtensionAlgorithm{Label: "rsa-custom", Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512},
			},
		}
		if err := signer.SignRequest(req, key, sigre.CavageSignaturePlacementSignature, opts); !errors.Is(err, sigre.ErrInvalidSigningOptions) {
			t.Fatalf("error = %v, want ErrInvalidSigningOptions", err)
		}
	})
}

func TestCavageSignerPlacement(t *testing.T) {
	secret := []byte(testHMACSecret)
	key := fixedHMACSigningKey("placement-key", sigre.AlgorithmHMACSHA512, secret)
	signer := &sigre.CavageSigner{Now: func() time.Time { return testFixedTime }}

	t.Run("Signature header", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		if err := signer.SignRequestWithHMAC(req, key, sigre.CavageSignaturePlacementSignature, nil); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		if req.Header.Get(sigre.Signature) == "" {
			t.Fatal("Signature header is missing")
		}
		if strings.HasPrefix(req.Header.Get(sigre.Authorization), "Signature ") {
			t.Fatal("Authorization also contains a Cavage signature")
		}
	})

	t.Run("Authorization Signature scheme", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		if err := signer.SignRequestWithHMAC(req, key, sigre.CavageSignaturePlacementAuthorization, nil); err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		if req.Header.Get(sigre.Signature) != "" {
			t.Fatal("Signature header was also written")
		}
		if !strings.HasPrefix(req.Header.Get(sigre.Authorization), "Signature keyId=") {
			t.Fatalf("Authorization = %q", req.Header.Get(sigre.Authorization))
		}
	})

	t.Run("existing signature source is not overwritten", func(t *testing.T) {
		for _, setup := range []func(*http.Request){
			func(req *http.Request) { req.Header.Set(sigre.Signature, `keyId="existing"`) },
			func(req *http.Request) { req.Header.Set(sigre.Authorization, `Signature keyId="existing"`) },
		} {
			req := newSignerPolicyRequest(t)
			setup(req)
			err := signer.SignRequestWithHMAC(req, key, sigre.CavageSignaturePlacementSignature, nil)
			if !errors.Is(err, sigre.ErrInvalidSignaturePlacement) {
				t.Fatalf("error = %v, want ErrInvalidSignaturePlacement", err)
			}
		}
	})

	t.Run("second placement cannot create two sources", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		if err := signer.SignRequestWithHMAC(req, key, sigre.CavageSignaturePlacementSignature, nil); err != nil {
			t.Fatalf("first signing failed: %v", err)
		}
		err := signer.SignRequestWithHMAC(req, key, sigre.CavageSignaturePlacementAuthorization, nil)
		if !errors.Is(err, sigre.ErrInvalidSignaturePlacement) {
			t.Fatalf("second error = %v, want ErrInvalidSignaturePlacement", err)
		}
		if strings.HasPrefix(req.Header.Get(sigre.Authorization), "Signature ") {
			t.Fatal("second placement was written")
		}
	})
}
