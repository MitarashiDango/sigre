package sigre_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

func TestSignAndVerify(t *testing.T) {
	rsaKeys := generateRSAKeys(t)
	rsaPrivateKey, rsaPubKey := rsaKeys.private, rsaKeys.public

	ecdsaKeys := generateECDSAKeys(t)
	ecdsaPrivateKey, ecdsaPubKey := ecdsaKeys.private, ecdsaKeys.public

	ed25519Keys := generateEd25519Keys(t)
	ed25519PrivateKey, ed25519PubKey := ed25519Keys.private, ed25519Keys.public

	hmacSecret := []byte("this-is-a-super-secret-key-for-hmac")

	testCases := []struct {
		name       string
		signOpts   signOptsPartial
		verifyOpts verifyOptsPartial

		isRequest   bool
		method      string
		url         string
		body        string
		headers     http.Header
		expectError bool
		wantErr     error
	}{
		{
			name:       "Success: RSA-SHA256 (Request)",
			isRequest:  true,
			method:     "POST",
			url:        "https://example.com/foo?param=value&pet=dog",
			body:       `{"hello": "world"}`,
			signOpts:   signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{publicKey: rsaPubKey},
		},
		{
			name:       "Success: RSA-SHA512 (Response)",
			isRequest:  false,
			method:     "GET",
			url:        "https://example.com/bar",
			body:       `"response data"`,
			signOpts:   signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA512, headers: []string{"date", "digest"}},
			verifyOpts: verifyOptsPartial{publicKey: rsaPubKey},
		},
		{
			name:       "Success: ECDSA-SHA256",
			isRequest:  true,
			method:     "PUT",
			url:        "https://example.com/baz",
			body:       "update data",
			signOpts:   signOptsPartial{privateKey: ecdsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{publicKey: ecdsaPubKey},
		},
		{
			name:       "Success: Ed25519",
			isRequest:  true,
			method:     "GET",
			url:        "https://example.com/",
			body:       "",
			signOpts:   signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(request-target)", "host", "date"}},
			verifyOpts: verifyOptsPartial{publicKey: ed25519PubKey},
		},
		{
			name:       "Success: HMAC-SHA256",
			isRequest:  true,
			method:     "DELETE",
			url:        "https://example.com/resource/123",
			body:       "",
			signOpts:   signOptsPartial{secret: hmacSecret, hash: crypto.SHA256, headers: []string{"(request-target)", "date"}},
			verifyOpts: verifyOptsPartial{secret: hmacSecret},
		},
		{
			name:       "Success: RequiredHeaders satisfied",
			isRequest:  true,
			method:     "POST",
			url:        "https://example.com/",
			signOpts:   signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256, headers: []string{"host", "date", "(request-target)"}},
			verifyOpts: verifyOptsPartial{publicKey: rsaPubKey, requiredHeaders: []string{"date", "host"}},
		},
		{
			name:      "Success: MaxSignatureAge within boundary",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(created)", "date"}},
			verifyOpts: verifyOptsPartial{
				publicKey:       ed25519PubKey,
				maxSignatureAge: 1 * time.Minute,
				overrideNowFunc: func() time.Time { return time.Date(2024, 6, 8, 10, 30, 30, 0, time.UTC) },
			},
		},
		{
			name:      "Success: AllowedAlgorithms includes signing algorithm (RSA-SHA256)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			body:      `{"hello": "world"}`,
			signOpts:  signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{
				publicKey:         rsaPubKey,
				allowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256},
			},
		},
		{
			name:      "Success: AllowedAlgorithms includes multiple algorithms (RSA-SHA512)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			body:      `{"hello": "world"}`,
			signOpts:  signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA512},
			verifyOpts: verifyOptsPartial{
				publicKey:         rsaPubKey,
				allowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA512, sigre.AlgorithmRSAPKCS1v15SHA256},
			},
		},
		{
			name:      "Success: AllowedAlgorithms unspecified",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			body:      `{"hello": "world"}`,
			signOpts:  signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{
				publicKey: rsaPubKey,
			},
		},
		{
			name:      "Success: AllowedAlgorithms permits Ed25519",
			isRequest: true,
			method:    "GET",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(request-target)", "host", "date"}},
			verifyOpts: verifyOptsPartial{
				publicKey:         ed25519PubKey,
				allowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmEd25519},
			},
		},
		{
			name:      "Success: AllowedAlgorithms permits HMAC-SHA256",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{secret: hmacSecret, hash: crypto.SHA256, headers: []string{"(request-target)", "date"}},
			verifyOpts: verifyOptsPartial{
				secret:            hmacSecret,
				allowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmHMACSHA256},
			},
		},
		{
			name:      "Failure: AllowedAlgorithms does not include trusted algorithm",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			body:      `{"hello": "world"}`,
			signOpts:  signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{
				publicKey:         rsaPubKey,
				allowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA512},
			},
			expectError: true,
			wantErr:     sigre.ErrInvalidSignatureAlgorithm,
		},
		{
			name:      "Failure: AllowedAlgorithms rejects HMAC algorithm",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{secret: hmacSecret, hash: crypto.SHA256, headers: []string{"(request-target)", "date"}},
			verifyOpts: verifyOptsPartial{
				secret:            hmacSecret,
				allowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmHMACSHA512},
			},
			expectError: true,
			wantErr:     sigre.ErrInvalidSignatureAlgorithm,
		},
		{
			name:        "Failure: RequiredHeaders not satisfied",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256, headers: []string{"host", "date"}},
			verifyOpts:  verifyOptsPartial{publicKey: rsaPubKey, requiredHeaders: []string{"digest"}},
			expectError: true,
			wantErr:     sigre.ErrRequiredHeaderMissing,
		},
		{
			name:      "Failure: MaxSignatureAge exceeded",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(created)", "date"}},
			verifyOpts: verifyOptsPartial{
				publicKey:       ed25519PubKey,
				maxSignatureAge: 1 * time.Minute,
				overrideNowFunc: func() time.Time { return time.Date(2024, 6, 8, 10, 31, 1, 0, time.UTC) },
			},
			expectError: true,
			wantErr:     sigre.ErrInvalidCreationTime,
		},
		{
			name:        "Failure: request header tampered after signing",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts:  verifyOptsPartial{publicKey: rsaPubKey, tamperHeader: &tamperAction{key: "Date", value: "tampered"}},
			expectError: true,
			wantErr:     sigre.ErrVerification,
		},
		{
			name:        "Failure: verification with wrong public key",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts:  verifyOptsPartial{publicKey: generateRSAKeys(t).public},
			expectError: true,
			wantErr:     sigre.ErrVerification,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testingNowFunc := func() time.Time {
				return time.Date(2024, 6, 8, 10, 30, 0, 0, time.UTC)
			}

			var req *http.Request
			var res *http.Response
			var err error
			if tc.isRequest {
				req, err = http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}
			} else {
				dummyReq, _ := http.NewRequest(tc.method, tc.url, nil)
				res = &http.Response{
					Request: dummyReq,
					Header:  make(http.Header),
					Body:    io.NopCloser(strings.NewReader(tc.body)),
				}
				req = dummyReq
			}

			targetHeader := req.Header
			if !tc.isRequest {
				targetHeader = res.Header
			}
			if tc.headers != nil {
				for k, v := range tc.headers {
					targetHeader[k] = v
				}
			}

			if targetHeader.Get("Date") == "" {
				targetHeader.Set("Date", testingNowFunc().UTC().Format(time.RFC1123))
			}

			if req.Host == "" {
				req.Host = req.URL.Host
			}

			if targetHeader.Get("Host") == "" {
				targetHeader.Set("Host", req.Host)
			}

			if tc.body != "" {
				h := sha256.New()
				h.Write([]byte(tc.body))
				digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
				targetHeader.Set("Digest", "SHA-256="+digest)
			}

			signOptions := &sigre.CavageSignOptions{
				Headers:         tc.signOpts.headers,
				HashAlgorithm:   tc.signOpts.hash,
				SignatureHeader: sigre.Signature,
			}

			keyId := "test-key-id"

			signer := &sigre.CavageSigner{
				Now: testingNowFunc,
			}

			if tc.isRequest {
				if len(tc.signOpts.secret) != 0 {
					if err := signer.SignRequestWithHMAC(req, tc.signOpts.secret, keyId, signOptions); err != nil {
						t.Fatalf("SignRequest failed: %v", err)
					}
				} else {
					if err := signer.SignRequest(req, tc.signOpts.privateKey, keyId, signOptions); err != nil {
						t.Fatalf("SignRequest failed: %v", err)
					}
				}
			} else {
				if len(tc.signOpts.secret) != 0 {
					if err := signer.SignResponseWithHMAC(res, tc.signOpts.secret, keyId, signOptions); err != nil {
						t.Fatalf("SignResponse failed: %v", err)
					}
				} else {
					if err := signer.SignResponse(res, tc.signOpts.privateKey, keyId, signOptions); err != nil {
						t.Fatalf("SignResponse failed: %v", err)
					}
				}
			}

			if tc.verifyOpts.tamperHeader != nil {
				tamperTarget := req.Header
				if !tc.isRequest {
					tamperTarget = res.Header
				}
				tamperTarget.Set(tc.verifyOpts.tamperHeader.key, tc.verifyOpts.tamperHeader.value)
			}
			if tc.verifyOpts.overrideNowFunc != nil {
				testingNowFunc = tc.verifyOpts.overrideNowFunc
			}

			var verifier *sigre.CavageVerifier
			if tc.isRequest {
				req.RequestURI = req.URL.RequestURI()
				verifier, err = sigre.NewCavageRequestVerifier(req)
			} else {
				verifier, err = sigre.NewCavageResponseVerifier(res)
			}
			if err != nil {
				if !tc.expectError {
					t.Fatalf("NewVerifier failed: %v", err)
				}
				return
			}

			verifier.Now = testingNowFunc

			algorithm, wireLabel := testVerificationAlgorithm(tc.signOpts)
			verifyOptions := fixedVerificationOptions(algorithm, wireLabel)
			verifyOptions.RequiredHeaders = tc.verifyOpts.requiredHeaders
			verifyOptions.AllowedAlgorithms = tc.verifyOpts.allowedAlgorithms
			verifyOptions.MaxSignatureAge = tc.verifyOpts.maxSignatureAge

			if len(tc.verifyOpts.secret) != 0 {
				err = verifier.VerifyHMAC(fixedHMACVerificationKey(keyId, algorithm, tc.verifyOpts.secret), verifyOptions)
			} else {
				err = verifier.Verify(fixedPublicVerificationKey(keyId, algorithm, tc.verifyOpts.publicKey), verifyOptions)
			}

			if tc.expectError {
				if err == nil {
					t.Error("expected an error, but verification succeeded")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got: %v", tc.wantErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("verification failed unexpectedly: %v", err)
				}
			}
		})
	}
}

func TestSignerInputValidation(t *testing.T) {
	rsaKeys := generateRSAKeys(t)
	rsaPrivateKey := rsaKeys.private
	hmacSecret := []byte("this-is-a-super-secret-key-for-hmac")
	validationDateHeader := time.Date(2024, 6, 8, 10, 30, 0, 0, time.UTC).Format(time.RFC1123)

	signer := sigre.NewCavageSigner()
	if signer.Now == nil {
		t.Fatal("NewCavageSigner() returned a signer with nil Now")
	}

	t.Run("SignRequest fails without private key", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://example.com/", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Date", validationDateHeader)
		req.Header.Set("Host", "example.com")

		err = signer.SignRequest(req, nil, "test-key", &sigre.CavageSignOptions{
			Headers:       []string{"date"},
			HashAlgorithm: crypto.SHA256,
		})
		if !errors.Is(err, sigre.ErrMissingPrivateKey) {
			t.Fatalf("expected ErrMissingPrivateKey, got: %v", err)
		}
	})

	t.Run("SignResponse fails without private key", func(t *testing.T) {
		res := &http.Response{Header: make(http.Header)}
		res.Header.Set("Date", validationDateHeader)

		err := signer.SignResponse(res, nil, "test-key", &sigre.CavageSignOptions{
			Headers:       []string{"date"},
			HashAlgorithm: crypto.SHA256,
		})
		if !errors.Is(err, sigre.ErrMissingPrivateKey) {
			t.Fatalf("expected ErrMissingPrivateKey, got: %v", err)
		}
	})

	t.Run("SignRequestWithHMAC fails without secret", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://example.com/", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Date", validationDateHeader)

		err = signer.SignRequestWithHMAC(req, nil, "test-key", &sigre.CavageSignOptions{
			Headers:       []string{"date"},
			HashAlgorithm: crypto.SHA256,
		})
		if !errors.Is(err, sigre.ErrMissingSharedSecret) {
			t.Fatalf("expected ErrMissingSharedSecret, got: %v", err)
		}
	})

	t.Run("SignResponseWithHMAC fails without secret", func(t *testing.T) {
		res := &http.Response{Header: make(http.Header)}
		res.Header.Set("Date", validationDateHeader)

		err := signer.SignResponseWithHMAC(res, nil, "test-key", &sigre.CavageSignOptions{
			Headers:       []string{"date"},
			HashAlgorithm: crypto.SHA256,
		})
		if !errors.Is(err, sigre.ErrMissingSharedSecret) {
			t.Fatalf("expected ErrMissingSharedSecret, got: %v", err)
		}
	})

	t.Run("RSA signing fails without hash algorithm", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://example.com/", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Date", validationDateHeader)

		err = signer.SignRequest(req, rsaPrivateKey, "test-key", &sigre.CavageSignOptions{
			Headers: []string{"date"},
		})
		if err == nil || !strings.Contains(err.Error(), "hash algorithm must be specified") {
			t.Fatalf("expected missing hash algorithm error, got: %v", err)
		}
	})

	t.Run("legacy RSA signing rejects created pseudo-header", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://example.com/", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		err = signer.SignRequest(req, rsaPrivateKey, "test-key", &sigre.CavageSignOptions{
			Headers:       []string{"(created)"},
			HashAlgorithm: crypto.SHA256,
		})
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected ErrInvalidSignatureAlgorithm, got: %v", err)
		}
	})

	t.Run("legacy HMAC signing rejects expires pseudo-header", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://example.com/", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		err = signer.SignRequestWithHMAC(req, hmacSecret, "test-key", &sigre.CavageSignOptions{
			Headers:       []string{"(expires)"},
			HashAlgorithm: crypto.SHA256,
		})
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected ErrInvalidSignatureAlgorithm, got: %v", err)
		}
	})

	t.Run("signing fails when a listed header is missing", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://example.com/", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		err = signer.SignRequest(req, rsaPrivateKey, "test-key", &sigre.CavageSignOptions{
			Headers:       []string{"date"},
			HashAlgorithm: crypto.SHA256,
		})
		if err == nil || !strings.Contains(err.Error(), "missing header") {
			t.Fatalf("expected missing header error, got: %v", err)
		}
	})

	t.Run("keyId is escaped in Authorization and restored by the parser", func(t *testing.T) {
		const keyID = "key\"quote\\slash"
		req, err := http.NewRequest("GET", "https://example.com/", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Date", validationDateHeader)

		err = signer.SignRequest(req, rsaPrivateKey, keyID, &sigre.CavageSignOptions{
			Headers:         []string{"date"},
			HashAlgorithm:   crypto.SHA256,
			SignatureHeader: sigre.Authorization,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}
		if got := req.Header.Get(sigre.Authorization); !strings.Contains(got, `keyId="key\"quote\\slash"`) {
			t.Fatalf("Authorization keyId is not correctly escaped: %s", got)
		}

		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("failed to parse generated Authorization signature: %v", err)
		}
		if verifier.KeyId() != keyID {
			t.Fatalf("KeyId() = %q, want %q", verifier.KeyId(), keyID)
		}
	})

	t.Run("all signing paths reject empty or unsafe keyId", func(t *testing.T) {
		testCases := []struct {
			name  string
			keyID string
			run   func(string) (http.Header, error)
		}{
			{
				name: "request asymmetric",
				run: func(keyID string) (http.Header, error) {
					req, err := http.NewRequest("GET", "https://example.com/", nil)
					if err != nil {
						return nil, err
					}
					req.Header.Set("Date", validationDateHeader)
					err = signer.SignRequest(req, rsaPrivateKey, keyID, &sigre.CavageSignOptions{Headers: []string{"date"}, HashAlgorithm: crypto.SHA256})
					return req.Header, err
				},
			},
			{
				name: "request HMAC",
				run: func(keyID string) (http.Header, error) {
					req, err := http.NewRequest("GET", "https://example.com/", nil)
					if err != nil {
						return nil, err
					}
					req.Header.Set("Date", validationDateHeader)
					err = signer.SignRequestWithHMAC(req, hmacSecret, keyID, &sigre.CavageSignOptions{Headers: []string{"date"}, HashAlgorithm: crypto.SHA256})
					return req.Header, err
				},
			},
			{
				name: "response asymmetric",
				run: func(keyID string) (http.Header, error) {
					res := &http.Response{Header: make(http.Header)}
					res.Header.Set("Date", validationDateHeader)
					err := signer.SignResponse(res, rsaPrivateKey, keyID, &sigre.CavageSignOptions{Headers: []string{"date"}, HashAlgorithm: crypto.SHA256})
					return res.Header, err
				},
			},
			{
				name: "response HMAC",
				run: func(keyID string) (http.Header, error) {
					res := &http.Response{Header: make(http.Header)}
					res.Header.Set("Date", validationDateHeader)
					err := signer.SignResponseWithHMAC(res, hmacSecret, keyID, &sigre.CavageSignOptions{Headers: []string{"date"}, HashAlgorithm: crypto.SHA256})
					return res.Header, err
				},
			},
		}

		for _, tc := range testCases {
			for _, keyID := range []string{"", "unsafe\nkey"} {
				t.Run(tc.name+"/"+keyID, func(t *testing.T) {
					header, err := tc.run(keyID)
					if err == nil {
						t.Fatal("expected invalid keyId to be rejected")
					}
					if header.Get(sigre.Signature) != "" || header.Get(sigre.Authorization) != "" {
						t.Fatal("signer wrote a signature header after rejecting keyId")
					}
				})
			}
		}
	})
}

type signOptsPartial struct {
	privateKey crypto.PrivateKey
	secret     []byte
	hash       crypto.Hash
	headers    []string
}

type verifyOptsPartial struct {
	publicKey         crypto.PublicKey
	secret            []byte
	maxSignatureAge   time.Duration
	requiredHeaders   []string
	allowedAlgorithms []sigre.AlgorithmID
	tamperHeader      *tamperAction
	overrideNowFunc   func() time.Time
}

func testVerificationAlgorithm(opts signOptsPartial) (sigre.AlgorithmID, string) {
	if len(opts.secret) != 0 {
		if opts.hash == crypto.SHA512 {
			return sigre.AlgorithmHMACSHA512, "hmac-sha512"
		}
		return sigre.AlgorithmHMACSHA256, "hmac-sha256"
	}
	switch opts.privateKey.(type) {
	case *rsa.PrivateKey:
		if opts.hash == crypto.SHA512 {
			return sigre.AlgorithmRSAPKCS1v15SHA512, "rsa-sha512"
		}
		return sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256"
	case *ecdsa.PrivateKey:
		if opts.hash == crypto.SHA512 {
			return sigre.AlgorithmECDSASHA512, "ecdsa-sha512"
		}
		return sigre.AlgorithmECDSASHA256, "ecdsa-sha256"
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return sigre.AlgorithmEd25519, "ed25519"
	default:
		panic("unsupported test signing key")
	}
}

type tamperAction struct {
	key   string
	value string
}

type rsaKeyPair struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func generateRSAKeys(t *testing.T) rsaKeyPair {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA keys: %v", err)
	}
	return rsaKeyPair{private: privateKey, public: &privateKey.PublicKey}
}

type ecdsaKeyPair struct {
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

func generateECDSAKeys(t *testing.T) ecdsaKeyPair {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA keys: %v", err)
	}
	return ecdsaKeyPair{private: privateKey, public: &privateKey.PublicKey}
}

type ed25519KeyPair struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func generateEd25519Keys(t *testing.T) ed25519KeyPair {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keys: %v", err)
	}
	return ed25519KeyPair{private: privateKey, public: publicKey}
}
