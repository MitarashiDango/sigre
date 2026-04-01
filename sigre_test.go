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
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

// Sign and Verify E2E Tests
func TestSignAndVerify(t *testing.T) {
	// Generate key pairs used in tests
	rsaKeys := generateRSAKeys(t)
	rsaPrivateKey, rsaPubKey := rsaKeys.private, rsaKeys.public

	ecdsaKeys := generateECDSAKeys(t)
	ecdsaPrivateKey, ecdsaPubKey := ecdsaKeys.private, ecdsaKeys.public

	ed25519Keys := generateEd25519Keys(t)
	ed25519PrivateKey, ed25519PubKey := ed25519Keys.private, ed25519Keys.public

	hmacSecret := []byte("this-is-a-super-secret-key-for-hmac")

	// Test case definitions
	testCases := []struct {
		name string // test case name

		// sign options
		signOpts signOptsPartial

		// verify options
		verifyOpts verifyOptsPartial

		// HTTP request/response
		isRequest   bool
		method      string
		url         string
		body        string
		headers     http.Header
		expectError bool
	}{
		// --- Success cases: algorithm tests ---
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
			body:       "", // no body
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
		// --- Success cases: VerifyOptions tests ---
		{
			name:       "Success: RequiredHeaders satisfied",
			isRequest:  true,
			method:     "POST",
			url:        "https://example.com/",
			signOpts:   signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256, headers: []string{"host", "date", "(request-target)"}},
			verifyOpts: verifyOptsPartial{publicKey: rsaPubKey, requiredHeaders: []string{"date", "host"}},
		},
		{
			name:      "Success: AllowedClockSkew (future)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(created)", "date"}},
			verifyOpts: verifyOptsPartial{
				publicKey: ed25519PubKey,
				clockSkew: 1 * time.Minute,
				// Verify 30 seconds later; should succeed within skew (60s)
				overrideNowFunc: func() time.Time { return time.Date(2024, 6, 8, 10, 30, 30, 0, time.UTC) },
			},
		},
		// --- Success cases: AllowedHashAlgorithms tests ---
		{
			name:      "Success: AllowedHashAlgorithms includes signing algorithm (RSA-SHA256)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			body:      `{"hello": "world"}`,
			signOpts:  signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{
				publicKey:     rsaPubKey,
				allowedHashes: []crypto.Hash{crypto.SHA256},
			},
		},
		{
			name:      "Success: AllowedHashAlgorithms includes multiple hashes (RSA-SHA512)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			body:      `{"hello": "world"}`,
			signOpts:  signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA512},
			verifyOpts: verifyOptsPartial{
				publicKey:     rsaPubKey,
				allowedHashes: []crypto.Hash{crypto.SHA512, crypto.SHA256},
			},
		},
		{
			name:      "Success: AllowedHashAlgorithms unspecified (uses default allow list)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			body:      `{"hello": "world"}`,
			signOpts:  signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{
				publicKey: rsaPubKey,
				// allowedHashes not set -> DefaultAllowedHashAlgorithms (SHA-512, SHA-256)
			},
		},
		{
			name:      "Success: AllowedHashAlgorithms does not affect Ed25519 (no hash required)",
			isRequest: true,
			method:    "GET",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(request-target)", "host", "date"}},
			verifyOpts: verifyOptsPartial{
				publicKey:     ed25519PubKey,
				allowedHashes: []crypto.Hash{crypto.SHA512}, // Ed25519 does not use hash, so no effect
			},
		},
		{
			name:      "Success: AllowedHashAlgorithms permits HMAC-SHA256",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{secret: hmacSecret, hash: crypto.SHA256, headers: []string{"(request-target)", "date"}},
			verifyOpts: verifyOptsPartial{
				secret:        hmacSecret,
				allowedHashes: []crypto.Hash{crypto.SHA256},
			},
		},
		// --- Failure cases ---
		{
			name:      "Failure: AllowedHashAlgorithms does not include signing algorithm",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			body:      `{"hello": "world"}`,
			signOpts:  signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{
				publicKey:     rsaPubKey,
				allowedHashes: []crypto.Hash{crypto.SHA512}, // signed with SHA-256 but only SHA-512 allowed
			},
			expectError: true,
		},
		{
			name:      "Failure: AllowedHashAlgorithms rejects HMAC hash",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{secret: hmacSecret, hash: crypto.SHA256, headers: []string{"(request-target)", "date"}},
			verifyOpts: verifyOptsPartial{
				secret:        hmacSecret,
				allowedHashes: []crypto.Hash{crypto.SHA512}, // signed with SHA-256 but only SHA-512 allowed
			},
			expectError: true,
		},
		{
			name:        "Failure: RequiredHeaders not satisfied",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256, headers: []string{"host", "date"}},
			verifyOpts:  verifyOptsPartial{publicKey: rsaPubKey, requiredHeaders: []string{"digest"}},
			expectError: true, // error because `digest` is not in signed headers
		},
		{
			name:      "Failure: AllowedClockSkew exceeded (too old)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(created)", "date"}},
			verifyOpts: verifyOptsPartial{
				publicKey: ed25519PubKey,
				clockSkew: 1 * time.Minute,
				// Verify 61 seconds later; exceeds skew (60s) so should fail
				overrideNowFunc: func() time.Time { return time.Date(2024, 6, 8, 10, 31, 1, 0, time.UTC) },
			},
			expectError: true,
		},
		{
			name:        "Failure: request header tampered after signing",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts:  verifyOptsPartial{publicKey: rsaPubKey, tamperHeader: &tamperAction{key: "Date", value: "tampered"}},
			expectError: true,
		},
		{
			name:        "Failure: verification with wrong public key",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts:  verifyOptsPartial{publicKey: generateRSAKeys(t).public}, // different key pair
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// --- Test setup ---

			// Fix the time so signature results are always the same
			testingNowFunc := func() time.Time {
				// 2024-06-08 10:30:00 UTC
				return time.Date(2024, 6, 8, 10, 30, 0, 0, time.UTC)
			}

			// Create request/response objects
			var req *http.Request
			var res *http.Response
			var err error
			if tc.isRequest {
				req, err = http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}
			} else {
				// Response tests require a dummy request
				dummyReq, _ := http.NewRequest(tc.method, tc.url, nil)
				res = &http.Response{
					Request: dummyReq,
					Header:  make(http.Header),
					Body:    io.NopCloser(strings.NewReader(tc.body)),
				}
				req = dummyReq // host etc. are taken from the request even for response signing
			}

			// Prepare headers
			targetHeader := req.Header
			if !tc.isRequest {
				targetHeader = res.Header
			}
			if tc.headers != nil {
				for k, v := range tc.headers {
					targetHeader[k] = v
				}
			}

			// Add default required headers
			if targetHeader.Get("Date") == "" {
				targetHeader.Set("Date", time.Now().UTC().Format(time.RFC1123))
			}

			if req.Host == "" { // http.NewRequest sets Host from URL
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

			t.Log(targetHeader)

			// --- Sign ---
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

			// --- Prepare verification (tampering, time override, etc.) ---
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

			// --- Verify ---
			var verifier *sigre.CavageVerifier
			if tc.isRequest {
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

			verifyOptions := &sigre.VerifyOptions{
				AllowedClockSkew:      tc.verifyOpts.clockSkew,
				RequiredHeaders:       tc.verifyOpts.requiredHeaders,
				AllowedHashAlgorithms: tc.verifyOpts.allowedHashes,
			}

			if len(tc.verifyOpts.secret) != 0 {
				err = verifier.VerifyHMAC(tc.verifyOpts.secret, verifyOptions)
			} else {
				err = verifier.Verify(tc.verifyOpts.publicKey, verifyOptions)
			}

			// --- Check results ---
			if tc.expectError {
				if err == nil {
					t.Error("expected an error, but verification succeeded")
				}
			} else {
				if err != nil {
					t.Errorf("verification failed unexpectedly: %v", err)
				}
			}
		})
	}
}

// ===== Helper Structs for Tests =====

// signOptsPartial holds partial sign options that differ per test case.
type signOptsPartial struct {
	privateKey crypto.PrivateKey
	secret     []byte
	hash       crypto.Hash
	headers    []string
}

// verifyOptsPartial holds partial verify options that differ per test case.
type verifyOptsPartial struct {
	publicKey       crypto.PublicKey
	secret          []byte
	clockSkew       time.Duration
	requiredHeaders []string
	allowedHashes   []crypto.Hash
	tamperHeader    *tamperAction
	overrideNowFunc func() time.Time
}

// tamperAction defines a header tampering action before verification.
type tamperAction struct {
	key   string
	value string
}

// ===== Helper Functions for Key Generation =====

// rsaKeyPair holds an RSA key pair for tests.
type rsaKeyPair struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

// generateRSAKeys generates an RSA key pair for tests.
func generateRSAKeys(t *testing.T) rsaKeyPair {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA keys: %v", err)
	}
	return rsaKeyPair{private: privateKey, public: &privateKey.PublicKey}
}

// ecdsaKeyPair holds an ECDSA key pair for tests.
type ecdsaKeyPair struct {
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

// generateECDSAKeys generates an ECDSA key pair (P-256) for tests.
func generateECDSAKeys(t *testing.T) ecdsaKeyPair {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA keys: %v", err)
	}
	return ecdsaKeyPair{private: privateKey, public: &privateKey.PublicKey}
}

// ed25519KeyPair holds an Ed25519 key pair for tests.
type ed25519KeyPair struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

// generateEd25519Keys generates an Ed25519 key pair for tests.
func generateEd25519Keys(t *testing.T) ed25519KeyPair {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keys: %v", err)
	}
	return ed25519KeyPair{private: privateKey, public: publicKey}
}
