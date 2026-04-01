package sigre_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

// ===== Fixed test keys (PEM) =====
// These keys are for testing only and are used to ensure reproducibility of test vectors.

const testRSAPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz5wcFrzkXvQgvbXngC32au35pwT0zHYbcrFe/OSm5G1UJlyh
M6+trtaPH9uQBziFE6EmUbDlums2qJpmS1vn4rmVb2YgfrnKmMPzHMeM3sshp0Z+
gT3HdBBgZ+5b7xvs+nEWWT4C/0BbZ2MDrde3h7aILJi5cKPYPOff2MdKA9RLjSyH
NBjZj8GdL+gSNWAFgUYcWD0yNZSoCcNDLhMInD+6JZ+mm+yCt1A5Oao6e1iD5nkj
ghXTNmaBqX/okYPXUf6wAk+UI6uIfSfbefHboGPO25zmOAJR7tRR4CTsCMIn6Dbu
/1JSTg8XJM0oia+YmcS7KetZUeghv4uM9q36XQIDAQABAoIBABGp7pngqG2Lx91c
RL4bKwQeC0eynEFpKxyvCq3ppml5A9ffubd0Ewr1JmhHfhGfNXNeGqyIqIMb7CKc
QGfZAfnAYH6B6fHeTOaChYTFVa7/CXX6AXltkDLH0ewF07ycW6VTSdt98zNUfnJl
ckKwP+VEGoHw3JZA2n0UHW+MRTfeCPSagSyOKVDsrlix/tO5qwXhugocUN58ZaTo
inatgF2PyUJmpdlLa0tOFFSTH3F40sIdAC1cHLajYT6sp6IAvSDfuG+HLQYO1/6a
4d2ZDmKenSW7UDktz7t4XBCOtUPDlT54I3lLg0DScTGcsCwrhhejYZyoeJlugXoZ
wAOb3OECgYEA5WaWniln9IXKKqmEqDmB6MpQm37cCCPGxNR7/ibUH7gkjy2Y1od5
PB1ulLsqYqe/WzhQS6cTqNN1HIY6H+ziKOaKNduc8NZwby8oMqqgQxGbX5xAJbJR
A2UJGve7lDgyTH3zVssVf+jVnAeLllPjWVWrt+UVlP+8KziK8uiCsJMCgYEA566w
0wwwzwspEJRUYIn8SYtmobqaUxPEJf6iwNch8BifFBi4M54gDtTzqAuQL8PK6nlH
9SFUtdRuR0sJQkb0undaVu0NJi7vht+uGYuagOHtipg5lhPsZfxiMP04OfNqWO75
rizwN5Fnqqz2j/eOcFZk++vbCOqjMrwcaynnr08CgYAQ+Rsxzpx7ch64M1y2WbLr
93QpXSSIkaUWUSZvco4FXsmNsnD5hoKI2SCiboq/S+wTosIGJvGEb0jd+Gx6ijtd
jVkyjPI6u5MMFvAhd5BuBfJ6C4SPhXcLCkG3Nhcx60qFcFg91r7bfO25IrHISKKs
rHMNIy0KnjVc+U0Glf99cwKBgQCbbCCpZEs2ChmhSrCUFt1NhRvzsRgoVWFHz9vl
HC1jQVEujSq9Tf3ZlVhjymYO9P0icPwp4RNP69OTNi5e7PTuRnUvTVV94QzE4TeN
YY7jmSzexiIToQf8nuRMUwMuNTKJuL987h60WHJAGEpL6FoA2KRkMCQ/hhC3T2SN
K46GlwKBgC/hwcwKqHx5lEVsIQaUDuoSpEeBJHpmW8D01SzR7bsczjIw6QwlhoAv
KT27nz/wWooXv+Z6l1bGvskWxRbdY4IlkziguvR5VxCpiiwADluX2iK+Etf231CY
lfoa3jvZZXlHvNAsPkvJVYTJiDvSsuhHOrPOoSV0EQ6AtXu7Wh2t
-----END RSA PRIVATE KEY-----`

const testRSAPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5wcFrzkXvQgvbXngC32
au35pwT0zHYbcrFe/OSm5G1UJlyhM6+trtaPH9uQBziFE6EmUbDlums2qJpmS1vn
4rmVb2YgfrnKmMPzHMeM3sshp0Z+gT3HdBBgZ+5b7xvs+nEWWT4C/0BbZ2MDrde3
h7aILJi5cKPYPOff2MdKA9RLjSyHNBjZj8GdL+gSNWAFgUYcWD0yNZSoCcNDLhMI
nD+6JZ+mm+yCt1A5Oao6e1iD5nkjghXTNmaBqX/okYPXUf6wAk+UI6uIfSfbefHb
oGPO25zmOAJR7tRR4CTsCMIn6Dbu/1JSTg8XJM0oia+YmcS7KetZUeghv4uM9q36
XQIDAQAB
-----END PUBLIC KEY-----`

const testECDSAPrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHYkGVux8qaVm70//JmEmsCpopfHRJ8HNXxfflM1xzw3oAoGCCqGSM49
AwEHoUQDQgAEnNXHQzaD5HXNK4RgIvEBZNxKRR+GJqFpSx5fDc7vKwSeu8mjYPV1
6CHta3/VzziupiyM0JwX9RqvyfBSRrtYDA==
-----END EC PRIVATE KEY-----`

const testECDSAPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnNXHQzaD5HXNK4RgIvEBZNxKRR+G
JqFpSx5fDc7vKwSeu8mjYPV16CHta3/VzziupiyM0JwX9RqvyfBSRrtYDA==
-----END PUBLIC KEY-----`

const testEd25519PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICcT+YOJKFs5p9zksAMb9H2hYwm2cguxTOc0HVPDLmiI
-----END PRIVATE KEY-----`

const testEd25519PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAXqAc1ePYsErSWb5ZhyRLjUQXx4nbWvLJqAPlnLGuLq8=
-----END PUBLIC KEY-----`

const testHMACSecret = "test-hmac-secret-key-for-sigre-testing"

// testFixedTime is the fixed time used in signing tests (2024-06-08 10:30:00 UTC).
// Unix timestamp: 1717839000
var testFixedTime = time.Date(2024, 6, 8, 10, 30, 0, 0, time.UTC)

// ===== PEM key parse helpers =====

func parseRSAPrivateKey(t *testing.T, pemStr string) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse RSA private key: %v", err)
	}
	return key
}

func parseRSAPublicKey(t *testing.T, pemStr string) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse RSA public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not an RSA public key")
	}
	return rsaPub
}

func parseECDSAPrivateKey(t *testing.T, pemStr string) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse ECDSA private key: %v", err)
	}
	return key
}

func parseECDSAPublicKey(t *testing.T, pemStr string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse ECDSA public key: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not an ECDSA public key")
	}
	return ecPub
}

func parseEd25519PrivateKey(t *testing.T, pemStr string) ed25519.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse Ed25519 private key: %v", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("parsed key is not an Ed25519 private key")
	}
	return edKey
}

func parseEd25519PublicKey(t *testing.T, pemStr string) ed25519.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse Ed25519 public key: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("parsed key is not an Ed25519 public key")
	}
	return edPub
}

// ===== Test HTTP request/response construction helpers =====

const testDateHeader = "Sat, 08 Jun 2024 10:30:00 UTC"
const testBodyJSON = `{"hello": "world"}`

// testBodyDigest is the SHA-256 digest of testBodyJSON in "SHA-256=..." format.
var testBodyDigest = func() string {
	h := sha256.Sum256([]byte(testBodyJSON))
	return "SHA-256=" + base64.StdEncoding.EncodeToString(h[:])
}()

func newTestRequest(t *testing.T, method, urlStr, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create test request: %v", err)
	}
	return req
}

// setStandardHeaders sets standard headers for tests.
func setStandardHeaders(t *testing.T, header http.Header, host string, includeDigest bool) {
	t.Helper()
	header.Set("Date", testDateHeader)
	header.Set("Host", host)
	if includeDigest {
		header.Set("Digest", testBodyDigest)
	}
}

// ===================================================================
// Sign and verify tests using fixed key pairs
// ===================================================================

// TestFixedKeySignAndVerify runs E2E sign and verify tests using fixed PEM key pairs.
func TestFixedKeySignAndVerify(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)
	ecPriv := parseECDSAPrivateKey(t, testECDSAPrivateKeyPEM)
	ecPub := parseECDSAPublicKey(t, testECDSAPublicKeyPEM)
	edPriv := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)
	hmacSecret := []byte(testHMACSecret)

	nowFunc := func() time.Time { return testFixedTime }

	testCases := []struct {
		name        string
		setup       func(t *testing.T) *http.Request
		signFunc    func(t *testing.T, signer *sigre.CavageSigner, req *http.Request)
		verifyFunc  func(t *testing.T, verifier *sigre.CavageVerifier)
		wantKeyId   string
		expectError bool
	}{
		{
			name: "RSA-SHA256: sign with fixed key and verify with same public key",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/foo?param=value&pet=dog", testBodyJSON)
				setStandardHeaders(t, req.Header, "example.com", true)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "host", "date", "digest"},
					HashAlgorithm:   crypto.SHA256,
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				err := verifier.Verify(rsaPub, &sigre.VerifyOptions{})
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}
			},
			wantKeyId: "test-key-rsa",
		},
		{
			name: "RSA-SHA512: sign with fixed key and verify with same public key",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "PUT", "https://example.com/update", testBodyJSON)
				setStandardHeaders(t, req.Header, "example.com", true)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequest(req, rsaPriv, "test-key-rsa-512", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "host", "date", "digest"},
					HashAlgorithm:   crypto.SHA512,
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				err := verifier.Verify(rsaPub, &sigre.VerifyOptions{})
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}
			},
			wantKeyId: "test-key-rsa-512",
		},
		{
			name: "ECDSA-SHA256: sign with fixed key and verify with same public key",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/ecdsa", testBodyJSON)
				setStandardHeaders(t, req.Header, "example.com", true)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequest(req, ecPriv, "test-key-ecdsa", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "host", "date", "digest"},
					HashAlgorithm:   crypto.SHA256,
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				err := verifier.Verify(ecPub, &sigre.VerifyOptions{})
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}
			},
			wantKeyId: "test-key-ecdsa",
		},
		{
			name: "Ed25519: sign with fixed key and verify with same public key",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "GET", "https://example.com/", "")
				setStandardHeaders(t, req.Header, "example.com", false)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequest(req, edPriv, "test-key-ed25519", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "host", "date"},
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				err := verifier.Verify(edPub, &sigre.VerifyOptions{})
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}
			},
			wantKeyId: "test-key-ed25519",
		},
		{
			name: "HMAC-SHA256: sign with fixed secret and verify with same secret",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "DELETE", "https://example.com/resource/123", "")
				setStandardHeaders(t, req.Header, "example.com", false)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequestWithHMAC(req, hmacSecret, "test-key-hmac", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "date"},
					HashAlgorithm:   crypto.SHA256,
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				err := verifier.VerifyHMAC(hmacSecret, &sigre.VerifyOptions{})
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}
			},
			wantKeyId: "test-key-hmac",
		},
		{
			name: "RSA-SHA256: verification fails with different RSA public key",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/foo", testBodyJSON)
				setStandardHeaders(t, req.Header, "example.com", true)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "host", "date", "digest"},
					HashAlgorithm:   crypto.SHA256,
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				// Attempt verification with a different random RSA key
				wrongKey := generateRSAKeys(t).public
				err := verifier.Verify(wrongKey, &sigre.VerifyOptions{})
				if err == nil {
					t.Error("verification succeeded with a different public key")
				}
			},
			wantKeyId:   "test-key-rsa",
			expectError: true,
		},
		{
			name: "Ed25519: verification fails with different Ed25519 public key",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "GET", "https://example.com/", "")
				setStandardHeaders(t, req.Header, "example.com", false)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequest(req, edPriv, "test-key-ed25519", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "host", "date"},
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				wrongKey := generateEd25519Keys(t).public
				err := verifier.Verify(wrongKey, &sigre.VerifyOptions{})
				if err == nil {
					t.Error("verification succeeded with a different public key")
				}
			},
			wantKeyId:   "test-key-ed25519",
			expectError: true,
		},
		{
			name: "HMAC-SHA256: verification fails with different secret",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "DELETE", "https://example.com/resource/123", "")
				setStandardHeaders(t, req.Header, "example.com", false)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequestWithHMAC(req, hmacSecret, "test-key-hmac", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "date"},
					HashAlgorithm:   crypto.SHA256,
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				wrongSecret := []byte("wrong-secret-key")
				err := verifier.VerifyHMAC(wrongSecret, &sigre.VerifyOptions{})
				if err == nil {
					t.Error("verification succeeded with a different secret")
				}
			},
			wantKeyId:   "test-key-hmac",
			expectError: true,
		},
		{
			name: "Ed25519: sign and verify with (created) pseudo-header",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/api/data", "")
				setStandardHeaders(t, req.Header, "example.com", false)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequest(req, edPriv, "test-key-ed25519", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "(created)", "host"},
					SignatureHeader: sigre.Signature,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				err := verifier.Verify(edPub, &sigre.VerifyOptions{})
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}
			},
			wantKeyId: "test-key-ed25519",
		},
		{
			name: "RSA-SHA256: sign and verify with Authorization header format",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/auth", testBodyJSON)
				setStandardHeaders(t, req.Header, "example.com", true)
				return req
			},
			signFunc: func(t *testing.T, signer *sigre.CavageSigner, req *http.Request) {
				err := signer.SignRequest(req, rsaPriv, "test-key-rsa-auth", &sigre.CavageSignOptions{
					Headers:         []string{"(request-target)", "host", "date", "digest"},
					HashAlgorithm:   crypto.SHA256,
					SignatureHeader: sigre.Authorization,
				})
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) {
				err := verifier.Verify(rsaPub, &sigre.VerifyOptions{})
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}
			},
			wantKeyId: "test-key-rsa-auth",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.setup(t)

			signer := &sigre.CavageSigner{Now: nowFunc}
			tc.signFunc(t, signer, req)

			verifier, err := sigre.NewCavageRequestVerifier(req)
			if err != nil {
				t.Fatalf("failed to create verifier: %v", err)
			}
			verifier.Now = nowFunc

			if verifier.KeyId() != tc.wantKeyId {
				t.Errorf("KeyId() = %q, want %q", verifier.KeyId(), tc.wantKeyId)
			}

			tc.verifyFunc(t, verifier)
		})
	}
}

// ===================================================================
// Verification tests using precomputed signature values
// These tests verify manually constructed Signature headers without using the library's signer.
// Signature values are precomputed from the test keys and fixed.
// ===================================================================

// TestVerifyPrecomputedSignatures verifies precomputed signatures directly.
// RSA and Ed25519 are deterministic signature algorithms, so they always produce
// the same signature for the same input.
func TestVerifyPrecomputedSignatures(t *testing.T) {
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	testCases := []struct {
		name       string
		setup      func(t *testing.T) *http.Request
		verifyFunc func(t *testing.T, verifier *sigre.CavageVerifier) error
		wantKeyId  string
		wantErr    bool
	}{
		{
			name: "RSA-SHA256: verify precomputed signature succeeds",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/foo?param=value&pet=dog", testBodyJSON)
				req.Header.Set("Date", testDateHeader)
				req.Header.Set("Host", "example.com")
				req.Header.Set("Digest", testBodyDigest)
				// Set precomputed Signature header directly
				req.Header.Set("Signature",
					`keyId="test-key-rsa",signature="dOtpLN/dEThM4gw4WBel/t5AybfCgIerAzkHzj2S3rU6OH+ODDLxcwS0UcL0L6NOCnCgw/ndz67ATcpbkSwRZ0QDAn+fTCP4Xe8Yjal/GyC9FhglQ3wTxFp6rUp5bpT7Al3NrYeAMAcvHlMeHi3b64LovkCtPY8TAf+MbKOdtxFiU8F264O5eRZ0wkSp2cBX5JOrPGEWsLY/wO1n1nG02yBzswntBsSK2CCEDra4XjIKFfzooB3tUco4b+1mflALaHMezUP8sn/B48ShoCH4+vUxjcuuJaL162coMgbw+6T1oCOCdXLUSjveqPi8PCRPkO7OIELkTdKOf+VqE5nqlA==",algorithm="rsa-sha256",headers="(request-target) host date digest"`)
				return req
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) error {
				return verifier.Verify(rsaPub, &sigre.VerifyOptions{})
			},
			wantKeyId: "test-key-rsa",
		},
		{
			name: "RSA-SHA512: verify precomputed signature succeeds",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/foo", testBodyJSON)
				req.Header.Set("Date", testDateHeader)
				req.Header.Set("Host", "example.com")
				req.Header.Set("Digest", testBodyDigest)
				req.Header.Set("Signature",
					`keyId="test-key-rsa",signature="l36dg8IqFddjKdyQsdWZ4n2QzkSdpCnq9jmvVqsBFcQUW9+r19azLRCpUoV2p3DkvhN1+Ub4mwouipzczQRQcAtcs1x4ZaZKi7J6uYgCe8QpsV/4ixAmD80mDYttXHPCUr8IU1Wg/Iaq6emYsm/cHFH/O46NSO+7dnZDJ1uCAVSTOp5vrlOTKtwgbg6sU7SXEDhUQ+gXSdToa7wXzHkgEIJAMnU815Y0lxI4Djt20ncmWbDC73Mp1ePlalbH2N9Y+rSY3/j4Aos0vIvtSl30zYi2EWO8Uhto4BmzivPRmXKGTJNk8tWtfT99I/t/4UIPuVPaI4kiWcVT0wcamkVkEA==",algorithm="rsa-sha512",headers="date digest"`)
				return req
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) error {
				return verifier.Verify(rsaPub, &sigre.VerifyOptions{})
			},
			wantKeyId: "test-key-rsa",
		},
		{
			name: "Ed25519: verify precomputed signature succeeds",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "GET", "https://example.com/", "")
				req.Header.Set("Date", testDateHeader)
				req.Header.Set("Host", "example.com")
				req.Header.Set("Signature",
					`keyId="test-key-ed25519",signature="UMoMdVYlZBWj9umkv0oWSu5SDuOiZcE621beuDE7UmiGX9ttA/5drFgi5ZweInRDPj5fS70q8jQEgJni5ZGNAA==",algorithm="ed25519",headers="(request-target) host date"`)
				return req
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) error {
				return verifier.Verify(edPub, &sigre.VerifyOptions{})
			},
			wantKeyId: "test-key-ed25519",
		},
		{
			name: "HMAC-SHA256: verify precomputed signature succeeds",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "DELETE", "https://example.com/resource/123", "")
				req.Header.Set("Date", testDateHeader)
				req.Header.Set("Host", "example.com")
				req.Header.Set("Signature",
					`keyId="test-key-hmac",signature="Su9pRLxbHq1uWcYC53G6vM07vvi57kexqkakgMi3pTs=",algorithm="hmac-sha256",headers="(request-target) date"`)
				return req
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) error {
				return verifier.VerifyHMAC([]byte(testHMACSecret), &sigre.VerifyOptions{})
			},
			wantKeyId: "test-key-hmac",
		},
		{
			name: "RSA-SHA256: verification fails with tampered signature value",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/foo?param=value&pet=dog", testBodyJSON)
				req.Header.Set("Date", testDateHeader)
				req.Header.Set("Host", "example.com")
				req.Header.Set("Digest", testBodyDigest)
				// Tamper the beginning of signature value
				req.Header.Set("Signature",
					`keyId="test-key-rsa",signature="AAAAALN/dEThM4gw4WBel/t5AybfCgIerAzkHzj2S3rU6OH+ODDLxcwS0UcL0L6NOCnCgw/ndz67ATcpbkSwRZ0QDAn+fTCP4Xe8Yjal/GyC9FhglQ3wTxFp6rUp5bpT7Al3NrYeAMAcvHlMeHi3b64LovkCtPY8TAf+MbKOdtxFiU8F264O5eRZ0wkSp2cBX5JOrPGEWsLY/wO1n1nG02yBzswntBsSK2CCEDra4XjIKFfzooB3tUco4b+1mflALaHMezUP8sn/B48ShoCH4+vUxjcuuJaL162coMgbw+6T1oCOCdXLUSjveqPi8PCRPkO7OIELkTdKOf+VqE5nqlA==",algorithm="rsa-sha256",headers="(request-target) host date digest"`)
				return req
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) error {
				return verifier.Verify(rsaPub, &sigre.VerifyOptions{})
			},
			wantKeyId: "test-key-rsa",
			wantErr:   true,
		},
		{
			name: "Ed25519: verification fails with tampered signature value",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "GET", "https://example.com/", "")
				req.Header.Set("Date", testDateHeader)
				req.Header.Set("Host", "example.com")
				// Tamper the beginning of signature value
				req.Header.Set("Signature",
					`keyId="test-key-ed25519",signature="AAAAAAAAAABWJ9umkv0oWSu5SDuOiZcE621beuDE7UmiGX9ttA/5drFgi5ZweInRDPj5fS70q8jQEgJni5ZGNAA==",algorithm="ed25519",headers="(request-target) host date"`)
				return req
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) error {
				return verifier.Verify(edPub, &sigre.VerifyOptions{})
			},
			wantKeyId: "test-key-ed25519",
			wantErr:   true,
		},
		{
			name: "HMAC-SHA256: verification fails with tampered signature value",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "DELETE", "https://example.com/resource/123", "")
				req.Header.Set("Date", testDateHeader)
				req.Header.Set("Host", "example.com")
				// Tamper the signature value
				req.Header.Set("Signature",
					`keyId="test-key-hmac",signature="AAAAAAAAAAAAAAAYC53G6vM07vvi57kexqkakgMi3pTs=",algorithm="hmac-sha256",headers="(request-target) date"`)
				return req
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) error {
				return verifier.VerifyHMAC([]byte(testHMACSecret), &sigre.VerifyOptions{})
			},
			wantKeyId: "test-key-hmac",
			wantErr:   true,
		},
		{
			name: "RSA-SHA256: verification fails with tampered header",
			setup: func(t *testing.T) *http.Request {
				req := newTestRequest(t, "POST", "https://example.com/foo?param=value&pet=dog", testBodyJSON)
				req.Header.Set("Date", "Sat, 08 Jun 2024 11:00:00 UTC") // tampered date
				req.Header.Set("Host", "example.com")
				req.Header.Set("Digest", testBodyDigest)
				req.Header.Set("Signature",
					`keyId="test-key-rsa",signature="dOtpLN/dEThM4gw4WBel/t5AybfCgIerAzkHzj2S3rU6OH+ODDLxcwS0UcL0L6NOCnCgw/ndz67ATcpbkSwRZ0QDAn+fTCP4Xe8Yjal/GyC9FhglQ3wTxFp6rUp5bpT7Al3NrYeAMAcvHlMeHi3b64LovkCtPY8TAf+MbKOdtxFiU8F264O5eRZ0wkSp2cBX5JOrPGEWsLY/wO1n1nG02yBzswntBsSK2CCEDra4XjIKFfzooB3tUco4b+1mflALaHMezUP8sn/B48ShoCH4+vUxjcuuJaL162coMgbw+6T1oCOCdXLUSjveqPi8PCRPkO7OIELkTdKOf+VqE5nqlA==",algorithm="rsa-sha256",headers="(request-target) host date digest"`)
				return req
			},
			verifyFunc: func(t *testing.T, verifier *sigre.CavageVerifier) error {
				return verifier.Verify(rsaPub, &sigre.VerifyOptions{})
			},
			wantKeyId: "test-key-rsa",
			wantErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.setup(t)

			verifier, err := sigre.NewCavageRequestVerifier(req)
			if err != nil {
				t.Fatalf("failed to create verifier: %v", err)
			}
			verifier.Now = nowFunc

			if verifier.KeyId() != tc.wantKeyId {
				t.Errorf("KeyId() = %q, want %q", verifier.KeyId(), tc.wantKeyId)
			}

			err = tc.verifyFunc(t, verifier)
			if tc.wantErr {
				if err == nil {
					t.Error("expected an error, but verification succeeded")
				}
			} else {
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}
			}
		})
	}
}

// ===================================================================
// Deterministic signature tests (RSA-PKCS1v15 and Ed25519)
// ===================================================================

// TestDeterministicSignatures verifies that deterministic algorithms produce
// the same signature value every time for the same input.
func TestDeterministicSignatures(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	edPriv := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	t.Run("RSA-SHA256: produces identical signature for identical input", func(t *testing.T) {
		signatures := make([]string, 3)
		for i := range signatures {
			req := newTestRequest(t, "POST", "https://example.com/foo?param=value&pet=dog", testBodyJSON)
			setStandardHeaders(t, req.Header, "example.com", true)

			signer := &sigre.CavageSigner{Now: nowFunc}
			err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
				Headers:         []string{"(request-target)", "host", "date", "digest"},
				HashAlgorithm:   crypto.SHA256,
				SignatureHeader: sigre.Signature,
			})
			if err != nil {
				t.Fatalf("signing failed (attempt %d): %v", i, err)
			}
			signatures[i] = req.Header.Get("Signature")
		}

		for i := 1; i < len(signatures); i++ {
			if signatures[i] != signatures[0] {
				t.Errorf("signatures do not match: signatures[0] = %q, signatures[%d] = %q", signatures[0], i, signatures[i])
			}
		}
	})

	t.Run("Ed25519: produces identical signature for identical input", func(t *testing.T) {
		signatures := make([]string, 3)
		for i := range signatures {
			req := newTestRequest(t, "GET", "https://example.com/", "")
			setStandardHeaders(t, req.Header, "example.com", false)

			signer := &sigre.CavageSigner{Now: nowFunc}
			err := signer.SignRequest(req, edPriv, "test-key-ed25519", &sigre.CavageSignOptions{
				Headers:         []string{"(request-target)", "host", "date"},
				SignatureHeader: sigre.Signature,
			})
			if err != nil {
				t.Fatalf("signing failed (attempt %d): %v", i, err)
			}
			signatures[i] = req.Header.Get("Signature")
		}

		for i := 1; i < len(signatures); i++ {
			if signatures[i] != signatures[0] {
				t.Errorf("signatures do not match: signatures[0] = %q, signatures[%d] = %q", signatures[0], i, signatures[i])
			}
		}
	})
}

// ===================================================================
// Key type mismatch tests
// ===================================================================

// TestKeyTypeMismatch verifies that verification fails when the signature algorithm
// does not match the key type.
func TestKeyTypeMismatch(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	ecPub := parseECDSAPublicKey(t, testECDSAPublicKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	testCases := []struct {
		name      string
		verifyKey crypto.PublicKey
	}{
		{
			name:      "RSA signature verified with ECDSA public key fails",
			verifyKey: ecPub,
		},
		{
			name:      "RSA signature verified with Ed25519 public key fails",
			verifyKey: edPub,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := newTestRequest(t, "POST", "https://example.com/foo", testBodyJSON)
			setStandardHeaders(t, req.Header, "example.com", true)

			signer := &sigre.CavageSigner{Now: nowFunc}
			err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
				Headers:         []string{"(request-target)", "host", "date", "digest"},
				HashAlgorithm:   crypto.SHA256,
				SignatureHeader: sigre.Signature,
			})
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}

			verifier, err := sigre.NewCavageRequestVerifier(req)
			if err != nil {
				t.Fatalf("failed to create verifier: %v", err)
			}
			verifier.Now = nowFunc

			err = verifier.Verify(tc.verifyKey, &sigre.VerifyOptions{})
			if err == nil {
				t.Error("verification succeeded with mismatched key type")
			}
			if !errors.Is(err, sigre.ErrAlgorithmMismatch) && !errors.Is(err, sigre.ErrVerification) {
				t.Errorf("unexpected error type: %v", err)
			}
		})
	}
}

// ===================================================================
// Verification tests via NewRequestVerifier / NewResponseVerifier
// ===================================================================

// TestFixedKeyWithGenericVerifier verifies fixed-key signatures via
// NewRequestVerifier / NewResponseVerifier.
func TestFixedKeyWithGenericVerifier(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)
	edPriv := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	t.Run("NewRequestVerifier: RSA-SHA256", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/generic", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
			Headers:         []string{"(request-target)", "host", "date", "digest"},
			HashAlgorithm:   crypto.SHA256,
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, err := sigre.NewRequestVerifier(req)
		if err != nil {
			t.Fatalf("NewRequestVerifier failed: %v", err)
		}
		if verifier.KeyId() != "test-key-rsa" {
			t.Errorf("KeyId() = %q, want %q", verifier.KeyId(), "test-key-rsa")
		}
		if err := verifier.Verify(rsaPub, &sigre.VerifyOptions{}); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("NewRequestVerifier: Ed25519", func(t *testing.T) {
		req := newTestRequest(t, "GET", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(req, edPriv, "test-key-ed", &sigre.CavageSignOptions{
			Headers:         []string{"(request-target)", "host", "date"},
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, err := sigre.NewRequestVerifier(req)
		if err != nil {
			t.Fatalf("NewRequestVerifier failed: %v", err)
		}
		if verifier.KeyId() != "test-key-ed" {
			t.Errorf("KeyId() = %q, want %q", verifier.KeyId(), "test-key-ed")
		}
		if err := verifier.Verify(edPub, &sigre.VerifyOptions{}); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})
}

// ===================================================================
// Response signing tests (fixed keys)
// ===================================================================

// TestFixedKeyResponseSignAndVerify tests response signing and verification with fixed keys.
func TestFixedKeyResponseSignAndVerify(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	t.Run("RSA-SHA256: response sign and verify", func(t *testing.T) {
		dummyReq, _ := http.NewRequest("GET", "https://example.com/data", nil)
		res := &http.Response{
			Request: dummyReq,
			Header:  make(http.Header),
		}
		res.Header.Set("Date", testDateHeader)
		res.Header.Set("Digest", testBodyDigest)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignResponse(res, rsaPriv, "test-key-rsa-resp", &sigre.CavageSignOptions{
			Headers:         []string{"date", "digest"},
			HashAlgorithm:   crypto.SHA256,
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("response signing failed: %v", err)
		}

		verifier, err := sigre.NewCavageResponseVerifier(res)
		if err != nil {
			t.Fatalf("failed to create verifier: %v", err)
		}
		verifier.Now = nowFunc

		if verifier.KeyId() != "test-key-rsa-resp" {
			t.Errorf("KeyId() = %q, want %q", verifier.KeyId(), "test-key-rsa-resp")
		}
		if err := verifier.Verify(rsaPub, &sigre.VerifyOptions{}); err != nil {
			t.Errorf("response signature verification failed: %v", err)
		}
	})

	t.Run("RSA-SHA512: response sign and verify", func(t *testing.T) {
		dummyReq, _ := http.NewRequest("GET", "https://example.com/data", nil)
		res := &http.Response{
			Request: dummyReq,
			Header:  make(http.Header),
		}
		res.Header.Set("Date", testDateHeader)
		res.Header.Set("Digest", testBodyDigest)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignResponse(res, rsaPriv, "test-key-rsa-resp", &sigre.CavageSignOptions{
			Headers:         []string{"date", "digest"},
			HashAlgorithm:   crypto.SHA512,
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("response signing failed: %v", err)
		}

		verifier, err := sigre.NewCavageResponseVerifier(res)
		if err != nil {
			t.Fatalf("failed to create verifier: %v", err)
		}
		verifier.Now = nowFunc

		if err := verifier.Verify(rsaPub, &sigre.VerifyOptions{}); err != nil {
			t.Errorf("response signature verification failed: %v", err)
		}
	})
}

// ===================================================================
// VerifyOptions detail tests (fixed keys)
// ===================================================================

// TestFixedKeyVerifyOptions tests each VerifyOptions field with fixed keys.
func TestFixedKeyVerifyOptions(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)
	edPriv := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	t.Run("RequiredHeaders: verification succeeds when signed headers satisfy requirements", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
			Headers:         []string{"(request-target)", "host", "date", "digest"},
			HashAlgorithm:   crypto.SHA256,
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("failed to create verifier: %v", err)
		}
		verifier.Now = nowFunc

		err = verifier.Verify(rsaPub, &sigre.VerifyOptions{
			RequiredHeaders: []string{"date", "host", "digest"},
		})
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("RequiredHeaders: verification fails when required header is not in signed headers", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
			Headers:         []string{"(request-target)", "host", "date"},
			HashAlgorithm:   crypto.SHA256,
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("failed to create verifier: %v", err)
		}
		verifier.Now = nowFunc

		err = verifier.Verify(rsaPub, &sigre.VerifyOptions{
			RequiredHeaders: []string{"digest"}, // digest is not in signed headers
		})
		if err == nil {
			t.Error("verification succeeded despite missing required header")
		}
		if !errors.Is(err, sigre.ErrRequiredHeaderMissing) {
			t.Errorf("unexpected error type: %v", err)
		}
	})

	t.Run("AllowedClockSkew: verification succeeds within (created) skew tolerance", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(req, edPriv, "test-key-ed25519", &sigre.CavageSignOptions{
			Headers:         []string{"(request-target)", "(created)", "host"},
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("failed to create verifier: %v", err)
		}
		// Verify 30 seconds later (within 60s skew)
		verifier.Now = func() time.Time { return testFixedTime.Add(30 * time.Second) }

		err = verifier.Verify(edPub, &sigre.VerifyOptions{
			AllowedClockSkew: 1 * time.Minute,
		})
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("AllowedClockSkew: verification fails when (created) exceeds skew tolerance", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(req, edPriv, "test-key-ed25519", &sigre.CavageSignOptions{
			Headers:         []string{"(request-target)", "(created)", "host"},
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("failed to create verifier: %v", err)
		}
		// Verify 61 seconds later (exceeds 60s skew)
		verifier.Now = func() time.Time { return testFixedTime.Add(61 * time.Second) }

		err = verifier.Verify(edPub, &sigre.VerifyOptions{
			AllowedClockSkew: 1 * time.Minute,
		})
		if err == nil {
			t.Error("verification succeeded despite clock skew exceeded")
		}
		if !errors.Is(err, sigre.ErrInvalidCreationTime) {
			t.Errorf("unexpected error type: %v", err)
		}
	})

	t.Run("AllowedHashAlgorithms: verification succeeds with permitted hash", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
			Headers:         []string{"(request-target)", "host", "date", "digest"},
			HashAlgorithm:   crypto.SHA256,
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("failed to create verifier: %v", err)
		}
		verifier.Now = nowFunc

		err = verifier.Verify(rsaPub, &sigre.VerifyOptions{
			AllowedHashAlgorithms: []crypto.Hash{crypto.SHA256, crypto.SHA512},
		})
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("AllowedHashAlgorithms: verification fails with non-permitted hash", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(req, rsaPriv, "test-key-rsa", &sigre.CavageSignOptions{
			Headers:         []string{"(request-target)", "host", "date", "digest"},
			HashAlgorithm:   crypto.SHA256,
			SignatureHeader: sigre.Signature,
		})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, err := sigre.NewCavageRequestVerifier(req)
		if err != nil {
			t.Fatalf("failed to create verifier: %v", err)
		}
		verifier.Now = nowFunc

		err = verifier.Verify(rsaPub, &sigre.VerifyOptions{
			AllowedHashAlgorithms: []crypto.Hash{crypto.SHA512}, // SHA-256 is not permitted
		})
		if err == nil {
			t.Error("verification succeeded with non-permitted hash algorithm")
		}
		if !errors.Is(err, sigre.ErrUnsupportedHashAlgorithm) {
			t.Errorf("unexpected error type: %v", err)
		}
	})
}
