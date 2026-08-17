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

// Static test keys keep signature vectors reproducible.
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

var testFixedTime = time.Date(2024, 6, 8, 10, 30, 0, 0, time.UTC)

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

const testDateHeader = "Sat, 08 Jun 2024 10:30:00 UTC"
const testBodyJSON = `{"hello": "world"}`

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
	req.RequestURI = req.URL.RequestURI()
	return req
}

func setStandardHeaders(t *testing.T, header http.Header, host string, includeDigest bool) {
	t.Helper()
	header.Set("Date", testDateHeader)
	header.Set("Host", host)
	if includeDigest {
		header.Set("Digest", testBodyDigest)
	}
}

func fixedPublicVerificationKey(keyID string, algorithm sigre.AlgorithmID, publicKey crypto.PublicKey) sigre.VerificationKey {
	return sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: keyID, Algorithm: algorithm},
		PublicKey: publicKey,
	}
}

func fixedHMACVerificationKey(keyID string, algorithm sigre.AlgorithmID, secret []byte) sigre.HMACVerificationKey {
	return sigre.HMACVerificationKey{
		Metadata: sigre.TrustedKeyMetadata{KeyID: keyID, Algorithm: algorithm},
		Secret:   secret,
	}
}

func fixedVerificationOptions(algorithm sigre.AlgorithmID, wireLabel string) *sigre.CavageVerificationOptions {
	opts := &sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{algorithm}}
	switch wireLabel {
	case "rsa-sha256", "ecdsa-sha256", "hmac-sha256":
		opts.Compatibility = &sigre.CavageVerificationCompatibility{
			AllowedLegacyAlgorithms: []sigre.AlgorithmID{algorithm},
		}
	case "hs2019", "":
	case "rsa-sha512", "ecdsa-sha512", "hmac-sha512", "ed25519":
		opts.Compatibility = &sigre.CavageVerificationCompatibility{
			ExtensionAlgorithms: map[string]sigre.AlgorithmID{wireLabel: algorithm},
		}
	default:
		panic("unsupported fixed test wire label: " + wireLabel)
	}
	return opts
}

func parseFixedRequest(t *testing.T, req *http.Request, opts *sigre.CavageVerificationOptions, now func() time.Time) (*sigre.CavageVerifier, *sigre.CavageSignature) {
	t.Helper()
	options := sigre.CavageVerificationOptions{}
	if opts != nil {
		options = *opts
	}
	options.Now = now
	verifier, err := sigre.NewCavageVerifier(&options)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	return verifier, signature
}

func parseFixedResponse(t *testing.T, res *http.Response, opts *sigre.CavageVerificationOptions, now func() time.Time) (*sigre.CavageVerifier, *sigre.CavageSignature) {
	t.Helper()
	options := sigre.CavageVerificationOptions{}
	if opts != nil {
		options = *opts
	}
	options.Now = now
	verifier, err := sigre.NewCavageVerifier(&options)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	signature, err := verifier.ParseResponse(res)
	if err != nil {
		t.Fatalf("ParseResponse() failed: %v", err)
	}
	return verifier, signature
}

func fixedSigningKey(keyID string, algorithm sigre.AlgorithmID, privateKey crypto.PrivateKey) sigre.SigningKey {
	return sigre.SigningKey{
		Metadata:   sigre.TrustedKeyMetadata{KeyID: keyID, Algorithm: algorithm},
		PrivateKey: privateKey,
	}
}

func fixedHMACSigningKey(keyID string, algorithm sigre.AlgorithmID, secret []byte) sigre.HMACSigningKey {
	return sigre.HMACSigningKey{
		Metadata: sigre.TrustedKeyMetadata{KeyID: keyID, Algorithm: algorithm},
		Secret:   secret,
	}
}

func fixedSigningOptions(
	algorithm sigre.AlgorithmID,
	wireLabel string,
	headers []string,
	expiresAfter time.Duration,
) *sigre.CavageSigningOptions {
	compatibility := &sigre.CavageSigningCompatibility{ExactHeaders: headers}
	switch wireLabel {
	case "hs2019":
		if algorithm == sigre.AlgorithmRSAPKCS1v15SHA256 {
			compatibility.AlgorithmField = sigre.AlgorithmFieldHS2019WithSHA256
		}
	case "":
		compatibility.AlgorithmField = sigre.AlgorithmFieldOmitted
	case "rsa-sha256", "ecdsa-sha256", "hmac-sha256":
		compatibility.AlgorithmField = sigre.AlgorithmFieldLegacy
	case "rsa-sha512", "ecdsa-sha512", "hmac-sha512", "ed25519":
		compatibility.Extension = &sigre.ExtensionAlgorithm{Label: wireLabel, Algorithm: algorithm}
	default:
		panic("unsupported fixed signing wire label: " + wireLabel)
	}
	return &sigre.CavageSigningOptions{
		ExpiresAfter:  expiresAfter,
		Compatibility: compatibility,
	}
}

func TestFixedKeySignAndVerify(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)
	ecPriv := parseECDSAPrivateKey(t, testECDSAPrivateKeyPEM)
	ecPub := parseECDSAPublicKey(t, testECDSAPublicKeyPEM)
	edPriv := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)
	hmacSecret := []byte(testHMACSecret)

	nowFunc := func() time.Time { return testFixedTime }

	signer := &sigre.CavageSigner{Now: nowFunc}
	newVerifier := func(t *testing.T, req *http.Request, wantKeyID string, opts *sigre.CavageVerificationOptions) (*sigre.CavageVerifier, *sigre.CavageSignature) {
		t.Helper()
		verifier, signature := parseFixedRequest(t, req, opts, nowFunc)
		if signature.KeyID() != wantKeyID {
			t.Errorf("KeyID() = %q, want %q", signature.KeyID(), wantKeyID)
		}
		return verifier, signature
	}

	t.Run("RSA-SHA256: sign with fixed key and verify with same public key", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/foo?param=value&pet=dog", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-rsa", fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256"))
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("RSA-SHA512: sign with fixed key and verify with same public key", func(t *testing.T) {
		req := newTestRequest(t, "PUT", "https://example.com/update", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa-512", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA512, "rsa-sha512", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-rsa-512", fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA512, "rsa-sha512"))
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa-512", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("ECDSA-SHA256: sign with fixed key and verify with same public key", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/ecdsa", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ecdsa", sigre.AlgorithmECDSASHA256, ecPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmECDSASHA256, "ecdsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-ecdsa", fixedVerificationOptions(sigre.AlgorithmECDSASHA256, "ecdsa-sha256"))
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-ecdsa", sigre.AlgorithmECDSASHA256, ecPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("Ed25519: sign with fixed key and verify with same public key", func(t *testing.T) {
		req := newTestRequest(t, "GET", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "host", "date"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-ed25519", fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519"))
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-ed25519", sigre.AlgorithmEd25519, edPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("HMAC-SHA256: sign with fixed secret and verify with same secret", func(t *testing.T) {
		req := newTestRequest(t, "DELETE", "https://example.com/resource/123", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		err := signer.SignRequestWithHMAC(
			req,
			fixedHMACSigningKey("test-key-hmac", sigre.AlgorithmHMACSHA256, hmacSecret),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256", []string{"(request-target)", "date"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-hmac", fixedVerificationOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256"))
		if err := verifier.VerifyHMAC(signature, fixedHMACVerificationKey("test-key-hmac", sigre.AlgorithmHMACSHA256, hmacSecret)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("RSA-SHA256: verification fails with different RSA public key", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/foo", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-rsa", fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256"))
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, generateRSAKeys(t).public)); err == nil {
			t.Error("verification succeeded with a different public key")
		}
	})

	t.Run("Ed25519: verification fails with different Ed25519 public key", func(t *testing.T) {
		req := newTestRequest(t, "GET", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "host", "date"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-ed25519", fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519"))
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-ed25519", sigre.AlgorithmEd25519, generateEd25519Keys(t).public)); err == nil {
			t.Error("verification succeeded with a different public key")
		}
	})

	t.Run("HMAC-SHA256: verification fails with different secret", func(t *testing.T) {
		req := newTestRequest(t, "DELETE", "https://example.com/resource/123", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		err := signer.SignRequestWithHMAC(
			req,
			fixedHMACSigningKey("test-key-hmac", sigre.AlgorithmHMACSHA256, hmacSecret),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256", []string{"(request-target)", "date"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-hmac", fixedVerificationOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256"))
		if err := verifier.VerifyHMAC(signature, fixedHMACVerificationKey("test-key-hmac", sigre.AlgorithmHMACSHA256, []byte("wrong-secret-key"))); err == nil {
			t.Error("verification succeeded with a different secret")
		}
	})

	t.Run("Ed25519: sign and verify with (created) pseudo-header", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/api/data", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "(created)", "host"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := newVerifier(t, req, "test-key-ed25519", fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519"))
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-ed25519", sigre.AlgorithmEd25519, edPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("RSA-SHA256: sign and verify with Authorization header format", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/auth", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa-auth", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementAuthorization,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verificationOptions := fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256")
		verificationOptions.RequestSignatureSource = sigre.CavageRequestSignatureSourceAuthorization
		verifier, signature := newVerifier(t, req, "test-key-rsa-auth", verificationOptions)
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa-auth", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})
}

// Precomputed signature values verify compatibility without using the signer.
func TestVerifyPrecomputedSignatures(t *testing.T) {
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	testCases := []struct {
		name      string
		method    string
		url       string
		body      string
		date      string
		host      string
		digest    string
		signature string
		verifyBy  string
		wantKeyID string
		algorithm sigre.AlgorithmID
		wireLabel string
		wantErr   bool
		wantErrIs error
	}{
		{
			name:      "RSA-SHA256: verify precomputed signature succeeds",
			method:    "POST",
			url:       "https://example.com/foo?param=value&pet=dog",
			body:      testBodyJSON,
			date:      testDateHeader,
			host:      "example.com",
			digest:    testBodyDigest,
			signature: `keyId="test-key-rsa",signature="dOtpLN/dEThM4gw4WBel/t5AybfCgIerAzkHzj2S3rU6OH+ODDLxcwS0UcL0L6NOCnCgw/ndz67ATcpbkSwRZ0QDAn+fTCP4Xe8Yjal/GyC9FhglQ3wTxFp6rUp5bpT7Al3NrYeAMAcvHlMeHi3b64LovkCtPY8TAf+MbKOdtxFiU8F264O5eRZ0wkSp2cBX5JOrPGEWsLY/wO1n1nG02yBzswntBsSK2CCEDra4XjIKFfzooB3tUco4b+1mflALaHMezUP8sn/B48ShoCH4+vUxjcuuJaL162coMgbw+6T1oCOCdXLUSjveqPi8PCRPkO7OIELkTdKOf+VqE5nqlA==",algorithm="rsa-sha256",headers="(request-target) host date digest"`,
			verifyBy:  "rsa",
			wantKeyID: "test-key-rsa",
			algorithm: sigre.AlgorithmRSAPKCS1v15SHA256,
			wireLabel: "rsa-sha256",
		},
		{
			name:      "RSA-SHA512: verify precomputed signature succeeds",
			method:    "POST",
			url:       "https://example.com/foo",
			body:      testBodyJSON,
			date:      testDateHeader,
			host:      "example.com",
			digest:    testBodyDigest,
			signature: `keyId="test-key-rsa",signature="l36dg8IqFddjKdyQsdWZ4n2QzkSdpCnq9jmvVqsBFcQUW9+r19azLRCpUoV2p3DkvhN1+Ub4mwouipzczQRQcAtcs1x4ZaZKi7J6uYgCe8QpsV/4ixAmD80mDYttXHPCUr8IU1Wg/Iaq6emYsm/cHFH/O46NSO+7dnZDJ1uCAVSTOp5vrlOTKtwgbg6sU7SXEDhUQ+gXSdToa7wXzHkgEIJAMnU815Y0lxI4Djt20ncmWbDC73Mp1ePlalbH2N9Y+rSY3/j4Aos0vIvtSl30zYi2EWO8Uhto4BmzivPRmXKGTJNk8tWtfT99I/t/4UIPuVPaI4kiWcVT0wcamkVkEA==",algorithm="rsa-sha512",headers="date digest"`,
			verifyBy:  "rsa",
			wantKeyID: "test-key-rsa",
			algorithm: sigre.AlgorithmRSAPKCS1v15SHA512,
			wireLabel: "rsa-sha512",
		},
		{
			name:      "Ed25519: verify precomputed signature succeeds",
			method:    "GET",
			url:       "https://example.com/",
			date:      testDateHeader,
			host:      "example.com",
			signature: `keyId="test-key-ed25519",signature="UMoMdVYlZBWj9umkv0oWSu5SDuOiZcE621beuDE7UmiGX9ttA/5drFgi5ZweInRDPj5fS70q8jQEgJni5ZGNAA==",algorithm="ed25519",headers="(request-target) host date"`,
			verifyBy:  "ed25519",
			wantKeyID: "test-key-ed25519",
			algorithm: sigre.AlgorithmEd25519,
			wireLabel: "ed25519",
		},
		{
			name:      "HMAC-SHA256: verify precomputed signature succeeds",
			method:    "DELETE",
			url:       "https://example.com/resource/123",
			date:      testDateHeader,
			host:      "example.com",
			signature: `keyId="test-key-hmac",signature="Su9pRLxbHq1uWcYC53G6vM07vvi57kexqkakgMi3pTs=",algorithm="hmac-sha256",headers="(request-target) date"`,
			verifyBy:  "hmac",
			wantKeyID: "test-key-hmac",
			algorithm: sigre.AlgorithmHMACSHA256,
			wireLabel: "hmac-sha256",
		},
		{
			name:      "RSA-SHA256: verification fails with tampered signature value",
			method:    "POST",
			url:       "https://example.com/foo?param=value&pet=dog",
			body:      testBodyJSON,
			date:      testDateHeader,
			host:      "example.com",
			digest:    testBodyDigest,
			signature: `keyId="test-key-rsa",signature="AOtpLN/dEThM4gw4WBel/t5AybfCgIerAzkHzj2S3rU6OH+ODDLxcwS0UcL0L6NOCnCgw/ndz67ATcpbkSwRZ0QDAn+fTCP4Xe8Yjal/GyC9FhglQ3wTxFp6rUp5bpT7Al3NrYeAMAcvHlMeHi3b64LovkCtPY8TAf+MbKOdtxFiU8F264O5eRZ0wkSp2cBX5JOrPGEWsLY/wO1n1nG02yBzswntBsSK2CCEDra4XjIKFfzooB3tUco4b+1mflALaHMezUP8sn/B48ShoCH4+vUxjcuuJaL162coMgbw+6T1oCOCdXLUSjveqPi8PCRPkO7OIELkTdKOf+VqE5nqlA==",algorithm="rsa-sha256",headers="(request-target) host date digest"`,
			verifyBy:  "rsa",
			wantKeyID: "test-key-rsa",
			algorithm: sigre.AlgorithmRSAPKCS1v15SHA256,
			wireLabel: "rsa-sha256",
			wantErr:   true,
		},
		{
			name:      "Ed25519: verification fails with tampered signature value",
			method:    "GET",
			url:       "https://example.com/",
			date:      testDateHeader,
			host:      "example.com",
			signature: `keyId="test-key-ed25519",signature="AMoMdVYlZBWj9umkv0oWSu5SDuOiZcE621beuDE7UmiGX9ttA/5drFgi5ZweInRDPj5fS70q8jQEgJni5ZGNAA==",algorithm="ed25519",headers="(request-target) host date"`,
			verifyBy:  "ed25519",
			wantKeyID: "test-key-ed25519",
			algorithm: sigre.AlgorithmEd25519,
			wireLabel: "ed25519",
			wantErr:   true,
		},
		{
			name:      "HMAC-SHA256: verification fails with tampered signature value",
			method:    "DELETE",
			url:       "https://example.com/resource/123",
			date:      testDateHeader,
			host:      "example.com",
			signature: `keyId="test-key-hmac",signature="Au9pRLxbHq1uWcYC53G6vM07vvi57kexqkakgMi3pTs=",algorithm="hmac-sha256",headers="(request-target) date"`,
			verifyBy:  "hmac",
			wantKeyID: "test-key-hmac",
			algorithm: sigre.AlgorithmHMACSHA256,
			wireLabel: "hmac-sha256",
			wantErr:   true,
		},
		{
			name:      "RSA-SHA256: verification fails with tampered header",
			method:    "POST",
			url:       "https://example.com/foo?param=value&pet=dog",
			body:      testBodyJSON,
			date:      "Sat, 08 Jun 2024 11:00:00 UTC",
			host:      "example.com",
			digest:    testBodyDigest,
			signature: `keyId="test-key-rsa",signature="dOtpLN/dEThM4gw4WBel/t5AybfCgIerAzkHzj2S3rU6OH+ODDLxcwS0UcL0L6NOCnCgw/ndz67ATcpbkSwRZ0QDAn+fTCP4Xe8Yjal/GyC9FhglQ3wTxFp6rUp5bpT7Al3NrYeAMAcvHlMeHi3b64LovkCtPY8TAf+MbKOdtxFiU8F264O5eRZ0wkSp2cBX5JOrPGEWsLY/wO1n1nG02yBzswntBsSK2CCEDra4XjIKFfzooB3tUco4b+1mflALaHMezUP8sn/B48ShoCH4+vUxjcuuJaL162coMgbw+6T1oCOCdXLUSjveqPi8PCRPkO7OIELkTdKOf+VqE5nqlA==",algorithm="rsa-sha256",headers="(request-target) host date digest"`,
			verifyBy:  "rsa",
			wantKeyID: "test-key-rsa",
			algorithm: sigre.AlgorithmRSAPKCS1v15SHA256,
			wireLabel: "rsa-sha256",
			wantErr:   true,
			wantErrIs: sigre.ErrVerification,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := newTestRequest(t, tc.method, tc.url, tc.body)
			req.Header.Set("Date", tc.date)
			req.Header.Set("Host", tc.host)
			req.Header.Set("Signature", tc.signature)
			if tc.digest != "" {
				req.Header.Set("Digest", tc.digest)
			}

			verificationOptions := fixedVerificationOptions(tc.algorithm, tc.wireLabel)
			verifier, signature := parseFixedRequest(t, req, verificationOptions, nowFunc)

			if signature.KeyID() != tc.wantKeyID {
				t.Errorf("KeyID() = %q, want %q", signature.KeyID(), tc.wantKeyID)
			}

			var err error
			switch tc.verifyBy {
			case "rsa":
				err = verifier.Verify(signature, fixedPublicVerificationKey(tc.wantKeyID, tc.algorithm, rsaPub))
			case "ed25519":
				err = verifier.Verify(signature, fixedPublicVerificationKey(tc.wantKeyID, tc.algorithm, edPub))
			case "hmac":
				err = verifier.VerifyHMAC(signature, fixedHMACVerificationKey(tc.wantKeyID, tc.algorithm, []byte(testHMACSecret)))
			default:
				t.Fatalf("unknown verifyBy value: %q", tc.verifyBy)
			}

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, but verification succeeded")
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("expected error %v, got: %v", tc.wantErrIs, err)
				}
				return
			}
			if err != nil {
				t.Errorf("verification failed: %v", err)
			}
		})
	}
}

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
			err := signer.SignRequest(
				req,
				fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
				sigre.CavageSignaturePlacementSignature,
				fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
			)
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
			err := signer.SignRequest(
				req,
				fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
				sigre.CavageSignaturePlacementSignature,
				fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "host", "date"}, 0),
			)
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
			err := signer.SignRequest(
				req,
				fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
				sigre.CavageSignaturePlacementSignature,
				fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
			)
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}

			verifier, signature := parseFixedRequest(t, req, fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256"), nowFunc)

			err = verifier.Verify(
				signature,
				fixedPublicVerificationKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, tc.verifyKey),
			)
			if err == nil {
				t.Error("verification succeeded with mismatched key type")
			}
			if !errors.Is(err, sigre.ErrAlgorithmMismatch) {
				t.Errorf("unexpected error type: %v", err)
			}
		})
	}
}

func TestFixedKeyWithCavageVerifier(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)
	edPriv := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	t.Run("ParseRequest: RSA-SHA256", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/generic", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := parseFixedRequest(t, req, fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256"), nowFunc)
		if signature.KeyID() != "test-key-rsa" {
			t.Errorf("KeyID() = %q, want %q", signature.KeyID(), "test-key-rsa")
		}
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("ParseRequest: Ed25519", func(t *testing.T) {
		req := newTestRequest(t, "GET", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "host", "date"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := parseFixedRequest(t, req, fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519"), nowFunc)
		if signature.KeyID() != "test-key-ed" {
			t.Errorf("KeyID() = %q, want %q", signature.KeyID(), "test-key-ed")
		}
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-ed", sigre.AlgorithmEd25519, edPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("ParseResponse: RSA-SHA256", func(t *testing.T) {
		dummyReq, _ := http.NewRequest("GET", "https://example.com/generic-response", nil)
		res := &http.Response{
			Request: dummyReq,
			Header:  make(http.Header),
		}
		res.Header.Set("Date", testDateHeader)
		res.Header.Set("Digest", testBodyDigest)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignResponse(
			res,
			fixedSigningKey("test-key-rsa-res", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("response signing failed: %v", err)
		}

		verifier, signature := parseFixedResponse(t, res, fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256"), nowFunc)
		if signature.KeyID() != "test-key-rsa-res" {
			t.Errorf("KeyID() = %q, want %q", signature.KeyID(), "test-key-rsa-res")
		}
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa-res", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPub)); err != nil {
			t.Errorf("response verification failed: %v", err)
		}
	})

	t.Run("ParseResponse: missing signature", func(t *testing.T) {
		res := &http.Response{Header: make(http.Header)}
		verifier, err := sigre.NewCavageVerifier(nil)
		if err != nil {
			t.Fatalf("NewCavageVerifier() failed: %v", err)
		}
		_, err = verifier.ParseResponse(res)
		if !errors.Is(err, sigre.ErrMissingSignature) {
			t.Fatalf("expected ErrMissingSignature, got: %v", err)
		}
	})

}

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
		err := signer.SignResponse(
			res,
			fixedSigningKey("test-key-rsa-resp", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("response signing failed: %v", err)
		}

		verifier, signature := parseFixedResponse(t, res, fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256"), nowFunc)

		if signature.KeyID() != "test-key-rsa-resp" {
			t.Errorf("KeyID() = %q, want %q", signature.KeyID(), "test-key-rsa-resp")
		}
		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa-resp", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPub)); err != nil {
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
		err := signer.SignResponse(
			res,
			fixedSigningKey("test-key-rsa-resp", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA512, "rsa-sha512", []string{"date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("response signing failed: %v", err)
		}

		verifier, signature := parseFixedResponse(t, res, fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA512, "rsa-sha512"), nowFunc)

		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa-resp", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPub)); err != nil {
			t.Errorf("response signature verification failed: %v", err)
		}
	})

	t.Run("HMAC-SHA256: response sign and verify", func(t *testing.T) {
		dummyReq, _ := http.NewRequest("GET", "https://example.com/data", nil)
		res := &http.Response{
			Request: dummyReq,
			Header:  make(http.Header),
		}
		res.Header.Set("Date", testDateHeader)
		res.Header.Set("Digest", testBodyDigest)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignResponseWithHMAC(
			res,
			fixedHMACSigningKey("test-key-hmac-resp", sigre.AlgorithmHMACSHA256, []byte(testHMACSecret)),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256", []string{"date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("response HMAC signing failed: %v", err)
		}

		verifier, signature := parseFixedResponse(t, res, fixedVerificationOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256"), nowFunc)

		if signature.KeyID() != "test-key-hmac-resp" {
			t.Errorf("KeyID() = %q, want %q", signature.KeyID(), "test-key-hmac-resp")
		}
		if err := verifier.VerifyHMAC(signature, fixedHMACVerificationKey("test-key-hmac-resp", sigre.AlgorithmHMACSHA256, []byte(testHMACSecret))); err != nil {
			t.Errorf("response HMAC verification failed: %v", err)
		}
	})

	t.Run("HMAC-SHA256: response verification fails with wrong secret", func(t *testing.T) {
		dummyReq, _ := http.NewRequest("GET", "https://example.com/data", nil)
		res := &http.Response{
			Request: dummyReq,
			Header:  make(http.Header),
		}
		res.Header.Set("Date", testDateHeader)
		res.Header.Set("Digest", testBodyDigest)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignResponseWithHMAC(
			res,
			fixedHMACSigningKey("test-key-hmac-resp", sigre.AlgorithmHMACSHA256, []byte(testHMACSecret)),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256", []string{"date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("response HMAC signing failed: %v", err)
		}

		verifier, signature := parseFixedResponse(t, res, fixedVerificationOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256"), nowFunc)

		err = verifier.VerifyHMAC(signature, fixedHMACVerificationKey("test-key-hmac-resp", sigre.AlgorithmHMACSHA256, []byte("wrong-secret")))
		if !errors.Is(err, sigre.ErrVerification) {
			t.Fatalf("expected ErrVerification, got: %v", err)
		}
	})

	t.Run("HMAC-SHA256: response verification fails after header tampering", func(t *testing.T) {
		dummyReq, _ := http.NewRequest("GET", "https://example.com/data", nil)
		res := &http.Response{
			Request: dummyReq,
			Header:  make(http.Header),
		}
		res.Header.Set("Date", testDateHeader)
		res.Header.Set("Digest", testBodyDigest)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignResponseWithHMAC(
			res,
			fixedHMACSigningKey("test-key-hmac-resp", sigre.AlgorithmHMACSHA256, []byte(testHMACSecret)),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256", []string{"date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("response HMAC signing failed: %v", err)
		}
		res.Header.Set("Date", "Sat, 08 Jun 2024 11:00:00 UTC")

		verifier, signature := parseFixedResponse(t, res, fixedVerificationOptions(sigre.AlgorithmHMACSHA256, "hmac-sha256"), nowFunc)

		err = verifier.VerifyHMAC(signature, fixedHMACVerificationKey("test-key-hmac-resp", sigre.AlgorithmHMACSHA256, []byte(testHMACSecret)))
		if !errors.Is(err, sigre.ErrVerification) {
			t.Fatalf("expected ErrVerification, got: %v", err)
		}
	})
}

func TestFixedKeyCavageVerificationOptions(t *testing.T) {
	rsaPriv := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	rsaPub := parseRSAPublicKey(t, testRSAPublicKeyPEM)
	edPriv := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	edPub := parseEd25519PublicKey(t, testEd25519PublicKeyPEM)

	nowFunc := func() time.Time { return testFixedTime }

	t.Run("RequiredHeaders: verification succeeds when signed headers satisfy requirements", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		opts := fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256")
		opts.RequiredHeaders = []string{"date", "host", "digest"}
		verifier, signature := parseFixedRequest(t, req, opts, nowFunc)
		err = verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPub))
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("RequiredHeaders: verification fails when required header is not in signed headers", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		opts := fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256")
		opts.RequiredHeaders = []string{"digest"}
		verifier, err := sigre.NewCavageVerifier(opts)
		if err != nil {
			t.Fatalf("NewCavageVerifier() failed: %v", err)
		}
		_, err = verifier.ParseRequest(req)
		if !errors.Is(err, sigre.ErrRequiredHeaderMissing) {
			t.Errorf("unexpected error type: %v", err)
		}
	})

	t.Run("MaxSignatureAge: verification succeeds at the age boundary", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "(created)", "host"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		opts := fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519")
		opts.MaxSignatureAge = 30 * time.Second
		verifier, signature := parseFixedRequest(t, req, opts, func() time.Time { return testFixedTime.Add(30 * time.Second) })
		err = verifier.Verify(signature, fixedPublicVerificationKey("test-key-ed25519", sigre.AlgorithmEd25519, edPub))
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("MaxSignatureAge: verification fails outside the age boundary", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "(created)", "host"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		opts := fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519")
		opts.MaxSignatureAge = time.Minute
		opts.Now = func() time.Time { return testFixedTime.Add(61 * time.Second) }
		verifier, err := sigre.NewCavageVerifier(opts)
		if err != nil {
			t.Fatalf("NewCavageVerifier() failed: %v", err)
		}
		_, err = verifier.ParseRequest(req)
		if !errors.Is(err, sigre.ErrInvalidCreationTime) {
			t.Errorf("unexpected error type: %v", err)
		}
	})

	t.Run("Expires: verification succeeds before expiry", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "(created)", "(expires)", "host"}, time.Minute),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		verifier, signature := parseFixedRequest(t, req, fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519"), func() time.Time { return testFixedTime.Add(30 * time.Second) })

		if err := verifier.Verify(signature, fixedPublicVerificationKey("test-key-ed25519", sigre.AlgorithmEd25519, edPub)); err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("Expires: verification fails after expiry", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "(created)", "(expires)", "host"}, time.Minute),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		opts := fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519")
		opts.Now = func() time.Time { return testFixedTime.Add(61 * time.Second) }
		verifier, err := sigre.NewCavageVerifier(opts)
		if err != nil {
			t.Fatalf("NewCavageVerifier() failed: %v", err)
		}
		_, err = verifier.ParseRequest(req)
		if !errors.Is(err, sigre.ErrSignatureExpired) {
			t.Fatalf("expected ErrSignatureExpired, got: %v", err)
		}
	})

	t.Run("Expires: verification succeeds within skew tolerance", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-ed25519", sigre.AlgorithmEd25519, edPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmEd25519, "ed25519", []string{"(request-target)", "(created)", "(expires)", "host"}, time.Minute),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		opts := fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519")
		opts.Compatibility.AllowedExpiredSkew = 2 * time.Second
		verifier, signature := parseFixedRequest(t, req, opts, func() time.Time { return testFixedTime.Add(61 * time.Second) })
		err = verifier.Verify(signature, fixedPublicVerificationKey("test-key-ed25519", sigre.AlgorithmEd25519, edPub))
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("Expires: verification fails when signed parameter is missing", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", "")
		setStandardHeaders(t, req.Header, "example.com", false)
		req.Header.Set("Signature", `keyId="test-key-ed25519",signature="AAAA",algorithm="ed25519",headers="(expires)"`)

		opts := fixedVerificationOptions(sigre.AlgorithmEd25519, "ed25519")
		opts.Now = nowFunc
		verifier, err := sigre.NewCavageVerifier(opts)
		if err != nil {
			t.Fatalf("NewCavageVerifier() failed: %v", err)
		}
		_, err = verifier.ParseRequest(req)
		if !errors.Is(err, sigre.ErrInvalidExpirationTime) {
			t.Fatalf("expected missing expires parameter error, got: %v", err)
		}
	})

	t.Run("AllowedAlgorithms: verification succeeds with permitted algorithm", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		opts := fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256")
		opts.AllowedAlgorithms = []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256, sigre.AlgorithmRSAPKCS1v15SHA512}
		verifier, signature := parseFixedRequest(t, req, opts, nowFunc)
		err = verifier.Verify(signature, fixedPublicVerificationKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPub))
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("AllowedAlgorithms: verification fails with non-permitted algorithm", func(t *testing.T) {
		req := newTestRequest(t, "POST", "https://example.com/", testBodyJSON)
		setStandardHeaders(t, req.Header, "example.com", true)

		signer := &sigre.CavageSigner{Now: nowFunc}
		err := signer.SignRequest(
			req,
			fixedSigningKey("test-key-rsa", sigre.AlgorithmRSAPKCS1v15SHA256, rsaPriv),
			sigre.CavageSignaturePlacementSignature,
			fixedSigningOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256", []string{"(request-target)", "host", "date", "digest"}, 0),
		)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		opts := fixedVerificationOptions(sigre.AlgorithmRSAPKCS1v15SHA256, "rsa-sha256")
		opts.AllowedAlgorithms = []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA512}
		opts.Now = nowFunc
		verifier, err := sigre.NewCavageVerifier(opts)
		if err != nil {
			t.Fatalf("NewCavageVerifier() failed: %v", err)
		}
		_, err = verifier.ParseRequest(req)
		if err == nil {
			t.Error("verification succeeded with non-permitted hash algorithm")
		}
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Errorf("unexpected error type: %v", err)
		}
	})
}
