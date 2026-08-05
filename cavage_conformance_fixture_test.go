package sigre_test

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

const cavageConformanceFixtureDirectory = "testdata/cavage-draft-12"

type cavageConformanceFixtureFile struct {
	FormatVersion int                        `json:"format_version"`
	Fixtures      []cavageConformanceFixture `json:"fixtures"`
}

type cavageConformanceFixture struct {
	ID                      string                   `json:"id"`
	Description             string                   `json:"description"`
	Source                  string                   `json:"source"`
	Specification           []string                 `json:"specification"`
	Generation              string                   `json:"generation"`
	IndependentValidation   string                   `json:"independent_validation"`
	Message                 cavageFixtureHTTPMessage `json:"message"`
	SignedHeaders           []string                 `json:"signed_headers"`
	ExpectedSigningString   string                   `json:"expected_signing_string"`
	SignatureHeader         string                   `json:"signature_header"`
	SignatureHeaderValue    string                   `json:"signature_header_value"`
	KeyID                   string                   `json:"key_id"`
	WireAlgorithm           string                   `json:"algorithm"`
	CryptoPath              string                   `json:"crypto_path"`
	Hash                    string                   `json:"hash"`
	Created                 string                   `json:"created"`
	SignatureBase64         string                   `json:"signature_base64"`
	VerificationKeyFile     string                   `json:"verification_key_file"`
	SigningKeyFile          string                   `json:"signing_key_file"`
	HMACSecretFile          string                   `json:"hmac_secret_file"`
	VerificationTimeString  string                   `json:"verification_time"`
	ZeroValueSigningOptions bool                     `json:"zero_value_signing_options"`
}

type cavageFixtureHTTPMessage struct {
	Type          string                `json:"type"`
	Method        string                `json:"method"`
	URL           string                `json:"url"`
	RequestTarget string                `json:"request_target"`
	StatusCode    int                   `json:"status_code"`
	Status        string                `json:"status"`
	Headers       []cavageFixtureHeader `json:"headers"`
	Body          string                `json:"body"`
}

type cavageFixtureHeader struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

func loadCavageConformanceFixtures(t *testing.T) []cavageConformanceFixture {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(cavageConformanceFixtureDirectory, "fixtures.json"))
	if err != nil {
		t.Fatalf("failed to read Cavage conformance fixtures: %v", err)
	}

	var fixtureFile cavageConformanceFixtureFile
	if err := json.Unmarshal(data, &fixtureFile); err != nil {
		t.Fatalf("failed to decode Cavage conformance fixtures: %v", err)
	}
	if fixtureFile.FormatVersion != 1 {
		t.Fatalf("unsupported Cavage conformance fixture format version: %d", fixtureFile.FormatVersion)
	}
	if len(fixtureFile.Fixtures) == 0 {
		t.Fatal("Cavage conformance fixture file contains no fixtures")
	}

	seen := make(map[string]bool, len(fixtureFile.Fixtures))
	for i := range fixtureFile.Fixtures {
		fixture := &fixtureFile.Fixtures[i]
		if fixture.ID == "" || seen[fixture.ID] {
			t.Fatalf("fixture has an empty or duplicate id: %q", fixture.ID)
		}
		seen[fixture.ID] = true
		if fixture.Description == "" || fixture.Source == "" || len(fixture.Specification) == 0 || fixture.Generation == "" || fixture.IndependentValidation == "" {
			t.Fatalf("fixture %q is missing provenance metadata", fixture.ID)
		}
		if fixture.Message.Type != "request" && fixture.Message.Type != "response" {
			t.Fatalf("fixture %q has unsupported message type %q", fixture.ID, fixture.Message.Type)
		}
		if fixture.Message.Type == "request" && fixture.Message.RequestTarget == "" {
			t.Fatalf("request fixture %q is missing its fixed request-target", fixture.ID)
		}
		if len(fixture.SignedHeaders) == 0 || fixture.ExpectedSigningString == "" {
			t.Fatalf("fixture %q is missing its signed headers or expected signing string", fixture.ID)
		}
		if strings.HasSuffix(fixture.ExpectedSigningString, "\n") || strings.Contains(fixture.ExpectedSigningString, "\r") {
			t.Fatalf("fixture %q expected signing string must use internal LF separators without a trailing LF", fixture.ID)
		}
		if fixture.SignatureHeader == "" || fixture.SignatureHeaderValue == "" || fixture.SignatureBase64 == "" {
			t.Fatalf("fixture %q is missing its fixed signature", fixture.ID)
		}
		if cavageSignatureParameter(t, fixture.SignatureHeaderValue) != fixture.SignatureBase64 {
			t.Fatalf("fixture %q signature_base64 does not match signature_header_value", fixture.ID)
		}
		if fixture.KeyID == "" || fixture.WireAlgorithm == "" || fixture.CryptoPath == "" || fixture.VerificationTimeString == "" {
			t.Fatalf("fixture %q is missing signature metadata", fixture.ID)
		}
		switch fixture.CryptoPath {
		case "rsa", "ecdsa":
			if fixture.Hash != "sha512" || fixture.VerificationKeyFile == "" || fixture.SigningKeyFile == "" {
				t.Fatalf("fixture %q is missing SHA-512 asymmetric key metadata", fixture.ID)
			}
		case "ed25519":
			if fixture.Hash != "" || fixture.VerificationKeyFile == "" || fixture.SigningKeyFile == "" {
				t.Fatalf("fixture %q is missing raw Ed25519 key metadata", fixture.ID)
			}
		case "hmac":
			if fixture.Hash != "sha512" || fixture.HMACSecretFile == "" {
				t.Fatalf("fixture %q is missing HMAC-SHA-512 metadata", fixture.ID)
			}
		default:
			t.Fatalf("fixture %q has unsupported crypto path %q", fixture.ID, fixture.CryptoPath)
		}
	}

	return fixtureFile.Fixtures
}

func (f cavageConformanceFixture) verificationTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, f.VerificationTimeString)
	if err != nil {
		t.Fatalf("fixture %q has invalid verification_time: %v", f.ID, err)
	}
	return tm
}

func (f cavageConformanceFixture) algorithmID(t *testing.T) sigre.AlgorithmID {
	t.Helper()
	switch f.CryptoPath + "/" + f.Hash {
	case "rsa/sha512":
		return sigre.AlgorithmRSAPKCS1v15SHA512
	case "ecdsa/sha512":
		return sigre.AlgorithmECDSASHA512
	case "ed25519/":
		return sigre.AlgorithmEd25519
	case "hmac/sha512":
		return sigre.AlgorithmHMACSHA512
	default:
		t.Fatalf("fixture %q has no AlgorithmID for %s/%s", f.ID, f.CryptoPath, f.Hash)
		return 0
	}
}

func (f cavageConformanceFixture) newRequest(t *testing.T, includeSignature bool) *http.Request {
	t.Helper()
	if f.Message.Type != "request" {
		t.Fatalf("fixture %q is not a request", f.ID)
	}
	req, err := http.NewRequest(f.Message.Method, f.Message.URL, strings.NewReader(f.Message.Body))
	if err != nil {
		t.Fatalf("failed to construct request for fixture %q: %v", f.ID, err)
	}
	applyCavageFixtureHeaders(req.Header, f.Message.Headers)
	if includeSignature {
		req.RequestURI = f.Message.RequestTarget
		req.Header.Set(f.SignatureHeader, f.SignatureHeaderValue)
	}
	return req
}

func (f cavageConformanceFixture) newResponse(t *testing.T, includeSignature bool) *http.Response {
	t.Helper()
	if f.Message.Type != "response" {
		t.Fatalf("fixture %q is not a response", f.ID)
	}
	res := &http.Response{
		StatusCode: f.Message.StatusCode,
		Status:     f.Message.Status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(f.Message.Body)),
	}
	applyCavageFixtureHeaders(res.Header, f.Message.Headers)
	if includeSignature {
		res.Header.Set(f.SignatureHeader, f.SignatureHeaderValue)
	}
	return res
}

func applyCavageFixtureHeaders(dst http.Header, headers []cavageFixtureHeader) {
	for _, header := range headers {
		dst[http.CanonicalHeaderKey(header.Name)] = append([]string(nil), header.Values...)
	}
}

func loadCavageFixturePrivateKey(t *testing.T, name string) crypto.PrivateKey {
	t.Helper()
	block := loadCavageFixturePEM(t, name)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse fixture private key %q: %v", name, err)
	}
	return key
}

func loadCavageFixturePublicKey(t *testing.T, name string) crypto.PublicKey {
	t.Helper()
	block := loadCavageFixturePEM(t, name)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse fixture public key %q: %v", name, err)
	}
	return key
}

func loadCavageFixturePEM(t *testing.T, name string) *pem.Block {
	t.Helper()
	data := readCavageFixtureFile(t, name)
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("fixture key %q is not a single PEM block", name)
	}
	return block
}

func loadCavageFixtureHMACSecret(t *testing.T, name string) []byte {
	t.Helper()
	secret, err := hex.DecodeString(strings.TrimSpace(string(readCavageFixtureFile(t, name))))
	if err != nil {
		t.Fatalf("failed to decode fixture HMAC secret %q: %v", name, err)
	}
	return secret
}

func readCavageFixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cavageConformanceFixtureDirectory, name))
	if err != nil {
		t.Fatalf("failed to read Cavage fixture file %q: %v", name, err)
	}
	return data
}

func cavageSignatureParameter(t *testing.T, headerValue string) string {
	t.Helper()
	const prefix = `signature="`
	start := strings.Index(headerValue, prefix)
	if start < 0 {
		t.Fatalf("signature parameter not found in %q", headerValue)
	}
	value := headerValue[start+len(prefix):]
	end := strings.IndexByte(value, '"')
	if end < 0 {
		t.Fatalf("signature parameter is not terminated in %q", headerValue)
	}
	return value[:end]
}

func replaceCavageSignatureParameter(t *testing.T, headerValue string) string {
	t.Helper()
	signature := cavageSignatureParameter(t, headerValue)
	return strings.Replace(headerValue, `signature="`+signature+`"`, `signature="<variable>"`, 1)
}
