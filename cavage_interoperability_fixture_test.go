package sigre_test

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

const cavageInteroperabilityFixtureDirectory = "testdata/cavage-interoperability"

type cavageInteroperabilityFixtureFile struct {
	FormatVersion int                             `json:"format_version"`
	Fixtures      []cavageInteroperabilityFixture `json:"fixtures"`
}

type cavageInteroperabilityFixture struct {
	ID                        string                                          `json:"id"`
	Target                    string                                          `json:"target"`
	Description               string                                          `json:"description"`
	Construction              string                                          `json:"construction"`
	Sources                   []cavageInteroperabilitySource                  `json:"sources"`
	Generation                string                                          `json:"generation"`
	IndependentValidation     string                                          `json:"independent_validation"`
	Message                   cavageInteroperabilityHTTPMessage               `json:"message"`
	SignedHeaders             []string                                        `json:"signed_headers"`
	ExpectedSigningString     string                                          `json:"expected_signing_string"`
	KeyID                     string                                          `json:"key_id"`
	WireAlgorithm             string                                          `json:"wire_algorithm"`
	TrustedAlgorithm          string                                          `json:"trusted_algorithm"`
	SignaturePlacement        string                                          `json:"signature_placement"`
	SignatureHeaderValue      string                                          `json:"signature_header_value"`
	SignatureBase64           string                                          `json:"signature_base64"`
	VerificationKeyFile       string                                          `json:"verification_key_file"`
	SigningKeyFile            string                                          `json:"signing_key_file"`
	VerificationTimeString    string                                          `json:"verification_time"`
	StrictRejection           string                                          `json:"strict_rejection"`
	VerificationCompatibility cavageInteroperabilityVerificationCompatibility `json:"verification_compatibility"`
	SigningCompatibility      cavageInteroperabilitySigningCompatibility      `json:"signing_compatibility"`
}

type cavageInteroperabilitySource struct {
	URL       string `json:"url"`
	Revision  string `json:"revision"`
	Assertion string `json:"assertion"`
}

type cavageInteroperabilityHTTPMessage struct {
	Method        string                `json:"method"`
	URL           string                `json:"url"`
	RequestTarget string                `json:"request_target"`
	Headers       []cavageFixtureHeader `json:"headers"`
	Body          string                `json:"body"`
}

type cavageInteroperabilityVerificationCompatibility struct {
	AllowedLegacyAlgorithms []string          `json:"allowed_legacy_algorithms"`
	ExtensionAlgorithms     map[string]string `json:"extension_algorithms"`
	AllowHS2019WithSHA256   bool              `json:"allow_hs2019_with_sha256"`
}

type cavageInteroperabilitySigningCompatibility struct {
	AlgorithmField string                                    `json:"algorithm_field"`
	ExactHeaders   []string                                  `json:"exact_headers"`
	Extension      *cavageInteroperabilityExtensionAlgorithm `json:"extension"`
}

type cavageInteroperabilityExtensionAlgorithm struct {
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"`
}

func loadCavageInteroperabilityFixtures(t *testing.T) []cavageInteroperabilityFixture {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(cavageInteroperabilityFixtureDirectory, "fixtures.json"))
	if err != nil {
		t.Fatalf("failed to read Cavage interoperability fixtures: %v", err)
	}

	var fixtureFile cavageInteroperabilityFixtureFile
	if err := json.Unmarshal(data, &fixtureFile); err != nil {
		t.Fatalf("failed to decode Cavage interoperability fixtures: %v", err)
	}
	if fixtureFile.FormatVersion != 1 {
		t.Fatalf("unsupported Cavage interoperability fixture format version: %d", fixtureFile.FormatVersion)
	}
	if len(fixtureFile.Fixtures) == 0 {
		t.Fatal("Cavage interoperability fixture file contains no fixtures")
	}

	seen := make(map[string]bool, len(fixtureFile.Fixtures))
	for i := range fixtureFile.Fixtures {
		fixture := &fixtureFile.Fixtures[i]
		validateCavageInteroperabilityFixture(t, fixture, seen)
		seen[fixture.ID] = true
	}
	return fixtureFile.Fixtures
}

func validateCavageInteroperabilityFixture(t *testing.T, fixture *cavageInteroperabilityFixture, seen map[string]bool) {
	t.Helper()
	if fixture.ID == "" || seen[fixture.ID] {
		t.Fatalf("interoperability fixture has an empty or duplicate id: %q", fixture.ID)
	}
	if fixture.Target == "" || fixture.Description == "" || fixture.Construction == "" {
		t.Fatalf("fixture %q is missing identity or construction metadata", fixture.ID)
	}
	if !strings.Contains(fixture.Construction, "locally constructed") {
		t.Fatalf("fixture %q must state that it was locally constructed", fixture.ID)
	}
	if len(fixture.Sources) == 0 || fixture.Generation == "" || fixture.IndependentValidation == "" {
		t.Fatalf("fixture %q is missing provenance or validation metadata", fixture.ID)
	}
	for _, source := range fixture.Sources {
		if source.URL == "" || source.Revision == "" || source.Assertion == "" {
			t.Fatalf("fixture %q has an incomplete source record", fixture.ID)
		}
		if sourceURL, err := url.Parse(source.URL); err != nil || sourceURL.Scheme != "https" || sourceURL.Host == "" {
			t.Fatalf("fixture %q has an invalid source URL %q", fixture.ID, source.URL)
		}
	}

	if fixture.Message.Method == "" || fixture.Message.URL == "" || fixture.Message.RequestTarget == "" {
		t.Fatalf("fixture %q is missing HTTP request metadata", fixture.ID)
	}
	parsedURL, err := url.Parse(fixture.Message.URL)
	if err != nil {
		t.Fatalf("fixture %q has an invalid request URL: %v", fixture.ID, err)
	}
	if parsedURL.RequestURI() != fixture.Message.RequestTarget {
		t.Fatalf("fixture %q request_target = %q, URL preserves %q", fixture.ID, fixture.Message.RequestTarget, parsedURL.RequestURI())
	}
	if len(fixture.SignedHeaders) == 0 || fixture.ExpectedSigningString == "" {
		t.Fatalf("fixture %q is missing signed headers or its expected signing string", fixture.ID)
	}
	if strings.HasSuffix(fixture.ExpectedSigningString, "\n") || strings.Contains(fixture.ExpectedSigningString, "\r") {
		t.Fatalf("fixture %q expected signing string must use internal LF separators without a trailing LF", fixture.ID)
	}
	if got := buildInteroperabilitySigningString(t, *fixture); got != fixture.ExpectedSigningString {
		t.Fatalf("fixture %q expected signing string does not match its fixed message\ngot:  %q\nwant: %q", fixture.ID, got, fixture.ExpectedSigningString)
	}

	seenHeaders := make(map[string]bool, len(fixture.SignedHeaders))
	for _, header := range fixture.SignedHeaders {
		if header == "" || header != strings.ToLower(header) || seenHeaders[header] {
			t.Fatalf("fixture %q has an empty, non-lowercase, or duplicate signed header %q", fixture.ID, header)
		}
		seenHeaders[header] = true
	}

	if fixture.KeyID == "" || fixture.WireAlgorithm == "" || fixture.TrustedAlgorithm == "" {
		t.Fatalf("fixture %q is missing algorithm or key metadata", fixture.ID)
	}
	if fixture.SignatureHeaderValue == "" || fixture.SignatureBase64 == "" {
		t.Fatalf("fixture %q is missing its fixed signature", fixture.ID)
	}
	if got := interoperabilityQuotedParameter(t, fixture.SignatureHeaderValue, "keyId"); got != fixture.KeyID {
		t.Fatalf("fixture %q keyId parameter = %q, want %q", fixture.ID, got, fixture.KeyID)
	}
	if got := interoperabilityQuotedParameter(t, fixture.SignatureHeaderValue, "algorithm"); got != fixture.WireAlgorithm {
		t.Fatalf("fixture %q algorithm parameter = %q, want %q", fixture.ID, got, fixture.WireAlgorithm)
	}
	if got := interoperabilityQuotedParameter(t, fixture.SignatureHeaderValue, "headers"); got != strings.Join(fixture.SignedHeaders, " ") {
		t.Fatalf("fixture %q headers parameter = %q, want %q", fixture.ID, got, strings.Join(fixture.SignedHeaders, " "))
	}
	if got := interoperabilityQuotedParameter(t, fixture.SignatureHeaderValue, "signature"); got != fixture.SignatureBase64 {
		t.Fatalf("fixture %q signature parameter differs from signature_base64", fixture.ID)
	}
	if signature, err := base64.StdEncoding.Strict().DecodeString(fixture.SignatureBase64); err != nil || len(signature) == 0 {
		t.Fatalf("fixture %q has an invalid fixed Base64 signature: length=%d error=%v", fixture.ID, len(signature), err)
	}

	switch fixture.SignaturePlacement {
	case sigre.Signature:
		if strings.HasPrefix(fixture.SignatureHeaderValue, "Signature ") {
			t.Fatalf("fixture %q Signature header value must not contain an auth scheme", fixture.ID)
		}
	case sigre.Authorization:
		if !strings.HasPrefix(fixture.SignatureHeaderValue, "Signature ") {
			t.Fatalf("fixture %q Authorization value must use the Signature scheme", fixture.ID)
		}
	default:
		t.Fatalf("fixture %q has unsupported signature placement %q", fixture.ID, fixture.SignaturePlacement)
	}

	if fixture.VerificationKeyFile == "" || fixture.SigningKeyFile == "" || fixture.VerificationTimeString == "" || fixture.StrictRejection == "" {
		t.Fatalf("fixture %q is missing key, time, or strict-rejection metadata", fixture.ID)
	}
	fixture.algorithmID(t)
	fixture.strictRejectionError(t)
	fixture.verificationTime(t)
	fixture.verificationOptions(t)
	fixture.signingOptions(t)

	if digest, ok := fixture.headerValue("digest"); ok {
		if err := verifyInteroperabilitySHA256Digest([]byte(fixture.Message.Body), digest); err != nil {
			t.Fatalf("fixture %q body does not match Digest: %v", fixture.ID, err)
		}
	}
	if length, ok := fixture.headerValue("content-length"); ok {
		got, err := strconv.Atoi(length)
		if err != nil || got != len([]byte(fixture.Message.Body)) {
			t.Fatalf("fixture %q content-length = %q, body length = %d", fixture.ID, length, len([]byte(fixture.Message.Body)))
		}
	}
}

func buildInteroperabilitySigningString(t *testing.T, fixture cavageInteroperabilityFixture) string {
	t.Helper()
	lines := make([]string, 0, len(fixture.SignedHeaders))
	for _, name := range fixture.SignedHeaders {
		if name == sigre.RequestTarget {
			lines = append(lines, sigre.RequestTarget+": "+strings.ToLower(fixture.Message.Method)+" "+fixture.Message.RequestTarget)
			continue
		}
		values, ok := fixture.headerValues(name)
		if !ok {
			t.Fatalf("fixture %q signs missing header %q", fixture.ID, name)
		}
		trimmed := make([]string, len(values))
		for i, value := range values {
			trimmed[i] = strings.Trim(value, " \t")
		}
		lines = append(lines, name+": "+strings.Join(trimmed, ", "))
	}
	return strings.Join(lines, "\n")
}

func (f cavageInteroperabilityFixture) headerValues(name string) ([]string, bool) {
	var values []string
	for _, header := range f.Message.Headers {
		if strings.EqualFold(header.Name, name) {
			if values != nil {
				return nil, false
			}
			values = header.Values
		}
	}
	return values, values != nil
}

func (f cavageInteroperabilityFixture) headerValue(name string) (string, bool) {
	values, ok := f.headerValues(name)
	if !ok || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func (f cavageInteroperabilityFixture) newRequest(t *testing.T, includeSignature bool) *http.Request {
	t.Helper()
	req := httptest.NewRequest(f.Message.Method, f.Message.RequestTarget, strings.NewReader(f.Message.Body))
	parsedURL, err := url.Parse(f.Message.URL)
	if err != nil {
		t.Fatalf("failed to parse URL for fixture %q: %v", f.ID, err)
	}
	req.URL = parsedURL
	req.Host = parsedURL.Host
	applyCavageFixtureHeaders(req.Header, f.Message.Headers)
	if includeSignature {
		req.Header.Set(f.SignaturePlacement, f.SignatureHeaderValue)
	}
	return req
}

func (f cavageInteroperabilityFixture) verificationTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, f.VerificationTimeString)
	if err != nil {
		t.Fatalf("fixture %q has invalid verification_time: %v", f.ID, err)
	}
	return tm
}

func (f cavageInteroperabilityFixture) algorithmID(t *testing.T) sigre.AlgorithmID {
	t.Helper()
	switch f.TrustedAlgorithm {
	case "AlgorithmRSAPKCS1v15SHA256":
		return sigre.AlgorithmRSAPKCS1v15SHA256
	case "AlgorithmRSAPKCS1v15SHA512":
		return sigre.AlgorithmRSAPKCS1v15SHA512
	default:
		t.Fatalf("fixture %q has unsupported trusted_algorithm %q", f.ID, f.TrustedAlgorithm)
		return 0
	}
}

func (f cavageInteroperabilityFixture) strictRejectionError(t *testing.T) error {
	t.Helper()
	switch f.StrictRejection {
	case "ErrInvalidSignatureAlgorithm":
		return sigre.ErrInvalidSignatureAlgorithm
	case "ErrAlgorithmMismatch":
		return sigre.ErrAlgorithmMismatch
	default:
		t.Fatalf("fixture %q has unsupported strict rejection %q", f.ID, f.StrictRejection)
		return nil
	}
}

func (f cavageInteroperabilityFixture) verificationOptions(t *testing.T) *sigre.CavageVerificationOptions {
	t.Helper()
	compatibility := &sigre.CavageVerificationCompatibility{
		AllowHS2019WithSHA256: f.VerificationCompatibility.AllowHS2019WithSHA256,
	}
	for _, name := range f.VerificationCompatibility.AllowedLegacyAlgorithms {
		compatibility.AllowedLegacyAlgorithms = append(compatibility.AllowedLegacyAlgorithms, interoperabilityAlgorithmID(t, f.ID, name))
	}
	if len(f.VerificationCompatibility.ExtensionAlgorithms) > 0 {
		compatibility.ExtensionAlgorithms = make(map[string]sigre.AlgorithmID, len(f.VerificationCompatibility.ExtensionAlgorithms))
		for label, name := range f.VerificationCompatibility.ExtensionAlgorithms {
			compatibility.ExtensionAlgorithms[label] = interoperabilityAlgorithmID(t, f.ID, name)
		}
	}
	if len(compatibility.AllowedLegacyAlgorithms) == 0 && len(compatibility.ExtensionAlgorithms) == 0 && !compatibility.AllowHS2019WithSHA256 {
		t.Fatalf("fixture %q does not record an explicit verification compatibility setting", f.ID)
	}
	options := &sigre.CavageVerificationOptions{
		AllowedAlgorithms: []sigre.AlgorithmID{f.algorithmID(t)},
		Compatibility:     compatibility,
	}
	if f.SignaturePlacement == sigre.Authorization {
		options.RequestSignatureSource = sigre.CavageRequestSignatureSourceAuthorization
	}
	return options
}

func (f cavageInteroperabilityFixture) signingOptions(t *testing.T) *sigre.CavageSigningOptions {
	t.Helper()
	compatibility := &sigre.CavageSigningCompatibility{
		ExactHeaders: append([]string(nil), f.SigningCompatibility.ExactHeaders...),
	}
	switch f.SigningCompatibility.AlgorithmField {
	case "AlgorithmFieldLegacy":
		compatibility.AlgorithmField = sigre.AlgorithmFieldLegacy
	case "AlgorithmFieldHS2019WithSHA256":
		compatibility.AlgorithmField = sigre.AlgorithmFieldHS2019WithSHA256
	case "ExtensionAlgorithm":
		if f.SigningCompatibility.Extension == nil {
			t.Fatalf("fixture %q is missing signing extension metadata", f.ID)
		}
		compatibility.Extension = &sigre.ExtensionAlgorithm{
			Label:     f.SigningCompatibility.Extension.Label,
			Algorithm: interoperabilityAlgorithmID(t, f.ID, f.SigningCompatibility.Extension.Algorithm),
		}
	default:
		t.Fatalf("fixture %q has unsupported signing algorithm field %q", f.ID, f.SigningCompatibility.AlgorithmField)
	}
	if !slices.Equal(compatibility.ExactHeaders, f.SignedHeaders) {
		t.Fatalf("fixture %q signing ExactHeaders differ from signed_headers", f.ID)
	}
	return &sigre.CavageSigningOptions{Compatibility: compatibility}
}

func (f cavageInteroperabilityFixture) placement(t *testing.T) sigre.CavageSignaturePlacement {
	t.Helper()
	switch f.SignaturePlacement {
	case sigre.Signature:
		return sigre.CavageSignaturePlacementSignature
	case sigre.Authorization:
		return sigre.CavageSignaturePlacementAuthorization
	default:
		t.Fatalf("fixture %q has unsupported signature placement %q", f.ID, f.SignaturePlacement)
		return 0
	}
}

func interoperabilityAlgorithmID(t *testing.T, fixtureID, name string) sigre.AlgorithmID {
	t.Helper()
	switch name {
	case "AlgorithmRSAPKCS1v15SHA256":
		return sigre.AlgorithmRSAPKCS1v15SHA256
	case "AlgorithmRSAPKCS1v15SHA512":
		return sigre.AlgorithmRSAPKCS1v15SHA512
	case "AlgorithmECDSASHA512":
		return sigre.AlgorithmECDSASHA512
	default:
		t.Fatalf("fixture %q refers to unsupported AlgorithmID name %q", fixtureID, name)
		return 0
	}
}

func interoperabilityQuotedParameter(t *testing.T, headerValue, name string) string {
	t.Helper()
	prefix := name + `="`
	start := strings.Index(headerValue, prefix)
	if start < 0 {
		t.Fatalf("parameter %q not found in %q", name, headerValue)
	}
	value := headerValue[start+len(prefix):]
	end := strings.IndexByte(value, '"')
	if end < 0 {
		t.Fatalf("parameter %q is not terminated in %q", name, headerValue)
	}
	return value[:end]
}

func loadCavageInteroperabilityPrivateKey(t *testing.T, name string) crypto.PrivateKey {
	t.Helper()
	block := loadCavageInteroperabilityPEM(t, name)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse interoperability private key %q: %v", name, err)
	}
	return key
}

func loadCavageInteroperabilityPublicKey(t *testing.T, name string) crypto.PublicKey {
	t.Helper()
	block := loadCavageInteroperabilityPEM(t, name)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse interoperability public key %q: %v", name, err)
	}
	return key
}

func loadCavageInteroperabilityPEM(t *testing.T, name string) *pem.Block {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cavageInteroperabilityFixtureDirectory, name))
	if err != nil {
		t.Fatalf("failed to read interoperability key %q: %v", name, err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("interoperability key %q is not a single PEM block", name)
	}
	return block
}

func verifyInteroperabilitySHA256Digest(rawBody []byte, digestHeader string) error {
	const prefix = "SHA-256="
	if !strings.HasPrefix(digestHeader, prefix) {
		return fmt.Errorf("only a single SHA-256 Digest value is supported by this test helper")
	}
	encoded := strings.TrimPrefix(digestHeader, prefix)
	if encoded == "" || strings.ContainsAny(encoded, ", \t") {
		return fmt.Errorf("Digest must contain one unadorned Base64 value")
	}
	received, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("Digest is not strict standard Base64: %w", err)
	}
	if len(received) != sha256.Size {
		return fmt.Errorf("Digest decodes to %d bytes, want %d for SHA-256", len(received), sha256.Size)
	}
	calculated := sha256.Sum256(rawBody)
	if subtle.ConstantTimeCompare(received, calculated[:]) != 1 {
		return fmt.Errorf("Digest does not match the retained raw body")
	}
	return nil
}
