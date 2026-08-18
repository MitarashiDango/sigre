package sigre_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

func TestActivityPubRawBodyDigestBeforeProcessing(t *testing.T) {
	t.Parallel()

	fixture := cavageInteroperabilityFixtureByID(
		t,
		loadCavageInteroperabilityFixtures(t),
		"misskey-inbox-post-rsa-sha256",
	)
	req := fixture.newRequest(t, true)
	rawBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to retain the exact raw request body: %v", err)
	}
	if err := req.Body.Close(); err != nil {
		t.Fatalf("failed to close request body after retaining it: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(rawBody))

	digest, ok := fixture.headerValue("digest")
	if !ok {
		t.Fatal("fixture does not contain exactly one Digest value")
	}
	if err := verifyInteroperabilitySHA256Digest(rawBody, digest); err != nil {
		t.Fatalf("raw body and Digest comparison failed: %v", err)
	}

	opts := fixture.verificationOptions(t)
	opts.RequiredHeaders = []string{"digest"}
	opts.Now = func() time.Time { return fixture.verificationTime(t) }
	verifier, err := sigre.NewCavageVerifier(opts)
	if err != nil {
		t.Fatalf("failed to construct HTTP signature verifier: %v", err)
	}
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		t.Fatalf("failed to parse HTTP signature: %v", err)
	}
	key := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)
	if err := verifier.Verify(signature, key); err != nil {
		t.Fatalf("HTTP signature verification with signed Digest requirement failed: %v", err)
	}

	var activity map[string]any
	if err := json.Unmarshal(rawBody, &activity); err != nil {
		t.Fatalf("body accepted by both checks is not valid JSON: %v", err)
	}
	if activity["type"] != "Follow" {
		t.Fatalf("decoded ActivityPub type = %v, want Follow", activity["type"])
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read restored request body: %v", err)
	}
	if !bytes.Equal(restored, rawBody) {
		t.Fatal("restored request body differs from the retained raw bytes")
	}
}

func TestActivityPubDigestRejectsChangedRawBodyEvenWhenSignatureIsValid(t *testing.T) {
	t.Parallel()

	fixture := cavageInteroperabilityFixtureByID(
		t,
		loadCavageInteroperabilityFixtures(t),
		"misskey-inbox-post-rsa-sha256",
	)
	changedRawBody := append([]byte(fixture.Message.Body), '\n')
	req := fixture.newRequest(t, true)
	req.Body = io.NopCloser(bytes.NewReader(changedRawBody))
	key := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)
	opts := fixture.verificationOptions(t)
	opts.RequiredHeaders = []string{"digest"}
	opts.Now = func() time.Time { return fixture.verificationTime(t) }
	verifier, err := sigre.NewCavageVerifier(opts)
	if err != nil {
		t.Fatalf("failed to construct verifier for request with changed raw body: %v", err)
	}
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		t.Fatalf("failed to parse signature for request with changed raw body: %v", err)
	}
	if err := verifier.Verify(signature, key); err != nil {
		t.Fatalf("fixed HTTP signature should remain valid because it signs the Digest field value: %v", err)
	}

	digest, ok := fixture.headerValue("digest")
	if !ok {
		t.Fatal("fixture does not contain exactly one Digest value")
	}
	if err := verifyInteroperabilitySHA256Digest(changedRawBody, digest); err == nil {
		t.Fatal("changed raw body unexpectedly matched the signed Digest field value")
	}
}

func TestActivityPubDigestMustBeSignedByCallerPolicy(t *testing.T) {
	t.Parallel()

	fixture := cavageInteroperabilityFixtureByID(
		t,
		loadCavageInteroperabilityFixtures(t),
		"misskey-signed-get-rsa-sha256",
	)
	emptyDigest := sha256.Sum256(nil)
	fixture.Message.Headers = append(fixture.Message.Headers, cavageFixtureHeader{
		Name:   "Digest",
		Values: []string{"SHA-256=" + base64.StdEncoding.EncodeToString(emptyDigest[:])},
	})
	key := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)

	verifier, signature, err := parseCavageInteroperability(t, fixture, fixture.verificationTime(t), fixture.verificationOptions(t))
	if err != nil {
		t.Fatalf("signature should parse when an unsigned Digest field is merely present: %v", err)
	}
	if err := verifier.Verify(signature, key); err != nil {
		t.Fatalf("signature should remain valid when an unsigned Digest field is merely present: %v", err)
	}

	opts := fixture.verificationOptions(t)
	opts.RequiredHeaders = []string{"digest"}
	_, _, err = parseCavageInteroperability(t, fixture, fixture.verificationTime(t), opts)
	if !errors.Is(err, sigre.ErrRequiredHeaderMissing) {
		t.Fatalf("RequiredHeaders did not reject unsigned Digest: %v", err)
	}
}

func TestActivityPubDigestHelperRejectsUnsupportedOrMalformedValues(t *testing.T) {
	t.Parallel()

	validDigest := sha256.Sum256([]byte("fixture"))
	validBase64 := base64.StdEncoding.EncodeToString(validDigest[:])
	tests := []struct {
		name   string
		header string
	}{
		{name: "invalid Base64", header: "SHA-256=not*base64"},
		{name: "non-canonical Base64", header: "SHA-256=" + strings.TrimRight(validBase64, "=")},
		{name: "wrong digest algorithm", header: "SHA-512=" + validBase64},
		{name: "wrong decoded length", header: "SHA-256=" + base64.StdEncoding.EncodeToString([]byte("short"))},
		{name: "multiple digest values", header: "SHA-256=" + validBase64 + ",SHA-256=" + validBase64},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := verifyInteroperabilitySHA256Digest([]byte("fixture"), test.header); err == nil {
				t.Fatalf("Digest helper accepted unsupported or malformed value %q", test.header)
			}
		})
	}
}
