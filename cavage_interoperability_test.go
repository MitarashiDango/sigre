package sigre_test

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

func TestCavageInteroperabilityFixtureCoverage(t *testing.T) {
	t.Parallel()

	type expectation struct {
		target        string
		placement     string
		signedHeaders []string
	}
	expected := map[string]expectation{
		"mastodon-cavage-post-rsa-sha256": {
			target:        "Mastodon Cavage POST compatibility form",
			placement:     sigre.Signature,
			signedHeaders: []string{"host", "date", "digest", sigre.RequestTarget},
		},
		"misskey-inbox-post-rsa-sha256": {
			target:        "Misskey inbox POST compatibility form",
			placement:     sigre.Signature,
			signedHeaders: []string{sigre.RequestTarget, "date", "host", "digest"},
		},
		"misskey-signed-get-rsa-sha256": {
			target:        "Misskey signed GET compatibility form",
			placement:     sigre.Signature,
			signedHeaders: []string{sigre.RequestTarget, "date", "host"},
		},
		"pleroma-inbox-post-rsa-sha256": {
			target:        "Pleroma inbox POST compatibility form",
			placement:     sigre.Signature,
			signedHeaders: []string{sigre.RequestTarget, "content-length", "date", "digest", "host"},
		},
		"oci-authorization-get-rsa-sha256": {
			target:        "Oracle Cloud Infrastructure Signature Version 1 GET compatibility form",
			placement:     sigre.Authorization,
			signedHeaders: []string{"date", sigre.RequestTarget, "host"},
		},
		"fediverse-hs2019-rsa-sha256": {
			target:        "Fediverse hs2019 with RSA PKCS #1 v1.5 and SHA-256 compatibility form",
			placement:     sigre.Signature,
			signedHeaders: []string{sigre.RequestTarget, "host", "date", "digest", "content-type"},
		},
		"extension-sigre-test-rsa-sha512": {
			target:        "Unregistered extension label compatibility form",
			placement:     sigre.Signature,
			signedHeaders: []string{sigre.RequestTarget, "host", "date"},
		},
	}

	fixtures := loadCavageInteroperabilityFixtures(t)
	if len(fixtures) != len(expected) {
		t.Fatalf("fixture count = %d, want %d", len(fixtures), len(expected))
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			t.Parallel()
			want, ok := expected[fixture.ID]
			if !ok {
				t.Fatalf("unexpected fixture id %q", fixture.ID)
			}
			if fixture.Target != want.target || fixture.SignaturePlacement != want.placement {
				t.Fatalf("fixture target/placement = %q/%q, want %q/%q", fixture.Target, fixture.SignaturePlacement, want.target, want.placement)
			}
			if !slices.Equal(fixture.SignedHeaders, want.signedHeaders) {
				t.Fatalf("signed headers = %q, want %q", fixture.SignedHeaders, want.signedHeaders)
			}
		})
	}

	mastodon := cavageInteroperabilityFixtureByID(t, fixtures, "mastodon-cavage-post-rsa-sha256")
	if mastodon.Message.RequestTarget != "/inbox?shared=1&next=%2Fitems" {
		t.Fatalf("Mastodon request-target = %q", mastodon.Message.RequestTarget)
	}
	misskeyGET := cavageInteroperabilityFixtureByID(t, fixtures, "misskey-signed-get-rsa-sha256")
	if strings.Contains(misskeyGET.Message.RequestTarget, "?") {
		t.Fatalf("Misskey signed GET fixture must remain query-free: %q", misskeyGET.Message.RequestTarget)
	}
	oci := cavageInteroperabilityFixtureByID(t, fixtures, "oci-authorization-get-rsa-sha256")
	if oci.Message.RequestTarget != "/20160918/instances?availabilityDomain=Fixture%3A%20AD-1&displayName=Team%20X&limit=25" {
		t.Fatalf("OCI request-target did not preserve encoding and query order: %q", oci.Message.RequestTarget)
	}
	extension := cavageInteroperabilityFixtureByID(t, fixtures, "extension-sigre-test-rsa-sha512")
	if extension.Message.RequestTarget != "/resource/%2Fsegment?view=full&cursor=a%2Fb" {
		t.Fatalf("extension request-target did not preserve encoding and query order: %q", extension.Message.RequestTarget)
	}
}

func TestCavageInteroperabilityStrictAndExplicitVerification(t *testing.T) {
	t.Parallel()

	for _, fixture := range loadCavageInteroperabilityFixtures(t) {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			t.Parallel()
			key := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)

			strictVerifier := newCavageInteroperabilityVerifier(t, fixture, fixture.verificationTime(t))
			if err := strictVerifier.Verify(key, nil); !errors.Is(err, fixture.strictRejectionError(t)) {
				t.Fatalf("strict verification error = %v, want %v", err, fixture.strictRejectionError(t))
			}

			explicitVerifier := newCavageInteroperabilityVerifier(t, fixture, fixture.verificationTime(t))
			if err := explicitVerifier.Verify(key, fixture.verificationOptions(t)); err != nil {
				t.Fatalf("verification with recorded explicit compatibility failed: %v", err)
			}
		})
	}

	fixture := cavageInteroperabilityFixtureByID(t, loadCavageInteroperabilityFixtures(t), "mastodon-cavage-post-rsa-sha256")
	key := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)
	verifier := newCavageInteroperabilityVerifier(t, fixture, fixture.verificationTime(t))
	err := verifier.Verify(key, &sigre.CavageVerificationOptions{
		AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256},
	})
	if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
		t.Fatalf("AllowedAlgorithms alone enabled rsa-sha256: %v", err)
	}
}

func TestCavageInteroperabilitySignerMatchesFixedSignatures(t *testing.T) {
	t.Parallel()

	for _, fixture := range loadCavageInteroperabilityFixtures(t) {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			t.Parallel()
			req := fixture.newRequest(t, false)
			signer := sigre.NewCavageSigner()
			signer.Now = func() time.Time { return fixture.verificationTime(t) }
			key := sigre.SigningKey{
				Metadata: sigre.TrustedKeyMetadata{
					KeyID:     fixture.KeyID,
					Algorithm: fixture.algorithmID(t),
				},
				PrivateKey: loadCavageInteroperabilityPrivateKey(t, fixture.SigningKeyFile),
			}
			if err := signer.SignRequest(req, key, fixture.placement(t), fixture.signingOptions(t)); err != nil {
				t.Fatalf("signing with recorded explicit compatibility failed: %v", err)
			}

			actual := cavageInteroperabilitySignatureParameters(t, fixture, req)
			if got := strings.Count(actual, `headers="`); got != 1 {
				t.Fatalf("generated signature contains %d headers parameters, want exactly one: %q", got, actual)
			}
			if got := interoperabilityQuotedParameter(t, actual, "keyId"); got != fixture.KeyID {
				t.Fatalf("generated keyId = %q, want %q", got, fixture.KeyID)
			}
			if got := interoperabilityQuotedParameter(t, actual, "algorithm"); got != fixture.WireAlgorithm {
				t.Fatalf("generated algorithm = %q, want %q", got, fixture.WireAlgorithm)
			}
			if got := interoperabilityQuotedParameter(t, actual, "headers"); got != strings.Join(fixture.SignedHeaders, " ") {
				t.Fatalf("generated signed headers = %q, want %q", got, strings.Join(fixture.SignedHeaders, " "))
			}
			if got := interoperabilityQuotedParameter(t, actual, "signature"); got != fixture.SignatureBase64 {
				t.Fatalf("generated signature differs from independent fixed value\ngot:  %s\nwant: %s", got, fixture.SignatureBase64)
			}
			if strings.Contains(actual, "version=") {
				t.Fatalf("generic signer unexpectedly emitted an OCI-specific version parameter: %q", actual)
			}

			verifier, err := sigre.NewCavageRequestVerifier(req)
			if err != nil {
				t.Fatalf("generated signature could not be parsed: %v", err)
			}
			verifier.Now = func() time.Time { return fixture.verificationTime(t) }
			verificationKey := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)
			if err := verifier.Verify(verificationKey, fixture.verificationOptions(t)); err != nil {
				t.Fatalf("generated signature could not be verified once with its trusted AlgorithmID: %v", err)
			}
		})
	}
}

func TestCavageInteroperabilityExtensionMappingIsExact(t *testing.T) {
	t.Parallel()

	fixture := cavageInteroperabilityFixtureByID(t, loadCavageInteroperabilityFixtures(t), "extension-sigre-test-rsa-sha512")
	publicKey := loadCavageInteroperabilityPublicKey(t, fixture.VerificationKeyFile)
	key := sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512},
		PublicKey: publicKey,
	}
	tests := []struct {
		name    string
		key     sigre.VerificationKey
		mapping map[string]sigre.AlgorithmID
		wantErr error
	}{
		{
			name:    "missing mapping",
			key:     key,
			wantErr: sigre.ErrInvalidSignatureAlgorithm,
		},
		{
			name:    "label comparison is case sensitive",
			key:     key,
			mapping: map[string]sigre.AlgorithmID{"Sigre-Test-RSA-SHA512": sigre.AlgorithmRSAPKCS1v15SHA512},
			wantErr: sigre.ErrInvalidSignatureAlgorithm,
		},
		{
			name:    "mapping identifies a different algorithm",
			key:     key,
			mapping: map[string]sigre.AlgorithmID{fixture.WireAlgorithm: sigre.AlgorithmRSAPKCS1v15SHA256},
			wantErr: sigre.ErrAlgorithmMismatch,
		},
		{
			name: "trusted metadata differs from mapping",
			key: sigre.VerificationKey{
				Metadata:  sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: sigre.AlgorithmRSAPKCS1v15SHA256},
				PublicKey: publicKey,
			},
			mapping: map[string]sigre.AlgorithmID{fixture.WireAlgorithm: sigre.AlgorithmRSAPKCS1v15SHA512},
			wantErr: sigre.ErrAlgorithmMismatch,
		},
		{
			name:    "exact label and trusted algorithm",
			key:     key,
			mapping: map[string]sigre.AlgorithmID{fixture.WireAlgorithm: sigre.AlgorithmRSAPKCS1v15SHA512},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			verifier := newCavageInteroperabilityVerifier(t, fixture, fixture.verificationTime(t))
			opts := &sigre.CavageVerificationOptions{}
			if test.mapping != nil {
				opts.Compatibility = &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: test.mapping}
			}
			err := verifier.Verify(test.key, opts)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("verification error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestCavageInteroperabilityUsesOnlyTrustedAlgorithmAndKeyType(t *testing.T) {
	t.Parallel()

	fixtures := loadCavageInteroperabilityFixtures(t)
	mastodon := cavageInteroperabilityFixtureByID(t, fixtures, "mastodon-cavage-post-rsa-sha256")
	rsaPublicKey := loadCavageInteroperabilityPublicKey(t, mastodon.VerificationKeyFile)
	wrongAlgorithmKey := sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: mastodon.KeyID, Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512},
		PublicKey: rsaPublicKey,
	}
	verifier := newCavageInteroperabilityVerifier(t, mastodon, mastodon.verificationTime(t))
	if err := verifier.Verify(wrongAlgorithmKey, mastodon.verificationOptions(t)); !errors.Is(err, sigre.ErrAlgorithmMismatch) {
		t.Fatalf("rsa-sha256 wire label selected a different trusted algorithm: %v", err)
	}

	wrongKeyType := sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: mastodon.KeyID, Algorithm: sigre.AlgorithmRSAPKCS1v15SHA256},
		PublicKey: loadCavageInteroperabilityPublicKey(t, "../cavage-draft-12/keys/ecdsa-public.pem"),
	}
	verifier = newCavageInteroperabilityVerifier(t, mastodon, mastodon.verificationTime(t))
	if err := verifier.Verify(wrongKeyType, mastodon.verificationOptions(t)); !errors.Is(err, sigre.ErrAlgorithmMismatch) {
		t.Fatalf("RSA AlgorithmID accepted a non-RSA key: %v", err)
	}

	fediverse := cavageInteroperabilityFixtureByID(t, fixtures, "fediverse-hs2019-rsa-sha256")
	sha512Key := sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: fediverse.KeyID, Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512},
		PublicKey: loadCavageInteroperabilityPublicKey(t, fediverse.VerificationKeyFile),
	}
	verifier = newCavageInteroperabilityVerifier(t, fediverse, fediverse.verificationTime(t))
	err := verifier.Verify(sha512Key, &sigre.CavageVerificationOptions{
		Compatibility: &sigre.CavageVerificationCompatibility{AllowHS2019WithSHA256: true},
	})
	if !errors.Is(err, sigre.ErrVerification) {
		t.Fatalf("hs2019 wire label changed the trusted SHA-512 choice or unexpectedly verified: %v", err)
	}
}

func TestCavageInteroperabilityOCICallerPolicies(t *testing.T) {
	t.Parallel()

	fixture := cavageInteroperabilityFixtureByID(t, loadCavageInteroperabilityFixtures(t), "oci-authorization-get-rsa-sha256")
	key := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)
	opts := fixture.verificationOptions(t)
	opts.AllowedAlgorithms = []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256}
	opts.RequiredHeaders = []string{"date", sigre.RequestTarget, "host"}
	opts.MaxDateAge = 5 * time.Minute

	verifier := newCavageInteroperabilityVerifier(t, fixture, fixture.verificationTime(t).Add(5*time.Minute))
	if err := verifier.Verify(key, opts); err != nil {
		t.Fatalf("OCI fixture failed at the caller-selected five-minute boundary: %v", err)
	}
	verifier = newCavageInteroperabilityVerifier(t, fixture, fixture.verificationTime(t).Add(5*time.Minute+time.Nanosecond))
	if err := verifier.Verify(key, opts); !errors.Is(err, sigre.ErrInvalidDate) {
		t.Fatalf("OCI caller-selected MaxDateAge did not reject an older Date value: %v", err)
	}
}

func cavageInteroperabilityFixtureByID(t *testing.T, fixtures []cavageInteroperabilityFixture, id string) cavageInteroperabilityFixture {
	t.Helper()
	for _, fixture := range fixtures {
		if fixture.ID == id {
			return fixture
		}
	}
	t.Fatalf("interoperability fixture %q not found", id)
	return cavageInteroperabilityFixture{}
}

func interoperabilityVerificationKey(
	t *testing.T,
	fixture cavageInteroperabilityFixture,
	algorithm sigre.AlgorithmID,
	keyFile string,
) sigre.VerificationKey {
	t.Helper()
	return sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: algorithm},
		PublicKey: loadCavageInteroperabilityPublicKey(t, keyFile),
	}
}

func newCavageInteroperabilityVerifier(
	t *testing.T,
	fixture cavageInteroperabilityFixture,
	now time.Time,
) *sigre.CavageVerifier {
	t.Helper()
	verifier, err := sigre.NewCavageRequestVerifier(fixture.newRequest(t, true))
	if err != nil {
		t.Fatalf("failed to construct verifier for fixture %q: %v", fixture.ID, err)
	}
	verifier.Now = func() time.Time { return now }
	return verifier
}

func cavageInteroperabilitySignatureParameters(
	t *testing.T,
	fixture cavageInteroperabilityFixture,
	req *http.Request,
) string {
	t.Helper()
	switch fixture.SignaturePlacement {
	case sigre.Signature:
		if value := req.Header.Get(sigre.Authorization); value != "" {
			t.Fatalf("Signature placement also wrote Authorization: %q", value)
		}
		return req.Header.Get(sigre.Signature)
	case sigre.Authorization:
		if value := req.Header.Get(sigre.Signature); value != "" {
			t.Fatalf("Authorization placement also wrote Signature: %q", value)
		}
		value := req.Header.Get(sigre.Authorization)
		if !strings.HasPrefix(value, "Signature ") {
			t.Fatalf("Authorization did not use the Signature scheme: %q", value)
		}
		return strings.TrimPrefix(value, "Signature ")
	default:
		t.Fatalf("unsupported placement %q", fixture.SignaturePlacement)
		return ""
	}
}
