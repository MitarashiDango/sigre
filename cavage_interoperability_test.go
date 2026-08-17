package sigre_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

type cavageRFC9421CoexistFixture struct {
	FormatVersion         int    `json:"format_version"`
	BaseFixtureID         string `json:"base_fixture_id"`
	RFC9421Signature      string `json:"rfc_9421_signature"`
	RFC9421SignatureInput string `json:"rfc_9421_signature_input"`
}

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

			strictVerifier, strictSignature, err := parseCavageInteroperability(t, fixture, fixture.verificationTime(t), nil)
			if err == nil {
				err = strictVerifier.Verify(strictSignature, key)
			}
			if !errors.Is(err, fixture.strictRejectionError(t)) {
				t.Fatalf("strict verification error = %v, want %v", err, fixture.strictRejectionError(t))
			}

			explicitVerifier, signature, err := parseCavageInteroperability(t, fixture, fixture.verificationTime(t), fixture.verificationOptions(t))
			if err != nil {
				t.Fatalf("parsing with recorded explicit compatibility failed: %v", err)
			}
			if err := explicitVerifier.Verify(signature, key); err != nil {
				t.Fatalf("verification with recorded explicit compatibility failed: %v", err)
			}
		})
	}

	fixture := cavageInteroperabilityFixtureByID(t, loadCavageInteroperabilityFixtures(t), "mastodon-cavage-post-rsa-sha256")
	_, _, err := parseCavageInteroperability(t, fixture, fixture.verificationTime(t), &sigre.CavageVerificationOptions{
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

			options := fixture.verificationOptions(t)
			options.Now = func() time.Time { return fixture.verificationTime(t) }
			verifier, err := sigre.NewCavageVerifier(options)
			if err != nil {
				t.Fatalf("generated signature verifier could not be constructed: %v", err)
			}
			signature, err := verifier.ParseRequest(req)
			if err != nil {
				t.Fatalf("generated signature could not be parsed: %v", err)
			}
			verificationKey := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)
			if err := verifier.Verify(signature, verificationKey); err != nil {
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
			opts := &sigre.CavageVerificationOptions{
				AllowedAlgorithms: []sigre.AlgorithmID{
					sigre.AlgorithmRSAPKCS1v15SHA256,
					sigre.AlgorithmRSAPKCS1v15SHA512,
				},
			}
			if test.mapping != nil {
				opts.Compatibility = &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: test.mapping}
			}
			verifier, signature, err := parseCavageInteroperability(t, fixture, fixture.verificationTime(t), opts)
			if err == nil {
				err = verifier.Verify(signature, test.key)
			}
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
	mastodonOptions := mastodon.verificationOptions(t)
	mastodonOptions.AllowedAlgorithms = []sigre.AlgorithmID{
		sigre.AlgorithmRSAPKCS1v15SHA256,
		sigre.AlgorithmRSAPKCS1v15SHA512,
	}
	verifier, signature, err := parseCavageInteroperability(t, mastodon, mastodon.verificationTime(t), mastodonOptions)
	if err != nil {
		t.Fatalf("failed to parse Mastodon fixture: %v", err)
	}
	if err := verifier.Verify(signature, wrongAlgorithmKey); !errors.Is(err, sigre.ErrAlgorithmMismatch) {
		t.Fatalf("rsa-sha256 wire label selected a different trusted algorithm: %v", err)
	}

	wrongKeyType := sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: mastodon.KeyID, Algorithm: sigre.AlgorithmRSAPKCS1v15SHA256},
		PublicKey: loadCavageInteroperabilityPublicKey(t, "../cavage-draft-12/keys/ecdsa-public.pem"),
	}
	verifier, signature, err = parseCavageInteroperability(t, mastodon, mastodon.verificationTime(t), mastodon.verificationOptions(t))
	if err != nil {
		t.Fatalf("failed to parse Mastodon fixture: %v", err)
	}
	if err := verifier.Verify(signature, wrongKeyType); !errors.Is(err, sigre.ErrAlgorithmMismatch) {
		t.Fatalf("RSA AlgorithmID accepted a non-RSA key: %v", err)
	}

	fediverse := cavageInteroperabilityFixtureByID(t, fixtures, "fediverse-hs2019-rsa-sha256")
	sha512Key := sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: fediverse.KeyID, Algorithm: sigre.AlgorithmRSAPKCS1v15SHA512},
		PublicKey: loadCavageInteroperabilityPublicKey(t, fediverse.VerificationKeyFile),
	}
	verifier, signature, err = parseCavageInteroperability(t, fediverse, fediverse.verificationTime(t), &sigre.CavageVerificationOptions{
		AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256, sigre.AlgorithmRSAPKCS1v15SHA512},
		Compatibility:     &sigre.CavageVerificationCompatibility{AllowHS2019WithSHA256: true},
	})
	if err == nil {
		err = verifier.Verify(signature, sha512Key)
	}
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

	verifier, signature, err := parseCavageInteroperability(t, fixture, fixture.verificationTime(t).Add(5*time.Minute), opts)
	if err != nil {
		t.Fatalf("OCI fixture failed to parse at the caller-selected five-minute boundary: %v", err)
	}
	if err := verifier.Verify(signature, key); err != nil {
		t.Fatalf("OCI fixture failed at the caller-selected five-minute boundary: %v", err)
	}
	_, _, err = parseCavageInteroperability(t, fixture, fixture.verificationTime(t).Add(5*time.Minute+time.Nanosecond), opts)
	if !errors.Is(err, sigre.ErrInvalidDate) {
		t.Fatalf("OCI caller-selected MaxDateAge did not reject an older Date value: %v", err)
	}
}

func TestCavageInteroperabilityAuthorizationCoexistsWithRFC9421(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(cavageInteroperabilityFixtureDirectory, "rfc9421-coexist.json"))
	if err != nil {
		t.Fatalf("failed to read coexistence fixture: %v", err)
	}
	var coexist cavageRFC9421CoexistFixture
	if err := json.Unmarshal(data, &coexist); err != nil {
		t.Fatalf("failed to decode coexistence fixture: %v", err)
	}
	if coexist.FormatVersion != 1 || coexist.BaseFixtureID == "" || coexist.RFC9421Signature == "" || coexist.RFC9421SignatureInput == "" {
		t.Fatalf("coexistence fixture is incomplete: %+v", coexist)
	}

	fixture := cavageInteroperabilityFixtureByID(t, loadCavageInteroperabilityFixtures(t), coexist.BaseFixtureID)
	req := fixture.newRequest(t, true)
	req.Header.Set(sigre.Signature, coexist.RFC9421Signature)
	req.Header.Set("Signature-Input", coexist.RFC9421SignatureInput)
	options := fixture.verificationOptions(t)
	if options.RequestSignatureSource != sigre.CavageRequestSignatureSourceAuthorization {
		t.Fatal("Authorization fixture did not explicitly select the Authorization source")
	}
	options.Now = func() time.Time { return fixture.verificationTime(t) }
	verifier, err := sigre.NewCavageVerifier(options)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		t.Fatalf("Cavage Authorization did not coexist with RFC 9421 fields: %v", err)
	}
	if signature.Placement() != sigre.CavageSignaturePlacementAuthorization {
		t.Fatalf("Placement() = %d, want Authorization", signature.Placement())
	}
	key := interoperabilityVerificationKey(t, fixture, fixture.algorithmID(t), fixture.VerificationKeyFile)
	if err := verifier.Verify(signature, key); err != nil {
		t.Fatalf("coexistence fixture verification failed: %v", err)
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

func parseCavageInteroperability(
	t *testing.T,
	fixture cavageInteroperabilityFixture,
	now time.Time,
	opts *sigre.CavageVerificationOptions,
) (*sigre.CavageVerifier, *sigre.CavageSignature, error) {
	t.Helper()
	options := sigre.CavageVerificationOptions{}
	if opts != nil {
		options = *opts
	}
	options.Now = func() time.Time { return now }
	if fixture.SignaturePlacement == sigre.Authorization {
		options.RequestSignatureSource = sigre.CavageRequestSignatureSourceAuthorization
	}
	verifier, err := sigre.NewCavageVerifier(&options)
	if err != nil {
		return nil, nil, err
	}
	signature, err := verifier.ParseRequest(fixture.newRequest(t, true))
	return verifier, signature, err
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
