package sigre_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

func TestCavageConformanceFixedSignatureVerification(t *testing.T) {
	for _, fixture := range loadCavageConformanceFixtures(t) {
		t.Run(fixture.ID, func(t *testing.T) {
			var verifier *sigre.CavageVerifier
			var err error
			switch fixture.Message.Type {
			case "request":
				verifier, err = sigre.NewCavageRequestVerifier(fixture.newRequest(t, true))
			case "response":
				verifier, err = sigre.NewCavageResponseVerifier(fixture.newResponse(t, true))
			}
			if err != nil {
				t.Fatalf("failed to construct verifier: %v", err)
			}
			verifier.Now = func() time.Time { return fixture.verificationTime(t) }
			if verifier.KeyId() != fixture.KeyID {
				t.Fatalf("KeyId() = %q, want %q", verifier.KeyId(), fixture.KeyID)
			}

			if fixture.CryptoPath == "hmac" {
				err = verifier.VerifyHMAC(sigre.HMACVerificationKey{
					Metadata: sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: fixture.algorithmID(t)},
					Secret:   loadCavageFixtureHMACSecret(t, fixture.HMACSecretFile),
				}, nil)
			} else {
				err = verifier.Verify(sigre.VerificationKey{
					Metadata:  sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: fixture.algorithmID(t)},
					PublicKey: loadCavageFixturePublicKey(t, fixture.VerificationKeyFile),
				}, nil)
			}
			if err != nil {
				t.Fatalf("fixed signature verification failed: %v", err)
			}
		})
	}
}

func TestCavageConformanceSignerUsesExpectedSigningString(t *testing.T) {
	for _, fixture := range loadCavageConformanceFixtures(t) {
		t.Run(fixture.ID, func(t *testing.T) {
			now := fixture.verificationTime(t)
			signer := &sigre.CavageSigner{Now: func() time.Time { return now }}
			var opts *sigre.CavageSigningOptions
			if !fixture.ZeroValueSigningOptions {
				opts = &sigre.CavageSigningOptions{
					Compatibility: &sigre.CavageSigningCompatibility{
						ExactHeaders: append([]string(nil), fixture.SignedHeaders...),
					},
				}
			}
			placement := sigre.CavageSignaturePlacementSignature
			if fixture.SignatureHeader == sigre.Authorization {
				placement = sigre.CavageSignaturePlacementAuthorization
			}

			var generatedHeader string
			var err error
			switch fixture.Message.Type {
			case "request":
				req := fixture.newRequest(t, false)
				if fixture.CryptoPath == "hmac" {
					err = signer.SignRequestWithHMAC(req, sigre.HMACSigningKey{
						Metadata: sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: fixture.algorithmID(t)},
						Secret:   loadCavageFixtureHMACSecret(t, fixture.HMACSecretFile),
					}, placement, opts)
				} else {
					err = signer.SignRequest(req, sigre.SigningKey{
						Metadata:   sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: fixture.algorithmID(t)},
						PrivateKey: loadCavageFixturePrivateKey(t, fixture.SigningKeyFile),
					}, placement, opts)
				}
				generatedHeader = req.Header.Get(fixture.SignatureHeader)
			case "response":
				res := fixture.newResponse(t, false)
				if fixture.CryptoPath == "hmac" {
					err = signer.SignResponseWithHMAC(res, sigre.HMACSigningKey{
						Metadata: sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: fixture.algorithmID(t)},
						Secret:   loadCavageFixtureHMACSecret(t, fixture.HMACSecretFile),
					}, placement, opts)
				} else {
					err = signer.SignResponse(res, sigre.SigningKey{
						Metadata:   sigre.TrustedKeyMetadata{KeyID: fixture.KeyID, Algorithm: fixture.algorithmID(t)},
						PrivateKey: loadCavageFixturePrivateKey(t, fixture.SigningKeyFile),
					}, placement, opts)
				}
				generatedHeader = res.Header.Get(fixture.SignatureHeader)
			}
			if err != nil {
				t.Fatalf("signature generation failed: %v", err)
			}

			generatedSignature, err := base64.StdEncoding.DecodeString(cavageSignatureParameter(t, generatedHeader))
			if err != nil {
				t.Fatalf("generated signature is not valid Base64: %v", err)
			}
			verifyGeneratedSignatureOverExpectedString(t, fixture, generatedSignature)

			if fixture.CryptoPath == "ecdsa" {
				if replaceCavageSignatureParameter(t, generatedHeader) != replaceCavageSignatureParameter(t, fixture.SignatureHeaderValue) {
					t.Fatalf("generated ECDSA parameters do not match fixed fixture\ngot:  %s\nwant: %s", generatedHeader, fixture.SignatureHeaderValue)
				}
				return
			}
			if generatedHeader != fixture.SignatureHeaderValue {
				t.Fatalf("generated signature header does not match independent fixed value\ngot:  %s\nwant: %s", generatedHeader, fixture.SignatureHeaderValue)
			}
		})
	}
}

func TestCavageConformanceFixtureCoverage(t *testing.T) {
	fixtures := loadCavageConformanceFixtures(t)
	cryptoPaths := make(map[string]bool, 4)
	messageTypes := make(map[string]bool, 2)
	var normalPath, escapedRequestTarget, owsBoundary, nonOWSUnicode, multipleValues, emptyValue bool

	for _, fixture := range fixtures {
		if fixture.WireAlgorithm != "hs2019" {
			t.Errorf("fixture %q uses wire algorithm %q, want hs2019", fixture.ID, fixture.WireAlgorithm)
		}
		cryptoPaths[fixture.CryptoPath] = true
		messageTypes[fixture.Message.Type] = true
		signedHeaders := make(map[string]bool, len(fixture.SignedHeaders))
		for _, name := range fixture.SignedHeaders {
			signedHeaders[strings.ToLower(name)] = true
		}
		if fixture.Message.Type == "request" {
			u, err := url.Parse(fixture.Message.URL)
			if err != nil {
				t.Fatalf("fixture %q has invalid URL: %v", fixture.ID, err)
			}
			if signedHeaders[sigre.RequestTarget] && strings.HasPrefix(u.Path, "/") && u.Path != "/" && u.RawPath == "" && u.EscapedPath() == u.Path && !u.ForceQuery {
				normalPath = true
			}
			if signedHeaders[sigre.RequestTarget] && strings.Contains(fixture.Message.RequestTarget, "%2F") {
				escapedRequestTarget = true
			}
		}
		for _, header := range fixture.Message.Headers {
			if !signedHeaders[strings.ToLower(header.Name)] {
				continue
			}
			if len(header.Values) > 1 {
				multipleValues = true
			}
			if len(header.Values) == 1 && header.Values[0] == "" {
				emptyValue = true
			}
			for _, value := range header.Values {
				if strings.Trim(value, " \t") != value {
					owsBoundary = true
				}
				if strings.ContainsAny(value, "\u00a0\u2003") {
					nonOWSUnicode = true
				}
			}
		}
	}

	for _, cryptoPath := range []string{"rsa", "ecdsa", "ed25519", "hmac"} {
		if !cryptoPaths[cryptoPath] {
			t.Errorf("fixture coverage is missing crypto path %q", cryptoPath)
		}
	}
	for _, messageType := range []string{"request", "response"} {
		if !messageTypes[messageType] {
			t.Errorf("fixture coverage is missing message type %q", messageType)
		}
	}
	if !normalPath || !escapedRequestTarget || !owsBoundary || !nonOWSUnicode || !multipleValues || !emptyValue {
		t.Errorf("fixture coverage incomplete: normalPath=%t escapedRequestTarget=%t owsBoundary=%t nonOWSUnicode=%t multipleValues=%t emptyValue=%t", normalPath, escapedRequestTarget, owsBoundary, nonOWSUnicode, multipleValues, emptyValue)
	}
}

func verifyGeneratedSignatureOverExpectedString(t *testing.T, fixture cavageConformanceFixture, signature []byte) {
	t.Helper()
	message := []byte(fixture.ExpectedSigningString)

	switch fixture.CryptoPath {
	case "rsa":
		publicKey, ok := loadCavageFixturePublicKey(t, fixture.VerificationKeyFile).(*rsa.PublicKey)
		if !ok {
			t.Fatalf("fixture %q verification key is not RSA", fixture.ID)
		}
		digest := sha512.Sum512(message)
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, digest[:], signature); err != nil {
			t.Fatalf("generated RSA signature is not over expected signing string: %v", err)
		}
	case "ecdsa":
		publicKey, ok := loadCavageFixturePublicKey(t, fixture.VerificationKeyFile).(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("fixture %q verification key is not ECDSA", fixture.ID)
		}
		digest := sha512.Sum512(message)
		if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
			t.Fatal("generated ECDSA signature is not over expected signing string")
		}
	case "ed25519":
		publicKey, ok := loadCavageFixturePublicKey(t, fixture.VerificationKeyFile).(ed25519.PublicKey)
		if !ok {
			t.Fatalf("fixture %q verification key is not Ed25519", fixture.ID)
		}
		if !ed25519.Verify(publicKey, message, signature) {
			t.Fatal("generated Ed25519 signature is not over expected signing string")
		}
	case "hmac":
		mac := hmac.New(sha512.New, loadCavageFixtureHMACSecret(t, fixture.HMACSecretFile))
		if _, err := mac.Write(message); err != nil {
			t.Fatalf("failed to compute independent HMAC: %v", err)
		}
		if !hmac.Equal(signature, mac.Sum(nil)) {
			t.Fatal("generated HMAC is not over expected signing string")
		}
	default:
		t.Fatalf("fixture %q uses unsupported crypto path %q", fixture.ID, fixture.CryptoPath)
	}
}
