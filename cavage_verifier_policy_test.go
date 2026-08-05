package sigre_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

const verifierPolicyKeyID = "policy-key"

var _ sigre.Verifier = (*externalVerifierMock)(nil)

type externalVerifierMock struct{}

func (*externalVerifierMock) KeyId() string { return "" }

func (*externalVerifierMock) Verify(sigre.VerificationKey, *sigre.CavageVerificationOptions) error {
	return nil
}

func (*externalVerifierMock) VerifyHMAC(sigre.HMACVerificationKey, *sigre.CavageVerificationOptions) error {
	return nil
}

func newVerifierPolicyRequest(t *testing.T) *http.Request {
	t.Helper()
	req := newTestRequest(t, http.MethodPost, "https://example.com/policy?fixed=1", "")
	req.Header.Set("Date", testFixedTime.Format(http.TimeFormat))
	req.Header.Set("Host", "example.com")
	return req
}

func newVerifierPolicyVerifier(t *testing.T, req *http.Request, now time.Time) *sigre.CavageVerifier {
	t.Helper()
	verifier, err := sigre.NewCavageRequestVerifier(req)
	if err != nil {
		t.Fatalf("NewCavageRequestVerifier() failed: %v", err)
	}
	verifier.Now = func() time.Time { return now }
	return verifier
}

func signVerifierPolicyRSA(t *testing.T, hash crypto.Hash, useHS2019 bool, headers []string, now time.Time) (*http.Request, *rsa.PublicKey) {
	t.Helper()
	privateKey := parseRSAPrivateKey(t, testRSAPrivateKeyPEM)
	req := newVerifierPolicyRequest(t)
	signer := &sigre.CavageSigner{Now: func() time.Time { return now }}
	err := signer.SignRequest(req, privateKey, verifierPolicyKeyID, &sigre.CavageSignOptions{
		Headers:         headers,
		HashAlgorithm:   hash,
		UseHS2019:       useHS2019,
		SignatureHeader: sigre.Signature,
	})
	if err != nil {
		t.Fatalf("RSA signing failed: %v", err)
	}
	return req, &privateKey.PublicKey
}

func signVerifierPolicyECDSA(t *testing.T, hash crypto.Hash, useHS2019 bool, headers []string, now time.Time) (*http.Request, *ecdsa.PublicKey) {
	t.Helper()
	privateKey := parseECDSAPrivateKey(t, testECDSAPrivateKeyPEM)
	req := newVerifierPolicyRequest(t)
	signer := &sigre.CavageSigner{Now: func() time.Time { return now }}
	err := signer.SignRequest(req, privateKey, verifierPolicyKeyID, &sigre.CavageSignOptions{
		Headers:         headers,
		HashAlgorithm:   hash,
		UseHS2019:       useHS2019,
		SignatureHeader: sigre.Signature,
	})
	if err != nil {
		t.Fatalf("ECDSA signing failed: %v", err)
	}
	return req, &privateKey.PublicKey
}

func signVerifierPolicyEd25519(t *testing.T, useHS2019 bool, headers []string, now time.Time, expiry int64) (*http.Request, ed25519.PublicKey) {
	t.Helper()
	privateKey := parseEd25519PrivateKey(t, testEd25519PrivateKeyPEM)
	req := newVerifierPolicyRequest(t)
	signer := &sigre.CavageSigner{Now: func() time.Time { return now }}
	err := signer.SignRequest(req, privateKey, verifierPolicyKeyID, &sigre.CavageSignOptions{
		Headers:         headers,
		Expiry:          expiry,
		UseHS2019:       useHS2019,
		SignatureHeader: sigre.Signature,
	})
	if err != nil {
		t.Fatalf("Ed25519 signing failed: %v", err)
	}
	return req, privateKey.Public().(ed25519.PublicKey)
}

func signVerifierPolicyHMAC(t *testing.T, hash crypto.Hash, useHS2019 bool, headers []string, now time.Time) (*http.Request, []byte) {
	t.Helper()
	secret := []byte(testHMACSecret)
	req := newVerifierPolicyRequest(t)
	signer := &sigre.CavageSigner{Now: func() time.Time { return now }}
	err := signer.SignRequestWithHMAC(req, secret, verifierPolicyKeyID, &sigre.CavageSignOptions{
		Headers:         headers,
		HashAlgorithm:   hash,
		UseHS2019:       useHS2019,
		SignatureHeader: sigre.Signature,
	})
	if err != nil {
		t.Fatalf("HMAC signing failed: %v", err)
	}
	return req, secret
}

func removeQuotedPolicyParameter(t *testing.T, value, name string) string {
	t.Helper()
	prefix := "," + name + "=\""
	start := strings.Index(value, prefix)
	if start < 0 {
		t.Fatalf("parameter %q not found in %q", name, value)
	}
	end := start + len(prefix)
	for end < len(value) {
		if value[end] == '\\' {
			end += 2
			continue
		}
		if value[end] == '"' {
			return value[:start] + value[end+1:]
		}
		end++
	}
	t.Fatalf("parameter %q is unterminated in %q", name, value)
	return ""
}

func replacePolicyAlgorithm(t *testing.T, value, label string) string {
	t.Helper()
	prefix := ",algorithm=\""
	start := strings.Index(value, prefix)
	if start < 0 {
		t.Fatalf("algorithm parameter not found in %q", value)
	}
	valueStart := start + len(prefix)
	end := strings.IndexByte(value[valueStart:], '"')
	if end < 0 {
		t.Fatalf("algorithm parameter is unterminated in %q", value)
	}
	return value[:valueStart] + label + value[valueStart+end:]
}

func removeTokenPolicyParameter(t *testing.T, value, name string) string {
	t.Helper()
	prefix := "," + name + "="
	start := strings.Index(value, prefix)
	if start < 0 {
		t.Fatalf("parameter %q not found in %q", name, value)
	}
	end := strings.IndexByte(value[start+len(prefix):], ',')
	if end < 0 {
		return value[:start]
	}
	return value[:start] + value[start+len(prefix)+end:]
}

func replaceTokenPolicyParameter(t *testing.T, value, name, replacement string) string {
	t.Helper()
	prefix := "," + name + "="
	start := strings.Index(value, prefix)
	if start < 0 {
		t.Fatalf("parameter %q not found in %q", name, value)
	}
	valueStart := start + len(prefix)
	end := strings.IndexByte(value[valueStart:], ',')
	if end < 0 {
		return value[:valueStart] + replacement
	}
	return value[:valueStart] + replacement + value[valueStart+end:]
}

func legacyPolicyOptions(ids ...sigre.AlgorithmID) *sigre.CavageVerificationOptions {
	return &sigre.CavageVerificationOptions{
		Compatibility: &sigre.CavageVerificationCompatibility{AllowedLegacyAlgorithms: ids},
	}
}

func TestCavageVerifierTrustBoundary(t *testing.T) {
	req, rsaPublicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
	verifier := newVerifierPolicyVerifier(t, req, testFixedTime)

	t.Run("exact opaque keyId succeeds", func(t *testing.T) {
		err := verifier.Verify(fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, rsaPublicKey), nil)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}
	})

	t.Run("keyId mismatch is rejected", func(t *testing.T) {
		err := verifier.Verify(fixedPublicVerificationKey("POLICY-KEY", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPublicKey), nil)
		if !errors.Is(err, sigre.ErrKeyIDMismatch) {
			t.Fatalf("expected ErrKeyIDMismatch, got %v", err)
		}
	})

	t.Run("empty trusted KeyID is rejected", func(t *testing.T) {
		err := verifier.Verify(fixedPublicVerificationKey("", sigre.AlgorithmRSAPKCS1v15SHA512, rsaPublicKey), nil)
		if !errors.Is(err, sigre.ErrInvalidKeyMetadata) {
			t.Fatalf("expected ErrInvalidKeyMetadata, got %v", err)
		}
	})

	t.Run("zero AlgorithmID is rejected", func(t *testing.T) {
		err := verifier.Verify(fixedPublicVerificationKey(verifierPolicyKeyID, 0, rsaPublicKey), nil)
		if !errors.Is(err, sigre.ErrInvalidKeyMetadata) {
			t.Fatalf("expected ErrInvalidKeyMetadata, got %v", err)
		}
	})

	t.Run("nil public key is rejected", func(t *testing.T) {
		err := verifier.Verify(fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, nil), nil)
		if !errors.Is(err, sigre.ErrMissingPublicKey) {
			t.Fatalf("expected ErrMissingPublicKey, got %v", err)
		}
	})

	t.Run("public key type and AlgorithmID must agree", func(t *testing.T) {
		ecdsaPublicKey := parseECDSAPublicKey(t, testECDSAPublicKeyPEM)
		err := verifier.Verify(fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, ecdsaPublicKey), nil)
		if !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected ErrAlgorithmMismatch, got %v", err)
		}
	})

	t.Run("HMAC AlgorithmID is rejected by Verify", func(t *testing.T) {
		err := verifier.Verify(fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, rsaPublicKey), nil)
		if !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected ErrAlgorithmMismatch, got %v", err)
		}
	})

	t.Run("asymmetric AlgorithmID is rejected by VerifyHMAC", func(t *testing.T) {
		err := verifier.VerifyHMAC(fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, []byte("secret")), nil)
		if !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected ErrAlgorithmMismatch, got %v", err)
		}
	})

	t.Run("empty HMAC secret is rejected", func(t *testing.T) {
		hmacReq, _ := signVerifierPolicyHMAC(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		hmacVerifier := newVerifierPolicyVerifier(t, hmacReq, testFixedTime)
		err := hmacVerifier.VerifyHMAC(fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, nil), nil)
		if !errors.Is(err, sigre.ErrMissingSharedSecret) {
			t.Fatalf("expected ErrMissingSharedSecret, got %v", err)
		}
	})

	t.Run("correct key with a different AlgorithmID does not succeed", func(t *testing.T) {
		err := verifier.Verify(fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, rsaPublicKey), nil)
		if !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected ErrAlgorithmMismatch, got %v", err)
		}
	})

	t.Run("wire hs2019 cannot switch the trusted hash or trigger fallback", func(t *testing.T) {
		hmacReq, secret := signVerifierPolicyHMAC(t, crypto.SHA256, true, []string{"date"}, testFixedTime)
		hmacVerifier := newVerifierPolicyVerifier(t, hmacReq, testFixedTime)
		err := hmacVerifier.VerifyHMAC(fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret), nil)
		if !errors.Is(err, sigre.ErrVerification) {
			t.Fatalf("expected one SHA-512 verification to fail with ErrVerification, got %v", err)
		}
	})
}

func TestCavageVerifierStrictZeroValue(t *testing.T) {
	t.Run("omitted algorithm and headers use trusted Ed25519 and effective created", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime, 0)
		header := req.Header.Get(sigre.Signature)
		header = removeQuotedPolicyParameter(t, header, "algorithm")
		header = removeQuotedPolicyParameter(t, header, "headers")
		req.Header.Set(sigre.Signature, header)
		verifier := newVerifierPolicyVerifier(t, req, testFixedTime)

		err := verifier.Verify(fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey), nil)
		if err != nil {
			t.Fatalf("strict omitted-parameter verification failed: %v", err)
		}
		err = verifier.Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey),
			&sigre.CavageVerificationOptions{RequiredHeaders: []string{sigre.Created}},
		)
		if err != nil {
			t.Fatalf("RequiredHeaders did not inspect effective (created): %v", err)
		}
	})

	t.Run("hs2019 with SHA-512 succeeds", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey), nil,
		)
		if err != nil {
			t.Fatalf("strict hs2019 verification failed: %v", err)
		}
	})

	t.Run("hs2019 with SHA-256 is rejected", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA256, true, []string{"date"}, testFixedTime)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, publicKey), nil,
		)
		if !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected ErrAlgorithmMismatch, got %v", err)
		}
	})

	t.Run("deprecated labels are rejected", func(t *testing.T) {
		tests := []struct {
			name   string
			verify func() error
		}{
			{
				name: "rsa-sha256",
				verify: func() error {
					req, publicKey := signVerifierPolicyRSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, publicKey), nil)
				},
			},
			{
				name: "ecdsa-sha256",
				verify: func() error {
					req, publicKey := signVerifierPolicyECDSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSASHA256, publicKey), nil)
				},
			},
			{
				name: "hmac-sha256",
				verify: func() error {
					req, secret := signVerifierPolicyHMAC(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					return newVerifierPolicyVerifier(t, req, testFixedTime).VerifyHMAC(fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA256, secret), nil)
				},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.verify(); !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
					t.Fatalf("expected ErrInvalidSignatureAlgorithm, got %v", err)
				}
			})
		}
	})

	t.Run("unregistered and differently cased labels are rejected", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, false, []string{"date"}, testFixedTime)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey), nil,
		)
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected unregistered rsa-sha512 to be rejected, got %v", err)
		}

		req, publicKey = signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		req.Header.Set(sigre.Signature, replacePolicyAlgorithm(t, req.Header.Get(sigre.Signature), "HS2019"))
		err = newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey), nil,
		)
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected case-sensitive label rejection, got %v", err)
		}
	})

	t.Run("future created is rejected without compatibility skew", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime.Add(time.Second), 0)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey), nil,
		)
		if !errors.Is(err, sigre.ErrInvalidCreationTime) {
			t.Fatalf("expected ErrInvalidCreationTime, got %v", err)
		}
	})

	t.Run("past expires is rejected without compatibility skew", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created, sigre.Expires}, testFixedTime, 1)
		err := newVerifierPolicyVerifier(t, req, testFixedTime.Add(2*time.Second)).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey), nil,
		)
		if !errors.Is(err, sigre.ErrSignatureExpired) {
			t.Fatalf("expected ErrSignatureExpired, got %v", err)
		}
	})

	t.Run("old created is accepted when no maximum age is configured", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime, 0)
		err := newVerifierPolicyVerifier(t, req, testFixedTime.Add(24*time.Hour)).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey), nil,
		)
		if err != nil {
			t.Fatalf("zero value unexpectedly imposed a maximum age: %v", err)
		}
	})
}

func TestCavageVerifierAdditionalPolicies(t *testing.T) {
	t.Run("RequiredHeaders adds a requirement", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey),
			&sigre.CavageVerificationOptions{RequiredHeaders: []string{"digest"}},
		)
		if !errors.Is(err, sigre.ErrRequiredHeaderMissing) {
			t.Fatalf("expected ErrRequiredHeaderMissing, got %v", err)
		}
	})

	t.Run("AllowedAlgorithms only narrows the trusted algorithm", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey)
		verifier := newVerifierPolicyVerifier(t, req, testFixedTime)
		if err := verifier.Verify(key, &sigre.CavageVerificationOptions{
			AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA512},
		}); err != nil {
			t.Fatalf("permitted AlgorithmID failed: %v", err)
		}
		err := verifier.Verify(key, &sigre.CavageVerificationOptions{
			AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmECDSASHA512},
		})
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected ErrInvalidSignatureAlgorithm, got %v", err)
		}
	})

	t.Run("AllowedAlgorithms alone does not enable a legacy label", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, publicKey),
			&sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256}},
		)
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected ErrInvalidSignatureAlgorithm, got %v", err)
		}
	})

	t.Run("RequireAlgorithm rejects omission", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime, 0)
		req.Header.Set(sigre.Signature, removeQuotedPolicyParameter(t, req.Header.Get(sigre.Signature), "algorithm"))
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey),
			&sigre.CavageVerificationOptions{RequireAlgorithm: true},
		)
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected ErrInvalidSignatureAlgorithm, got %v", err)
		}
	})

	t.Run("RequireExplicitHeaders distinguishes omission", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime, 0)
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey)
		if err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(key, &sigre.CavageVerificationOptions{RequireExplicitHeaders: true}); err != nil {
			t.Fatalf("explicit headers were rejected: %v", err)
		}
		req.Header.Set(sigre.Signature, removeQuotedPolicyParameter(t, req.Header.Get(sigre.Signature), "headers"))
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(key, &sigre.CavageVerificationOptions{RequireExplicitHeaders: true})
		if !errors.Is(err, sigre.ErrRequiredHeaderMissing) {
			t.Fatalf("expected ErrRequiredHeaderMissing, got %v", err)
		}
	})

	t.Run("MaxSignatureAge has inclusive duration boundaries", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime, 0)
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey)
		tests := []struct {
			name    string
			age     time.Duration
			wantErr bool
		}{
			{name: "inside", age: time.Minute - time.Nanosecond},
			{name: "boundary", age: time.Minute},
			{name: "outside", age: time.Minute + time.Nanosecond, wantErr: true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := newVerifierPolicyVerifier(t, req, testFixedTime.Add(tc.age)).Verify(key, &sigre.CavageVerificationOptions{MaxSignatureAge: time.Minute})
				if tc.wantErr && !errors.Is(err, sigre.ErrInvalidCreationTime) {
					t.Fatalf("expected ErrInvalidCreationTime, got %v", err)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("boundary verification failed: %v", err)
				}
			})
		}
	})

	t.Run("MaxSignatureAge requires signed valid created", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey),
			&sigre.CavageVerificationOptions{MaxSignatureAge: time.Minute},
		)
		if !errors.Is(err, sigre.ErrRequiredHeaderMissing) {
			t.Fatalf("expected ErrRequiredHeaderMissing, got %v", err)
		}

		for _, tc := range []struct {
			name   string
			mutate func(string) string
		}{
			{name: "missing", mutate: func(value string) string { return removeTokenPolicyParameter(t, value, "created") }},
			{name: "invalid", mutate: func(value string) string { return replaceTokenPolicyParameter(t, value, "created", "invalid") }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				createdReq, edPublicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime, 0)
				createdReq.Header.Set(sigre.Signature, tc.mutate(createdReq.Header.Get(sigre.Signature)))
				err := newVerifierPolicyVerifier(t, createdReq, testFixedTime).Verify(
					fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, edPublicKey),
					&sigre.CavageVerificationOptions{MaxSignatureAge: time.Minute},
				)
				if !errors.Is(err, sigre.ErrInvalidCreationTime) {
					t.Fatalf("expected ErrInvalidCreationTime, got %v", err)
				}
			})
		}
	})

	t.Run("MaxDateAge checks past and future with inclusive boundaries", func(t *testing.T) {
		req, secret := signVerifierPolicyHMAC(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		key := fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret)
		tests := []struct {
			name    string
			now     time.Time
			wantErr bool
		}{
			{name: "past inside", now: testFixedTime.Add(time.Minute - time.Nanosecond)},
			{name: "past boundary", now: testFixedTime.Add(time.Minute)},
			{name: "past outside", now: testFixedTime.Add(time.Minute + time.Nanosecond), wantErr: true},
			{name: "future inside", now: testFixedTime.Add(-time.Minute + time.Nanosecond)},
			{name: "future boundary", now: testFixedTime.Add(-time.Minute)},
			{name: "future outside", now: testFixedTime.Add(-time.Minute - time.Nanosecond), wantErr: true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := newVerifierPolicyVerifier(t, req, tc.now).VerifyHMAC(key, &sigre.CavageVerificationOptions{MaxDateAge: time.Minute})
				if tc.wantErr && !errors.Is(err, sigre.ErrInvalidDate) {
					t.Fatalf("expected ErrInvalidDate, got %v", err)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("boundary verification failed: %v", err)
				}
			})
		}
	})

	t.Run("MaxDateAge requires one valid signed Date", func(t *testing.T) {
		edReq, edPublicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime, 0)
		err := newVerifierPolicyVerifier(t, edReq, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, edPublicKey),
			&sigre.CavageVerificationOptions{MaxDateAge: time.Minute},
		)
		if !errors.Is(err, sigre.ErrRequiredHeaderMissing) {
			t.Fatalf("expected ErrRequiredHeaderMissing, got %v", err)
		}

		for _, tc := range []struct {
			name   string
			mutate func(http.Header)
		}{
			{name: "missing", mutate: func(header http.Header) { header.Del("Date") }},
			{name: "multiple", mutate: func(header http.Header) { header.Add("Date", testFixedTime.Add(time.Second).Format(http.TimeFormat)) }},
			{name: "invalid", mutate: func(header http.Header) { header.Set("Date", "not-an-http-date") }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req, secret := signVerifierPolicyHMAC(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
				tc.mutate(req.Header)
				err := newVerifierPolicyVerifier(t, req, testFixedTime).VerifyHMAC(
					fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret),
					&sigre.CavageVerificationOptions{MaxDateAge: time.Minute},
				)
				if !errors.Is(err, sigre.ErrInvalidDate) {
					t.Fatalf("expected ErrInvalidDate, got %v", err)
				}
			})
		}
	})

	t.Run("negative durations are configuration errors", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey)
		tests := []struct {
			name string
			opts *sigre.CavageVerificationOptions
		}{
			{name: "MaxSignatureAge", opts: &sigre.CavageVerificationOptions{MaxSignatureAge: -time.Nanosecond}},
			{name: "MaxDateAge", opts: &sigre.CavageVerificationOptions{MaxDateAge: -time.Nanosecond}},
			{name: "AllowedCreatedFutureSkew", opts: &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{AllowedCreatedFutureSkew: -time.Nanosecond}}},
			{name: "AllowedExpiredSkew", opts: &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{AllowedExpiredSkew: -time.Nanosecond}}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(key, tc.opts)
				if !errors.Is(err, sigre.ErrInvalidVerificationOptions) {
					t.Fatalf("expected ErrInvalidVerificationOptions, got %v", err)
				}
			})
		}
	})
}

func TestCavageVerifierCompatibility(t *testing.T) {
	t.Run("deprecated SHA-256 labels require their matching explicit permission", func(t *testing.T) {
		tests := []struct {
			name      string
			algorithm sigre.AlgorithmID
			verify    func(*sigre.CavageVerificationOptions) error
		}{
			{
				name:      "rsa-sha256",
				algorithm: sigre.AlgorithmRSAPKCS1v15SHA256,
				verify: func(opts *sigre.CavageVerificationOptions) error {
					req, publicKey := signVerifierPolicyRSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
						fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, publicKey), opts,
					)
				},
			},
			{
				name:      "ecdsa-sha256",
				algorithm: sigre.AlgorithmECDSASHA256,
				verify: func(opts *sigre.CavageVerificationOptions) error {
					req, publicKey := signVerifierPolicyECDSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
						fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSASHA256, publicKey), opts,
					)
				},
			},
			{
				name:      "hmac-sha256",
				algorithm: sigre.AlgorithmHMACSHA256,
				verify: func(opts *sigre.CavageVerificationOptions) error {
					req, secret := signVerifierPolicyHMAC(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					return newVerifierPolicyVerifier(t, req, testFixedTime).VerifyHMAC(
						fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA256, secret), opts,
					)
				},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.verify(nil); !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
					t.Fatalf("expected strict rejection, got %v", err)
				}
				if err := tc.verify(legacyPolicyOptions(tc.algorithm)); err != nil {
					t.Fatalf("explicit legacy permission failed: %v", err)
				}
			})
		}
	})

	t.Run("omitted SHA-256 algorithms require their matching explicit legacy permission", func(t *testing.T) {
		tests := []struct {
			name           string
			algorithm      sigre.AlgorithmID
			otherAlgorithm sigre.AlgorithmID
			verify         func(*sigre.CavageVerificationOptions) error
		}{
			{
				name:           "RSA PKCS1 v1.5 SHA-256",
				algorithm:      sigre.AlgorithmRSAPKCS1v15SHA256,
				otherAlgorithm: sigre.AlgorithmECDSASHA256,
				verify: func(opts *sigre.CavageVerificationOptions) error {
					req, publicKey := signVerifierPolicyRSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					req.Header.Set(sigre.Signature, removeQuotedPolicyParameter(t, req.Header.Get(sigre.Signature), "algorithm"))
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
						fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, publicKey), opts,
					)
				},
			},
			{
				name:           "ECDSA SHA-256",
				algorithm:      sigre.AlgorithmECDSASHA256,
				otherAlgorithm: sigre.AlgorithmHMACSHA256,
				verify: func(opts *sigre.CavageVerificationOptions) error {
					req, publicKey := signVerifierPolicyECDSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					req.Header.Set(sigre.Signature, removeQuotedPolicyParameter(t, req.Header.Get(sigre.Signature), "algorithm"))
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
						fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSASHA256, publicKey), opts,
					)
				},
			},
			{
				name:           "HMAC SHA-256",
				algorithm:      sigre.AlgorithmHMACSHA256,
				otherAlgorithm: sigre.AlgorithmRSAPKCS1v15SHA256,
				verify: func(opts *sigre.CavageVerificationOptions) error {
					req, secret := signVerifierPolicyHMAC(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
					req.Header.Set(sigre.Signature, removeQuotedPolicyParameter(t, req.Header.Get(sigre.Signature), "algorithm"))
					return newVerifierPolicyVerifier(t, req, testFixedTime).VerifyHMAC(
						fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA256, secret), opts,
					)
				},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				for _, opts := range []*sigre.CavageVerificationOptions{
					nil,
					{},
					{AllowedAlgorithms: []sigre.AlgorithmID{tc.algorithm}},
					legacyPolicyOptions(tc.otherAlgorithm),
				} {
					if err := tc.verify(opts); !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
						t.Fatalf("expected ErrInvalidSignatureAlgorithm without matching legacy permission, got %v", err)
					}
				}
				if err := tc.verify(legacyPolicyOptions(tc.algorithm)); err != nil {
					t.Fatalf("matching legacy permission failed: %v", err)
				}
			})
		}
	})

	t.Run("legacy label and trusted AlgorithmID must agree", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey),
			legacyPolicyOptions(sigre.AlgorithmRSAPKCS1v15SHA256),
		)
		if !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected ErrAlgorithmMismatch, got %v", err)
		}
	})

	t.Run("AllowedAlgorithms additionally narrows legacy permission", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA256, false, []string{"date"}, testFixedTime)
		err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, publicKey),
			&sigre.CavageVerificationOptions{
				AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmECDSASHA256},
				Compatibility: &sigre.CavageVerificationCompatibility{
					AllowedLegacyAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256},
				},
			},
		)
		if !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected ErrInvalidSignatureAlgorithm, got %v", err)
		}
	})

	t.Run("deprecated family labels retain the created restriction", func(t *testing.T) {
		tests := []struct {
			name   string
			verify func() error
		}{
			{
				name: "rsa-sha256",
				verify: func() error {
					req, publicKey := signVerifierPolicyRSA(t, crypto.SHA256, true, []string{sigre.Created}, testFixedTime)
					req.Header.Set(sigre.Signature, replacePolicyAlgorithm(t, req.Header.Get(sigre.Signature), "rsa-sha256"))
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
						fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, publicKey),
						legacyPolicyOptions(sigre.AlgorithmRSAPKCS1v15SHA256),
					)
				},
			},
			{
				name: "ecdsa-sha256",
				verify: func() error {
					req, publicKey := signVerifierPolicyECDSA(t, crypto.SHA256, true, []string{sigre.Created}, testFixedTime)
					req.Header.Set(sigre.Signature, replacePolicyAlgorithm(t, req.Header.Get(sigre.Signature), "ecdsa-sha256"))
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
						fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSASHA256, publicKey),
						legacyPolicyOptions(sigre.AlgorithmECDSASHA256),
					)
				},
			},
			{
				name: "hmac-sha256",
				verify: func() error {
					req, secret := signVerifierPolicyHMAC(t, crypto.SHA256, true, []string{sigre.Created}, testFixedTime)
					req.Header.Set(sigre.Signature, replacePolicyAlgorithm(t, req.Header.Get(sigre.Signature), "hmac-sha256"))
					return newVerifierPolicyVerifier(t, req, testFixedTime).VerifyHMAC(
						fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA256, secret),
						legacyPolicyOptions(sigre.AlgorithmHMACSHA256),
					)
				},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.verify(); !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
					t.Fatalf("expected ErrInvalidSignatureAlgorithm, got %v", err)
				}
			})
		}
	})

	t.Run("extension label requires an exact label-to-AlgorithmID mapping", func(t *testing.T) {
		const extensionLabel = "vendor-rsa-sha512"
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		req.Header.Set(sigre.Signature, replacePolicyAlgorithm(t, req.Header.Get(sigre.Signature), extensionLabel))
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey)
		verifier := newVerifierPolicyVerifier(t, req, testFixedTime)

		if err := verifier.Verify(key, nil); !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
			t.Fatalf("expected unregistered label rejection, got %v", err)
		}
		if err := verifier.Verify(key, &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{
			ExtensionAlgorithms: map[string]sigre.AlgorithmID{extensionLabel: sigre.AlgorithmECDSASHA512},
		}}); !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected mapping mismatch rejection, got %v", err)
		}
		if err := verifier.Verify(key, &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{
			ExtensionAlgorithms: map[string]sigre.AlgorithmID{extensionLabel: sigre.AlgorithmRSAPKCS1v15SHA512},
		}}); err != nil {
			t.Fatalf("exact extension mapping failed: %v", err)
		}
	})

	t.Run("rsa-sha1 remains reserved for every implemented AlgorithmID", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey)
		for _, algorithm := range []sigre.AlgorithmID{
			sigre.AlgorithmRSAPKCS1v15SHA512,
			sigre.AlgorithmRSAPKCS1v15SHA256,
			sigre.AlgorithmECDSASHA512,
			sigre.AlgorithmECDSASHA256,
			sigre.AlgorithmEd25519,
			sigre.AlgorithmHMACSHA512,
			sigre.AlgorithmHMACSHA256,
		} {
			err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(key, &sigre.CavageVerificationOptions{
				Compatibility: &sigre.CavageVerificationCompatibility{
					ExtensionAlgorithms: map[string]sigre.AlgorithmID{"rsa-sha1": algorithm},
				},
			})
			if !errors.Is(err, sigre.ErrInvalidVerificationOptions) {
				t.Fatalf("expected ErrInvalidVerificationOptions for AlgorithmID %d, got %v", algorithm, err)
			}
		}
	})

	t.Run("extension map cannot override known labels or name unsupported algorithms", func(t *testing.T) {
		req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{"date"}, testFixedTime)
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey)
		tests := []struct {
			name       string
			extensions map[string]sigre.AlgorithmID
		}{
			{name: "hs2019 override", extensions: map[string]sigre.AlgorithmID{"hs2019": sigre.AlgorithmRSAPKCS1v15SHA512}},
			{name: "legacy override", extensions: map[string]sigre.AlgorithmID{"rsa-sha256": sigre.AlgorithmRSAPKCS1v15SHA512}},
			{name: "zero AlgorithmID", extensions: map[string]sigre.AlgorithmID{"vendor-zero": 0}},
			{name: "unsupported AlgorithmID", extensions: map[string]sigre.AlgorithmID{"vendor-unknown": 65535}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(key, &sigre.CavageVerificationOptions{
					Compatibility: &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: tc.extensions},
				})
				if !errors.Is(err, sigre.ErrInvalidVerificationOptions) {
					t.Fatalf("expected ErrInvalidVerificationOptions, got %v", err)
				}
			})
		}
	})

	t.Run("family-prefixed extensions retain the created restriction", func(t *testing.T) {
		tests := []struct {
			name   string
			verify func() error
		}{
			{
				name: "rsa extension",
				verify: func() error {
					const label = "rsa-vendor-sha512"
					req, publicKey := signVerifierPolicyRSA(t, crypto.SHA512, true, []string{sigre.Created}, testFixedTime)
					req.Header.Set(sigre.Signature, replacePolicyAlgorithm(t, req.Header.Get(sigre.Signature), label))
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
						fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, publicKey),
						&sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{
							ExtensionAlgorithms: map[string]sigre.AlgorithmID{label: sigre.AlgorithmRSAPKCS1v15SHA512},
						}},
					)
				},
			},
			{
				name: "ecdsa extension",
				verify: func() error {
					const label = "ecdsa-vendor-sha512"
					req, publicKey := signVerifierPolicyECDSA(t, crypto.SHA512, true, []string{sigre.Created}, testFixedTime)
					req.Header.Set(sigre.Signature, replacePolicyAlgorithm(t, req.Header.Get(sigre.Signature), label))
					return newVerifierPolicyVerifier(t, req, testFixedTime).Verify(
						fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSASHA512, publicKey),
						&sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{
							ExtensionAlgorithms: map[string]sigre.AlgorithmID{label: sigre.AlgorithmECDSASHA512},
						}},
					)
				},
			},
			{
				name: "hmac extension",
				verify: func() error {
					const label = "hmac-vendor-sha512"
					req, secret := signVerifierPolicyHMAC(t, crypto.SHA512, true, []string{sigre.Created}, testFixedTime)
					req.Header.Set(sigre.Signature, replacePolicyAlgorithm(t, req.Header.Get(sigre.Signature), label))
					return newVerifierPolicyVerifier(t, req, testFixedTime).VerifyHMAC(
						fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret),
						&sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{
							ExtensionAlgorithms: map[string]sigre.AlgorithmID{label: sigre.AlgorithmHMACSHA512},
						}},
					)
				},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.verify(); !errors.Is(err, sigre.ErrInvalidSignatureAlgorithm) {
					t.Fatalf("expected ErrInvalidSignatureAlgorithm, got %v", err)
				}
			})
		}
	})

	t.Run("Fediverse hs2019 SHA-256 relaxation is RSA-only", func(t *testing.T) {
		rsaReq, rsaPublicKey := signVerifierPolicyRSA(t, crypto.SHA256, true, []string{"date"}, testFixedTime)
		rsaKey := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, rsaPublicKey)
		if err := newVerifierPolicyVerifier(t, rsaReq, testFixedTime).Verify(rsaKey, nil); !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected strict RSA SHA-256 rejection, got %v", err)
		}
		fediverseOptions := &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{AllowHS2019WithSHA256: true}}
		if err := newVerifierPolicyVerifier(t, rsaReq, testFixedTime).Verify(rsaKey, fediverseOptions); err != nil {
			t.Fatalf("Fediverse RSA SHA-256 verification failed: %v", err)
		}

		ecdsaReq, ecdsaPublicKey := signVerifierPolicyECDSA(t, crypto.SHA256, true, []string{"date"}, testFixedTime)
		if err := newVerifierPolicyVerifier(t, ecdsaReq, testFixedTime).Verify(
			fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSASHA256, ecdsaPublicKey), fediverseOptions,
		); !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected ECDSA SHA-256 rejection, got %v", err)
		}

		hmacReq, secret := signVerifierPolicyHMAC(t, crypto.SHA256, true, []string{"date"}, testFixedTime)
		if err := newVerifierPolicyVerifier(t, hmacReq, testFixedTime).VerifyHMAC(
			fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA256, secret), fediverseOptions,
		); !errors.Is(err, sigre.ErrAlgorithmMismatch) {
			t.Fatalf("expected HMAC SHA-256 rejection, got %v", err)
		}
	})

	t.Run("AllowedCreatedFutureSkew has an inclusive exact-duration boundary", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created}, testFixedTime.Add(time.Second), 0)
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey)
		tests := []struct {
			name    string
			skew    time.Duration
			wantErr bool
		}{
			{name: "inside", skew: time.Second + time.Nanosecond},
			{name: "boundary", skew: time.Second},
			{name: "outside", skew: time.Second - time.Nanosecond, wantErr: true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := newVerifierPolicyVerifier(t, req, testFixedTime).Verify(key, &sigre.CavageVerificationOptions{
					Compatibility: &sigre.CavageVerificationCompatibility{AllowedCreatedFutureSkew: tc.skew},
				})
				if tc.wantErr && !errors.Is(err, sigre.ErrInvalidCreationTime) {
					t.Fatalf("expected ErrInvalidCreationTime, got %v", err)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("boundary verification failed: %v", err)
				}
			})
		}
	})

	t.Run("AllowedExpiredSkew has an inclusive exact-duration boundary", func(t *testing.T) {
		req, publicKey := signVerifierPolicyEd25519(t, true, []string{sigre.Created, sigre.Expires}, testFixedTime, 1)
		key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmEd25519, publicKey)
		now := testFixedTime.Add(2 * time.Second)
		tests := []struct {
			name    string
			skew    time.Duration
			wantErr bool
		}{
			{name: "inside", skew: time.Second + time.Nanosecond},
			{name: "boundary", skew: time.Second},
			{name: "outside", skew: time.Second - time.Nanosecond, wantErr: true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := newVerifierPolicyVerifier(t, req, now).Verify(key, &sigre.CavageVerificationOptions{
					Compatibility: &sigre.CavageVerificationCompatibility{AllowedExpiredSkew: tc.skew},
				})
				if tc.wantErr && !errors.Is(err, sigre.ErrSignatureExpired) {
					t.Fatalf("expected ErrSignatureExpired, got %v", err)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("boundary verification failed: %v", err)
				}
			})
		}
	})
}
