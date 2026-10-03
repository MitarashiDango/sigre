package sigre_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

const verifierPolicyKeyID = "policy-key"

func rawVerifierPolicyRequest(parameters string) *http.Request {
	return &http.Request{
		Method:     http.MethodPost,
		RequestURI: "/policy?fixed=1",
		URL:        &url.URL{Path: "/policy", RawQuery: "fixed=1"},
		Host:       "example.test",
		Header: http.Header{
			"Signature": {parameters},
			"X-Test":    {"test value"},
			"Date":      {time.Unix(100, 0).UTC().Format(http.TimeFormat)},
		},
	}
}

func verifierPolicyParameters(algorithm, headers, times string) string {
	value := `keyId="` + verifierPolicyKeyID + `",signature="c2ln"`
	if algorithm != "" {
		value += `,algorithm="` + algorithm + `"`
	}
	if headers != "" {
		value += `,headers="` + headers + `"`
	}
	return value + times
}

func parseVerifierPolicyRequest(req *http.Request, opts *sigre.CavageVerificationOptions) (*sigre.CavageVerifier, *sigre.CavageSignature, error) {
	verifier, err := sigre.NewCavageVerifier(opts)
	if err != nil {
		return nil, nil, err
	}
	signature, err := verifier.ParseRequest(req)
	return verifier, signature, err
}

func TestNewCavageVerifierValidationAndDeepCopy(t *testing.T) {
	invalid := []*sigre.CavageVerificationOptions{
		{RequestSignatureSource: 255},
		{RequiredHeaders: []string{"bad field"}},
		{RequiredHeaders: []string{"\u212A-foo"}},
		{RequiredHeaders: []string{"(exp\u0130res)"}},
		{AllowedAlgorithms: []sigre.AlgorithmID{0}},
		{MaxSignatureAge: -time.Nanosecond},
		{MaxDateAge: -time.Nanosecond},
		{Compatibility: &sigre.CavageVerificationCompatibility{AllowedCreatedFutureSkew: -time.Nanosecond}},
		{Compatibility: &sigre.CavageVerificationCompatibility{AllowedExpiredSkew: -time.Nanosecond}},
		{Compatibility: &sigre.CavageVerificationCompatibility{AllowedLegacyAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmEd25519}}},
		{Compatibility: &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: map[string]sigre.AlgorithmID{"": sigre.AlgorithmEd25519}}},
		{Compatibility: &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: map[string]sigre.AlgorithmID{"hs2019": sigre.AlgorithmEd25519}}},
		{Compatibility: &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: map[string]sigre.AlgorithmID{"rsa-sha1": sigre.AlgorithmEd25519}}},
		{Compatibility: &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: map[string]sigre.AlgorithmID{"ecdsa-sha256": sigre.AlgorithmEd25519}}},
		{Compatibility: &sigre.CavageVerificationCompatibility{AllowedLegacyAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256}}},
		{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmEd25519}, Compatibility: &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: map[string]sigre.AlgorithmID{"vendor-rsa512": sigre.AlgorithmRSAPKCS1v15SHA512}}},
		{Compatibility: &sigre.CavageVerificationCompatibility{AllowHS2019WithSHA256: true}},
	}
	for i, options := range invalid {
		if _, err := sigre.NewCavageVerifier(options); err == nil {
			t.Fatalf("invalid options case %d succeeded", i)
		} else {
			assertPackageError(t, err, sigre.ErrInvalidVerificationOptions)
		}
	}

	nowCalls := 0
	compatibility := &sigre.CavageVerificationCompatibility{
		AllowedCreatedFutureSkew: time.Second,
		AllowedLegacyAlgorithms:  []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256},
		ExtensionAlgorithms:      map[string]sigre.AlgorithmID{"vendor-rsa512": sigre.AlgorithmRSAPKCS1v15SHA512},
	}
	required := []string{"x-test"}
	allowed := []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA512, sigre.AlgorithmRSAPKCS1v15SHA256}
	options := &sigre.CavageVerificationOptions{
		RequiredHeaders:   required,
		AllowedAlgorithms: allowed,
		Now: func() time.Time {
			nowCalls++
			return time.Unix(100, 0)
		},
		Compatibility: compatibility,
	}
	verifier, err := sigre.NewCavageVerifier(options)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	if nowCalls != 0 {
		t.Fatalf("constructor called Now %d times", nowCalls)
	}

	options.RequestSignatureSource = sigre.CavageRequestSignatureSourceAuthorization
	required[0] = "missing"
	allowed[0] = sigre.AlgorithmRSAPKCS1v15SHA256
	compatibility.AllowedLegacyAlgorithms[0] = sigre.AlgorithmHMACSHA256
	compatibility.ExtensionAlgorithms["vendor-rsa512"] = sigre.AlgorithmECDSAASN1SHA512
	compatibility.AllowedCreatedFutureSkew = -time.Second

	req := rawVerifierPolicyRequest(verifierPolicyParameters("vendor-rsa512", "x-test", ""))
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		t.Fatalf("mutating options changed verifier behavior: %v", err)
	}
	if nowCalls != 0 {
		t.Fatalf("time-independent parse called Now %d times", nowCalls)
	}
	rsaPublicKey := fixedRSAPublicKey(t)
	err = verifier.Verify(signature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, rsaPublicKey))
	assertPackageError(t, err, sigre.ErrVerification)

	future := rawVerifierPolicyRequest(verifierPolicyParameters("hs2019", "(created) x-test", ",created=101"))
	if _, err := verifier.ParseRequest(future); err != nil {
		t.Fatalf("mutating Compatibility changed copied future skew: %v", err)
	}
	if nowCalls != 1 {
		t.Fatalf("time comparison called Now %d times, want 1", nowCalls)
	}
	legacy := rawVerifierPolicyRequest(verifierPolicyParameters("rsa-sha256", "x-test", ""))
	if _, err := verifier.ParseRequest(legacy); err != nil {
		t.Fatalf("mutating AllowedLegacyAlgorithms changed verifier behavior: %v", err)
	}
}

func TestCavageVerifierSnapshotIsImmutable(t *testing.T) {
	secret := []byte(testHMACSecret)
	now := time.Unix(100, 0).UTC()
	req := newTestRequest(t, http.MethodPost, "https://example.test/original?x=%2F", "")
	req.Host = "example.test"
	req.Header.Set("X-Test", "original")
	signer := &sigre.CavageSigner{Now: func() time.Time { return now }}
	if err := signer.SignRequestWithHMAC(
		req,
		fixedHMACSigningKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret),
		sigre.CavageSignaturePlacementSignature,
		&sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{
			ExactHeaders: []string{sigre.CavageRequestTarget, "host", "x-test"},
		}},
	); err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	req.RequestURI = req.URL.RequestURI()
	originalMethod := req.Method
	originalRequestURI := req.RequestURI
	originalHost := req.Host
	originalURL := *req.URL
	originalHeader := req.Header.Clone()
	verifier, signature, err := parseVerifierPolicyRequest(req, nil)
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	if req.Method != originalMethod || req.RequestURI != originalRequestURI || req.Host != originalHost || *req.URL != originalURL || !equalHTTPHeader(req.Header, originalHeader) {
		t.Fatal("ParseRequest() modified the request")
	}

	firstHeaders := signature.SignedHeaders()
	firstHeaders[0] = "changed"
	if slices.Equal(firstHeaders, signature.SignedHeaders()) {
		t.Fatal("SignedHeaders returned verifier-owned storage")
	}
	req.Method = http.MethodDelete
	req.RequestURI = "/changed"
	req.Host = "changed.example"
	req.URL.Path = "/changed-url"
	req.URL.RawQuery = "changed=true"
	req.Header.Set("X-Test", "changed")
	req.Header.Set(sigre.HeaderSignature, "malformed")
	if err := verifier.VerifyHMAC(signature, fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret)); err != nil {
		t.Fatalf("request mutation changed verification result: %v", err)
	}

	response := &http.Response{
		Request: &http.Request{Method: http.MethodGet, RequestURI: "/response?fixed=1", Host: "example.test", URL: &url.URL{Path: "/response", RawQuery: "fixed=1"}},
		Header:  make(http.Header),
	}
	response.Header.Set("X-Test", "response")
	response.Header.Set("Host", "response.example")
	if err := signer.SignResponseWithHMAC(
		response,
		fixedHMACSigningKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret),
		&sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{ExactHeaders: []string{sigre.CavageRequestTarget, "host", "x-test"}}},
	); err != nil {
		t.Fatalf("response signing failed: %v", err)
	}
	responseVerifier, err := sigre.NewCavageVerifier(nil)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	responseSignature, err := responseVerifier.ParseResponse(response)
	if err != nil {
		t.Fatalf("ParseResponse() failed: %v", err)
	}
	response.Header.Set("X-Test", "changed")
	response.Header.Set("Host", "changed-response.example")
	response.Request.Method = http.MethodDelete
	response.Request.RequestURI = "/changed"
	response.Request.Host = "changed.example"
	response.Request.URL.Path = "/changed-url"
	response.Request.URL.RawQuery = "changed=true"
	if err := responseVerifier.VerifyHMAC(responseSignature, fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret)); err != nil {
		t.Fatalf("response mutation changed verification result: %v", err)
	}
}

func equalHTTPHeader(left, right http.Header) bool {
	if len(left) != len(right) {
		return false
	}
	for name, values := range left {
		if !slices.Equal(values, right[name]) {
			return false
		}
	}
	return true
}

func TestCavageSignatureAccessors(t *testing.T) {
	nowCalls := 0
	params := verifierPolicyParameters("hs2019", "(created) (expires) x-test", ",created=100,expires=101.5")
	verifier, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{
		Now: func() time.Time {
			nowCalls++
			return time.Unix(100, 0)
		},
	})
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	_ = verifier
	if nowCalls != 1 {
		t.Fatalf("Now calls = %d, want 1", nowCalls)
	}
	if signature.KeyID() != verifierPolicyKeyID || signature.Placement() != sigre.CavageSignaturePlacementSignature {
		t.Fatalf("unexpected KeyID/Placement: %q/%d", signature.KeyID(), signature.Placement())
	}
	if label, ok := signature.AlgorithmLabel(); !ok || label != "hs2019" {
		t.Fatalf("AlgorithmLabel() = %q/%t", label, ok)
	}
	if created, ok := signature.Created(); !ok || !created.Equal(time.Unix(100, 0)) {
		t.Fatalf("Created() = %v/%t", created, ok)
	}
	if expires, ok := signature.Expires(); !ok || !expires.Equal(time.Unix(101, 500_000_000)) {
		t.Fatalf("Expires() = %v/%t", expires, ok)
	}
	if !signature.HeadersExplicit() || !slices.Equal(signature.SignedHeaders(), []string{sigre.CavageCreated, sigre.CavageExpires, "x-test"}) {
		t.Fatalf("unexpected signed headers: explicit=%t headers=%q", signature.HeadersExplicit(), signature.SignedHeaders())
	}

	omitted := rawVerifierPolicyRequest(verifierPolicyParameters("", "", ",created=100"))
	_, omittedSignature, err := parseVerifierPolicyRequest(omitted, &sigre.CavageVerificationOptions{Now: func() time.Time { return time.Unix(100, 0) }})
	if err != nil {
		t.Fatalf("omitted parameters failed: %v", err)
	}
	if _, ok := omittedSignature.AlgorithmLabel(); ok || omittedSignature.HeadersExplicit() || !slices.Equal(omittedSignature.SignedHeaders(), []string{sigre.CavageCreated}) {
		t.Fatalf("omitted accessor state is incorrect")
	}
}

func TestCavageVerifierParseRequestEnforcesHeaderRequirements(t *testing.T) {
	tests := []struct {
		name string
		opts *sigre.CavageVerificationOptions
	}{
		{name: "RequiredHeaders", opts: &sigre.CavageVerificationOptions{RequiredHeaders: []string{"digest"}}},
		{name: "RequireExplicitHeaders", opts: &sigre.CavageVerificationOptions{RequireExplicitHeaders: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := verifierPolicyParameters("", "", ",created=100")
			req := rawVerifierPolicyRequest(params)
			test.opts.Now = func() time.Time { return time.Unix(100, 0) }
			_, _, err := parseVerifierPolicyRequest(req, test.opts)
			assertPackageError(t, err, sigre.ErrRequiredHeaderMissing)
		})
	}
}

func TestCavageVerifierSignedHeaderMissing(t *testing.T) {
	req := rawVerifierPolicyRequest(verifierPolicyParameters("hs2019", "x-missing", ""))
	_, _, err := parseVerifierPolicyRequest(req, nil)
	assertPackageError(t, err, sigre.ErrSignedHeaderMissing)
}

func TestCavageVerifierTimeSyntaxAndBoundaries(t *testing.T) {
	createdInvalid := []string{
		"", "+1", "1.0", "1e3", "--1", "9223372036854775808", "-9223372036854775809",
		"9223371974719179008", "9223372036854775807",
	}
	for _, value := range createdInvalid {
		t.Run("created/"+value, func(t *testing.T) {
			params := verifierPolicyParameters("hs2019", "x-test", ",created="+value)
			if value == "" {
				params = verifierPolicyParameters("hs2019", "x-test", `,created=""`)
			}
			nowCalls := 0
			_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{Now: func() time.Time { nowCalls++; return time.Unix(0, 0) }})
			assertPackageError(t, err, sigre.ErrInvalidCreationTime)
			if nowCalls != 0 {
				t.Fatalf("invalid created called Now %d times", nowCalls)
			}
		})
	}

	expiresInvalid := []string{
		"", ".", "+1", ".5", "1.", "1e3", "1.2x000", "1. 000", "1.2\t000", "1.-000", "1.２000",
		"1.1234567891", "1.12345678910", "0.0000000001",
		"9223371974719179008", "9223372036854775807", "9223372036854775807.0000000000",
		"9223372036854775808", "9223372036854775808.0000000000",
		"-9223372036854775808.1", "-9223372036854775808.0000000010",
		"-9223372036854775809.0000000000", "18446744073709551616.0000000000",
	}
	for _, value := range expiresInvalid {
		t.Run("expires/"+value, func(t *testing.T) {
			parameter := `,expires="` + value + `"`
			nowCalls := 0
			params := verifierPolicyParameters("hs2019", "x-test", parameter)
			_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{Now: func() time.Time { nowCalls++; return time.Unix(0, 0) }})
			assertPackageError(t, err, sigre.ErrInvalidExpirationTime)
			if nowCalls != 0 {
				t.Fatalf("invalid expires called Now %d times", nowCalls)
			}
		})
	}
	for _, value := range []string{"1.1234567891", "9223372036854775808"} {
		t.Run("expires/bare/"+value, func(t *testing.T) {
			nowCalls := 0
			params := verifierPolicyParameters("hs2019", "x-test", ",expires="+value)
			_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{Now: func() time.Time { nowCalls++; return time.Unix(0, 0) }})
			assertPackageError(t, err, sigre.ErrInvalidExpirationTime)
			if nowCalls != 0 {
				t.Fatalf("invalid expires called Now %d times", nowCalls)
			}
		})
	}

	t.Run("missing signed created", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "(created) x-test", "")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), nil)
		assertPackageError(t, err, sigre.ErrInvalidCreationTime)
	})
	t.Run("missing signed expires", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "(expires) x-test", "")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), nil)
		assertPackageError(t, err, sigre.ErrInvalidExpirationTime)
	})
	t.Run("fractional expires inclusive boundary", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "(expires) x-test", ",expires=100.5")
		for _, test := range []struct {
			name    string
			now     time.Time
			wantErr error
		}{
			{name: "equal", now: time.Unix(100, 500_000_000)},
			{name: "outside", now: time.Unix(100, 500_000_001), wantErr: sigre.ErrSignatureExpired},
		} {
			t.Run(test.name, func(t *testing.T) {
				_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{Now: func() time.Time { return test.now }})
				if test.wantErr != nil {
					assertPackageError(t, err, test.wantErr)
				} else if err != nil {
					t.Fatalf("error = %v, want %v", err, test.wantErr)
				}
			})
		}
	})
	t.Run("negative fractional expires is exact", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "(expires) x-test", ",expires=-0.5")
		_, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{Now: func() time.Time { return time.Unix(-1, 500_000_000) }})
		if err != nil {
			t.Fatalf("ParseRequest() failed: %v", err)
		}
		expires, ok := signature.Expires()
		if !ok || !expires.Equal(time.Unix(-1, 500_000_000)) {
			t.Fatalf("Expires() = %v/%t", expires, ok)
		}
	})
	t.Run("supported second boundaries round trip", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			parameter string
			header    string
			now       time.Time
			read      func(*sigre.CavageSignature) (time.Time, bool)
		}{
			{name: "created minimum", parameter: ",created=-9223372036854775808", header: "(created) x-test", now: time.Unix(-1<<63, 0), read: (*sigre.CavageSignature).Created},
			{name: "created maximum", parameter: ",created=9223371974719179007", header: "(created) x-test", now: time.Unix(9223371974719179007, 0), read: (*sigre.CavageSignature).Created},
			{name: "expires minimum", parameter: ",expires=-9223372036854775808", header: "(expires) x-test", now: time.Unix(-1<<63, 0), read: (*sigre.CavageSignature).Expires},
			{name: "expires maximum", parameter: ",expires=9223371974719179007", header: "(expires) x-test", now: time.Unix(9223371974719179007, 0), read: (*sigre.CavageSignature).Expires},
		} {
			t.Run(test.name, func(t *testing.T) {
				params := verifierPolicyParameters("hs2019", test.header, test.parameter)
				_, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{Now: func() time.Time { return test.now }})
				if err != nil {
					t.Fatalf("ParseRequest() failed: %v", err)
				}
				got, ok := test.read(signature)
				if !ok || got.Unix() != test.now.Unix() || got.Nanosecond() != 0 {
					t.Fatalf("parsed time = %v/%t, want %v", got, ok, test.now)
				}
			})
		}
	})
	t.Run("extreme time comparisons", func(t *testing.T) {
		now := time.Unix(0, 0)
		createdMaximum := verifierPolicyParameters("hs2019", "(created) x-test", ",created=9223371974719179007")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(createdMaximum), &sigre.CavageVerificationOptions{
			Now: func() time.Time { return now },
		})
		assertPackageError(t, err, sigre.ErrInvalidCreationTime)

		expiresMaximum := verifierPolicyParameters("hs2019", "(expires) x-test", ",expires=9223371974719179007")
		_, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(expiresMaximum), &sigre.CavageVerificationOptions{
			Now: func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("maximum expires was treated as expired: %v", err)
		}
		expires, present := signature.Expires()
		if !present || !expires.After(now) {
			t.Fatalf("Expires() = %v/%t, want a time after %v", expires, present, now)
		}

		oldCreated := verifierPolicyParameters("hs2019", "(created) x-test", ",created=0")
		maximumAge := time.Duration(1<<63 - 1)
		maximumAgeBoundary := time.Unix(int64(maximumAge/time.Second), int64(maximumAge%time.Second))
		if _, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(oldCreated), &sigre.CavageVerificationOptions{
			MaxSignatureAge: maximumAge,
			Now:             func() time.Time { return maximumAgeBoundary },
		}); err != nil {
			t.Fatalf("maximum signature age boundary failed: %v", err)
		}
		_, _, err = parseVerifierPolicyRequest(rawVerifierPolicyRequest(oldCreated), &sigre.CavageVerificationOptions{
			MaxSignatureAge: maximumAge,
			Now:             func() time.Time { return time.Unix(10_000_000_000, 0) },
		})
		assertPackageError(t, err, sigre.ErrInvalidCreationTime)
	})
	t.Run("inclusive created age and skew", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "(created) x-test", ",created=100")
		options := &sigre.CavageVerificationOptions{
			MaxSignatureAge: time.Second,
			Now:             func() time.Time { return time.Unix(101, 0) },
		}
		if _, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), options); err != nil {
			t.Fatalf("age boundary failed: %v", err)
		}
		options.Now = func() time.Time { return time.Unix(101, 1) }
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), options)
		assertPackageError(t, err, sigre.ErrInvalidCreationTime)

		future := verifierPolicyParameters("hs2019", "(created) x-test", ",created=101")
		options = &sigre.CavageVerificationOptions{
			Now: func() time.Time { return time.Unix(100, 0) },
			Compatibility: &sigre.CavageVerificationCompatibility{
				AllowedCreatedFutureSkew: time.Second,
			},
		}
		if _, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(future), options); err != nil {
			t.Fatalf("future skew boundary failed: %v", err)
		}
	})
	t.Run("inclusive Date age", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "date x-test", "")
		req := rawVerifierPolicyRequest(params)
		options := &sigre.CavageVerificationOptions{MaxDateAge: time.Second, Now: func() time.Time { return time.Unix(101, 0) }}
		if _, _, err := parseVerifierPolicyRequest(req, options); err != nil {
			t.Fatalf("Date boundary failed: %v", err)
		}
		options.Now = func() time.Time { return time.Unix(101, 1) }
		_, _, err := parseVerifierPolicyRequest(req, options)
		assertPackageError(t, err, sigre.ErrInvalidDate)
	})
	t.Run("Date count and syntax fail before reading Now", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			values []string
		}{
			{name: "missing"},
			{name: "multiple", values: []string{time.Unix(100, 0).UTC().Format(http.TimeFormat), time.Unix(100, 0).UTC().Format(http.TimeFormat)}},
			{name: "invalid", values: []string{"not a date"}},
		} {
			t.Run(test.name, func(t *testing.T) {
				req := rawVerifierPolicyRequest(verifierPolicyParameters("hs2019", "date x-test", ""))
				req.Header["Date"] = test.values
				nowCalls := 0
				_, _, err := parseVerifierPolicyRequest(req, &sigre.CavageVerificationOptions{
					MaxDateAge: time.Second,
					Now:        func() time.Time { nowCalls++; return time.Unix(100, 0) },
				})
				assertPackageError(t, err, sigre.ErrInvalidDate)
				if nowCalls != 0 {
					t.Fatalf("invalid Date called Now %d times", nowCalls)
				}
			})
		}
	})
}

func TestCavageVerifierTimeAdditionAtUpperLimit(t *testing.T) {
	for _, test := range []struct {
		name               string
		parameter          string
		header             string
		maxSignatureAge    time.Duration
		allowedExpiredSkew time.Duration
	}{
		{
			name:               "expires with fractional carry",
			parameter:          ",expires=9223371974719179007.9",
			header:             "(expires) x-test",
			allowedExpiredSkew: 500 * time.Millisecond,
		},
		{
			name:               "expires with whole second overflow",
			parameter:          ",expires=9223371974719179006.9",
			header:             "(expires) x-test",
			allowedExpiredSkew: 1500 * time.Millisecond,
		},
		{
			name:            "created age overflow",
			parameter:       ",created=9223371974719179007",
			header:          "(created) x-test",
			maxSignatureAge: time.Second,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			nowCalls := 0
			params := verifierPolicyParameters("hs2019", test.header, test.parameter)
			_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{
				MaxSignatureAge: test.maxSignatureAge,
				Now: func() time.Time {
					nowCalls++
					return time.Unix(9223371974719179007, 500_000_000)
				},
				Compatibility: &sigre.CavageVerificationCompatibility{
					AllowedExpiredSkew: test.allowedExpiredSkew,
				},
			})
			if nowCalls != 1 {
				t.Errorf("Now calls = %d, want 1", nowCalls)
			}
			if err != nil {
				t.Fatalf("ParseRequest() failed: %v", err)
			}
		})
	}
}

func TestCavageVerifierNowCallContract(t *testing.T) {
	t.Run("constructor and early failures do not call Now", func(t *testing.T) {
		calls := 0
		verifier, err := sigre.NewCavageVerifier(&sigre.CavageVerificationOptions{Now: func() time.Time { calls++; return time.Unix(100, 0) }})
		if err != nil {
			t.Fatalf("NewCavageVerifier() failed: %v", err)
		}
		if calls != 0 {
			t.Fatalf("constructor called Now %d times", calls)
		}
		if _, err := verifier.ParseRequest(nil); !errors.Is(err, sigre.ErrInvalidHTTPMessage) {
			t.Fatalf("ParseRequest(nil) error = %v", err)
		}
		if _, err := verifier.ParseRequest(&http.Request{}); !errors.Is(err, sigre.ErrMissingSignature) {
			t.Fatalf("missing signature error = %v", err)
		}
		bad := rawVerifierPolicyRequest(`keyId="key"`)
		if _, err := verifier.ParseRequest(bad); !errors.Is(err, sigre.ErrInvalidSignatureParameters) {
			t.Fatalf("parameter error = %v", err)
		}
		if calls != 0 {
			t.Fatalf("early failures called Now %d times", calls)
		}
	})

	t.Run("all time comparisons share one call and Verify uses none", func(t *testing.T) {
		calls := 0
		now := time.Unix(100, 0).UTC()
		params := verifierPolicyParameters("hs2019", "(created) (expires) date x-test", ",created=100,expires=101")
		req := rawVerifierPolicyRequest(params)
		options := &sigre.CavageVerificationOptions{
			MaxSignatureAge: time.Second,
			MaxDateAge:      time.Second,
			Now: func() time.Time {
				calls++
				return now
			},
		}
		verifier, signature, err := parseVerifierPolicyRequest(req, options)
		if err != nil {
			t.Fatalf("ParseRequest() failed: %v", err)
		}
		if calls != 1 {
			t.Fatalf("ParseRequest() called Now %d times, want 1", calls)
		}
		err = verifier.VerifyHMAC(signature, fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, []byte("secret")))
		assertPackageError(t, err, sigre.ErrVerification)
		if calls != 1 {
			t.Fatalf("VerifyHMAC() called Now; total calls = %d", calls)
		}
	})

	t.Run("time-independent parse does not call Now", func(t *testing.T) {
		calls := 0
		params := verifierPolicyParameters("hs2019", "x-test", "")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{Now: func() time.Time { calls++; return time.Now() }})
		if err != nil {
			t.Fatalf("ParseRequest() failed: %v", err)
		}
		if calls != 0 {
			t.Fatalf("time-independent parse called Now %d times", calls)
		}
	})
}

func TestCavageVerifierAlgorithmPolicy(t *testing.T) {
	rsaPublicKey := fixedRSAPublicKey(t)
	rsa256Key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA256, rsaPublicKey)
	rsa512Key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, rsaPublicKey)

	tests := []struct {
		name       string
		algorithm  string
		opts       *sigre.CavageVerificationOptions
		key        sigre.VerificationKey
		parseError error
		verifyErr  error
	}{
		{name: "strict hs2019 SHA-512", algorithm: "hs2019", key: rsa512Key, verifyErr: sigre.ErrVerification},
		{name: "non-empty allowed set replaces defaults", algorithm: "hs2019", opts: &sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmEd25519}}, key: rsa512Key, verifyErr: sigre.ErrInvalidSignatureAlgorithm},
		{name: "label is case-sensitive", algorithm: "HS2019", key: rsa512Key, parseError: sigre.ErrInvalidSignatureAlgorithm},
		{name: "legacy label disabled", algorithm: "rsa-sha256", key: rsa256Key, parseError: sigre.ErrInvalidSignatureAlgorithm},
		{
			name:      "legacy exact permission",
			algorithm: "rsa-sha256",
			opts:      &sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256}, Compatibility: &sigre.CavageVerificationCompatibility{AllowedLegacyAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256}}},
			key:       rsa256Key,
			verifyErr: sigre.ErrVerification,
		},
		{
			name:       "hs2019 SHA-256 requires explicit exception during parsing",
			algorithm:  "hs2019",
			opts:       &sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256}},
			parseError: sigre.ErrInvalidSignatureAlgorithm,
		},
		{
			name:      "hs2019 SHA-256 requires explicit exception for trusted key",
			algorithm: "hs2019",
			opts:      &sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256, sigre.AlgorithmRSAPKCS1v15SHA512}},
			key:       rsa256Key,
			verifyErr: sigre.ErrAlgorithmMismatch,
		},
		{
			name:      "hs2019 SHA-256 explicit exception",
			algorithm: "hs2019",
			opts:      &sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256}, Compatibility: &sigre.CavageVerificationCompatibility{AllowHS2019WithSHA256: true}},
			key:       rsa256Key,
			verifyErr: sigre.ErrVerification,
		},
		{
			name:      "extension exact mapping",
			algorithm: "vendor-rsa512",
			opts:      &sigre.CavageVerificationOptions{Compatibility: &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: map[string]sigre.AlgorithmID{"vendor-rsa512": sigre.AlgorithmRSAPKCS1v15SHA512}}},
			key:       rsa512Key,
			verifyErr: sigre.ErrVerification,
		},
		{
			name:      "extension mapping mismatch",
			algorithm: "vendor-rsa512",
			opts:      &sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256, sigre.AlgorithmRSAPKCS1v15SHA512}, Compatibility: &sigre.CavageVerificationCompatibility{ExtensionAlgorithms: map[string]sigre.AlgorithmID{"vendor-rsa512": sigre.AlgorithmRSAPKCS1v15SHA512}}},
			key:       rsa256Key,
			verifyErr: sigre.ErrAlgorithmMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := verifierPolicyParameters(test.algorithm, "x-test", "")
			verifier, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), test.opts)
			if test.parseError != nil {
				assertPackageError(t, err, test.parseError)
				return
			}
			if err != nil {
				t.Fatalf("ParseRequest() failed: %v", err)
			}
			err = verifier.Verify(signature, test.key)
			assertPackageError(t, err, test.verifyErr)
		})
	}

	t.Run("legacy label rejects created pseudo-header", func(t *testing.T) {
		params := verifierPolicyParameters("rsa-sha256", "(request-target) (created)", ",created=1")
		options := &sigre.CavageVerificationOptions{
			AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256},
			Compatibility: &sigre.CavageVerificationCompatibility{
				AllowedLegacyAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256},
			},
		}
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), options)
		assertPackageError(t, err, sigre.ErrInvalidSignatureAlgorithm)
	})

	t.Run("omitted algorithm accepts explicitly allowed SHA-256", func(t *testing.T) {
		params := verifierPolicyParameters("", "x-test", "")
		options := &sigre.CavageVerificationOptions{AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256}}
		verifier, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), options)
		if err != nil {
			t.Fatalf("ParseRequest() failed: %v", err)
		}
		err = verifier.Verify(signature, rsa256Key)
		assertPackageError(t, err, sigre.ErrVerification)
	})
	t.Run("RequireAlgorithm controls omission", func(t *testing.T) {
		params := verifierPolicyParameters("", "x-test", "")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{RequireAlgorithm: true})
		assertPackageError(t, err, sigre.ErrInvalidSignatureAlgorithm)
	})
}

func TestCavageVerifierVerifyPriorityAndOwnership(t *testing.T) {
	params := verifierPolicyParameters("hs2019", "x-test", "")
	verifier, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), nil)
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	rsaPublicKey := fixedRSAPublicKey(t)
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	var zeroVerifier sigre.CavageVerifier
	assertPackageError(t, zeroVerifier.Verify(signature, sigre.VerificationKey{}), sigre.ErrInvalidVerificationOptions)
	var nilVerifier *sigre.CavageVerifier
	assertPackageError(t, nilVerifier.Verify(signature, sigre.VerificationKey{}), sigre.ErrInvalidVerificationOptions)
	assertPackageError(t, verifier.Verify(nil, sigre.VerificationKey{}), sigre.ErrInvalidHTTPMessage)
	assertPackageError(t, verifier.Verify(&sigre.CavageSignature{}, sigre.VerificationKey{}), sigre.ErrInvalidHTTPMessage)
	otherVerifier, err := sigre.NewCavageVerifier(nil)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	assertPackageError(t, otherVerifier.Verify(signature, sigre.VerificationKey{}), sigre.ErrInvalidHTTPMessage)

	assertPackageError(t, verifier.Verify(signature, sigre.VerificationKey{}), sigre.ErrInvalidKeyMetadata)
	assertPackageError(t, verifier.Verify(signature, fixedPublicVerificationKey("wrong", sigre.AlgorithmRSAPKCS1v15SHA512, nil)), sigre.ErrKeyIDMismatch)
	assertPackageError(t, verifier.Verify(signature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, nil)), sigre.ErrMissingPublicKey)
	assertPackageError(t, verifier.Verify(signature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, nil)), sigre.ErrMissingPublicKey)
	assertPackageError(t, verifier.Verify(signature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, rsaPublicKey)), sigre.ErrAlgorithmMismatch)
	assertPackageError(t, verifier.Verify(signature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, &ecdsaPrivateKey.PublicKey)), sigre.ErrAlgorithmMismatch)

	var nilEd25519PublicKey ed25519.PublicKey
	emptyEd25519PublicKey := ed25519.PublicKey{}
	invalidEd25519PublicKey := make(ed25519.PublicKey, ed25519.PublicKeySize-1)
	for _, tt := range []struct {
		name      string
		algorithm sigre.AlgorithmID
		publicKey *ed25519.PublicKey
		wantErr   error
	}{
		{name: "nil Ed25519 public key pointer", algorithm: sigre.AlgorithmEd25519, wantErr: sigre.ErrMissingPublicKey},
		{name: "pointer to nil Ed25519 public key", algorithm: sigre.AlgorithmEd25519, publicKey: &nilEd25519PublicKey, wantErr: sigre.ErrMissingPublicKey},
		{name: "pointer to empty Ed25519 public key", algorithm: sigre.AlgorithmEd25519, publicKey: &emptyEd25519PublicKey, wantErr: sigre.ErrMissingPublicKey},
		{name: "pointer to invalid length Ed25519 public key", algorithm: sigre.AlgorithmEd25519, publicKey: &invalidEd25519PublicKey, wantErr: sigre.ErrUnsupportedKeyFormat},
		{name: "nil Ed25519 public key pointer with HMAC AlgorithmID", algorithm: sigre.AlgorithmHMACSHA512, wantErr: sigre.ErrMissingPublicKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := fixedPublicVerificationKey(verifierPolicyKeyID, tt.algorithm, tt.publicKey)
			assertPackageError(t, verifier.Verify(signature, key), tt.wantErr)
		})
	}

	restrictedVerifier, restrictedSignature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{
		AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmEd25519},
	})
	if err != nil {
		t.Fatalf("restricted ParseRequest() failed: %v", err)
	}
	assertPackageError(t, restrictedVerifier.Verify(restrictedSignature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, &ecdsaPrivateKey.PublicKey)), sigre.ErrAlgorithmMismatch)
	assertPackageError(t, restrictedVerifier.Verify(restrictedSignature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, &rsa.PublicKey{})), sigre.ErrUnsupportedKeyFormat)
	assertPackageError(t, restrictedVerifier.Verify(restrictedSignature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, rsaPublicKey)), sigre.ErrInvalidSignatureAlgorithm)

	customParams := *elliptic.P256().Params()
	customParams.Name = "custom-P256"
	for _, tt := range []struct {
		name string
		key  *ecdsa.PublicKey
	}{
		{name: "ECDSA point off curve", key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}},
		{name: "ECDSA nil Curve", key: &ecdsa.PublicKey{X: ecdsaPrivateKey.X, Y: ecdsaPrivateKey.Y}},
		{name: "ECDSA nil X", key: &ecdsa.PublicKey{Curve: elliptic.P256(), Y: ecdsaPrivateKey.Y}},
		{name: "ECDSA nil Y", key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: ecdsaPrivateKey.X}},
		{name: "ECDSA custom curve", key: &ecdsa.PublicKey{Curve: &customParams, X: ecdsaPrivateKey.X, Y: ecdsaPrivateKey.Y}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSAASN1SHA512, tt.key)
			assertPackageError(t, verifier.Verify(signature, key), sigre.ErrUnsupportedKeyFormat)
			assertPackageError(t, restrictedVerifier.Verify(restrictedSignature, key), sigre.ErrUnsupportedKeyFormat)
		})
	}

	t.Run("ECDSA signature with another public key", func(t *testing.T) {
		req := newSignerPolicyRequest(t)
		signer := &sigre.CavageSigner{Now: func() time.Time { return testFixedTime }}
		if err := signer.SignRequest(req, fixedSigningKey(verifierPolicyKeyID, sigre.AlgorithmECDSAASN1SHA512, ecdsaPrivateKey), sigre.CavageSignaturePlacementSignature, nil); err != nil {
			t.Fatalf("SignRequest() failed: %v", err)
		}
		req.RequestURI = req.URL.RequestURI()
		ecdsaVerifier, ecdsaSignature := parseSignerPolicyRequest(t, req, testFixedTime, nil)
		if err := ecdsaVerifier.Verify(ecdsaSignature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSAASN1SHA512, &ecdsaPrivateKey.PublicKey)); err != nil {
			t.Fatalf("Verify() with the signing key failed: %v", err)
		}
		otherPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate another ECDSA key: %v", err)
		}
		err = ecdsaVerifier.Verify(ecdsaSignature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmECDSAASN1SHA512, &otherPrivateKey.PublicKey))
		assertPackageError(t, err, sigre.ErrVerification)
	})

	hmacVerifier, hmacSignature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), nil)
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	assertPackageError(t, hmacVerifier.VerifyHMAC(hmacSignature, sigre.HMACVerificationKey{}), sigre.ErrInvalidKeyMetadata)
	assertPackageError(t, hmacVerifier.VerifyHMAC(hmacSignature, fixedHMACVerificationKey("wrong", sigre.AlgorithmHMACSHA512, nil)), sigre.ErrKeyIDMismatch)
	assertPackageError(t, hmacVerifier.VerifyHMAC(hmacSignature, fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, nil)), sigre.ErrMissingSharedSecret)
	assertPackageError(t, hmacVerifier.VerifyHMAC(hmacSignature, fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, nil)), sigre.ErrMissingSharedSecret)
}

func TestCavageVerifierErrorPriority(t *testing.T) {
	t.Run("constructor before nil message", func(t *testing.T) {
		var verifier sigre.CavageVerifier
		_, err := verifier.ParseRequest(nil)
		assertPackageError(t, err, sigre.ErrInvalidVerificationOptions)
		var nilVerifier *sigre.CavageVerifier
		_, err = nilVerifier.ParseResponse(nil)
		assertPackageError(t, err, sigre.ErrInvalidVerificationOptions)
	})
	t.Run("source conflict before malformed parameters", func(t *testing.T) {
		verifier, err := sigre.NewCavageVerifier(&sigre.CavageVerificationOptions{RequestSignatureSource: sigre.CavageRequestSignatureSourceSignatureOrAuthorization})
		if err != nil {
			t.Fatal(err)
		}
		req := rawVerifierPolicyRequest("malformed")
		req.Header.Set(sigre.HeaderAuthorization, "Signature malformed")
		_, err = verifier.ParseRequest(req)
		assertPackageError(t, err, sigre.ErrSignatureSourceConflict)
	})
	t.Run("created syntax before expires syntax", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "x-test", ",created=bad,expires=bad")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), nil)
		assertPackageError(t, err, sigre.ErrInvalidCreationTime)
	})
	t.Run("required header before missing pseudo parameter", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "(created) x-test", "")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{RequiredHeaders: []string{"digest"}})
		assertPackageError(t, err, sigre.ErrRequiredHeaderMissing)
	})
	t.Run("pseudo parameter before algorithm", func(t *testing.T) {
		params := verifierPolicyParameters("invalid", "(created) x-test", "")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), nil)
		assertPackageError(t, err, sigre.ErrInvalidCreationTime)
	})
	t.Run("algorithm before signed header", func(t *testing.T) {
		params := verifierPolicyParameters("invalid", "x-missing", "")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), nil)
		assertPackageError(t, err, sigre.ErrInvalidSignatureAlgorithm)
	})
	t.Run("signed header before HTTP message", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "x-missing (request-target)", "")
		req := rawVerifierPolicyRequest(params)
		req.Method = ""
		req.RequestURI = ""
		_, _, err := parseVerifierPolicyRequest(req, nil)
		assertPackageError(t, err, sigre.ErrSignedHeaderMissing)
	})
	t.Run("missing Date before missing signed header", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "x-missing date", "")
		req := rawVerifierPolicyRequest(params)
		req.Header.Del("Date")
		_, _, err := parseVerifierPolicyRequest(req, &sigre.CavageVerificationOptions{MaxDateAge: time.Second})
		assertPackageError(t, err, sigre.ErrInvalidDate)
	})
	t.Run("multiple Date values before missing signed header", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "x-missing date", "")
		req := rawVerifierPolicyRequest(params)
		req.Header.Add("Date", req.Header.Get("Date"))
		_, _, err := parseVerifierPolicyRequest(req, &sigre.CavageVerificationOptions{MaxDateAge: time.Second})
		assertPackageError(t, err, sigre.ErrInvalidDate)
	})
	t.Run("missing Date with MaxDateAge disabled", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "date", "")
		req := rawVerifierPolicyRequest(params)
		req.Header.Del("Date")
		_, _, err := parseVerifierPolicyRequest(req, &sigre.CavageVerificationOptions{MaxDateAge: 0})
		assertPackageError(t, err, sigre.ErrSignedHeaderMissing)
	})
	t.Run("Date syntax before HTTP message", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "(request-target) date", "")
		req := rawVerifierPolicyRequest(params)
		req.Method = ""
		req.Header.Set("Date", "invalid")
		_, _, err := parseVerifierPolicyRequest(req, &sigre.CavageVerificationOptions{MaxDateAge: time.Second})
		assertPackageError(t, err, sigre.ErrInvalidDate)
	})
	t.Run("Date syntax before created policy", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "date x-test", ",created=101")
		req := rawVerifierPolicyRequest(params)
		req.Header.Set("Date", "invalid")
		_, _, err := parseVerifierPolicyRequest(req, &sigre.CavageVerificationOptions{MaxDateAge: time.Second, Now: func() time.Time { return time.Unix(100, 0) }})
		assertPackageError(t, err, sigre.ErrInvalidDate)
	})
	t.Run("created policy before expiration", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "x-test", ",created=101,expires=99")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{Now: func() time.Time { return time.Unix(100, 0) }})
		assertPackageError(t, err, sigre.ErrInvalidCreationTime)
	})
	t.Run("expiration before Date range", func(t *testing.T) {
		params := verifierPolicyParameters("hs2019", "(expires) date x-test", ",expires=199")
		_, _, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{
			MaxDateAge: time.Second,
			Now:        func() time.Time { return time.Unix(200, 0) },
		})
		assertPackageError(t, err, sigre.ErrSignatureExpired)
	})
}

func TestCavageVerifierExpiresDecimalPrecision(t *testing.T) {
	for _, test := range []struct {
		value       string
		seconds     int64
		nanoseconds int
	}{
		{value: "1.1234567890", seconds: 1, nanoseconds: 123456789},
		{value: "1.123456789000", seconds: 1, nanoseconds: 123456789},
		{value: "0.0000000010", nanoseconds: 1},
		{value: "1.0000000000", seconds: 1},
		{value: "0"},
		{value: "0.0000000000"},
		{value: "-0.0000000000"},
		{value: "-0.0000000010", seconds: -1, nanoseconds: 999999999},
		{value: "-1.1234567890", seconds: -2, nanoseconds: 876543211},
		{value: "9223371974719179007.0000000000", seconds: 9223371974719179007},
		{value: "9223371974719179007.5", seconds: 9223371974719179007, nanoseconds: 500000000},
		{value: "-9223372036854775808.0000000000", seconds: -1 << 63},
		{value: "-9223372036854775807.9999999990", seconds: -1 << 63, nanoseconds: 1},
	} {
		t.Run(test.value, func(t *testing.T) {
			params := verifierPolicyParameters("hs2019", "(expires)", ",expires="+test.value)
			_, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{
				Now: func() time.Time { return time.Unix(test.seconds, int64(test.nanoseconds)) },
			})
			if err != nil {
				t.Fatalf("ParseRequest() failed: %v", err)
			}
			expires, present := signature.Expires()
			if !present || expires.Unix() != test.seconds || expires.Nanosecond() != test.nanoseconds {
				t.Fatalf("Expires() = (%d, %d)/%t, want (%d, %d)/true", expires.Unix(), expires.Nanosecond(), present, test.seconds, test.nanoseconds)
			}
		})
	}
}

func TestCavageVerifierExpiresDecimalBoundary(t *testing.T) {
	for _, value := range []string{"1.123456789", "1.1234567890"} {
		for _, headers := range []string{"(expires)", "x-test"} {
			for _, test := range []struct {
				name    string
				now     time.Time
				wantErr error
			}{
				{name: "before", now: time.Unix(1, 123456788)},
				{name: "equal", now: time.Unix(1, 123456789)},
				{name: "after", now: time.Unix(1, 123456790), wantErr: sigre.ErrSignatureExpired},
			} {
				t.Run(value+"/"+headers+"/"+test.name, func(t *testing.T) {
					params := verifierPolicyParameters("hs2019", headers, ",expires="+value)
					_, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), &sigre.CavageVerificationOptions{
						Now: func() time.Time { return test.now },
					})
					if test.wantErr != nil {
						assertPackageError(t, err, test.wantErr)
						return
					}
					if err != nil {
						t.Fatalf("ParseRequest() failed: %v", err)
					}
					expires, present := signature.Expires()
					if !present || !expires.Equal(time.Unix(1, 123456789)) {
						t.Fatalf("Expires() = %v/%t, want %v/true", expires, present, time.Unix(1, 123456789))
					}
				})
			}
		}
	}
}

func FuzzCavageVerifierParseRequest(f *testing.F) {
	f.Add(`keyId="key",signature="c2ln",algorithm="hs2019",headers="x-test"`)
	f.Add(`keyId="key",signature="not-base64"`)
	f.Add(`keyId="key",signature="c2ln",algorithm="hs2019",headers="(expires)",expires=1.1234567890`)
	f.Add(`keyId="key",signature="c2ln",algorithm="hs2019",headers="x-test",expires=-0.0000000000`)
	f.Add(`keyId="key",signature="c2ln",algorithm="hs2019",headers="x-test",expires=1.12345678910`)
	f.Add("")
	f.Fuzz(func(t *testing.T, parameters string) {
		verifier, err := sigre.NewCavageVerifier(nil)
		if err != nil {
			t.Fatalf("NewCavageVerifier() failed: %v", err)
		}
		req := rawVerifierPolicyRequest(parameters)
		_, err = verifier.ParseRequest(req)
		if err != nil {
			var packageError *sigre.Error
			if !errors.As(err, &packageError) {
				t.Fatalf("ParseRequest() returned an unwrapped error: %v", err)
			}
		}
	})
}

func TestCavageVerifierRejectsInvalidRSAFormat(t *testing.T) {
	params := verifierPolicyParameters("hs2019", "x-test", "")
	verifier, signature, err := parseVerifierPolicyRequest(rawVerifierPolicyRequest(params), nil)
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	validRSA := fixedRSAPublicKey(t)
	for _, test := range []struct {
		name string
		key  *rsa.PublicKey
	}{
		{name: "missing modulus", key: &rsa.PublicKey{}},
		{name: "exponent one", key: &rsa.PublicKey{N: validRSA.N, E: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifier.Verify(signature, fixedPublicVerificationKey(verifierPolicyKeyID, sigre.AlgorithmRSAPKCS1v15SHA512, test.key))
			assertPackageError(t, err, sigre.ErrUnsupportedKeyFormat)
		})
	}
}

func TestCavageVerifierConcurrentUse(t *testing.T) {
	secret := []byte(testHMACSecret)
	req := newTestRequest(t, http.MethodPost, "https://example.test/concurrent?value=1", "")
	req.Host = "example.test"
	req.RequestURI = req.URL.RequestURI()
	req.Header.Set("X-Test", "value")
	signer := sigre.NewCavageSigner()
	if err := signer.SignRequestWithHMAC(
		req,
		fixedHMACSigningKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret),
		sigre.CavageSignaturePlacementSignature,
		&sigre.CavageSigningOptions{Compatibility: &sigre.CavageSigningCompatibility{ExactHeaders: []string{sigre.CavageRequestTarget, "host", "x-test"}}},
	); err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	verifier, err := sigre.NewCavageVerifier(nil)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}

	const workers = 32
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			signature, err := verifier.ParseRequest(req)
			if err == nil {
				err = verifier.VerifyHMAC(signature, fixedHMACVerificationKey(verifierPolicyKeyID, sigre.AlgorithmHMACSHA512, secret))
			}
			errorsByWorker <- err
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent ParseRequest/VerifyHMAC failed: %v", err)
		}
	}
}
