package sigre

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

var signingStringTestSecret = []byte("signing-string-test-secret")

func signingStringHMACSigningKey(keyID string) HMACSigningKey {
	return HMACSigningKey{
		Metadata: TrustedKeyMetadata{KeyID: keyID, Algorithm: AlgorithmHMACSHA256},
		Secret:   signingStringTestSecret,
	}
}

func signingStringOptions(headers []string) *CavageSigningOptions {
	return &CavageSigningOptions{
		Compatibility: &CavageSigningCompatibility{
			AlgorithmField: AlgorithmFieldOmitted,
			ExactHeaders:   headers,
		},
	}
}

func TestOutgoingRequestTargetMatchesHTTPWireForm(t *testing.T) {
	tests := []struct {
		name   string
		method string
		url    *url.URL
		want   string
	}{
		{
			name:   "normal path",
			method: "GET",
			url:    &url.URL{Scheme: "https", Host: "example.test", Path: "/inbox"},
			want:   "/inbox",
		},
		{
			name:   "percent-encoded path and query",
			method: "POST",
			url:    parseSigningStringTestURL(t, "https://example.test/a%2Fb?x=%2F"),
			want:   "/a%2Fb?x=%2F",
		},
		{
			name:   "valid RawPath",
			method: "PUT",
			url:    &url.URL{Scheme: "https", Host: "example.test", Path: "/a/b", RawPath: "/a%2fb", RawQuery: "x=%2f"},
			want:   "/a%2fb?x=%2f",
		},
		{
			name:   "query parameter and duplicate value order",
			method: "GET",
			url:    &url.URL{Scheme: "https", Host: "example.test", Path: "/search", RawQuery: "b=2&a=1&a=0"},
			want:   "/search?b=2&a=1&a=0",
		},
		{
			name:   "escaped reserved query value",
			method: "GET",
			url:    &url.URL{Scheme: "https", Host: "example.test", Path: "/search", RawQuery: "value=%2F%3F%26%3D"},
			want:   "/search?value=%2F%3F%26%3D",
		},
		{
			name:   "empty query forced",
			method: "HEAD",
			url:    &url.URL{Scheme: "https", Host: "example.test", Path: "/empty", ForceQuery: true},
			want:   "/empty?",
		},
		{
			name:   "empty path",
			method: "OPTIONS",
			url:    &url.URL{Scheme: "https", Host: "example.test"},
			want:   "/",
		},
		{
			name:   "root path without query",
			method: "GET",
			url:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
			want:   "/",
		},
		{
			name:   "only method is lowercased",
			method: "PaTcH",
			url:    &url.URL{Scheme: "https", Host: "example.test", Path: "/Case/Path", RawQuery: "A=%2F"},
			want:   "/Case/Path?A=%2F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outgoingRequestTarget(tt.url); got != tt.want {
				t.Fatalf("outgoingRequestTarget() = %q, want %q", got, tt.want)
			}
			if got := outgoingRequestTarget(tt.url); got != tt.url.RequestURI() {
				t.Fatalf("outgoingRequestTarget() = %q, net/url URL.RequestURI() = %q", got, tt.url.RequestURI())
			}

			req := &http.Request{
				Method: tt.method,
				URL:    tt.url,
				Host:   tt.url.Host,
				Header: make(http.Header),
			}
			signer := NewCavageSigner()
			err := signer.SignRequestWithHMAC(
				req,
				signingStringHMACSigningKey("request-target-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{RequestTarget}),
			)
			if err != nil {
				t.Fatalf("SignRequestWithHMAC() failed: %v", err)
			}

			wantSigningString := "(request-target): " + strings.ToLower(tt.method) + " " + tt.want
			assertCavageHMACSignature(t, req.Header.Get(Signature), wantSigningString)

			var wire bytes.Buffer
			if err := req.Write(&wire); err != nil {
				t.Fatalf("Request.Write() failed: %v", err)
			}
			requestLine := strings.SplitN(wire.String(), "\r\n", 2)[0]
			wantRequestLine := tt.method + " " + tt.want + " HTTP/1.1"
			if requestLine != wantRequestLine {
				t.Fatalf("request line = %q, want %q", requestLine, wantRequestLine)
			}
		})
	}
}

func TestCavageRequestSignerRejectsOpaqueRequestTarget(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Opaque: "//example.test/opaque%2Fpath?b=2&a=1",
		},
		Host:   "example.test",
		Header: make(http.Header),
	}

	err := NewCavageSigner().SignRequestWithHMAC(
		req,
		signingStringHMACSigningKey("opaque-key"),
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{RequestTarget}),
	)
	if err == nil || !strings.Contains(err.Error(), "request-target is missing") {
		t.Fatalf("SignRequestWithHMAC() error = %v, want a missing request-target error", err)
	}
}

func TestGenerateSignatureStringNormalHeaders(t *testing.T) {
	header := signingStringTestHeaders()
	headers := []string{"X-One", "x-MULTI", "X-Empty", "x-Internal", "X-Unicode"}
	want := "x-one: single\n" +
		"x-multi: first, second\n" +
		"x-empty: \n" +
		"x-internal: a \t b\n" +
		"x-unicode: \u00a0kept\u2003"

	buf, err := generateSignatureStringBuffer(headers, "", "", "", header, "", "")
	if err != nil {
		t.Fatalf("generateSignatureStringBuffer() failed: %v", err)
	}
	if got := buf.String(); got != want {
		t.Fatalf("signing string mismatch\ngot:  %q\nwant: %q", got, want)
	}
	if strings.HasSuffix(buf.String(), "\n") || strings.Contains(buf.String(), "\r") {
		t.Fatalf("signing string has an invalid line separator: %q", buf.String())
	}
}

func TestCavageSignerNormalHeaderCanonicalization(t *testing.T) {
	want := "x-one: single\n" +
		"x-multi: first, second\n" +
		"x-empty: \n" +
		"x-internal: a \t b\n" +
		"x-unicode: \u00a0kept\u2003"
	headers := []string{"X-One", "x-MULTI", "X-Empty", "x-Internal", "X-Unicode"}

	for _, messageType := range []string{"request", "response"} {
		t.Run(messageType, func(t *testing.T) {
			header := signingStringTestHeaders()
			opts := signingStringOptions(headers)
			signer := NewCavageSigner()

			var err error
			switch messageType {
			case "request":
				req := &http.Request{
					Method: "GET",
					URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
					Host:   "example.test",
					Header: header,
				}
				err = signer.SignRequestWithHMAC(req, signingStringHMACSigningKey("normal-header-key"), CavageSignaturePlacementSignature, opts)
			case "response":
				res := &http.Response{Header: header}
				err = signer.SignResponseWithHMAC(res, signingStringHMACSigningKey("normal-header-key"), CavageSignaturePlacementSignature, opts)
			}
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}
			assertCavageHMACSignature(t, header.Get(Signature), want)
		})
	}
}

func TestCavageRequestVerifierUsesRequestURI(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		requestURI string
		want       string
	}{
		{
			name:       "percent encoding differs from URL Path",
			method:     "GET",
			requestURI: "/a%2Fb?x=%2F",
			want:       "(request-target): get /a%2Fb?x=%2F",
		},
		{
			name:       "trailing empty query",
			method:     "HEAD",
			requestURI: "/empty?",
			want:       "(request-target): head /empty?",
		},
		{
			name:       "query and duplicate value order",
			method:     "GET",
			requestURI: "/search?b=2&a=1&a=0&value=%2F%3F",
			want:       "(request-target): get /search?b=2&a=1&a=0&value=%2F%3F",
		},
		{
			name:       "method only is lowercased",
			method:     "CuStOm",
			requestURI: "/Case%2fPath?A=1",
			want:       "(request-target): custom /Case%2fPath?A=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := make(http.Header)
			header.Set(Signature, fixedCavageHMACHeader(t, tt.want, RequestTarget))
			req := &http.Request{
				Method:     tt.method,
				RequestURI: tt.requestURI,
				URL:        &url.URL{Path: "/different", RawQuery: "different=true"},
				Host:       "example.test",
				Header:     header,
			}

			verifier, err := NewCavageRequestVerifier(req)
			if err != nil {
				t.Fatalf("NewCavageRequestVerifier() failed: %v", err)
			}
			if err := verifier.VerifyHMAC(signingStringVerificationKey(), signingStringVerificationOptions()); err != nil {
				t.Fatalf("VerifyHMAC() failed: %v", err)
			}
		})
	}
}

func TestCavageRequestVerifierDoesNotRebuildMissingRequestURI(t *testing.T) {
	want := "(request-target): get /from-url"
	header := make(http.Header)
	header.Set(Signature, fixedCavageHMACHeader(t, want, RequestTarget))
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/from-url"},
		Host:   "example.test",
		Header: header,
	}

	verifier, err := NewCavageRequestVerifier(req)
	if err != nil {
		t.Fatalf("NewCavageRequestVerifier() failed: %v", err)
	}
	err = verifier.VerifyHMAC(signingStringVerificationKey(), signingStringVerificationOptions())
	if err == nil || !strings.Contains(err.Error(), "request-target is missing") {
		t.Fatalf("VerifyHMAC() error = %v, want a missing request-target error", err)
	}
}

func TestCavageResponseRequestTargetUsesAssociatedRequestURI(t *testing.T) {
	tests := []struct {
		name                  string
		method                string
		requestURI            string
		expectedSigningString string
	}{
		{
			name:                  "escaped path and ordered raw query",
			method:                "PaTcH",
			requestURI:            "/received%2Fpath?z=last&a=%2F&a=first",
			expectedSigningString: "(request-target): patch /received%2Fpath?z=last&a=%2F&a=first",
		},
		{
			name:                  "trailing empty query",
			method:                "HeAd",
			requestURI:            "/received%2Fempty?",
			expectedSigningString: "(request-target): head /received%2Fempty?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method:     tt.method,
				RequestURI: tt.requestURI,
				URL: &url.URL{
					Path:       "/different/url/path",
					RawPath:    "/different%2Furl%2Fpath",
					RawQuery:   "a=from-url&z=different",
					ForceQuery: true,
				},
			}

			t.Run("signer", func(t *testing.T) {
				res := &http.Response{Request: req, Header: make(http.Header)}
				err := NewCavageSigner().SignResponseWithHMAC(
					res,
					signingStringHMACSigningKey("response-request-uri-key"),
					CavageSignaturePlacementSignature,
					signingStringOptions([]string{RequestTarget}),
				)
				if err != nil {
					t.Fatalf("SignResponseWithHMAC() failed: %v", err)
				}
				assertCavageHMACSignature(t, res.Header.Get(Signature), tt.expectedSigningString)
			})

			t.Run("verifier", func(t *testing.T) {
				header := make(http.Header)
				header.Set(Signature, fixedCavageHMACHeader(t, tt.expectedSigningString, RequestTarget))
				res := &http.Response{Request: req, Header: header}

				verifier, err := NewCavageResponseVerifier(res)
				if err != nil {
					t.Fatalf("NewCavageResponseVerifier() failed: %v", err)
				}
				if err := verifier.VerifyHMAC(signingStringVerificationKey(), signingStringVerificationOptions()); err != nil {
					t.Fatalf("VerifyHMAC() failed: %v", err)
				}
			})
		})
	}
}

func TestCavageResponseRequestTargetUsesOutgoingURL(t *testing.T) {
	tests := []struct {
		name                  string
		method                string
		url                   *url.URL
		expectedRequestTarget string
		expectedSigningString string
	}{
		{
			name:   "valid RawPath and ordered RawQuery",
			method: "PoSt",
			url: &url.URL{
				Scheme:   "https",
				Host:     "example.test",
				Path:     "/sent/path",
				RawPath:  "/sent%2Fpath",
				RawQuery: "z=last&a=%2F&a=first",
			},
			expectedRequestTarget: "/sent%2Fpath?z=last&a=%2F&a=first",
			expectedSigningString: "(request-target): post /sent%2Fpath?z=last&a=%2F&a=first",
		},
		{
			name:   "ForceQuery preserves trailing question mark",
			method: "GeT",
			url: &url.URL{
				Scheme:     "https",
				Host:       "example.test",
				Path:       "/sent/empty",
				RawPath:    "/sent%2Fempty",
				ForceQuery: true,
			},
			expectedRequestTarget: "/sent%2Fempty?",
			expectedSigningString: "(request-target): get /sent%2Fempty?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.url.RequestURI(); got != tt.expectedRequestTarget {
				t.Fatalf("net/url URL.RequestURI() = %q, want fixed request-target %q", got, tt.expectedRequestTarget)
			}
			req := &http.Request{
				Method: tt.method,
				URL:    tt.url,
				Host:   tt.url.Host,
			}

			t.Run("signer", func(t *testing.T) {
				res := &http.Response{Request: req, Header: make(http.Header)}
				err := NewCavageSigner().SignResponseWithHMAC(
					res,
					signingStringHMACSigningKey("response-outgoing-url-key"),
					CavageSignaturePlacementSignature,
					signingStringOptions([]string{RequestTarget}),
				)
				if err != nil {
					t.Fatalf("SignResponseWithHMAC() failed: %v", err)
				}
				assertCavageHMACSignature(t, res.Header.Get(Signature), tt.expectedSigningString)
			})

			t.Run("verifier", func(t *testing.T) {
				header := make(http.Header)
				header.Set(Signature, fixedCavageHMACHeader(t, tt.expectedSigningString, RequestTarget))
				res := &http.Response{Request: req, Header: header}

				verifier, err := NewCavageResponseVerifier(res)
				if err != nil {
					t.Fatalf("NewCavageResponseVerifier() failed: %v", err)
				}
				if err := verifier.VerifyHMAC(signingStringVerificationKey(), signingStringVerificationOptions()); err != nil {
					t.Fatalf("VerifyHMAC() failed: %v", err)
				}
			})
		})
	}
}

func TestCavageVerifierNormalHeaderCanonicalization(t *testing.T) {
	want := "x-one: single\n" +
		"x-multi: first, second\n" +
		"x-empty: \n" +
		"x-internal: a \t b\n" +
		"x-unicode: \u00a0kept\u2003"
	signedHeaders := "x-one x-multi x-empty x-internal x-unicode"

	for _, messageType := range []string{"request", "response"} {
		t.Run(messageType, func(t *testing.T) {
			header := signingStringTestHeaders()
			header.Set(Signature, fixedCavageHMACHeader(t, want, signedHeaders))

			var verifier *CavageVerifier
			var err error
			switch messageType {
			case "request":
				verifier, err = NewCavageRequestVerifier(&http.Request{
					Method:     "GET",
					RequestURI: "/unused",
					URL:        &url.URL{Path: "/unused"},
					Host:       "example.test",
					Header:     header,
				})
			case "response":
				verifier, err = NewCavageResponseVerifier(&http.Response{Header: header})
			}
			if err != nil {
				t.Fatalf("verifier construction failed: %v", err)
			}
			if err := verifier.VerifyHMAC(signingStringVerificationKey(), signingStringVerificationOptions()); err != nil {
				t.Fatalf("VerifyHMAC() failed: %v", err)
			}
		})
	}
}

func TestCavageSignerRejectsInvalidOrMissingSignedHeader(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		setHeader  func(http.Header)
	}{
		{
			name:       "invalid field-name in manually constructed Header",
			headerName: "bad field",
			setHeader: func(header http.Header) {
				header["bad field"] = []string{"value"}
			},
		},
		{
			name:       "unknown pseudo-header",
			headerName: "(unknown)",
			setHeader:  func(http.Header) {},
		},
		{
			name:       "missing header",
			headerName: "x-missing",
			setHeader:  func(http.Header) {},
		},
		{
			name:       "header with no values",
			headerName: "x-empty-list",
			setHeader: func(header http.Header) {
				header["X-Empty-List"] = nil
			},
		},
	}

	for _, messageType := range []string{"request", "response"} {
		for _, tt := range tests {
			t.Run(messageType+"/"+tt.name, func(t *testing.T) {
				header := make(http.Header)
				tt.setHeader(header)
				opts := signingStringOptions([]string{tt.headerName})
				signer := NewCavageSigner()

				var err error
				switch messageType {
				case "request":
					err = signer.SignRequestWithHMAC(&http.Request{
						Method: "GET",
						URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
						Host:   "example.test",
						Header: header,
					}, signingStringHMACSigningKey("invalid-header-key"), CavageSignaturePlacementSignature, opts)
				case "response":
					err = signer.SignResponseWithHMAC(&http.Response{Header: header}, signingStringHMACSigningKey("invalid-header-key"), CavageSignaturePlacementSignature, opts)
				}
				if err == nil {
					t.Fatal("signing unexpectedly succeeded")
				}
			})
		}
	}
}

func TestCavageVerifierRejectsInvalidOrMissingSignedHeader(t *testing.T) {
	tests := []struct {
		name          string
		signedHeaders string
		setHeader     func(http.Header)
		wantError     string
	}{
		{
			name:          "invalid field-name in manually constructed Header",
			signedHeaders: "bad@field",
			setHeader: func(header http.Header) {
				header["bad@field"] = []string{"value"}
			},
			wantError: "invalid HTTP field-name",
		},
		{
			name:          "Unicode whitespace is not field-name OWS",
			signedHeaders: "x-one\u00a0",
			setHeader: func(header http.Header) {
				header["X-One"] = []string{"value"}
			},
			wantError: "invalid HTTP field-name",
		},
		{
			name:          "unknown pseudo-header",
			signedHeaders: "(unknown)",
			setHeader:     func(http.Header) {},
			wantError:     "invalid HTTP field-name",
		},
		{
			name:          "missing header",
			signedHeaders: "x-missing",
			setHeader:     func(http.Header) {},
			wantError:     "missing header",
		},
		{
			name:          "header with no values",
			signedHeaders: "x-empty-list",
			setHeader: func(header http.Header) {
				header["X-Empty-List"] = nil
			},
			wantError: "missing header",
		},
	}

	for _, messageType := range []string{"request", "response"} {
		for _, tt := range tests {
			t.Run(messageType+"/"+tt.name, func(t *testing.T) {
				header := make(http.Header)
				tt.setHeader(header)
				header.Set(Signature, fixedCavageHMACHeader(t, "fixed invalid-header input", tt.signedHeaders))

				var verifier *CavageVerifier
				var err error
				switch messageType {
				case "request":
					verifier, err = NewCavageRequestVerifier(&http.Request{
						Method:     "GET",
						RequestURI: "/",
						URL:        &url.URL{Path: "/"},
						Host:       "example.test",
						Header:     header,
					})
				case "response":
					verifier, err = NewCavageResponseVerifier(&http.Response{Header: header})
				}
				if err != nil {
					t.Fatalf("verifier construction failed: %v", err)
				}
				err = verifier.VerifyHMAC(signingStringVerificationKey(), signingStringVerificationOptions())
				if err == nil {
					t.Fatal("verification unexpectedly succeeded")
				}
				if !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("verification error = %v, want it to contain %q", err, tt.wantError)
				}
			})
		}
	}
}

func FuzzOutgoingRequestTarget(f *testing.F) {
	f.Add("/a/b", "/a%2Fb", "x=%2F", false)
	f.Add("", "", "", false)
	f.Add("/empty", "", "", true)
	f.Add("/search", "invalid%zz", "b=2&a=1&a=0", false)

	f.Fuzz(func(t *testing.T, path, rawPath, rawQuery string, forceQuery bool) {
		u := &url.URL{
			Path:       path,
			RawPath:    rawPath,
			RawQuery:   rawQuery,
			ForceQuery: forceQuery,
		}
		if got, want := outgoingRequestTarget(u), u.RequestURI(); got != want {
			t.Fatalf("outgoingRequestTarget() = %q, net/url URL.RequestURI() = %q", got, want)
		}
	})
}

func signingStringTestHeaders() http.Header {
	return http.Header{
		"X-One":      []string{" single "},
		"X-Multi":    []string{"first ", "\tsecond"},
		"X-Empty":    []string{"\t "},
		"X-Internal": []string{"a \t b"},
		"X-Unicode":  []string{"\u00a0kept\u2003"},
	}
}

func parseSigningStringTestURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", rawURL, err)
	}
	return u
}

func fixedCavageHMACHeader(t *testing.T, signingString, signedHeaders string) string {
	t.Helper()
	mac := hmac.New(sha256.New, signingStringTestSecret)
	if _, err := mac.Write([]byte(signingString)); err != nil {
		t.Fatalf("failed to calculate fixed HMAC: %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return `keyId="test-key",signature="` + signature + `",algorithm="hmac-sha256",headers="` + signedHeaders + `"`
}

func signingStringVerificationKey() HMACVerificationKey {
	return HMACVerificationKey{
		Metadata: TrustedKeyMetadata{KeyID: "test-key", Algorithm: AlgorithmHMACSHA256},
		Secret:   signingStringTestSecret,
	}
}

func signingStringVerificationOptions() *CavageVerificationOptions {
	return &CavageVerificationOptions{
		Compatibility: &CavageVerificationCompatibility{
			AllowedLegacyAlgorithms: []AlgorithmID{AlgorithmHMACSHA256},
		},
	}
}

func assertCavageHMACSignature(t *testing.T, headerValue, signingString string) {
	t.Helper()
	const prefix = `signature="`
	start := strings.Index(headerValue, prefix)
	if start < 0 {
		t.Fatalf("signature parameter not found in %q", headerValue)
	}
	encoded := headerValue[start+len(prefix):]
	end := strings.IndexByte(encoded, '"')
	if end < 0 {
		t.Fatalf("signature parameter is not terminated in %q", headerValue)
	}
	got, err := base64.StdEncoding.DecodeString(encoded[:end])
	if err != nil {
		t.Fatalf("signature is not valid Base64: %v", err)
	}

	mac := hmac.New(sha256.New, signingStringTestSecret)
	if _, err := mac.Write([]byte(signingString)); err != nil {
		t.Fatalf("failed to calculate expected HMAC: %v", err)
	}
	if !hmac.Equal(got, mac.Sum(nil)) {
		t.Fatalf("signature does not cover fixed signing string %q", signingString)
	}
}
