package sigre

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"reflect"
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
	headers := []string{"X-One", "x-MULTI", "X-Zero", "X-Empty", "x-Internal", "X-Unicode"}
	want := "x-one: single\n" +
		"x-multi: first, second\n" +
		"x-zero: \n" +
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
		"x-zero: \n" +
		"x-empty: \n" +
		"x-internal: a \t b\n" +
		"x-unicode: \u00a0kept\u2003"
	headers := []string{"X-One", "x-MULTI", "X-Zero", "X-Empty", "x-Internal", "X-Unicode"}

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

func TestGenerateSignatureStringRejectsForbiddenHeaderValueBytes(t *testing.T) {
	tests := []struct {
		name string
		b    byte
	}{
		{name: "CR", b: '\r'},
		{name: "LF", b: '\n'},
		{name: "NUL", b: 0x00},
		{name: "DEL", b: 0x7f},
		{name: "other CTL", b: 0x01},
	}
	valueSets := []struct {
		name   string
		values func(byte) []string
	}{
		{
			name: "single value",
			values: func(b byte) []string {
				return []string{"ok" + string(b) + "changed"}
			},
		},
		{
			name: "second value",
			values: func(b byte) []string {
				return []string{"first", "ok" + string(b) + "changed"}
			},
		},
	}

	for _, valueSet := range valueSets {
		for _, tt := range tests {
			t.Run(valueSet.name+"/"+tt.name, func(t *testing.T) {
				header := http.Header{"X-Signed": valueSet.values(tt.b)}
				_, err := generateSignatureStringBuffer([]string{"x-signed"}, "", "", "", header, "", "")
				if !errors.Is(err, ErrInvalidHTTPMessage) {
					t.Fatalf("generateSignatureStringBuffer() error = %v, want ErrInvalidHTTPMessage", err)
				}
			})
		}
	}

	diagnosticTests := []struct {
		name             string
		values           []string
		wantValueIndex   string
		wantBytePosition string
		forbiddenText    string
	}{
		{
			name:             "single value",
			values:           []string{"bb\rcc"},
			wantValueIndex:   "value index 0",
			wantBytePosition: "byte position 3",
		},
		{
			name:             "second value",
			values:           []string{"aaaaaaaaaa", "bb\rcc"},
			wantValueIndex:   "value index 1",
			wantBytePosition: "byte position 3",
		},
		{
			name:             "field value is not disclosed",
			values:           []string{"SENTINEL\rprivate"},
			wantValueIndex:   "value index 0",
			wantBytePosition: "byte position 9",
			forbiddenText:    "SENTINEL",
		},
	}
	diagnosticErrors := make(map[string]string, len(diagnosticTests))

	for _, tt := range diagnosticTests {
		t.Run("diagnostics/"+tt.name, func(t *testing.T) {
			header := http.Header{"X-Signed": tt.values}
			_, err := generateSignatureStringBuffer([]string{"x-signed"}, "", "", "", header, "", "")
			if !errors.Is(err, ErrInvalidHTTPMessage) {
				t.Fatalf("generateSignatureStringBuffer() error = %v, want ErrInvalidHTTPMessage", err)
			}
			for _, want := range []string{"x-signed", tt.wantValueIndex, tt.wantBytePosition} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
			if tt.forbiddenText != "" && strings.Contains(err.Error(), tt.forbiddenText) {
				t.Errorf("error = %q, must not disclose field value text %q", err, tt.forbiddenText)
			}
			diagnosticErrors[tt.name] = err.Error()
		})
	}

	if diagnosticErrors["single value"] == diagnosticErrors["second value"] {
		t.Errorf("single-value and second-value errors are indistinguishable: %q", diagnosticErrors["single value"])
	}
}

func TestGenerateSignatureStringRejectsForbiddenHostFallbackBytes(t *testing.T) {
	tests := []struct {
		name string
		b    byte
	}{
		{name: "CR", b: '\r'},
		{name: "LF", b: '\n'},
		{name: "NUL", b: 0x00},
		{name: "DEL", b: 0x7f},
		{name: "other CTL", b: 0x01},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := "signed" + string(tt.b) + "host"
			_, err := generateSignatureStringBuffer([]string{"host"}, host, "", "", make(http.Header), "", "")
			if !errors.Is(err, ErrInvalidHTTPMessage) {
				t.Fatalf("generateSignatureStringBuffer() error = %v, want ErrInvalidHTTPMessage", err)
			}
		})
	}

	t.Run("diagnostics", func(t *testing.T) {
		const host = "SENTINEL\rhost"
		_, err := generateSignatureStringBuffer([]string{"host"}, host, "", "", make(http.Header), "", "")
		if !errors.Is(err, ErrInvalidHTTPMessage) {
			t.Fatalf("generateSignatureStringBuffer() error = %v, want ErrInvalidHTTPMessage", err)
		}
		for _, want := range []string{"host", "value index 0", "byte position 9"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %q, want it to contain %q", err, want)
			}
		}
		if strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("error = %q, must not disclose the Host fallback value", err)
		}
	})
}

func TestGenerateSignatureStringNormalHostFallback(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "plain host", host: "example.test:8443", want: "host: example.test:8443"},
		{name: "OWS is trimmed", host: " \texample.test:8443\t ", want: "host: example.test:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := generateSignatureStringBuffer([]string{"host"}, tt.host, "", "", make(http.Header), "", "")
			if err != nil {
				t.Fatalf("generateSignatureStringBuffer() failed: %v", err)
			}
			if got := buf.String(); got != tt.want {
				t.Fatalf("signing string = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCavageSignerRejectsForbiddenHostFallbackWithoutMutation(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		header := http.Header{"X-Unrelated": []string{"unchanged"}}
		beforeHeader := header.Clone()
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
			Host:   "signed\rhost",
			Header: header,
			Body:   http.NoBody,
		}
		beforeURL := *req.URL
		beforeBody := req.Body

		err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("invalid-host-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"host"}),
		)
		if !errors.Is(err, ErrInvalidHTTPMessage) {
			t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
		}
		var sigreErr *SigreError
		if !errors.As(err, &sigreErr) {
			t.Fatalf("SignRequestWithHMAC() error type = %T, want *SigreError", err)
		}
		if !reflect.DeepEqual(header, beforeHeader) {
			t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", header, beforeHeader)
		}
		if req.Host != "signed\rhost" {
			t.Fatalf("Request.Host = %q, want original value", req.Host)
		}
		if !reflect.DeepEqual(req.URL, &beforeURL) {
			t.Fatalf("Request.URL changed after failed signing\ngot:  %#v\nwant: %#v", req.URL, &beforeURL)
		}
		if req.Body != beforeBody {
			t.Fatal("Request.Body changed after failed signing")
		}
		if _, ok := header[Signature]; ok {
			t.Fatalf("Signature was set after failed signing: %q", header.Values(Signature))
		}
		if _, ok := header[Authorization]; ok {
			t.Fatalf("Authorization was set after failed signing: %q", header.Values(Authorization))
		}
	})

	t.Run("response associated request", func(t *testing.T) {
		header := http.Header{"X-Unrelated": []string{"unchanged"}}
		beforeHeader := header.Clone()
		associatedRequest := &http.Request{Host: "signed\x00host", Body: http.NoBody}
		res := &http.Response{
			Header:  header,
			Body:    http.NoBody,
			Request: associatedRequest,
		}
		beforeBody := res.Body

		err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("invalid-host-key"),
			CavageSignaturePlacementAuthorization,
			signingStringOptions([]string{"host"}),
		)
		if !errors.Is(err, ErrInvalidHTTPMessage) {
			t.Fatalf("SignResponseWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
		}
		var sigreErr *SigreError
		if !errors.As(err, &sigreErr) {
			t.Fatalf("SignResponseWithHMAC() error type = %T, want *SigreError", err)
		}
		if !reflect.DeepEqual(header, beforeHeader) {
			t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", header, beforeHeader)
		}
		if res.Request != associatedRequest || associatedRequest.Host != "signed\x00host" {
			t.Fatal("Response.Request changed after failed signing")
		}
		if res.Body != beforeBody {
			t.Fatal("Response.Body changed after failed signing")
		}
		if _, ok := header[Signature]; ok {
			t.Fatalf("Signature was set after failed signing: %q", header.Values(Signature))
		}
		if _, ok := header[Authorization]; ok {
			t.Fatalf("Authorization was set after failed signing: %q", header.Values(Authorization))
		}
	})
}

func TestCavageSignerNilHeaderContract(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	asymmetricKey := SigningKey{
		Metadata:   TrustedKeyMetadata{KeyID: "nil-header-asymmetric-key", Algorithm: AlgorithmEd25519},
		PrivateKey: privateKey,
	}
	hmacKey := signingStringHMACSigningKey("nil-header-hmac-key")

	tests := []struct {
		name      string
		isRequest bool
		isHMAC    bool
		placement CavageSignaturePlacement
		sign      func(*http.Request, *http.Response, CavageSignaturePlacement) error
	}{
		{
			name:      "asymmetric request",
			isRequest: true,
			placement: CavageSignaturePlacementSignature,
			sign: func(req *http.Request, _ *http.Response, placement CavageSignaturePlacement) error {
				return NewCavageSigner().SignRequest(req, asymmetricKey, placement, signingStringOptions([]string{"host"}))
			},
		},
		{
			name:      "asymmetric response",
			placement: CavageSignaturePlacementAuthorization,
			sign: func(_ *http.Request, res *http.Response, placement CavageSignaturePlacement) error {
				return NewCavageSigner().SignResponse(res, asymmetricKey, placement, signingStringOptions([]string{"host"}))
			},
		},
		{
			name:      "HMAC request",
			isRequest: true,
			isHMAC:    true,
			placement: CavageSignaturePlacementAuthorization,
			sign: func(req *http.Request, _ *http.Response, placement CavageSignaturePlacement) error {
				return NewCavageSigner().SignRequestWithHMAC(req, hmacKey, placement, signingStringOptions([]string{"host"}))
			},
		},
		{
			name:      "HMAC response",
			isHMAC:    true,
			placement: CavageSignaturePlacementSignature,
			sign: func(_ *http.Request, res *http.Response, placement CavageSignaturePlacement) error {
				return NewCavageSigner().SignResponseWithHMAC(res, hmacKey, placement, signingStringOptions([]string{"host"}))
			},
		},
	}

	newMessages := func(host string) (*http.Request, *http.Response) {
		associatedRequest := &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
			Host:   host,
			Header: nil,
			Body:   http.NoBody,
		}
		return associatedRequest, &http.Response{
			Header:  nil,
			Body:    http.NoBody,
			Request: associatedRequest,
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("forbidden Host fallback", func(t *testing.T) {
				forbiddenHost := "signed\x00host"
				if tt.isRequest {
					forbiddenHost = "signed\rhost"
				}
				req, res := newMessages(forbiddenHost)
				beforeURL := *req.URL
				beforeRequestBody := req.Body
				beforeResponseBody := res.Body
				beforeAssociatedRequest := res.Request

				err := tt.sign(req, res, tt.placement)
				isInvalidHTTPMessage := errors.Is(err, ErrInvalidHTTPMessage)
				var sigreErr *SigreError
				isSigreError := errors.As(err, &sigreErr)
				if !isInvalidHTTPMessage {
					t.Fatalf("signing error = %v, want ErrInvalidHTTPMessage", err)
				}
				if !isSigreError {
					t.Fatalf("signing error type = %T, want *SigreError", err)
				}
				for _, want := range []string{"failed to create signing string", `HTTP field "host"`, "value index 0", "byte position 7"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error = %q, want it to contain %q", err, want)
					}
				}

				var gotHeader http.Header
				if tt.isRequest {
					gotHeader = req.Header
				} else {
					gotHeader = res.Header
				}
				if gotHeader != nil {
					t.Fatalf("Header = %#v, want nil (errors.Is(ErrInvalidHTTPMessage) = %t, errors.As(*SigreError) = %t, error = %q)", gotHeader, isInvalidHTTPMessage, isSigreError, err)
				}
				if !tt.isRequest && req.Header != nil {
					t.Fatalf("associated Request.Header = %#v, want nil", req.Header)
				}
				if req.Host != forbiddenHost {
					t.Fatalf("associated Request.Host = %q, want %q", req.Host, forbiddenHost)
				}
				if !reflect.DeepEqual(req.URL, &beforeURL) {
					t.Fatalf("associated Request.URL changed after failed signing\ngot:  %#v\nwant: %#v", req.URL, &beforeURL)
				}
				if req.Body != beforeRequestBody {
					t.Fatal("associated Request.Body changed after failed signing")
				}
				if res.Request != beforeAssociatedRequest {
					t.Fatal("Response.Request changed after failed signing")
				}
				if res.Body != beforeResponseBody {
					t.Fatal("Response.Body changed after failed signing")
				}
			})

			t.Run("successful signing", func(t *testing.T) {
				req, res := newMessages("example.test")
				if err := tt.sign(req, res, tt.placement); err != nil {
					t.Fatalf("signing failed: %v", err)
				}

				header := res.Header
				if tt.isRequest {
					header = req.Header
				}
				if header == nil {
					t.Fatal("Header = nil after successful signing")
				}
				if !tt.isRequest && req.Header != nil {
					t.Fatalf("associated Request.Header = %#v after successful response signing, want nil", req.Header)
				}
				field := Signature
				if tt.placement == CavageSignaturePlacementAuthorization {
					field = Authorization
				}
				if got := header.Get(field); got == "" {
					t.Fatalf("%s header was not set after successful signing", field)
				}
				if tt.isHMAC {
					assertCavageHMACSignature(t, header.Get(field), "host: example.test")
				}
			})
		})
	}
}

func TestCavageSignerRejectsForbiddenHeaderValuesWithoutMutation(t *testing.T) {
	tests := []struct {
		name       string
		isRequest  bool
		values     []string
		placement  CavageSignaturePlacement
		asymmetric bool
	}{
		{
			name:      "request single CR with Authorization output",
			isRequest: true,
			values:    []string{"ok\rchanged"},
			placement: CavageSignaturePlacementAuthorization,
		},
		{
			name:       "request second value NUL with asymmetric key",
			isRequest:  true,
			values:     []string{"first", "a\x00b"},
			placement:  CavageSignaturePlacementSignature,
			asymmetric: true,
		},
		{
			name:      "response single LF",
			values:    []string{"ok\nchanged"},
			placement: CavageSignaturePlacementSignature,
		},
		{
			name:      "response second value DEL",
			values:    []string{"first", "a\x7fb"},
			placement: CavageSignaturePlacementSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{
				"Authorization": []string{"Bearer existing-token"},
				"X-Signed":      append([]string(nil), tt.values...),
				"X-Unrelated":   []string{"unchanged"},
			}
			before := header.Clone()
			opts := signingStringOptions([]string{"x-signed"})
			signer := NewCavageSigner()

			var err error
			if tt.isRequest {
				req := &http.Request{
					Method: "GET",
					URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
					Host:   "example.test",
					Header: header,
				}
				if tt.asymmetric {
					privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
					err = signer.SignRequest(req, SigningKey{
						Metadata:   TrustedKeyMetadata{KeyID: "invalid-value-key", Algorithm: AlgorithmEd25519},
						PrivateKey: privateKey,
					}, tt.placement, opts)
				} else {
					err = signer.SignRequestWithHMAC(req, signingStringHMACSigningKey("invalid-value-key"), tt.placement, opts)
				}
			} else {
				res := &http.Response{Header: header}
				err = signer.SignResponseWithHMAC(res, signingStringHMACSigningKey("invalid-value-key"), tt.placement, opts)
			}

			if !errors.Is(err, ErrInvalidHTTPMessage) {
				t.Fatalf("signing error = %v, want ErrInvalidHTTPMessage", err)
			}
			if !reflect.DeepEqual(header, before) {
				t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", header, before)
			}
			if got := header.Get(Authorization); got != "Bearer existing-token" {
				t.Fatalf("Authorization = %q, want existing Bearer value", got)
			}
			if _, ok := header[Signature]; ok {
				t.Fatalf("Signature was set after failed signing: %q", header.Values(Signature))
			}
		})
	}
}

func TestCavageVerifierRejectsForbiddenSignedHeaderValues(t *testing.T) {
	tests := []struct {
		name      string
		isRequest bool
		value     string
	}{
		{name: "request", isRequest: true, value: "ok\rchanged"},
		{name: "response", value: "a\x00b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantSigningString := "x-signed: " + tt.value
			header := http.Header{
				"X-Signed": []string{tt.value},
				Signature:  []string{fixedCavageHMACHeader(t, wantSigningString, "x-signed")},
			}
			before := header.Clone()
			verifier, err := NewCavageVerifier(signingStringVerificationOptions())
			if err != nil {
				t.Fatalf("NewCavageVerifier() failed: %v", err)
			}

			if tt.isRequest {
				_, err = verifier.ParseRequest(&http.Request{
					Method:     "GET",
					RequestURI: "/",
					URL:        &url.URL{Path: "/"},
					Host:       "example.test",
					Header:     header,
				})
			} else {
				_, err = verifier.ParseResponse(&http.Response{Header: header})
			}
			if !errors.Is(err, ErrInvalidHTTPMessage) {
				t.Fatalf("parsing error = %v, want ErrInvalidHTTPMessage", err)
			}
			if !reflect.DeepEqual(header, before) {
				t.Fatalf("Header changed after failed parsing\ngot:  %#v\nwant: %#v", header, before)
			}
		})
	}
}

func TestCavageSignerNormalHeaderValuesMatchHTTPWireForm(t *testing.T) {
	const wantSigningString = "x-wire: first\tvalue, \u00a0second"

	for _, messageType := range []string{"request", "response"} {
		t.Run(messageType, func(t *testing.T) {
			header := http.Header{"X-Wire": []string{" \tfirst\tvalue \t", "\u00a0second"}}
			opts := signingStringOptions([]string{"x-wire"})
			var wire bytes.Buffer

			switch messageType {
			case "request":
				req := &http.Request{
					Method: "GET",
					URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
					Host:   "example.test",
					Header: header,
				}
				if err := NewCavageSigner().SignRequestWithHMAC(req, signingStringHMACSigningKey("wire-key"), CavageSignaturePlacementSignature, opts); err != nil {
					t.Fatalf("SignRequestWithHMAC() failed: %v", err)
				}
				assertCavageHMACSignature(t, header.Get(Signature), wantSigningString)
				if err := req.Write(&wire); err != nil {
					t.Fatalf("Request.Write() failed: %v", err)
				}
				parsed, err := http.ReadRequest(bufio.NewReader(&wire))
				if err != nil {
					t.Fatalf("http.ReadRequest() failed: %v", err)
				}
				if got := "x-wire: " + strings.Join(parsed.Header.Values("X-Wire"), ", "); got != wantSigningString {
					t.Fatalf("wire field values = %q, want %q", got, wantSigningString)
				}
			case "response":
				res := &http.Response{
					Status:        "200 OK",
					StatusCode:    http.StatusOK,
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        header,
					Body:          http.NoBody,
					ContentLength: 0,
				}
				if err := NewCavageSigner().SignResponseWithHMAC(res, signingStringHMACSigningKey("wire-key"), CavageSignaturePlacementSignature, opts); err != nil {
					t.Fatalf("SignResponseWithHMAC() failed: %v", err)
				}
				assertCavageHMACSignature(t, header.Get(Signature), wantSigningString)
				if err := res.Write(&wire); err != nil {
					t.Fatalf("Response.Write() failed: %v", err)
				}
				parsed, err := http.ReadResponse(bufio.NewReader(&wire), nil)
				if err != nil {
					t.Fatalf("http.ReadResponse() failed: %v", err)
				}
				defer parsed.Body.Close()
				if got := "x-wire: " + strings.Join(parsed.Header.Values("X-Wire"), ", "); got != wantSigningString {
					t.Fatalf("wire field values = %q, want %q", got, wantSigningString)
				}
			}
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

			verifier, signature := parseSigningStringRequest(t, req)
			if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
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

	verifier, err := NewCavageVerifier(signingStringVerificationOptions())
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	_, err = verifier.ParseRequest(req)
	if err == nil || !strings.Contains(err.Error(), "request-target is required") {
		t.Fatalf("ParseRequest() error = %v, want a missing request-target error", err)
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

				verifier, signature := parseSigningStringResponse(t, res)
				if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
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

				verifier, signature := parseSigningStringResponse(t, res)
				if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
					t.Fatalf("VerifyHMAC() failed: %v", err)
				}
			})
		})
	}
}

func TestCavageVerifierNormalHeaderCanonicalization(t *testing.T) {
	want := "x-one: single\n" +
		"x-multi: first, second\n" +
		"x-zero: \n" +
		"x-empty: \n" +
		"x-internal: a \t b\n" +
		"x-unicode: \u00a0kept\u2003"
	signedHeaders := "x-one x-multi x-zero x-empty x-internal x-unicode"

	for _, messageType := range []string{"request", "response"} {
		t.Run(messageType, func(t *testing.T) {
			header := signingStringTestHeaders()
			header.Set(Signature, fixedCavageHMACHeader(t, want, signedHeaders))

			var verifier *CavageVerifier
			var signature *CavageSignature
			switch messageType {
			case "request":
				verifier, signature = parseSigningStringRequest(t, &http.Request{
					Method:     "GET",
					RequestURI: "/unused",
					URL:        &url.URL{Path: "/unused"},
					Host:       "example.test",
					Header:     header,
				})
			case "response":
				verifier, signature = parseSigningStringResponse(t, &http.Response{Header: header})
			}
			if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
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
			wantError:     "signed header missing",
		},
		{
			name:          "header with no values",
			signedHeaders: "x-empty-list",
			setHeader: func(header http.Header) {
				header["X-Empty-List"] = nil
			},
			wantError: "signed header missing",
		},
	}

	for _, messageType := range []string{"request", "response"} {
		for _, tt := range tests {
			t.Run(messageType+"/"+tt.name, func(t *testing.T) {
				header := make(http.Header)
				tt.setHeader(header)
				header.Set(Signature, fixedCavageHMACHeader(t, "fixed invalid-header input", tt.signedHeaders))

				verifier, err := NewCavageVerifier(signingStringVerificationOptions())
				if err != nil {
					t.Fatalf("NewCavageVerifier() failed: %v", err)
				}
				switch messageType {
				case "request":
					_, err = verifier.ParseRequest(&http.Request{
						Method:     "GET",
						RequestURI: "/",
						URL:        &url.URL{Path: "/"},
						Host:       "example.test",
						Header:     header,
					})
				case "response":
					_, err = verifier.ParseResponse(&http.Response{Header: header})
				}
				if err == nil {
					t.Fatal("parsing unexpectedly succeeded")
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
		"X-Zero":     []string{""},
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
		AllowedAlgorithms: []AlgorithmID{AlgorithmHMACSHA256},
		Compatibility: &CavageVerificationCompatibility{
			AllowedLegacyAlgorithms: []AlgorithmID{AlgorithmHMACSHA256},
		},
	}
}

func parseSigningStringRequest(t *testing.T, req *http.Request) (*CavageVerifier, *CavageSignature) {
	t.Helper()
	verifier, err := NewCavageVerifier(signingStringVerificationOptions())
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	return verifier, signature
}

func parseSigningStringResponse(t *testing.T, res *http.Response) (*CavageVerifier, *CavageSignature) {
	t.Helper()
	verifier, err := NewCavageVerifier(signingStringVerificationOptions())
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	signature, err := verifier.ParseResponse(res)
	if err != nil {
		t.Fatalf("ParseResponse() failed: %v", err)
	}
	return verifier, signature
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
