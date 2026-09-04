package sigre

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
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
			name:   "server-wide OPTIONS",
			method: http.MethodOptions,
			url:    &url.URL{Scheme: "https", Host: "example.test", Path: "*"},
			want:   "*",
		},
		{
			name:   "CONNECT comparison is case-sensitive",
			method: "connect",
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
			req := &http.Request{
				Method: tt.method,
				URL:    tt.url,
				Host:   tt.url.Host,
				Header: make(http.Header),
			}
			gotTarget, err := outgoingRequestTarget(req)
			if err != nil {
				t.Fatalf("outgoingRequestTarget() failed: %v", err)
			}
			if gotTarget != tt.want {
				t.Fatalf("outgoingRequestTarget() = %q, want %q", gotTarget, tt.want)
			}
			if gotTarget != tt.url.RequestURI() {
				t.Fatalf("outgoingRequestTarget() = %q, net/url URL.RequestURI() = %q", gotTarget, tt.url.RequestURI())
			}

			signer := NewCavageSigner()
			err = signer.SignRequestWithHMAC(
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
	if !errors.Is(err, ErrInvalidHTTPMessage) || !strings.Contains(err.Error(), "request-target is missing") {
		t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage for a missing request-target", err)
	}
}

func TestCavageRequestSignerRejectsNilURLRequestTarget(t *testing.T) {
	req := &http.Request{
		Method: http.MethodGet,
		Header: http.Header{"X-Unrelated": {"unchanged"}},
	}
	headerBefore := req.Header.Clone()

	err := NewCavageSigner().SignRequestWithHMAC(
		req,
		signingStringHMACSigningKey("nil-url-key"),
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{RequestTarget}),
	)
	if !errors.Is(err, ErrInvalidHTTPMessage) {
		t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
	}
	if !reflect.DeepEqual(req.Header, headerBefore) || req.Header.Get(Signature) != "" {
		t.Fatalf("failed signing changed Header: %#v", req.Header)
	}
}

func TestRequestTargetResolversRejectUnresolvableInputs(t *testing.T) {
	tests := []struct {
		name       string
		resolve    func() (string, error)
		wantDetail string
	}{
		{
			name: "received authority-form without CONNECT",
			resolve: func() (string, error) {
				return receivedRequestTarget(&http.Request{Method: http.MethodGet, RequestURI: "example.test:443"})
			},
			wantDetail: "authority-form",
		},
		{
			name: "missing associated request",
			resolve: func() (string, error) {
				return associatedRequestTarget(nil)
			},
			wantDetail: "associated request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := tt.resolve()
			if target != "" || !errors.Is(err, ErrInvalidHTTPMessage) || !strings.Contains(err.Error(), tt.wantDetail) {
				t.Fatalf("resolver result = %q, %v; want empty target and ErrInvalidHTTPMessage containing %q", target, err, tt.wantDetail)
			}
		})
	}
}

func TestCavageRequestSignerRejectsCONNECTRequestTarget(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	tests := []struct {
		name    string
		urlPath string
		sign    func(*http.Request) error
	}{
		{
			name: "asymmetric",
			sign: func(req *http.Request) error {
				return NewCavageSigner().SignRequest(
					req,
					SigningKey{
						Metadata:   TrustedKeyMetadata{KeyID: "connect-asymmetric-key", Algorithm: AlgorithmEd25519},
						PrivateKey: privateKey,
					},
					CavageSignaturePlacementSignature,
					signingStringOptions([]string{RequestTarget}),
				)
			},
		},
		{
			name:    "HMAC with path-form URL",
			urlPath: "/_goRPC_",
			sign: func(req *http.Request) error {
				return NewCavageSigner().SignRequestWithHMAC(
					req,
					signingStringHMACSigningKey("connect-hmac-key"),
					CavageSignaturePlacementAuthorization,
					signingStringOptions([]string{RequestTarget}),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &receivedCountingBody{}
			req := &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Host: "Tunnel.Example:443", Path: tt.urlPath},
				Host:   "Tunnel.Example:443",
				Header: http.Header{
					"Authorization": {"Bearer unchanged"},
					"X-Unrelated":   {"unchanged"},
				},
				Body: body,
			}
			headerBefore := req.Header.Clone()
			urlBefore := *req.URL

			err := tt.sign(req)
			assertInvalidRequestTargetError(t, err, "CONNECT")
			if !reflect.DeepEqual(req.Header, headerBefore) || !reflect.DeepEqual(req.URL, &urlBefore) || req.Body != body || req.Method != http.MethodConnect || req.RequestURI != "" {
				t.Fatal("failed CONNECT signing modified the request")
			}
			if req.Header.Get(Signature) != "" || req.Header.Get(Authorization) != "Bearer unchanged" {
				t.Fatalf("failed CONNECT signing changed signature fields: %#v", req.Header)
			}
			if body.reads != 0 || body.closes != 0 {
				t.Fatalf("failed CONNECT signing accessed Body: reads=%d closes=%d", body.reads, body.closes)
			}
		})
	}
}

func TestCavageResponseSignerRejectsAssociatedCONNECTRequestTarget(t *testing.T) {
	raw := "CONNECT Tunnel.Example:443 HTTP/1.1\r\nHost: Tunnel.Example:443\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("http.ReadRequest() failed: %v", err)
	}
	defer req.Body.Close()
	reqBody := &receivedCountingBody{}
	req.Body = reqBody
	resBody := &receivedCountingBody{}
	res := &http.Response{
		Request: req,
		Header: http.Header{
			"Authorization": {"Bearer unchanged"},
			"X-Unrelated":   {"unchanged"},
		},
		Body: resBody,
	}
	headerBefore := res.Header.Clone()
	requestHeaderBefore := req.Header.Clone()
	requestURLBefore := *req.URL

	err = NewCavageSigner().SignResponseWithHMAC(
		res,
		signingStringHMACSigningKey("response-connect-key"),
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{RequestTarget}),
	)
	assertInvalidRequestTargetError(t, err, "CONNECT")
	if !reflect.DeepEqual(res.Header, headerBefore) || res.Body != resBody || res.Request != req {
		t.Fatal("failed response signing modified the response")
	}
	if !reflect.DeepEqual(req.Header, requestHeaderBefore) || !reflect.DeepEqual(req.URL, &requestURLBefore) || req.Body != reqBody || req.Method != http.MethodConnect || req.RequestURI != "Tunnel.Example:443" {
		t.Fatal("failed response signing modified the associated CONNECT request")
	}
	if res.Header.Get(Signature) != "" || res.Header.Get(Authorization) != "Bearer unchanged" {
		t.Fatalf("failed response signing changed signature fields: %#v", res.Header)
	}
	if reqBody.reads != 0 || reqBody.closes != 0 || resBody.reads != 0 || resBody.closes != 0 {
		t.Fatalf("failed response signing accessed a Body: request=(%d,%d) response=(%d,%d)", reqBody.reads, reqBody.closes, resBody.reads, resBody.closes)
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

func TestCavageSignerRejectsAuthorizationSelfReference(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		opts   *CavageSigningOptions
	}{
		{
			name: "ExactHeaders with existing Bearer authorization",
			header: http.Header{
				Authorization: []string{"Bearer token"},
				"X-Unrelated": []string{"unchanged"},
			},
			opts: signingStringOptions([]string{"authorization"}),
		},
		{
			name: "mixed-case AdditionalHeaders",
			header: http.Header{
				Authorization: []string{"Bearer token"},
				"X-Unrelated": []string{"unchanged"},
			},
			opts: &CavageSigningOptions{
				AdditionalHeaders: []string{"AuThOrIzAtIoN"},
				Compatibility: &CavageSigningCompatibility{
					AlgorithmField: AlgorithmFieldOmitted,
				},
			},
		},
		{
			name:   "missing authorization with nil Header",
			header: nil,
			opts:   signingStringOptions([]string{"AUTHORIZATION"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/resource"},
				Host:   "example.test",
				Header: tt.header,
				Body:   http.NoBody,
			}
			beforeHeader := tt.header.Clone()
			beforeURL := *req.URL
			beforeBody := req.Body

			err := NewCavageSigner().SignRequestWithHMAC(
				req,
				signingStringHMACSigningKey("self-reference-key"),
				CavageSignaturePlacementAuthorization,
				tt.opts,
			)
			assertInvalidPlacementError(t, err, "self-reference")

			if !reflect.DeepEqual(req.Header, beforeHeader) {
				t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", req.Header, beforeHeader)
			}
			if req.Header.Get(Authorization) != tt.header.Get(Authorization) {
				t.Fatalf("Authorization = %q, want %q", req.Header.Get(Authorization), tt.header.Get(Authorization))
			}
			if req.Header.Get(Signature) != "" {
				t.Fatalf("Signature was added after failed signing: %q", req.Header.Get(Signature))
			}
			if req.Host != "example.test" || !reflect.DeepEqual(req.URL, &beforeURL) || req.Body != beforeBody {
				t.Fatal("request fields changed after failed signing")
			}
		})
	}
}

func TestCavageSignerRejectsResponseAuthorizationPlacement(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	asymmetricKey := SigningKey{
		Metadata:   TrustedKeyMetadata{KeyID: "response-asymmetric-key", Algorithm: AlgorithmEd25519},
		PrivateKey: privateKey,
	}
	hmacKey := HMACSigningKey{
		Metadata: TrustedKeyMetadata{KeyID: "response-hmac-key", Algorithm: AlgorithmHMACSHA512},
		Secret:   []byte("response-placement-secret"),
	}

	tests := []struct {
		name   string
		header http.Header
		sign   func(*http.Response) error
	}{
		{
			name: "asymmetric",
			header: http.Header{
				Authorization: []string{"Bearer token"},
				"X-Unrelated": []string{"unchanged"},
			},
			sign: func(res *http.Response) error {
				return NewCavageSigner().SignResponse(res, asymmetricKey, CavageSignaturePlacementAuthorization, nil)
			},
		},
		{
			name: "HMAC with existing signature",
			header: http.Header{
				Authorization: []string{"Bearer token"},
				Signature:     []string{`keyId="existing"`},
				"X-Unrelated": []string{"first", "second"},
			},
			sign: func(res *http.Response) error {
				return NewCavageSigner().SignResponseWithHMAC(res, hmacKey, CavageSignaturePlacementAuthorization, nil)
			},
		},
		{
			name:   "HMAC with nil Header",
			header: nil,
			sign: func(res *http.Response) error {
				return NewCavageSigner().SignResponseWithHMAC(res, hmacKey, CavageSignaturePlacementAuthorization, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			associatedRequest := &http.Request{Host: "example.test", Body: http.NoBody}
			res := &http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				Header:        tt.header,
				Body:          http.NoBody,
				ContentLength: 17,
				Request:       associatedRequest,
			}
			beforeHeader := tt.header.Clone()
			beforeBody := res.Body
			beforeRequest := res.Request

			err := tt.sign(res)
			assertInvalidPlacementError(t, err, "response")

			if !reflect.DeepEqual(res.Header, beforeHeader) {
				t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", res.Header, beforeHeader)
			}
			if res.Status != "200 OK" || res.StatusCode != http.StatusOK || res.ContentLength != 17 {
				t.Fatal("response fields changed after failed signing")
			}
			if res.Body != beforeBody || res.Request != beforeRequest || res.Request != associatedRequest {
				t.Fatal("response Body or associated Request changed after failed signing")
			}
		})
	}
}

func TestCavageSignerAllowsNonSelfReferentialPlacement(t *testing.T) {
	const created = int64(1700000000)
	signer := &CavageSigner{Now: func() time.Time { return time.Unix(created, 0) }}

	t.Run("Authorization placement with default signed headers", func(t *testing.T) {
		req := &http.Request{
			Method: "POST",
			URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/resource", RawQuery: "x=1"},
			Host:   "example.test",
			Header: http.Header{"X-Unrelated": []string{"unchanged"}},
		}
		opts := &CavageSigningOptions{Compatibility: &CavageSigningCompatibility{AlgorithmField: AlgorithmFieldOmitted}}

		if err := signer.SignRequestWithHMAC(req, signingStringHMACSigningKey("authorization-output-key"), CavageSignaturePlacementAuthorization, opts); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		authorization := req.Header.Get(Authorization)
		if !strings.HasPrefix(authorization, "Signature keyId=") {
			t.Fatalf("Authorization = %q, want Signature scheme", authorization)
		}
		if req.Header.Get(Signature) != "" || req.Header.Get("X-Unrelated") != "unchanged" {
			t.Fatalf("unexpected final Header: %#v", req.Header)
		}
		assertCavageHMACSignature(t, authorization, "(request-target): post /resource?x=1\n(created): 1700000000")
	})

	t.Run("Signature placement signs existing Bearer authorization", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
			Host:   "example.test",
			Header: http.Header{Authorization: []string{"Bearer token"}},
		}

		if err := signer.SignRequestWithHMAC(req, signingStringHMACSigningKey("authorization-input-key"), CavageSignaturePlacementSignature, signingStringOptions([]string{"Authorization"})); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		if req.Header.Get(Authorization) != "Bearer token" {
			t.Fatalf("Authorization = %q, want existing Bearer value", req.Header.Get(Authorization))
		}
		if req.Header.Get(Signature) == "" {
			t.Fatal("Signature header is missing")
		}
		assertCavageHMACSignature(t, req.Header.Get(Signature), "authorization: Bearer token")
	})

	t.Run("response Signature placement", func(t *testing.T) {
		res := &http.Response{Header: http.Header{"X-Response": []string{"signed value"}}}
		if err := signer.SignResponseWithHMAC(res, signingStringHMACSigningKey("response-signature-key"), CavageSignaturePlacementSignature, signingStringOptions([]string{"X-Response"})); err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		if res.Header.Get(Signature) == "" || res.Header.Get(Authorization) != "" {
			t.Fatalf("unexpected final Header: %#v", res.Header)
		}
		assertCavageHMACSignature(t, res.Header.Get(Signature), "x-response: signed value")
	})
}

func TestCavageSignerRejectsInvalidPlacementBeforeSigningWork(t *testing.T) {
	algorithm, err := algorithmDefinitionFor(AlgorithmHMACSHA256)
	if err != nil {
		t.Fatalf("algorithmDefinitionFor() failed: %v", err)
	}

	for _, tt := range []struct {
		name      string
		isRequest bool
		detail    string
	}{
		{name: "request self-reference", isRequest: true, detail: "self-reference"},
		{name: "response Authorization placement", detail: "response"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{Authorization: []string{"Bearer token"}}
			beforeHeader := header.Clone()
			resolveCalls := 0
			timeCalls := 0
			signCalls := 0
			message := cavageSigningMessage{
				isRequest: tt.isRequest,
				header:    header,
				resolveFields: func([]string) (string, http.Header, error) {
					resolveCalls++
					return "", header, nil
				},
			}
			signer := &CavageSigner{Now: func() time.Time {
				timeCalls++
				return time.Unix(1700000000, 0)
			}}

			err := signer.signMessage(
				message,
				TrustedKeyMetadata{KeyID: "callback-key", Algorithm: AlgorithmHMACSHA256},
				algorithm,
				CavageSignaturePlacementAuthorization,
				signingStringOptions([]string{"authorization"}),
				func([]byte) ([]byte, error) {
					signCalls++
					return []byte("signature"), nil
				},
			)
			if !errors.Is(err, ErrInvalidSignaturePlacement) || !strings.Contains(err.Error(), tt.detail) {
				t.Fatalf("signMessage() error = %v, want ErrInvalidSignaturePlacement containing %q", err, tt.detail)
			}
			if resolveCalls != 0 || timeCalls != 0 || signCalls != 0 {
				t.Fatalf("calls after placement rejection: resolveFields=%d, Now=%d, sign=%d; want all zero", resolveCalls, timeCalls, signCalls)
			}
			if !reflect.DeepEqual(header, beforeHeader) {
				t.Fatalf("Header changed after placement rejection\ngot:  %#v\nwant: %#v", header, beforeHeader)
			}
		})
	}
}

func TestCavageSignerRejectsCONNECTBeforeCryptographicWork(t *testing.T) {
	algorithm, err := algorithmDefinitionFor(AlgorithmHMACSHA256)
	if err != nil {
		t.Fatalf("algorithmDefinitionFor() failed: %v", err)
	}
	header := http.Header{"X-Unrelated": {"unchanged"}}
	headerBefore := header.Clone()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: "Tunnel.Example:443"},
		Host:   "Tunnel.Example:443",
		Header: header,
	}
	timeCalls := 0
	signCalls := 0
	signer := &CavageSigner{Now: func() time.Time {
		timeCalls++
		return time.Unix(1700000000, 0)
	}}

	err = signer.signMessage(
		requestSigningMessage(req, header),
		TrustedKeyMetadata{KeyID: "connect-callback-key", Algorithm: AlgorithmHMACSHA256},
		algorithm,
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{RequestTarget}),
		func([]byte) ([]byte, error) {
			signCalls++
			return []byte("signature"), nil
		},
	)
	if !errors.Is(err, ErrInvalidHTTPMessage) {
		t.Fatalf("signMessage() error = %v, want ErrInvalidHTTPMessage", err)
	}
	if timeCalls != 0 || signCalls != 0 {
		t.Fatalf("calls after CONNECT rejection: Now=%d, sign=%d; want both zero", timeCalls, signCalls)
	}
	if !reflect.DeepEqual(header, headerBefore) {
		t.Fatalf("Header changed after CONNECT rejection\ngot:  %#v\nwant: %#v", header, headerBefore)
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

func TestCavageSignerRejectsForbiddenHostWithoutMutation(t *testing.T) {
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

	t.Run("response Host field", func(t *testing.T) {
		header := http.Header{"Host": []string{"signed\x00host"}, "X-Unrelated": []string{"unchanged"}}
		beforeHeader := header.Clone()
		associatedRequest := &http.Request{Host: "request.example", Body: http.NoBody}
		res := &http.Response{
			Header:  header,
			Body:    http.NoBody,
			Request: associatedRequest,
		}
		beforeBody := res.Body

		err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("invalid-host-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"host"}),
		)
		if !errors.Is(err, ErrInvalidHTTPMessage) {
			t.Fatalf("SignResponseWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
		}
		var sigreErr *SigreError
		if !errors.As(err, &sigreErr) {
			t.Fatalf("SignResponseWithHMAC() error type = %T, want *SigreError", err)
		}
		for _, want := range []string{`HTTP field "host"`, "value index 0", "byte position 7"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %q, want it to contain %q", err, want)
			}
		}
		if !reflect.DeepEqual(header, beforeHeader) {
			t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", header, beforeHeader)
		}
		if res.Request != associatedRequest || associatedRequest.Host != "request.example" {
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
	fixedTime := time.Unix(1700000000, 0)
	signer := &CavageSigner{Now: func() time.Time { return fixedTime }}

	tests := []struct {
		name      string
		isRequest bool
		isHMAC    bool
		placement CavageSignaturePlacement
		sign      func(*http.Request, *http.Response, CavageSignaturePlacement, *CavageSigningOptions) error
	}{
		{
			name:      "asymmetric request",
			isRequest: true,
			placement: CavageSignaturePlacementSignature,
			sign: func(req *http.Request, _ *http.Response, placement CavageSignaturePlacement, opts *CavageSigningOptions) error {
				return signer.SignRequest(req, asymmetricKey, placement, opts)
			},
		},
		{
			name:      "asymmetric response",
			placement: CavageSignaturePlacementSignature,
			sign: func(_ *http.Request, res *http.Response, placement CavageSignaturePlacement, opts *CavageSigningOptions) error {
				return signer.SignResponse(res, asymmetricKey, placement, opts)
			},
		},
		{
			name:      "HMAC request",
			isRequest: true,
			isHMAC:    true,
			placement: CavageSignaturePlacementAuthorization,
			sign: func(req *http.Request, _ *http.Response, placement CavageSignaturePlacement, opts *CavageSigningOptions) error {
				return signer.SignRequestWithHMAC(req, hmacKey, placement, opts)
			},
		},
		{
			name:      "HMAC response",
			isHMAC:    true,
			placement: CavageSignaturePlacementSignature,
			sign: func(_ *http.Request, res *http.Response, placement CavageSignaturePlacement, opts *CavageSigningOptions) error {
				return signer.SignResponseWithHMAC(res, hmacKey, placement, opts)
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
			t.Run("Host signing failure", func(t *testing.T) {
				forbiddenHost := "signed\x00host"
				if tt.isRequest {
					forbiddenHost = "signed\rhost"
				}
				req, res := newMessages(forbiddenHost)
				beforeURL := *req.URL
				beforeRequestBody := req.Body
				beforeResponseBody := res.Body
				beforeAssociatedRequest := res.Request

				err := tt.sign(req, res, tt.placement, signingStringOptions([]string{"host"}))
				wantError := ErrSignedHeaderMissing
				if tt.isRequest {
					wantError = ErrInvalidHTTPMessage
				}
				var sigreErr *SigreError
				isSigreError := errors.As(err, &sigreErr)
				if !errors.Is(err, wantError) {
					t.Fatalf("signing error = %v, want %v", err, wantError)
				}
				if !isSigreError {
					t.Fatalf("signing error type = %T, want *SigreError", err)
				}
				if tt.isRequest {
					for _, want := range []string{"failed to create signing string", `HTTP field "host"`, "value index 0", "byte position 7"} {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("error = %q, want it to contain %q", err, want)
						}
					}
				}

				var gotHeader http.Header
				if tt.isRequest {
					gotHeader = req.Header
				} else {
					gotHeader = res.Header
				}
				if gotHeader != nil {
					t.Fatalf("Header = %#v after failed signing, want nil", gotHeader)
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
				opts := signingStringOptions([]string{"host"})
				wantSigningString := "host: example.test"
				if !tt.isRequest {
					opts = signingStringOptions([]string{Created})
					wantSigningString = "(created): 1700000000"
				}
				if err := tt.sign(req, res, tt.placement, opts); err != nil {
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
					assertCavageHMACSignature(t, header.Get(field), wantSigningString)
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
		{
			name:       "asterisk form",
			method:     http.MethodOptions,
			requestURI: "*",
			want:       "(request-target): options *",
		},
		{
			name:       "origin-form OPTIONS root",
			method:     http.MethodOptions,
			requestURI: "/",
			want:       "(request-target): options /",
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

func TestCavageRequestVerifierHandlesAbsoluteFormRequestTarget(t *testing.T) {
	readAbsoluteRequest := func(t *testing.T, method, rawRequestTarget string) *http.Request {
		t.Helper()
		raw := method + " " + rawRequestTarget + " HTTP/1.1\r\n" +
			"Host: ignored.example\r\n\r\n"
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatalf("http.ReadRequest() failed: %v", err)
		}
		return req
	}

	tests := []struct {
		name             string
		method           string
		rawRequestTarget string
		wantScheme       string
		wantPath         string
		wantRawPath      string
		wantRawQuery     string
		wantForceQuery   bool
		wantTarget       string
	}{
		{
			name:             "empty path",
			method:           http.MethodGet,
			rawRequestTarget: "http://example.test",
			wantScheme:       "http",
			wantTarget:       "/",
		},
		{
			name:             "empty path and trailing empty query",
			method:           http.MethodGet,
			rawRequestTarget: "http://example.test?",
			wantScheme:       "http",
			wantForceQuery:   true,
			wantTarget:       "/?",
		},
		{
			name:             "empty path and raw query",
			method:           http.MethodGet,
			rawRequestTarget: "http://example.test?x=1",
			wantScheme:       "http",
			wantRawQuery:     "x=1",
			wantTarget:       "/?x=1",
		},
		{
			name:             "escaped path and ordered raw query",
			method:           http.MethodGet,
			rawRequestTarget: "http://Proxy.Example/a%2Fb?b=2&a=%2F&a=0",
			wantScheme:       "http",
			wantPath:         "/a/b",
			wantRawPath:      "/a%2Fb",
			wantRawQuery:     "b=2&a=%2F&a=0",
			wantTarget:       "/a%2Fb?b=2&a=%2F&a=0",
		},
		{
			name:             "server-wide OPTIONS over HTTP",
			method:           http.MethodOptions,
			rawRequestTarget: "http://example.test",
			wantScheme:       "http",
			wantTarget:       "*",
		},
		{
			name:             "server-wide OPTIONS over HTTPS",
			method:           http.MethodOptions,
			rawRequestTarget: "https://example.test",
			wantScheme:       "https",
			wantTarget:       "*",
		},
		{
			name:             "server-wide OPTIONS with port",
			method:           http.MethodOptions,
			rawRequestTarget: "http://example.test:8001",
			wantScheme:       "http",
			wantTarget:       "*",
		},
		{
			name:             "OPTIONS with non-HTTP scheme",
			method:           http.MethodOptions,
			rawRequestTarget: "ftp://example.test",
			wantScheme:       "ftp",
			wantTarget:       "/",
		},
		{
			name:             "lowercase options method",
			method:           "options",
			rawRequestTarget: "http://example.test",
			wantScheme:       "http",
			wantTarget:       "/",
		},
		{
			name:             "OPTIONS with explicit root path",
			method:           http.MethodOptions,
			rawRequestTarget: "http://example.test/",
			wantScheme:       "http",
			wantPath:         "/",
			wantTarget:       "/",
		},
		{
			name:             "OPTIONS with query component",
			method:           http.MethodOptions,
			rawRequestTarget: "http://example.test?x=1",
			wantScheme:       "http",
			wantRawQuery:     "x=1",
			wantTarget:       "/?x=1",
		},
		{
			name:             "OPTIONS with empty query component",
			method:           http.MethodOptions,
			rawRequestTarget: "http://example.test?",
			wantScheme:       "http",
			wantForceQuery:   true,
			wantTarget:       "/?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := readAbsoluteRequest(t, tt.method, tt.rawRequestTarget)
			defer req.Body.Close()

			if req.RequestURI != tt.rawRequestTarget {
				t.Fatalf("RequestURI = %q, want %q", req.RequestURI, tt.rawRequestTarget)
			}
			if req.URL.Scheme != tt.wantScheme || req.URL.Path != tt.wantPath || req.URL.RawPath != tt.wantRawPath || req.URL.RawQuery != tt.wantRawQuery || req.URL.ForceQuery != tt.wantForceQuery {
				t.Fatalf("parsed URL = %#v, want Scheme=%q Path=%q RawPath=%q RawQuery=%q ForceQuery=%t", req.URL, tt.wantScheme, tt.wantPath, tt.wantRawPath, tt.wantRawQuery, tt.wantForceQuery)
			}

			wantSigningString := "(request-target): " + strings.ToLower(tt.method) + " " + tt.wantTarget
			req.Header.Set(Signature, fixedCavageHMACHeader(t, wantSigningString, RequestTarget))
			verifier, signature := parseSigningStringRequest(t, req)
			if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
				t.Fatalf("VerifyHMAC() failed: %v", err)
			}
		})
	}

	t.Run("snapshot is independent from the request", func(t *testing.T) {
		const rawRequestTarget = "http://Proxy.Example/a%2Fb?b=2&a=%2F&a=0"
		const wantSigningString = "(request-target): get /a%2Fb?b=2&a=%2F&a=0"
		req := readAbsoluteRequest(t, http.MethodGet, rawRequestTarget)
		defer req.Body.Close()
		req.Header.Set(Signature, fixedCavageHMACHeader(t, wantSigningString, RequestTarget))
		headerBefore := req.Header.Clone()
		urlBefore := *req.URL
		bodyBefore := req.Body

		verifier, signature := parseSigningStringRequest(t, req)
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("VerifyHMAC() failed: %v", err)
		}
		if !reflect.DeepEqual(req.Header, headerBefore) || !reflect.DeepEqual(req.URL, &urlBefore) || req.Body != bodyBefore || req.Method != http.MethodGet || req.RequestURI != rawRequestTarget {
			t.Fatal("ParseRequest() modified the absolute-form request")
		}

		req.Method = http.MethodPost
		req.RequestURI = "/changed"
		req.URL.Path = "/changed"
		req.URL.RawPath = ""
		req.URL.RawQuery = "changed=true"
		req.URL.ForceQuery = false
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("request mutation changed the parsed snapshot: %v", err)
		}
	})
}

func TestCavageRequestVerifierRejectsAbsoluteURIRequestTargetSignature(t *testing.T) {
	const rawRequestTarget = "http://Proxy.Example/a%2Fb?b=2&a=%2F&a=0"
	raw := "GET " + rawRequestTarget + " HTTP/1.1\r\nHost: ignored.example\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("http.ReadRequest() failed: %v", err)
	}
	defer req.Body.Close()

	oldSigningString := "(request-target): get " + rawRequestTarget
	req.Header.Set(Signature, fixedCavageHMACHeader(t, oldSigningString, RequestTarget))
	verifier, signature := parseSigningStringRequest(t, req)
	if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); !errors.Is(err, ErrVerification) {
		t.Fatalf("VerifyHMAC() error = %v, want ErrVerification for the absolute-URI signing form", err)
	}
}

func TestCavageRequestVerifierRejectsCONNECTRequestTarget(t *testing.T) {
	for _, rawRequestTarget := range []string{"Tunnel.Example:443", "/_goRPC_"} {
		t.Run(rawRequestTarget, func(t *testing.T) {
			raw := "CONNECT " + rawRequestTarget + " HTTP/1.1\r\n" +
				"Host: Tunnel.Example:443\r\n\r\n"
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
			if err != nil {
				t.Fatalf("http.ReadRequest() failed: %v", err)
			}
			defer req.Body.Close()
			body := &receivedCountingBody{}
			req.Body = body
			req.Header.Set(Signature, fixedCavageHMACHeader(t, "(request-target): connect invalid", RequestTarget))
			headerBefore := req.Header.Clone()
			urlBefore := *req.URL

			verifier, err := NewCavageVerifier(signingStringVerificationOptions())
			if err != nil {
				t.Fatalf("NewCavageVerifier() failed: %v", err)
			}
			signature, err := verifier.ParseRequest(req)
			if signature != nil {
				t.Fatal("ParseRequest() returned a snapshot for CONNECT")
			}
			assertInvalidRequestTargetError(t, err, "CONNECT")
			if !reflect.DeepEqual(req.Header, headerBefore) || !reflect.DeepEqual(req.URL, &urlBefore) || req.Body != body || req.Method != http.MethodConnect || req.RequestURI != rawRequestTarget {
				t.Fatal("failed CONNECT parsing modified the request")
			}
			if body.reads != 0 || body.closes != 0 {
				t.Fatalf("failed CONNECT parsing accessed Body: reads=%d closes=%d", body.reads, body.closes)
			}
		})
	}
}

func TestCavageResponseVerifierRejectsAssociatedCONNECTRequestTarget(t *testing.T) {
	body := &receivedCountingBody{}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: "Tunnel.Example:443"},
		Host:   "Tunnel.Example:443",
		Body:   body,
	}
	res := &http.Response{
		Request: req,
		Header: http.Header{
			Signature: {fixedCavageHMACHeader(t, "(request-target): connect invalid", RequestTarget)},
		},
		Body: body,
	}
	headerBefore := res.Header.Clone()
	urlBefore := *req.URL

	verifier, err := NewCavageVerifier(signingStringVerificationOptions())
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	signature, err := verifier.ParseResponse(res)
	if signature != nil {
		t.Fatal("ParseResponse() returned a snapshot for an associated CONNECT request")
	}
	assertInvalidRequestTargetError(t, err, "CONNECT")
	if !reflect.DeepEqual(res.Header, headerBefore) || res.Body != body || res.Request != req || !reflect.DeepEqual(req.URL, &urlBefore) || req.Method != http.MethodConnect || req.RequestURI != "" {
		t.Fatal("failed response parsing modified the response or associated CONNECT request")
	}
	if body.reads != 0 || body.closes != 0 {
		t.Fatalf("failed response parsing accessed Body: reads=%d closes=%d", body.reads, body.closes)
	}
}

func TestCavageCONNECTAllowedWithoutRequestTarget(t *testing.T) {
	const wantSigningString = "x-test: value"
	opts := signingStringOptions([]string{"x-test"})

	t.Run("request signer", func(t *testing.T) {
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: "Tunnel.Example:443"},
			Host:   "Tunnel.Example:443",
			Header: http.Header{"X-Test": {"value"}},
		}
		if err := NewCavageSigner().SignRequestWithHMAC(req, signingStringHMACSigningKey("connect-no-target-key"), CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, req.Header.Get(Signature), wantSigningString)
	})

	t.Run("response signer", func(t *testing.T) {
		req := &http.Request{
			Method:     http.MethodConnect,
			RequestURI: "Tunnel.Example:443",
			URL:        &url.URL{Host: "Tunnel.Example:443"},
			Host:       "Tunnel.Example:443",
		}
		res := &http.Response{Request: req, Header: http.Header{"X-Test": {"value"}}}
		if err := NewCavageSigner().SignResponseWithHMAC(res, signingStringHMACSigningKey("response-connect-no-target-key"), CavageSignaturePlacementSignature, opts); err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, res.Header.Get(Signature), wantSigningString)
	})

	t.Run("request verifier", func(t *testing.T) {
		raw := "CONNECT Tunnel.Example:443 HTTP/1.1\r\nHost: Tunnel.Example:443\r\nX-Test: value\r\n\r\n"
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatalf("http.ReadRequest() failed: %v", err)
		}
		defer req.Body.Close()
		req.Header.Set(Signature, fixedCavageHMACHeader(t, wantSigningString, "x-test"))
		verifier, signature := parseSigningStringRequest(t, req)
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("VerifyHMAC() failed: %v", err)
		}
	})

	t.Run("response verifier", func(t *testing.T) {
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: "Tunnel.Example:443"},
			Host:   "Tunnel.Example:443",
		}
		res := &http.Response{
			Request: req,
			Header: http.Header{
				"X-Test":  {"value"},
				Signature: {fixedCavageHMACHeader(t, wantSigningString, "x-test")},
			},
		}
		verifier, signature := parseSigningStringResponse(t, res)
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("VerifyHMAC() failed: %v", err)
		}
	})
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

func TestCavageResponseRequestTargetUsesReceivedAbsoluteForm(t *testing.T) {
	const rawRequestTarget = "http://Proxy.Example/a%2Fb?b=2&a=%2F&a=0"
	const wantSigningString = "(request-target): patch /a%2Fb?b=2&a=%2F&a=0"

	newAssociatedRequest := func(t *testing.T) *http.Request {
		t.Helper()
		raw := "PaTcH " + rawRequestTarget + " HTTP/1.1\r\nHost: ignored.example\r\n\r\n"
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatalf("http.ReadRequest() failed: %v", err)
		}
		return req
	}

	t.Run("signer", func(t *testing.T) {
		req := newAssociatedRequest(t)
		defer req.Body.Close()
		requestHeaderBefore := req.Header.Clone()
		requestURLBefore := *req.URL
		requestBodyBefore := req.Body
		res := &http.Response{Request: req, Header: make(http.Header)}

		err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("response-absolute-form-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{RequestTarget}),
		)
		if err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, res.Header.Get(Signature), wantSigningString)
		if !reflect.DeepEqual(req.Header, requestHeaderBefore) || !reflect.DeepEqual(req.URL, &requestURLBefore) || req.Body != requestBodyBefore || req.Method != "PaTcH" || req.RequestURI != rawRequestTarget {
			t.Fatal("SignResponseWithHMAC() modified the associated request")
		}
	})

	t.Run("verifier snapshot", func(t *testing.T) {
		req := newAssociatedRequest(t)
		defer req.Body.Close()
		res := &http.Response{
			Request: req,
			Header: http.Header{
				Signature: {fixedCavageHMACHeader(t, wantSigningString, RequestTarget)},
			},
		}
		verifier, signature := parseSigningStringResponse(t, res)
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("VerifyHMAC() failed: %v", err)
		}

		req.Method = http.MethodDelete
		req.RequestURI = "/changed"
		req.URL.Path = "/changed"
		req.URL.RawPath = ""
		req.URL.RawQuery = "changed=true"
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("associated request mutation changed the parsed response snapshot: %v", err)
		}
	})

	t.Run("server-wide OPTIONS", func(t *testing.T) {
		const optionsSigningString = "(request-target): options *"
		newOptionsRequest := func(t *testing.T) *http.Request {
			t.Helper()
			raw := "OPTIONS http://example.test HTTP/1.1\r\nHost: example.test\r\n\r\n"
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
			if err != nil {
				t.Fatalf("http.ReadRequest() failed: %v", err)
			}
			return req
		}

		t.Run("signer", func(t *testing.T) {
			req := newOptionsRequest(t)
			defer req.Body.Close()
			res := &http.Response{Request: req, Header: make(http.Header)}
			if err := NewCavageSigner().SignResponseWithHMAC(
				res,
				signingStringHMACSigningKey("response-options-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{RequestTarget}),
			); err != nil {
				t.Fatalf("SignResponseWithHMAC() failed: %v", err)
			}
			assertCavageHMACSignature(t, res.Header.Get(Signature), optionsSigningString)
		})

		t.Run("verifier", func(t *testing.T) {
			req := newOptionsRequest(t)
			defer req.Body.Close()
			res := &http.Response{
				Request: req,
				Header: http.Header{
					Signature: {fixedCavageHMACHeader(t, optionsSigningString, RequestTarget)},
				},
			}
			verifier, signature := parseSigningStringResponse(t, res)
			if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
				t.Fatalf("VerifyHMAC() failed: %v", err)
			}
		})
	})
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

func TestCavageVerifierPreservesExpiresDecimalSignature(t *testing.T) {
	const signingString = "(expires): 1.1234567890"
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	mac := hmac.New(sha512.New, signingStringTestSecret)
	if _, err := mac.Write([]byte(signingString)); err != nil {
		t.Fatalf("failed to calculate fixed HMAC: %v", err)
	}
	verifier, err := NewCavageVerifier(&CavageVerificationOptions{
		Now: func() time.Time { return time.Unix(1, 123456789) },
	})
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}

	for _, test := range []struct {
		name      string
		signature []byte
		parse     func(http.Header) (*CavageSignature, error)
		verify    func(*CavageSignature) error
	}{
		{
			name:      "Ed25519 request",
			signature: ed25519.Sign(privateKey, []byte(signingString)),
			parse: func(header http.Header) (*CavageSignature, error) {
				return verifier.ParseRequest(&http.Request{Header: header})
			},
			verify: func(signature *CavageSignature) error {
				return verifier.Verify(signature, VerificationKey{
					Metadata:  TrustedKeyMetadata{KeyID: "test-key", Algorithm: AlgorithmEd25519},
					PublicKey: privateKey.Public(),
				})
			},
		},
		{
			name:      "HMAC response",
			signature: mac.Sum(nil),
			parse: func(header http.Header) (*CavageSignature, error) {
				return verifier.ParseResponse(&http.Response{Header: header})
			},
			verify: func(signature *CavageSignature) error {
				return verifier.VerifyHMAC(signature, HMACVerificationKey{
					Metadata: TrustedKeyMetadata{KeyID: "test-key", Algorithm: AlgorithmHMACSHA512},
					Secret:   signingStringTestSecret,
				})
			},
		},
	} {
		for _, value := range []string{"1.1234567890", "1.123456789"} {
			t.Run(test.name+"/"+value, func(t *testing.T) {
				parameters := `keyId="test-key",algorithm="hs2019",headers="(expires)",expires=` + value +
					`,signature="` + base64.StdEncoding.EncodeToString(test.signature) + `"`
				header := http.Header{Signature: {parameters}}
				signature, err := test.parse(header)
				if err != nil {
					t.Fatalf("parse failed: %v", err)
				}
				expires, present := signature.Expires()
				if !present || !expires.Equal(time.Unix(1, 123456789)) {
					t.Fatalf("Expires() = %v/%t, want %v/true", expires, present, time.Unix(1, 123456789))
				}
				if header.Get(Signature) != parameters {
					t.Fatal("parsing modified the received Signature field")
				}
				err = test.verify(signature)
				if value == "1.123456789" {
					if !errors.Is(err, ErrVerification) {
						t.Fatalf("verification error = %v, want ErrVerification", err)
					}
					var packageError *SigreError
					if !errors.As(err, &packageError) {
						t.Fatalf("verification error is not wrapped by *SigreError: %v", err)
					}
				} else if err != nil {
					t.Fatalf("verification failed: %v", err)
				}
			})
		}
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
	f.Add(http.MethodGet, "/a/b", "/a%2Fb", "x=%2F", false)
	f.Add(http.MethodGet, "", "", "", false)
	f.Add(http.MethodHead, "/empty", "", "", true)
	f.Add(http.MethodGet, "/search", "invalid%zz", "b=2&a=1&a=0", false)
	f.Add(http.MethodOptions, "*", "", "", false)
	f.Add(http.MethodConnect, "", "", "", false)

	f.Fuzz(func(t *testing.T, method, path, rawPath, rawQuery string, forceQuery bool) {
		u := &url.URL{
			Path:       path,
			RawPath:    rawPath,
			RawQuery:   rawQuery,
			ForceQuery: forceQuery,
		}
		got, err := outgoingRequestTarget(&http.Request{Method: method, URL: u})
		if method == http.MethodConnect {
			if !errors.Is(err, ErrInvalidHTTPMessage) || got != "" {
				t.Fatalf("outgoingRequestTarget() = %q, %v; want empty target and ErrInvalidHTTPMessage for CONNECT", got, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("outgoingRequestTarget() failed: %v", err)
		}
		if want := u.RequestURI(); got != want {
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

func assertInvalidRequestTargetError(t *testing.T, err error, form string) {
	t.Helper()
	if !errors.Is(err, ErrInvalidHTTPMessage) {
		t.Fatalf("error = %v, want ErrInvalidHTTPMessage", err)
	}
	var sigreErr *SigreError
	if !errors.As(err, &sigreErr) {
		t.Fatalf("error type = %T, want *SigreError", err)
	}
	if !strings.Contains(err.Error(), form) {
		t.Errorf("error = %q, want it to contain %q", err, form)
	}
}

func assertInvalidPlacementError(t *testing.T, err error, detail string) {
	t.Helper()
	if !errors.Is(err, ErrInvalidSignaturePlacement) {
		t.Fatalf("signing error = %v, want ErrInvalidSignaturePlacement", err)
	}
	var sigreErr *SigreError
	if !errors.As(err, &sigreErr) {
		t.Fatalf("signing error type = %T, want *SigreError", err)
	}
	if !strings.Contains(err.Error(), detail) {
		t.Fatalf("signing error = %q, want it to contain %q", err, detail)
	}
}
