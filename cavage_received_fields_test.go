package sigre

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestCavageVerifierReconstructsParsedRequestTransferEncoding(t *testing.T) {
	want := "transfer-encoding: chunked"
	raw := "POST /chunked HTTP/1.1\r\n" +
		"Host: request.example\r\n" +
		"Transfer-Encoding: Chunked\r\n" +
		"Signature: " + fixedCavageHMACHeader(t, want, "transfer-encoding") + "\r\n" +
		"\r\n" +
		"0\r\n\r\n"
	req := readCavageRequest(t, raw)
	if _, ok := req.Header["Transfer-Encoding"]; ok {
		t.Fatal("http.ReadRequest() retained Transfer-Encoding in Header")
	}
	if !slices.Equal(req.TransferEncoding, []string{"chunked"}) {
		t.Fatalf("TransferEncoding = %q, want [chunked]", req.TransferEncoding)
	}

	verifyCavageRequestHMAC(t, req)
}

func TestCavageVerifierReconstructsParsedRequestTrailer(t *testing.T) {
	t.Run("single declaration", func(t *testing.T) {
		want := "trailer: X-Trace"
		raw := "POST /trailer HTTP/1.1\r\n" +
			"Host: request.example\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Trailer: X-Trace\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, want, "trailer") + "\r\n" +
			"\r\n" +
			"0\r\n\r\n"
		req := readCavageRequest(t, raw)
		if _, ok := req.Header["Trailer"]; ok {
			t.Fatal("http.ReadRequest() retained chunked Trailer in Header")
		}
		if !reflect.DeepEqual(req.Trailer, http.Header{"X-Trace": nil}) {
			t.Fatalf("Trailer = %#v, want X-Trace declaration", req.Trailer)
		}

		verifyCavageRequestHMAC(t, req)
	})

	t.Run("canonicalized sorted declaration", func(t *testing.T) {
		want := "trailer: X-Alpha,X-Zeta"
		raw := "POST /trailers HTTP/1.1\r\n" +
			"Host: request.example\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Trailer: X-Zeta, x-alpha\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, want, "trailer") + "\r\n" +
			"\r\n" +
			"0\r\n\r\n"
		req := readCavageRequest(t, raw)
		if !reflect.DeepEqual(req.Trailer, http.Header{"X-Alpha": nil, "X-Zeta": nil}) {
			t.Fatalf("Trailer = %#v, want canonical declaration keys", req.Trailer)
		}
		verifyCavageRequestHMAC(t, req)
	})
}

func TestCavageVerifierRejectsConsumedParsedRequestTrailer(t *testing.T) {
	t.Run("declared and undeclared trailer fields", func(t *testing.T) {
		raw := "POST /consumed-trailer HTTP/1.1\r\n" +
			"Host: request.example\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Trailer: X-Trace\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, "trailer: X-Trace", "trailer") + "\r\n" +
			"\r\n" +
			"1\r\na\r\n" +
			"0\r\n" +
			"X-Trace: abc\r\n" +
			"X-Extra: undeclared\r\n" +
			"\r\n"
		req := readCavageRequest(t, raw)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("io.ReadAll(Body) failed: %v", err)
		}
		if string(body) != "a" {
			t.Fatalf("Body = %q, want %q", body, "a")
		}
		if !reflect.DeepEqual(req.Trailer, http.Header{"X-Extra": {"undeclared"}, "X-Trace": {"abc"}}) {
			t.Fatalf("Trailer after Body EOF = %#v, want received trailer fields", req.Trailer)
		}
		assertCavageRequestParseError(t, req, ErrSignedHeaderMissing)
	})

	t.Run("undeclared trailer without declaration", func(t *testing.T) {
		raw := "POST /undeclared-trailer HTTP/1.1\r\n" +
			"Host: request.example\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, "trailer: X-Sneaky", "trailer") + "\r\n" +
			"\r\n" +
			"1\r\na\r\n" +
			"0\r\n" +
			"X-Sneaky: injected\r\n" +
			"\r\n"
		req := readCavageRequest(t, raw)
		if _, err := io.ReadAll(req.Body); err != nil {
			t.Fatalf("io.ReadAll(Body) failed: %v", err)
		}
		if !reflect.DeepEqual(req.Trailer, http.Header{"X-Sneaky": {"injected"}}) {
			t.Fatalf("Trailer after Body EOF = %#v, want received undeclared trailer", req.Trailer)
		}
		assertCavageRequestParseError(t, req, ErrSignedHeaderMissing)
	})
}

func TestCavageVerifierUsesParsedRequestHost(t *testing.T) {
	for _, host := range []string{"Mixed.Example:8443", "[2001:DB8::1]:8443"} {
		t.Run(host, func(t *testing.T) {
			want := "host: " + host
			raw := "GET /host HTTP/1.1\r\n" +
				"Host: " + host + "\r\n" +
				"Signature: " + fixedCavageHMACHeader(t, want, "host") + "\r\n" +
				"\r\n"
			req := readCavageRequest(t, raw)
			if req.Host != host {
				t.Fatalf("Host = %q, want %q", req.Host, host)
			}
			if _, ok := req.Header["Host"]; ok {
				t.Fatal("http.ReadRequest() retained Host in Header")
			}

			req.Header["Host"] = []string{"changed.example"}
			verifyCavageRequestHMAC(t, req)
		})
	}
}

func TestCavageVerifierRequestManagedFieldPriority(t *testing.T) {
	t.Run("missing dedicated Host does not use Header", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"Host":      {"header.example"},
				"Signature": {fixedCavageHMACHeader(t, "host: header.example", "host")},
			},
		}
		verifier := newSigningStringVerifier(t)
		_, err := verifier.ParseRequest(req)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("ParseRequest() error = %v, want ErrSignedHeaderMissing", err)
		}
	})

	t.Run("Host has no verification fallback", func(t *testing.T) {
		wrong := "host: changed.example"
		raw := "GET /host HTTP/1.1\r\n" +
			"Host: wire.example\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, wrong, "host") + "\r\n" +
			"\r\n"
		req := readCavageRequest(t, raw)
		req.Header["Host"] = []string{"changed.example"}
		verifier := newSigningStringVerifier(t)
		signature, err := verifier.ParseRequest(req)
		if err != nil {
			t.Fatalf("ParseRequest() failed: %v", err)
		}
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); !errors.Is(err, ErrVerification) {
			t.Fatalf("VerifyHMAC() error = %v, want ErrVerification", err)
		}
	})

	t.Run("Transfer-Encoding keeps slice order", func(t *testing.T) {
		want := "transfer-encoding: gzip, chunked"
		req := &http.Request{
			Header: http.Header{
				"Signature":         {fixedCavageHMACHeader(t, want, "transfer-encoding")},
				"Transfer-Encoding": {"identity"},
			},
			TransferEncoding: []string{"gzip", "chunked"},
		}
		verifyCavageRequestHMAC(t, req)
	})

	t.Run("missing dedicated Transfer-Encoding does not use Header", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"Signature":         {fixedCavageHMACHeader(t, "transfer-encoding: identity", "transfer-encoding")},
				"Transfer-Encoding": {"identity"},
			},
		}
		verifier := newSigningStringVerifier(t)
		_, err := verifier.ParseRequest(req)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("ParseRequest() error = %v, want ErrSignedHeaderMissing", err)
		}
	})

	t.Run("Transfer-Encoding has no verification fallback", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"Signature":         {fixedCavageHMACHeader(t, "transfer-encoding: identity", "transfer-encoding")},
				"Transfer-Encoding": {"identity"},
			},
			TransferEncoding: []string{"chunked"},
		}
		verifier := newSigningStringVerifier(t)
		signature, err := verifier.ParseRequest(req)
		if err != nil {
			t.Fatalf("ParseRequest() failed: %v", err)
		}
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); !errors.Is(err, ErrVerification) {
			t.Fatalf("VerifyHMAC() error = %v, want ErrVerification", err)
		}
	})

	t.Run("Trailer map overrides Header", func(t *testing.T) {
		want := "trailer: X-Alpha,X-Zeta"
		req := &http.Request{
			Header: http.Header{
				"Signature": {fixedCavageHMACHeader(t, want, "trailer")},
				"Trailer":   {"X-Ignored"},
			},
			Trailer: http.Header{"x-zeta": nil, "X-Alpha": nil},
		}
		verifyCavageRequestHMAC(t, req)
	})

	t.Run("Trailer has no verification fallback", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"Signature": {fixedCavageHMACHeader(t, "trailer: X-Ignored", "trailer")},
				"Trailer":   {"X-Ignored"},
			},
			Trailer: http.Header{"X-Trace": nil},
		}
		verifier := newSigningStringVerifier(t)
		signature, err := verifier.ParseRequest(req)
		if err != nil {
			t.Fatalf("ParseRequest() failed: %v", err)
		}
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); !errors.Is(err, ErrVerification) {
			t.Fatalf("VerifyHMAC() error = %v, want ErrVerification", err)
		}
	})
}

func TestCavageVerifierDoesNotResolveUnsignedManagedFields(t *testing.T) {
	want := "x-test: unchanged"
	header := http.Header{
		"Signature": {fixedCavageHMACHeader(t, want, "x-test")},
		"X-Test":    {"unchanged"},
	}

	req := &http.Request{
		Host:             "invalid\nrequest-host",
		Header:           header.Clone(),
		TransferEncoding: []string{"invalid\nencoding"},
		Trailer:          http.Header{"Invalid\nTrailer": nil},
	}
	verifyCavageRequestHMAC(t, req)

	res := &http.Response{
		Request:          &http.Request{Host: "invalid\nassociated-host"},
		Header:           header.Clone(),
		TransferEncoding: []string{"invalid\nencoding"},
		Trailer:          http.Header{"Invalid\nTrailer": nil},
	}
	verifyCavageResponseHMAC(t, res)
}

func TestCavageVerifierUsesParsedRequestContentLengthHeader(t *testing.T) {
	t.Run("preserves lexical representation", func(t *testing.T) {
		want := "content-length: 003"
		raw := "POST /length HTTP/1.1\r\n" +
			"Host: request.example\r\n" +
			"Content-Length: 003\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, want, "content-length") + "\r\n" +
			"\r\n" +
			"abc"
		req := readCavageRequest(t, raw)
		if req.ContentLength != 3 || !slices.Equal(req.Header["Content-Length"], []string{"003"}) {
			t.Fatalf("ContentLength/Header = %d/%q, want 3/[003]", req.ContentLength, req.Header["Content-Length"])
		}
		verifyCavageRequestHMAC(t, req)
	})

	t.Run("does not synthesize absent zero", func(t *testing.T) {
		raw := "GET /no-length HTTP/1.1\r\n" +
			"Host: request.example\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, "content-length: 0", "content-length") + "\r\n" +
			"\r\n"
		req := readCavageRequest(t, raw)
		if req.ContentLength != 0 {
			t.Fatalf("ContentLength = %d, want 0", req.ContentLength)
		}
		assertCavageRequestParseError(t, req, ErrSignedHeaderMissing)
	})

	t.Run("does not synthesize removed chunked length", func(t *testing.T) {
		raw := "POST /chunked-length HTTP/1.1\r\n" +
			"Host: request.example\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Content-Length: 003\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, "content-length: 003", "content-length") + "\r\n" +
			"\r\n" +
			"0\r\n\r\n"
		req := readCavageRequest(t, raw)
		if req.ContentLength != -1 {
			t.Fatalf("ContentLength = %d, want -1", req.ContentLength)
		}
		if _, ok := req.Header["Content-Length"]; ok {
			t.Fatal("http.ReadRequest() retained Content-Length overridden by chunked encoding")
		}
		assertCavageRequestParseError(t, req, ErrSignedHeaderMissing)
	})
}

func TestCavageVerifierParsedRequestNormalFieldOrder(t *testing.T) {
	want := "x-order: first, second"
	raw := "GET /headers HTTP/1.1\r\n" +
		"Host: request.example\r\n" +
		"X-Order: first\r\n" +
		"X-Order: second\r\n" +
		"Signature: " + fixedCavageHMACHeader(t, want, "x-order") + "\r\n" +
		"\r\n"
	req := readCavageRequest(t, raw)
	if !slices.Equal(req.Header["X-Order"], []string{"first", "second"}) {
		t.Fatalf("X-Order = %q, want [first second]", req.Header["X-Order"])
	}
	verifyCavageRequestHMAC(t, req)
}

func TestCavageVerifierReconstructsParsedResponseTransferEncoding(t *testing.T) {
	want := "transfer-encoding: chunked"
	raw := "HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: Chunked\r\n" +
		"Signature: " + fixedCavageHMACHeader(t, want, "transfer-encoding") + "\r\n" +
		"\r\n" +
		"0\r\n\r\n"
	res := readCavageResponse(t, raw, http.MethodGet)
	if _, ok := res.Header["Transfer-Encoding"]; ok {
		t.Fatal("http.ReadResponse() retained Transfer-Encoding in Header")
	}
	if !slices.Equal(res.TransferEncoding, []string{"chunked"}) {
		t.Fatalf("TransferEncoding = %q, want [chunked]", res.TransferEncoding)
	}

	verifyCavageResponseHMAC(t, res)
}

func TestCavageVerifierReconstructsParsedResponseTrailer(t *testing.T) {
	want := "trailer: X-Alpha,X-Zeta"
	raw := "HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Trailer: X-Zeta, x-alpha\r\n" +
		"Signature: " + fixedCavageHMACHeader(t, want, "trailer") + "\r\n" +
		"\r\n" +
		"0\r\n\r\n"
	res := readCavageResponse(t, raw, http.MethodGet)
	if _, ok := res.Header["Trailer"]; ok {
		t.Fatal("http.ReadResponse() retained chunked Trailer in Header")
	}
	if !reflect.DeepEqual(res.Trailer, http.Header{"X-Alpha": nil, "X-Zeta": nil}) {
		t.Fatalf("Trailer = %#v, want canonical declaration keys", res.Trailer)
	}

	verifyCavageResponseHMAC(t, res)
}

func TestCavageVerifierResponseManagedFieldPriority(t *testing.T) {
	t.Run("Transfer-Encoding slice overrides Header", func(t *testing.T) {
		want := "transfer-encoding: chunked"
		res := &http.Response{
			Header: http.Header{
				"Signature":         {fixedCavageHMACHeader(t, want, "transfer-encoding")},
				"Transfer-Encoding": {"identity"},
			},
			TransferEncoding: []string{"chunked"},
		}
		verifyCavageResponseHMAC(t, res)
	})

	t.Run("Trailer map overrides Header", func(t *testing.T) {
		want := "trailer: X-Alpha,X-Zeta"
		res := &http.Response{
			Header: http.Header{
				"Signature": {fixedCavageHMACHeader(t, want, "trailer")},
				"Trailer":   {"X-Ignored"},
			},
			Trailer: http.Header{"x-zeta": nil, "X-Alpha": nil},
		}
		verifyCavageResponseHMAC(t, res)
	})
}

func TestCavageVerifierUsesParsedResponseContentLengthHeader(t *testing.T) {
	tests := []struct {
		name              string
		status            string
		contentLength     string
		body              string
		wantParsedLength  int64
		wantSigningString string
	}{
		{
			name:              "positive lexical representation",
			status:            "200 OK",
			contentLength:     "003",
			body:              "abc",
			wantParsedLength:  3,
			wantSigningString: "content-length: 003",
		},
		{
			name:              "no-content status retains wire field",
			status:            "204 No Content",
			contentLength:     "3",
			wantParsedLength:  0,
			wantSigningString: "content-length: 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := "HTTP/1.1 " + tt.status + "\r\n" +
				"Content-Length: " + tt.contentLength + "\r\n" +
				"Signature: " + fixedCavageHMACHeader(t, tt.wantSigningString, "content-length") + "\r\n" +
				"\r\n" + tt.body
			res := readCavageResponse(t, raw, http.MethodGet)
			if res.ContentLength != tt.wantParsedLength || !slices.Equal(res.Header["Content-Length"], []string{tt.contentLength}) {
				t.Fatalf("ContentLength/Header = %d/%q, want %d/[%s]", res.ContentLength, res.Header["Content-Length"], tt.wantParsedLength, tt.contentLength)
			}
			verifyCavageResponseHMAC(t, res)
		})
	}

	t.Run("does not synthesize absent unknown length", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\n" +
			"Signature: " + fixedCavageHMACHeader(t, "content-length: -1", "content-length") + "\r\n" +
			"\r\n"
		res := readCavageResponse(t, raw, http.MethodGet)
		if res.ContentLength != -1 {
			t.Fatalf("ContentLength = %d, want -1", res.ContentLength)
		}
		assertCavageResponseParseError(t, res, ErrSignedHeaderMissing)
	})
}

func TestCavageVerifierUsesNonChunkedResponseTrailerHeader(t *testing.T) {
	want := "trailer: X-Zeta, x-alpha"
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 0\r\n" +
		"Trailer: X-Zeta, x-alpha\r\n" +
		"Signature: " + fixedCavageHMACHeader(t, want, "trailer") + "\r\n" +
		"\r\n"
	res := readCavageResponse(t, raw, http.MethodGet)
	if res.Trailer != nil || !slices.Equal(res.Header["Trailer"], []string{"X-Zeta, x-alpha"}) {
		t.Fatalf("Trailer/Header = %#v/%q, want nil/[X-Zeta, x-alpha]", res.Trailer, res.Header["Trailer"])
	}
	verifyCavageResponseHMAC(t, res)
}

func TestCavageVerifierParsedResponseNormalFieldOrder(t *testing.T) {
	want := "x-order: first, second"
	raw := "HTTP/1.1 204 No Content\r\n" +
		"X-Order: first\r\n" +
		"X-Order: second\r\n" +
		"Signature: " + fixedCavageHMACHeader(t, want, "x-order") + "\r\n" +
		"\r\n"
	res := readCavageResponse(t, raw, http.MethodGet)
	if !slices.Equal(res.Header["X-Order"], []string{"first", "second"}) {
		t.Fatalf("X-Order = %q, want [first second]", res.Header["X-Order"])
	}
	verifyCavageResponseHMAC(t, res)
}

func TestCavageVerifierReceivedManagedSnapshotIsImmutable(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		want := "host: Request.Example:8443\n" +
			"transfer-encoding: chunked\n" +
			"trailer: X-Alpha,X-Zeta\n" +
			"x-test: request-original"
		body := &receivedCountingBody{}
		req := &http.Request{
			Method:     http.MethodPost,
			RequestURI: "/snapshot",
			URL:        &url.URL{Path: "/snapshot"},
			Host:       "Request.Example:8443",
			Header: http.Header{
				"Signature": {fixedCavageHMACHeader(t, want, "host transfer-encoding trailer x-test")},
				"X-Test":    {"request-original"},
			},
			Body:             body,
			ContentLength:    -1,
			TransferEncoding: []string{"chunked"},
			Trailer:          http.Header{"x-zeta": nil, "X-Alpha": nil},
		}
		headerBefore := req.Header.Clone()
		trailerBefore := req.Trailer.Clone()
		transferBefore := append([]string(nil), req.TransferEncoding...)
		hostBefore := req.Host
		lengthBefore := req.ContentLength
		bodyBefore := req.Body

		verifier := newSigningStringVerifier(t)
		signature, err := verifier.ParseRequest(req)
		if err != nil {
			t.Fatalf("ParseRequest() failed: %v", err)
		}
		if req.Host != hostBefore {
			t.Errorf("Host = %q, want %q", req.Host, hostBefore)
		}
		if req.ContentLength != lengthBefore {
			t.Errorf("ContentLength = %d, want %d", req.ContentLength, lengthBefore)
		}
		if req.Body != bodyBefore {
			t.Error("Body was replaced")
		}
		if !reflect.DeepEqual(req.Header, headerBefore) {
			t.Errorf("Header = %#v, want %#v", req.Header, headerBefore)
		}
		if !reflect.DeepEqual(req.Trailer, trailerBefore) {
			t.Errorf("Trailer = %#v, want %#v", req.Trailer, trailerBefore)
		}
		if !slices.Equal(req.TransferEncoding, transferBefore) {
			t.Errorf("TransferEncoding = %q, want %q", req.TransferEncoding, transferBefore)
		}
		if body.reads != 0 {
			t.Errorf("Body.Read calls = %d, want 0", body.reads)
		}
		if body.closes != 0 {
			t.Errorf("Body.Close calls = %d, want 0", body.closes)
		}
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("initial VerifyHMAC() failed: %v", err)
		}

		req.Host = "changed.example"
		req.ContentLength = 99
		req.Header.Set("X-Test", "changed")
		req.Header.Set(Signature, "malformed")
		req.TransferEncoding[0] = "identity"
		req.TransferEncoding = append(req.TransferEncoding, "changed")
		req.Trailer["x-zeta"] = []string{"changed"}
		delete(req.Trailer, "X-Alpha")
		req.Trailer["X-Changed"] = []string{"changed"}
		req.Body = &receivedCountingBody{}
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("request mutation changed verification result: %v", err)
		}
	})

	t.Run("response", func(t *testing.T) {
		want := "host: Associated.Example:9443\n" +
			"transfer-encoding: chunked\n" +
			"trailer: X-Alpha,X-Zeta\n" +
			"x-test: response-original"
		body := &receivedCountingBody{}
		associatedRequest := &http.Request{Method: http.MethodGet, RequestURI: "/associated", Host: "Associated.Example:9443"}
		res := &http.Response{
			Request: associatedRequest,
			Header: http.Header{
				"Signature": {fixedCavageHMACHeader(t, want, "host transfer-encoding trailer x-test")},
				"X-Test":    {"response-original"},
			},
			Body:             body,
			ContentLength:    -1,
			TransferEncoding: []string{"chunked"},
			Trailer:          http.Header{"x-zeta": nil, "X-Alpha": nil},
		}
		headerBefore := res.Header.Clone()
		trailerBefore := res.Trailer.Clone()
		transferBefore := append([]string(nil), res.TransferEncoding...)
		requestBefore := res.Request
		hostBefore := res.Request.Host
		lengthBefore := res.ContentLength
		bodyBefore := res.Body

		verifier := newSigningStringVerifier(t)
		signature, err := verifier.ParseResponse(res)
		if err != nil {
			t.Fatalf("ParseResponse() failed: %v", err)
		}
		if res.Request != requestBefore {
			t.Error("associated Request was replaced")
		}
		if res.Request.Host != hostBefore {
			t.Errorf("associated Request.Host = %q, want %q", res.Request.Host, hostBefore)
		}
		if res.ContentLength != lengthBefore {
			t.Errorf("ContentLength = %d, want %d", res.ContentLength, lengthBefore)
		}
		if res.Body != bodyBefore {
			t.Error("Body was replaced")
		}
		if !reflect.DeepEqual(res.Header, headerBefore) {
			t.Errorf("Header = %#v, want %#v", res.Header, headerBefore)
		}
		if !reflect.DeepEqual(res.Trailer, trailerBefore) {
			t.Errorf("Trailer = %#v, want %#v", res.Trailer, trailerBefore)
		}
		if !slices.Equal(res.TransferEncoding, transferBefore) {
			t.Errorf("TransferEncoding = %q, want %q", res.TransferEncoding, transferBefore)
		}
		if body.reads != 0 {
			t.Errorf("Body.Read calls = %d, want 0", body.reads)
		}
		if body.closes != 0 {
			t.Errorf("Body.Close calls = %d, want 0", body.closes)
		}
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("initial VerifyHMAC() failed: %v", err)
		}

		res.Request.Host = "changed.example"
		res.ContentLength = 99
		res.Header.Set("X-Test", "changed")
		res.Header.Set(Signature, "malformed")
		res.TransferEncoding[0] = "identity"
		res.TransferEncoding = append(res.TransferEncoding, "changed")
		res.Trailer["x-zeta"] = []string{"changed"}
		delete(res.Trailer, "X-Alpha")
		res.Trailer["X-Changed"] = []string{"changed"}
		res.Body = &receivedCountingBody{}
		if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
			t.Fatalf("response mutation changed verification result: %v", err)
		}
	})
}

func TestCavageVerifierReceivedManagedFieldErrorDoesNotModifyInput(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		body := &receivedCountingBody{}
		req := &http.Request{
			Host: "request.example",
			Header: http.Header{
				"Signature":         {fixedCavageHMACHeader(t, "transfer-encoding: identity", "transfer-encoding")},
				"Transfer-Encoding": {"identity"},
			},
			Body:          body,
			ContentLength: 7,
			Trailer:       http.Header{"X-Trace": {"unchanged"}},
		}
		headerBefore := req.Header.Clone()
		trailerBefore := req.Trailer.Clone()
		bodyBefore := req.Body

		verifier := newSigningStringVerifier(t)
		_, err := verifier.ParseRequest(req)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("ParseRequest() error = %v, want ErrSignedHeaderMissing", err)
		}
		if req.Body != bodyBefore {
			t.Error("Body was replaced")
		}
		if body.reads != 0 {
			t.Errorf("Body.Read calls = %d, want 0", body.reads)
		}
		if body.closes != 0 {
			t.Errorf("Body.Close calls = %d, want 0", body.closes)
		}
		if req.Host != "request.example" {
			t.Errorf("Host = %q, want %q", req.Host, "request.example")
		}
		if req.ContentLength != 7 {
			t.Errorf("ContentLength = %d, want 7", req.ContentLength)
		}
		if !reflect.DeepEqual(req.Header, headerBefore) {
			t.Errorf("Header = %#v, want %#v", req.Header, headerBefore)
		}
		if !reflect.DeepEqual(req.Trailer, trailerBefore) {
			t.Errorf("Trailer = %#v, want %#v", req.Trailer, trailerBefore)
		}
		if req.TransferEncoding != nil {
			t.Errorf("TransferEncoding = %q, want nil", req.TransferEncoding)
		}
	})

	t.Run("response", func(t *testing.T) {
		body := &receivedCountingBody{}
		associatedRequest := &http.Request{Method: http.MethodGet, Host: "response.example"}
		res := &http.Response{
			Request: associatedRequest,
			Header: http.Header{
				"Signature":         {fixedCavageHMACHeader(t, "transfer-encoding: identity", "transfer-encoding")},
				"Transfer-Encoding": {"identity"},
			},
			Body:          body,
			ContentLength: 7,
			Trailer:       http.Header{"X-Trace": {"unchanged"}},
		}
		headerBefore := res.Header.Clone()
		trailerBefore := res.Trailer.Clone()
		bodyBefore := res.Body

		verifier := newSigningStringVerifier(t)
		_, err := verifier.ParseResponse(res)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("ParseResponse() error = %v, want ErrSignedHeaderMissing", err)
		}
		if res.Request != associatedRequest {
			t.Error("associated Request was replaced")
		}
		if res.Body != bodyBefore {
			t.Error("Body was replaced")
		}
		if body.reads != 0 {
			t.Errorf("Body.Read calls = %d, want 0", body.reads)
		}
		if body.closes != 0 {
			t.Errorf("Body.Close calls = %d, want 0", body.closes)
		}
		if res.ContentLength != 7 {
			t.Errorf("ContentLength = %d, want 7", res.ContentLength)
		}
		if !reflect.DeepEqual(res.Header, headerBefore) {
			t.Errorf("Header = %#v, want %#v", res.Header, headerBefore)
		}
		if !reflect.DeepEqual(res.Trailer, trailerBefore) {
			t.Errorf("Trailer = %#v, want %#v", res.Trailer, trailerBefore)
		}
		if res.TransferEncoding != nil {
			t.Errorf("TransferEncoding = %q, want nil", res.TransferEncoding)
		}
	})
}

func readCavageRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("http.ReadRequest() failed: %v", err)
	}
	return req
}

func readCavageResponse(t *testing.T, raw, method string) *http.Response {
	t.Helper()
	associatedRequest := &http.Request{Method: method}
	res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), associatedRequest)
	if err != nil {
		t.Fatalf("http.ReadResponse() failed: %v", err)
	}
	if res.Request != associatedRequest {
		t.Fatal("http.ReadResponse() did not retain the associated request")
	}
	return res
}

func newSigningStringVerifier(t *testing.T) *CavageVerifier {
	t.Helper()
	verifier, err := NewCavageVerifier(signingStringVerificationOptions())
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	return verifier
}

func verifyCavageRequestHMAC(t *testing.T, req *http.Request) {
	t.Helper()
	verifier := newSigningStringVerifier(t)
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest() failed: %v", err)
	}
	if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
		t.Fatalf("VerifyHMAC() failed: %v", err)
	}
}

func verifyCavageResponseHMAC(t *testing.T, res *http.Response) {
	t.Helper()
	verifier := newSigningStringVerifier(t)
	signature, err := verifier.ParseResponse(res)
	if err != nil {
		t.Fatalf("ParseResponse() failed: %v", err)
	}
	if err := verifier.VerifyHMAC(signature, signingStringVerificationKey()); err != nil {
		t.Fatalf("VerifyHMAC() failed: %v", err)
	}
}

func assertCavageRequestParseError(t *testing.T, req *http.Request, want error) {
	t.Helper()
	_, err := newSigningStringVerifier(t).ParseRequest(req)
	if !errors.Is(err, want) {
		t.Fatalf("ParseRequest() error = %v, want %v", err, want)
	}
}

func assertCavageResponseParseError(t *testing.T, res *http.Response, want error) {
	t.Helper()
	_, err := newSigningStringVerifier(t).ParseResponse(res)
	if !errors.Is(err, want) {
		t.Fatalf("ParseResponse() error = %v, want %v", err, want)
	}
}

type receivedCountingBody struct {
	reads  int
	closes int
}

func (b *receivedCountingBody) Read([]byte) (int, error) {
	b.reads++
	return 0, io.EOF
}

func (b *receivedCountingBody) Close() error {
	b.closes++
	return nil
}
