package sigre

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestCavageRequestSignerUsesOutgoingHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		url  *url.URL
		want string
	}{
		{
			name: "Request Host",
			host: "real.example:8443",
			url:  &url.URL{Scheme: "https", Host: "url.example", Path: "/"},
			want: "real.example:8443",
		},
		{
			name: "URL Host fallback",
			url:  &url.URL{Scheme: "https", Host: "fallback.example:8080", Path: "/"},
			want: "fallback.example:8080",
		},
		{
			name: "international domain name",
			host: "münich.example:8443",
			url:  &url.URL{Scheme: "https", Host: "unused.example", Path: "/"},
			want: "xn--mnich-kva.example:8443",
		},
		{
			name: "zoned IPv6 literal",
			host: "[fe80::1%en0]:8080",
			url:  &url.URL{Scheme: "https", Host: "unused.example", Path: "/"},
			want: "[fe80::1]:8080",
		},
		{
			name: "IPv6 literal",
			host: "[2001:db8::1]:443",
			url:  &url.URL{Scheme: "https", Host: "unused.example", Path: "/"},
			want: "[2001:db8::1]:443",
		},
		{
			name: "empty Host field",
			url:  &url.URL{Path: "/"},
			want: "",
		},
		{
			name: "invalid Host field is cleared by net/http",
			host: "invalid host",
			url:  &url.URL{Scheme: "https", Host: "unused.example", Path: "/"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				URL:    tt.url,
				Host:   tt.host,
				Header: make(http.Header),
			}
			if err := NewCavageSigner().SignRequestWithHMAC(
				req,
				signingStringHMACSigningKey("outgoing-host-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{"host"}),
			); err != nil {
				t.Fatalf("SignRequestWithHMAC() failed: %v", err)
			}
			assertCavageHMACSignature(t, req.Header.Get(Signature), "host: "+tt.want)

			wireReq := &http.Request{
				Method: "GET",
				URL:    cloneOutgoingTestURL(tt.url),
				Host:   tt.host,
				Header: make(http.Header),
			}
			wire := writeOutgoingRequest(t, wireReq)
			assertOutgoingWireField(t, wire, "Host", []string{tt.want})
		})
	}
}

func TestCavageRequestSignerRejectsHostWithoutURL(t *testing.T) {
	req := &http.Request{Method: "GET", Host: "example.test", Header: make(http.Header)}
	err := NewCavageSigner().SignRequestWithHMAC(
		req,
		signingStringHMACSigningKey("missing-url-key"),
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{"host"}),
	)
	if !errors.Is(err, ErrInvalidHTTPMessage) {
		t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
	}
	if req.Header.Get(Signature) != "" {
		t.Fatalf("Signature was added after failed signing: %q", req.Header.Get(Signature))
	}
}

func TestCavageRequestSignerRejectsOutgoingHostConflictWithoutMutation(t *testing.T) {
	body := &outgoingCountingBody{reader: strings.NewReader("abc")}
	req := &http.Request{
		Method:        "POST",
		URL:           &url.URL{Scheme: "https", Host: "url.example", Path: "/inbox"},
		Host:          "real.example",
		Header:        http.Header{"Host": []string{"signed.example"}},
		Body:          body,
		ContentLength: 3,
	}
	beforeURL := *req.URL
	beforeHeader := req.Header.Clone()
	beforeHost := req.Host
	beforeContentLength := req.ContentLength

	err := NewCavageSigner().SignRequestWithHMAC(
		req,
		signingStringHMACSigningKey("host-conflict-key"),
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{"host"}),
	)
	if !errors.Is(err, ErrInvalidHTTPMessage) {
		t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
	}
	if req.Host != beforeHost || req.ContentLength != beforeContentLength || *req.URL != beforeURL {
		t.Fatalf("request fields changed after failed signing: %#v", req)
	}
	if !reflect.DeepEqual(req.Header, beforeHeader) {
		t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", req.Header, beforeHeader)
	}
	if req.Body != body || body.reads != 0 || body.closes != 0 {
		t.Fatalf("Body changed or was used: body=%p reads=%d closes=%d", req.Body, body.reads, body.closes)
	}
	if req.Header.Get(Signature) != "" {
		t.Fatalf("Signature was added after failed signing: %q", req.Header.Get(Signature))
	}
}

func TestCavageRequestSignerOutgoingHostRedundantHeaderPolicy(t *testing.T) {
	t.Run("matching normalized canonical value is accepted", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "https", Host: "unused.example", Path: "/"},
			Host:   "münich.example",
			Header: http.Header{"Host": []string{"xn--mnich-kva.example"}},
		}
		if err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("matching-host-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"host"}),
		); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, req.Header.Get(Signature), "host: xn--mnich-kva.example")
	})

	for _, key := range []string{"host", "HOST", "hOsT"} {
		t.Run("noncanonical map key "+key, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
				Host:   "example.test",
				Header: http.Header{key: []string{"example.test"}},
			}
			err := NewCavageSigner().SignRequestWithHMAC(
				req,
				signingStringHMACSigningKey("noncanonical-host-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{"host"}),
			)
			if !errors.Is(err, ErrInvalidHTTPMessage) {
				t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
			}
			if req.Header.Get(Signature) != "" {
				t.Fatalf("Signature was added after failed signing: %q", req.Header.Get(Signature))
			}
		})
	}
}

func TestCavageRequestSignerUsesOutgoingContentLength(t *testing.T) {
	t.Run("known positive length from NewRequest", func(t *testing.T) {
		req, err := http.NewRequest("POST", "https://example.test/inbox", strings.NewReader("abc"))
		if err != nil {
			t.Fatalf("http.NewRequest() failed: %v", err)
		}
		if _, ok := req.Header["Content-Length"]; ok {
			t.Fatal("test setup unexpectedly copied Content-Length into Header")
		}
		if err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("request-content-length-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, req.Header.Get(Signature), "content-length: 3")

		wireReq, err := http.NewRequest("POST", "https://example.test/inbox", strings.NewReader("abc"))
		if err != nil {
			t.Fatalf("http.NewRequest() for wire comparison failed: %v", err)
		}
		assertOutgoingWireField(t, writeOutgoingRequest(t, wireReq), "Content-Length", []string{"3"})
	})

	t.Run("POST known zero emits field", func(t *testing.T) {
		req := outgoingTestRequest("POST")
		if err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("request-zero-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, req.Header.Get(Signature), "content-length: 0")
		assertOutgoingWireField(t, writeOutgoingRequest(t, outgoingTestRequest("POST")), "Content-Length", []string{"0"})
	})

	for _, tt := range []struct {
		name string
		req  func() *http.Request
	}{
		{
			name: "GET known zero omits field",
			req: func() *http.Request {
				return outgoingTestRequest("GET")
			},
		},
		{
			name: "chunked omits field",
			req: func() *http.Request {
				req := outgoingTestRequest("POST")
				req.Body = io.NopCloser(strings.NewReader("abc"))
				req.ContentLength = 3
				req.TransferEncoding = []string{"chunked"}
				return req
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.req()
			err := NewCavageSigner().SignRequestWithHMAC(
				req,
				signingStringHMACSigningKey("request-missing-length-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{"content-length"}),
			)
			if !errors.Is(err, ErrSignedHeaderMissing) {
				t.Fatalf("SignRequestWithHMAC() error = %v, want ErrSignedHeaderMissing", err)
			}
			assertOutgoingWireField(t, writeOutgoingRequest(t, tt.req()), "Content-Length", nil)
		})
	}
}

func TestCavageRequestSignerContentLengthHeaderConflictPolicy(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantError bool
	}{
		{name: "matching redundant value", header: "3"},
		{name: "conflicting ignored value", header: "4", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "https://example.test/inbox", strings.NewReader("abc"))
			if err != nil {
				t.Fatalf("http.NewRequest() failed: %v", err)
			}
			req.Header["Content-Length"] = []string{tt.header}
			err = NewCavageSigner().SignRequestWithHMAC(
				req,
				signingStringHMACSigningKey("request-length-conflict-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{"content-length"}),
			)
			if tt.wantError {
				if !errors.Is(err, ErrInvalidHTTPMessage) {
					t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
				}
				if req.Header.Get(Signature) != "" {
					t.Fatalf("Signature was added after failed signing: %q", req.Header.Get(Signature))
				}
				return
			}
			if err != nil {
				t.Fatalf("SignRequestWithHMAC() failed: %v", err)
			}
			assertCavageHMACSignature(t, req.Header.Get(Signature), "content-length: 3")
		})
	}
}

func TestCavageRequestSignerUsesOutgoingTransferEncodingAndTrailer(t *testing.T) {
	t.Run("explicit chunked", func(t *testing.T) {
		body := &outgoingCountingBody{reader: strings.NewReader("abc")}
		req := outgoingTestRequest("POST")
		req.Body = body
		req.ContentLength = 3
		req.TransferEncoding = []string{"chunked"}
		if err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("request-transfer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding"}),
		); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, req.Header.Get(Signature), "transfer-encoding: chunked")
		if body.reads != 0 || body.closes != 0 {
			t.Fatalf("signing used Body: reads=%d closes=%d", body.reads, body.closes)
		}

		wireReq := outgoingTestRequest("POST")
		wireReq.Body = io.NopCloser(strings.NewReader("abc"))
		wireReq.ContentLength = 3
		wireReq.TransferEncoding = []string{"chunked"}
		assertOutgoingWireField(t, writeOutgoingRequest(t, wireReq), "Transfer-Encoding", []string{"chunked"})
	})

	t.Run("automatic chunked for POST is deterministic", func(t *testing.T) {
		body := &outgoingCountingBody{reader: strings.NewReader("abc")}
		req := outgoingTestRequest("POST")
		req.Body = body
		req.ContentLength = 0
		if err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("request-auto-transfer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding"}),
		); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, req.Header.Get(Signature), "transfer-encoding: chunked")
		if body.reads != 0 || body.closes != 0 {
			t.Fatalf("signing used Body: reads=%d closes=%d", body.reads, body.closes)
		}
	})

	t.Run("nil Body removes explicit chunked encoding", func(t *testing.T) {
		req := outgoingTestRequest("POST")
		req.TransferEncoding = []string{"chunked"}
		err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("request-nil-body-transfer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding"}),
		)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("SignRequestWithHMAC() error = %v, want ErrSignedHeaderMissing", err)
		}
		wireReq := outgoingTestRequest("POST")
		wireReq.TransferEncoding = []string{"chunked"}
		wire := writeOutgoingRequest(t, wireReq)
		assertOutgoingWireField(t, wire, "Transfer-Encoding", nil)
		assertOutgoingWireField(t, wire, "Content-Length", []string{"0"})
	})

	t.Run("Trailer declaration uses normalized sorted keys", func(t *testing.T) {
		body := &outgoingCountingBody{reader: strings.NewReader("abc")}
		req := outgoingTestRequest("POST")
		req.Body = body
		req.TransferEncoding = []string{"chunked"}
		req.Trailer = http.Header{
			"x-zeta":  []string{"ignored"},
			"X-Alpha": nil,
		}
		if err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("request-trailer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"trailer"}),
		); err != nil {
			t.Fatalf("SignRequestWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, req.Header.Get(Signature), "trailer: X-Alpha,X-Zeta")
		if body.reads != 0 || body.closes != 0 {
			t.Fatalf("signing used Body: reads=%d closes=%d", body.reads, body.closes)
		}

		wireReq := outgoingTestRequest("POST")
		wireReq.Body = io.NopCloser(strings.NewReader("abc"))
		wireReq.TransferEncoding = []string{"chunked"}
		wireReq.Trailer = http.Header{"x-zeta": []string{"ignored"}, "X-Alpha": nil}
		assertOutgoingWireField(t, writeOutgoingRequest(t, wireReq), "Trailer", []string{"X-Alpha,X-Zeta"})
	})
}

func TestCavageRequestSignerRejectsMissingInvalidOrIndeterminateTransferFields(t *testing.T) {
	t.Run("non-chunked Trailer is missing", func(t *testing.T) {
		req := outgoingTestRequest("POST")
		req.Trailer = http.Header{"X-Trace": nil}
		err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("request-missing-trailer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"trailer"}),
		)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("SignRequestWithHMAC() error = %v, want ErrSignedHeaderMissing", err)
		}
	})

	for _, forbidden := range []string{"Content-Length", "Transfer-Encoding", "Trailer"} {
		t.Run("forbidden Trailer key "+forbidden, func(t *testing.T) {
			req := outgoingTestRequest("POST")
			req.Body = io.NopCloser(strings.NewReader("abc"))
			req.TransferEncoding = []string{"chunked"}
			req.Trailer = http.Header{forbidden: nil}
			err := NewCavageSigner().SignRequestWithHMAC(
				req,
				signingStringHMACSigningKey("request-invalid-trailer-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{"trailer"}),
			)
			if !errors.Is(err, ErrInvalidHTTPMessage) {
				t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
			}
		})
	}

	t.Run("GET automatic chunking requires a Body probe", func(t *testing.T) {
		body := &outgoingCountingBody{reader: strings.NewReader("abc")}
		req := outgoingTestRequest("GET")
		req.Body = body
		req.ContentLength = 0
		err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("request-indeterminate-transfer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding"}),
		)
		if !errors.Is(err, ErrInvalidHTTPMessage) || !strings.Contains(err.Error(), "Body") {
			t.Fatalf("SignRequestWithHMAC() error = %v, want an ErrInvalidHTTPMessage explaining Body uncertainty", err)
		}
		if body.reads != 0 || body.closes != 0 {
			t.Fatalf("failed signing used Body: reads=%d closes=%d", body.reads, body.closes)
		}
		if req.Header.Get(Signature) != "" {
			t.Fatalf("Signature was added after failed signing: %q", req.Header.Get(Signature))
		}
	})
}

func TestCavageRequestSignerManagedHeaderConflicts(t *testing.T) {
	tests := []struct {
		name       string
		signedName string
		headerName string
		header     string
		configure  func(*http.Request)
	}{
		{
			name:       "Transfer-Encoding",
			signedName: "transfer-encoding",
			headerName: "Transfer-Encoding",
			header:     "identity",
			configure: func(req *http.Request) {
				req.Body = io.NopCloser(strings.NewReader("abc"))
				req.TransferEncoding = []string{"chunked"}
			},
		},
		{
			name:       "Trailer",
			signedName: "trailer",
			headerName: "Trailer",
			header:     "X-Other",
			configure: func(req *http.Request) {
				req.Body = io.NopCloser(strings.NewReader("abc"))
				req.TransferEncoding = []string{"chunked"}
				req.Trailer = http.Header{"X-Trace": nil}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := outgoingTestRequest("POST")
			tt.configure(req)
			req.Header[tt.headerName] = []string{tt.header}
			before := req.Header.Clone()
			err := NewCavageSigner().SignRequestWithHMAC(
				req,
				signingStringHMACSigningKey("request-managed-conflict-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{tt.signedName}),
			)
			if !errors.Is(err, ErrInvalidHTTPMessage) {
				t.Fatalf("SignRequestWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
			}
			if !reflect.DeepEqual(req.Header, before) {
				t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", req.Header, before)
			}
		})
	}
}

func TestCavageRequestSignerAcceptsMatchingTransferHeaders(t *testing.T) {
	body := &outgoingCountingBody{reader: strings.NewReader("abc")}
	req := outgoingTestRequest("POST")
	req.Body = body
	req.TransferEncoding = []string{"chunked"}
	req.Trailer = http.Header{"X-Trace": nil}
	req.Header["Transfer-Encoding"] = []string{"chunked"}
	req.Header["Trailer"] = []string{"X-Trace"}

	if err := NewCavageSigner().SignRequestWithHMAC(
		req,
		signingStringHMACSigningKey("matching-transfer-key"),
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{"transfer-encoding", "trailer"}),
	); err != nil {
		t.Fatalf("SignRequestWithHMAC() failed: %v", err)
	}
	assertCavageHMACSignature(t, req.Header.Get(Signature), "transfer-encoding: chunked\ntrailer: X-Trace")
	if body.reads != 0 || body.closes != 0 {
		t.Fatalf("signing used Body: reads=%d closes=%d", body.reads, body.closes)
	}
}

func TestCavageRequestSignerOnlyResolvesSelectedManagedFields(t *testing.T) {
	body := &outgoingCountingBody{reader: strings.NewReader("abc")}
	req := outgoingTestRequest("GET")
	req.Body = body
	req.ContentLength = 0
	req.Header["Content-Length"] = []string{"999"}
	if err := NewCavageSigner().SignRequestWithHMAC(
		req,
		signingStringHMACSigningKey("selected-managed-key"),
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{"host"}),
	); err != nil {
		t.Fatalf("SignRequestWithHMAC() rejected an unselected Content-Length conflict: %v", err)
	}
	assertCavageHMACSignature(t, req.Header.Get(Signature), "host: example.test")
	if body.reads != 0 || body.closes != 0 {
		t.Fatalf("signing resolved an unselected transfer field: reads=%d closes=%d", body.reads, body.closes)
	}
}

func TestCavageResponseSignerUsesOutgoingManagedFields(t *testing.T) {
	t.Run("known positive Content-Length", func(t *testing.T) {
		body := &outgoingCountingBody{reader: strings.NewReader("abc")}
		res := outgoingTestResponse()
		res.Body = body
		res.ContentLength = 3
		if err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("response-length-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		); err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, res.Header.Get(Signature), "content-length: 3")
		if body.reads != 0 || body.closes != 0 {
			t.Fatalf("signing used Body: reads=%d closes=%d", body.reads, body.closes)
		}

		wireRes := outgoingTestResponse()
		wireRes.Body = io.NopCloser(strings.NewReader("abc"))
		wireRes.ContentLength = 3
		assertOutgoingWireField(t, writeOutgoingResponse(t, wireRes), "Content-Length", []string{"3"})
	})

	t.Run("known zero Content-Length", func(t *testing.T) {
		res := outgoingTestResponse()
		res.Body = nil
		res.ContentLength = 0
		if err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("response-zero-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		); err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, res.Header.Get(Signature), "content-length: 0")
		wireRes := outgoingTestResponse()
		wireRes.Body = nil
		assertOutgoingWireField(t, writeOutgoingResponse(t, wireRes), "Content-Length", []string{"0"})
	})

	t.Run("status without a body suppresses zero Content-Length", func(t *testing.T) {
		res := outgoingTestResponse()
		res.Status = "204 No Content"
		res.StatusCode = http.StatusNoContent
		res.Body = nil
		err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("response-status-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("SignResponseWithHMAC() error = %v, want ErrSignedHeaderMissing", err)
		}
		wireRes := outgoingTestResponse()
		wireRes.Status = "204 No Content"
		wireRes.StatusCode = http.StatusNoContent
		wireRes.Body = nil
		assertOutgoingWireField(t, writeOutgoingResponse(t, wireRes), "Content-Length", nil)
	})

	t.Run("explicit chunked and Trailer", func(t *testing.T) {
		body := &outgoingCountingBody{reader: strings.NewReader("abc")}
		res := outgoingTestResponse()
		res.Body = body
		res.ContentLength = 3
		res.TransferEncoding = []string{"chunked"}
		res.Trailer = http.Header{"x-zeta": nil, "X-Alpha": []string{"ignored"}}
		if err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("response-transfer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding", "trailer"}),
		); err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, res.Header.Get(Signature), "transfer-encoding: chunked\ntrailer: X-Alpha,X-Zeta")
		if body.reads != 0 || body.closes != 0 {
			t.Fatalf("signing used Body: reads=%d closes=%d", body.reads, body.closes)
		}

		wireRes := outgoingTestResponse()
		wireRes.Body = io.NopCloser(strings.NewReader("abc"))
		wireRes.ContentLength = 3
		wireRes.TransferEncoding = []string{"chunked"}
		wireRes.Trailer = http.Header{"x-zeta": nil, "X-Alpha": []string{"ignored"}}
		wire := writeOutgoingResponse(t, wireRes)
		assertOutgoingWireField(t, wire, "Transfer-Encoding", []string{"chunked"})
		assertOutgoingWireField(t, wire, "Trailer", []string{"X-Alpha,X-Zeta"})
	})

	t.Run("zero ContentLength with explicit chunked does not require a Body probe", func(t *testing.T) {
		body := &outgoingCountingBody{reader: strings.NewReader("abc")}
		res := outgoingTestResponse()
		res.Body = body
		res.ContentLength = 0
		res.TransferEncoding = []string{"chunked"}
		if err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("response-zero-chunked-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding"}),
		); err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, res.Header.Get(Signature), "transfer-encoding: chunked")
		if body.reads != 0 || body.closes != 0 {
			t.Fatalf("signing used Body: reads=%d closes=%d", body.reads, body.closes)
		}
	})

	t.Run("nil Body removes explicit chunked encoding", func(t *testing.T) {
		res := outgoingTestResponse()
		res.Body = nil
		res.TransferEncoding = []string{"chunked"}
		err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("response-nil-body-transfer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding"}),
		)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("SignResponseWithHMAC() error = %v, want ErrSignedHeaderMissing", err)
		}
		wireRes := outgoingTestResponse()
		wireRes.Body = nil
		wireRes.TransferEncoding = []string{"chunked"}
		assertOutgoingWireField(t, writeOutgoingResponse(t, wireRes), "Transfer-Encoding", nil)
	})

	t.Run("HTTP/1.0 removes chunked and retains known Content-Length", func(t *testing.T) {
		newResponse := func() *http.Response {
			res := outgoingTestResponse()
			res.Proto = "HTTP/1.0"
			res.ProtoMajor = 1
			res.ProtoMinor = 0
			res.Body = io.NopCloser(strings.NewReader("abc"))
			res.ContentLength = 3
			res.TransferEncoding = []string{"chunked"}
			return res
		}

		lengthResponse := newResponse()
		if err := NewCavageSigner().SignResponseWithHMAC(
			lengthResponse,
			signingStringHMACSigningKey("response-http10-length-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		); err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, lengthResponse.Header.Get(Signature), "content-length: 3")

		transferResponse := newResponse()
		err := NewCavageSigner().SignResponseWithHMAC(
			transferResponse,
			signingStringHMACSigningKey("response-http10-transfer-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding"}),
		)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("SignResponseWithHMAC() error = %v, want ErrSignedHeaderMissing", err)
		}

		wire := writeOutgoingResponse(t, newResponse())
		assertOutgoingWireField(t, wire, "Content-Length", []string{"3"})
		assertOutgoingWireField(t, wire, "Transfer-Encoding", nil)
	})

	t.Run("HEAD response keeps explicit chunked Transfer-Encoding", func(t *testing.T) {
		res := outgoingTestResponse()
		res.Request = &http.Request{Method: "HEAD"}
		res.Body = nil
		res.TransferEncoding = []string{"chunked"}
		if err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("response-head-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"transfer-encoding"}),
		); err != nil {
			t.Fatalf("SignResponseWithHMAC() failed: %v", err)
		}
		assertCavageHMACSignature(t, res.Header.Get(Signature), "transfer-encoding: chunked")
		wireRes := outgoingTestResponse()
		wireRes.Request = &http.Request{Method: "HEAD"}
		wireRes.Body = nil
		wireRes.TransferEncoding = []string{"chunked"}
		wire := writeOutgoingResponse(t, wireRes)
		assertOutgoingWireField(t, wire, "Transfer-Encoding", []string{"chunked"})
		assertOutgoingWireField(t, wire, "Content-Length", nil)

		lengthResponse := outgoingTestResponse()
		lengthResponse.Request = &http.Request{Method: "HEAD"}
		lengthResponse.Body = nil
		lengthResponse.TransferEncoding = []string{"chunked"}
		err := NewCavageSigner().SignResponseWithHMAC(
			lengthResponse,
			signingStringHMACSigningKey("response-head-length-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("SignResponseWithHMAC() error = %v, want ErrSignedHeaderMissing", err)
		}
	})
}

func TestCavageResponseSignerRejectsManagedHeaderConflicts(t *testing.T) {
	tests := []struct {
		name       string
		signedName string
		headerName string
		header     string
		configure  func(*http.Response)
	}{
		{
			name:       "Content-Length",
			signedName: "content-length",
			headerName: "Content-Length",
			header:     "4",
			configure: func(res *http.Response) {
				res.Body = io.NopCloser(strings.NewReader("abc"))
				res.ContentLength = 3
			},
		},
		{
			name:       "Transfer-Encoding",
			signedName: "transfer-encoding",
			headerName: "Transfer-Encoding",
			header:     "identity",
			configure: func(res *http.Response) {
				res.Body = io.NopCloser(strings.NewReader("abc"))
				res.TransferEncoding = []string{"chunked"}
			},
		},
		{
			name:       "Trailer",
			signedName: "trailer",
			headerName: "Trailer",
			header:     "X-Other",
			configure: func(res *http.Response) {
				res.Body = io.NopCloser(strings.NewReader("abc"))
				res.TransferEncoding = []string{"chunked"}
				res.Trailer = http.Header{"X-Trace": nil}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := outgoingTestResponse()
			tt.configure(res)
			res.Header[tt.headerName] = []string{tt.header}
			beforeHeader := res.Header.Clone()
			beforeContentLength := res.ContentLength
			beforeTransferEncoding := append([]string(nil), res.TransferEncoding...)
			beforeTrailer := res.Trailer.Clone()
			err := NewCavageSigner().SignResponseWithHMAC(
				res,
				signingStringHMACSigningKey("response-conflict-key"),
				CavageSignaturePlacementSignature,
				signingStringOptions([]string{tt.signedName}),
			)
			if !errors.Is(err, ErrInvalidHTTPMessage) {
				t.Fatalf("SignResponseWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
			}
			if !reflect.DeepEqual(res.Header, beforeHeader) || res.ContentLength != beforeContentLength ||
				!reflect.DeepEqual(res.TransferEncoding, beforeTransferEncoding) || !reflect.DeepEqual(res.Trailer, beforeTrailer) {
				t.Fatalf("response changed after failed signing: %#v", res)
			}
		})
	}
}

func TestCavageResponseSignerRejectsIndeterminateContentLengthWithoutBodyProbe(t *testing.T) {
	body := &outgoingCountingBody{reader: strings.NewReader("abc")}
	res := outgoingTestResponse()
	res.Body = body
	res.ContentLength = 0
	beforeHeader := res.Header.Clone()

	err := NewCavageSigner().SignResponseWithHMAC(
		res,
		signingStringHMACSigningKey("response-indeterminate-length-key"),
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{"content-length"}),
	)
	if !errors.Is(err, ErrInvalidHTTPMessage) || !strings.Contains(err.Error(), "Body") {
		t.Fatalf("SignResponseWithHMAC() error = %v, want an ErrInvalidHTTPMessage explaining Body uncertainty", err)
	}
	if body.reads != 0 || body.closes != 0 || res.Body != body {
		t.Fatalf("failed signing changed or used Body: body=%p reads=%d closes=%d", res.Body, body.reads, body.closes)
	}
	if !reflect.DeepEqual(res.Header, beforeHeader) {
		t.Fatalf("Header changed after failed signing\ngot:  %#v\nwant: %#v", res.Header, beforeHeader)
	}

	emptyWire := outgoingTestResponse()
	emptyWire.Body = http.NoBody
	emptyWire.ContentLength = 0
	assertOutgoingWireField(t, writeOutgoingResponse(t, emptyWire), "Content-Length", []string{"0"})
	nonEmptyWire := outgoingTestResponse()
	nonEmptyWire.Body = io.NopCloser(strings.NewReader("abc"))
	nonEmptyWire.ContentLength = 0
	assertOutgoingWireField(t, writeOutgoingResponse(t, nonEmptyWire), "Content-Length", nil)
}

func TestCavageOutgoingResolverPreservesNilHeaderOnError(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
			Host:   "example.test",
			Header: nil,
		}
		err := NewCavageSigner().SignRequestWithHMAC(
			req,
			signingStringHMACSigningKey("nil-request-header-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		)
		if !errors.Is(err, ErrSignedHeaderMissing) {
			t.Fatalf("SignRequestWithHMAC() error = %v, want ErrSignedHeaderMissing", err)
		}
		if req.Header != nil {
			t.Fatalf("Request.Header = %#v, want nil", req.Header)
		}
	})

	t.Run("response", func(t *testing.T) {
		body := &outgoingCountingBody{reader: strings.NewReader("abc")}
		res := outgoingTestResponse()
		res.Header = nil
		res.Body = body
		res.ContentLength = 0
		err := NewCavageSigner().SignResponseWithHMAC(
			res,
			signingStringHMACSigningKey("nil-response-header-key"),
			CavageSignaturePlacementSignature,
			signingStringOptions([]string{"content-length"}),
		)
		if !errors.Is(err, ErrInvalidHTTPMessage) {
			t.Fatalf("SignResponseWithHMAC() error = %v, want ErrInvalidHTTPMessage", err)
		}
		if res.Header != nil {
			t.Fatalf("Response.Header = %#v, want nil", res.Header)
		}
		if body.reads != 0 || body.closes != 0 {
			t.Fatalf("failed signing used Body: reads=%d closes=%d", body.reads, body.closes)
		}
	})
}

func TestCavageSignerAsymmetricUsesOutgoingFieldResolver(t *testing.T) {
	req, err := http.NewRequest("POST", "https://example.test/inbox", strings.NewReader("abc"))
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	err = NewCavageSigner().SignRequest(
		req,
		SigningKey{
			Metadata:   TrustedKeyMetadata{KeyID: "asymmetric-outgoing-key", Algorithm: AlgorithmEd25519},
			PrivateKey: privateKey,
		},
		CavageSignaturePlacementSignature,
		signingStringOptions([]string{"content-length"}),
	)
	if err != nil {
		t.Fatalf("SignRequest() failed: %v", err)
	}
	if req.Header.Get(Signature) == "" {
		t.Fatal("SignRequest() did not write Signature")
	}

	params, err := parseCavageParams(req.Header.Get(Signature))
	if err != nil {
		t.Fatalf("parseCavageParams() failed: %v", err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(params.Signature)
	if err != nil {
		t.Fatalf("signature is not strict Base64: %v", err)
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), []byte("content-length: 3"), signature) {
		t.Fatal("SignRequest() signature does not cover fixed signing string")
	}
}

func outgoingTestRequest(method string) *http.Request {
	return &http.Request{
		Method: method,
		URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/inbox"},
		Host:   "example.test",
		Header: make(http.Header),
	}
}

func outgoingTestResponse() *http.Response {
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		ContentLength: 0,
	}
}

type outgoingCountingBody struct {
	reader io.Reader
	reads  int
	closes int
}

func (b *outgoingCountingBody) Read(p []byte) (int, error) {
	b.reads++
	return b.reader.Read(p)
}

func (b *outgoingCountingBody) Close() error {
	b.closes++
	return nil
}

func cloneOutgoingTestURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	clone := *u
	return &clone
}

func writeOutgoingRequest(t *testing.T, req *http.Request) string {
	t.Helper()
	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		t.Fatalf("Request.Write() failed: %v", err)
	}
	return wire.String()
}

func writeOutgoingResponse(t *testing.T, res *http.Response) string {
	t.Helper()
	var wire bytes.Buffer
	if err := res.Write(&wire); err != nil {
		t.Fatalf("Response.Write() failed: %v", err)
	}
	return wire.String()
}

func assertOutgoingWireField(t *testing.T, wire, name string, want []string) {
	t.Helper()
	headerEnd := strings.Index(wire, "\r\n\r\n")
	if headerEnd < 0 {
		t.Fatalf("HTTP wire form has no complete header section: %q", wire)
	}
	var got []string
	for _, line := range strings.Split(wire[:headerEnd], "\r\n")[1:] {
		fieldName, fieldValue, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(fieldName, name) {
			got = append(got, strings.Trim(fieldValue, " \t"))
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wire field %s = %#v, want %#v\nwire: %q", name, got, want, wire[:headerEnd])
	}
}
