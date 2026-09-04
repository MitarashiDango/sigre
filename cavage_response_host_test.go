package sigre

import (
	"bufio"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestCavageVerifierRejectsRawResponseMissingHost(t *testing.T) {
	const signingString = "host: example.test"
	const encodedSignature = "HTtXqB9DtEL8JTtueZzQi6gMnqFDAfXCBGl3bUv4sBOE5x/r1fwFbqGj6y2e+CqiPDDPBiPxRvcypIn4dqxWFQ=="
	key := HMACVerificationKey{
		Metadata: TrustedKeyMetadata{KeyID: "review-key", Algorithm: AlgorithmHMACSHA512},
		Secret:   []byte("review-only-secret"),
	}
	mac := hmac.New(sha512.New, key.Secret)
	mac.Write([]byte(signingString))
	if got := base64.StdEncoding.EncodeToString(mac.Sum(nil)); got != encodedSignature {
		t.Fatalf("independent HMAC = %q, want %q", got, encodedSignature)
	}
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" +
		`Signature: keyId="review-key",algorithm="hs2019",headers="host",signature="` + encodedSignature + "\"\r\n\r\n"
	req := &http.Request{Method: http.MethodGet, Host: "example.test", URL: &url.URL{Scheme: "https", Host: "example.test", Path: "/"}}
	res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), req)
	if err != nil {
		t.Fatalf("http.ReadResponse() failed: %v", err)
	}
	defer res.Body.Close()
	if _, present := res.Header["Host"]; present {
		t.Fatal("raw response unexpectedly contains Host")
	}
	verifier, err := NewCavageVerifier(nil)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	signature, err := verifier.ParseResponse(res)
	if signature != nil {
		t.Errorf("ParseResponse() returned a snapshot for missing Host; VerifyHMAC() = %v", verifier.VerifyHMAC(signature, key))
	}
	assertResponseHostError(t, err, ErrSignedHeaderMissing)
}

func TestCavageResponseMissingHostDoesNotUseRequestOrModifyInput(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	tests := []struct {
		name      string
		header    http.Header
		noRequest bool
		host      string
	}{
		{name: "absent Host", header: http.Header{}, host: "request.example"},
		{name: "no associated request", header: http.Header{}, noRequest: true},
		{name: "nil values", header: http.Header{"Host": nil}, host: "request.example"},
		{name: "empty values", header: http.Header{"Host": {}}, host: "request.example"},
		{name: "request Header and URL candidates", header: http.Header{}},
		{name: "forbidden request Host", header: http.Header{}, host: "invalid\x00host"},
		{name: "nil Header", host: "request.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, operation := range []string{"SignResponse", "SignResponseWithHMAC", "ParseResponse"} {
				t.Run(operation, func(t *testing.T) {
					res := &http.Response{Header: tt.header.Clone(), Body: &receivedCountingBody{}}
					if !tt.noRequest {
						res.Request = &http.Request{
							Method: http.MethodGet,
							Host:   tt.host,
							Header: http.Header{"Host": {"header.example"}, "Authorization": {"Bearer request-token"}},
							URL:    &url.URL{Scheme: "https", Host: "url.example", Path: "/original"},
							Body:   &receivedCountingBody{},
						}
					}
					if res.Header != nil {
						res.Header.Set(Authorization, "Bearer response-token")
						res.Header.Set("X-Unrelated", "unchanged")
						if operation == "ParseResponse" {
							res.Header.Set(Signature, fixedCavageHMACHeader(t, "host: request.example", "host"))
						}
					}
					assertResponseHostInputUnchanged(t, res)
					var err error
					want := ErrSignedHeaderMissing
					switch operation {
					case "SignResponse":
						err = NewCavageSigner().SignResponse(res, SigningKey{
							Metadata:   TrustedKeyMetadata{KeyID: "response-host-key", Algorithm: AlgorithmEd25519},
							PrivateKey: privateKey,
						}, CavageSignaturePlacementSignature, signingStringOptions([]string{"host"}))
					case "SignResponseWithHMAC":
						err = NewCavageSigner().SignResponseWithHMAC(res, signingStringHMACSigningKey("test-key"), CavageSignaturePlacementSignature, signingStringOptions([]string{"host"}))
					case "ParseResponse":
						var signature *CavageSignature
						signature, err = newSigningStringVerifier(t).ParseResponse(res)
						if signature != nil {
							t.Error("ParseResponse() returned a snapshot after failed parsing")
						}
						if tt.header == nil {
							want = ErrMissingSignature
						}
					}
					assertResponseHostError(t, err, want)
				})
			}
		})
	}
}

func TestCavageResponseUsesOwnHost(t *testing.T) {
	tests := []struct {
		name        string
		values      []string
		requestHost string
		noRequest   bool
		want        string
	}{
		{name: "different request Host", values: []string{"Response.Example:9443"}, requestHost: "request.example", want: "host: Response.Example:9443"},
		{name: "empty request Host", values: []string{"Response.Example:9443"}, want: "host: Response.Example:9443"},
		{name: "forbidden request Host", values: []string{"Response.Example:9443"}, requestHost: "invalid\x00host", want: "host: Response.Example:9443"},
		{name: "no associated request", values: []string{"Response.Example:9443"}, noRequest: true, want: "host: Response.Example:9443"},
		{name: "empty value", values: []string{""}, requestHost: "request.example", want: "host: "},
		{name: "only OWS", values: []string{" \t "}, requestHost: "request.example", want: "host: "},
		{name: "multiple values", values: []string{" first.example\t", "second.example "}, requestHost: "request.example", want: "host: first.example, second.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &http.Response{
				Header: http.Header{"Host": tt.values, "Authorization": {"Bearer response-token"}},
				Body:   &receivedCountingBody{},
			}
			if !tt.noRequest {
				res.Request = &http.Request{Host: tt.requestHost, Body: &receivedCountingBody{}}
			}
			wantHeader := res.Header.Clone()
			if err := NewCavageSigner().SignResponseWithHMAC(res, signingStringHMACSigningKey("test-key"), CavageSignaturePlacementSignature, signingStringOptions([]string{"host"})); err != nil {
				t.Fatalf("SignResponseWithHMAC() failed: %v", err)
			}
			assertCavageHMACSignature(t, res.Header.Get(Signature), tt.want)
			wantHeader.Set(Signature, res.Header.Get(Signature))
			if !reflect.DeepEqual(res.Header, wantHeader) {
				t.Error("signing modified fields other than Signature")
			}

			// Verify an independently calculated signature over the fixed string.
			res.Header.Set(Signature, fixedCavageHMACHeader(t, tt.want, "host"))
			assertResponseHostInputUnchanged(t, res)
			verifyCavageResponseHMAC(t, res)
		})
	}
}

func TestCavageResponseRejectsForbiddenHostValues(t *testing.T) {
	for _, operation := range []string{"SignResponseWithHMAC", "ParseResponse"} {
		t.Run(operation, func(t *testing.T) {
			res := &http.Response{
				Header: http.Header{"Host": {"first.example", "a\x7fb"}, "Authorization": {"Bearer response-token"}},
				Body:   &receivedCountingBody{},
			}
			if operation == "ParseResponse" {
				res.Header.Set(Signature, fixedCavageHMACHeader(t, "host: first.example, a\x7fb", "host"))
			}
			assertResponseHostInputUnchanged(t, res)
			var err error
			if operation == "SignResponseWithHMAC" {
				err = NewCavageSigner().SignResponseWithHMAC(res, signingStringHMACSigningKey("test-key"), CavageSignaturePlacementSignature, signingStringOptions([]string{"host"}))
			} else {
				var signature *CavageSignature
				signature, err = newSigningStringVerifier(t).ParseResponse(res)
				if signature != nil {
					t.Error("ParseResponse() returned a snapshot for forbidden Host bytes")
				}
			}
			assertResponseHostError(t, err, ErrInvalidHTTPMessage)
			if err != nil {
				for _, want := range []string{`HTTP field "host"`, "value index 1", "byte position 2"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error = %q, want it to contain %q", err, want)
					}
				}
			}
		})
	}
}

func TestCavageResponseDoesNotResolveUnsignedHost(t *testing.T) {
	for _, tt := range []struct {
		name   string
		header http.Header
		host   string
	}{
		{name: "missing response and request Host", header: http.Header{}},
		{name: "forbidden response and request Host", header: http.Header{"Host": {"invalid\rhost"}}, host: "invalid\x00host"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := &http.Response{
				Header:  tt.header,
				Body:    &receivedCountingBody{},
				Request: &http.Request{Host: tt.host, Body: &receivedCountingBody{}},
			}
			res.Header.Set("X-Test", "signed")
			if err := NewCavageSigner().SignResponseWithHMAC(res, signingStringHMACSigningKey("test-key"), CavageSignaturePlacementSignature, signingStringOptions([]string{"x-test"})); err != nil {
				t.Fatalf("SignResponseWithHMAC() failed: %v", err)
			}
			assertCavageHMACSignature(t, res.Header.Get(Signature), "x-test: signed")
			res.Header.Set(Signature, fixedCavageHMACHeader(t, "x-test: signed", "x-test"))
			assertResponseHostInputUnchanged(t, res)
			verifyCavageResponseHMAC(t, res)
		})
	}
}

func TestCavageResponseHostMatchesHTTPWireForm(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "nonempty Host", value: "Response.Example:9443", want: "host: Response.Example:9443"},
		{name: "empty Host", value: "", want: "host: "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := outgoingTestResponse()
			res.Body = http.NoBody
			res.Request = outgoingTestRequest(http.MethodGet)
			res.Header["Host"] = []string{tt.value}
			if err := NewCavageSigner().SignResponseWithHMAC(res, signingStringHMACSigningKey("test-key"), CavageSignaturePlacementSignature, signingStringOptions([]string{"host"})); err != nil {
				t.Fatalf("SignResponseWithHMAC() failed: %v", err)
			}
			assertCavageHMACSignature(t, res.Header.Get(Signature), tt.want)
			wire := writeOutgoingResponse(t, res)
			assertOutgoingWireField(t, wire, "Host", []string{tt.value})
			received, err := http.ReadResponse(bufio.NewReader(strings.NewReader(wire)), res.Request)
			if err != nil {
				t.Fatalf("http.ReadResponse() failed: %v", err)
			}
			defer received.Body.Close()
			if got := received.Header["Host"]; !reflect.DeepEqual(got, []string{tt.value}) {
				t.Fatalf("received Host = %#v, want %#v", got, []string{tt.value})
			}
			verifyCavageResponseHMAC(t, received)
		})
	}
}

func assertResponseHostError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want %v", err, want)
	}
	var sigreErr *SigreError
	if !errors.As(err, &sigreErr) {
		t.Errorf("error type = %T, want *SigreError", err)
	}
}

func assertResponseHostInputUnchanged(t *testing.T, res *http.Response) {
	t.Helper()
	before := *res
	before.Header = res.Header.Clone()
	if res.Request != nil {
		requestBefore := *res.Request
		requestBefore.Header = res.Request.Header.Clone()
		requestBefore.URL = cloneOutgoingTestURL(res.Request.URL)
		before.Request = &requestBefore
	}
	request, body := res.Request, res.Body
	bodies := []*receivedCountingBody{body.(*receivedCountingBody)}
	if request != nil {
		bodies = append(bodies, request.Body.(*receivedCountingBody))
	}
	t.Cleanup(func() {
		if !reflect.DeepEqual(res, &before) || res.Request != request || res.Body != body {
			t.Error("response or associated request changed")
		}
		for _, body := range bodies {
			if body.reads != 0 || body.closes != 0 {
				t.Errorf("Body was accessed: reads=%d closes=%d", body.reads, body.closes)
			}
		}
	})
}
