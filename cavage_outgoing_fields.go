package sigre

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

type outgoingHTTPField struct {
	value   string
	present bool
	known   bool
}

type outgoingTransferFields struct {
	contentLength    outgoingHTTPField
	transferEncoding outgoingHTTPField
	trailer          outgoingHTTPField
}

func resolveOutgoingRequestFields(req *http.Request, header http.Header, signedHeaders []string) (http.Header, error) {
	resolved := header
	transferFieldsNeeded := slices.Contains(signedHeaders, "content-length") ||
		slices.Contains(signedHeaders, "transfer-encoding") ||
		slices.Contains(signedHeaders, "trailer")
	if transferFieldsNeeded || slices.Contains(signedHeaders, "host") {
		resolved = header.Clone()
	}
	var transfer outgoingTransferFields
	var err error
	if transferFieldsNeeded {
		transfer, err = outgoingRequestTransferFields(req, slices.Contains(signedHeaders, "trailer"))
		if err != nil {
			return nil, err
		}
	}

	for _, name := range signedHeaders {
		var field outgoingHTTPField
		var normalize func(string) (string, error)
		switch name {
		case "host":
			field, err = outgoingRequestHostField(req)
			if err != nil {
				return nil, err
			}
			normalize = normalizeOutgoingRequestHost
		case "content-length":
			field = transfer.contentLength
		case "transfer-encoding":
			field = transfer.transferEncoding
		case "trailer":
			field = transfer.trailer
		default:
			continue
		}
		if err = resolveOutgoingField(header, resolved, name, field, normalize); err != nil {
			return nil, err
		}
	}

	return resolved, nil
}

func resolveOutgoingResponseFields(res *http.Response, header http.Header, signedHeaders []string) (http.Header, error) {
	// Response Host is an ordinary field and must be present in the response itself.
	if slices.Contains(signedHeaders, "host") && len(header["Host"]) == 0 {
		return nil, fmt.Errorf("%w: host", ErrSignedHeaderMissing)
	}
	transferFieldsNeeded := slices.Contains(signedHeaders, "content-length") ||
		slices.Contains(signedHeaders, "transfer-encoding") ||
		slices.Contains(signedHeaders, "trailer")
	if !transferFieldsNeeded {
		return header, nil
	}
	transfer, err := outgoingResponseTransferFields(res, slices.Contains(signedHeaders, "trailer"))
	if err != nil {
		return nil, err
	}

	resolved := header.Clone()
	for _, name := range signedHeaders {
		var field outgoingHTTPField
		switch name {
		case "content-length":
			field = transfer.contentLength
		case "transfer-encoding":
			field = transfer.transferEncoding
		case "trailer":
			field = transfer.trailer
		default:
			continue
		}
		if err = resolveOutgoingField(header, resolved, name, field, nil); err != nil {
			return nil, err
		}
	}
	return resolved, nil
}

func resolveOutgoingField(
	original http.Header,
	resolved http.Header,
	name string,
	field outgoingHTTPField,
	normalize func(string) (string, error),
) error {
	canonicalName := http.CanonicalHeaderKey(name)
	for key := range original {
		if strings.EqualFold(key, canonicalName) && key != canonicalName {
			return fmt.Errorf("%w: non-canonical %s map key is ambiguous for outgoing signing", ErrInvalidHTTPMessage, canonicalName)
		}
	}

	headerValues, headerPresent := original[canonicalName]
	if !field.known {
		return fmt.Errorf("%w: outgoing %s cannot be determined without reading Body; use nil or http.NoBody for a known empty Body, or set a positive ContentLength or explicit TransferEncoding", ErrInvalidHTTPMessage, canonicalName)
	}
	if !field.present {
		if headerPresent {
			return fmt.Errorf("%w: %s in Header conflicts with the absent outgoing field", ErrInvalidHTTPMessage, canonicalName)
		}
		return fmt.Errorf("%w: %s", ErrSignedHeaderMissing, name)
	}
	if headerPresent {
		if len(headerValues) != 1 {
			return fmt.Errorf("%w: %s in Header must contain exactly one value for outgoing signing", ErrInvalidHTTPMessage, canonicalName)
		}
		headerValue := trimCavageOWS(headerValues[0])
		if err := validateOutgoingHTTPFieldValue(name, headerValue); err != nil {
			return err
		}
		if normalize != nil {
			var err error
			headerValue, err = normalize(headerValue)
			if err != nil {
				return err
			}
		}
		if headerValue != field.value {
			return fmt.Errorf("%w: %s in Header conflicts with the outgoing field", ErrInvalidHTTPMessage, canonicalName)
		}
	}

	resolved[canonicalName] = []string{field.value}
	return nil
}

func validateOutgoingHTTPFieldValue(name, value string) error {
	if byteIndex, ok := forbiddenHeaderValueByteIndex(value); ok {
		return fmt.Errorf("%w: HTTP field %q value index 0 contains a forbidden control byte at byte position %d", ErrInvalidHTTPMessage, name, byteIndex+1)
	}
	return nil
}

func outgoingRequestHostField(req *http.Request) (outgoingHTTPField, error) {
	if req.URL == nil {
		return outgoingHTTPField{}, fmt.Errorf("%w: request host cannot be determined without URL", ErrInvalidHTTPMessage)
	}
	source := req.Host
	if source == "" {
		source = req.URL.Host
	}
	if err := validateOutgoingHTTPFieldValue("host", source); err != nil {
		return outgoingHTTPField{}, err
	}
	host, err := normalizeOutgoingRequestHost(source)
	if err != nil {
		return outgoingHTTPField{}, err
	}
	return outgoingHTTPField{value: host, present: true, known: true}, nil
}

// normalizeOutgoingRequestHost delegates to Request.Write so host IDNA
// conversion, invalid-host clearing, and IPv6 zone removal stay aligned with
// the Go 1.26 net/http request writer without copying its internal httpguts use.
// TestCavageRequestSignerUsesOutgoingHost checks this behavior against
// Request.Write output.
func normalizeOutgoingRequestHost(host string) (string, error) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Host: host, Path: "/"},
		Host:   host,
		Header: make(http.Header),
	}
	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		return "", fmt.Errorf("%w: request Host cannot be represented by net/http", ErrInvalidHTTPMessage)
	}
	lines := strings.SplitN(wire.String(), "\r\n", 3)
	if len(lines) < 2 {
		return "", fmt.Errorf("%w: net/http did not write a Host field", ErrInvalidHTTPMessage)
	}
	name, value, ok := strings.Cut(lines[1], ":")
	if !ok || name != "Host" {
		return "", fmt.Errorf("%w: net/http did not write a Host field", ErrInvalidHTTPMessage)
	}
	return strings.TrimPrefix(value, " "), nil
}

// outgoingRequestTransferFields follows Request.outgoingLength,
// newTransferWriter, and transferWriter.shouldSendContentLength in Go 1.26.
// The Body-probe branch is represented as unknown rather than reading Body.
// TestCavageRequestSignerUsesOutgoingContentLength and
// TestCavageRequestSignerUsesOutgoingTransferEncodingAndTrailer compare
// against Request.Write output.
func outgoingRequestTransferFields(req *http.Request, includeTrailer bool) (outgoingTransferFields, error) {
	if req.Body == nil && req.ContentLength != 0 {
		return outgoingTransferFields{}, fmt.Errorf("%w: request ContentLength is nonzero with nil Body", ErrInvalidHTTPMessage)
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}
	bodyNil := req.Body == nil
	bodyIsNoBody := req.Body == http.NoBody
	contentLength := int64(-1)
	switch {
	case bodyNil || bodyIsNoBody:
		contentLength = 0
	case req.ContentLength != 0:
		contentLength = req.ContentLength
	}

	transferEncoding := req.TransferEncoding
	if contentLength < 0 && len(transferEncoding) == 0 {
		switch {
		case method == "CONNECT":
		case requestMethodUsuallyLacksBody(method):
			fields := outgoingTransferFields{
				contentLength:    outgoingHTTPField{known: true},
				transferEncoding: outgoingHTTPField{known: false},
				trailer:          outgoingHTTPField{known: len(req.Trailer) == 0},
			}
			return fields, nil
		default:
			transferEncoding = []string{"chunked"}
		}
	}

	if bodyNil {
		transferEncoding = nil
	}
	if outgoingIsChunked(transferEncoding) {
		contentLength = -1
	} else if bodyNil {
		contentLength = 0
	}

	fields := outgoingTransferFields{
		contentLength:    outgoingContentLengthField(method, contentLength, transferEncoding),
		transferEncoding: outgoingTransferEncodingField(transferEncoding),
		trailer:          outgoingHTTPField{known: true},
	}
	if includeTrailer && outgoingIsChunked(transferEncoding) {
		trailer, err := outgoingTrailerField(req.Trailer)
		if err != nil {
			return outgoingTransferFields{}, err
		}
		fields.trailer = trailer
	}
	return fields, nil
}

func requestMethodUsuallyLacksBody(method string) bool {
	switch method {
	case "GET", "HEAD", "DELETE", "OPTIONS", "PROPFIND", "SEARCH":
		return true
	}
	return false
}

// outgoingResponseTransferFields follows Response.Write and
// newTransferWriter in Go 1.26. Response.Write probes an arbitrary non-nil
// Body when ContentLength is zero; only fields that differ across the empty
// and non-empty outcomes are marked unknown.
// TestCavageResponseSignerUsesOutgoingManagedFields and
// TestCavageResponseSignerRejectsIndeterminateContentLengthWithoutBodyProbe
// compare against Response.Write output.
func outgoingResponseTransferFields(res *http.Response, includeTrailer bool) (outgoingTransferFields, error) {
	if res.ContentLength == 0 && res.Body != nil && res.Body != http.NoBody {
		empty, err := outgoingResponseTransferState(res, 0, false, includeTrailer)
		if err != nil {
			return outgoingTransferFields{}, err
		}
		nonEmpty, err := outgoingResponseTransferState(res, -1, false, includeTrailer)
		if err != nil {
			return outgoingTransferFields{}, err
		}
		return outgoingTransferFields{
			contentLength:    combineOutgoingHTTPField(empty.contentLength, nonEmpty.contentLength),
			transferEncoding: combineOutgoingHTTPField(empty.transferEncoding, nonEmpty.transferEncoding),
			trailer:          combineOutgoingHTTPField(empty.trailer, nonEmpty.trailer),
		}, nil
	}
	return outgoingResponseTransferState(res, res.ContentLength, res.Body == nil, includeTrailer)
}

func outgoingResponseTransferState(res *http.Response, contentLength int64, bodyNil, includeTrailer bool) (outgoingTransferFields, error) {
	method := ""
	if res.Request != nil {
		method = res.Request.Method
	}
	originalTransferEncoding := res.TransferEncoding
	transferEncoding := originalTransferEncoding
	transferContentLength := contentLength
	responseToHEAD := method == "HEAD"
	atLeastHTTP11 := res.ProtoMajor > 1 || res.ProtoMajor == 1 && res.ProtoMinor >= 1

	if responseToHEAD {
		if outgoingIsChunked(transferEncoding) {
			transferContentLength = -1
		}
	} else {
		if !atLeastHTTP11 || bodyNil {
			transferEncoding = nil
		}
		if outgoingIsChunked(transferEncoding) {
			transferContentLength = -1
		} else if bodyNil {
			transferContentLength = 0
		}
	}

	contentLengthField := outgoingContentLengthField(method, transferContentLength, transferEncoding)
	// Match Response.Write's explicit Content-Length: 0 when the transfer writer
	// has not already sent a Content-Length field.
	if !contentLengthField.present && contentLength == 0 && !outgoingIsChunked(originalTransferEncoding) && outgoingBodyAllowedForStatus(res.StatusCode) {
		contentLengthField = outgoingHTTPField{value: "0", present: true, known: true}
	}
	fields := outgoingTransferFields{
		contentLength:    contentLengthField,
		transferEncoding: outgoingTransferEncodingField(transferEncoding),
		trailer:          outgoingHTTPField{known: true},
	}
	if includeTrailer && outgoingIsChunked(transferEncoding) {
		trailer, err := outgoingTrailerField(res.Trailer)
		if err != nil {
			return outgoingTransferFields{}, err
		}
		fields.trailer = trailer
	}
	return fields, nil
}

func outgoingContentLengthField(method string, contentLength int64, transferEncoding []string) outgoingHTTPField {
	field := outgoingHTTPField{known: true}
	if outgoingIsChunked(transferEncoding) || contentLength < 0 {
		return field
	}
	if contentLength > 0 || method == "POST" || method == "PUT" || method == "PATCH" ||
		contentLength == 0 && outgoingIsIdentity(transferEncoding) && method != "GET" && method != "HEAD" {
		field.present = true
		field.value = strconv.FormatInt(contentLength, 10)
	}
	return field
}

func outgoingTransferEncodingField(transferEncoding []string) outgoingHTTPField {
	if outgoingIsChunked(transferEncoding) {
		return outgoingHTTPField{value: "chunked", present: true, known: true}
	}
	return outgoingHTTPField{known: true}
}

func outgoingTrailerField(trailer http.Header) (outgoingHTTPField, error) {
	field := outgoingHTTPField{known: true}
	keys := make([]string, 0, len(trailer))
	for key := range trailer {
		key = http.CanonicalHeaderKey(key)
		switch key {
		case "Transfer-Encoding", "Trailer", "Content-Length":
			return outgoingHTTPField{}, fmt.Errorf("%w: invalid Trailer key", ErrInvalidHTTPMessage)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return field, nil
	}
	slices.Sort(keys)
	field.present = true
	field.value = strings.Join(keys, ",")
	return field, nil
}

func combineOutgoingHTTPField(first, second outgoingHTTPField) outgoingHTTPField {
	if first == second {
		return first
	}
	return outgoingHTTPField{known: false}
}

func outgoingIsChunked(transferEncoding []string) bool {
	return len(transferEncoding) > 0 && transferEncoding[0] == "chunked"
}

func outgoingIsIdentity(transferEncoding []string) bool {
	return len(transferEncoding) == 1 && transferEncoding[0] == "identity"
}

func outgoingBodyAllowedForStatus(status int) bool {
	return !(status >= 100 && status <= 199 || status == http.StatusNoContent || status == http.StatusNotModified)
}
