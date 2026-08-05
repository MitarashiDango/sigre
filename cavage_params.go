package sigre

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Cavage HTTP Signature pseudo-header names (draft-cavage-http-signatures-12 Section 2.3).
const (
	RequestTarget = "(request-target)"
	Created       = "(created)"
	Expires       = "(expires)"
)

// hs2019 is the non-deprecated algorithm identifier defined in the IANA
// HTTP Signature Algorithms Registry (Appendix E.2).
const hs2019 = "hs2019"

// defaultExpirySeconds is used for (expires) when Expiry is unset.
const defaultExpirySeconds int64 = 60

// cavageParams holds the parsed fields of a Cavage HTTP Signature header.
type cavageParams struct {
	KeyId          string
	Signature      string
	Algorithm      string
	Created        string // Unix timestamp as decimal string
	Expires        string // Unix timestamp as decimal string
	Headers        []string
	HeadersPresent bool
}

// serializeCavageParams serialises p into the Cavage signature-params wire format.
func serializeCavageParams(p *cavageParams) (string, error) {
	if p == nil {
		return "", fmt.Errorf("signature parameters are nil")
	}
	if err := validateCavageKeyID(p.KeyId); err != nil {
		return "", err
	}
	if p.Signature == "" {
		return "", fmt.Errorf("missing required parameter: signature")
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(p.Signature); err != nil {
		return "", fmt.Errorf("invalid 'signature' value: %w", err)
	}
	if p.Created != "" {
		if err := isValidUnixTime(p.Created); err != nil {
			return "", fmt.Errorf("invalid 'created' value: %w", err)
		}
	}
	if p.Expires != "" {
		if err := isValidUnixTime(p.Expires); err != nil {
			return "", fmt.Errorf("invalid 'expires' value: %w", err)
		}
	}

	var sb strings.Builder
	if err := appendCavageQuotedString(&sb, "keyId", p.KeyId); err != nil {
		return "", err
	}
	sb.WriteString(",")
	if err := appendCavageQuotedString(&sb, "signature", p.Signature); err != nil {
		return "", err
	}

	if p.Algorithm != "" {
		sb.WriteString(",")
		if err := appendCavageQuotedString(&sb, "algorithm", p.Algorithm); err != nil {
			return "", err
		}
	}

	if p.Created != "" {
		sb.WriteString(",created=")
		sb.WriteString(p.Created)
	}

	if p.Expires != "" {
		sb.WriteString(",expires=")
		sb.WriteString(p.Expires)
	}

	if len(p.Headers) > 0 {
		for _, h := range p.Headers {
			if h == "" {
				return "", fmt.Errorf("'headers' parameter must not contain an empty header name")
			}
		}
		sb.WriteString(",")
		if err := appendCavageQuotedString(&sb, "headers", strings.Join(p.Headers, " ")); err != nil {
			return "", err
		}
	}

	return sb.String(), nil
}

func appendCavageQuotedString(sb *strings.Builder, name, value string) error {
	if err := validateCavageQuotedStringValue(name, value); err != nil {
		return err
	}

	sb.WriteString(name)
	sb.WriteString("=\"")
	for i := 0; i < len(value); i++ {
		if value[i] == '"' || value[i] == '\\' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(value[i])
	}
	sb.WriteByte('"')
	return nil
}

func validateCavageKeyID(keyID string) error {
	if keyID == "" {
		return fmt.Errorf("missing required parameter: keyId")
	}
	return validateCavageQuotedStringValue("keyId", keyID)
}

func validateCavageQuotedStringValue(name, value string) error {
	for i := 0; i < len(value); i++ {
		if isForbiddenHeaderValueByte(value[i]) {
			return fmt.Errorf("'%s' contains a byte that cannot be written to an HTTP header", name)
		}
	}
	return nil
}

// parseCavageParams parses a Cavage HTTP Signature parameter string as defined in
// draft-cavage-http-signatures-12 Section 2.1.
func parseCavageParams(input string) (*cavageParams, error) {
	var hasHeaders bool
	p := &cavageParams{}
	seen := make(map[string]bool, 6)

	for pos := 0; pos < len(input); {
		segment, next, err := nextCavageAuthParam(input, pos)
		if err != nil {
			return nil, err
		}
		pos = next
		segment = trimCavageOWS(segment)
		if segment == "" {
			continue
		}

		name, valueStart, wellFormedName := parseCavageAuthParamName(segment)
		canonicalName, known := knownCavageParamName(name)
		if known {
			if seen[canonicalName] {
				return nil, fmt.Errorf("duplicate parameter name '%s' found", name)
			}
			seen[canonicalName] = true
		}
		if !wellFormedName || !known {
			continue
		}

		value, wellFormedValue := parseCavageAuthParamValue(segment, valueStart)
		if !wellFormedValue {
			continue
		}

		switch canonicalName {
		case "keyid":
			p.KeyId = value
		case "signature":
			p.Signature = value
		case "algorithm":
			p.Algorithm = value
		case "created":
			if err := isValidUnixTime(value); err != nil {
				continue
			}
			p.Created = value
		case "expires":
			if err := isValidUnixTime(value); err != nil {
				continue
			}
			p.Expires = value
		case "headers":
			hasHeaders = true
			p.HeadersPresent = true
			for _, h := range strings.Split(value, " ") {
				if h != "" {
					p.Headers = append(p.Headers, strings.ToLower(h))
				}
			}
		}
	}

	if p.KeyId == "" {
		return nil, fmt.Errorf("missing required parameter: keyId")
	}
	if p.Signature == "" {
		return nil, fmt.Errorf("missing required parameter: signature")
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(p.Signature); err != nil {
		return nil, fmt.Errorf("invalid 'signature' value: %w", err)
	}
	if len(p.Headers) == 0 && hasHeaders {
		return nil, fmt.Errorf("'headers' parameter must specify a non-empty value")
	}

	return p, nil
}

func nextCavageAuthParam(input string, start int) (segment string, next int, err error) {
	inQuotedString := false
	for i := start; i < len(input); i++ {
		b := input[i]
		if isForbiddenHeaderValueByte(b) {
			return "", 0, fmt.Errorf("forbidden control byte at position %d", i+1)
		}
		if !inQuotedString {
			switch b {
			case ',':
				return input[start:i], i + 1, nil
			case '"':
				inQuotedString = true
			}
			continue
		}

		switch b {
		case '"':
			inQuotedString = false
		case '\\':
			if i+1 >= len(input) {
				return "", 0, fmt.Errorf("incomplete quoted-pair at end of input")
			}
			if !isCavageQuotedPairByte(input[i+1]) {
				return "", 0, fmt.Errorf("invalid quoted-pair at position %d", i+1)
			}
			i++
		default:
			if !isCavageQDTextByte(b) {
				return "", 0, fmt.Errorf("invalid quoted-string byte at position %d", i+1)
			}
		}
	}
	if inQuotedString {
		return "", 0, fmt.Errorf("unexpected end of input: unclosed quoted-string")
	}
	return input[start:], len(input), nil
}

func parseCavageAuthParamName(segment string) (name string, valueStart int, wellFormed bool) {
	pos := 0
	for pos < len(segment) && isCavageTokenByte(segment[pos]) {
		pos++
	}
	if pos == 0 {
		return "", 0, false
	}
	name = segment[:pos]
	pos = skipCavageOWS(segment, pos)
	if pos >= len(segment) || segment[pos] != '=' {
		return name, 0, false
	}
	pos++
	pos = skipCavageOWS(segment, pos)
	if pos >= len(segment) {
		return name, 0, false
	}
	return name, pos, true
}

func parseCavageAuthParamValue(segment string, pos int) (value string, wellFormed bool) {
	if segment[pos] == '"' {
		var ok bool
		value, pos, ok = parseCavageQuotedString(segment, pos)
		if !ok {
			return "", false
		}
	} else {
		valueStart := pos
		for pos < len(segment) && isCavageTokenByte(segment[pos]) {
			pos++
		}
		if pos == valueStart {
			return "", false
		}
		value = segment[valueStart:pos]
	}

	pos = skipCavageOWS(segment, pos)
	return value, pos == len(segment)
}

func parseCavageQuotedString(input string, start int) (value string, next int, ok bool) {
	valueStart := start + 1
	last := valueStart
	var sb strings.Builder
	for pos := valueStart; pos < len(input); pos++ {
		switch input[pos] {
		case '"':
			if sb.Len() == 0 {
				return input[valueStart:pos], pos + 1, true
			}
			sb.WriteString(input[last:pos])
			return sb.String(), pos + 1, true
		case '\\':
			if pos+1 >= len(input) || !isCavageQuotedPairByte(input[pos+1]) {
				return "", 0, false
			}
			if sb.Len() == 0 {
				sb.Grow(len(input) - valueStart)
			}
			sb.WriteString(input[last:pos])
			sb.WriteByte(input[pos+1])
			pos++
			last = pos + 1
		default:
			if !isCavageQDTextByte(input[pos]) {
				return "", 0, false
			}
		}
	}
	return "", 0, false
}

func knownCavageParamName(name string) (string, bool) {
	switch {
	case strings.EqualFold(name, "keyId"):
		return "keyid", true
	case strings.EqualFold(name, "signature"):
		return "signature", true
	case strings.EqualFold(name, "algorithm"):
		return "algorithm", true
	case strings.EqualFold(name, "created"):
		return "created", true
	case strings.EqualFold(name, "expires"):
		return "expires", true
	case strings.EqualFold(name, "headers"):
		return "headers", true
	default:
		return "", false
	}
}

func trimCavageOWS(value string) string {
	start := skipCavageOWS(value, 0)
	end := len(value)
	for end > start && isCavageOWS(value[end-1]) {
		end--
	}
	return value[start:end]
}

func skipCavageOWS(value string, pos int) int {
	for pos < len(value) && isCavageOWS(value[pos]) {
		pos++
	}
	return pos
}

func isCavageOWS(b byte) bool {
	return b == ' ' || b == '\t'
}

func isCavageTokenByte(b byte) bool {
	return b >= '0' && b <= '9' ||
		b >= 'A' && b <= 'Z' ||
		b >= 'a' && b <= 'z' ||
		strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}

func isCavageQDTextByte(b byte) bool {
	return b == '\t' || b == ' ' || b == '!' ||
		b >= '#' && b <= '[' || b >= ']' && b <= '~' || b >= 0x80
}

func isCavageQuotedPairByte(b byte) bool {
	return b == '\t' || b == ' ' || b >= '!' && b <= '~' || b >= 0x80
}

func isForbiddenHeaderValueByte(b byte) bool {
	return b < ' ' && b != '\t' || b == 0x7f
}

// validateCreatedExpiresWithAlgorithm enforces the Section 2.3 restriction:
// the (created) and (expires) pseudo-headers MUST NOT appear in the headers list
// when the algorithm starts with "rsa", "hmac", or "ecdsa".
func validateCreatedExpiresWithAlgorithm(headers []string, keyType string) error {
	if keyType != "rsa" && keyType != "hmac" && keyType != "ecdsa" {
		return nil
	}
	if slices.Contains(headers, Created) {
		return fmt.Errorf("%w: '(created)' MUST NOT be used with '%s' family algorithms", ErrInvalidSignatureAlgorithm, keyType)
	}
	if slices.Contains(headers, Expires) {
		return fmt.Errorf("%w: '(expires)' MUST NOT be used with '%s' family algorithms", ErrInvalidSignatureAlgorithm, keyType)
	}
	return nil
}

// outgoingRequestTarget returns the origin-form that net/http sends for a
// client URL without reparsing or re-encoding its query.
func outgoingRequestTarget(u *url.URL) string {
	if u == nil || u.Opaque != "" {
		return ""
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.ForceQuery || u.RawQuery != "" {
		return path + "?" + u.RawQuery
	}
	return path
}

// associatedRequestTarget handles the request associated with a response.
// Server-side responses retain the received RequestURI, while client-side
// responses refer to the URL of the request that was sent.
func associatedRequestTarget(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.RequestURI != "" {
		return req.RequestURI
	}
	return outgoingRequestTarget(req.URL)
}

func normalizeCavageSignedHeaderName(name string) (string, error) {
	lowerName := strings.ToLower(name)
	switch lowerName {
	case RequestTarget, Created, Expires:
		return lowerName, nil
	}

	if name == "" {
		return "", fmt.Errorf("signed header name is empty")
	}
	for i := 0; i < len(name); i++ {
		if !isCavageTokenByte(name[i]) {
			return "", fmt.Errorf("invalid HTTP field-name in signed headers: %q", name)
		}
	}
	return lowerName, nil
}

func appendCavageHeaderValues(buf *bytes.Buffer, values []string) {
	for i, value := range values {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(trimCavageOWS(value))
	}
}

// generateSignatureStringBuffer builds the signature string as defined in
// draft-cavage-http-signatures-12 Section 2.3.
func generateSignatureStringBuffer(
	headers []string,
	host string,
	method string,
	requestTarget string,
	header http.Header,
	createdValue string,
	expiresValue string,
) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	buf.Grow(8192)

	for i, configuredName := range headers {
		name, err := normalizeCavageSignedHeaderName(configuredName)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString(name)
		buf.WriteString(": ")

		switch name {
		case RequestTarget:
			if method == "" {
				return nil, fmt.Errorf("'%s' is included, but method is missing", RequestTarget)
			}
			if requestTarget == "" {
				return nil, fmt.Errorf("'%s' is included, but request-target is missing", RequestTarget)
			}
			buf.WriteString(strings.ToLower(method))
			buf.WriteString(" ")
			buf.WriteString(requestTarget)
		case Created:
			if createdValue == "" {
				return nil, fmt.Errorf("'%s' is included in signing string, but 'created' value is empty", Created)
			}
			buf.WriteString(createdValue)
		case Expires:
			if expiresValue == "" {
				return nil, fmt.Errorf("'%s' is included in signing string, but 'expires' value is empty", Expires)
			}
			buf.WriteString(expiresValue)
		case "host":
			values, ok := header[http.CanonicalHeaderKey(name)]
			if ok {
				if len(values) == 0 {
					return nil, fmt.Errorf("missing header in message for signing string: %s", name)
				}
				appendCavageHeaderValues(buf, values)
			} else if host != "" {
				buf.WriteString(trimCavageOWS(host))
			} else {
				return nil, fmt.Errorf("failed to get host value for signing string: 'Host' header missing and no fallback host provided")
			}
		default:
			vals, ok := header[http.CanonicalHeaderKey(name)]
			if !ok || len(vals) == 0 {
				return nil, fmt.Errorf("missing header in message for signing string: %s (canonical: %s)", name, http.CanonicalHeaderKey(name))
			}
			appendCavageHeaderValues(buf, vals)
		}
	}

	return buf, nil
}
