package sigre

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
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
	KeyId     string
	Signature string
	Algorithm string
	Created   string // Unix timestamp as decimal string
	Expires   string // Unix timestamp as decimal string
	Headers   []string
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
			for _, h := range strings.Split(value, " ") {
				if trimmed := strings.TrimSpace(h); trimmed != "" {
					p.Headers = append(p.Headers, strings.ToLower(trimmed))
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

// generateSignatureStringBuffer builds the signature string as defined in
// draft-cavage-http-signatures-12 Section 2.3.
// headers must already be lowercased; method must be lowercased.
func generateSignatureStringBuffer(
	headers []string,
	host string,
	method string,
	requestPath string,
	requestQuery string,
	header http.Header,
	createdValue string,
	expiresValue string,
) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	buf.Grow(8192)

	for i, name := range headers {
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
			if requestPath == "" {
				return nil, fmt.Errorf("'%s' is included, but requestPath is missing", RequestTarget)
			}
			buf.WriteString(method)
			buf.WriteString(" ")
			buf.WriteString(requestPath)
			if requestQuery != "" {
				buf.WriteString("?")
				buf.WriteString(requestQuery)
			}
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
			if v := header.Get("Host"); v != "" {
				buf.WriteString(v)
			} else if host != "" {
				buf.WriteString(host)
			} else {
				return nil, fmt.Errorf("failed to get host value for signing string: 'Host' header missing and no fallback host provided")
			}
		default:
			vals, ok := header[http.CanonicalHeaderKey(name)]
			if !ok {
				return nil, fmt.Errorf("missing header in message for signing string: %s (canonical: %s)", name, http.CanonicalHeaderKey(name))
			}
			for j, val := range vals {
				if j > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(strings.TrimSpace(val))
			}
		}
	}

	return buf, nil
}
