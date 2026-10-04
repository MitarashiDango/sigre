package sigre

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type cavageParams struct {
	KeyID            string
	Signature        string
	Algorithm        string
	AlgorithmPresent bool
	// Created and Expires hold parameter text. Time syntax is checked by
	// CavageVerifier.parse, not parseCavageParams.
	Created        string
	CreatedPresent bool
	Expires        string
	ExpiresPresent bool
	Headers        []string
	HeadersPresent bool
}

func serializeCavageParams(p *cavageParams) (string, error) {
	var sb strings.Builder
	if err := appendCavageQuotedString(&sb, "keyId", p.KeyID); err != nil {
		return "", err
	}
	sb.WriteString(",")
	if err := appendCavageQuotedString(&sb, "signature", p.Signature); err != nil {
		return "", err
	}

	if p.AlgorithmPresent || p.Algorithm != "" {
		sb.WriteString(",")
		if err := appendCavageQuotedString(&sb, "algorithm", p.Algorithm); err != nil {
			return "", err
		}
	}

	if p.CreatedPresent || p.Created != "" {
		if err := appendCavageToken(&sb, "created", p.Created); err != nil {
			return "", err
		}
	}

	if p.ExpiresPresent || p.Expires != "" {
		if err := appendCavageToken(&sb, "expires", p.Expires); err != nil {
			return "", err
		}
	}

	if p.HeadersPresent || len(p.Headers) > 0 {
		sb.WriteString(",")
		if err := appendCavageQuotedString(&sb, "headers", strings.Join(p.Headers, " ")); err != nil {
			return "", err
		}
	}

	return sb.String(), nil
}

// appendCavageToken writes an unquoted parameter value. The value must be a
// non-empty token so that the serialized parameter can be parsed again.
func appendCavageToken(sb *strings.Builder, name, value string) error {
	if value == "" {
		return fmt.Errorf("'%s' must be a non-empty token", name)
	}
	for i := 0; i < len(value); i++ {
		if !isCavageTokenByte(value[i]) {
			return fmt.Errorf("'%s' contains a non-token byte at position %d", name, i)
		}
	}
	sb.WriteString(",")
	sb.WriteString(name)
	sb.WriteString("=")
	sb.WriteString(value)
	return nil
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
	if _, ok := forbiddenHeaderValueByteIndex(value); ok {
		return fmt.Errorf("'%s' contains a byte that cannot be written to an HTTP header", name)
	}
	return nil
}

// parseCavageParams parses a Cavage HTTP Signature parameter string as defined in
// draft-cavage-http-signatures-12 Section 2.1.
func parseCavageParams(input string) (*cavageParams, error) {
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
		if !wellFormedName {
			continue
		}
		canonicalName, known := knownCavageParamName(name)
		if !known {
			continue
		}

		value, wellFormedValue := parseCavageAuthParamValue(segment, valueStart)
		if !wellFormedValue {
			continue
		}
		if seen[canonicalName] {
			return nil, fmt.Errorf("duplicate parameter name '%s' found", name)
		}
		seen[canonicalName] = true

		switch canonicalName {
		case "keyid":
			p.KeyID = value
		case "signature":
			p.Signature = value
		case "algorithm":
			p.Algorithm = value
			p.AlgorithmPresent = true
		case "created":
			p.Created = value
			p.CreatedPresent = true
		case "expires":
			p.Expires = value
			p.ExpiresPresent = true
		case "headers":
			p.HeadersPresent = true
			for _, h := range strings.Split(value, " ") {
				if h != "" {
					p.Headers = append(p.Headers, h)
				}
			}
		}
	}

	if p.KeyID == "" {
		return nil, fmt.Errorf("missing required parameter: keyId")
	}
	if p.Signature == "" {
		return nil, fmt.Errorf("missing required parameter: signature")
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(p.Signature); err != nil {
		return nil, fmt.Errorf("invalid 'signature' value: %w", err)
	}
	if len(p.Headers) == 0 && p.HeadersPresent {
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

func forbiddenHeaderValueByteIndex(value string) (int, bool) {
	for i := 0; i < len(value); i++ {
		if isForbiddenHeaderValueByte(value[i]) {
			return i, true
		}
	}
	return 0, false
}
