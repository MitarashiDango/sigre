package sigre

import (
	"bytes"
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

// defaultExpirySeconds is the fallback signature lifetime when Expiry is unset.
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

// String serialises p into the Cavage signature-params wire format.
func (p *cavageParams) String() string {
	var sb strings.Builder
	sb.Grow(8192)

	sb.WriteString("keyId=\"")
	sb.WriteString(p.KeyId)
	sb.WriteString("\",signature=\"")
	sb.WriteString(p.Signature)
	sb.WriteString("\"")

	if p.Algorithm != "" {
		sb.WriteString(",algorithm=\"")
		sb.WriteString(p.Algorithm)
		sb.WriteString("\"")
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
		sb.WriteString(",headers=\"")
		for i, h := range p.Headers {
			if i > 0 {
				sb.WriteString(" ")
			}
			sb.WriteString(h)
		}
		sb.WriteString("\"")
	}

	return sb.String()
}

// parseCavageParams parses a Cavage HTTP Signature parameter string as defined in
// draft-cavage-http-signatures-12 Section 2.1.
func parseCavageParams(input string) (*cavageParams, error) {
	kvPairs := make(map[string]string, 6)
	state := 0
	var buf strings.Builder
	buf.Grow(4096)
	var paramName string
	var unquoted bool

	for pos, ch := range input {
		switch state {
		case 0: // reading parameter name
			if ch == '=' {
				if buf.Len() == 0 {
					return nil, fmt.Errorf("parameter name required")
				}
				paramName = buf.String()
				buf.Reset()
				state++
			} else {
				buf.WriteRune(ch)
			}
		case 1: // before value
			if ch == '"' {
				unquoted = false
				buf.Grow(4096)
				state++
			} else if (paramName == "created" || paramName == "expires") && ch != ',' {
				unquoted = true
				buf.WriteRune(ch)
				state++
			} else {
				return nil, fmt.Errorf("unexpected character '%c' at position %d, expected '\"'", ch, pos+1)
			}
		case 2: // reading value
			if (!unquoted && ch == '"') || (unquoted && ch == ',') {
				if _, ok := kvPairs[paramName]; ok {
					return nil, fmt.Errorf("duplicate parameter name '%s' found", paramName)
				}
				kvPairs[paramName] = buf.String()
				buf.Reset()
				paramName = ""
				if !unquoted {
					state++
				} else {
					buf.Grow(4096)
					state = 0
				}
			} else {
				buf.WriteRune(ch)
			}
		case 3: // after value
			if ch == ',' {
				buf.Grow(4096)
				state = 0
			} else {
				return nil, fmt.Errorf("unexpected character '%c' at position %d, expected ',' or end of input", ch, pos+1)
			}
		}
	}

	if state == 0 && buf.Len() > 0 {
		return nil, fmt.Errorf("unexpected end of input while reading parameter name")
	}
	if state == 1 {
		return nil, fmt.Errorf("unexpected end of input, expecting '\"' for parameter value")
	}
	if state == 2 {
		if !unquoted {
			return nil, fmt.Errorf("unexpected end of input, unclosed parameter value for '%s'", paramName)
		}
		if buf.Len() == 0 {
			return nil, fmt.Errorf("unexpected end of input while reading parameter value")
		}
		kvPairs[paramName] = buf.String()
	}

	var hasHeaders bool
	p := &cavageParams{}
	for key, value := range kvPairs {
		switch key {
		case "keyId":
			p.KeyId = value
		case "signature":
			p.Signature = value
		case "algorithm":
			p.Algorithm = value
		case "created":
			if err := isValidUnixTime(value); err != nil {
				return nil, fmt.Errorf("invalid 'created' value: %w", err)
			}
			p.Created = value
		case "expires":
			if err := isValidUnixTime(value); err != nil {
				return nil, fmt.Errorf("invalid 'expires' value: %w", err)
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
		// Unrecognised parameters are silently ignored per Section 2.2.
	}

	if p.KeyId == "" {
		return nil, fmt.Errorf("missing required parameter: keyId")
	}
	if p.Signature == "" {
		return nil, fmt.Errorf("missing required parameter: signature")
	}
	if len(p.Headers) == 0 && hasHeaders {
		return nil, fmt.Errorf("'header' parameter must specify a non-empty value")
	}

	return p, nil
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
