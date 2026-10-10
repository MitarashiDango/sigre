package sigre

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

const (
	// CavageRequestTarget is the Cavage (request-target) pseudo-header name.
	CavageRequestTarget = "(request-target)"
	// CavageCreated is the Cavage (created) pseudo-header name.
	CavageCreated = "(created)"
	// CavageExpires is the Cavage (expires) pseudo-header name.
	CavageExpires = "(expires)"
)

func normalizeCavageSignedHeaderName(name string) (string, error) {
	// Reject non-ASCII bytes before strings.ToLower, which maps some non-ASCII
	// letters, such as U+212A KELVIN SIGN and U+0130, to ASCII letters. Otherwise
	// a non-ASCII name could alias a field or pseudo-header name.
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return "", fmt.Errorf("invalid HTTP field-name in signed headers: %q", name)
		}
	}
	lowerName := strings.ToLower(name)
	switch lowerName {
	case CavageRequestTarget, CavageCreated, CavageExpires:
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

func appendCavageHeaderValues(buf *bytes.Buffer, name string, values []string) error {
	for valueIndex, value := range values {
		if byteIndex, ok := forbiddenHeaderValueByteIndex(value); ok {
			return fmt.Errorf("%w: HTTP field %q value index %d contains a forbidden control byte at byte position %d", ErrInvalidHTTPMessage, name, valueIndex, byteIndex+1)
		}
	}

	for i, value := range values {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(trimCavageOWS(value))
	}
	return nil
}

// generateCavageSigningString builds the signature string as defined in
// draft-cavage-http-signatures-12 Section 2.3 using normalized signed-header names.
func generateCavageSigningString(
	normalizedHeaders []string,
	method string,
	requestTarget string,
	header http.Header,
	createdValue string,
	expiresValue string,
) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}

	for i, name := range normalizedHeaders {
		if i > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString(name)
		buf.WriteString(": ")

		switch name {
		case CavageRequestTarget:
			if method == "" {
				return nil, fmt.Errorf("%w: '%s' is included, but method is missing", ErrInvalidHTTPMessage, CavageRequestTarget)
			}
			if requestTarget == "" {
				return nil, fmt.Errorf("%w: '%s' is included, but request-target is missing", ErrInvalidHTTPMessage, CavageRequestTarget)
			}
			buf.WriteString(strings.ToLower(method))
			buf.WriteString(" ")
			buf.WriteString(requestTarget)
		case CavageCreated:
			if createdValue == "" {
				return nil, fmt.Errorf("%w: '%s' is included in signing string, but 'created' value is empty", ErrInvalidCreationTime, CavageCreated)
			}
			buf.WriteString(createdValue)
		case CavageExpires:
			if expiresValue == "" {
				return nil, fmt.Errorf("%w: '%s' is included in signing string, but 'expires' value is empty", ErrInvalidExpirationTime, CavageExpires)
			}
			buf.WriteString(expiresValue)
		default:
			vals, ok := header[http.CanonicalHeaderKey(name)]
			if !ok || len(vals) == 0 {
				return nil, fmt.Errorf("%w: %s", ErrSignedHeaderMissing, name)
			}
			if err := appendCavageHeaderValues(buf, name, vals); err != nil {
				return nil, err
			}
		}
	}

	return buf, nil
}
