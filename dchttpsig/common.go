package dchttpsig

import (
	"bytes"
	"crypto"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	RequestTarget = "(request-target)"
	Created       = "(created)"
	Expires       = "(expires)"

	HS2019 = "hs2019" // Special algorithm value

	DefaultExpiryTime = 60 // seconds
)

func getHash(hashAlgorithm string) (crypto.Hash, error) {
	switch hashAlgorithm {
	case "sha256":
		return crypto.SHA256, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, ErrUnsupportedHashAlgorithm
	}
}

func isValidUnixTime(s string) error {
	_, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid integer format: %w", err)
	}

	return nil
}

func generateSignatureStringBuffer(
	signTargetNames []string, // Expected to be lowercase
	host string,
	method string, // Expected to be lowercase
	requestPath string,
	requestQuery string,
	header http.Header,
	createdValue string,
	expiresValue string,
) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	buf.Grow(8192)

	for i, signTargetName := range signTargetNames {
		if i > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString(signTargetName)
		buf.WriteString(": ")

		switch signTargetName {
		case RequestTarget:
			if method == "" {
				return nil, fmt.Errorf("'%s' is included, but method is missing", RequestTarget)
			}
			if requestPath == "" && signTargetName == RequestTarget {
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
		case "host": //must lowercase
			headerVal := header.Get("Host")
			if headerVal != "" {
				buf.WriteString(headerVal)
			} else if host != "" {
				buf.WriteString(host)
			} else {
				return nil, fmt.Errorf("failed to get host value for signing string: 'Host' header missing and no fallback host provided")
			}
		default:
			headerValues, ok := header[http.CanonicalHeaderKey(signTargetName)]
			if !ok {
				return nil, fmt.Errorf("missing header in message for signing string: %s (canonical: %s)", signTargetName, http.CanonicalHeaderKey(signTargetName))
			}
			for j, val := range headerValues {
				if j > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(strings.TrimSpace(val))
			}
		}
	}
	return buf, nil
}
