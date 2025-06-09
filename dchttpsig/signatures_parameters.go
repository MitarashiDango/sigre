package dchttpsig

import (
	"fmt"
	"strings"
)

type signaturesParameters struct {
	KeyId             string
	Signature         string
	Algorithm         string
	Created           string // Unix timestamp (sec)
	Expires           string // Unix timestamp (sec)
	SignTargetHeaders []string
}

func (sp *signaturesParameters) String() string {
	var sb strings.Builder
	sb.Grow(8192) // Initial capacity

	sb.WriteString("keyId=\"")
	sb.WriteString(sp.KeyId)
	sb.WriteString("\",signature=\"")
	sb.WriteString(sp.Signature)
	sb.WriteString("\"")

	if sp.Algorithm != "" {
		sb.WriteString(",algorithm=\"")
		sb.WriteString(sp.Algorithm)
		sb.WriteString("\"")
	}

	if sp.Created != "" {
		sb.WriteString(",created=\"")
		sb.WriteString(sp.Created)
		sb.WriteString("\"")
	}

	if sp.Expires != "" {
		sb.WriteString(",expires=\"")
		sb.WriteString(sp.Expires)
		sb.WriteString("\"")
	}

	if len(sp.SignTargetHeaders) > 0 {
		sb.WriteString(",headers=\"")
		for i, val := range sp.SignTargetHeaders {
			if i > 0 {
				sb.WriteString(" ")
			}
			sb.WriteString(val)
		}
		sb.WriteString("\"")
	}

	return sb.String()
}

func parseSignatureParameters(input string) (*signaturesParameters, error) {
	keyValuePairs := make(map[string]string, 6)
	state := 0
	var buf strings.Builder
	buf.Grow(4096)
	var parameterName string
	var noQuotes bool
	for pos, ch := range input {
		switch state {
		case 0: // Reading parameter name
			if ch == '=' {
				if buf.Len() == 0 {
					return nil, fmt.Errorf("parameter name required")
				}
				parameterName = buf.String()
				buf.Reset()
				state++
			} else {
				buf.WriteRune(ch)
			}
		case 1: // Before parameter value
			if ch == '"' {
				noQuotes = false
				buf.Grow(4096)
				state++
			} else if (parameterName == "created" || parameterName == "expires") && ch != ',' {
				noQuotes = true
				buf.WriteRune(ch)
				state++
			} else {
				return nil, fmt.Errorf("unexpected character '%c' at position %d, expected '\"'", ch, pos+1)
			}
		case 2: // Reading parameter value
			if (!noQuotes && ch == '"') || (noQuotes && ch == ',') {
				if _, ok := keyValuePairs[parameterName]; ok {
					return nil, fmt.Errorf("duplicate parameter name '%s' found", parameterName)
				}
				keyValuePairs[parameterName] = buf.String()
				buf.Reset()
				parameterName = ""
				if !noQuotes {
					state++
				} else {
					buf.Grow(4096)
					state = 0
				}
			} else {
				buf.WriteRune(ch)
			}
		case 3: // After parameter item (expecting comma or end)
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
		if !noQuotes {
			return nil, fmt.Errorf("unexpected end of input, unclosed parameter value for '%s'", parameterName)
		}

		if buf.Len() == 0 {
			return nil, fmt.Errorf("unexpected end of input while reading parameter value")
		}

		// "created" or "expires"
		keyValuePairs[parameterName] = buf.String()
	}

	var hasHeadersParameter bool
	sp := &signaturesParameters{}
	for key, value := range keyValuePairs {
		switch key {
		case "keyId":
			sp.KeyId = value
		case "signature":
			sp.Signature = value
		case "algorithm":
			sp.Algorithm = value
		case "created":
			if err := isValidUnixTime(value); err != nil {
				return nil, fmt.Errorf("invalid 'created' value: %w", err)
			}
			sp.Created = value
		case "expires":
			if err := isValidUnixTime(value); err != nil {
				return nil, fmt.Errorf("invalid 'expires' value: %w", err)
			}
			sp.Expires = value
		case "headers":
			hasHeadersParameter = true
			rawHeaders := strings.Split(value, " ")
			sp.SignTargetHeaders = make([]string, 0, len(rawHeaders))
			for _, h := range rawHeaders {
				trimmedHeader := strings.TrimSpace(h)
				if trimmedHeader != "" {
					sp.SignTargetHeaders = append(sp.SignTargetHeaders, strings.ToLower(trimmedHeader))
				}
			}
		default:
			// 上記以外のパラメーターは全て無視する
		}
	}

	// Validate required parameters (as per draft-cavage-http-signatures-12 section 2.1)
	if sp.KeyId == "" {
		return nil, fmt.Errorf("missing required parameter: keyId")
	}

	if sp.Signature == "" {
		return nil, fmt.Errorf("missing required parameter: signature")
	}

	if len(sp.SignTargetHeaders) == 0 && hasHeadersParameter {
		return nil, fmt.Errorf("'header' parameter must specify a non-empty value")
	}

	return sp, nil
}
