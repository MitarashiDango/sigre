package sigre_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MitarashiDango/sigre"
)

func TestParseCavageParams(t *testing.T) {
	t.Helper()

	testCases := []struct {
		name          string
		input         string
		expected      *sigre.ExportForTesting_cavageParams
		expectError   bool
		errorContains string
	}{
		// Success cases
		{
			name:  "Success: all parameters present",
			input: `keyId="test-key-1",algorithm="rsa-sha256",created=1618952679,expires=1618952739,headers="(created) (expires) host date digest",signature="Base64SignatureHere"`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "test-key-1",
				Algorithm: "rsa-sha256",
				Created:   "1618952679",
				Expires:   "1618952739",
				Headers: []string{
					"(created)",
					"(expires)",
					"host",
					"date",
					"digest",
				},
				Signature: "Base64SignatureHere",
			},
			expectError: false,
		},
		{
			name:  "Success: without created and expires",
			input: `keyId="test-key-2",algorithm="hmac-sha512",headers="host date",signature="AnotherBase64Signature"`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "test-key-2",
				Algorithm: "hmac-sha512",
				Headers:   []string{"host", "date"},
				Signature: "AnotherBase64Signature",
			},
			expectError: false,
		},
		{
			name:  "Success: uppercase header names in headers param are lowercased",
			input: `keyId="test-key-3",headers="Host Date Content-Type",signature="sig"`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "test-key-3",
				Headers:   []string{"host", "date", "content-type"},
				Signature: "sig",
			},
			expectError: false,
		},
		{
			name:  "Success: different parameter order",
			input: `signature="sig",headers="date",keyId="test-key-4"`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "test-key-4",
				Headers:   []string{"date"},
				Signature: "sig",
			},
			expectError: false,
		},
		{
			name:  "Success: unknown parameters are ignored",
			input: `keyId="test-key-5",signature="sig",custom="some-value"`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "test-key-5",
				Signature: "sig",
			},
			expectError: false,
		},

		// Failure cases
		{
			name:          "Failure: missing required parameter keyId",
			input:         `algorithm="rsa-sha256",signature="sig"`,
			expectError:   true,
			errorContains: "missing required parameter: keyId",
		},
		{
			name:          "Failure: missing required parameter signature",
			input:         `keyId="test-key-1"`,
			expectError:   true,
			errorContains: "missing required parameter: signature",
		},
		{
			name:          "Failure: invalid format (no quotes)",
			input:         `keyId=test-key-1`,
			expectError:   true,
			errorContains: "expected '\"'",
		},
		{
			name:          "Failure: invalid format (unclosed quote)",
			input:         `keyId="test-key-1`,
			expectError:   true,
			errorContains: "unclosed parameter value",
		},
		{
			name:          "Failure: invalid format (extra characters after last parameter)",
			input:         `keyId="test-key-1"a`,
			expectError:   true,
			errorContains: "unexpected character",
		},
		{
			name:          "Failure: duplicate parameter",
			input:         `keyId="key1",keyId="key2",signature="sig"`,
			expectError:   true,
			errorContains: "duplicate parameter name",
		},
		{
			name:          "Failure: invalid created value",
			input:         `keyId="k",signature="s",created="not-a-number"`,
			expectError:   true,
			errorContains: "invalid 'created' value",
		},
		{
			name:          "Failure: invalid expires value",
			input:         `keyId="k",signature="s",expires="not-a-number"`,
			expectError:   true,
			errorContains: "invalid 'expires' value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := sigre.ExportForTesting_parseCavageParams(tc.input)

			if tc.expectError {
				if err == nil {
					t.Fatal("expected an error, but got none")
				}
				if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', but got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect an error, but got: %v", err)
				}
				if !reflect.DeepEqual(tc.expected, actual) {
					t.Errorf("parsed parameters do not match expected\nexpected: %+v\nactual:   %+v", tc.expected, actual)
				}
			}
		})
	}
}
