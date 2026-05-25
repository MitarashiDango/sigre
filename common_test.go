package sigre_test

import (
	"crypto"
	"errors"
	"testing"

	"github.com/MitarashiDango/sigre"
)

func TestGetHash(t *testing.T) {
	t.Helper()

	testCases := []struct {
		name          string
		input         string
		expectedHash  crypto.Hash
		expectedError error
	}{
		{
			name:          "Success: SHA256",
			input:         "sha256",
			expectedHash:  crypto.SHA256,
			expectedError: nil,
		},
		{
			name:          "Success: SHA512",
			input:         "sha512",
			expectedHash:  crypto.SHA512,
			expectedError: nil,
		},
		{
			name:          "Failure: unsupported algorithm",
			input:         "sha1",
			expectedHash:  0,
			expectedError: sigre.ErrUnsupportedHashAlgorithm,
		},
		{
			name:          "Failure: invalid algorithm name",
			input:         "invalid-algorithm",
			expectedHash:  0,
			expectedError: sigre.ErrUnsupportedHashAlgorithm,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualHash, actualErr := sigre.ExportForTesting_getHash(tc.input)

			if !errors.Is(actualErr, tc.expectedError) {
				t.Errorf("expected error: %v, got: %v", tc.expectedError, actualErr)
			}

			if actualHash != tc.expectedHash {
				t.Errorf("expected hash: %v, got: %v", tc.expectedHash, actualHash)
			}
		})
	}
}
