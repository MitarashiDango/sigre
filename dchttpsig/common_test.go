package dchttpsig_test

import (
	"crypto"
	"errors"
	"testing"

	"github.com/MitarashiDango/sigre/dchttpsig"
)

func TestGetHash(t *testing.T) {
	t.Helper()

	testCases := []struct {
		name          string      // テストケース名
		input         string      // getHashへの入力
		expectedHash  crypto.Hash // 期待されるハッシュ値
		expectedError error       // 期待されるエラー
	}{
		{
			name:          "正常系: SHA256",
			input:         "sha256",
			expectedHash:  crypto.SHA256,
			expectedError: nil,
		},
		{
			name:          "正常系: SHA512",
			input:         "sha512",
			expectedHash:  crypto.SHA512,
			expectedError: nil,
		},
		{
			name:          "異常系: サポートされていないアルゴリズム",
			input:         "sha1",
			expectedHash:  0,
			expectedError: dchttpsig.ErrUnsupportedHashAlgorithm,
		},
		{
			name:          "異常系: 不正なアルゴリズム名",
			input:         "invalid-algorithm",
			expectedHash:  0,
			expectedError: dchttpsig.ErrUnsupportedHashAlgorithm,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualHash, actualErr := dchttpsig.ExportForTesting_getHash(tc.input)

			// エラーの比較
			if !errors.Is(actualErr, tc.expectedError) {
				t.Errorf("expected error: %v, got: %v", tc.expectedError, actualErr)
			}

			// 戻り値の比較
			if actualHash != tc.expectedHash {
				t.Errorf("expected hash: %v, got: %v", tc.expectedHash, actualHash)
			}
		})
	}
}
