package dchttpsig_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MitarashiDango/sigre/dchttpsig"
)

func TestParseSignatureParameters(t *testing.T) {
	t.Helper()

	testCases := []struct {
		name          string                                           // テストケース名
		input         string                                           // パース対象の文字列
		expected      *dchttpsig.ExportForTesting_signaturesParameters // 期待されるパース結果
		expectError   bool                                             // エラーが発生することを期待するか
		errorContains string                                           // エラーに含まれるべき文字列
	}{
		// 正常系テストケース
		{
			name:  "正常系: 全てのパラメータを含む",
			input: `keyId="test-key-1",algorithm="rsa-sha256",created=1618952679,expires=1618952739,headers="(created) (expires) host date digest",signature="Base64SignatureHere"`,
			expected: &dchttpsig.ExportForTesting_signaturesParameters{
				KeyId:     "test-key-1",
				Algorithm: "rsa-sha256",
				Created:   "1618952679",
				Expires:   "1618952739",
				SignTargetHeaders: []string{
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
			name:  "正常系: createdとexpiresがない",
			input: `keyId="test-key-2",algorithm="hmac-sha512",headers="host date",signature="AnotherBase64Signature"`,
			expected: &dchttpsig.ExportForTesting_signaturesParameters{
				KeyId:             "test-key-2",
				Algorithm:         "hmac-sha512",
				SignTargetHeaders: []string{"host", "date"},
				Signature:         "AnotherBase64Signature",
			},
			expectError: false,
		},
		{
			name:  "正常系: headers内のヘッダー名が大文字（小文字に変換されることを期待）",
			input: `keyId="test-key-3",headers="Host Date Content-Type",signature="sig"`,
			expected: &dchttpsig.ExportForTesting_signaturesParameters{
				KeyId:             "test-key-3",
				SignTargetHeaders: []string{"host", "date", "content-type"},
				Signature:         "sig",
			},
			expectError: false,
		},
		{
			name:  "正常系: パラメータの順序が異なる",
			input: `signature="sig",headers="date",keyId="test-key-4"`,
			expected: &dchttpsig.ExportForTesting_signaturesParameters{
				KeyId:             "test-key-4",
				SignTargetHeaders: []string{"date"},
				Signature:         "sig",
			},
			expectError: false,
		},
		{
			name:  "正常系: 未知のパラメータは無視される",
			input: `keyId="test-key-5",signature="sig",custom="some-value"`,
			expected: &dchttpsig.ExportForTesting_signaturesParameters{
				KeyId:     "test-key-5",
				Signature: "sig",
			},
			expectError: false,
		},

		// 異常系テストケース
		{
			name:          "異常系: 必須パラメータ keyId がない",
			input:         `algorithm="rsa-sha256",signature="sig"`,
			expectError:   true,
			errorContains: "missing required parameter: keyId",
		},
		{
			name:          "異常系: 必須パラメータ signature がない",
			input:         `keyId="test-key-1"`,
			expectError:   true,
			errorContains: "missing required parameter: signature",
		},
		{
			name:          "異常系: 不正なフォーマット (クォートなし)",
			input:         `keyId=test-key-1`,
			expectError:   true,
			errorContains: "expected '\"'",
		},
		{
			name:          "異常系: 不正なフォーマット (最後のクォートが閉じていない)",
			input:         `keyId="test-key-1`,
			expectError:   true,
			errorContains: "unclosed parameter value",
		},
		{
			name:          "異常系: 不正なフォーマット (最後のパラメータの後に余計な文字)",
			input:         `keyId="test-key-1"a`,
			expectError:   true,
			errorContains: "unexpected character",
		},
		{
			name:          "異常系: パラメータの重複",
			input:         `keyId="key1",keyId="key2",signature="sig"`,
			expectError:   true,
			errorContains: "duplicate parameter name",
		},
		{
			name:          "異常系: created の値が不正",
			input:         `keyId="k",signature="s",created="not-a-number"`,
			expectError:   true,
			errorContains: "invalid 'created' value",
		},
		{
			name:          "異常系: expires の値が不正",
			input:         `keyId="k",signature="s",expires="not-a-number"`,
			expectError:   true,
			errorContains: "invalid 'expires' value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := dchttpsig.ExportForTesting_parseSignatureParameters(tc.input)

			if tc.expectError {
				if err == nil {
					t.Fatal("expected an error, but got none")
				}
				// エラーメッセージの内容を部分的に検証
				if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', but got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect an error, but got: %v", err)
				}
				// reflect.DeepEqual で構造体全体を比較
				if !reflect.DeepEqual(tc.expected, actual) {
					t.Errorf("parsed parameters do not match expected\nexpected: %+v\nactual:   %+v", tc.expected, actual)
				}
			}
		})
	}
}
