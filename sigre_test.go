package sigre_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

// Sign and Verify E2E Tests
func TestSignAndVerify(t *testing.T) {
	// テストで使用する鍵ペアの生成
	rsaKeys := generateRSAKeys(t)
	rsaPrivateKey, rsaPubKey := rsaKeys.private, rsaKeys.public

	ecdsaKeys := generateECDSAKeys(t)
	ecdsaPrivateKey, ecdsaPubKey := ecdsaKeys.private, ecdsaKeys.public

	ed25519Keys := generateEd25519Keys(t)
	ed25519PrivateKey, ed25519PubKey := ed25519Keys.private, ed25519Keys.public

	hmacSecret := []byte("this-is-a-super-secret-key-for-hmac")

	// テストケースの定義
	testCases := []struct {
		name string // テストケース名

		// 署名オプション
		signOpts signOptsPartial

		// 検証オプション
		verifyOpts verifyOptsPartial

		// HTTPリクエスト/レスポンス
		isRequest   bool
		method      string
		url         string
		body        string
		headers     http.Header
		expectError bool
	}{
		// --- 正常系: 各アルゴリズムのテスト ---
		{
			name:       "正常系: RSA-SHA256 (Request)",
			isRequest:  true,
			method:     "POST",
			url:        "https://example.com/foo?param=value&pet=dog",
			body:       `{"hello": "world"}`,
			signOpts:   signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{publicKey: rsaPubKey},
		},
		{
			name:       "正常系: RSA-SHA512 (Response)",
			isRequest:  false,
			method:     "GET",
			url:        "https://example.com/bar",
			body:       `"response data"`,
			signOpts:   signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA512, headers: []string{"date", "digest"}},
			verifyOpts: verifyOptsPartial{publicKey: rsaPubKey},
		},
		{
			name:       "正常系: ECDSA-SHA256",
			isRequest:  true,
			method:     "PUT",
			url:        "https://example.com/baz",
			body:       "update data",
			signOpts:   signOptsPartial{privateKey: ecdsaPrivateKey, hash: crypto.SHA256},
			verifyOpts: verifyOptsPartial{publicKey: ecdsaPubKey},
		},
		{
			name:       "正常系: Ed25519",
			isRequest:  true,
			method:     "GET",
			url:        "https://example.com/",
			body:       "", // ボディなし
			signOpts:   signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(request-target)", "host", "date"}},
			verifyOpts: verifyOptsPartial{publicKey: ed25519PubKey},
		},
		{
			name:       "正常系: HMAC-SHA256",
			isRequest:  true,
			method:     "DELETE",
			url:        "https://example.com/resource/123",
			body:       "",
			signOpts:   signOptsPartial{secret: hmacSecret, hash: crypto.SHA256, headers: []string{"(request-target)", "date"}},
			verifyOpts: verifyOptsPartial{secret: hmacSecret},
		},
		// --- 正常系: VerifyOptions のテスト ---
		{
			name:       "正常系: RequiredHeaders が満たされている",
			isRequest:  true,
			method:     "POST",
			url:        "https://example.com/",
			signOpts:   signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256, headers: []string{"host", "date", "(request-target)"}},
			verifyOpts: verifyOptsPartial{publicKey: rsaPubKey, requiredHeaders: []string{"date", "host"}},
		},
		{
			name:      "正常系: AllowedClockSkew (未来)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(created)", "date"}},
			verifyOpts: verifyOptsPartial{
				publicKey: ed25519PubKey,
				clockSkew: 1 * time.Minute,
				// now を 30秒 進めて検証。skew(60秒)の範囲内なので成功するはず。
				overrideNowFunc: func() time.Time { return time.Date(2024, 6, 8, 10, 30, 30, 0, time.UTC) },
			},
		},
		// --- 異常系テスト ---
		{
			name:        "異常系: RequiredHeaders が満たされていない",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256, headers: []string{"host", "date"}},
			verifyOpts:  verifyOptsPartial{publicKey: rsaPubKey, requiredHeaders: []string{"digest"}},
			expectError: true, // `digest` が署名対象に含まれていないためエラー
		},
		{
			name:      "異常系: AllowedClockSkew 超過 (古すぎる)",
			isRequest: true,
			method:    "POST",
			url:       "https://example.com/",
			signOpts:  signOptsPartial{privateKey: ed25519PrivateKey, headers: []string{"(created)", "date"}},
			verifyOpts: verifyOptsPartial{
				publicKey: ed25519PubKey,
				clockSkew: 1 * time.Minute,
				// now を 61秒 進めて検証。skew(60秒)を超えるため失敗するはず。
				overrideNowFunc: func() time.Time { return time.Date(2024, 6, 8, 10, 31, 1, 0, time.UTC) },
			},
			expectError: true,
		},
		{
			name:        "異常系: 署名後にリクエストヘッダを改ざん",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts:  verifyOptsPartial{publicKey: rsaPubKey, tamperHeader: &tamperAction{key: "Date", value: "tampered"}},
			expectError: true,
		},
		{
			name:        "異常系: 間違った公開鍵で検証",
			isRequest:   true,
			method:      "POST",
			url:         "https://example.com/",
			signOpts:    signOptsPartial{privateKey: rsaPrivateKey, hash: crypto.SHA256},
			verifyOpts:  verifyOptsPartial{publicKey: generateRSAKeys(t).public}, // 別の鍵ペア
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// --- テストのセットアップ ---

			// 時刻を固定して、署名結果が常に同じになるようにする
			testingNowFunc := func() time.Time {
				// 2024-06-08 10:30:00 UTC
				return time.Date(2024, 6, 8, 10, 30, 0, 0, time.UTC)
			}

			// リクエスト/レスポンスオブジェクトの作成
			var req *http.Request
			var res *http.Response
			var err error
			if tc.isRequest {
				req, err = http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}
			} else {
				// レスポンスのテストではダミーのリクエストが必要
				dummyReq, _ := http.NewRequest(tc.method, tc.url, nil)
				res = &http.Response{
					Request: dummyReq,
					Header:  make(http.Header),
					Body:    io.NopCloser(strings.NewReader(tc.body)),
				}
				req = dummyReq // レスポンス署名でも host などはリクエストから取るため
			}

			// ヘッダーの準備
			targetHeader := req.Header
			if !tc.isRequest {
				targetHeader = res.Header
			}
			if tc.headers != nil {
				for k, v := range tc.headers {
					targetHeader[k] = v
				}
			}

			// デフォルトで必要なヘッダーを追加
			if targetHeader.Get("Date") == "" {
				targetHeader.Set("Date", time.Now().UTC().Format(time.RFC1123))
			}

			if req.Host == "" { // http.NewRequest は URL から Host を設定する
				req.Host = req.URL.Host
			}

			if targetHeader.Get("Host") == "" {
				targetHeader.Set("Host", req.Host)
			}

			if tc.body != "" {
				h := sha256.New()
				h.Write([]byte(tc.body))
				digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
				targetHeader.Set("Digest", "SHA-256="+digest)
			}

			t.Log(targetHeader)

			// --- 署名 ---
			signOptions := &sigre.CavageSignOptions{
				Headers:         tc.signOpts.headers,
				HashAlgorithm:   tc.signOpts.hash,
				SignatureHeader: sigre.Signature,
			}

			keyId := "test-key-id"

			signer := &sigre.CavageSigner{
				Now: testingNowFunc,
			}

			if tc.isRequest {
				if len(tc.signOpts.secret) != 0 {
					if err := signer.SignRequestWithHMAC(req, tc.signOpts.secret, keyId, signOptions); err != nil {
						t.Fatalf("SignRequest failed: %v", err)
					}
				} else {
					if err := signer.SignRequest(req, tc.signOpts.privateKey, keyId, signOptions); err != nil {
						t.Fatalf("SignRequest failed: %v", err)
					}
				}
			} else {
				if len(tc.signOpts.secret) != 0 {
					if err := signer.SignResponseWithHMAC(res, tc.signOpts.secret, keyId, signOptions); err != nil {
						t.Fatalf("SignResponse failed: %v", err)
					}
				} else {
					if err := signer.SignResponse(res, tc.signOpts.privateKey, keyId, signOptions); err != nil {
						t.Fatalf("SignResponse failed: %v", err)
					}
				}
			}

			// --- 検証の準備 (改ざん、時刻の上書きなど) ---
			if tc.verifyOpts.tamperHeader != nil {
				tamperTarget := req.Header
				if !tc.isRequest {
					tamperTarget = res.Header
				}
				tamperTarget.Set(tc.verifyOpts.tamperHeader.key, tc.verifyOpts.tamperHeader.value)
			}
			if tc.verifyOpts.overrideNowFunc != nil {
				testingNowFunc = tc.verifyOpts.overrideNowFunc
			}

			// --- 検証 ---
			var verifier *sigre.CavageVerifier
			if tc.isRequest {
				verifier, err = sigre.NewCavageRequestVerifier(req)
			} else {
				verifier, err = sigre.NewCavageResponseVerifier(res)
			}
			if err != nil {
				if !tc.expectError {
					t.Fatalf("NewVerifier failed: %v", err)
				}
				return
			}

			verifier.Now = testingNowFunc

			verifyOptions := &sigre.VerifyOptions{
				AllowedClockSkew: tc.verifyOpts.clockSkew,
				RequiredHeaders:  tc.verifyOpts.requiredHeaders,
			}

			if len(tc.verifyOpts.secret) != 0 {
				err = verifier.VerifyHMAC(tc.verifyOpts.secret, verifyOptions)
			} else {
				err = verifier.Verify(tc.verifyOpts.publicKey, verifyOptions)
			}

			// --- 結果の確認 ---
			if tc.expectError {
				if err == nil {
					t.Error("expected an error, but verification succeeded")
				}
			} else {
				if err != nil {
					t.Errorf("verification failed unexpectedly: %v", err)
				}
			}
		})
	}
}

// ===== Helper Structs for Tests =====

// signOptsPartial は、テストケースごとに異なる署名オプションの一部を保持します。
type signOptsPartial struct {
	privateKey crypto.PrivateKey
	secret     []byte
	hash       crypto.Hash
	headers    []string
}

// verifyOptsPartial は、テストケースごとに異なる検証オプションの一部を保持します。
type verifyOptsPartial struct {
	publicKey       crypto.PublicKey
	secret          []byte
	clockSkew       time.Duration
	requiredHeaders []string
	tamperHeader    *tamperAction
	overrideNowFunc func() time.Time
}

// tamperAction は、検証前にヘッダーを改ざんするアクションを定義します。
type tamperAction struct {
	key   string
	value string
}

// ===== Helper Functions for Key Generation =====

// rsaKeyPair は、テスト用のRSA鍵ペアを保持します。
type rsaKeyPair struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

// generateRSAKeys は、テスト用のRSA鍵ペアを生成します。
func generateRSAKeys(t *testing.T) rsaKeyPair {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA keys: %v", err)
	}
	return rsaKeyPair{private: privateKey, public: &privateKey.PublicKey}
}

// ecdsaKeyPair は、テスト用のECDSA鍵ペアを保持します。
type ecdsaKeyPair struct {
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

// generateECDSAKeys は、テスト用のECDSA鍵ペア(P-256)を生成します。
func generateECDSAKeys(t *testing.T) ecdsaKeyPair {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA keys: %v", err)
	}
	return ecdsaKeyPair{private: privateKey, public: &privateKey.PublicKey}
}

// ed25519KeyPair は、テスト用のEd25519鍵ペアを保持します。
type ed25519KeyPair struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

// generateEd25519Keys は、テスト用のEd25519鍵ペアを生成します。
func generateEd25519Keys(t *testing.T) ed25519KeyPair {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keys: %v", err)
	}
	return ed25519KeyPair{private: privateKey, public: publicKey}
}
