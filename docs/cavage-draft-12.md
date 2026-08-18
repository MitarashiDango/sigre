# Cavage draft-12利用ガイド

この文書では、本ライブラリーによる[draft-cavage-http-signatures-12](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12)形式の署名と検証を説明します。

## 対応する暗号方式

`AlgorithmID`は、鍵種別、ハッシュ関数、RSAパディングの組み合わせを表します。

| `AlgorithmID`                | 鍵種別  | ハッシュ関数     | RSAパディング | 厳格な既定値での使用 |
| ---------------------------- | ------- | ---------------- | ------------- | -------------------- |
| `AlgorithmRSAPKCS1v15SHA512` | RSA     | SHA-512          | PKCS #1 v1.5  | 可                   |
| `AlgorithmRSAPKCS1v15SHA256` | RSA     | SHA-256          | PKCS #1 v1.5  | 不可                 |
| `AlgorithmECDSASHA512`       | ECDSA   | SHA-512          | ―             | 可                   |
| `AlgorithmECDSASHA256`       | ECDSA   | SHA-256          | ―             | 不可                 |
| `AlgorithmEd25519`           | Ed25519 | 事前ハッシュなし | ―             | 可                   |
| `AlgorithmHMACSHA512`        | 共通鍵  | SHA-512          | ―             | 可                   |
| `AlgorithmHMACSHA256`        | 共通鍵  | SHA-256          | ―             | 不可                 |

非対称鍵には`SigningKey`と`VerificationKey`を使用します。HMACには`HMACSigningKey`と`HMACVerificationKey`を使用します。

## 署名

`NewCavageSigner`で署名器を作成します。非対称鍵では`SignRequest`または`SignResponse`を使用します。HMACでは`SignRequestWithHMAC`または`SignResponseWithHMAC`を使用します。署名の格納先は`CavageSignaturePlacementSignature`または`CavageSignaturePlacementAuthorization`で指定します。

```go
err := signer.SignRequest(
	req,
	sigre.SigningKey{Metadata: metadata, PrivateKey: privateKey},
	sigre.CavageSignaturePlacementSignature,
	nil,
)
```

`CavageSigningOptions`に`nil`を渡すと、厳格な既定値を使用します。リクエストの署名対象は`(request-target)`と`(created)`です。レスポンスでは`headers`パラメータを省略し、`(created)`だけを署名します。

`AdditionalHeaders`は既定の署名対象に項目を追加します。`Compatibility.ExactHeaders`は署名対象全体を置き換えます。両方を同時に指定することはできません。

`ExpiresAfter`を使う場合は、署名対象に`(expires)`を含めます。SHA-256方式や非推奨の`algorithm`ラベルは互換性設定が必要です。`hs2019`とRSA/SHA-256の組み合わせや拡張ラベルも、`CavageSigningCompatibility`で明示します。

本ライブラリーでは本文の`Digest`を計算しません。`Digest`を署名する場合は、署名処理を呼び出す前にリクエストヘッダーへ値を設定します。

## `(request-target)`の扱い

署名時は`req.URL`から`(request-target)`を組み立てます。エスケープ済みのパス、`RawQuery`の順序、`ForceQuery`による末尾の`?`を保持します。

検証時は、受信した`req.RequestURI`をそのまま使用します。`net/http`サーバーが受信したリクエストでは、この値は設定済みです。`http.NewRequest`で作成したリクエストをテスト内で直接検証する場合は、サーバー受信後の状態を再現するため、`ParseRequest`の前に`req.RequestURI = req.URL.RequestURI()`を設定してください。

クエリを省略して再試行する機能はありません。

## 検証

`NewCavageVerifier`で検証器を作成し、検証ポリシーを設定します。受信メッセージは`ParseRequest`または`ParseResponse`で解析します。

解析結果は`CavageSignature`です。署名パラメータ、デコード済みの署名、署名対象、署名文字列、その生成に使ったHTTP値を保持します。これらの値は後から変更できません。

解析後に元のリクエスト、レスポンス、`Header`、`URL`を変更しても、検証結果には影響しません。`CavageSignature`は、それを生成した`CavageVerifier`でのみ検証できます。

リクエストでは、既定で`Signature`フィールドだけを解析します。`RequestSignatureSource`では、`Authorization: Signature`だけを選ぶことも、両方を候補にすることもできます。両方に署名がある場合は`ErrSignatureSourceConflict`になります。選択していないフィールドは解析しません。

レスポンスでは`Signature`フィールドだけを解析します。

解析後、`CavageSignature.KeyID()`の値を信頼済み鍵へ解決します。非対称鍵には`Verify`、HMACには`VerifyHMAC`を使用します。

```go
verifier, err := sigre.NewCavageVerifier(nil)
if err != nil {
	return err
}
req.RequestURI = req.URL.RequestURI() // テストでサーバー受信後の状態を再現する
signature, err := verifier.ParseRequest(req)
if err != nil {
	return err
}
verificationKey, ok := trustedKeys[signature.KeyID()]
if !ok {
	return errors.New("keyId could not be resolved to a trusted key")
}
return verifier.Verify(signature, verificationKey)
```

### 検証ポリシー

`CavageVerificationOptions`では、次の項目を設定できます。

- `RequiredHeaders`: 署名対象に必須とする項目。`headers`パラメータを省略した場合は、署名対象を`(created)`と確定してから検査します。
- `AllowedAlgorithms`: 許可する`AlgorithmID`の集合。1つ以上指定すると、厳格な既定値を置き換えます。`nil`または空の場合は、上表で「可」とした4方式を許可します。
- `MaxSignatureAge`: 署名された`(created)`からの最大経過時間。ゼロの場合は制限しません。
- `MaxDateAge`: 署名された単一の`Date`と現在時刻との差の上限。ゼロの場合は制限しません。
- `Now`: 時刻比較に使う関数。必要な解析ごとに1回だけ呼ばれます。`NewCavageVerifier`と`Verify`では呼ばれません。
- `Compatibility.AllowedCreatedFutureSkew`: 未来の`(created)`に許容する時刻差。
- `Compatibility.AllowedExpiredSkew`: 過去の`(expires)`に許容する時刻差。

`RequireAlgorithm`と`RequireExplicitHeaders`は、対応するパラメータの明示を要求します。

## 信頼境界と責務の分担

受信した`keyId`は信頼できません。`CavageSignature.KeyID()`の値を、アプリケーション側で`VerificationKey`か`HMACVerificationKey`へ解決してください。

`TrustedKeyMetadata.KeyID`は、受信した`keyId`とバイト単位で一致する必要があります。暗号方式は`TrustedKeyMetadata.Algorithm`で決まります。受信した`algorithm`パラメータは、一致確認にだけ使用します。鍵種別、ハッシュ関数、RSAパディングの選択には使いません。

本ライブラリーが扱うのは、署名パラメータ、署名文字列、暗号処理です。次の処理はアプリケーション側で行う必要があります。

- 解析前の本文を保持し、`Digest`を計算して受信値と照合する。後続処理でも本文を読む場合は`Body`を復元する。
- `keyId`を信頼済みの鍵へ解決する。
- 最小鍵長、鍵用途、鍵の失効を検査する。

## 厳格な既定値と互換性設定

厳格な既定値では、`hs2019`表現とSHA-512方式またはEd25519を使用します。次の互換性設定は自動では有効になりません。

- `AlgorithmFieldLegacy`と`AllowedLegacyAlgorithms`: `rsa-sha256`、`ecdsa-sha256`、`hmac-sha256`という非推奨ラベル。検証側では、対応する方式を`AllowedAlgorithms`にも含めます。
- `AlgorithmFieldHS2019WithSHA256`と`AllowHS2019WithSHA256`: Fediverse実装で使用例がある、`hs2019`をRSA PKCS #1 v1.5/SHA-256として扱う設定。
- `Extension`と`ExtensionAlgorithms`: 未登録ラベルと1つの`AlgorithmID`を明示的に対応付ける設定。
- `ExactHeaders`: 接続先が要求する署名対象全体を指定する設定。

## エラー処理

公開メソッドは、原因をラップした`*SigreError`を返します。

```go
verifier, err := sigre.NewCavageVerifier(nil)
if err == nil {
	_, err = verifier.ParseRequest(req)
}
if errors.Is(err, sigre.ErrMissingSignature) {
	// 署名が存在しない場合の処理
}
var packageError *sigre.SigreError
if errors.As(err, &packageError) {
	// packageError.Errにラップされた原因がある
}
```

代表的なエラーは次のとおりです。

| エラー                       | 条件                                             |
| ---------------------------- | ------------------------------------------------ |
| `ErrMissingSignature`        | 署名が存在しない                                 |
| `ErrSignatureSourceConflict` | 選択した署名の取得元が競合した                   |
| `ErrSignedHeaderMissing`     | 署名対象のフィールドがHTTPメッセージに存在しない |
| `ErrVerification`            | 暗号学的な検証に失敗した                         |
| `ErrKeyIDMismatch`           | 受信した`keyId`と信頼済みメタデータが一致しない  |
| `ErrRequiredHeaderMissing`   | 必須の署名対象が存在しない                       |
| `ErrSignatureExpired`        | 署名の有効期限が切れている                       |

## 完全な実行例

完全なコードは[`example_test.go`](../example_test.go)にあります。`go test`でコンパイルと実行を確認できます。

| 例                                              | 内容                                     |
| ----------------------------------------------- | ---------------------------------------- |
| `ExampleCavageSigner_SignRequest`               | Ed25519によるリクエスト署名              |
| `ExampleCavageVerifier_Verify`                  | 受信した`keyId`の解決とリクエスト検証    |
| `ExampleCavageSigner_SignRequest_compatibility` | `rsa-sha256`互換設定による署名と検証     |
| `ExampleSigreError`                             | `errors.Is`と`errors.As`によるエラー判定 |
