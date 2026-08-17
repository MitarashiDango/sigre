# Sigre

## これは何？

HTTP リクエスト／レスポンスへの署名付与、および付与されている署名の検証を行うライブラリー<br />

以下の仕様に対応予定

- [HTTP Signatures (draft-cavage-http-signatures-12)](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12)
  - 現在実装中。(公開インターフェースはまだ安定していないため、今後大幅に変更される可能性あり。)
- [HTTP Message Signatures (RFC9421)](https://datatracker.ietf.org/doc/html/rfc9421)

## クイックスタート

署名には`CavageSigner`、検証には`CavageVerifier`を使用します。

```go
signer := sigre.NewCavageSigner()
err := signer.SignRequest(
	req,
	sigre.SigningKey{Metadata: metadata, PrivateKey: privateKey},
	sigre.CavageSignaturePlacementSignature,
	nil,
)
```

```go
verifier, err := sigre.NewCavageVerifier(nil)
signature, err := verifier.ParseRequest(req)
verificationKey, ok := trustedKeys[signature.KeyID()]
if !ok {
	return errors.New("keyIdを信頼済み鍵へ解決できません")
}
err = verifier.Verify(signature, verificationKey)
```

詳しい使い方については、[Cavage draft-12利用ガイド](./docs/cavage-draft-12.md)を参照してください。

## ライセンスは？

MIT License
