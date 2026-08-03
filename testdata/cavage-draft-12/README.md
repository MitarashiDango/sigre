# Cavage draft-12 conformance fixtures

This directory contains test-only, locally constructed conformance vectors for
`draft-cavage-http-signatures-12`. They establish fixed expectations without
using sigre production code to create either the expected signing strings or
the fixed signatures.

The vectors are not copied from Appendix C. Appendix C warns that its values may
be outdated or incorrect, so none of its signatures are treated as an oracle
here.

## Fixture format

`fixtures.json` stores the following information for each vector:

- the fixed request or response, including headers as ordered value lists;
- the ordered `signed_headers` list;
- the literal `expected_signing_string`;
- the complete Signature header value and its Base64 signature value;
- the wire `algorithm` parameter and the separate `crypto_path` used to identify
  the RSA, ECDSA, Ed25519, or HMAC test path;
- the test-only verification key or HMAC secret location;
- the source, applicable specification sections, and validation procedure.

The header list representation preserves multiple values and distinguishes an
empty value (`[""]`) from an absent field. All keys and the HMAC secret under
`keys/` were created only for these tests. They are not operational credentials
and must never be used outside the test suite.

## Sources and specification coverage

| Fixture | Source and purpose | Specification sections |
|---|---|---|
| `rsa-request-multiple-and-empty-values` | Locally constructed request covering a normal path, query, ordered multiple values, and an empty value. | Sections 2.1.3, 2.3, 2.4, and 2.5; Appendix E.2 |
| `ecdsa-response-multiple-and-empty-values` | Locally constructed response covering ordered multiple values, an empty value, and a fixed ASN.1 ECDSA signature. | Sections 2.1.3, 2.3, 2.4, and 2.5; Appendix E.2 |
| `ed25519-request-created` | Locally constructed request covering a normal path and the `(created)` pseudo-header. | Sections 2.1.3, 2.1.4, 2.3, 2.4, and 2.5; Appendix E.2 |
| `hmac-response-multiple-and-empty-values` | Locally constructed response covering ordered multiple values and an empty value. | Sections 2.1.3, 2.3, 2.4, and 2.5; Appendix E.2 |

Section 2.1.3 requires a valid, non-deprecated wire algorithm. Appendix E.2
identifies `hs2019` as the active value and specifies SHA-512 for its hashed
signature paths. Every fixture therefore carries `algorithm="hs2019"` on the
wire. RSA PKCS#1 v1.5, ECDSA, and HMAC use SHA-512; Ed25519 signs the message
bytes directly. The separate `crypto_path` metadata records which of those four
cryptographic paths a fixture exercises without overloading the wire label.

The expected strings were transcribed directly from the fixed messages by
applying Section 2.3: lowercase the method and field names, retain the listed
field order, join multiple values with `, `, retain the single space after the
colon for an empty value, separate lines with LF, and do not append a final LF.
No sigre function or test export was used for this transcription.

The SHA-256 digests of the exact expected signing-string bytes are:

| Fixture | SHA-256 |
|---|---|
| `rsa-request-multiple-and-empty-values` | `825276861ff042a37aa7de249d00c8c25f7ac16d0910fe952a7f9720648ac74f` |
| `ecdsa-response-multiple-and-empty-values` | `80dad3e9af5c2429c34d704a2984451160cebe18f0ee615a39e339bde5415ff5` |
| `ed25519-request-created` | `b68c0fb469781f39e1f62cc7554ade7f341b9333926164fc5c3258068cf9da70` |
| `hmac-response-multiple-and-empty-values` | `8da155d99248d6ff52da19a3e5d4b9465e6027349b6b1ecd5951bfc23d0420ca` |

## Generation environment

The committed vectors were generated on 2026-08-04 with:

```text
OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)
jq-1.7.1-apple
```

The test-only asymmetric keys were created with these commands:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-private.pem
openssl pkey -in rsa-private.pem -pubout -out rsa-public.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ecdsa-private.pem
openssl pkey -in ecdsa-private.pem -pubout -out ecdsa-public.pem
openssl genpkey -algorithm ED25519 -out ed25519-private.pem
openssl pkey -in ed25519-private.pem -pubout -out ed25519-public.pem
openssl rand -hex 32
```

The last command produced the test-only HMAC key stored in
`keys/hmac-secret.hex`.

## Signature generation

The following commands reproduce signatures over the literal JSON strings. The
`jq -j` option is essential because it does not append a newline.

```sh
fixture_dir=testdata/cavage-draft-12
scratch_dir=$(mktemp -d /tmp/sigre-cavage-fixtures.XXXXXX)

jq -jr '.fixtures[] | select(.id == "rsa-request-multiple-and-empty-values") | .expected_signing_string' "$fixture_dir/fixtures.json" > "$scratch_dir/rsa-input.txt"
openssl dgst -sha512 -sign "$fixture_dir/keys/rsa-private.pem" -out "$scratch_dir/rsa.sig" "$scratch_dir/rsa-input.txt"
openssl base64 -A -in "$scratch_dir/rsa.sig"

jq -jr '.fixtures[] | select(.id == "ecdsa-response-multiple-and-empty-values") | .expected_signing_string' "$fixture_dir/fixtures.json" > "$scratch_dir/ecdsa-input.txt"
openssl dgst -sha512 -sign "$fixture_dir/keys/ecdsa-private.pem" -out "$scratch_dir/ecdsa.sig" "$scratch_dir/ecdsa-input.txt"
openssl base64 -A -in "$scratch_dir/ecdsa.sig"

jq -jr '.fixtures[] | select(.id == "ed25519-request-created") | .expected_signing_string' "$fixture_dir/fixtures.json" > "$scratch_dir/ed25519-input.txt"
openssl pkeyutl -sign -rawin -inkey "$fixture_dir/keys/ed25519-private.pem" -in "$scratch_dir/ed25519-input.txt" -out "$scratch_dir/ed25519.sig"
openssl base64 -A -in "$scratch_dir/ed25519.sig"

jq -jr '.fixtures[] | select(.id == "hmac-response-multiple-and-empty-values") | .expected_signing_string' "$fixture_dir/fixtures.json" > "$scratch_dir/hmac-input.txt"
openssl dgst -sha512 -mac HMAC -macopt hexkey:d3e709c705ce6575dc8b3e1e3be172825c66c766a317ce4a522a88d24adf0047 -binary -out "$scratch_dir/hmac.sig" "$scratch_dir/hmac-input.txt"
openssl base64 -A -in "$scratch_dir/hmac.sig"
```

RSA PKCS#1 v1.5, Ed25519, and HMAC signatures are deterministic for these
inputs. ECDSA uses a per-signature nonce and OpenSSL may produce a different
valid value on each run. The committed ECDSA signature is therefore used as a
fixed verifier vector, while signer tests independently verify each newly
generated ECDSA signature against the fixed expected string.

## Independent verification

These commands decode the fixed values from JSON and validate them without
calling sigre production code:

```sh
fixture_dir=testdata/cavage-draft-12
scratch_dir=$(mktemp -d /tmp/sigre-cavage-verify.XXXXXX)

for fixture_id in rsa-request-multiple-and-empty-values ecdsa-response-multiple-and-empty-values ed25519-request-created hmac-response-multiple-and-empty-values; do
  jq -jr --arg fixture_id "$fixture_id" '.fixtures[] | select(.id == $fixture_id) | .expected_signing_string' "$fixture_dir/fixtures.json" > "$scratch_dir/$fixture_id.txt"
  jq -jr --arg fixture_id "$fixture_id" '.fixtures[] | select(.id == $fixture_id) | .signature_base64' "$fixture_dir/fixtures.json" | openssl base64 -d -A -out "$scratch_dir/$fixture_id.sig"
done

openssl dgst -sha512 -verify "$fixture_dir/keys/rsa-public.pem" -signature "$scratch_dir/rsa-request-multiple-and-empty-values.sig" "$scratch_dir/rsa-request-multiple-and-empty-values.txt"
openssl dgst -sha512 -verify "$fixture_dir/keys/ecdsa-public.pem" -signature "$scratch_dir/ecdsa-response-multiple-and-empty-values.sig" "$scratch_dir/ecdsa-response-multiple-and-empty-values.txt"
openssl pkeyutl -verify -rawin -pubin -inkey "$fixture_dir/keys/ed25519-public.pem" -in "$scratch_dir/ed25519-request-created.txt" -sigfile "$scratch_dir/ed25519-request-created.sig"
openssl dgst -sha512 -mac HMAC -macopt hexkey:d3e709c705ce6575dc8b3e1e3be172825c66c766a317ce4a522a88d24adf0047 -binary -out "$scratch_dir/hmac-check.sig" "$scratch_dir/hmac-response-multiple-and-empty-values.txt"
cmp "$scratch_dir/hmac-response-multiple-and-empty-values.sig" "$scratch_dir/hmac-check.sig"
```

The expected results are `Verified OK` for RSA and ECDSA, `Signature Verified
Successfully` for Ed25519, and a zero exit status from `cmp` for HMAC.
