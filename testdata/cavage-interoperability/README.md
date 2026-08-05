# Cavage interoperability fixtures

This directory contains fixed, offline interoperability vectors for external
formats derived from Cavage HTTP Signatures. It is intentionally separate from
`testdata/cavage-draft-12`: the conformance fixtures there require active
`hs2019` behavior and SHA-512, while the vectors here exercise deprecated or
implementation-specific representations that require explicit compatibility
settings.

Every product vector was constructed locally from the behavior of a fixed
source revision or an official document. None was captured from a running
product, and none should be described as a signature actually emitted by that
product. The HTTP messages, identifiers, and signatures are test data. The RSA
key is the existing test-only key from `../cavage-draft-12/keys`; no operational
key or user data is present.

## Fixture inventory

| Fixture | Fixed source | Wire form | Trusted algorithm | Signed headers |
|---|---|---|---|---|
| `mastodon-cavage-post-rsa-sha256` | Mastodon commit `f80b1ba92e63c3da771b405b9100f5c9abda909f` | `Signature`, `rsa-sha256` | `AlgorithmRSAPKCS1v15SHA256` | `host date digest (request-target)` |
| `misskey-inbox-post-rsa-sha256` | Misskey commit `8ea4a0ecac058688f69706ab88de1fcd439e2621` | `Signature`, `rsa-sha256` | `AlgorithmRSAPKCS1v15SHA256` | `(request-target) date host digest` |
| `misskey-signed-get-rsa-sha256` | Misskey commit `8ea4a0ecac058688f69706ab88de1fcd439e2621` | `Signature`, `rsa-sha256` | `AlgorithmRSAPKCS1v15SHA256` | `(request-target) date host` |
| `pleroma-inbox-post-rsa-sha256` | Pleroma commit `f53342775d0f11aba7ee7a635a3c359397b87fa9`; locked `http_signatures` 0.1.3 | `Signature`, `rsa-sha256` | `AlgorithmRSAPKCS1v15SHA256` | `(request-target) content-length date digest host` |
| `oci-authorization-get-rsa-sha256` | OCI Request Signatures, Signature Version 1, retrieved 2026-08-05 | `Authorization: Signature`, `rsa-sha256` | `AlgorithmRSAPKCS1v15SHA256` | `date (request-target) host` |
| `fediverse-hs2019-rsa-sha256` | SWICG interoperability report, retrieved 2026-08-05 | `Signature`, `hs2019` | `AlgorithmRSAPKCS1v15SHA256` | `(request-target) host date digest content-type` |
| `extension-sigre-test-rsa-sha512` | Locally defined extension under draft-12 Section 2.1.3 | `Signature`, `sigre-test-rsa-sha512` | `AlgorithmRSAPKCS1v15SHA512` | `(request-target) host date` |

The exact source URLs, revision or retrieval date, construction status, message
bytes, request-target, signed-header order, signing string, key ID, signature,
and compatibility metadata are stored with each entry in `fixtures.json`.

## Primary-source observations

- Mastodon's fixed generator signs ordinary headers in insertion order and then
  appends `(request-target)`. Its request setup inserts `Host`, `Date`, and, for
  a body, `Digest` in that order. The generator includes the URL query in the
  request-target. Its receiver also contains a query-omission retry, but that
  retry is not reproduced by sigre or by these fixtures.
- Misskey's fixed POST list is `(request-target) date host digest`; its signed
  GET list is `(request-target) date host`. Its request-target generator uses
  `URL.pathname`, omitting a query. The GET fixture is therefore deliberately
  query-free.
- Pleroma passes request-target, host, content-length, digest, and date in a map.
  Its locked `http_signatures` 0.1.3 package sorts the map keys before signing,
  which fixes the order used by this fixture. Pleroma's query retry behavior is
  not reproduced.
- OCI requires `Authorization: Signature`, RSA-SHA256, and method-specific
  signed fields. Its official documentation requires the encoded path, encoded
  query, and query ordering to be retained. The OCI fixture uses a test-only,
  non-URL key ID, fully synthetic query values, and `version="1"`. Sigre safely
  ignores that unknown received parameter. The signer does not generate it; OCI
  documents that an omitted version means the current version.
- The SWICG report describes the Fediverse interpretation of `hs2019` as
  RSA-SHA256. This differs from strict draft-12 SHA-512 behavior and is recorded
  as a Fediverse compatibility form, not attributed to Mastodon, Misskey, or
  Pleroma.

The fixed primary sources are:

- [Mastodon signature generator](https://github.com/mastodon/mastodon/blob/f80b1ba92e63c3da771b405b9100f5c9abda909f/app/lib/http_signature_draft.rb#L14-L28)
- [Mastodon request setup](https://github.com/mastodon/mastodon/blob/f80b1ba92e63c3da771b405b9100f5c9abda909f/app/lib/request.rb#L151-L164)
- [Mastodon Cavage receiver](https://github.com/mastodon/mastodon/blob/f80b1ba92e63c3da771b405b9100f5c9abda909f/app/lib/signed_request.rb#L9-L135)
- [Misskey request signer](https://github.com/misskey-dev/misskey/blob/8ea4a0ecac058688f69706ab88de1fcd439e2621/packages/backend/src/core/activitypub/ApRequestService.ts#L44-L130)
- [Misskey inbox and raw-body Digest check](https://github.com/misskey-dev/misskey/blob/8ea4a0ecac058688f69706ab88de1fcd439e2621/packages/backend/src/server/ActivityPubServerService.ts#L108-L175)
- [Pleroma publisher](https://git.pleroma.social/pleroma/pleroma/src/commit/f53342775d0f11aba7ee7a635a3c359397b87fa9/lib/pleroma/web/activity_pub/publisher.ex#L132-L183)
- [Pleroma request-target receiver behavior](https://git.pleroma.social/pleroma/pleroma/src/commit/f53342775d0f11aba7ee7a635a3c359397b87fa9/lib/pleroma/signature.ex#L98-L140)
- [Pleroma locked dependency](https://git.pleroma.social/pleroma/pleroma/src/commit/f53342775d0f11aba7ee7a635a3c359397b87fa9/mix.lock#L65)
- [`http_signatures` 0.1.3 package](https://repo.hex.pm/tarballs/http_signatures-0.1.3.tar)
- [OCI Request Signatures](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm)
- [SWICG ActivityPub and HTTP Signatures report](https://swicg.github.io/activitypub-http-signature/)
- [draft-cavage-http-signatures-12](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12)

No product version number is inferred from a commit.

## Explicit settings exercised by the tests

Strict zero-value verification rejects all seven fixtures: the five
`rsa-sha256` product vectors are deprecated, the Fediverse `hs2019` label does
not identify the trusted SHA-256 AlgorithmID in strict mode, and the extension
label is unregistered.

The successful path requires only the matching, explicit compatibility choice:

- the Mastodon, Misskey, Pleroma, and OCI vectors set
  `AllowedLegacyAlgorithms` to `AlgorithmRSAPKCS1v15SHA256`;
- the Fediverse vector sets `AllowHS2019WithSHA256`;
- the extension vector maps the exact `sigre-test-rsa-sha512` label to
  `AlgorithmRSAPKCS1v15SHA512` in `ExtensionAlgorithms`.

On the signing side, the product vectors select `AlgorithmFieldLegacy`, the
Fediverse vector selects `AlgorithmFieldHS2019WithSHA256`, and the extension
vector supplies an `ExtensionAlgorithm`. Every vector supplies `ExactHeaders`
and explicitly chooses `Signature` or `Authorization` placement. In every case,
`SigningKey.Metadata.Algorithm` determines the cryptographic operation; the
wire label does not.

`AllowedAlgorithms`, `RequiredHeaders`, and `MaxDateAge` remain independent
application policies. The tests use `RequiredHeaders: []string{"digest"}` for
the raw-body example. They also demonstrate an OCI caller policy with
`AllowedAlgorithms: []AlgorithmID{AlgorithmRSAPKCS1v15SHA256}`,
`RequiredHeaders: []string{"date", "(request-target)", "host"}`, and
`MaxDateAge: 5*time.Minute`. Those values are not generic defaults and do not
enable the deprecated wire label; `AllowedLegacyAlgorithms` is still required.

## Raw body and Digest responsibility

Sigre authenticates the signed `Digest` header value. It does not compute a
body digest or decide whether the body matches that header. The focused tests
show the required caller sequence:

1. read and retain the exact raw body before JSON decoding;
2. accept only the single test-scope `SHA-256=<base64>` form;
3. decode with strict standard Base64 and require exactly 32 decoded bytes;
4. hash the retained bytes and compare in constant time;
5. verify the HTTP signature with `digest` in `RequiredHeaders`;
6. decode and dispatch the activity only after both checks succeed; and
7. restore `req.Body` from the retained bytes when a later consumer needs it.

The helper in the test is intentionally not a general RFC 3230 parser. It
rejects multiple digest values, parameters, whitespace variations, and every
algorithm other than SHA-256. Applications needing broader syntax must use a
separately reviewed parser without weakening the signature requirement.

## Query-omission limitation and safety conditions

Sigre has no public query-omission option. This fixture set does not add one,
does not rewrite `RequestURI`, and does not retry after a failed verification.
The query-free Misskey GET and Pleroma POST vectors cover their other known
interoperability properties. The Mastodon and OCI vectors retain their original
queries.

Any future query-omission feature must satisfy all of these conditions:

- it is disabled in generic defaults;
- it is selected explicitly for a specific endpoint;
- it is never used where query data affects resource identity, authorization,
  visibility, pagination, or processing;
- it does not remove or alter the actual query used by HTTP routing or the
  application;
- it does not try query-present and query-omitted request-targets, hashes,
  paddings, or cryptographic algorithms in sequence after a failure;
- it fixes one signing string before cryptographic verification and performs
  one verification with one trusted algorithm;
- it does not expose an example that rewrites `RequestURI`; and
- its configuration and use are auditable and logged.

## Fixed signature generation

The fixture messages and signing strings were written from the fixed sources
before signatures were generated. Sigre production code was not used. The
committed signatures were generated on 2026-08-05 with the repository's
test-only RSA key and OpenSSL:

```sh
fixture_dir=testdata/cavage-interoperability
key_dir=testdata/cavage-draft-12/keys
fixture_workdir=$(mktemp -d /tmp/sigre-cavage-interoperability.XXXXXX)

for fixture_id in \
  mastodon-cavage-post-rsa-sha256 \
  misskey-inbox-post-rsa-sha256 \
  misskey-signed-get-rsa-sha256 \
  pleroma-inbox-post-rsa-sha256 \
  oci-authorization-get-rsa-sha256 \
  fediverse-hs2019-rsa-sha256
do
  jq -jr --arg fixture_id "$fixture_id" \
    '.fixtures[] | select(.id == $fixture_id) | .expected_signing_string' \
    "$fixture_dir/fixtures.json" > "$fixture_workdir/$fixture_id.txt"
  openssl dgst -sha256 -sign "$key_dir/rsa-private.pem" \
    -out "$fixture_workdir/$fixture_id.sig" "$fixture_workdir/$fixture_id.txt"
  openssl base64 -A -in "$fixture_workdir/$fixture_id.sig"
done

fixture_id=extension-sigre-test-rsa-sha512
jq -jr --arg fixture_id "$fixture_id" \
  '.fixtures[] | select(.id == $fixture_id) | .expected_signing_string' \
  "$fixture_dir/fixtures.json" > "$fixture_workdir/$fixture_id.txt"
openssl dgst -sha512 -sign "$key_dir/rsa-private.pem" \
  -out "$fixture_workdir/$fixture_id.sig" "$fixture_workdir/$fixture_id.txt"
openssl base64 -A -in "$fixture_workdir/$fixture_id.sig"
```

RSA PKCS #1 v1.5 signatures are deterministic for these fixed inputs.

The SHA-256 hashes of the exact signing-string bytes are:

| Fixture | SHA-256 |
|---|---|
| `mastodon-cavage-post-rsa-sha256` | `1fecf396d80f24f1942f24b8653a3c13cb022f27c94cf398c360c99b5e4b3e7c` |
| `misskey-inbox-post-rsa-sha256` | `b1c7a81687b95ca11db6e2e6a88c250befeceb5f05dd19b0d9c4d769750251de` |
| `misskey-signed-get-rsa-sha256` | `fe93d037637c12e13dc5e72f7ecbf301368c4c2d043d1b5700d6fb38744c56f7` |
| `pleroma-inbox-post-rsa-sha256` | `ca9b0419c22e13a8a763037d958841ca9e281ca96ca9d8fb4c945c98bbb535ae` |
| `oci-authorization-get-rsa-sha256` | `052e90c20ec5bbe5fd014a68f721fad3f41dc13727ea10b49467d89313d014bd` |
| `fediverse-hs2019-rsa-sha256` | `e61217097201f9a89ebaa5e728c842deff0d40bd8fd953d0cf150480a67d8c42` |
| `extension-sigre-test-rsa-sha512` | `4d0a1f531c1a4cadd6ca1aa328f753a2fab0bbcbe33259ce363c47b081f6498f` |

## Independent Digest reproduction

The body digests can be reproduced without sigre:

```sh
fixture_dir=testdata/cavage-interoperability

for fixture_id in \
  mastodon-cavage-post-rsa-sha256 \
  misskey-inbox-post-rsa-sha256 \
  pleroma-inbox-post-rsa-sha256 \
  fediverse-hs2019-rsa-sha256
do
  jq -jr --arg fixture_id "$fixture_id" \
    '.fixtures[] | select(.id == $fixture_id) | .message.body' \
    "$fixture_dir/fixtures.json" | openssl dgst -sha256 -binary | openssl base64 -A
done
```

The expected Base64 values, in the same order, are:

```text
wUcY70G61UmGiv1h5BcDptK4F4dQwSC8GYamueGOwQI=
yyzVOHgT2fi3ipwlZNEseWTE6HFbb0R8h0mMTqOVrVM=
NwxmGd+vay9TePC/w+TUch7/jOyrTyqe5+81fsH0gvs=
B48r61tD91nlsYyoHg0yhSXm52Q0iVwL8pqYyTTcvTA=
```

## Independent signature verification

These commands validate every fixed signature without calling sigre production
code:

```sh
fixture_dir=testdata/cavage-interoperability
key_dir=testdata/cavage-draft-12/keys
fixture_workdir=$(mktemp -d /tmp/sigre-cavage-interoperability-verify.XXXXXX)

for fixture_id in $(jq -r '.fixtures[].id' "$fixture_dir/fixtures.json")
do
  jq -jr --arg fixture_id "$fixture_id" \
    '.fixtures[] | select(.id == $fixture_id) | .expected_signing_string' \
    "$fixture_dir/fixtures.json" > "$fixture_workdir/$fixture_id.txt"
  jq -jr --arg fixture_id "$fixture_id" \
    '.fixtures[] | select(.id == $fixture_id) | .signature_base64' \
    "$fixture_dir/fixtures.json" | openssl base64 -d -A \
    -out "$fixture_workdir/$fixture_id.sig"
done

for fixture_id in \
  mastodon-cavage-post-rsa-sha256 \
  misskey-inbox-post-rsa-sha256 \
  misskey-signed-get-rsa-sha256 \
  pleroma-inbox-post-rsa-sha256 \
  oci-authorization-get-rsa-sha256 \
  fediverse-hs2019-rsa-sha256
do
  openssl dgst -sha256 -verify "$key_dir/rsa-public.pem" \
    -signature "$fixture_workdir/$fixture_id.sig" "$fixture_workdir/$fixture_id.txt"
done

fixture_id=extension-sigre-test-rsa-sha512
openssl dgst -sha512 -verify "$key_dir/rsa-public.pem" \
  -signature "$fixture_workdir/$fixture_id.sig" "$fixture_workdir/$fixture_id.txt"
```

Every verification must print `Verified OK`.
