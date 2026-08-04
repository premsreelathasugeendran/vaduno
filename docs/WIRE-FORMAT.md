# Vaduno wire format

Everything Vaduno signs or hashes, defined precisely enough to reimplement.

This document exists because the stated goal is an **adopted format**, not a
library — and a format nobody else can reproduce is not a format. Until 0.3.0
there was no spec and no test vector anywhere in the repo: `hash.test.ts`
compared the canonicalizer to *itself*, so every preimage could have drifted
without a test noticing.

The normative artifacts are **[`spec/vectors/*.json`](../spec/vectors)**. They
are committed constants, and [`packages/guard/test/wire-format.test.ts`](../packages/guard/test/wire-format.test.ts)
asserts the implementation reproduces them. A diff in those files is a wire
format change: it breaks every existing signature and must bump the relevant
domain tag's version.

Status: **v1 of every structure below is FROZEN**, and one structure has an
ADDITIVE v2: the hybrid mandate (§3b), which coexists with v1 rather than
replacing it — every v1 vector is byte-identical to the day it was committed.
No second implementation exists yet. If you are writing one, the vectors are
the contract — and disagreements are bugs worth
[reporting](https://github.com/premsreelathasugeendran/vaduno/issues).

---

## 1. Canonicalization

Every preimage is built on `canonicalJson`, so its rules come first.

**The property that matters is injectivity: distinct inputs MUST produce
distinct output.** A canonicalizer that merely produces *stable* bytes is not
sufficient for signing — two different values sharing an encoding means two
different meanings sharing a signature.

Accepted types are exactly JSON's: `null`, boolean, **finite** number, string,
array, and plain object.

| Rule | |
|---|---|
| Object keys | sorted by UTF-16 code unit, at every level |
| Array order | preserved |
| Strings | escaped per `JSON.stringify` |
| Numbers | `JSON.stringify` formatting; finite only |
| `__proto__` | an ordinary key, committed to like any other |
| `undefined` own property | **omitted** — see below |

**Everything else throws** rather than being coerced. Until 0.3.0 it was coerced
"deterministically", which produced five collision families:

```
{n: 1n}          collided with  {n: "1n"}
{d: new Date(0)} collided with  {d: "1970-01-01T00:00:00.000Z"}
{x: NaN}         collided with  {x: null}
[undefined]      collided with  [null]
Map / Set / RegExp / class instances  all became  {}
```

That made `contextHash` forgeable, defeating the check that binds a mandate to
one approved task run. If you want a timestamp or a big integer in a signed
payload, **serialize it yourself** — then the bytes are your decision.

**The one deliberate omission:** an own property whose value is `undefined` is
skipped, so `{a:1, b:undefined}` and `{a:1}` agree. Both say "b is absent", so
it is not a meaningful collision. Inside an **array** `undefined` throws,
because there position carries meaning and it would collide with `null`.

Aligned with [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) in spirit. Number
formatting follows ECMAScript, which agrees with JCS on every integer and on the
decimals this project produces — amounts are always integer minor units, so the
pathological float cases JCS enumerates are unreachable here.

Vectors: [`canonical-json.json`](../spec/vectors/canonical-json.json),
[`sha256.json`](../spec/vectors/sha256.json)

---

## 2. Domain separation

Every signed structure is prefixed with a versioned, newline-terminated tag.

```
vaduno-mandate/v1\n            mandate signing payload (v1, frozen)
vaduno-mandate/v2\n            HYBRID mandate signing payload (v2 — §3b)
vaduno-mandate-key/v1\n        mandate key id derivation (both algorithms)
vaduno-mandate-ctx/v1\n        mandate context binding
vaduno-consume-digest/v1\n     consume-once intent digest
vaduno-ledger-entry/v1\n       transparency log leaf
vaduno-tlog-sth/v1\n           signed tree head
vaduno-status-list/v1\n        W3C status list credential
```

Without a tag, a signature is bound to *some canonical JSON*, not to what that
JSON means — any other structure whose canonical form could coincide would share
its signature space. The trailing newline stops one tag being a prefix of
another; the version is what makes a future change expressible.

**The ledger entry hash is deliberately untagged.** It is an internal chain link,
not a signed assertion, and it gets wrapped by the transparency leaf tag when
published.

Vector: [`domains.json`](../spec/vectors/domains.json)

---

## 3. Mandate

A signed, time-bound, use-bounded permission slip.

**Preimage:** `"vaduno-mandate/v1\n" + canonicalJson(mandate minus signature)`
**Signature:** Ed25519, base64.

```jsonc
{
  "v": 1,                    // format version — refuse what you don't recognise
  "alg": "Ed25519",          // refuse an algorithm you don't implement
  "kid": "…16 hex chars…",   // which key signed this
  "id": "uuid",
  "issuer": "human@example.com",
  "agentId": "agent-1",
  "constraints": { "maxAmountMinor": 10000, "currency": "USD", "…": "…" },
  "createdAt": "2026-01-01T00:00:00.000Z",
  "signature": "base64"
}
```

**A verifier MUST refuse, not guess:**

| Condition | Result |
|---|---|
| `v` unrecognised | `VERSION_UNSUPPORTED` |
| `alg` unimplemented | `ALG_UNSUPPORTED` |
| `kid` not held | `KEY_UNKNOWN` |
| signature bad | `SIGNATURE_INVALID` |

**Key id:** first 8 bytes of `SHA-256("vaduno-mandate-key/v1\n" || SPKI DER)`, hex.
Derived from the key rather than assigned, so two implementations reach the same
id independently.

**Select the key the mandate NAMES.** Do not try every key you hold — that would
let a rotation window accept a mandate whose `kid` claims one key while the
signature came from another. `kid` is inside the preimage, so relabelling breaks
the signature; that attack is a test.

Vector: [`mandate.json`](../spec/vectors/mandate.json) — includes a fixed test
key pair, so a second implementation can verify a real signature.

### 3b. Hybrid (v2) mandate — post-quantum readiness, additive

**Preimage:** `"vaduno-mandate/v2\n" + canonicalJson(mandate minus signatures)`
**Signatures:** BOTH Ed25519 (64 bytes) and ML-DSA-44 (FIPS 204, 2420 bytes),
base64, each over the SAME preimage. Where a verifier can check a signature it
MUST verify — a present-but-invalid half is refused, never ignored.

```jsonc
{
  "v": 2,
  "algs": ["Ed25519", "ML-DSA-44"],   // exactly this suite, in this order
  "kids": { "Ed25519": "…16 hex…", "ML-DSA-44": "…16 hex…" },
  "id": "uuid",
  "issuer": "human@example.com",
  "agentId": "agent-1",
  "constraints": { "…": "…" },        // same shape as v1
  "createdAt": "2026-01-01T00:00:00.000Z",
  "signatures": { "Ed25519": "base64", "ML-DSA-44": "base64" }
}
```

**Pre-crypto structural bounds (MALFORMED before any signature check):**

| Bound | Why |
|---|---|
| `algs` equals the suite above exactly, in order | order is part of the signed canonical form |
| `kids` keys equal `algs` EXACTLY; each kid matches `^[0-9a-f]{16}$` | kids is signed, but an issuer-side bug must not ship a bloated or unresolvable kids object |
| `signatures` keys equal `algs` exactly | no extra, no missing |
| each signature must DECODE to exactly 64 / 2420 bytes | Node's base64 decoder silently skips invalid characters — an encoded-string length check is NOT a signature length check |

**Key lookup is (algorithm, kid).** Both families derive the id the same way
(first 8 bytes of `SHA-256("vaduno-mandate-key/v1\n" || SPKI DER)`, hex) — and
because that is a 64-bit TRUNCATED hash, distinct keys can collide (~2^32
birthday / ~2^64 targeted). Binding the algorithm at lookup keeps a collision
from crossing families; the within-family residual is stated in
`docs/SECURITY-MODEL.md`.

**Verification policy:** absent runtime ML-DSA support (see the probe in
`SECURITY-MODEL.md`) or a held key for the named ML-DSA kid, a v2 mandate is
accepted resting on its classical signature — v1-equivalent standing — unless
the verifier sets `requireAlgs: ["ML-DSA-44"]`, which makes every
unverifiable-PQ case a refusal. `requireAlgs` is the only post-CRQC defense;
see the downgrade section of `SECURITY-MODEL.md`.

Vector: [`mandate-v2.json`](../spec/vectors/mandate-v2.json) — pins the
preimage, both kid derivations, and the (deterministic) Ed25519 signature.
The ML-DSA-44 signature bytes are not pinned because FIPS 204 signing is
hedged (randomized); the vector pins its exact decoded length instead.

### Context binding

`contextHash = SHA-256("vaduno-mandate-ctx/v1\n" + canonicalJson(context))`

Binds a mandate to one approved task run. Two fields carry enforced meaning when
present: `agentId` and `merchantId` must equal the paying intent's, so a stolen
context blob cannot be replayed by a different agent or at a different merchant
even inside the mandate's allowlists.

Vector: [`mandate-context.json`](../spec/vectors/mandate-context.json)

---

## 4. Consume-once intent digest

`SHA-256("vaduno-consume-digest/v1\n" + canonicalJson({amountMinor, currency,
merchantId, merchantUrl, rail, mandateId}))`

Commits to the **money-affecting fields only**. That is deliberate in both
directions: a replayed intent id carrying different money is detected
(`MANDATE_REPLAY_MISMATCH`), while an honest retry carrying a new timestamp still
replays rather than being rejected as a different payment.

Vector: [`intent-digest.json`](../spec/vectors/intent-digest.json)

---

## 5. Ledger entry

`hash = SHA-256(canonicalJson(entry without its own hash))`, where the entry
carries `prevHash`. Genesis `prevHash` is 64 zeros.

Each entry commits to its predecessor, so any edit, deletion or reorder is
detectable by `verify()`. **Tamper-evident, not tamper-proof** — the difference
is load-bearing: an attacker who controls the store can rewrite the whole chain,
which is what the transparency log and a retained head exist to catch.

Vector: [`ledger-entry.json`](../spec/vectors/ledger-entry.json)

---

## 6. Transparency log

[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) / RFC 6962 hashing:

```
leaf:     SHA-256(0x00 || data)
interior: SHA-256(0x01 || left || right)
```

The distinct prefixes are what prevent a leaf being presented as an interior
node — the second-preimage attack the prefixes exist for. Empty tree root is
SHA-256 of the empty string.

Leaves are `"vaduno-ledger-entry/v1\n" + canonicalJson(entry)`.

Signed tree heads use `"vaduno-tlog-sth/v1\n"`, and checkpoints follow
[C2SP `tlog-checkpoint`](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md)
signed-note format with `tlog-cosignature` witnesses — so a real Go or Sigsum
witness can cosign. That interop is the reason the format is not homegrown.

Vector: [`merkle.json`](../spec/vectors/merkle.json)

### ML-DSA-44 (0x06) witness cosignatures

Two cosignature types per C2SP `tlog-cosignature`, distinguished by the
key-id algorithm byte:

| Type | Key id | Signed payload |
|---|---|---|
| `0x04` (Ed25519) | `SHA-256(name \|\| 0x0A \|\| 0x04 \|\| raw 32-byte key)[:4]` | TEXT: `"cosignature/v1\n" + "time T\n" + note body` |
| `0x06` (ML-DSA-44) | `SHA-256(name \|\| 0x0A \|\| 0x06 \|\| raw 1312-byte key)[:4]` | BINARY struct below — **not** the 0x04 text with a different algorithm |

```
struct {
  u8     label[12] = "subtree/v1\n\0";
  opaque cosigner_name<1..255>;     // 1-byte length prefix
  uint64 timestamp;                 // big-endian POSIX seconds
  opaque log_origin<1..255>;        // 1-byte length prefix
  uint64 start;                     // MUST be 0 for checkpoints
  uint64 end;                       // = tree size
  u8     hash[32];                  // RAW root hash
}
```

The signature line blob is `keyID[4] || uint64BE timestamp || signature[2420]`,
same layout as 0x04. The raw ML-DSA-44 public key comes from an actual SPKI
parse (`rawMlDsa44PublicKey`) — the Ed25519 "last 32 bytes of the DER"
shortcut would silently produce a garbage key id for an ML-DSA key, and
`rawEd25519PublicKey` now refuses non-Ed25519 keys for the same reason.

**Coverage asymmetry, part of the contract:** the 0x06 struct covers
(origin, size, root) only; 0x04 covers the full note body including extension
lines. A PQ-witnessed claim therefore attests tree state, not extension
lines. See `docs/SECURITY-MODEL.md` (post-quantum posture).

Vector: [`cosign-mldsa44-payload.json`](../spec/vectors/cosign-mldsa44-payload.json)

---

## 7. Revocation status list

W3C [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)
credentials, signed over `"vaduno-status-list/v1\n" + canonicalJson(unsigned)`.
Index 0 is the leftmost/most-significant bit; GZIP then multibase base64url
(`u` prefix); minimum 131,072 entries.

**Known limitation:** bit indices are allocated by a single-writer in-memory
store, so two replicas assign index 0 to *different* mandates. A Postgres store
is [the next thing to build](../CHANGELOG.md). Until then, allocate indices from
one process.

---

## Changing any of this

1. Bump the relevant domain tag's version (`/v1` → `/v2`).
2. `node scripts/gen-vectors.mjs` — the diff **is** the change; review it.
3. Expect every existing signature to become invalid, and say so in the changelog.

Never regenerate vectors to make a failing test pass. The failure is the point.
