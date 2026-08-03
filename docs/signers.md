# Pluggable signers: non-exportable evidence keys (KMS / HSM / hardware)

Vaduno signs five evidence structures with Ed25519: **mandates**
(`@vaduno/guard`), **signed tree heads**, **checkpoints** and **witness
cosignatures** (`@vaduno/transparency`), and **status lists**
(`@vaduno/revocation`). These keys sign *authorization and audit evidence*.
They are **never keys to funds** — but a stolen mandate key forges spending
authorization and a stolen log key forges history, so they deserve real key
custody.

The `Ed25519Signer` interface makes that custody pluggable: the private key
can live in a cloud KMS, an HSM, or a hardware token, and only *signatures*
ever cross into the Vaduno process. This is the same shape as signing-as-a
service key custody (Google Cloud KMS asymmetric signing) and the
hardware-bound-credential property (a key that can be *used* but not
*extracted*), applied to Vaduno's own evidence keys. No FIPS certification is
claimed — the property provided is **non-exportability**, exactly as strong
as the backend you plug in.

```ts
interface Ed25519Signer {
  readonly algorithm: "Ed25519";
  readonly publicKeyPem: string;           // SPKI PEM of the public half
  sign(message: Uint8Array): Promise<Uint8Array>; // 64-byte raw signature
}
```

An `Ed25519Signer` is a **capability, not a key**: there is no export method
and no `toJSON`. The bundled `LocalKeySigner` (which wraps a PKCS#8 PEM for
in-process signing) keeps its key in an ECMAScript `#private` field, so
`JSON.stringify` and `util.inspect` of it contain no key material — asserted
by test, not just by this sentence.

## NORMATIVE: key separation (read this before wiring a KMS)

**A key used behind `Ed25519Signer` MUST be dedicated to Vaduno: minted for
this purpose, holding no other signing authority of any kind.**

**It is PROHIBITED to point Vaduno at an Ed25519 blockchain wallet key —
Solana, NEAR, Stellar, or any other chain — or at any key shared with
another system** (SSH keys, other services' signing keys, anything).

The rationale is the project's hard constraint. Vaduno's code never holds
funds or keys to funds. But a signer is, mechanically, a signing oracle: the
process asks the backend to sign bytes. If the key behind it were also a
funded wallet's key, the *deployment* — wearing Vaduno's documentation — would
have turned a spend firewall into a process adjacent to a key that moves
money. That crosses the hard constraint even though the code does not, so the
requirement is stated here normatively and enforced socially: a configuration
that violates it is a misdeployment, not a supported setup.

Defense-in-depth behind the requirement — and its honest limit (both tested,
in `packages/revocation/test/signer-domain-tags.test.ts`):

- **Tagged payloads.** Mandate, tree-head, and status-list signing payloads
  begin with a fixed, versioned domain tag (`vaduno-mandate/v1`,
  `vaduno-tlog-sth/v1`, `vaduno-status-list/v1`), and witness cosignatures
  begin with the fixed C2SP `cosignature/v1` header. None of these byte
  layouts is a rail transaction, so a misdeployed shared key cannot be
  *steered* into signing one through these paths.
- **Checkpoint payloads carry NO fixed tag.** A C2SP checkpoint body's
  leading line is the OPERATOR-CHOSEN `origin` — that is the exact format
  third-party witnesses verify, and there is no room for a Vaduno tag in
  front of it. `signCheckpointWith` therefore refuses any checkpoint body
  containing control or non-ASCII bytes before the signer ever sees it, so a
  signer-path checkpoint payload cannot reproduce a binary transaction
  framing (a Solana message header, for instance) — but its leading bytes
  remain whatever the operator set as the origin. The steering guarantee
  above is scoped to the tagged payloads; for checkpoints, key separation is
  the ONLY wall.

**Domain tags are defense-in-depth, NOT a licence to share keys.** The
requirement above stands on its own.

## The `checkedSign` gate

Every signer output passes through one gate before anything is emitted or
recorded (`checkedSign`, exported from `@vaduno/guard`):

1. **Copy in.** The signer receives its own copy of the message; mutating it
   changes nothing.
2. **Deadline.** The sign call races a timeout (default 10s,
   `SignerTimeoutError`). A late resolution is discarded without mutating
   any state.
3. **Shape.** Output must be exactly 64 bytes (`SignerError` otherwise,
   before any verification).
4. **Verify.** The signature is verified against the signer's *declared*
   public key using the *original* bytes. Only a verified signature is ever
   returned (`SignerVerificationError` otherwise).

Consequences, all fail-closed and all covered by tests:

- A rejecting, hanging, truncating, or wrong-key signer **denies**; nothing
  unverifiable can leave the process, and no half-issued state is recorded.
- `MandateManager.issue()` orders: build unsigned → `checkedSign` → *only
  then* record. A signer failure leaves no phantom mandate in memory or in
  the ledger.
- Verification and consumption never touch the signer, so a wedged KMS denies
  **new** authority only — previously issued mandates still verify and
  consume, and the breach window of a revoked KMS grant is bounded to the
  time it was live.
- `LedgerMirror.sync()` with a failing signer rejects but keeps its appended
  leaves (they mirror real ledger entries — the tree stays truthful); the
  next healthy sync signs the same root.
- `RevocationRegistry.publish()` RESERVES its version before the signer
  round-trip and advances the version floor (as a monotonic max) only *after*
  signing succeeds: two concurrent publishes can neither sign the same
  version nor regress the floor, and a failed publish releases its
  reservation so the SAME version stays retryable — no gap for a verifier's
  rollback floor to misread.
- The signer's declared public key is SNAPSHOTTED at construction by
  `MandateManager`, `RevocationRegistry`, and `LedgerMirror`; every signature
  is verified against that frozen key, never against whatever the backend
  declares at sign time. A KMS wrapper that resolves "latest key version" and
  rotates mid-life is refused (`SignerVerificationError`) instead of minting
  evidence the deployment can no longer verify. Rotate by constructing over
  the new key with an overlap window (see Operational notes), not by mutating
  a live signer.
- Misconfiguration throws at **construction**, before any authority exists —
  in `MandateManager`, `RevocationRegistry`, and `LedgerMirror` alike: both
  `privateKeyPem` and `signer`; a non-Ed25519 algorithm; a declared public
  key (or legacy private key) that does not parse; and, in `MandateManager`
  (the only one that also takes a separate verify key), a `publicKeyPem`
  that does not match the signing key — whether that key comes from a
  `signer` or a legacy `privateKeyPem`.

## Wiring it

```ts
import { MandateManager, LocalKeySigner } from "@vaduno/guard";

// Legacy (unchanged, byte-identical wire output):
new MandateManager({ publicKeyPem, privateKeyPem });

// Non-exportable (the key never enters this process):
new MandateManager({ signer: myKmsSigner });

// Transparency and revocation take the same capability:
new LedgerMirror(ledger, tree, { signing: { logId, signer: myKmsSigner } });
new RevocationRegistry({ issuer, listId, signer: myKmsSigner });
// Async twins of the sync signing functions:
//   signTreeHeadWith, signCheckpointWith, cosignCheckpointWith,
//   publishStatusListWith
```

A legacy `privateKeyPem` is wrapped in `LocalKeySigner` internally, so both
configurations share one signing path and produce byte-identical signatures
for the same key (Ed25519 is deterministic).

## Example: Google Cloud KMS

Cloud KMS supports Ed25519 asymmetric signing (algorithm `EC_SIGN_ED25519`,
PureEdDSA over the raw message) — which is exactly the operation Vaduno
verifies, so a Cloud KMS-resident key is directly usable.

**Create a fresh, purpose-restricted key.** Never point Vaduno at an existing
key version that has ever signed anything else — mint one that exists only
for this deployment, and grant *sign-only* access to the one service identity
that runs the guard:

```sh
gcloud kms keyrings create vaduno --location us-east1

# ec-sign-ed25519 is the gcloud spelling of the EC_SIGN_ED25519 algorithm.
gcloud kms keys create vaduno-mandate-signing \
  --location us-east1 --keyring vaduno \
  --purpose asymmetric-signing \
  --default-algorithm ec-sign-ed25519

# Sign-only, on THIS key only, for the Vaduno service identity only.
gcloud kms keys add-iam-policy-binding vaduno-mandate-signing \
  --location us-east1 --keyring vaduno \
  --member "serviceAccount:vaduno-guard@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role roles/cloudkms.signer
```

Then implement the interface. `@google-cloud/kms` is **not** a dependency of
any Vaduno package (published packages have zero runtime dependencies outside
`@vaduno/*`, and a test freezes that) — install it in *your* application:

```ts
import { KeyManagementServiceClient } from "@google-cloud/kms";
import type { Ed25519Signer } from "@vaduno/guard";

export async function cloudKmsSigner(versionName: string): Promise<Ed25519Signer> {
  const client = new KeyManagementServiceClient();
  // e.g. projects/P/locations/us-east1/keyRings/vaduno/cryptoKeys/
  //      vaduno-mandate-signing/cryptoKeyVersions/1
  const [pub] = await client.getPublicKey({ name: versionName });
  if (!pub.pem) throw new Error(`no public key PEM for ${versionName}`);
  return {
    algorithm: "Ed25519",
    publicKeyPem: pub.pem,
    async sign(message: Uint8Array): Promise<Uint8Array> {
      // Ed25519 in Cloud KMS signs the RAW message (PureEdDSA): pass the
      // bytes, not a digest.
      const [res] = await client.asymmetricSign({
        name: versionName,
        data: Buffer.from(message),
      });
      if (!res.signature) throw new Error("Cloud KMS returned no signature");
      return new Uint8Array(res.signature as Uint8Array);
    },
  };
}
```

Whatever this returns is still funnelled through `checkedSign`: a corrupted
response, a proxy in the middle, or a substituted key is refused by post-sign
verification before anything is emitted.

**AWS KMS:** at the time of writing, AWS KMS does not offer Ed25519 signing
keys, so there is no AWS KMS example — one that could not work would be worse
than none. If you are on AWS, use an HSM or another backend that exposes
Ed25519 (e.g. via PKCS#11), or CloudHSM configured for it, behind the same
interface.

**PKCS#11 / TPM / hardware tokens:** any backend that can produce raw 64-byte
Ed25519 signatures fits the three-member interface the same way; keep the key
non-extractable in the token and follow the key-separation requirement above.

## Operational notes

- **Rotation:** mint a *new* dedicated key, run both via
  `additionalPublicKeyPems` for the overlap window, then retire the old one.
  Never re-purpose the retiring key.
- **Revocation of issuing power:** revoking the service identity's IAM grant
  stops new mandates at the next `issue()` (the signer starts rejecting; the
  manager records nothing). Already-issued mandates still verify and consume —
  bound the damage window with short mandate expiries.
- **A wedged signer is a denial, never a downgrade:** issuance does not fall
  back to unsigned or locally-signed output under any failure.
