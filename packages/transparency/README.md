# @vaduno/transparency

**An RFC 9162 Merkle transparency log for Vaduno's audit trail.**

The guard's hash-chained ledger proves *ordering* and *tamper-evidence*. This
package adds the two properties a bare hash chain cannot give you:

- **Non-omission** — an *inclusion proof* shows a specific decision **is**
  committed under a published root. Nobody can quietly drop the embarrassing
  entry and keep the rest.
- **Append-only history** — a *consistency proof* shows a later root extends
  an earlier one without rewriting anything in between.

Both are verifiable by a third party from the roots alone — the same math that
Certificate Transparency uses to watch the world's TLS certificate authorities
(RFC 9162, RFC 6962), applied to AI-agent payment decisions.

**Vaduno never holds funds or keys to funds.** The only key here signs
*evidence* (tree heads), not money.

## Install

```bash
npm install @vaduno/transparency @vaduno/guard
```

Zero runtime dependencies beyond `@vaduno/guard` and Node's `crypto`.

## Mirror the audit ledger, publish signed heads

```ts
import { AuditLedger, MemoryLedgerStore, VadunoGuard } from "@vaduno/guard";
import {
  LedgerMirror,
  TransparencyLog,
  MemoryTreeStore,
  generateLogKeyPair,
} from "@vaduno/transparency";

const ledger = new AuditLedger(new MemoryLedgerStore());
const guard = new VadunoGuard({ policy, ledger });

const keys = generateLogKeyPair(); // Ed25519; keep the private key out of agent reach
const tree = new TransparencyLog(new MemoryTreeStore());
const mirror = new LedgerMirror(ledger, tree, {
  signing: { logId: "my-agent-log", privateKeyPem: keys.privateKeyPem },
});

// ... payments happen through the guard ...

const { head, signedHead } = await mirror.sync(); // append new entries, sign the head
// PUBLISH signedHead somewhere outside the store (repo, endpoint, a friend).
```

## Prove a decision is in the history (non-omission)

```ts
import { leafHash, ledgerEntryLeaf, verifyInclusion } from "@vaduno/transparency";

const entry = (await ledger.all())[seq];          // the decision in question
const proof = await mirror.proveEntry(seq);        // from the operator
// A third party verifies with ONLY entry + proof + published head:
verifyInclusion(leafHash(ledgerEntryLeaf(entry)), proof, signedHead.rootHash); // true
```

## Witness a log (catch rewrites and truncation)

```ts
import { witnessObserve, type WitnessState } from "@vaduno/transparency";

let state: WitnessState = { logId, publicKeyPem, lastHead: null };

// Each time the operator publishes a new signed head + consistency proof:
const r = witnessObserve(state, newSignedHead, consistencyProof);
if (r.ok) state = r.state;         // advance
else alert(r.code);                // TREE_SHRANK / ROOT_CHANGED_WITHOUT_GROWTH /
                                   // CONSISTENCY_PROOF_INVALID / BAD_SIGNATURE …
```

Two signed heads of the same size with different roots are *signed proof* the
operator equivocated — `detectSplitView` finds them.

## Witness cosigning: non-equivocation (C2SP)

Everything above catches an operator who rewrites history for **one** viewer.
It does **not** catch one who signs *two* histories and shows a different one
to each party — every signature verifies and every consistency proof passes.
That is a **split view**, and the only defence is independent parties who
refuse to vouch for a history that contradicts one they already vouched for.

Vaduno speaks the [C2SP](https://github.com/C2SP/C2SP) formats the
transparency ecosystem actually uses (Go sumdb notes, Sigsum), so a
third-party witness needs no Vaduno-specific code:

```ts
import {
  signCheckpoint, witnessCosign, attachCosignatures, checkCosignatureQuorum,
} from "@vaduno/transparency";

// Operator: publish an interop checkpoint note.
const note = signCheckpoint(
  { origin: "vaduno.example/ledger", treeSize: head.treeSize, rootHash: head.rootHash },
  { name: "vaduno.example/ledger", privateKeyPem, publicKeyPem },
);

// Witness (someone else's server): cosign ONLY if append-only consistent
// with the last checkpoint this witness cosigned. Use the CLASS, not the bare
// function, so concurrent requests cannot make one witness sign two forks.
const witness = new CosigningWitness(state, { name, privateKeyPem, publicKeyPem }, persist);
const r = await witness.cosign(note, { proof });
if (r.ok) send(r.cosignature);

// Relying party: require a quorum before trusting the log.
const witnessed = attachCosignatures(note, cosignatures);
const quorum = checkCosignatureQuorum(witnessed, knownWitnesses, 2, {
  origin: "vaduno.example/ledger",   // REQUIRED — see below
  logPublicKeyPem,
});
if (!quorum.ok) refuse(quorum.message);
use(quorum.checkpoint);               // consume what was verified
```

`npm run demo:transparency` shows the attack and its defeat: the fork's log
signature verifies (the log's own crypto cannot catch it), but **0/3 witnesses
will cosign it**, so it never reaches quorum.

**The log binding is a required argument, not an option.** Witness
cosignatures attest *"this is the log I have been following"* — they say
nothing about *which* log that is, and public witnesses cosign many logs under
one key. Without pinning the origin and the log's own signature, an operator
can stand up a second origin, let honest witnesses cosign it at
trust-on-first-use, and serve the result as though it were yours. That is a
quorum bypass needing **zero** witness misbehaviour, so the API makes it
impossible to skip.

Wire format, for anyone checking interop: the cosignature blob is
`base64(keyID[4] || timestamp[8, big-endian] || signature)` and the signed
message is `"cosignature/v1\n" + "time <seconds>\n" + <note body>`. The
timestamp therefore travels **inside** the note — there is no side-channel to
keep in sync.

### ML-DSA-44 (0x06) cosignatures and anchor strength

The C2SP spec defines a second cosignature type — key-id algorithm byte
`0x06`, ML-DSA-44 (FIPS 204), 2420-byte signatures — and this package
implements it (`cosignCheckpointMlDsa44`, verified by the same
`verifyCosignatures`/`checkCosignatureQuorum`). Three things worth knowing
before relying on it:

- **The 0x06 payload is a different BINARY structure**, not the 0x04 text
  payload with a new algorithm: `label[12]="subtree/v1\n\0" ||
  name<1..255> || u64 timestamp || origin<1..255> || u64 start(=0) ||
  u64 end(=size) || raw 32-byte root`. It covers (origin, size, root) ONLY —
  extension lines are covered by 0x04, never 0x06 — so a PQ-witnessed claim
  attests **tree state**, not extension lines.
- **Signing needs runtime support** (`node:crypto` ML-DSA: Node ≥ 24.7 built
  against OpenSSL ≥ 3.5; the runtime probe decides, and without it signing
  throws a typed `PqUnavailableError`). Verifying without support IGNORES
  0x06 lines — the note rests on its Ed25519 cosignatures, and nothing
  unverifiable ever upgrades a claim.
- **`assessCheckpointAnchor`** reports `witnessed-pq` only when a k-party
  quorum of VERIFIED 0x06 cosignatures exists, and its `witnessedAt` counts
  only cosignatures at least as strong as the reported label — so an
  attacker who can forge Ed25519 (post-CRQC) cannot backdate a PQ-witnessed
  checkpoint with a forged classical line.

## Honest limits (read `docs/SECURITY-MODEL.md`)

- The log makes rewriting history **detectable and attributable**, not
  impossible. Detection requires someone *other than the operator* to retain
  or witness heads — publish them.
- A tree with zero external witnesses proves nothing to outsiders.
- **Witnessing gives non-equivocation, not completeness.** It proves everyone
  sees the *same* log; it does not prove the log contains every event that
  happened. Pair it with log-before-authorize.
- **Witnesses you run yourself count for nothing.** A quorum of keys held by
  one operator provides exactly zero additional assurance — independence is a
  social property the code cannot verify for you. Quorum counts distinct
  *keys*, which catches the same key registered under several names; it cannot
  catch one operator running several genuinely distinct keys.
- **A witness that forgets its state is worthless.** Its whole value is having
  a baseline to contradict. Persist `CosigningWitness` state durably, and
  serialize updates — a read-modify-write race lets one witness cosign two
  forks.
- **Evidence verification is ARCHIVAL by default; freshness is opt-in.**
  A cosignature attests "this witness saw this no later than T" — that does
  not decay, so by default there is NO staleness bound and a years-old
  evidence bundle verifies (only implausibly future-dated cosignatures are
  rejected, against your own clock). Pass `maxAgeSeconds` when you are
  asking the LIVENESS question — it stops an operator serving one ancient
  cosigned checkpoint forever, but a log that simply stops publishing still
  just... stops. Monitor for growth separately.
- Timestamps in signed heads are informational, not trusted time. Cosignature
  timestamp bounds are judged against your own clock.

## API surface

| Export | What |
|---|---|
| `TransparencyLog`, `MemoryTreeStore`, `JsonlTreeStore` | The Merkle tree over leaf bytes |
| `leafHash`, `rootFromLeafHashes`, `proveInclusion`, `proveConsistency` | RFC 9162 math (pure functions) |
| `verifyInclusion`, `verifyConsistency` | RFC 9162 verifiers — fail closed, never throw |
| `generateLogKeyPair`, `signTreeHead`, `verifyTreeHead` | Ed25519 signed tree heads |
| `witnessObserve`, `detectSplitView` | The client/witness half |
| `LedgerMirror` | Binds an `AuditLedger` to a tree: `sync` / `audit` / `proveEntry` |
| `signCheckpoint`, `parseNote`, `verifyNoteSignature` | C2SP signed-note / tlog-checkpoint interop format |
| `witnessCosign`, `CosigningWitness` | The witness protocol — refuses to cosign an inconsistent checkpoint; the class also serializes concurrent requests |
| `cosignCheckpoint`, `attachCosignatures`, `verifyCosignatures` | tlog-cosignature (0x04 Ed25519 and 0x06 ML-DSA-44) |
| `cosignCheckpointMlDsa44`, `mlDsa44CosignaturePayload` | the 0x06 ML-DSA-44 cosignature and its BINARY signed struct |
| `checkCosignatureQuorum` | k-of-n witness policy — binds the log, counts distinct parties (a witness's two key types are ONE party), fails closed |
| `assessCheckpointAnchor` | anchor strength (`witnessed-pq` / `witnessed` / `unwitnessed`) + strength-scoped `witnessedAt` |

Verified against the published Certificate Transparency test vectors and an
independent implementation; proof round-trips are tested exhaustively for
every leaf and every size pair in the tested ranges.
