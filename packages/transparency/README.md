# @paygent/transparency

**An RFC 9162 Merkle transparency log for Paygent's audit trail.**

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

**Paygent never holds keys or funds.** The only key here signs *evidence*
(tree heads), not money.

## Install

```bash
npm install @paygent/transparency @paygent/guard
```

Zero runtime dependencies beyond `@paygent/guard` and Node's `crypto`.

## Mirror the audit ledger, publish signed heads

```ts
import { AuditLedger, MemoryLedgerStore, PaygentGuard } from "@paygent/guard";
import {
  LedgerMirror,
  TransparencyLog,
  MemoryTreeStore,
  generateLogKeyPair,
} from "@paygent/transparency";

const ledger = new AuditLedger(new MemoryLedgerStore());
const guard = new PaygentGuard({ policy, ledger });

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
import { leafHash, ledgerEntryLeaf, verifyInclusion } from "@paygent/transparency";

const entry = (await ledger.all())[seq];          // the decision in question
const proof = await mirror.proveEntry(seq);        // from the operator
// A third party verifies with ONLY entry + proof + published head:
verifyInclusion(leafHash(ledgerEntryLeaf(entry)), proof, signedHead.rootHash); // true
```

## Witness a log (catch rewrites and truncation)

```ts
import { witnessObserve, type WitnessState } from "@paygent/transparency";

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

Paygent speaks the [C2SP](https://github.com/C2SP/C2SP) formats the
transparency ecosystem actually uses (Go sumdb notes, Sigsum), so a
third-party witness needs no Paygent-specific code:

```ts
import {
  signCheckpoint, witnessCosign, attachCosignatures, checkCosignatureQuorum,
} from "@paygent/transparency";

// Operator: publish an interop checkpoint note.
const note = signCheckpoint(
  { origin: "paygent.example/ledger", treeSize: head.treeSize, rootHash: head.rootHash },
  { name: "paygent.example/ledger", privateKeyPem, publicKeyPem },
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
  origin: "paygent.example/ledger",   // REQUIRED — see below
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
- **Freshness is bounded, not proven.** `maxAgeSeconds` stops an operator
  serving one ancient cosigned checkpoint forever, but a log that simply stops
  publishing still just... stops. Monitor for growth separately.
- Timestamps in signed heads are informational, not trusted time. Cosignature
  timestamps *are* checked for staleness, but only against your own clock.

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
| `cosignCheckpoint`, `attachCosignatures`, `verifyCosignatures` | tlog-cosignature v1 |
| `checkCosignatureQuorum` | k-of-n witness policy — binds the log, counts distinct keys, fails closed |

Verified against the published Certificate Transparency test vectors and an
independent implementation; proof round-trips are tested exhaustively for
every leaf and every size pair in the tested ranges.
