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

## Honest limits (read `docs/SECURITY-MODEL.md`)

- The log makes rewriting history **detectable and attributable**, not
  impossible. Detection requires someone *other than the operator* to retain
  or witness heads — publish them.
- A tree with zero external witnesses proves nothing to outsiders.
- Timestamps in signed heads are informational, not trusted time.

## API surface

| Export | What |
|---|---|
| `TransparencyLog`, `MemoryTreeStore`, `JsonlTreeStore` | The Merkle tree over leaf bytes |
| `leafHash`, `rootFromLeafHashes`, `proveInclusion`, `proveConsistency` | RFC 9162 math (pure functions) |
| `verifyInclusion`, `verifyConsistency` | RFC 9162 verifiers — fail closed, never throw |
| `generateLogKeyPair`, `signTreeHead`, `verifyTreeHead` | Ed25519 signed tree heads |
| `witnessObserve`, `detectSplitView` | The client/witness half |
| `LedgerMirror` | Binds an `AuditLedger` to a tree: `sync` / `audit` / `proveEntry` |

Verified against the published Certificate Transparency test vectors and an
independent implementation; proof round-trips are tested exhaustively for
every leaf and every size pair in the tested ranges.
