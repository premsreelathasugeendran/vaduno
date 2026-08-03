# @vaduno/revocation

**The kill switch for agent payment authority — honestly scoped.**

An agent's credentials leak at 2am. You need every mandate it holds to stop working *now*, you need proof of when you pulled the trigger, and you need to know which rails actually acknowledged it.

```bash
npm install @vaduno/revocation
```

## What revocation actually guarantees

This package is deliberately **not** marketed as a "universal instant kill switch." A neutral registry has no authority over rails it does not govern. The honest split:

| Authority | Guarantee |
|---|---|
| Mandates the Vaduno guard mediates | **Instant and guaranteed.** The guard consults the registry before money moves and fails closed. Nothing spends under a revoked mandate again. |
| Authority Vaduno does *not* mediate (a raw wallet key the agent holds, a card issued outside Vaduno) | **Best-effort fan-out** to each rail's own revocation API. Every attempt *and every failure* is recorded, so the gap between "we asked" and "it took effect" is visible rather than assumed. |
| Money already settled on-chain | **Nothing.** Settled spend cannot be clawed back by anyone. |

## Quick start

```ts
import { VadunoGuard } from "@vaduno/guard";
import { RevocationRegistry, createRegistryCheck } from "@vaduno/revocation";

const registry = new RevocationRegistry({
  issuer: "you@company.com",
  listId: "https://you.example/status/1",   // where you publish the status list
  privateKeyPem: keys.privateKeyPem,        // signs published lists
  ledger,                                   // every revocation is audited
  fanOut: [                                 // optional, best-effort
    { rail: "stripe-issuing", revoke: async (r) => stripe.issuing.cards.update(...) },
  ],
});

const guard = new VadunoGuard({
  policy, ledger, mandates,
  revocationCheck: createRegistryCheck(registry),   // <- makes it ENFORCED
});

// 2am: the agent is compromised.
// Register each mandate as you issue it — this assigns its status-list bit
// AND links it to its agent, which is what makes an agent-wide kill work.
await registry.assignIndex(mandate.id, agentId);

await registry.revokeAgent("shopper-agent-1", { reason: "credentials leaked", by: "prem" });
// Every mandate it holds is dead, and the agent id is blocked so mandates
// issued to it afterwards are refused too.
```

Rail fan-out runs **off** the kill path under a per-rail deadline, so a rail that hangs (rather than fails) can never delay — let alone wedge — the authoritative local revocation. `result.fanOut` is a promise you may await for the per-rail outcome; the kill is already in force either way.

Without `revocationCheck` wired into the guard, revocation is only bookkeeping. **Wire it.**

## The freeze every process observes (`FreezeStore`, new in 0.3.0)

`guard.freeze()` is an in-memory flag: instant in its own process, invisible to
every other live process — guard A denies while guard B keeps spending. The
shared `FreezeStore` is the cross-process half: one global row
`{ epoch, frozen, reason, by, at }` in a backend every process can reach,
consulted on every authorization through the same `revocationCheck` seam:

```ts
import {
  FileFreezeStore, createFreezeCheck, createRegistryCheck, allChecks,
} from "@vaduno/revocation";

const freezeStore = new FileFreezeStore("/var/lib/vaduno/freeze.json");

const guard = new VadunoGuard({
  policy, ledger, mandates,
  revocationCheck: allChecks(
    createRegistryCheck(registry),
    createFreezeCheck(freezeStore),   // <- the cross-process kill switch
  ),
});

// 2am, from ANY process:
const { epoch } = await freezeStore.freeze("credentials leaked", "prem");
// every wired process's NEXT authorization now denies GUARD_FROZEN,
// message carrying "credentials leaked".

// Later, once the incident is over — fenced on the epoch you LOOKED AT:
await freezeStore.unfreeze(epoch);   // refused (STALE_EPOCH) if anyone froze again
```

What to know before wiring it:

- **Checked inside the critical section, after human approval, before the
  budget reservation** — a freeze pulled while an approval sat pending still
  wins, and nothing is reserved for a payment the freeze denies.
- **Epoch-fenced unfreeze.** Every freeze bumps a monotonic epoch;
  `unfreeze(expectedEpoch)` applies only if the epoch is still the one you
  read, so you can never silently lift a NEWER freeze someone else issued. A
  refusal changes nothing. A `freeze("")` never blanks a live reason.
- **TOTAL STOP on outage — the availability cost, stated plainly.** The check
  fails closed, so an unreachable freeze store denies **every** payment on
  every wired guard (`FREEZE_CHECK_FAILED`). That is deliberate — "no money
  moves" is the recoverable direction, and it is the same stance the registry
  takes — but it makes the freeze store a **hard availability dependency for
  all payments**. There is no cache and no fail-open mode.
- **Local and shared are independent.** `guard.freeze()` does not write the
  store; a store `unfreeze()` does not clear a peer's local flag. An operator
  who wants both issues both. Single-process deployments can keep using
  `guard.freeze()` alone.
- **A freeze denies NEW authorizations only.** It cannot recall, pause or
  redirect a payment already handed to the rail — that power is exactly the
  custody Vaduno must never hold — and it deliberately does not gate
  `settle()`: a settle records money that already moved, and refusing to
  record it would corrupt the evidence, not protect anything.
- **Backends:** `MemoryFreezeStore` (one process — tests, reference
  semantics), `FileFreezeStore` (several processes on one box; advisory
  `FileMutex` lock, same documented `staleMs` reclaim residual as the other
  file stores), `PostgresFreezeStore` in
  [`@vaduno/postgres`](https://www.npmjs.com/package/@vaduno/postgres)
  (multi-instance; `UPDATE … WHERE epoch = $expected` *is* the
  compare-and-set). Memory and File are exercised by the freeze conformance
  suite on every test run; the Postgres backend's suite is env-gated and has
  only ever run where `VADUNO_TEST_POSTGRES_URL` points at a live database —
  check the CI postgres job for the commit you install.

## The race that matters

A kill switch is worthless if it loses to work already in flight. The guard checks revocation *inside its critical section, after human approval and before the mandate is consumed* — so an operator who pulls the switch while a human is still approving still wins:

```
human is deciding…  operator pulls the kill switch…
human APPROVED, but result = denied; rail ran: false → kill switch wins ✅
```

## Fail closed, always

Any inability to determine status denies the payment. An outage must never read as "not revoked", or an attacker could disable your kill switch by knocking the registry offline.

| Situation | Result |
|---|---|
| Mandate revoked / agent revoked | `MANDATE_REVOKED` / `AGENT_REVOKED` |
| Registry unreachable or throwing | `REVOCATION_CHECK_FAILED` — denied |
| Status list expired | `STATUS_LIST_EXPIRED` — unavailable, *not* "clean" |
| Status list not yet valid (future-dated) | `STATUS_LIST_NOT_YET_VALID` — denied |
| Status list signature invalid | `SIGNATURE_INVALID` — denied |
| Older (or different same-version) snapshot replayed | `STATUS_LIST_ROLLBACK` — denied |
| A list for another id / issuer / purpose | `LIST_MISMATCH` / `ISSUER_MISMATCH` / `PURPOSE_MISMATCH` |
| Mandate has no assigned status index | `NO_STATUS_INDEX` — denied |
| Shared freeze store says frozen | `GUARD_FROZEN` — denied, message carries the operator's reason |
| Shared freeze store unreachable or corrupt | `FREEZE_CHECK_FAILED` — **every** payment denied (total stop) |

## Publishing a status list (W3C Bitstring Status List v1.0)

For counterparties who don't own your registry, publish a signed [W3C Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/): one bit per mandate, GZIP'd and multibase base64url-encoded, so a 131,072-entry list is ~70 bytes on the wire.

```ts
const credential = await registry.publish(version);   // version MUST increase
// serve `credential` at listId; a verifier checks one entry:
import { checkStatus } from "@vaduno/revocation";
checkStatus(credential, statusListIndex, { publicKeyPem });
// → { valid, revoked, code, message }
```

`valid` and `revoked` are **not** complements: an expired or unverifiable list yields `valid: false, revoked: false` — status unknown, do not authorize.

Verifier side:

```ts
const check = createStatusListCheck({
  fetchList: () => fetch(listUrl).then((r) => r.json()),
  publicKeyPem: issuerPublicKey,
  indexFor: (intent) => indexOfMandate(intent.mandateId),
  // PIN these. A signature proves who signed, not WHICH list — without
  // pinning, any list that key ever signed (including a sibling suspension
  // list whose revocation bits are clear) substitutes for this one.
  expectedListId: listUrl,
  expectedIssuer: "you@company.com",
  expectedPurpose: "revocation",
  // Persist and seed the rollback floor, or a cold start (new replica,
  // serverless instance) accepts a pre-revocation snapshot for its whole TTL.
  initialVersionFloor: loadPersistedFloor(),
  onFloorAdvance: (version) => persistFloor(version),
});
```

It rejects rolled-back versions — including a *different* list served at the same version — so an attacker can't replay a still-fresh snapshot from before a revocation. `publish()` refuses to reuse or lower a version for the same reason.

## Suspension vs revocation

Per the W3C spec, `revocation` is **permanent** and `suspension` is **reversible** — and this package enforces that. `unsuspendMandate()` refuses to reinstate something that was permanently revoked.

```ts
await registry.revokeMandate(id, { purpose: "suspension" });  // pause
await registry.unsuspendMandate(id);                          // resume
await registry.revokeMandate(id);                             // permanent — no going back
```

## Demo

```bash
npm run demo:revocation
```

Shows the full lifecycle: revoke → denied, the approval race, agent-wide kill, registry outage failing closed, a published list a third party verifies, a forged bitstring rejected, and the audit trail.

## Limits

- **Enforcement requires mediation.** A cap or a kill only binds where the agent's spend actually flows through the guard. Give agents *only* guarded paths.
- **The rollback floor is per-verifier-instance** unless you persist it. A cold-started verifier with no seeded floor accepts a pre-revocation snapshot for its whole TTL — use `initialVersionFloor` / `onFloorAdvance`, and keep TTLs short.
- **Index assignment is stable and permanent** per mandate. Indices are never recycled — recycling would make one revocation silently apply to a different mandate.
- **Call `hydrateFromLedger()` at startup** when using the in-memory store with a durable ledger. Without it a restart silently un-revokes everything *and* restarts index allocation from zero.
- **A full status list still revokes locally.** If the bit space is exhausted the kill takes effect and the result is flagged `unpublishable` — enforced locally, invisible to third-party verifiers. Rotate to a new list.
- **The agent kill is keyed on `intent.agentId`**, which the agent supplies. Bind agent identity by other means (`requireMandate: true`) where that matters.
- **`MemoryRevocationStore` is single-process.** Bit indices are allocated
  from an in-memory counter, so two replicas would assign index **0** to
  *different* mandates and the collision lands in the published status list
  third parties read. For multiple instances supply `PostgresRevocationStore`
  from [`@vaduno/postgres`](https://www.npmjs.com/package/@vaduno/postgres)
  (new in 0.3.0 — allocation is serialized under an advisory lock with a
  UNIQUE constraint as the backstop; its conformance suite is env-gated and
  runs against a live Postgres only in CI). With the memory store, run one
  revocation writer.

See [docs/SECURITY-MODEL.md](../../docs/SECURITY-MODEL.md) for the full guarantee/non-guarantee list.

## License

MIT
