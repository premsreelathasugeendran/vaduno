# Paygent security model

Paygent is a **deterministic control + audit layer**, not a custody system. This
document states what it defends against, what it assumes, and what it explicitly
does **not** yet cover — so you can decide whether it fits your threat model.

## Trust model

- **Trust root:** the human/organization that writes the `SpendPolicy` and holds
  the mandate signing key. Everything else is treated as potentially hostile.
- **Assumed hostile:** the AI agent (it may be prompt-injected and will craft
  arbitrary `PaymentIntent` fields, including `merchant.id`, `amount`, getters);
  the merchant/web page the agent read; and, for tamper-evidence, the ledger
  store itself.
- **Deterministic last line:** all allow/deny logic is pure code over integer
  minor units. No model output is ever trusted to enforce a limit.

## What Paygent defends against

| Threat | Defense |
|---|---|
| Agent tries to overspend | Per-transaction / rolling day-week-month caps, evaluated deterministically |
| Prompt-injected merchant swap | Merchant allowlist matched against the **URL host**, never the attacker-controlled `merchant.id` |
| Forged `merchant.id` to impersonate an allowed host | Host patterns ignore `merchant.id` entirely; lookalikes and trailing-dot FQDNs are normalized out |
| Concurrent requests racing a limit | The decision→consume→execute→record section is serialized per guard (async mutex); limits are re-checked under the lock |
| Cap reset by rotating `agentId` | Rolling limits are **guard-wide** by default (agentId is not trusted to scope spend) |
| Overspend via a dropped/doctored audit write | Spend limits are enforced from an **in-memory authoritative counter** incremented under the lock the instant the executor succeeds — never from a read-back of the store. A lost `execution_result` write flags `auditDegraded` but cannot un-count the charge |
| Mandate replay (same signed mandate used twice) | Mandates are consume-once, incremented atomically under a queue, immediately before execution |
| Mandate replay across restart / second instance | `hydrateFromLedger()` rebuilds use-counts from a shared persistent ledger |
| Field-value swap between check and execution (getter TOCTOU) | The intent is `structuredClone`d to a flat snapshot at entry; checks and the executor use that snapshot |
| Timezone-offset expiry bypass | All timestamps compared as epoch ms via `Date.parse`; unparseable = fail closed |
| Silent history tampering | Hash-chained ledger; `verify()` re-derives every hash; `verify(retainedHead)` also catches truncation/rewrite |
| Human-in-the-loop for large spends | `approval` thresholds; **fails closed** if no approval handler is configured |
| Emergency stop | `freeze()` denies everything and is re-checked inside the critical section |

Every attempt — allowed, denied, approved, failed — is recorded. Denials and
failures are first-class evidence, not dropped.

## What Paygent does NOT do (by design)

- **It never holds funds, private keys to funds, or the ability to move money.**
  Your executor moves money; Paygent decides whether it may run and records the
  outcome. This is the deliberate line that keeps it out of money-transmitter
  scope. Do not put it in the money path.

## Known limitations (current version)

These are documented, not hidden. Some are scope choices; some are on the roadmap.

1. **Single live process for atomic guarantees.** The mutex (spend races), the
   in-memory spend counter, and mandate consume-once are atomic *within one
   process*. Two live processes sharing one ledger can still race unless the
   shared store enforces a uniqueness constraint on `(mandateId, use)` and
   serializes spend. Run one guard process per trust boundary, or supply a
   `SpendHistory` backed by a transactional store. On restart, the in-memory
   spend counter starts empty — call `rehydrateSpendFromLedger()` (and
   `MandateManager.hydrateFromLedger()`) to restore state, which trusts the
   ledger at startup as a documented boundary.
2. **Ledger tamper-evidence needs external head retention to be complete.** A
   store that controls *all* rows can present an internally-consistent forged
   chain. `verify()` catches recompute-inconsistent tampering; to catch a
   wholesale rewrite/truncation you must retain `head()` out-of-band and pass it
   to `verify(head)`. Signed heads / external anchoring are roadmap.
3. **`merchant.id` matching is weak by construction.** `id:`/bare-token patterns
   match an attacker-controlled field; use **host patterns** for anything
   security-relevant. `id` patterns are for trusted, integrator-assigned ids.
4. **Node runtime only.** Uses `node:crypto`. No edge/workerd build yet.
5. **One policy per guard.** No per-agent multi-policy routing yet; run separate
   guards for separate policies.
6. **Approval is blocking.** No persisted/resumable out-of-band approval yet;
   the handler is awaited in-line (outside the mutex).

## Reporting

Found a bypass? Please open a private security advisory rather than a public
issue. Concrete reproductions (the exact intent/interleaving) are most useful —
the test suite is organized around exactly these attack scenarios.
