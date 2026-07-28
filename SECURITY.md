# Vaduno security model

Vaduno is a **deterministic control + audit layer**, not a custody system. This
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

## What Vaduno defends against

| Threat | Defense |
|---|---|
| Agent tries to overspend | Per-transaction / rolling day-week-month caps, evaluated deterministically |
| Prompt-injected merchant swap | Merchant allowlist matched against the **URL host** when the pattern contains a dot (`openai.com`) — never the attacker-controlled `merchant.id`. A bare token without a dot matches `merchant.id` and is weak by construction; see limitation 3 |
| Forged `merchant.id` to impersonate an allowed host | Host patterns ignore `merchant.id` entirely; lookalikes and trailing-dot FQDNs are normalized out |
| Concurrent requests racing a limit | The decision→consume→execute→record section is serialized per guard (async mutex); limits are re-checked under the lock |
| Cap reset by rotating `agentId` | Rolling limits are **guard-wide** by default (agentId is not trusted to scope spend) |
| Overspend via a dropped/doctored audit write | Spend limits are enforced from an **in-memory authoritative counter** incremented under the lock the instant the executor succeeds — never from a read-back of the store. A lost `execution_result` write flags `auditDegraded` but cannot un-count the charge |
| Mandate replay (same signed mandate used twice) | Mandates are consume-once, claimed atomically in a `ConsumeStore` keyed on (mandateId, intentId), immediately before execution |
| Retry storm / duplicate orchestration hop double-charging | Runtime enforcement: the same (mandate, intent id) claims **one** use; every duplicate returns `replayed` with the original outcome and the executor never re-runs (the rail fires exactly once under N-way parallelism) |
| A used intent id reused for a *different* payment | The claim commits an `intentDigest` of amount+currency+merchant+rail; a mismatch is denied `MANDATE_REPLAY_MISMATCH` — never replayed, never executed |
| A mandate misapplied to a different task/merchant/agent | Optional context binding: `contextHash` must match the intent's context blob, and its `agentId`/`merchantId` fields must equal the intent (`CONTEXT_MISMATCH`) |
| Mandate replay across restart / second instance | `hydrateFromLedger()` rebuilds use-counts **and** the consume registry from a shared persistent ledger; a `FileConsumeStore` (or DB unique index) makes claims atomic across live processes |
| Field-value swap between check and execution (getter TOCTOU) | The intent is `structuredClone`d to a flat snapshot at entry; checks and the executor use that snapshot |
| Timezone-offset expiry bypass | All timestamps compared as epoch ms via `Date.parse`; unparseable = fail closed |
| Silent history tampering | Hash-chained ledger; `verify()` re-derives every hash; `verify(retainedHead)` also catches truncation/rewrite |
| Human-in-the-loop for large spends | `approval` thresholds; **fails closed** if no approval handler is configured |
| Emergency stop | `freeze()` denies everything and is re-checked inside the critical section |
| Compromised agent must be cut off mid-flight | `@vaduno/revocation`: revoking a mandate or an entire agent is checked inside the critical section **after** human approval, so a kill switch pulled while an approval is pending still wins. An unreachable registry denies (`REVOCATION_CHECK_FAILED`) — an outage never reads as "not revoked" |
| Un-revoking by tampering with a published status list | Status lists are Ed25519-signed with `validUntil` freshness and a monotonic version floor; a forged bitstring, a stale list, or a replayed pre-revocation snapshot all fail closed |

Every attempt — allowed, denied, approved, failed — is recorded. Denials and
failures are first-class evidence, not dropped.

## What Vaduno does NOT do (by design)

- **It never holds funds, private keys to funds, or the ability to move money.**
  Your executor moves money; Vaduno decides whether it may run and records the
  outcome. This is the deliberate line that keeps it out of money-transmitter
  scope. Do not put it in the money path.

## Known limitations (current version)

These are documented, not hidden. Some are scope choices; some are on the roadmap.

1. **Single live process for atomic guarantees.** The mutex (spend races) and
   the in-memory spend counter are atomic *within one process*. Two live
   processes sharing one ledger can still race on rolling **spend limits**
   unless the shared `SpendHistory` is backed by a transactional store. Run one
   guard process per trust boundary, or supply such a store. On restart,
   in-memory state starts empty — call `guard.hydrateFromLedger()` (restores
   spend counter + freeze state) and `MandateManager.hydrateFromLedger()`
   (restores consume-once + revocation state) to rebuild from the ledger, which
   trusts the ledger at startup as a documented boundary.
   - **Mandate consume-once IS cross-process safe** when you pass a shared
     `ConsumeStore`: `FileConsumeStore` (one box) or a DB store with a UNIQUE
     constraint enforce both per-intent idempotency and the `maxUses` budget
     atomically. The default `MemoryConsumeStore` is single-process only.
   - **`FileConsumeStore` residual:** its lock is advisory. A holder that
     STALLS past `staleMs` (default 30s) mid-write is treated as dead and can be
     reclaimed, briefly permitting two holders and a lost update. `staleMs` must
     exceed any real stall (a >30s stall means the process is effectively dead).
     For hard multi-**instance** guarantees use a transactional store whose
     UNIQUE/CHECK constraint spans the mandate budget.
   - **Revocation durability** rides on `hydrateFromLedger()` (rebuilt from
     `mandate_revoked` entries), not the `ConsumeStore`. If you skip hydration
     on restart, a revoked-but-unexpired mandate with uses left could be spent —
     always hydrate.
   - **Registry growth:** the consume registry keeps one record per distinct
     intent id forever (idempotent replay depends on it). An agent spraying
     unique ids grows it unbounded — cap upstream, or prune records for
     mandates already past `expiresAt` (a retry of an expired mandate is denied
     `EXPIRED`, not replayed, so pruning them is safe).
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
6. **Approval is blocking (but resolvable out-of-band).** The handler is awaited
   in-line (outside the mutex), so the agent process stays alive during a wait.
   `createQueuedApprovalHandler` + an `ApprovalStore` let a separate UI
   (e.g. the dashboard) list and resolve pending approvals; on timeout the
   handler fails closed (rejects).

## x402 rail adapter (`@vaduno/x402`)

The x402 adapter maps an untrusted, server-controlled 402 response onto a
PaymentIntent. Its threat model treats the **server as hostile** (it controls
every field of the payment requirement) and the **agent as possibly
prompt-injected** into calling arbitrary URLs. Guarantees:

- **The policed endpoint is the real one.** `merchant.url` is set from the URL
  the agent actually contacts, never the server's `resource` field. The server's
  claim is kept in `metadata.resourceClaimed` for audit only. By default a
  requirement whose `resource` origin differs from the request origin is refused
  (`requireResourceOriginMatch`, fail closed).
- **Host allowlist ≠ recipient control.** In x402 funds go to `payTo` (an
  address), decoupled from the request host. Constrain the recipient explicitly
  with an `id:<payTo>` merchant pattern; a host allowlist alone does not.
- **The token is pinned by the `assets` registry, not a label.** `extra.symbol`
  is attacker-controlled display text. Supply `assets: [{network, asset, symbol,
  decimals}]` so a requirement whose `(network, asset)` pair is unlisted is
  refused and the policy `currency` comes from your trusted symbol.
- **Pessimistic spend accounting.** Once the `X-PAYMENT` bearer authorization is
  transmitted, the spend is counted even if the server then returns an error —
  the server can still settle it. A payer that throws *before* transmitting is
  not counted. Bind a consume-once mandate to bound retries.
- **Vaduno still never holds keys.** `pay()` is your signer; it must sign for
  exactly the requirement it is handed. Vaduno polices the requirement, not the
  bytes you sign.

## Reporting

Found a bypass? Please open a private security advisory at
https://github.com/premsreelathasugeendran/vaduno/security/advisories/new rather than a public
issue. Concrete reproductions (the exact intent/interleaving) are most useful —
the test suite is organized around exactly these attack scenarios.
