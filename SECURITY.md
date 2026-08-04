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
| Concurrent requests racing a limit | The decision→**reserve**→consume→execute→commit section is serialized per guard (async mutex), and the cap itself is enforced INSIDE the atomic reserve rather than by a re-check under the lock — a re-check is still check-then-act across processes. The mutex orders one process; `SpendLimiter.reserve()` is what holds across them |
| Cap reset by rotating `agentId` | Reservations are scoped to the **policy id**, set by the operator — never `intent.agentId`, which the agent controls. **This row was FALSE in 0.2.0:** the limiter keyed on `agentId`, so two guards sharing one limiter passed $100 through a $50 cap by rotating it. Fixed in 0.2.1; regression test in `test/cap-bypass.test.ts` |
| Overspend via a dropped/doctored audit write | Spend limits are enforced from **authoritative in-memory state**, never from a read-back of the store: `execute()` increments its counter under the lock the instant the executor succeeds, and a two-phase `authorize()` spend counts from the moment its budget is reserved in the limiter. A lost `execution_result` write — on either path — flags `auditDegraded` but cannot un-count the charge |
| Mandate replay (same signed mandate used twice) | Mandates are consume-once, claimed atomically in a `ConsumeStore` keyed on (mandateId, intentId), immediately before execution |
| Retry storm / duplicate orchestration hop double-charging | Runtime enforcement: the same (mandate, intent id) claims **one** use; every duplicate returns `replayed` with the original outcome and the executor never re-runs (the rail fires **at most** once under N-way parallelism — zero times if the intent is denied or the executor never runs) |
| A used intent id reused for a *different* payment | The claim commits an `intentDigest` of amount+currency+merchant+rail; a mismatch is denied `MANDATE_REPLAY_MISMATCH` — never replayed, never executed |
| A mandate misapplied to a different task/merchant/agent | Optional context binding: `contextHash` must match the intent's context blob, and its `agentId`/`merchantId` fields must equal the intent (`CONTEXT_MISMATCH`) |
| Mandate replay across restart / second instance | `hydrateFromLedger()` rebuilds use-counts **and** the consume registry from a shared persistent ledger; a `FileConsumeStore` (or DB unique index) makes claims atomic across live processes |
| Field-value swap between check and execution (getter TOCTOU) | The intent is `structuredClone`d to a flat snapshot at entry; checks and the executor use that snapshot |
| Timezone-offset expiry bypass | All timestamps compared as epoch ms via `Date.parse`; unparseable = fail closed |
| Silent history tampering | Hash-chained ledger; `verify()` re-derives every hash; `verify(retainedHead)` also catches truncation/rewrite |
| Human-in-the-loop for large spends | `approval` thresholds; **fails closed** if no approval handler is configured |
| Emergency stop | `freeze()` flips its deny flag synchronously and takes no lock, so it is safe to call — and await — from anywhere, including inside an executor or `revocationCheck`. The flag is re-checked inside the critical section: at entry and again at a last exit before the final `execution_started` audit write, on both the `execute()` and `authorize()` paths. A freeze landing before that last exit denies the payment (a mandate use already consumed by it stays burned: over-hold, never overspend); one landing after it — a blind window of that one audit write plus a scheduler tick — cannot stop that payment, and money already handed to the rail (or an authorization already handed back to the caller) is never recalled: recalling in-flight money would require the control over funds Vaduno must never hold. A freeze whose `guard_frozen` write fails stays enforced locally and flags `isFreezeDegraded()` — it would not survive a restart. The LOCAL flag is per-process; for a freeze every process observes, wire a shared `FreezeStore` via `createFreezeCheck` — see Known Limits item 2 for exactly what each half covers |
| An operator freeze must stop OTHER live processes, not just the one it was issued in | A shared `FreezeStore` (one global row `{epoch, frozen, reason, by, at}` — `MemoryFreezeStore`/`FileFreezeStore` in `@vaduno/revocation`, `PostgresFreezeStore` in `@vaduno/postgres`) consulted on every authorization via `createFreezeCheck(store)` on the `revocationCheck` seam — inside the critical section, after human approval, immediately before the budget reservation. Freezing the store denies every wired process's VERY NEXT authorization; no push, no poll loop, no restart. `unfreeze(expectedEpoch)` is a compare-and-set: every freeze bumps a monotonic epoch, and a stale fence is refused without changing anything, so an operator cannot lift a re-freeze they never saw. Fail closed, loudly: an UNREACHABLE freeze store denies EVERY payment on every wired guard (`FREEZE_CHECK_FAILED`) — a deliberate total stop, which makes the store a hard availability dependency for all payments (see Known Limits item 2). A freeze only denies NEW authorizations: it does not recall in-flight money, and it deliberately does not gate `settle()` — settle records an outcome that already happened, and blocking it would destroy the record of real money rather than prevent any |
| Compromised agent must be cut off mid-flight | `@vaduno/revocation`: revoking a mandate or an entire agent is checked inside the critical section **after** human approval, so a kill switch pulled while an approval is pending still wins. An unreachable registry denies (`REVOCATION_CHECK_FAILED`) — an outage never reads as "not revoked" |
| In-policy but anomalous spend from a compromised agent (odd hours, novel merchants, amount spikes, policy-probing deny streaks) | Opt-in deterministic risk scorecard (`risk: new RiskScorecard(...)`): eight ledger-derived signals score every intent that passes policy — a preliminary pass outside the mutex and, for intents still headed for execution, a final re-evaluation inside the critical section (concurrent commits move the signals). Elevated scores route to the human approval branch (`RISK_STEPUP`); high scores deny (`RISK_DENY`) **before** any budget reservation or mandate consumption, and an approval can never override the deny; an `autoFreeze` threshold additionally stops the process (manual `unfreeze()` only, per-process scope — see Known Limits item 9). The merge is tighten-only (allow < require_approval < deny), so risk can never loosen a policy decision; unscorable = `RISK_UNSCORABLE` deny; every assessment is a hard `risk_scored` ledger entry carrying a head anchor that makes it reproducible bit-for-bit **given the same scorecard config and policy** (the entry records the config's hash, not the config; the policy is not ledgered) |
| Un-revoking by tampering with a published status list | Status lists are Ed25519-signed with `validUntil` freshness and a monotonic version floor; a forged bitstring, a stale list, or a replayed pre-revocation snapshot all fail closed |
| Archival evidence rejected for being old | Cosignature verification is temporal-precedence-based: NO staleness bound by default (a witness attestation "seen no later than T" does not decay), future-skew rejection retained; `maxAgeSeconds` is an opt-in liveness check and `Infinity` spells "unbounded" explicitly |
| A future adversary who can forge Ed25519 ("2026" signatures verified after ECC's 2030/2035 NIST sunset) | Hybrid (v2) mandates carry an ML-DSA-44 (FIPS 204) signature alongside Ed25519 over the same payload, and the transparency log accepts C2SP 0x06 ML-DSA-44 witness cosignatures, where the runtime supports them (runtime probe: Node >= 24.7 built against OpenSSL >= 3.5). **The classical signatures remain exposed post-CRQC unless the verifier sets `requireAlgs: ["ML-DSA-44"]`** — absent that, an attacker mints a fresh v1 under any registered Ed25519 kid; both the attack and the remedy are pinned as tests. `assessCheckpointAnchor` labels checkpoint anchoring (`witnessed-pq` only from verified 0x06 quorums, `witnessedAt` scoped to that strength so a backdated forged classical cosignature cannot move it). See `docs/SECURITY-MODEL.md`, post-quantum posture |

Every attempt — allowed, denied, approved, failed — is recorded. Denials and
failures are first-class evidence, not dropped.

## What Vaduno does NOT do (by design)

- **It never holds funds, private keys to funds, or the ability to move money.**
  Your executor moves money; Vaduno decides whether it may run and records the
  outcome. This is the deliberate line that keeps it out of money-transmitter
  scope. Do not put it in the money path.

## Known limitations (current version)

These are documented, not hidden. Some are scope choices; some are on the roadmap.

1. **Atomic guarantees are only as wide as the store you supply.** Both
   consume-once and rolling spend caps hold across processes — but only when
   you pass a shared implementation. The defaults are in-memory and therefore
   single-process, so two guard processes each enforcing a $50/day cap will let
   $100 through. Run one guard per trust boundary, or supply a shared store:
   `FileSpendLimiter` / `FileConsumeStore` for several processes on one box,
   `PostgresSpendLimiter` / `PostgresConsumeStore` for multiple instances.
   `npm run demo:cross-process` demonstrates both outcomes with two real OS
   processes. On restart, in-memory state starts empty — call
   `guard.hydrateFromLedger()` (spend counter + freeze state) and
   `MandateManager.hydrateFromLedger()` (consume-once + revocation state) to
   rebuild from the ledger, which trusts the ledger at startup as a documented
   boundary. `guard.hydrateFromLedger()` returns a `HydrateReport`; a nonzero
   `skippedUnparseableSpendRows` means rows claiming successful charges could
   not be restored into the caps (e.g. rows written by a pre-0.3.0
   `settle()`, which carried no amount) — reconcile before trusting the
   restored totals. A hydrate that fails verification throws without restoring
   anything, and the guard then denies every intent (`HYDRATION_REQUIRED`) by
   default until a retry succeeds — serving after a failed hydrate with the
   instance's fresh, EMPTY state (no freeze, zero counted spend) would be the
   *permissive* direction. A restart that never attempts hydrate still starts
   open; restart-over-a-ledger deployments should pass `requireHydration:
   true` to the guard to close that gap too.
   - **Why a shared store alone is not sufficient** (fixed in 0.2.0): the spend
     interface used to be a read-only `totalsSince()`, which can only support
     check-then-act. Two instances both read `$0`, both pass the check, both
     spend. Backing *that* with Postgres would not have helped — the race is in
     the gap between the read and the append. `SpendLimiter.reserve()` now
     evaluates every window and records the reservation as ONE atomic step. A
     limiter that reads totals and then inserts has reintroduced the bug, which
     is what the conformance suite exists to catch.
   - **A failed execution keeps its spend counted.** A thrown executor may
     still have moved money — a timeout after the charge landed is
     indistinguishable from a clean failure — so the reservation stays held
     rather than freeing the budget. Otherwise an executor that times out
     post-charge could be retried past any cap. Call `guard.releaseSpend(intentId)`
     only when you can prove the rail did not charge; it cannot un-count a
     successful execution.
   - **Mandate consume-once IS cross-process safe** when you pass a shared
     `ConsumeStore`: `FileConsumeStore` (one box) or `PostgresConsumeStore`
     (multi-instance) enforce both per-intent idempotency and the `maxUses`
     budget atomically. The default `MemoryConsumeStore` is single-process only.
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
   - **Registry growth is now prunable, with one sharp edge.** The consume
     registry keeps a record per distinct intent id (idempotent replay depends
     on it) and the spend table keeps every reservation, so an agent spraying
     unique ids grows both. Since 0.3.0 both interfaces expose a prune:
     - `SpendLimiter.pruneBefore(beforeMs)` is safe with no extra condition — a
       reservation outside every rolling window already contributes nothing to
       any cap. Pass a cutoff older than your widest window.
     - `ConsumeStore.pruneMandates(ids)` takes the ids from YOU, deliberately.
       Pruning a claim re-arms that intent id: a retry stops replaying and
       **can execute again**. It is only safe once the mandate is dead by
       another check — past `expiresAt`, where a retry is denied `EXPIRED`
       before consume-once is consulted. A `pruneBefore(timestamp)` here would
       be easier to call and would silently re-arm live mandates, which is why
       it does not exist. The conformance suite pins the re-arm behaviour as a
       test so nobody adds one.

     Before 0.3.0 this section told operators to prune through an API that did
     not exist.

2. **`guard.freeze()` — the LOCAL flag — is PER-PROCESS; the cross-process
   freeze is a separate, opt-in wiring.** Since 0.3.0 there are two halves,
   and they are independent by design:
   - **Local:** `guard.freeze()` is an in-memory field on the guard instance
     (`private frozen`). Freezing one process does **not** stop another live
     process — peers keep spending until each is frozen or restarted. That
     was the whole kill switch before 0.3.0, and it was undocumented — the
     worst combination: an operator pulls the switch, sees it take effect
     locally, and reasonably concludes spending has stopped. Everything
     documented about it still holds: `hydrateFromLedger()` restores freeze
     state at STARTUP from the ledger (a restart that never hydrates starts
     UNFROZEN — an attempted-and-failed hydrate denies until a retry
     succeeds, and `requireHydration: true` covers the restart that never
     attempts one), and a freeze whose `guard_frozen` append failed was never
     durable — the live process keeps enforcing it and reports
     `isFreezeDegraded()`, but a restart would forget it.
   - **Cross-process (new in 0.3.0):** wire a shared
     [`FreezeStore`](packages/revocation) into every guard via
     `revocationCheck: createFreezeCheck(store)` (compose with `allChecks`
     where a revocation registry is also in play). A `store.freeze(reason)`
     then denies every wired process's VERY NEXT authorization
     (`GUARD_FROZEN`, carrying the reason) — checked inside the critical
     section, after human approval, before the budget reservation.
     `unfreeze(expectedEpoch)` is epoch-fenced compare-and-set: a stale fence
     is refused and changes nothing, so nobody lifts a re-freeze they never
     evaluated. Backends: `MemoryFreezeStore` (one process — reference
     semantics), `FileFreezeStore` (several processes on one box; same
     advisory `FileMutex` and `staleMs` residual as the other file stores),
     `PostgresFreezeStore` (multi-instance; the compare-and-set is
     `UPDATE … WHERE epoch = $expected`). Honest evidence status: Memory and
     File are exercised by the freeze conformance suite on every test run;
     the Postgres backend's suite is env-gated on
     `VADUNO_TEST_POSTGRES_URL` and has NOT been exercised against a live
     database on the machine this was developed on — its live evidence is
     whatever the CI postgres job reports for the commit you install.
   - **What stays true either way:** the two halves do not write each other.
     A local `guard.freeze()` does not touch the shared store, and a store
     `unfreeze()` cannot clear a peer's local flag — an operator who wants
     both issues both. A freeze (either kind) only denies NEW authorizations:
     it never recalls a payment already handed to the rail, and it does not
     gate `settle()` — blocking settlement would erase the record of money
     that already moved.
   - **AVAILABILITY COST, stated loudly:** because the freeze check fails
     closed, an UNREACHABLE freeze store denies EVERY payment on every wired
     guard — a total stop. That is the correct posture for a spend firewall
     ("no money moves" is the recoverable direction, and it matches the
     revocation registry's stance), but it means the freeze store is a HARD
     AVAILABILITY DEPENDENCY for all payments the moment you wire it. Deploy
     it like one. There is deliberately no negative cache and no fail-open
     mode — a cached "not frozen" served during an outage is precisely how an
     attacker who can down the backend would disable the kill switch.

3. **Concurrent ledger writers hold since 0.3.0 — within each store's stated
   residual.** Before 0.3.0, `AuditLedger.append` derived `seq = last.seq + 1`
   inside a promise queue scoped to one **AuditLedger instance**, so two
   instances (one process or two) both read seq N and both wrote N+1 —
   Memory/Jsonl forked the chain and an honest system self-reported as
   tampered, while Supabase's `seq bigint primary key` rejected the loser and
   the rejection was swallowed into `auditDegraded`: money moved, the record
   was DROPPED, and `verify()` stayed green. `LedgerStore` is now
   compare-and-append: a store admits an entry only if it still extends the
   tip the writer chained onto; a loser is handed the real tip, re-chains, and
   retries (bounded — exhaustion fails CLOSED as `AUDIT_WRITE_FAILED` /
   `auditDegraded`, never as a fork or a silent drop). The mechanism is per
   store: `MemoryLedgerStore` compares and pushes in one synchronous body;
   `JsonlLedgerStore` re-reads the tip under the same `FileMutex` lockfile the
   other file stores share (same residual as `FileConsumeStore` above: a
   holder stalled past `staleMs`, default 30s, is reclaimed — briefly two
   holders), proven in-repo by two real OS processes appending overlapping
   bursts to one file; `SupabaseLedgerStore` and `PostgresLedgerStore`
   (`@vaduno/postgres`, new) rest on `seq bigint primary key` +
   `unique (prev_hash)` — one row per position, one child per parent — which
   make a fork unrepresentable at the database even to a buggy or hostile
   client, and the loser's SQLSTATE 23505 is classified as contention and
   retried, not dropped. Supabase requires the 0.3.0 `supabase/schema.sql`
   (the `prev_hash` unique index is new). A `LedgerStore` built against the
   pre-0.3.0 interface is REFUSED at runtime — its unchecked bare append is
   exactly the fork bug — but a pre-0.3.0 writer *process* on the same store
   is outside this guard's reach: upgrade every writer together.
   **Scope of the proof, exactly:** Memory and Jsonl are exercised against the
   real stores, Jsonl by two real OS processes. The database-backed stores
   rest on constraint atomicity that is Postgres's guarantee rather than this
   code's. `SupabaseLedgerStore` is exercised only against a schema-faithful
   in-repo fake. `PostgresLedgerStore`'s conformance suite runs against a real
   Postgres 16 in the CI job, but it is env-gated and skips everywhere else —
   so as of this release its live evidence is whatever that CI job last
   reported, and nothing more. Check it is green for the commit you install.

4. **Ledger tamper-evidence needs external head retention to be complete.** A
   store that controls *all* rows can present an internally-consistent forged
   chain. `verify()` catches recompute-inconsistent tampering; to catch a
   wholesale rewrite/truncation you must retain `head()` out-of-band and pass it
   to `verify(head)`. Signed heads / external anchoring are roadmap.
5. **`merchant.id` matching is weak by construction.** `id:`/bare-token patterns
   match an attacker-controlled field; use **host patterns** for anything
   security-relevant. `id` patterns are for trusted, integrator-assigned ids.
6. **Node runtime only.** Uses `node:crypto`. No edge/workerd build yet.
7. **One policy per guard.** No per-agent multi-policy routing yet; run separate
   guards for separate policies.
8. **Approval is blocking (but resolvable out-of-band).** The handler is awaited
   in-line (outside the mutex), so the agent process stays alive during a wait.
   `createQueuedApprovalHandler` + an `ApprovalStore` let a separate UI
   (e.g. the dashboard) list and resolve pending approvals; on timeout the
   handler fails closed (rejects).
9. **The risk scorecard sees ONE deployment's ledger, never network-scale
   data.** Visa Advanced Authorization and Mastercard Decision Intelligence
   score against signals aggregated across an entire card network; this
   scorecard scores against exactly what this deployment's ledger recorded.
   That is the deliberate trade for determinism and bit-for-bit
   reproducibility, not an oversight — and it means the scorecard cannot know
   what it never saw. The 3DS2 comparison is MECHANISM-ONLY: real 3DS2
   risk-based authentication carries an issuer LIABILITY SHIFT, and nothing
   here confers any liability property to anyone. What holds structurally:
   - **Merchant identity authority remains the allowlist.** The
     merchant-keyed signals (`FIRST_SEEN_MERCHANT`,
     `AMOUNT_ABOVE_MERCHANT_TYPICAL`) key on `merchantKeyOf()` over
     attacker-controlled fields, so merchant rotation mints "unfamiliar"
     merchants — which RAISES the unfamiliarity signal and gates off the
     typical-amount baseline. That asymmetry is safe only because risk is a
     TIGHTENING: weights are validated positive, the merge is tighten-only,
     and no signal combination can turn a policy deny (or the allowlist)
     into an allow. Risk is defense-in-depth, NEVER an allow authority.
   - **One documented score suppression:** `intent.mandateId` is
     attacker-controlled, and omitting it suppresses exactly
     `FIRST_USE_OF_MANDATE`'s weight when the guard does not
     `requireMandate` (with `requireMandate: true` a mandate-less intent is
     denied before risk runs). The field-invariance property test excludes
     mandateId for precisely this reason.
   - **`DENY_STREAK` counts the scorecard's own denials, so it
     self-amplifies.** The streak is every `policy_decision` deny in the
     window, including `RISK_DENY`, `RISK_UNSCORABLE` and
     `RISK_STEPUP_UNAPPROVED` — so a high score makes the next score higher.
     Tighten-only, never an allow, but combined with `autoFreeze` a run of
     ordinary unrelated denials (a stale merchant allowlist, a currency
     mismatch) can cascade into freezing the process. Tune `minDenies`
     against your deployment's normal denial rate, not against the attack.
   - **`autoFreeze` inherits the LOCAL freeze's per-process scope** (item 2):
     it denies the triggering intent, then flips this process's freeze flag —
     it does not stop a live peer, and it deliberately does not write the
     cross-process `FreezeStore` (which stays separate, operator-wired via
     `createFreezeCheck`). Manual `unfreeze()` is the only way back.
   - **No score is learned.** Out-of-hours windows are config-declared, the
     baselines are medians over the ledger, and the same intent scored over
     the same anchored prefix at the same clock reading yields the same
     assessment, always.

10. **Post-quantum readiness is partial, and the words are chosen
    precisely.** The hash chain and Merkle tree are SHA-256 and remain
    adequate against a quantum adversary (Grover halves the bits; 128-bit
    preimage resistance remains). The signatures are the exposed surface:
    hybrid v2 mandates and 0x06 witness cosignatures add ML-DSA-44 alongside
    Ed25519 **where the runtime supports it** — this machine class (Node <
    24.7 or OpenSSL < 3.5) cannot sign or verify ML-DSA at all, and the
    runtime probe (`mlDsa44Available()`), never a version string, decides.
    Ed25519 signatures remain forgeable by a future CRQC unless verifiers
    set `requireAlgs`; a v2 verified where ML-DSA cannot be checked rests on
    its classical signature (v1-equivalent standing). Key ids are 64-bit
    truncated hashes: lookup binds (algorithm, kid) so collisions cannot
    cross families, but the within-family truncation residual exists
    (~2^32 birthday between attacker-chosen keys). Nothing here is called
    "quantum-safe"; the release gate rejects that phrase.

## x402 rail adapter (`@vaduno/x402`)

The x402 adapter maps an untrusted, server-controlled 402 response onto a
PaymentIntent. Its threat model treats the **server as hostile** (it controls
every field of the payment requirement) and the **agent as possibly
prompt-injected** into calling arbitrary URLs. It speaks x402 v1 (body-carried)
and, opt-in, v2 (header-carried); neither has ever run against a live x402
server. Guarantees:

- **The policed endpoint is the real one.** `merchant.url` is set from the URL
  the agent actually contacts, never the server's claim (v1: per-requirement
  `resource`; v2: body-level `resource.url`). The claim is kept in
  `metadata.resourceClaimed` for audit only. By default a claim whose origin
  differs from the request origin is refused (`requireResourceOriginMatch`,
  fail closed).
- **Host allowlist ≠ recipient control.** In x402 funds go to `payTo`,
  decoupled from the request host. Constrain the recipient explicitly with an
  `id:<payTo>` merchant pattern; a host allowlist alone does not. v2 permits
  `payTo` to be a role constant (e.g. `"merchant"`) resolved out of band —
  refused by default (`PAYTO_ROLE_REFUSED`) when it matches `^[a-z]{1,16}$` —
  a SHAPE HEURISTIC, not a role list, so `MERCHANT` or `merchant_wallet` are
  treated as addresses — because an unresolvable recipient
  cannot be allowlisted; admitting one via `v2.allowPayToRoles` delegates
  recipient policing to whoever resolves the role.
- **The token is pinned by the `assets` registry, not a label.** `extra.symbol`
  is attacker-controlled display text. Supply `assets: [{network, asset, symbol,
  decimals}]` so a requirement whose `(network, asset)` pair is unlisted is
  refused and the policy `currency` comes from your trusted symbol. v1 network
  names and v2 CAIP-2 ids are separate key spaces (an entry for `base` does not
  trust `eip155:8453`); v2 matching is case-sensitive, with the asset
  case-folded only on `eip155:` (EVM hex) networks.
- **Pessimistic spend accounting.** Once the bearer authorization is
  transmitted (`X-PAYMENT` in v1, `PAYMENT-SIGNATURE` in v2), the spend is
  counted even if the server then returns an error — the server can still
  settle it. A payer that throws *before* transmitting is not counted. Under
  v2's `upto` scheme the counted amount is the authorized MAXIMUM; the settled
  amount an untrusted `PAYMENT-RESPONSE` later reports is never reconciled
  downward. Bind a consume-once mandate to bound retries. The v2 schemes ANALYSED for this work — `exact` (single-use by
  EIP-3009 nonce) and `upto` (settles at most once) — carry no sessions and
  no reusable authorizations, so per-authorization counting matches them
  exactly. A `batch-settlement` scheme also exists in the spec tree and was
  **not** analysed; it describes a signed running total redeemed at session
  end. Counting stays CONSERVATIVE under it rather than complete: every
  transmitted signature is counted at its stated amount, so a batch would be
  over-counted, never under. This is not a survey of every scheme the spec
  may define.
- **One carrier, one reading.** The `x402Version` discriminant is total —
  exactly two values are ACCEPTED on the v1 body carrier (absent, for
  back-compat with v1 servers in the wild, and the integer 1), and every
  other value including `"2"`, `1.5`, `0` and negative integers has a
  defined refusal, none coerced to 1 — and version routing is single-carrier: a
  `PAYMENT-REQUIRED` header means v2 and the body is never read; `x402Version:
  2` inside a JSON body is refused; v1 money/binding fields inside a v2
  requirement are refused as mixed-version shapes. The requirement the guard
  validates is the identical fixed-allowlist object handed to the payer. The
  full decision table is frozen in `spec/vectors/x402-http-v{1,2}.json`.
- **Vaduno still never holds keys to funds.** `pay()` / `v2.pay()` is your
  signer; it must sign for exactly the requirement it is handed (and in v2,
  echo exactly that requirement as the payload's `accepted`). Vaduno polices
  the requirement, not the bytes you sign — that includes any sign-in-with-x
  identity signature, which is likewise the host signer's operation. (Mandate
  signing uses a separate Ed25519 key that belongs to the *issuer* and cannot
  move money; a guard that only validates and consumes needs nothing but the
  public half.)

## Dependency posture

`@vaduno/guard` has **zero runtime dependencies** — deliberately, because it is
the package that sits between an agent and real money. The other six published
packages depend only on `@vaduno/*` and, for `@vaduno/stripe`, a `stripe`
*peer* dependency you supply. CI asserts this on every push: a published package
gaining any third-party runtime dependency fails the build, because an
installing user receiving no third-party code is what makes this supply chain
auditable by reading it.

Open advisories therefore live entirely in dev tooling and in `apps/dashboard`,
which is **not published to npm**:

- `next` → `sharp` (libvips CVEs). Next 15 pins `sharp@^0.34.3` and the fix is
  in 0.35.x, so an override cannot satisfy both; clearing it needs a Next 16
  migration of the demo dashboard. The dashboard does not use `next/image`, and
  nothing in the published packages links against `sharp`.
- `vite` / `esbuild` — dev-server advisories reachable only when a dev server is
  running and a hostile page is open in the same browser. Neither ships.
- `postcss` (GHSA-fxqj-rqcc-2cmp, sourceMappingURL reads arbitrary `.map` files
  when `from` is unset) — a transitive of the dashboard's Tailwind/Next
  toolchain, exercised only at build time on a developer's own machine. Note
  that the `overrides` entry pinning `postcss` in the root `package.json` does
  **not** currently take effect: npm records no `overrides` in the lockfile for
  this workspace layout, so treat that entry as intent rather than enforcement,
  and verify the resolved version before relying on it.

If an advisory ever lands in a published package's runtime dependency graph,
that is a genuine security issue for this project — report it privately.

## Reporting

Found a bypass? Please open a private security advisory at
https://github.com/premsreelathasugeendran/vaduno/security/advisories/new rather than a public
issue. Concrete reproductions (the exact intent/interleaving) are most useful —
the test suite is organized around exactly these attack scenarios.
