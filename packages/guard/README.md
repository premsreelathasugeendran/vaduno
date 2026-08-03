# @vaduno/guard

**A spend firewall and flight recorder for AI agents.**

Your agent has an API key that can spend real money. Research says it *will* eventually be tricked — in the [WASP benchmark](https://arxiv.org/abs/2504.18575), prompt-injection attacks against autonomous web agents *partially* succeed in **up to 86%** of cases. The model cannot be the last line of defense.

Vaduno puts deterministic code between your agent and the money:

```bash
npm install @vaduno/guard
```

Zero runtime dependencies. Node ≥ 18.

## 60-second example

```ts
import { VadunoGuard, AuditLedger, MemoryLedgerStore } from "@vaduno/guard";

const ledger = new AuditLedger(new MemoryLedgerStore());

const guard = new VadunoGuard({
  policy: {
    id: "shopper-policy", version: 1, currency: "USD",
    limits: { perTransactionMinor: 2_000, perDayMinor: 5_000 }, // $20/txn, $50/day
    merchants: { allow: ["openai.com", "anthropic.com", "aws.amazon.com"] },
    approval: { aboveMinor: 1_500 },                            // human sign-off at $15+
  },
  ledger,
  approvalHandler: async ({ intent }) => askHumanSomehow(intent),
});

const result = await guard.execute(
  {
    id: crypto.randomUUID(),
    agentId: "shopper-agent-1",
    merchant: { id: "openai", url: "https://api.openai.com" },
    amount: { amountMinor: 900, currency: "USD" },   // $9.00 — always integer minor units
    rail: "x402",
    requestedAt: new Date().toISOString(),
  },
  () => myPaymentClient.pay(...),   // your executor — Vaduno never touches the money
);

// result.status: "executed" | "denied" | "approval_rejected" | "failed" | "replayed"
await ledger.verify();  // { ok: true, entries: n } — or exactly where history was tampered
```

**Vaduno never holds funds, keys to funds, or the ability to move money.** It decides whether *your* executor function may run, and records everything. (Precisely: no custody, no card PANs, no wallet or bank credentials. It *does* use Ed25519 keys to sign and verify mandates — the private half belongs to whoever issues them, and a guard that only validates and consumes needs nothing but the public key.)

## What it enforces

| | |
|---|---|
| **Policy engine** | Per-transaction / rolling day-week-month caps, merchant & category allowlists, rail restrictions, velocity limits (scope-wide **and per-merchant**, layerable burst + sustained windows), approval thresholds. Pure code, no model in the loop. |
| **Signed mandates** | Ed25519 "permission slips" binding what a human authorized (amount, merchant, time window) to what executes. |
| **Runtime enforcement** | Consume-once is *enforced*, not just claimed: a retry storm firing the same payment N times runs the rail **at most once** and replays the original outcome. |
| **Context binding** | An optional context hash ties a mandate to one approved task run, so it can't be redirected by a different orchestration hop. |
| **Flight recorder** | Every attempt, decision, approval, and execution lands in a hash-chained, append-only ledger. Any edit, deletion, or reorder is detectable by `verify()`. |
| **Kill switch** | `guard.freeze()` denies everything on **this guard instance** instantly — the deny flag flips before the first await, takes no lock (safe to await even from inside an executor or `revocationCheck`), and is re-checked at a last exit before the final `execution_started` audit write, on both the `execute()` and `authorize()` paths. A freeze landing before that last exit stops the payment; one landing after it — a blind window of that one audit write plus a scheduler tick — cannot, and a payment already handed to the rail (or an authorization already returned to the caller) is never recalled: that would require the control over funds Vaduno must never hold. The freeze itself is audited; if that write fails the freeze stays enforced locally and `isFreezeDegraded()` reports it would not survive a restart. Per-process: a peer process keeps spending until frozen too. For a freeze every process observes, wire a shared `FreezeStore` from `@vaduno/revocation` into `revocationCheck` via `createFreezeCheck(store)` — a store freeze then denies every wired process's next authorization, an epoch-fenced compare-and-set unfreeze refuses stale lifts, and an unreachable store denies every payment on every wired guard (fail closed — a deliberate total stop). The two are independent: a local `freeze()` does not write the store, and a store unfreeze does not clear a local flag. |

## Runtime enforcement in one snippet

Signing a mandate proves it was *issued*; it does nothing to stop that valid mandate being executed twice by a retry loop or raced by two workers.

```ts
const results = await Promise.all(
  Array.from({ length: 6 }, () => guard.execute(sameIntent, payOnce)),
);
// rail ran at most once → 1 "executed" + 5 "replayed", never a double charge.
```

- `status: "replayed"` carries the original outcome (`executed` / `failed` / `unresolved`); the executor does **not** run again.
- A used intent id presented with **different money fields** is denied `MANDATE_REPLAY_MISMATCH` — an id-reuse attack, not a retry.
- Cross-process safety needs a shared `ConsumeStore` — [`FileConsumeStore`](https://www.npmjs.com/package/@vaduno/guard) on one box, [`PostgresConsumeStore`](https://www.npmjs.com/package/@vaduno/postgres) for multiple instances.
- **Rolling spend caps need a shared limiter too.** The default is in-memory and per-instance, so two guard processes each enforcing a $50/day cap let $100 through. Pass `FileSpendLimiter` (one box) or `PostgresSpendLimiter` (multiple instances) and the cap holds — `reserve()` evaluates every window and records the reservation as one atomic step, so there is no read-then-write gap to race. See [SECURITY.md](https://github.com/premsreelathasugeendran/vaduno/blob/master/SECURITY.md).
- **Caps are scoped to `policy.id`, never to `intent.agentId`.** The threat model assumes the agent controls every field of the intent, so a cap keyed on `agentId` would let a compromised agent mint a fresh budget by changing one string — which it did, in 0.2.0. If you want per-agent budgets, run one guard (and one policy id) per agent rather than trusting the intent.
- **A failed execution keeps its spend counted.** A thrown executor may still have moved money — a timeout after the charge landed is indistinguishable from a clean failure — so the amount stays held. Call `guard.releaseSpend(intentId)` only when you can prove the rail did not charge; it cannot un-count a successful execution.

## Velocity controls: transaction-count windows

The count analogue of Visa Transaction Controls velocity/transaction-count rules, Visa card-testing burst detection, and Mastercard In Control frequency controls — enforced deterministically at **one deployment** (this guard and whatever stores it shares), not network-side.

```ts
velocity: {
  // Scope-wide. One limit, or several that are ALL enforced — a burst window
  // AND a sustained window. Denies VELOCITY_EXCEEDED.
  maxTransactions: [
    { count: 10, perSeconds: 60 },
    { count: 100, perSeconds: 86_400 },
  ],
  // Per merchant. Denies MERCHANT_VELOCITY_EXCEEDED. Merchant identity is
  // merchantKeyOf(merchant): the URL host when present ("host:api.stripe.com"),
  // else "id:" + the trimmed lowercased id — two disjoint prefix families, so
  // an id crafted to look like a host cannot collide with a real one.
  maxTransactionsPerMerchant: { count: 5, perSeconds: 3_600 },
},
```

- **Counts ride the same atomic `reserve()` as amounts** — same critical section, same cross-process stores (`FileSpendLimiter`, `PostgresSpendLimiter`), so parallel workers cannot jointly exceed a count window. A denial consumes no slot and never burns a mandate use; a retry of the same intent id consumes no extra slot; a failed execution keeps its slot (burn-on-failure, same rule as amounts); `releaseSpend()` frees a slot only while it is provably unspent — a committed slot never frees.
- **Per-merchant velocity alone is NOT a security boundary** — merchant fields are attacker-controlled and rotation mints fresh per-merchant budgets. It is a tightening layered UNDER global count windows (which are rotation-proof) and the allowlist. Scope stays `policy.id`, so agentId rotation mints no count budget.
- **Malformed window config fails closed.** A window that cannot enforce (`count: NaN`, `perSeconds: 0`, a zero or non-integer count, a window with neither cap nor count) denies everything under the policy with `SPEND_WINDOW_INVALID`: corrupting config is a DoS the operator notices, never an uncapped budget.
- **No velocity-free upgrade interval.** Spend records written before merchant attribution existed carry no merchant key and count toward *every* merchant window until they age out — bounded over-hold instead of a blind spot.
- **Set `merchant.url` consistently, or one merchant gets two budgets.** Merchant identity is derived as the URL host when a URL is present and the merchant id otherwise, and the two forms are deliberately disjoint so an attacker cannot craft an id that collides with a host. The honest-integrator cost is that the *same* merchant sent sometimes with a URL and sometimes without counts as two separate per-merchant budgets.
- **An empty `maxTransactions: []` enforces nothing** — it produces no windows and is identical to omitting the field. It is not an error and it is not a limit of zero; if you mean "no transactions", the policy already has better tools.

## Design principles

1. **Fail closed.** No approval handler? Approval-needing intents are denied. Internal error? Denied and audited. Unknown mandate? Denied.
2. **Deterministic last line.** An attacker is assumed to control the agent and every field of the intent. Policy checks are pure code over integer minor units.
3. **Amounts are integers.** Minor units (cents, paise) everywhere. Floats are denied, not rounded.
4. **Everything is evidence.** Denials and failures are recorded as thoroughly as successes.
5. **Not in the money path.** No custody, no keys to funds, no transmission.

## The rest of the stack

| Package | What |
|---|---|
| [`@vaduno/x402`](https://www.npmjs.com/package/@vaduno/x402) | Governs Coinbase x402 HTTP-402 stablecoin payments |
| [`@vaduno/stripe`](https://www.npmjs.com/package/@vaduno/stripe) | Makes the guard the real-time authorization brain for Stripe Issuing cards |
| [`@vaduno/transparency`](https://www.npmjs.com/package/@vaduno/transparency) | RFC 9162 Merkle transparency log + C2SP witness cosigning |
| [`@vaduno/revocation`](https://www.npmjs.com/package/@vaduno/revocation) | Enforced kill switch + W3C Bitstring Status Lists |
| [`@vaduno/postgres`](https://www.npmjs.com/package/@vaduno/postgres) | Spend caps + consume-once that hold across **multiple instances** |

## Security

Read [SECURITY.md](https://github.com/premsreelathasugeendran/vaduno/blob/master/SECURITY.md) for the threat model, what this defends against, and the **known limitations** — they are documented, not hidden.

Report vulnerabilities via [GitHub Security Advisories](https://github.com/premsreelathasugeendran/vaduno/security/advisories/new).

## License

MIT
