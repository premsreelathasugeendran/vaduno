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
| **Policy engine** | Per-transaction / rolling day-week-month caps, merchant & category allowlists, rail restrictions, velocity limits, approval thresholds. Pure code, no model in the loop. |
| **Signed mandates** | Ed25519 "permission slips" binding what a human authorized (amount, merchant, time window) to what executes. |
| **Runtime enforcement** | Consume-once is *enforced*, not just claimed: a retry storm firing the same payment N times runs the rail **at most once** and replays the original outcome. |
| **Context binding** | An optional context hash ties a mandate to one approved task run, so it can't be redirected by a different orchestration hop. |
| **Flight recorder** | Every attempt, decision, approval, and execution lands in a hash-chained, append-only ledger. Any edit, deletion, or reorder is detectable by `verify()`. |
| **Kill switch** | `guard.freeze()` denies everything instantly, and the freeze itself is audited. |

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
