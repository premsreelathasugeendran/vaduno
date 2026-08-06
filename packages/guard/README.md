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
| **Policy engine** | Per-transaction / rolling day-week-month caps, merchant & category allowlists, **settlement-network** allow/block, rail restrictions, velocity limits (scope-wide **and per-merchant**, layerable burst + sustained windows), approval thresholds. Pure code, no model in the loop. |
| **Signed mandates** | Ed25519 "permission slips" binding what a human authorized (amount, merchant, time window) to what executes. |
| **Post-quantum readiness (evidence layer)** | The hash chain and Merkle tree are SHA-256 — already adequate against a quantum adversary (Grover halves the bits; 128-bit preimage resistance remains); the signatures are the exposed surface. Hybrid (v2) mandates carry an ML-DSA-44 (FIPS 204) signature alongside Ed25519 over the same `vaduno-mandate/v2` payload where the runtime supports it (a runtime probe — `mlDsa44Available()` — decides, never a version string; signing without support throws a typed `PqUnavailableError`). The classical signatures remain exposed post-CRQC unless the verifier sets `requireAlgs: ["ML-DSA-44"]`. See `docs/SECURITY-MODEL.md`, "Post-quantum posture". |
| **Non-exportable signing** | Pass an `Ed25519Signer` instead of a `privateKeyPem` and the mandate key can live in a KMS/HSM: only signatures enter the process, every signer output is verified against the public key the signer declared at construction before anything is recorded, and every signer failure denies (never degrades to unsigned output). The key behind a signer must be minted for Vaduno and hold no other signing authority — never a blockchain wallet key. See `docs/signers.md` in the repo. |
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
- A used intent id presented with **different money fields** *under the same mandate* is denied `MANDATE_REPLAY_MISMATCH` — an id-reuse attack, not a retry.
- A used intent id presented **under a different mandate** is denied `INTENT_ID_NOT_BUDGETED`. The digest check cannot see this one: `(M2, id)` is a claim key the registry has never held, so it answers "fresh". What catches it is the budget invariant — nothing executes on a spend reservation it did not take. Use a unique intent id per payment; reuse one only to retry the *same* payment under the *same* mandate.
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

## Merchant patterns and settlement networks: what they actually constrain

**No merchant pattern verifies the payee.** `merchantMatches` compares a policy
pattern against fields of the intent, and the caller sets every field of the
intent — `merchant.url` exactly as much as `merchant.id`. The guard never
contacts the URL and has no independent knowledge of who receives the money.

| Form | Compares against | What it buys |
|---|---|---|
| `"openai.com"` / `"host:openai"` | `merchant.url` | **Matching precision**: parsed as a URL, compared on the hostname at a dot boundary, so `evil-openai.com` and `openai.com.evil.net` cannot pass; case and trailing-dot FQDN variants normalize out. |
| `"id:openai"` / `"openai"` | `merchant.id` | Exact string compare. No parsing, no boundary logic. |

Neither is "the strong one" *a priori* — pick by which field **your**
integration derives honestly, per intent, from the real payment destination. A
`merchant.url` fixed once at construction makes every host pattern match for
every recipient. In a signer-level integration the ranking inverts: there
`merchant.id` carries the payee address pulled from the bytes about to be
signed (the strongest fact available) while `merchant.url` is the constant, so
`id:` is the stronger control. Same in x402, where funds go to `payTo`,
decoupled from the request host — constrain it with `id:<payTo>`.

**`allow` is disjunctive, so a host pattern there can only widen.** An intent
passes if *any* entry matches, so `["host:api.example.com", "id:0x…"]` does not
mean "this host **and** this recipient" — it means "this recipient **or**
anyone that host names". The conjunction is not expressible. Where the URL does
not determine the recipient, that makes a host entry in `allow` a recipient
bypass in the shape of a control, and `@vaduno/x402` refuses it outright
(`RECIPIENT_UNGATED`; opt out with `allowHostOnlyMerchantPolicy: true`) because
that adapter knows its rail's commitment structure. Host patterns in
`merchants.block` are unaffected — a match there always denies, so disjunction
only tightens.

A host-form entry in `merchants.block` **needs** a parseable `merchant.url`, so
an intent carrying none is denied `MERCHANT_URL_UNVERIFIABLE` rather than
passing. On the allow side a non-match already denies; on the block side "did
not match" would have meant "not blocked", and dropping one optional field
walked past the whole blocklist.

**Currency is not a chain.** USDC on Base Sepolia and USDC on Ethereum Sepolia
produce the identical intent shape and the same currency code, so constrain the
network explicitly:

```ts
policy: {
  // ...
  networks: { allow: ["eip155:84532"] },   // exact, case-insensitive, no wildcards
},
// and the intent says where it settles:
{ /* ... */ network: "eip155:84532" }      // CAIP-2 recommended; @vaduno/x402 sets it
```

- Exact match only. `"eip155"` does **not** stand for every EVM chain — implicit
  breadth is what made chain-blindness possible in the first place.
- Once a `networks` block exists, an intent that states **no** network is denied
  `NETWORK_MISSING`. Missing is a denial, never a skip.
- Omitting `networks` imposes no network constraint at all. That default is
  deliberate and additive — denying unstated networks would deny every payment
  of every deployment written before the field existed — but it means **a policy
  without `networks` is chain-blind**. If you settle on chains, set it.
- `@vaduno/x402` populates `intent.network` for you: the x402 network name in
  v1 (`"base-sepolia"`), the CAIP-2 id in v2 (`"eip155:84532"`). Separate key
  spaces, exactly like the `assets` registry — match the version you speak.

## Deterministic risk scorecard: tiers, step-up routing, auto-freeze

The routing analogue of 3DS2 risk-based authentication (frictionless → allow unchanged; challenge → your existing `approvalHandler`) and of the *signals* behind Visa Advanced Authorization / Mastercard Decision Intelligence — computed deterministically at **one deployment** from its own ledger, and reproducible from it bit-for-bit. Deliberately not black-box ML: every fired signal names its rule. **Mechanism-only comparison:** real 3DS2 carries an issuer liability shift; Vaduno's scorecard shifts liability to no one — it only routes this deployment's payment to allow / step-up / deny.

```ts
import { RiskScorecard } from "@vaduno/guard";

const guard = new VadunoGuard({
  policy,
  ledger,
  approvalHandler, // answers step-ups; it can never override a risk deny
  risk: new RiskScorecard({
    lookbackMs: 30 * 86_400_000,
    stepUpAt: 5,                  // score >= 5  → require_approval (RISK_STEPUP)
    denyAt: 10,                   // score >= 10 → deny (RISK_DENY)
    autoFreeze: { atScore: 15 },  // deny AND freeze this process; manual unfreeze only
    signals: {
      FIRST_SEEN_MERCHANT: { weight: 3 },
      AMOUNT_ABOVE_MERCHANT_TYPICAL: { weight: 3, multiplierBps: 30_000, minHistory: 5 },
      AMOUNT_ABOVE_GLOBAL_TYPICAL: { weight: 2, multiplierBps: 50_000, minHistory: 10 },
      OUT_OF_HOURS: { weight: 2, allowedWindowsUtc: [{ startMinute: 540, endMinute: 1020 }] },
      VELOCITY_BURST: { weight: 2, maxCount: 10, windowMs: 3_600_000 },
      DENY_STREAK: { weight: 4, minDenies: 3, windowMs: 3_600_000 },
      FIRST_USE_OF_MANDATE: { weight: 2 },
      CAP_APPROACH: { weight: 2, thresholdBps: 8_000 },
    },
  }),
});
```

- **Eight deterministic signals, integer/BigInt math over the ledger.** First-seen merchant, amount above the merchant/global lower-median, declared out-of-hours windows (never learned), execution bursts, deny streaks, first use of a mandate, approach to the day cap. No model in the loop.
- **Tighten-only, by construction.** Low = the policy decision unchanged; elevated = `require_approval` through the *existing* approval branch; high = deny, and the approval handler is never invoked. An assessment can raise a decision's strictness, never lower it — risk is defense-in-depth, not an allow authority.
- **A risk deny burns nothing.** Both risk denials land *before* the budget reservation and any mandate consumption.
- **Scored twice on the way to money.** A preliminary pass outside the mutex and, for intents still headed for execution, a final re-evaluation inside the critical section (concurrent intents move the signals); risk that rises in between without an approval denies `RISK_STEPUP_UNAPPROVED`.
- **Reproducible from the ledger.** Every assessment is hard-appended as a `risk_scored` entry carrying a ledger-head anchor; `anchoredPrefix()` + `RiskScorecard.assess()` re-derive it bit-for-bit.
- **Fail closed at every seam.** Invalid config throws at construction with *every* violation listed (a typo'd signal key does not silently no-op); an unscorable intent denies `RISK_UNSCORABLE`; an unreadable history source denies; a scorer bug denies; no `risk` option = the pipeline is unchanged.
- **Honest boundary.** The scorer sees one deployment's ledger, never network-scale data. Merchant identity authority remains the allowlist, and `autoFreeze` uses the per-process local freeze — the cross-process `FreezeStore` is separate wiring. See [SECURITY.md](https://github.com/premsreelathasugeendran/vaduno/blob/master/SECURITY.md).

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
