# Vaduno

**A spend firewall and flight recorder for AI agents.**

[![CI](https://github.com/premsreelathasugeendran/vaduno/actions/workflows/ci.yml/badge.svg)](https://github.com/premsreelathasugeendran/vaduno/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@vaduno/guard.svg)](https://www.npmjs.com/package/@vaduno/guard)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](packages/guard/package.json)

Your agent has an API key that can spend real money. Research says the agent *will* eventually be tricked — in the [WASP benchmark](https://arxiv.org/abs/2504.18575), prompt-injection attacks against autonomous web agents *partially* succeed in **up to 86%** of cases. The model cannot be the last line of defense.

Vaduno puts a deterministic guard between your agent and the money:

- **Policy engine** — per-transaction / daily / weekly / monthly caps, merchant & category allowlists, rail restrictions, velocity limits (scope-wide *and per-merchant*, layerable burst + sustained count windows — the deterministic, one-deployment analogue of Visa Transaction Controls / Mastercard In Control frequency rules, with no network-side enforcement claimed), human-approval thresholds. Pure code; no model in the loop.
- **Signed mandates** — Ed25519 "permission slips" binding what the human authorized (amount, merchant, time window) to what executes. Time-bound and **consume-once atomic**, closing the [mandate-replay attacks](https://arxiv.org/abs/2602.06345) published against agent-payment protocols.
- **Runtime enforcement** — a mandate's "consume-once, context-bound" isn't just signed, it's *enforced on the execution path*: a retry storm or duplicate orchestration hop firing the same payment N times runs the rail **at most once** and replays the original outcome to the rest; a used intent id reused for a different payment is denied; an optional context hash binds a mandate to one approved task run.
- **Flight recorder** — every attempt, decision, approval, and execution lands in a hash-chained, append-only audit ledger. Any edit, deletion, or reordering of history is detectable by `verify()`. Upgrade it to an [RFC 9162 Merkle transparency log](packages/transparency) for third-party inclusion (non-omission) and append-only consistency proofs.
- **Kill switch & revocation** — `guard.freeze()` denies everything on that guard instance instantly (**per-process**: a second live process keeps spending until it is frozen too — see [SECURITY.md](SECURITY.md) Known Limits). For a stop that every process actually observes, [`@vaduno/revocation`](packages/revocation) now also ships a shared **`FreezeStore`** (file on one box, Postgres across instances): wire `createFreezeCheck(store)` into each guard and one `store.freeze("credentials leaked")` denies every wired process's *next* authorization — no restart, no poll loop — with an epoch-fenced unfreeze so nobody lifts a re-freeze they never saw. Fail closed: an unreachable freeze store denies **every** payment on every wired guard (a total stop — the store becomes a hard availability dependency). The same package revokes a single mandate or an agent's entire authority against a *shared* registry, checked *after* human approval so a switch pulled mid-approval still wins — plus signed [W3C Bitstring Status Lists](https://www.w3.org/TR/vc-bitstring-status-list/) so third parties can verify status themselves.

**Vaduno never holds funds, keys to funds, or the ability to move money.** It decides whether *your* executor function may run, and records everything. (Precisely: it has no custody, no card PANs, and no wallet or bank credentials. It *does* use Ed25519 keys to sign and verify mandates — the private half belongs to whoever issues them, and a guard that only validates and consumes needs nothing but the public key.) Rail-agnostic by design: wrap an x402 client, a Stripe issuing call, a UPI collect — anything.

## Status: v0.4.0, new, and honest about it

Read this before you put it anywhere near real money.

- **Published this week. No known users. Never run in production.** The tests are thorough (863 across seven packages, including concurrency and adversarial cases; 3 of them are capability-gated skips — two need native ML-DSA in node:crypto, one needs a live Postgres — and every skip says so rather than silently passing) but tests are not production. npm reports a few hundred weekly downloads; that is registry mirrors, security scanners and the author's own CI — the curve is a single spike on publish day and flat afterwards, which is what "nobody depends on this yet" looks like.
- **The Stripe adapter has never run against Stripe.** Not even in test mode. It is verified against an in-process mock of the `issuing_authorization.request` webhook — the decision logic and the 1.3-second fail-closed deadline are exercised, the network path is not. Live Issuing needs a business entity and Stripe approval the author doesn't have. Treat it as a reference implementation, not a tested integration.
- **The API will break.** It's 0.x; breaking changes land in minor and patch versions. **Every API change so far has come from a security finding**, not from taste — the atomic limiter, the `agentId` → `policy.id` scope rename, the replay semantics, and the burn-on-failure rule each exist because something was found to be wrong. More review is planned, so expect more.
- **In-process, it can be routed around.** A library the agent's own process imports is a guardrail against a *confused* agent, not a *compromised runtime* — an injected agent holding a raw wallet key can simply not call it. The one configuration where it is genuinely non-bypassable today is **Stripe Issuing**, where the guard answers the card authorization itself and the network enforces the answer. Out-of-process and rail-side enforcement is what would make the rest of it as strong.
- **Spend caps hold across processes only if you supply a shared limiter.** The default is in-memory and per-instance, so two guard processes each enforcing a $50/day cap will let through $100. Pass a `FileSpendLimiter` (several processes, one box) or `PostgresSpendLimiter` (multiple instances) and the cap holds. `npm run demo:cross-process` spawns two real OS processes and shows both outcomes side by side. Fixed in 0.2.0 — before that there was no way to make it hold at all.
- **Caps don't prevent prompt injection. They bound the loss.** No policy engine stops an agent being tricked; it stops the tricked agent from spending more than you allowed, at a merchant you didn't allow, twice.
- **"Fully secure" is never claimed.** Bybit lost $1.5B and Ronin ~$600M with sound cryptography underneath; both broke at the human and supply-chain layer. [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) states the precise guarantees **and** the precise non-guarantees. If a claim anywhere contradicts that file, that file is right.

Built ahead of demand on purpose: real agent-payment volume today is tiny. The bet is that the controls need to exist before the money shows up, not after.

## Install

```bash
npm install @vaduno/guard
```

Zero runtime dependencies. Node ≥ 18.

Or clone and run the scenarios locally — `npm install` builds the workspace for you:

```bash
git clone https://github.com/premsreelathasugeendran/vaduno.git
cd vaduno && npm install
npm run demo
```

## 60-second example

```ts
import { randomUUID } from "node:crypto";
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
  // Called when policy says a human must decide. Fails CLOSED if omitted.
  approvalHandler: async ({ intent }) => ({ approved: true, approver: "you@company.com" }),
});

const result = await guard.execute(
  {
    id: randomUUID(),
    agentId: "shopper-agent-1",
    merchant: { id: "openai", url: "https://api.openai.com" },
    amount: { amountMinor: 900, currency: "USD" },              // $9.00 (always integer minor units)
    category: "api-credits",
    rail: "x402",
    requestedAt: new Date().toISOString(),
  },
  // Your executor. Vaduno never touches the money — it only decides
  // whether this function is allowed to run.
  async () => ({ receipt: "paid-via-your-rail" }),
);

// result.status: "executed" | "denied" | "approval_rejected" | "failed" | "replayed"

const audit = await ledger.verify();  // { ok: true, entries: n } — or exactly where history was tampered
```

**On merchant patterns:** a pattern containing a dot (`openai.com`) matches the **URL host** — the thing you actually connected to, which an agent cannot forge. A bare token with no dot (`openai`) matches `merchant.id`, a field the agent supplies, so it is only safe for trusted integrator-assigned ids. Use host patterns for anything security-relevant.

What the guard blocks, from the demo (`npm run demo`):

```
✅ Buy API credits: $9.00 at openai → executed
✅ Big compute purchase (needs human): $18.00 at aws → executed (approved)
⛔ PROMPT-INJECTED purchase: $12.00 at totally-legit-deals → denied — MERCHANT_NOT_ALLOWED
⛔ Over per-transaction cap: $25.00 → denied — PER_TXN_LIMIT_EXCEEDED
⛔ Would blow the daily budget: $19.00 → denied — PER_DAY_LIMIT_EXCEEDED
⛔ REPLAYED single-use mandate → denied — MANDATE_USES_EXHAUSTED
❌ tampering detected at seq 3 (ledger verification)
```

## Mandates: provable authorization

```ts
import { MandateManager, generateMandateKeyPair } from "@vaduno/guard";

const keys = generateMandateKeyPair();          // issuer keeps the private key
const mandates = new MandateManager(
  { publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem },
  ledger,
);

const mandate = await mandates.issue({
  issuer: "you@company.com",
  agentId: "shopper-agent-1",
  constraints: {
    maxAmountMinor: 1_000, currency: "USD",
    merchants: ["anthropic.com"],
    validFrom: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    maxUses: 1,                                  // consume-once
  },
});
```

Attach `mandateId` to an intent (set `requireMandate: true` to demand it for every payment). Validation is checked pre-flight and **consumed atomically right before execution** — two concurrent uses of a single-use mandate cannot both succeed. The signed mandate + the hash-chained trail together answer the dispute question no current agent-payment spec answers: *prove what the human authorized and what actually happened.*

**Where the signing key lives is the whole design.** A human signs a scope ahead of time — merchants, ceiling, time window — with an Ed25519 key held offline or somewhere the agent process cannot reach. The agent then spends unattended *inside* that scope. A validating process needs only the **public** key.

If you automate signing on the agent's own machine, the mandate stops being an authorization and becomes merely an audit format. That's a legitimate use, but be clear with yourself about which one you're deploying.

### Non-exportable signing (KMS / HSM)

The strongest form of "somewhere the agent process cannot reach" is a key that *no* process can extract. Pass a `signer` instead of a `privateKeyPem` and the mandate key can live in a cloud KMS or an HSM — only signatures ever enter the process:

```ts
new MandateManager({ signer: myKmsSigner });   // Ed25519Signer: a capability, not a key
```

Every signer output is verified against the public key the signer declared at construction before anything is issued or recorded, and every signer failure (reject, hang, wrong key, rotated key, truncated bytes) **denies** — issuance never degrades to unsigned output, and a wedged KMS blocks *new* mandates only while existing ones still verify and consume. The same capability plugs into signed tree heads, checkpoints, witness cosignatures and status lists (`signTreeHeadWith`, `signCheckpointWith`, `cosignCheckpointWith`, `publishStatusListWith`). Wire output is byte-identical to the `privateKeyPem` path.

**Key separation is normative:** the key behind a signer must be minted for Vaduno and hold no other signing authority — never an Ed25519 blockchain wallet key (Solana, NEAR, Stellar), never a key shared with another system. These keys sign authorization *evidence*, not funds, and [docs/signers.md](docs/signers.md) states the requirement, the reasons, and a Google Cloud KMS setup that creates a fresh, IAM-scoped key.

### Runtime enforcement: survive retries, races, and misapplication

Signing a mandate proves it was *issued*; it does nothing to stop that valid mandate from being executed twice by a retry loop or raced by two workers. Vaduno enforces it at execution time through a **consume-once registry** keyed on `(mandateId, intentId)`:

```ts
// The SAME payment fired 6x in parallel (a crashed/retried agent):
const results = await Promise.all(
  Array.from({ length: 6 }, () => guard.execute(sameIntent, payOnce)),
);
// rail ran AT MOST once → 1 "executed" + 5 "replayed" (original outcome), never a double charge.
```

**Scope of that guarantee:** at-most-once holds within one process by default, and across processes when you supply a shared store. `FileConsumeStore` covers several processes on one box; [`@vaduno/postgres`](packages/postgres) covers multiple instances. Both are held to the same conformance suite — the one that a check-then-act implementation passes sequentially and fails only under concurrency.

- **`status: "replayed"`** carries the original attempt's outcome (`executed` / `failed` / `unresolved`); the executor does **not** run again.
- A used intent id presented with **different money fields** is denied `MANDATE_REPLAY_MISMATCH` — an id-reuse attack, not a retry.
- **Context binding** (`mandateContextHash`): set `constraints.contextHash` at issue time and the intent must present the exact context blob — with `agentId`/`merchantId` matching — or it's denied `CONTEXT_MISMATCH`. This binds a mandate to one approved task run so a valid mandate can't be redirected by a different orchestration hop.
- **Cross-process:** the default `MemoryConsumeStore` covers one process; pass a `FileConsumeStore` (one box) or `PostgresConsumeStore` (multi-instance) so a race between processes still yields exactly one execution. `hydrateFromLedger()` rebuilds the registry after a restart.

Based on the runtime-verification results in [ZTRV](https://arxiv.org/abs/2602.06345) and APEX: signature-only checks intercept 0% of replays; an atomic consume registry intercepts 100%.

## Does a $50/day cap hold when you run two workers?

Only if you tell it to. The default limiter is per-process, and two processes with their own memory are two budgets:

```bash
npm run demo:cross-process
```

Two **real OS processes**, one cap, $100 of payments attempted:

```
1. Per-instance limiter (the default)
   worker-A: 5 executed, 0 denied  →  spent $50.00
   worker-B: 5 executed, 0 denied  →  spent $50.00
   TOTAL SPENT: $100.00  against a $50.00 cap
   ❌ OVER the cap by $50.00 — two processes are two budgets.

2. Shared FileSpendLimiter (one budget, atomic reserve)
   worker-A: 5 executed, 0 denied  →  spent $50.00
   worker-B: 0 executed, 5 denied  →  spent $0.00
   TOTAL SPENT: $50.00  ✅ The cap held.
```

The difference is one constructor argument:

```ts
import { FileSpendLimiter } from "@vaduno/guard";          // several processes, one box
import { PostgresSpendLimiter } from "@vaduno/postgres";   // multiple instances

const guard = new VadunoGuard({ policy, ledger, limiter: new PostgresSpendLimiter(pool) });
```

**Why a shared *store* isn't enough on its own.** Until 0.2.0 the spend interface was a read-only `totalsSince()`, which can only ever support check-then-act: read totals, execute, append. Two instances both read `$0`, both pass the `$50` check, both spend. Pointing *that* at Postgres would not have fixed anything — the race lives in the gap between the read and the append, not in where the rows are stored. So the budget check moved *inside* the mutating call:

```
reserve(windows, amount)  →  execute  →  commit
```

`SpendLimiter.reserve()` evaluates every rolling window and records the reservation as one atomic step. That is the same fix the consume store needed when `maxUses` had to move inside `claim()` — the same bug, one layer up.

Writing your own limiter is expected, and there's an oracle for it: [`spend-limiter-conformance.ts`](packages/guard/test/spend-limiter-conformance.ts) runs 23 cases against **two independent handles on one backing store**. A deliberately naive check-then-act implementation passes all 19 sequential cases and fails exactly the 4 concurrent ones — which is precisely how this class of bug reaches production.

## Risk scorecard: deterministic step-up routing and auto-freeze

Opt-in (`risk: new RiskScorecard({...})` on the guard): eight deterministic, ledger-derived signals — first-seen merchant, amount above the merchant/global typical, declared out-of-hours windows, execution bursts, deny streaks, first use of a mandate, approach to the day cap — score every intent that passes policy. Elevated scores route to your existing `approvalHandler` (`RISK_STEPUP`); high scores deny (`RISK_DENY`) *before* any budget or mandate use is touched, and an approval can never override a deny; an `autoFreeze` threshold additionally stops the process until a manual `unfreeze()`. The merge is tighten-only, so risk can never loosen a policy decision, and every assessment is recorded in the ledger with a head anchor that makes it reproducible bit-for-bit *given the same scorecard config and policy* — the entry carries the config's hash, not the config itself, and the policy is not ledgered.

This is the routing analogue of 3DS2 risk-based authentication (frictionless / challenge) and of the signals behind Visa Advanced Authorization / Mastercard Decision Intelligence — **mechanism only**: those network scores aggregate network-scale data and real 3DS2 carries an issuer liability shift, while this scorecard sees one deployment's ledger and confers no liability property of any kind. Deterministic and replayable is the trade, and it is deliberate. Details and the honest boundary: [`@vaduno/guard` README](packages/guard/README.md) and [SECURITY.md](SECURITY.md).

## Ledger stores

| Store | Use |
|---|---|
| `MemoryLedgerStore` | tests, ephemeral agents |
| `JsonlLedgerStore("ledger.jsonl")` | local flight-recorder file |
| `SupabaseLedgerStore(client)` | shared/team ledger — schema in [supabase/schema.sql](supabase/schema.sql), RLS keeps it append-only server-side. **Requires the 0.3.0 schema**: the `unique (prev_hash)` index is new and is what makes a fork unrepresentable |
| `PostgresLedgerStore(pool)` | multi-instance ledger — [`@vaduno/postgres`](packages/postgres), same two constraints plus an advisory lock to make retries rare |

The chain is computed client-side; `verify()` re-derives every hash, so even a compromised database cannot silently rewrite history.

Since 0.3.0 a store admits an entry only if it still extends the tip the writer chained onto, so concurrent writers can no longer fork the chain — see [SECURITY.md](SECURITY.md) Known Limits item 3 for each store's mechanism and residual, including which of them have and have not been exercised against a live database.

## x402 rail adapter (`@vaduno/x402`) — experimental, v1 + v2

`@vaduno/x402` wraps the HTTP 402 "pay-per-request" flow: on a 402 it builds a `PaymentIntent` from the server's requirement, runs the guard, and only if allowed calls **your** signer. Vaduno never sees keys.

> **It implements x402 v1 and v2 (HTTP transport) and has never run against a real x402 server.** The demo and every test mock both the server and the payer in-process — the v2 vector file ([spec/vectors/x402-http-v2.json](spec/vectors/x402-http-v2.json)) carries the spec's own wire examples verbatim *alongside* this adapter's own version-outcome table, which is Vaduno policy rather than spec text — so what is verified is agreement with the *spec's text and examples*, not interoperability with anything deployed. Same honest status as the Stripe adapter: **neither rail has ever touched a real endpoint.**

```ts
import { createX402Fetch, usdc } from "@vaduno/x402";

const fetchWithPay = createX402Fetch({
  guard,                                   // your VadunoGuard
  agentId: "researcher-agent-1",
  pay: (req) => myWallet.signX402(req),    // your v1 signer — Vaduno never holds keys to funds
  v2: {                                    // v2 is OPT-IN; omit it and v2 402s are refused
    pay: (req, ctx) => myWallet.signX402V2(req, ctx),
  },
  assets: [                                // bind spend to the REAL token, not a label
    { network: "base",        asset: "0x833589...2913", symbol: "USDC", decimals: 6 },
    { network: "eip155:8453", asset: "0x833589...2913", symbol: "USDC", decimals: 6 },
  ],
});

// Use it like fetch(). 402s are paid under policy; everything else passes through.
const res = await fetchWithPay("https://api.example.com/premium");
```

Version routing is per-response and single-carrier: a `PAYMENT-REQUIRED` header means v2 (the body is never read); no header means v1 (the JSON body). The `x402Version` discriminant is **total** — `"2"`, `1.5`, `0`, negative and friends are named refusals, never coerced to 1 — and the whole decision table is frozen as vectors ([docs/WIRE-FORMAT.md §8](docs/WIRE-FORMAT.md)).

Rail-specific security notes (see [SECURITY.md](SECURITY.md) and the [package README](packages/x402/README.md)):

- **`merchant.url` is the real endpoint you contact**, not the server's `resource`
  claim — host allowlists bind where you actually connect. A server that claims a
  different origin than the one reached is refused.
- **In x402 the money goes to `payTo`, decoupled from the request host.** A host
  allowlist does *not* constrain the recipient — pin it with an `id:<payTo>`
  pattern if that matters. v2 role-constant `payTo` values (e.g. `"merchant"`)
  are refused by default: an unresolvable recipient cannot be allowlisted.
- **Pass the `assets` registry.** Without it, `currency` comes from the server's
  spoofable `extra.symbol`. With it, a token that isn't on your list is refused.
  v1 network names and v2 CAIP-2 ids are **separate registry keys**.
- **Spend is counted once the payment header (`X-PAYMENT` / `PAYMENT-SIGNATURE`)
  is transmitted** — because it's a bearer authorization the server can still
  settle even while returning an error. Under v2's `upto` scheme the counted
  amount is the authorized maximum. Bind a consume-once mandate (`maxUses`) to
  bound retries. the v2 schemes analysed here (`exact`, `upto`) carry no reusable
  authorizations, so per-authorization counting matches them; an unanalysed
  `batch-settlement` scheme exists in the spec tree, under which counting is
  conservative rather than complete.

## Revocation & kill switch (`@vaduno/revocation`)

An agent's credentials leak at 2am. Revoke one mandate, or the agent's entire authority, and have it take effect before the next payment:

```ts
import { RevocationRegistry, createRegistryCheck } from "@vaduno/revocation";

const guard = new VadunoGuard({
  policy, ledger, mandates,
  revocationCheck: createRegistryCheck(registry),   // makes revocation ENFORCED
});

await registry.revokeAgent("shopper-agent-1", { reason: "credentials leaked" });
```

The check runs **inside the guard's critical section, after human approval** — so a kill switch pulled while someone is still approving still wins. Everything fails closed: a registry outage denies (`REVOCATION_CHECK_FAILED`) rather than reading as "not revoked". For counterparties who don't own your registry, `registry.publish(version)` emits a signed [W3C Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/) (131,072 entries in ~70 bytes) that rejects forged, stale, and rolled-back snapshots.

**Honest scope:** revocation is instant and guaranteed for mandates the guard mediates. For authority it doesn't mediate (a raw wallet key), fan-out to the rail's own API is best-effort — and every failure is recorded, never assumed away. Settled on-chain spend cannot be clawed back by anyone. See [packages/revocation](packages/revocation/README.md).

## Transparency log (`@vaduno/transparency`)

Upgrade the hash chain to an [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) Merkle transparency log — the Certificate Transparency machinery, applied to payment decisions. It adds what a bare chain cannot: **inclusion proofs** (a specific decision *is* in the published history — proof of non-omission) and **consistency proofs** (a later root only ever extended the earlier one), both verifiable by a third party from Ed25519-signed tree heads.

On top of that, **witness cosigning** ([C2SP](https://github.com/C2SP/C2SP) `tlog-checkpoint` / `tlog-cosignature`) closes the one hole the log's own math cannot: an operator who signs *two* histories and shows a different one to each party. Independent witnesses refuse to cosign a checkpoint that contradicts one they already cosigned, so a fork can never reach a k-of-n quorum. Honest limit: this proves everyone sees the *same* log, not that the log is *complete* — and witnesses you run yourself count for nothing. See [packages/transparency](packages/transparency/README.md) and [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Post-quantum readiness (evidence layer)

Audit evidence is long-lived: a dispute bundle verified in 2032 must resist a 2032 adversary forging "2026" signatures. NIST IR 8547 deprecates ECC/RSA signatures for new use in 2030 and disallows them in 2035 — every Ed25519 signature emitted today is inside that window if verified after 2030. What Vaduno does about it, stated exactly:

- **The hash chain and RFC 9162 Merkle tree are already adequate** against a quantum adversary (SHA-256; Grover halves the bits, 128-bit preimage resistance remains). They were not rebuilt. The **signatures** are the exposed surface.
- **Hybrid (v2) mandates** carry an ML-DSA-44 (FIPS 204) signature *alongside* Ed25519 over the same `vaduno-mandate/v2` payload; **0x06 witness cosignatures** (C2SP tlog-cosignature, ML-DSA-44) do the same for the transparency log — *where the runtime supports it*. ML-DSA in `node:crypto` needs Node ≥ 24.7 **built against OpenSSL ≥ 3.5**; a runtime probe (`mlDsa44Available()`), never a version string, decides, and signing without support fails with a typed `PqUnavailableError`.
- **The classical signatures remain exposed post-CRQC unless you set `requireAlgs`.** An attacker who can forge Ed25519 doesn't strip a v2 mandate — they mint a fresh **v1** under any Ed25519 kid your verifier still registers. `new MandateManager(keys, ..., { requireAlgs: ["ML-DSA-44"] })` is the enforcement switch; both the attack and the remedy are pinned as tests.
- **Archival verification works by default.** Cosignature verification applies no staleness bound (a witness attestation "seen no later than T" doesn't decay); freshness is an opt-in liveness check. `assessCheckpointAnchor` labels a checkpoint `witnessed-pq` only from *verified* ML-DSA-44 quorums, and its `witnessedAt` counts only cosignatures at least that strong — a backdated forged classical cosignature cannot move it.

v1 mandates and all frozen wire vectors are untouched; v2 is additive. Precise claims, the downgrade residual, and the migration path: [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) (post-quantum posture) and [`docs/WIRE-FORMAT.md`](docs/WIRE-FORMAT.md).

## Agent framework hooks (`@vaduno/agent`)

`guard.execute(intent, executor)` requires the guard to own the payment call, and **no agent framework works that way** — Claude Agent SDK `PreToolUse`, Vercel AI SDK `toolApproval`, OpenAI Agents `needsApproval`, LangChain `wrapToolCall` are all decide-only: they hand you a pending tool call, take an allow/deny, and run the tool themselves. So this binds to the two-phase `authorize()` / `settle()` path instead.

```ts
import { createSpendHooks, bindClaudeAgentSdk } from "@vaduno/agent";

const hooks = createSpendHooks({
  guard,
  resolve(call) {
    if (call.toolName !== "buy_api_credits") return null;      // not a spending tool
    return intentFrom(call.input);                             // you write this
  },
});

const sdk = bindClaudeAgentSdk(hooks);   // PreToolUse / PostToolUse
```

An allow **reserves budget immediately** — if it merely returned an opinion, two concurrent tool calls would both be told yes and the cap would mean nothing. Every ambiguous case fails toward over-holding: a throwing resolver denies, an unreadable tool result counts as spent, and a framework that never settles starves its own cap rather than leaking spend.

**Honest scope:** the decision core is framework-free and tested against real guard behavior; the Claude Agent SDK binding's hook payload shapes come from the documented contract and **have never been run against a live SDK session**. That file imports nothing from any SDK and is deliberately thin, so a drifted contract is a few lines to fix. See [packages/agent](packages/agent/README.md).

## Design principles

1. **Fail closed.** No approval handler? Approval-needing intents are denied. Internal error? Denied and audited. Unknown mandate? Denied.
2. **Deterministic last line.** An attacker is assumed to fully control the agent and every field of the intent. Policy checks are pure code over integer minor units.
3. **Amounts are integers.** Minor units (cents, paise) everywhere. Floats are denied, not rounded.
4. **Everything is evidence.** Denials and failures are recorded as thoroughly as successes — the audit trail is the product.
5. **Not in the money path.** No custody, no keys to funds, no transmission. Your executor moves money; Vaduno governs and records.

## Roadmap

- ✅ **x402 adapter** (`@vaduno/x402`) — wrap Coinbase x402 payments with policy + audit
- ✅ **Stripe issuing adapter** (`@vaduno/stripe`) — the guard as the real-time card-authorization brain
- ✅ **Dashboard** — live spend view, approval inbox, ledger explorer ("Vault Terminal")
- ✅ **Runtime mandate enforcement** — consume-once + idempotent replay + context binding
- ✅ **Transparency log** (`@vaduno/transparency`) — RFC 9162 inclusion / consistency proofs
- ✅ **Revocation registry** (`@vaduno/revocation`) — targeted kill switch + W3C Bitstring Status Lists
- ✅ **Witness cosigning** — C2SP checkpoints + cosignatures; independent witnesses attest the log never forked
- ✅ **Agent framework hooks** (`@vaduno/agent`) — decide-only tool-approval binding; SDK adapter not yet run against a live session
- ✅ **Deterministic risk scorecard** — ledger-derived tiers, step-up routing through the approval branch, auto-freeze; reproducible bit-for-bit from the ledger given the same scorecard config and policy
- ✅ **Post-quantum readiness (evidence layer)** — hybrid v2 mandates (Ed25519 + ML-DSA-44), C2SP 0x06 witness cosignatures, archival verification semantics, `requireAlgs` enforcement; runtime-probed, additive, v1 frozen
- **Consent-evidence dossiers** — exportable dispute/representment packets built on the audit trail
- **UPI adapter** — ready for NPCI delegated-payment APIs the day they open

## Prior art, and where this doesn't compete

**Stripe's `spending_controls` and Lithic (whose consumer product is Privacy.com) already enforce caps at the network** — the strongest possible place, because an agent cannot route around them. If you're on one rail, use those. They're better at that job than this is.

What Vaduno adds is one policy and one portable signed authority that survive *across* rails, plus an audit log a counterparty can verify without trusting you. On Stripe Issuing it sits behind their controls, not instead of them.

## What review has and hasn't happened

**No professional security audit has been done.** Nobody independent has been paid to break this, and for anything touching money that is the review that counts. Treat everything below as the author's own pre-release testing, not as assurance.

What that testing did catch, before release: a cross-process double-spend (the `maxUses` check was check-then-act across separate locks), a hanging payment rail that could freeze the kill switch for every later revocation, a witness-quorum bypass that required *zero* witness misbehaviour, and a C2SP wire-format error that would have broken interoperability with real Go/Sigsum witnesses while every local test still passed.

Those are listed because a security tool that hides its near-misses is asking you to trust the wrong thing — and because each one is concrete enough to check against the code and the commit history rather than taken on faith. The concurrency and the cryptography are where the real bugs have been, and they are where outside review is most wanted.

**Two adapters have never touched the system they adapt.** `@vaduno/stripe` has not contacted `api.stripe.com` in any mode, and `@vaduno/agent`'s Claude Agent SDK binding has not run in a live SDK session — both were written against published contracts. Their surrounding logic is tested; the wire shapes at the boundary are unconfirmed, and are isolated in one thin file each so that being wrong about them is cheap to fix and hard to miss.

## Contributing

Bug reports and criticism are wanted, particularly on the concurrency and the cryptography. See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go to [GitHub Security Advisories](https://github.com/premsreelathasugeendran/vaduno/security/advisories/new), never a public issue.

## License

MIT
