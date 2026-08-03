# Contributing to Vaduno

Thanks for looking. This is a young project (v0.2.2) and outside eyes are
genuinely wanted — especially on the concurrency and the cryptography, which
are where the real bugs have been.

## Reporting a security issue

**Do not open a public issue for a vulnerability.** Use
[GitHub Security Advisories](https://github.com/premsreelathasugeendran/vaduno/security/advisories/new).

A vulnerability here is anything that lets spend happen which policy should
have blocked, lets a mandate be used more times than it permits, lets audit
history be altered without detection, or makes any check fail *open*. If
you're unsure whether something qualifies, report it privately anyway.

## Getting set up

```bash
npm install
npm run build
npm run test        # 587 tests across seven packages
```

Then run the scenarios — each is a story from the README, and they are the
fastest way to understand the codebase:

```bash
npm run demo                 # policy, mandates, a retry storm, kill switch
npm run demo:x402            # HTTP 402 stablecoin rail
npm run demo:stripe          # Stripe Issuing real-time authorization
npm run demo:transparency    # inclusion proofs + witness cosigning
npm run demo:revocation      # the kill switch, and what it does NOT cover
npm run demo:cross-process   # two real OS processes racing one $50/day cap
```

## The rules that aren't negotiable

These aren't style preferences. Each one exists because breaking it produces a
class of bug this project is specifically built to prevent.

**1. Never hold funds, private keys to funds, or card PANs.** Vaduno decides
whether *your* executor may run; the executor moves the money. A full
compromise of Vaduno must not be able to move money on its own. This single
invariant is also what keeps the project clear of money-transmitter licensing,
so a PR that adds custody of any kind will be declined regardless of how good
the code is.

**2. Fail closed, always.** No approval handler configured? Deny. Registry
unreachable? Deny. Unexpected exception? Deny and audit. If you find yourself
writing a path where an error results in a payment proceeding, stop — that's
the bug. A denial is recoverable; an unintended charge is not.

**3. Amounts are integers in minor units.** Cents, paise. Never floats, never
rounded. `Number.isSafeInteger` guards exist deliberately; don't remove them.

**4. Deterministic decisions only.** No model output ever decides whether a
payment proceeds. The threat model assumes the agent is fully compromised and
controls every field of the intent, including `merchant.id` and `agentId`.

**5. Everything is evidence.** Denials and failures get recorded as thoroughly
as successes. If a code path can silently drop an audit write, it needs to
surface that (`auditDegraded`), not swallow it.

## What a good PR looks like

- **A test that fails before your change and passes after.** For anything
  touching concurrency, that test should actually exercise concurrency —
  `Promise.all` of the same operation, asserting exactly one wins. The
  double-spend bug in the consume store was invisible to sequential tests.

- **Honest comments.** Explain the constraint the code is under, not what the
  next line does. If something is a deliberate trade-off, say so and say why.
- **No new runtime dependencies in `@vaduno/guard`.** It has zero, and that is
  a feature — it is the package that sits between an agent and real money.
- **Documented limits stay documented.** If you strengthen a guarantee, update
  `docs/SECURITY-MODEL.md`. If you find that a documented guarantee is weaker
  than claimed, that is a valuable contribution on its own — open an issue.

## Writing a store (Redis, DynamoDB, MySQL, SQLite)

Two interfaces make Vaduno's guarantees hold across processes:

- **`ConsumeStore`** — consume-once mandates
- **`SpendLimiter`** — rolling spend caps

Memory (one process), file (one box) and Postgres (multiple instances)
implementations ship. **Redis, DynamoDB, MySQL and SQLite do not** — those are
the most useful things anyone could add.

Do not just satisfy the interface. Both are satisfied by implementations that
double-spend — this project has written that bug twice and **shipped** it once:
the consume store's `maxUses` gate was caught before the first publish, the
spend limiter's was not and went out in 0.2.0. Run the conformance suites:

```bash
npx vitest run packages/guard/test/consume-store.conformance.test.ts
npx vitest run packages/guard/test/spend-limiter.conformance.test.ts
npx vitest run packages/guard/test/ledger-concurrency.conformance.test.ts
```

The ledger suite's harness differs in a way worth copying: a handle is minted
from a shared **descriptor** (a path, a table, a pool) rather than from a shared
store *object*. That distinction is load-bearing — hand every handle the same
store object and a promise queue hidden inside it serializes them, so the suite
goes green while the real cross-process bug is untouched.

Both export a `run*Conformance(harness)`. They are **not** published to npm —
`@vaduno/guard` ships only `dist/` — so either copy the file into your repo
(each imports nothing but vitest and the package types) or add your store to
this repo and send a PR. Your harness returns **two independent handles on the
same backing store**: that is what exercises the cross-process contract, and a
single handle is precisely how both original bugs hid.

How much that matters, measured: a deliberately naive check-then-act limiter
**passes all 19 sequential cases and fails only the 4 concurrent ones.** If you
write a store and only run it sequentially, you will believe it works.

The whole contract reduces to one rule, in both interfaces: within a **single**
call, the duplicate check, the budget check, and the insert happen atomically
across every process sharing the store. `SELECT` then `INSERT` is the bug.
[`@vaduno/postgres`](packages/postgres) does it with `pg_advisory_xact_lock` on
the scope, taken as the first statement of a transaction on a dedicated pooled
connection — read that if you want a worked example, including why the
dedicated connection is not optional.

Reuse `firstViolatedWindow` from `@vaduno/guard` rather than reimplementing
window arithmetic. Four implementations already share it, which is why they
cannot drift on what a cap means.

## Claims and language

The project deliberately never claims to be "fully secure", and
`docs/SECURITY-MODEL.md` states precise non-guarantees alongside the
guarantees. Please keep that register. Bybit lost $1.5B and Ronin around $600M
with sound cryptography underneath; both broke at the human, UI and
supply-chain layers. A README that overclaims is a liability, not marketing.

If you strengthen something, describe exactly what it now guarantees and under
what assumption. "Tamper-evident" and "tamper-proof" are not synonyms here,
and the difference is load-bearing.

## Naming a new package or scope

Run the clearance gate before committing to any name:

```bash
node scripts/check-name.mjs <candidate>
```

It checks npm, GitHub and domains automatically, then refuses to clear the
name until a human has done the USPTO search. The comments in that file
explain, unsentimentally, why it exists.

## License

By contributing you agree your contributions are licensed under the MIT
License, same as the project.
