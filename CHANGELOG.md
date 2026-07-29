# Changelog

All six packages are versioned together and released as a matched set.

This project is pre-1.0. Under semver, 0.x minor bumps may break the API. One
has, and it was breaking because the fix for a real security bug required it. See [`SECURITY.md`](SECURITY.md) for what is and isn't
guaranteed.

## 0.2.1 — 2026-07-29

**Two cap bypasses shipped in 0.2.0. Upgrade.** Both were introduced by the
0.2.0 limiter itself — the release whose entire purpose was to make caps hold —
and both were found by a fact-check pass *after* publishing, not before.

### Fixed

- **Rotating `intent.agentId` reset the cap.** The reservation was scoped to
  `agentId`, a field this project's own threat model
  ([CONTRIBUTING](CONTRIBUTING.md) rule 4, [`types.ts`](packages/guard/src/types.ts))
  states the attacker controls. Reproduced: two guards sharing one limiter,
  `$100` through a `$50/day` cap, by changing one string. The same test with a
  fixed `agentId` correctly denied — which is why the conformance suite missed
  it entirely.

  Reservations are now scoped to **`policy.id`**, which the operator sets. Note
  this also means the pre-0.2.0 behaviour is restored: the old in-memory history
  deliberately *ignored* `agentId` for exactly this reason, and 0.2.0 silently
  regressed a mitigation `SECURITY.md` had claimed since 0.1.0. If you want
  per-agent budgets, derive the scope from an id **you** assign to a trusted
  principal, never from the intent.

- **Reusing an `intent.id` ran the rail again while counting one charge.** A
  replayed reservation returned `ok` and the guard fell through to the executor.
  Reproduced: the same intent id twice ran the rail **twice**, counted once; a
  throwing executor retried eight times ran the rail **eight times** and still
  counted one `$50` charge. That directly contradicted the burn-on-failure
  guarantee 0.2.0 added, which exists so an executor timing out *after* the
  charge lands cannot be retried past the cap.

  A replayed reservation now returns `status: "replayed"` — `executed` if the
  first attempt committed, `unresolved` if it never settled (money may have
  moved; the guard will not guess). When a mandate is present the mandate's
  consume-once registry still decides, because it holds strictly better
  information: the intent digest, so id reuse with *different* money is DENIED
  rather than replayed, and the settled outcome, so a failed attempt replays
  `failed` rather than `unresolved`.

### Changed (breaking, and it is a one-day-old interface)

- `ReserveRequest.agentId` → **`ReserveRequest.scope`**. Any `SpendLimiter` you
  wrote against 0.2.0 needs this rename, and should key on `scope`. The
  Postgres schema column `agent_id` → `scope` with it.
- `ReserveResult` gains `state` on a replay, so the caller can tell "the rail
  ran" from "the rail may have run".
- `GuardResult`'s `replayed` variant has `mandateId` **optional** — an intent id
  can now be replayed by the limiter with no mandate involved.

### Documentation corrections

The same pass found five claims a reader could have disproved:

- **The conformance suites are not published.** `@vaduno/guard` ships only
  `dist/`, yet both suites' own docblocks told you to
  `import … from "@vaduno/guard/test/…"`, CONTRIBUTING repeated it, and
  `@vaduno/postgres@0.2.0`'s README says they "ship with `@vaduno/guard`" —
  that one is immutable on npm now. They are repo test files; copy them or send
  a PR.
- "This project has shipped that bug twice" — written twice, **shipped once**.
  The `maxUses` gate was fixed six days before the first publish.
- "All five packages are versioned together" — six.
- The changelog claimed two breaking minor bumps; there had been one.

Tests 357 → 364, including regression tests for both bypasses.

## 0.2.0 — 2026-07-29

Spend caps now hold across processes. Until this release they did not, and
there was no way to make them.

### Added

- **`SpendLimiter`** — an atomic `reserve` / `commit` / `release` contract where
  every rolling window is evaluated *inside* the reserving call. Ships
  `MemorySpendLimiter` (default, single process) and `FileSpendLimiter`
  (several processes on one box).
- **[`@vaduno/postgres`](packages/postgres)** — `PostgresSpendLimiter` and
  `PostgresConsumeStore`, for caps and mandates that hold across **multiple
  instances**. Verified by both conformance suites against a real Postgres 16
  in CI — 40 tests, no mocks, because the property being tested lives in the
  database. `pg` is an optional peer dependency; `@vaduno/guard` still has zero
  runtime dependencies.
- **A `SpendLimiter` conformance suite** (23 cases per limiter) run against two
  independent handles on one backing store, plus `guard.releaseSpend(intentId)`.
- **`npm run demo:cross-process`** — spawns two real OS processes racing one
  $50/day cap. Shows $100 spent with the per-instance default and exactly $50
  with a shared limiter. Runs in CI on Linux, Windows and macOS and fails the
  build on any overspend.

### Fixed

- **Rolling spend caps did not hold across processes, and could not be made to.**
  `SpendHistory.totalsSince()` is a read-only query, so the guard could only ever
  check-then-act: read totals, execute, append. Two processes both read `$0`,
  both passed a `$50` check, both spent. Pointing that interface at a shared
  database would *not* have fixed it — the race lives in the gap between the read
  and the append, not in where the rows are. The budget check moved inside the
  mutating call, exactly as `maxUses` had to move inside `claim()` when the
  consume store had this same bug one layer down.

### Changed — read this one before upgrading

- **A failed execution now KEEPS its spend counted.** Previously a thrown
  executor freed the entire reserved amount. But a timeout *after* the charge
  landed is indistinguishable from a clean failure, so an executor that failed
  post-charge could be retried past any cap: N timeouts, N real charges, none of
  them counted — and with no mandate configured, nothing else bounded it. The
  amount now stays reserved (counted, but reclaimable). Call
  `guard.releaseSpend(intentId)` when you can prove the rail did not charge; it
  cannot un-count a successful execution, so a mistaken call is safe.
- `policyWindows(policy)` derives rolling windows in one place, so the advisory
  pre-check and the authoritative reserve can never disagree about a cap.
- `FileConsumeStore` now uses the extracted `FileMutex` that `FileSpendLimiter`
  also uses. Same lock, one implementation — two copies of a subtle lock is how
  the two copies drift.
- The release gate discovered packages from a **hardcoded list**, so
  `@vaduno/postgres` would have shipped completely ungated while the gate
  reported success. Now discovered from the filesystem.

Additive otherwise: `history` still works as an advisory fast-fail, and code
that does not pass `limiter` behaves as before — single-process, as documented.

Tests 309 → 357, plus 40 more against real Postgres in CI.

## 0.1.1 — 2026-07-28

No code changed. `dist/` is byte-identical to 0.1.0. This release exists
because the *documentation* shipped inside the packages was wrong in ways a
reader could act on.

### Fixed

- **The quickstart taught the weaker merchant matcher.** `@vaduno/guard`'s
  README showed `merchants: { allow: ["openai", "anthropic", "aws"] }`. A bare
  token matches the **agent-supplied** `merchant.id`, which a compromised agent
  controls; a dotted pattern like `"openai.com"` matches the URL host, which it
  does not. Anyone who copy-pasted the old example got a policy weaker than
  they had reason to expect. The example now uses `["openai.com",
  "anthropic.com", "aws.amazon.com"]`, matching the demos.

- **"Never holds funds or keys" was imprecise everywhere it shipped** — in all
  five package descriptions and in the `@vaduno/guard`, `@vaduno/stripe` and
  `@vaduno/transparency` READMEs, which npm renders as the package pages. The
  accurate claim, which `SECURITY.md` has always made, is no keys **to funds**:
  no custody, no card PANs, no wallet or bank credentials. Mandates are signed
  with an Ed25519 key that belongs to the *issuer* and cannot move money — and a
  guard that only validates and consumes needs nothing but the public half. A
  total compromise of Vaduno still cannot originate a payment.

- **`@vaduno/stripe`'s README claimed the adapter was "test-mode-only".** It has
  never run against Stripe in *any* mode — not test, not live. Nothing in the
  package has contacted `api.stripe.com`; the decision path, signature check and
  deadline are verified against an in-process mock of the
  `issuing_authorization.request` webhook. The README now says so at the top,
  where someone deciding whether to trust it will actually see it.

- **`@vaduno/stripe`'s README told readers to size their handler against a
  2-second deadline.** Stripe's authorization window is ~2s, but the adapter's
  own `decisionTimeoutMs` defaults to **1300ms** so its fail-closed DECLINE
  lands *inside* that window instead of racing it. A handler tuned to 2s would
  be declined by the adapter first.

- **`@vaduno/guard`'s README misstated its own citation.** It read
  "prompt-injection attacks against commerce agents succeed in 86% of
  attempts". [WASP](https://arxiv.org/abs/2504.18575) measures **web** agents,
  reports attacks that ***partially*** succeed, and gives 86% as an ***upper
  bound***. Overstating the threat you exist to mitigate is not a harmless
  error. Corrected to match the root README.

- **`@vaduno/guard`'s README claimed a retry storm runs the rail "exactly
  once".** At most once. A denied or failed intent runs it zero times, and the
  weaker claim is the one that is always true.

- **`@vaduno/guard`'s README never mentioned that spend caps are
  per-instance.** It documented the cross-process `ConsumeStore` requirement
  for consume-once and stopped there, leaving a reader to assume rolling caps
  came along. They do not.

### Changed (repository only — not shipped in any package)

- `vitest` `^2.1.9` → `^3.2.6` across all five packages shipping then (the lockfile resolves
  3.2.7). This cleared **one** critical advisory, GHSA-5xrq-8626-4rwp —
  arbitrary file read/execute when the Vitest UI server is listening, never
  applicable here because the UI is never started. Dependabot counts it once
  per manifest, so it showed as six alerts; it is one advisory. A
  devDependency either way: consumers are unaffected.
- Added a **ConsumeStore conformance suite** (17 cases per store) so a
  Postgres/Redis implementation can be *verified* rather than merely typechecked.
  The interface is satisfied by an implementation that double-spends; that is
  the bug this project shipped once already. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Documented two limits in the README that previously lived only in
  `SECURITY.md`: rolling **spend caps are per-guard-instance and do not hold
  across processes** (only consume-once does, and only with a shared store),
  and the Stripe handler's fail-closed deadline is **1300ms**, not the "2
  seconds" previously claimed.
- Test count 275 → 309.

## 0.1.0 — 2026-07-28

First public release. Five packages:

- **`@vaduno/guard`** — the spend firewall: deterministic policy (rolling
  day/week/month caps, merchant allowlists, velocity limits, approval
  thresholds), signed consume-once mandates with idempotent replay, and a
  hash-chained audit ledger. Zero runtime dependencies.
- **`@vaduno/transparency`** — RFC 9162 Merkle transparency log with inclusion
  and consistency proofs, C2SP `tlog-checkpoint` signed notes, and k-of-n
  witness cosigning for non-equivocation.
- **`@vaduno/revocation`** — enforced kill switch: W3C Bitstring Status List
  credentials, fail-closed revocation checked at authorization time, agent-wide
  kill, and best-effort fan-out to rail-native revocation.
- **`@vaduno/x402`** — HTTP 402 stablecoin rail adapter.
- **`@vaduno/stripe`** — Stripe Issuing adapter; the guard answers
  `issuing_authorization.request` in real time. Never run against Stripe.

Published under the name Vaduno after two earlier names were withdrawn — the
npm name `paygent` was taken, and `swale` collided with a pending USPTO mark in
the exact classes this project occupies. `scripts/check-name.mjs` exists so it
does not happen a third time.
