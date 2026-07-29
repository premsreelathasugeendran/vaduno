# Changelog

All five packages are versioned together and released as a matched set.

This project is pre-1.0. Under semver, 0.x minor bumps may break the API, and
two have already done so — both times because review found a real security bug
whose fix was breaking. See [`SECURITY.md`](SECURITY.md) for what is and isn't
guaranteed.

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

- `vitest` `^2.1.9` → `^3.2.6` across all five packages (the lockfile resolves
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
