# @vaduno/postgres

**Spend caps, consume-once mandates, and the audit ledger — all holding across multiple instances.**

[`@vaduno/guard`](https://www.npmjs.com/package/@vaduno/guard)'s default stores
are per-process. That is fine for one worker and wrong for a deployment: two
guard processes each enforcing a $50/day cap are two separate budgets, and the
pair spends $100. This package moves both budgets into Postgres so they hold
however many instances you run.

```bash
npm install @vaduno/postgres pg
```

`pg` is a peer dependency — you supply the pool.

## Use

```ts
import { Pool } from "pg";
import { VadunoGuard, AuditLedger, MemoryLedgerStore, MandateManager } from "@vaduno/guard";
import {
  PostgresSpendLimiter, PostgresConsumeStore, PostgresLedgerStore, migrate,
} from "@vaduno/postgres";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await migrate(pool);   // idempotent; or paste VADUNO_SCHEMA_SQL into your migrations

const guard = new VadunoGuard({
  policy,
  ledger: new AuditLedger(new PostgresLedgerStore(pool)),   // audit ledger, shared
  limiter: new PostgresSpendLimiter(pool),                  // rolling caps, shared
  mandates: new MandateManager(keys, ledger, undefined, {
    consumeStore: new PostgresConsumeStore(pool),           // consume-once, shared
  }),
});
```

That is the whole change. Every instance pointed at the same database shares one
budget, one consume-once registry, and one audit ledger.

Re-running `migrate(pool)` on an existing 0.3.0 database is safe and is the
upgrade path for per-merchant velocity windows: one idempotent
`ADD COLUMN IF NOT EXISTS merchant_key` on `vaduno_spend`. Existing rows stay
`NULL`, and a `NULL` row counts toward **every** merchant window until it ages
out — bounded over-hold instead of a velocity-free upgrade interval.

## The freeze that binds every instance (new in 0.3.0)

`PostgresFreezeStore` is the multi-instance backend for the shared emergency
freeze in [`@vaduno/revocation`](https://www.npmjs.com/package/@vaduno/revocation):

```ts
import { createFreezeCheck } from "@vaduno/revocation";
import { PostgresFreezeStore } from "@vaduno/postgres";

const freezeStore = new PostgresFreezeStore(pool);
const guard = new VadunoGuard({
  policy, ledger,
  revocationCheck: createFreezeCheck(freezeStore),
});

const { epoch } = await freezeStore.freeze("credentials leaked", "oncall");
// every instance's NEXT authorization denies GUARD_FROZEN
await freezeStore.unfreeze(epoch);   // compare-and-set; a stale epoch is refused
```

One global row; no advisory lock — the compare-and-set that fences unfreezes
**is** the SQL: `UPDATE … WHERE epoch = $expected` either matches exactly the
state the operator looked at or changes nothing. Fail-closed cuts both ways
and is deliberate: if this database is unreachable, **every payment on every
wired guard is denied** — the freeze store is a hard availability dependency.
See the availability discussion in the repo's SECURITY.md before wiring it.

## The ledger store (new in 0.3.0)

Until 0.3.0 this package shipped shared spend caps and shared consume-once but
**no shared ledger** — the one backend with real transactions was the one backend
the ledger could not use. `PostgresLedgerStore` closes that.

Correctness does not come from the TypeScript. It comes from two schema
constraints: `seq` PRIMARY KEY admits one row per position, and
`unique (prev_hash)` admits one child per parent. Together they make a forked
chain *unrepresentable* — even to a writer that bypasses this class entirely. A
losing concurrent writer gets SQLSTATE 23505, which is classified as contention
and answered with the real tip, so `AuditLedger` re-chains and retries rather
than dropping the entry. The hash chain itself stays client-side, so a
compromised database still cannot fabricate history.

## Why an advisory lock

The dangerous shape is *read totals → decide → insert*, with anything at all in
between. Two instances both read "spent $0", both pass a $50 check, and the pair
spends $100. A `PRIMARY KEY` does not help: the two rows have different ids and
both inserts are perfectly legal.

So `reserve()` and `claim()` take `pg_advisory_xact_lock` on the scope — the
`(scope, currency)` pair, or the mandate id — as the first statement of a
transaction on a **dedicated pooled connection**. Everything after it is
serialized for that scope until commit. The window arithmetic itself is not
reimplemented in SQL; it calls the same `firstViolatedWindow` the in-memory and
file limiters use, so the implementations cannot drift on what a cap means.

The trade-off, stated plainly: reserves for one scope serialize. That is
deliberate — correctness over throughput on the path where being wrong means
spending someone's money twice. Different scopes never contend.

## Verification

Both implementations are held to the conformance suites in the
[vaduno repo](https://github.com/premsreelathasugeendran/vaduno/tree/master/packages/guard/test),
run against a real Postgres in CI — never a mock, because the only property
worth proving lives in the database. (The suites are test files in the repo;
they are not published inside `@vaduno/guard`, which ships only `dist/`.)

The suites are worth running against your own store too, if you write one. They
are built around the observation that a check-then-act implementation passes
every sequential test and fails only the concurrent ones — which is exactly how
this class of bug reaches production.

From a clone of the repo:

```bash
VADUNO_TEST_POSTGRES_URL=postgres://... npm -w @vaduno/postgres run test
```

## Honest limitations

- **Nothing here has run in production.** It is verified by conformance suites
  against a real Postgres in CI, on Postgres 16. That is evidence, not a track
  record.
- **`PostgresLedgerStore` is new in 0.3.0 and its live evidence is one CI run
  old at best.** Its conformance suite is wired into the same CI job as the
  other two stores, but it is env-gated, so it skips on any machine without
  `VADUNO_TEST_POSTGRES_URL` — including every local run during its
  development. Its correctness argument rests on two Postgres constraints
  rather than on observed behavior. Weigh it accordingly, and check that the
  CI postgres job is green for the commit you are installing.
- **`PostgresFreezeStore` has NOT been exercised against a live database on
  the machine it was written on.** Like every store here its conformance
  suite is env-gated on `VADUNO_TEST_POSTGRES_URL`; the Memory and File
  freeze backends run the identical suite on every test run, and the
  Postgres backend's correctness argument is one atomic
  `UPDATE … WHERE epoch = $expected` statement. Check the CI postgres job
  for the commit you install.
- **`migrate()` is deliberately minimal** — a handful of
  `CREATE TABLE IF NOT EXISTS` statements and indexes. It is not a migration
  framework and does not version anything. Use `VADUNO_SCHEMA_SQL` with your
  own tool if you have one. 0.3.0 adds the `vaduno_freeze` table.
- **Old rows are never pruned.** A reservation outside every window stops
  counting but stays on disk. Add your own retention job.
- **`amount_minor` is `BIGINT`** and comes back from node-postgres as a string;
  it is parsed strictly and throws rather than admitting a `NaN` into a budget
  check. Amounts must be safe integers in minor units.
- **Advisory locks are per-database**, so two logically separate deployments
  sharing one database will contend on the same scope keys. Give them separate
  databases.
- **Vaduno never holds funds, keys to funds, or card PANs.** This package stores
  amounts and identifiers only — no credentials and no card data.

## License

MIT
