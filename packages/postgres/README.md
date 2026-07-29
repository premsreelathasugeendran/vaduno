# @vaduno/postgres

**Spend caps and consume-once mandates that hold across multiple instances.**

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
import { PostgresSpendLimiter, PostgresConsumeStore, migrate } from "@vaduno/postgres";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await migrate(pool);   // idempotent; or paste VADUNO_SCHEMA_SQL into your migrations

const guard = new VadunoGuard({
  policy,
  ledger: new AuditLedger(new MemoryLedgerStore()),
  limiter: new PostgresSpendLimiter(pool),          // rolling caps, shared
  mandates: new MandateManager(keys, ledger, undefined, {
    consumeStore: new PostgresConsumeStore(pool),   // consume-once, shared
  }),
});
```

That is the whole change. Every instance pointed at the same database shares one
budget and one consume-once registry.

## Why an advisory lock

The dangerous shape is *read totals → decide → insert*, with anything at all in
between. Two instances both read "spent $0", both pass a $50 check, and the pair
spends $100. A `PRIMARY KEY` does not help: the two rows have different ids and
both inserts are perfectly legal.

So `reserve()` and `claim()` take `pg_advisory_xact_lock` on the scope — the
`(agent, currency)` pair, or the mandate id — as the first statement of a
transaction on a **dedicated pooled connection**. Everything after it is
serialized for that scope until commit. The window arithmetic itself is not
reimplemented in SQL; it calls the same `firstViolatedWindow` the in-memory and
file limiters use, so the implementations cannot drift on what a cap means.

The trade-off, stated plainly: reserves for one agent serialize. That is
deliberate — correctness over throughput on the path where being wrong means
spending someone's money twice. Different agents never contend.

## Verification

Both implementations are held to the conformance suites that ship with
`@vaduno/guard`, run against a real Postgres in CI — never a mock, because the
only property worth proving lives in the database.

The suites are worth running against your own store too, if you write one. They
are built around the observation that a check-then-act implementation passes
every sequential test and fails only the concurrent ones — which is exactly how
this class of bug reaches production.

```bash
VADUNO_TEST_POSTGRES_URL=postgres://... npm -w @vaduno/postgres run test
```

## Honest limitations

- **Nothing here has run in production.** It is verified by conformance suites
  against a real Postgres in CI, on Postgres 16. That is evidence, not a track
  record.
- **`migrate()` is deliberately minimal** — two `CREATE TABLE IF NOT EXISTS`
  statements and two indexes. It is not a migration framework and does not
  version anything. Use `VADUNO_SCHEMA_SQL` with your own tool if you have one.
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
