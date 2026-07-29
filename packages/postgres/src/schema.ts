import type { PgPool } from "./pg.js";

/**
 * DDL for both stores. Idempotent — safe to run on every boot.
 *
 * Exported as a string so it can also be pasted into a migration tool; nothing
 * here requires being run by this package.
 */
export const VADUNO_SCHEMA_SQL = `
-- Rolling spend, reserved and committed. A "reserved" row counts against every
-- cap exactly like a committed one: over-hold, never overspend.
CREATE TABLE IF NOT EXISTS vaduno_spend (
  reservation_id TEXT PRIMARY KEY,
  agent_id       TEXT   NOT NULL,
  currency       TEXT   NOT NULL,
  amount_minor   BIGINT NOT NULL,
  occurred_ms    BIGINT NOT NULL,
  state          TEXT   NOT NULL CHECK (state IN ('reserved', 'committed'))
);

-- The lookup every reserve() does: rows for one (agent, currency) inside a
-- time window.
CREATE INDEX IF NOT EXISTS vaduno_spend_scope
  ON vaduno_spend (agent_id, currency, occurred_ms);

-- Consume-once registry. The PRIMARY KEY is the uniqueness half of the
-- contract; the advisory lock in claim() is the budget half.
CREATE TABLE IF NOT EXISTS vaduno_consume (
  mandate_id    TEXT NOT NULL,
  use_key       TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  claimed_at    TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('pending', 'settled')),
  outcome       JSONB,
  PRIMARY KEY (mandate_id, use_key)
);

CREATE INDEX IF NOT EXISTS vaduno_consume_mandate
  ON vaduno_consume (mandate_id);
`;

/** Create both tables if they do not exist. Idempotent. */
export async function migrate(pool: PgPool): Promise<void> {
  await pool.query(VADUNO_SCHEMA_SQL);
}
