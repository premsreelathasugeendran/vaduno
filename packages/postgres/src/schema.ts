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
  -- Operator-controlled budget scope (the policy id). NEVER intent.agentId:
  -- the agent controls that field, so scoping a cap by it lets a compromised
  -- agent mint a fresh budget. That was a real bypass in 0.2.0.
  scope          TEXT   NOT NULL,
  currency       TEXT   NOT NULL,
  amount_minor   BIGINT NOT NULL,
  occurred_ms    BIGINT NOT NULL,
  state          TEXT   NOT NULL CHECK (state IN ('reserved', 'committed'))
);

-- The lookup every reserve() does: rows for one (scope, currency) inside a
-- time window.
CREATE INDEX IF NOT EXISTS vaduno_spend_scope
  ON vaduno_spend (scope, currency, occurred_ms);

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

-- Revocation: bit-index allocation, mandate records, agent-wide blocks.
--
-- The index is a bit position in a PUBLISHED W3C status list, so a duplicate
-- allocation is not an internal inconsistency — it means one revocation
-- silently revokes the wrong mandate, in a credential third parties read. The
-- UNIQUE constraint makes that unrepresentable rather than merely unlikely.
CREATE TABLE IF NOT EXISTS vaduno_revocation_index (
  mandate_id TEXT   PRIMARY KEY,
  idx        BIGINT NOT NULL,
  agent_id   TEXT,
  CONSTRAINT vaduno_revocation_index_unique UNIQUE (idx)
);

CREATE INDEX IF NOT EXISTS vaduno_revocation_index_agent
  ON vaduno_revocation_index (agent_id);

CREATE TABLE IF NOT EXISTS vaduno_revocation_record (
  mandate_id TEXT PRIMARY KEY,
  idx        BIGINT,
  purpose    TEXT NOT NULL,
  revoked_at TEXT NOT NULL,
  reason     TEXT,
  revoked_by TEXT,
  agent_id   TEXT
);

CREATE TABLE IF NOT EXISTS vaduno_agent_block (
  agent_id   TEXT PRIMARY KEY,
  reason     TEXT,
  blocked_by TEXT,
  blocked_at TEXT NOT NULL,
  purpose    TEXT NOT NULL
);
`;

/** Create both tables if they do not exist. Idempotent. */
export async function migrate(pool: PgPool): Promise<void> {
  await pool.query(VADUNO_SCHEMA_SQL);
}
