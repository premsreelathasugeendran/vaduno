import type { PgPool } from "./pg.js";

/**
 * DDL for every store in this package. Idempotent — safe to run on every boot.
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
  -- merchantKeyOf() key, for per-merchant velocity windows. NULL means the
  -- row predates merchant attribution and counts toward EVERY merchant.
  merchant_key   TEXT,
  state          TEXT   NOT NULL CHECK (state IN ('reserved', 'committed'))
);

-- The lookup every reserve() does: rows for one (scope, currency) inside a
-- time window.
CREATE INDEX IF NOT EXISTS vaduno_spend_scope
  ON vaduno_spend (scope, currency, occurred_ms);

-- Merchant attribution for per-merchant velocity windows (merchantKeyOf()).
-- Nullable BY DESIGN: rows written before this column existed are NULL, and a
-- NULL row counts toward EVERY merchant window — bounded over-hold instead of
-- a velocity-free upgrade interval. Idempotent, safe over existing rows.
ALTER TABLE vaduno_spend ADD COLUMN IF NOT EXISTS merchant_key TEXT;

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

-- Emergency-freeze state: ONE global row per database (id is constrained to
-- 1). The compare-and-set that fences unfreezes lives in the statement, not
-- in a lock: UPDATE ... WHERE epoch = $expected either matches exactly the
-- state the operator looked at, or matches nothing and changes nothing.
-- epoch is monotonic — every freeze and every applied unfreeze bumps it.
CREATE TABLE IF NOT EXISTS vaduno_freeze (
  id        INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  epoch     BIGINT  NOT NULL,
  frozen    BOOLEAN NOT NULL,
  reason    TEXT,
  frozen_by TEXT,
  frozen_at TEXT
);

-- Audit ledger. The hash chain is computed CLIENT-SIDE (AuditLedger in
-- @vaduno/guard) — this table persists it, and its two uniqueness rules ARE
-- the compare-and-append: the primary key admits one row per position, the
-- unique index admits one CHILD per PARENT. A fork is unrepresentable at the
-- database even to a buggy or hostile client; a losing concurrent writer gets
-- SQLSTATE 23505 and retries onto the real tip. Genesis (prev_hash = 64
-- zeros) appears exactly once, which is correct.
--
-- "timestamp" is TEXT, not timestamptz, on purpose: the hash commits to the
-- EXACT ISO string produced client-side, and a timestamptz column reformats
-- on round-trip ('+00:00' vs 'Z', microsecond padding), making an honest
-- ledger fail verify(). Store the bytes that were hashed.
CREATE TABLE IF NOT EXISTS vaduno_ledger (
  seq        BIGINT PRIMARY KEY,
  timestamp  TEXT   NOT NULL,
  type       TEXT   NOT NULL,
  intent_id  TEXT,
  agent_id   TEXT,
  data       JSONB  NOT NULL,
  prev_hash  TEXT   NOT NULL,
  hash       TEXT   NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS vaduno_ledger_prev_hash_key
  ON vaduno_ledger (prev_hash);

CREATE INDEX IF NOT EXISTS vaduno_ledger_intent
  ON vaduno_ledger (intent_id);
`;

/** Create every table if it does not exist. Idempotent. */
export async function migrate(pool: PgPool): Promise<void> {
  await pool.query(VADUNO_SCHEMA_SQL);
}
