-- Swale audit ledger table (see packages/guard SupabaseLedgerStore).
-- The hash chain is computed client-side; this table just persists it.
-- Verification (AuditLedger.verify) re-derives every hash, so tampering
-- with rows here is detectable by any reader.

-- NOTE: `timestamp` is TEXT, not timestamptz, on purpose. The hash commits to
-- the EXACT ISO string produced client-side; a timestamptz column would
-- reformat it on round-trip (e.g. "+00:00" vs "Z", microsecond padding),
-- making an honest ledger fail verify(). Store the exact bytes that were
-- hashed. Index/query on it as text, or add a separate generated timestamptz
-- column for range queries if needed.
create table if not exists swale_ledger (
  seq        bigint primary key,
  timestamp  text not null,
  type       text not null,
  intent_id  text,
  agent_id   text,
  data       jsonb not null,
  prev_hash  text not null,
  hash       text not null
);

create index if not exists swale_ledger_agent_time
  on swale_ledger (agent_id, timestamp);

create index if not exists swale_ledger_intent
  on swale_ledger (intent_id);

-- Recommended: enable RLS and allow INSERT + SELECT only (no UPDATE/DELETE),
-- so the ledger stays append-only even at the database layer.
alter table swale_ledger enable row level security;

create policy swale_ledger_insert on swale_ledger
  for insert to authenticated with check (true);

create policy swale_ledger_select on swale_ledger
  for select to authenticated using (true);

-- Intentionally NO update/delete policies: with RLS enabled and no policy,
-- update/delete are rejected for non-service-role clients.
