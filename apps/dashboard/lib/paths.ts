import { join } from "node:path";

const dataDir = process.env.PAYGENT_DATA_DIR ?? join(process.cwd(), "data");

/** Path to the hash-chained audit ledger (JSONL). */
export const LEDGER_PATH = process.env.PAYGENT_LEDGER ?? join(dataDir, "ledger.jsonl");

/** Path to the shared approval queue (JSON). */
export const APPROVALS_PATH =
  process.env.PAYGENT_APPROVALS ?? join(dataDir, "approvals.json");
