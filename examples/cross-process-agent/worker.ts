/**
 * One worker process. Spawned twice by demo.ts, both racing the same daily cap.
 *
 * argv: <mode: shared|isolated> <stateDir> <workerName> <attempts> <amountMinor>
 *
 * "shared"   — both workers use a FileSpendLimiter over one file: ONE budget.
 * "isolated" — each worker uses its own MemorySpendLimiter: TWO budgets, which
 *              is what a per-instance limiter actually gives you.
 */
import { join } from "node:path";
import {
  AuditLedger,
  MemoryLedgerStore,
  VadunoGuard,
  FileSpendLimiter,
  MemorySpendLimiter,
  type SpendLimiter,
} from "@vaduno/guard";

const [, , mode, stateDir, workerName, attemptsRaw, amountRaw] = process.argv;
const attempts = Number(attemptsRaw);
const amountMinor = Number(amountRaw);

const DAY_CAP_MINOR = 5_000; // $50.00

const limiter: SpendLimiter =
  mode === "shared"
    ? new FileSpendLimiter(join(stateDir, "spend.json"))
    : new MemorySpendLimiter();

const guard = new VadunoGuard({
  policy: {
    id: "cross-process-demo",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 2_000, perDayMinor: DAY_CAP_MINOR },
    merchants: { allow: ["openai.com"] },
  },
  ledger: new AuditLedger(new MemoryLedgerStore()),
  limiter,
});

let executed = 0;
let denied = 0;
let spentMinor = 0;

// Fire every attempt concurrently — this is a race, not a queue.
await Promise.all(
  Array.from({ length: attempts }, async (_, i) => {
    const result = await guard.execute(
      {
        id: `${workerName}-intent-${i}`,
        agentId: "shopper-agent",
        merchant: { id: "openai", url: "https://api.openai.com" },
        amount: { amountMinor, currency: "USD" },
        rail: "x402",
        requestedAt: new Date().toISOString(),
      },
      async () => ({ receipt: `${workerName}-${i}` }),
    );
    if (result.status === "executed") {
      executed += 1;
      spentMinor += amountMinor;
    } else {
      denied += 1;
    }
  }),
);

process.stdout.write(
  JSON.stringify({ worker: workerName, executed, denied, spentMinor }) + "\n",
);
