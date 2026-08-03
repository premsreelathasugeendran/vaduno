/**
 * One writer PROCESS for the cross-process ledger test. Spawned twice by
 * ledger-cross-process.jsonl.test.ts, both appending to one jsonl path — the
 * exact topology the in-process conformance suite can only imitate.
 *
 * argv: <ledgerPath> <barrierDir> <name> <count>
 *
 * Barrier protocol: write `<name>.ready`, then wait for `go`. The parent
 * releases `go` only once BOTH workers are ready, so the append bursts
 * genuinely overlap instead of depending on process spawn timing.
 */
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AuditLedger } from "../../src/ledger/ledger.js";
import { JsonlLedgerStore } from "../../src/ledger/stores/jsonl.js";

const [, , ledgerPath, barrierDir, name, countRaw] = process.argv;
const count = Number(countRaw);

const ledger = new AuditLedger(new JsonlLedgerStore(ledgerPath!));

writeFileSync(join(barrierDir!, `${name}.ready`), "");
while (!existsSync(join(barrierDir!, "go"))) {
  // 2ms poll: tight enough that both workers leave the barrier within one
  // scheduler tick of each other, loose enough not to peg a core while the
  // sibling process boots.
  await new Promise((resolve) => setTimeout(resolve, 2));
}

let appended = 0;
let failed = 0;
await Promise.all(
  Array.from({ length: count }, async (_, i) => {
    try {
      await ledger.append("policy_decision", { writer: name, i });
      appended += 1;
    } catch {
      failed += 1;
    }
  }),
);

process.stdout.write(JSON.stringify({ name, appended, failed }) + "\n");
