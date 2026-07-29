/**
 * Does a $50/day cap actually hold when you run two workers?
 *
 * This is not a unit test with two objects in one event loop — it spawns two
 * real OS processes, races them against one cap, and adds up what they spent.
 *
 * It runs the SAME race twice so the fix is demonstrated rather than asserted:
 *   1. isolated — each process has its own in-memory limiter (the default)
 *   2. shared   — both processes share one FileSpendLimiter
 *
 * Run 1 overspends. That is not a bug in the demo; it is what a per-instance
 * limiter means, and it is why the shared store exists.
 */
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = join(HERE, "worker.ts");
// Resolve tsx rather than assuming a path: npm hoists it to the workspace root,
// so examples/*/node_modules/tsx does not exist.
const TSX_CLI = createRequire(import.meta.url).resolve("tsx/cli");

const DAY_CAP_MINOR = 5_000; // $50.00
const AMOUNT_MINOR = 1_000; // $10.00 per payment
const ATTEMPTS_PER_WORKER = 5; // 2 workers x 5 x $10 = $100 attempted

const usd = (minor: number) => `$${(minor / 100).toFixed(2)}`;

interface WorkerResult {
  worker: string;
  executed: number;
  denied: number;
  spentMinor: number;
}

function runWorker(mode: string, stateDir: string, name: string): Promise<WorkerResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        TSX_CLI,
        WORKER,
        mode,
        stateDir,
        name,
        String(ATTEMPTS_PER_WORKER),
        String(AMOUNT_MINOR),
      ],
      { cwd: HERE, stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    let err = "";
    child.stdout.on("data", (c) => (out += c));
    child.stderr.on("data", (c) => (err += c));
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(`${name} exited ${code}: ${err}`));
      const line = out.trim().split("\n").filter(Boolean).pop() ?? "{}";
      try {
        resolve(JSON.parse(line) as WorkerResult);
      } catch {
        reject(new Error(`${name} produced unparseable output: ${out}\n${err}`));
      }
    });
  });
}

async function race(mode: "isolated" | "shared"): Promise<number> {
  const dir = await mkdtemp(join(tmpdir(), `vaduno-xproc-${mode}-`));
  try {
    // Both processes start at the same moment and race the same cap.
    const results = await Promise.all([
      runWorker(mode, dir, "worker-A"),
      runWorker(mode, dir, "worker-B"),
    ]);
    for (const r of results) {
      console.log(
        `    ${r.worker}: ${r.executed} executed, ${r.denied} denied  →  spent ${usd(r.spentMinor)}`,
      );
    }
    return results.reduce((sum, r) => sum + r.spentMinor, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

console.log(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Two processes. One $50/day cap. $100 of payments attempted.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

console.log(`
  1. Per-instance limiter (the default: each process has its own memory)
`);
const isolatedTotal = await race("isolated");
console.log(`
    TOTAL SPENT: ${usd(isolatedTotal)}  against a ${usd(DAY_CAP_MINOR)} cap`);
console.log(
  isolatedTotal > DAY_CAP_MINOR
    ? `    ❌ OVER the cap by ${usd(isolatedTotal - DAY_CAP_MINOR)} — two processes are two budgets.`
    : `    (no overspend this run — the race is timing-dependent)`,
);

console.log(`
  2. Shared FileSpendLimiter (one budget on disk, atomic reserve)
`);
const sharedTotal = await race("shared");
console.log(`
    TOTAL SPENT: ${usd(sharedTotal)}  against a ${usd(DAY_CAP_MINOR)} cap`);

if (sharedTotal > DAY_CAP_MINOR) {
  console.error(`    ❌ OVERSPEND — the cap did not hold. This is a bug.`);
  process.exit(1);
}
console.log(`    ✅ The cap held. Every payment past ${usd(DAY_CAP_MINOR)} was denied.`);

console.log(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  The difference is one constructor argument:

    new VadunoGuard({ policy, ledger,
      limiter: new FileSpendLimiter("./spend.json"),   // <- this
    })

  A FileSpendLimiter covers several processes on ONE box. For multiple
  instances, implement SpendLimiter against a database — the conformance
  suite in packages/guard/test/spend-limiter-conformance.ts will tell you
  whether you got the atomicity right. A check-then-act implementation
  passes every sequential test and fails only the concurrent ones.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`);
