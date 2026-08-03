/**
 * Two REAL OS processes, one jsonl path. The in-process conformance suite
 * (ledger-concurrency.conformance.test.ts) mints two store objects on one
 * path, which catches a queue that hides in the store object — but a lock
 * held in PROCESS memory (a module-level registry keyed by path, say) still
 * passes it while two workers on one box fork the file. Only real processes
 * close that door, the same way examples/cross-process-agent proves the
 * FileSpendLimiter.
 *
 * Workers rendezvous on a file barrier so their append bursts overlap by
 * construction, not by spawn-timing luck.
 */
import { afterEach, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditLedger } from "../src/ledger/ledger.js";
import { JsonlLedgerStore } from "../src/ledger/stores/jsonl.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = join(HERE, "fixtures", "ledger-xproc-worker.ts");
// npm hoists tsx to the workspace root; resolve it rather than guessing paths.
const TSX_CLI = createRequire(import.meta.url).resolve("tsx/cli");

const APPENDS_PER_WORKER = 12;

interface WorkerResult {
  name: string;
  appended: number;
  failed: number;
}

function runWorker(
  ledgerPath: string,
  barrierDir: string,
  name: string,
): Promise<WorkerResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [TSX_CLI, WORKER, ledgerPath, barrierDir, name, String(APPENDS_PER_WORKER)],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    let err = "";
    child.stdout.on("data", (c) => (out += c));
    child.stderr.on("data", (c) => (err += c));
    child.on("error", reject);
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

async function waitFor(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const dirs: string[] = [];
afterEach(async () => {
  while (dirs.length) await rm(dirs.pop()!, { recursive: true, force: true });
});

async function freshDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "vaduno-ledger-xproc-"));
  dirs.push(dir);
  return dir;
}

describe("jsonl ledger: two OS processes on one path", () => {
  it("SEQUENTIAL control: one process fully, then the other", { timeout: 60_000 }, async () => {
    // A naive implementation PASSES this — it exists to prove the harness
    // (spawn, barrier, tsx) is sound, so a concurrent failure below indicts
    // the append path and nothing else.
    const dir = await freshDir();
    const ledgerPath = join(dir, "ledger.jsonl");
    await writeFile(join(dir, "go"), ""); // barrier pre-released: no overlap
    const a = await runWorker(ledgerPath, dir, "worker-A");
    const b = await runWorker(ledgerPath, dir, "worker-B");
    expect(a.failed + b.failed).toBe(0);

    const entries = await new JsonlLedgerStore(ledgerPath).all();
    expect(entries.map((e) => e.seq)).toEqual(
      Array.from({ length: 2 * APPENDS_PER_WORKER }, (_, i) => i),
    );
    const verdict = await new AuditLedger(new JsonlLedgerStore(ledgerPath)).verify();
    expect(verdict.ok).toBe(true);
  });

  it("CONCURRENT: overlapping append bursts keep the chain linear", { timeout: 60_000 }, async () => {
    const dir = await freshDir();
    const ledgerPath = join(dir, "ledger.jsonl");

    const workers = Promise.all([
      runWorker(ledgerPath, dir, "worker-A"),
      runWorker(ledgerPath, dir, "worker-B"),
    ]);
    // Release the barrier only when BOTH processes are booted and waiting.
    await waitFor(
      () => existsSync(join(dir, "worker-A.ready")) && existsSync(join(dir, "worker-B.ready")),
      "both workers ready",
    );
    await writeFile(join(dir, "go"), "");
    const [a, b] = await workers;

    // Every append durably recorded — none dropped, none failed.
    expect(a.failed + b.failed).toBe(0);
    const entries = await new JsonlLedgerStore(ledgerPath).all();
    expect(entries).toHaveLength(2 * APPENDS_PER_WORKER);

    // No duplicate seq, no duplicate prevHash (two children of one parent is
    // a fork regardless of numbering).
    const seqs = entries.map((e) => e.seq);
    expect(new Set(seqs).size).toBe(seqs.length);
    const prevs = entries.map((e) => e.prevHash);
    expect(new Set(prevs).size).toBe(prevs.length);

    // And the chain still verifies from a process that never wrote.
    const verdict = await new AuditLedger(new JsonlLedgerStore(ledgerPath)).verify();
    expect(verdict.ok).toBe(true);
  });
});
