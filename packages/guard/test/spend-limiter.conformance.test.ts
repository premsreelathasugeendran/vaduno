/**
 * Runs the shared SpendLimiter conformance suite against every limiter that
 * ships with the guard. A new limiter (Postgres, Redis, SQLite) should be
 * added here — or run the suite from its own repo. See CONTRIBUTING.md.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemorySpendLimiter } from "../src/enforce/spend-limiter.js";
import { FileSpendLimiter } from "../src/enforce/file-spend-limiter.js";
import { runSpendLimiterConformance } from "./spend-limiter-conformance.js";

// Single process by construction — one handle, so the cross-process cases skip
// themselves rather than asserting a guarantee this limiter never claimed.
runSpendLimiterConformance({
  name: "MemorySpendLimiter",
  async create() {
    return { limiters: [new MemorySpendLimiter()] };
  },
});

// Two independent handles on one file stand in for two processes on one box.
runSpendLimiterConformance({
  name: "FileSpendLimiter",
  async create() {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-limiter-"));
    const file = join(dir, "spend.json");
    return {
      limiters: [new FileSpendLimiter(file), new FileSpendLimiter(file)],
      cleanup: () => rm(dir, { recursive: true, force: true }),
    };
  },
});
