/**
 * Runs the shared ConsumeStore conformance suite against every store that
 * ships with the guard. A new store (Postgres, Redis, SQLite) should be added
 * here — or run the suite from its own repo. See CONTRIBUTING.md.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoryConsumeStore } from "../src/enforce/consume-store.js";
import { FileConsumeStore } from "../src/enforce/file-consume-store.js";
import { runConsumeStoreConformance } from "./consume-store-conformance.js";

// Single process by construction — supplies one handle, so the cross-process
// cases skip themselves rather than asserting a guarantee it never claimed.
runConsumeStoreConformance({
  name: "MemoryConsumeStore",
  async create() {
    return { stores: [new MemoryConsumeStore()] };
  },
});

// Two independent handles on one file stand in for two processes on one box.
runConsumeStoreConformance({
  name: "FileConsumeStore",
  async create() {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-conformance-"));
    const file = join(dir, "consume.json");
    return {
      stores: [new FileConsumeStore(file), new FileConsumeStore(file)],
      cleanup: () => rm(dir, { recursive: true, force: true }),
    };
  },
});
