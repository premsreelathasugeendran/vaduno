import { afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoryApprovalStore } from "../src/approval/approval.js";
import { FileApprovalStore } from "../src/approval/file-store.js";
import { runApprovalStoreConformance } from "./approval-store-conformance.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

runApprovalStoreConformance({
  name: "MemoryApprovalStore",
  async create() {
    const store = new MemoryApprovalStore();
    // Same handle twice: in-memory is single-process by design; the
    // cross-handle probes still run, against shared state by identity.
    return { stores: [store, store] };
  },
});

runApprovalStoreConformance({
  name: "FileApprovalStore",
  async create() {
    const dir = mkdtempSync(join(tmpdir(), "vaduno-approval-conf-"));
    dirs.push(dir);
    const file = join(dir, "approvals.json");
    // TWO handles on the SAME file — the agent + dashboard topology this
    // store exists for, and the only shape that exercises the reload path.
    return { stores: [new FileApprovalStore(file), new FileApprovalStore(file)] };
  },
});
