import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLedger } from "../src/ledger/ledger.js";
import { JsonlLedgerStore } from "../src/ledger/stores/jsonl.js";

const dirs: string[] = [];
function tempFile(): string {
  const dir = mkdtempSync(join(tmpdir(), "swale-jsonl-"));
  dirs.push(dir);
  return join(dir, "ledger.jsonl");
}

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("JsonlLedgerStore", () => {
  it("round-trips through disk and verifies from a fresh instance", async () => {
    const file = tempFile();
    const ledger = new AuditLedger(new JsonlLedgerStore(file));
    await ledger.append("intent_received", { note: "héllo → 世界" }, { intentId: "i1", agentId: "g" });
    await ledger.append("policy_decision", { ok: true }, { intentId: "i1", agentId: "g" });
    await ledger.append("execution_result", { success: true, amountMinor: 100, currency: "USD" }, { intentId: "i1", agentId: "g" });

    const reopened = new AuditLedger(new JsonlLedgerStore(file));
    const verdict = await reopened.verify();
    expect(verdict.ok).toBe(true);
    expect(verdict.entries).toBe(3);
    expect((await reopened.all()).length).toBe(3);
  });

  it("detects a mutated line from disk", async () => {
    const file = tempFile();
    const ledger = new AuditLedger(new JsonlLedgerStore(file));
    await ledger.append("policy_updated", { i: 0 });
    await ledger.append("policy_updated", { i: 1 });

    const lines = readFileSync(file, "utf8").trim().split("\n");
    const first = JSON.parse(lines[0]!);
    first.data = { i: 999 }; // tamper, but keep the (now-stale) hash
    lines[0] = JSON.stringify(first);
    writeFileSync(file, lines.join("\n") + "\n", "utf8");

    const verdict = await new AuditLedger(new JsonlLedgerStore(file)).verify();
    expect(verdict.ok).toBe(false);
    expect(verdict.firstBadSeq).toBe(0);
  });

  it("reloads when a second instance appended to the same file", async () => {
    const file = tempFile();
    const a = new JsonlLedgerStore(file);
    const ledgerA = new AuditLedger(a);
    await ledgerA.append("policy_updated", { i: 0 });

    // A different instance/process appends to the same file.
    const ledgerB = new AuditLedger(new JsonlLedgerStore(file));
    await ledgerB.append("policy_updated", { i: 1 });

    // `a` must observe the external write and extend the real chain, not fork.
    await ledgerA.append("policy_updated", { i: 2 });
    const verdict = await new AuditLedger(new JsonlLedgerStore(file)).verify();
    expect(verdict.ok).toBe(true);
    expect(verdict.entries).toBe(3);
  });
});
