import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLedger, GENESIS_HASH, type LedgerEntry } from "../src/ledger/ledger.js";
import { canonicalJson, sha256Hex } from "../src/ledger/hash.js";
import { JsonlLedgerStore } from "../src/ledger/stores/jsonl.js";

const dirs: string[] = [];
function tempFile(): string {
  const dir = mkdtempSync(join(tmpdir(), "vaduno-jsonl-"));
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

  it("detects a length-preserving tamper through the SAME store instance", async () => {
    const file = tempFile();
    const ledger = new AuditLedger(new JsonlLedgerStore(file));
    await ledger.append("policy_updated", { i: 0 });
    await ledger.append("policy_updated", { i: 1 });
    // First verify is green AND would warm any read cache the store kept.
    expect((await ledger.verify()).ok).toBe(true);

    // Mutate one byte WITHOUT changing the file's length: stat().size (and
    // any cache keyed on it) cannot tell the difference.
    const raw = readFileSync(file, "utf8");
    const tampered = raw.replace('"i":0', '"i":9');
    expect(tampered).not.toBe(raw);
    expect(Buffer.byteLength(tampered, "utf8")).toBe(Buffer.byteLength(raw, "utf8"));
    writeFileSync(file, tampered, "utf8");

    // Same AuditLedger + same store instance — no restart, no reopen.
    const verdict = await ledger.verify();
    expect(verdict.ok).toBe(false);
    expect(verdict.firstBadSeq).toBe(0);
  });

  it("verify(retainedHead) catches a length-preserving internally-consistent rewrite via the SAME instance", async () => {
    const file = tempFile();
    const ledger = new AuditLedger(new JsonlLedgerStore(file));
    await ledger.append("policy_updated", { i: 0 });
    await ledger.append("policy_updated", { i: 1 });
    const head = await ledger.head();
    expect((await ledger.verify(head)).ok).toBe(true); // warms any cache

    // Forge a full rewrite with correctly recomputed hashes: internally the
    // chain verifies, and because hex digests are fixed-width and the data
    // digits swap one-for-one, the file's byte length is unchanged.
    const raw = readFileSync(file, "utf8");
    let prevHash = GENESIS_HASH;
    const forged = raw
      .trim()
      .split("\n")
      .map((line) => {
        const { hash: _drop, ...rest } = JSON.parse(line) as LedgerEntry;
        rest.data = { i: ((rest.data as { i: number }).i + 5) % 10 };
        rest.prevHash = prevHash;
        prevHash = sha256Hex(canonicalJson(rest));
        return JSON.stringify({ ...rest, hash: prevHash });
      })
      .join("\n") + "\n";
    expect(Buffer.byteLength(forged, "utf8")).toBe(Buffer.byteLength(raw, "utf8"));
    writeFileSync(file, forged, "utf8");

    // The forgery is self-consistent, so plain verify() passes — the retained
    // head is the only thing standing between the operator and a rewrite...
    expect((await ledger.verify()).ok).toBe(true);
    // ...and it must not be defeated by a stale in-memory chain.
    const verdict = await ledger.verify(head);
    expect(verdict.ok).toBe(false);
    expect(verdict.problem).toMatch(/retained head/);
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
