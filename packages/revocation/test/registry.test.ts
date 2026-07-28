import { describe, expect, it } from "vitest";
import { AuditLedger, MemoryLedgerStore, generateMandateKeyPair } from "@swale/guard";
import {
  Bitstring,
  MemoryRevocationStore,
  RevocationRegistry,
  checkStatus,
  publishStatusList,
  type FanOutTarget,
} from "../src/index.js";

const keys = generateMandateKeyPair();

function setup(
  opts: { fanOut?: FanOutTarget[]; entries?: number; fanOutTimeoutMs?: number } = {},
) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const store = new MemoryRevocationStore();
  const registry = new RevocationRegistry({
    issuer: "prem@swale.dev",
    listId: "https://swale.example/status/1",
    privateKeyPem: keys.privateKeyPem,
    store,
    ledger,
    ...(opts.entries !== undefined ? { entries: opts.entries } : {}),
    ...(opts.fanOut ? { fanOut: opts.fanOut } : {}),
    ...(opts.fanOutTimeoutMs !== undefined ? { fanOutTimeoutMs: opts.fanOutTimeoutMs } : {}),
  });
  return { ledger, store, registry };
}

describe("RevocationRegistry", () => {
  it("assigns stable, sequential status-list indices", async () => {
    const { registry } = setup();
    const a = await registry.assignIndex("m-a", "agent-1");
    const b = await registry.assignIndex("m-b", "agent-1");
    expect(a).toBe(0);
    expect(b).toBe(1);
    // Idempotent: asking again returns the SAME index (a mandate's bit is fixed).
    expect(await registry.assignIndex("m-a", "agent-1")).toBe(0);
  });

  it("REGRESSION: assignIndex links the mandate to its agent, so revokeAgent finds it", async () => {
    // Previously assignIndex took no agentId and never linked, so an
    // agent-wide kill revoked ZERO mandates through the public API.
    const { registry } = setup();
    await registry.assignIndex("m-1", "agent-x");
    await registry.assignIndex("m-2", "agent-x");
    const results = await registry.revokeAgent("agent-x", { reason: "kill" });
    expect(results).toHaveLength(2);
    expect(await registry.isRevoked("m-1")).not.toBeNull();
    expect(await registry.isRevoked("m-2")).not.toBeNull();
  });

  it("REGRESSION: a HANGING fan-out rail cannot wedge later kills", async () => {
    // The critical finding: fan-out used to run inside the mutation queue, so
    // one unresponsive rail parked every subsequent revocation forever while
    // the guard kept authorizing.
    const hung: FanOutTarget = { rail: "hung-rail", revoke: () => new Promise<void>(() => {}) };
    const { registry } = setup({ fanOut: [hung], fanOutTimeoutMs: 50 });
    await registry.assignIndex("m-1", "rogue");
    await registry.assignIndex("m-2", "rogue");

    // First revoke returns promptly even though the rail never answers.
    await registry.revokeMandate("m-1");
    expect(await registry.isRevoked("m-1")).not.toBeNull();

    // The agent kill that follows must still land.
    const killed = await registry.revokeAgent("rogue", { reason: "compromised" });
    expect(killed.length).toBeGreaterThan(0);
    expect(await registry.isAgentBlocked("rogue")).toBe(true);
    expect(await registry.isRevoked("m-2")).not.toBeNull();
    // And the hung rail is reported as a timeout, not silently "ok".
    // (m-1 was already permanently revoked, so it correctly does NOT re-fan-out.)
    const fresh = killed.find((r) => r.record.mandateId === "m-2")!;
    const results = await fresh.fanOut;
    expect(results[0]!.ok).toBe(false);
    expect(results[0]!.error).toMatch(/timed out/);
  });

  it("REGRESSION: a full status list still revokes locally (flagged unpublishable)", async () => {
    // Previously this threw, leaving the mandate spendable.
    const { registry } = setup({ entries: 8 });
    for (let i = 0; i < 8; i++) await registry.assignIndex(`m-${i}`, "agent-1");
    const result = await registry.revokeMandate("m-overflow", { reason: "kill anyway" });
    expect(result.effectiveLocally).toBe(true);
    expect(result.unpublishable).toBe(true);
    expect(result.record.index).toBeNull();
    // Local enforcement still works — that is the part that stops spend.
    expect(await registry.isRevoked("m-overflow")).not.toBeNull();
  });

  it("agent-wide kills are visible to third-party verifiers in the published list", async () => {
    const { registry } = setup();
    const idx = await registry.assignIndex("m-1", "agent-x");
    await registry.revokeAgent("agent-x");
    const credential = await registry.publish(1);
    const check = checkStatus(credential, idx, {
      publicKeyPem: keys.publicKeyPem,
      expectedPurpose: "revocation",
    });
    expect(check.revoked).toBe(true);
  });

  it("an agent SUSPENSION is liftable; an agent REVOCATION is not", async () => {
    const { registry } = setup();
    await registry.revokeAgent("agent-s", { purpose: "suspension" });
    expect(await registry.isAgentBlocked("agent-s")).toBe(true);
    await registry.unblockAgent("agent-s");
    expect(await registry.isAgentBlocked("agent-s")).toBe(false);

    await registry.revokeAgent("agent-p");
    await expect(registry.unblockAgent("agent-p")).rejects.toThrow(/cannot be reinstated/);
    expect(await registry.isAgentBlocked("agent-p")).toBe(true);
  });

  it("publish() refuses a repeated or lower version", async () => {
    const { registry } = setup();
    await registry.publish(5);
    await expect(registry.publish(5)).rejects.toThrow(/strictly increase/);
    await expect(registry.publish(4)).rejects.toThrow(/strictly increase/);
    await expect(registry.publish(6)).resolves.toBeDefined();
  });

  it("hydrateFromLedger restores revocations, blocks, and index assignments", async () => {
    const { registry, ledger } = setup();
    const idx = await registry.assignIndex("m-1", "agent-x");
    await registry.revokeMandate("m-1", { reason: "compromised" });
    await registry.revokeAgent("agent-y", { reason: "leaked" });

    // "Restart": a brand-new registry over the SAME ledger.
    const fresh = new RevocationRegistry({
      issuer: "prem@swale.dev",
      listId: "https://swale.example/status/1",
      privateKeyPem: keys.privateKeyPem,
      store: new MemoryRevocationStore(),
      ledger,
    });
    expect(await fresh.isRevoked("m-1")).toBeNull(); // before hydrate
    await fresh.hydrateFromLedger();
    expect(await fresh.isRevoked("m-1")).not.toBeNull();
    expect(await fresh.isAgentBlocked("agent-y")).toBe(true);
    // The index is preserved, so bits are never recycled onto another mandate.
    expect(await fresh.assignIndex("m-1", "agent-x")).toBe(idx);
  });

  it("revokes a mandate with immediate local effect and audits it", async () => {
    const { registry, ledger } = setup();
    await registry.assignIndex("m-1", "agent-1");
    const result = await registry.revokeMandate("m-1", {
      reason: "agent compromised",
      by: "prem",
    });
    expect(result.effectiveLocally).toBe(true);
    expect(result.record.purpose).toBe("revocation");
    expect(await registry.isRevoked("m-1")).toMatchObject({
      mandateId: "m-1",
      reason: "agent compromised",
    });

    const types = (await ledger.all()).map((e) => e.type);
    expect(types).toContain("mandate_revoked");
  });

  it("is idempotent: re-revoking does not fan out twice", async () => {
    const calls: string[] = [];
    const fanOut: FanOutTarget[] = [
      {
        rail: "stripe-issuing",
        revoke: async (r) => {
          calls.push(r.mandateId);
        },
      },
    ];
    const { registry } = setup({ fanOut });
    await (await registry.revokeMandate("m-1")).fanOut;
    await (await registry.revokeMandate("m-1")).fanOut;
    expect(calls).toEqual(["m-1"]);
  });

  it("revokeAgent kills every mandate for that agent AND blocks future ones", async () => {
    const { registry } = setup();
    await registry.assignIndex("m-1", "agent-x");
    await registry.assignIndex("m-2", "agent-x");
    await registry.assignIndex("m-3", "agent-y");

    const results = await registry.revokeAgent("agent-x", { reason: "kill switch" });
    expect(results).toHaveLength(2);
    expect(await registry.isRevoked("m-1")).not.toBeNull();
    expect(await registry.isRevoked("m-2")).not.toBeNull();
    // A different agent's mandate is untouched.
    expect(await registry.isRevoked("m-3")).toBeNull();
    // And the agent itself is blocked, so a NEW mandate can't be used either.
    expect(await registry.isAgentBlocked("agent-x")).toBe(true);
    expect(await registry.isAgentBlocked("agent-y")).toBe(false);
  });

  it("a rail fan-out failure never un-revokes locally — it is recorded", async () => {
    const fanOut: FanOutTarget[] = [
      { rail: "stripe-issuing", revoke: async () => {} },
      {
        rail: "x402",
        revoke: async () => {
          throw new Error("rail API 503");
        },
      },
    ];
    const { registry, ledger } = setup({ fanOut });
    const result = await registry.revokeMandate("m-1");

    // Local kill stands regardless, and does not wait on the rails.
    expect(result.effectiveLocally).toBe(true);
    expect(await registry.isRevoked("m-1")).not.toBeNull();
    // The failure is visible, not swallowed.
    expect(await result.fanOut).toEqual([
      { rail: "stripe-issuing", ok: true },
      { rail: "x402", ok: false, error: "rail API 503" },
    ]);
    const fanoutEntry = (await ledger.all()).find((e) => e.type === "revocation_fanout");
    expect(fanoutEntry).toBeDefined();
  });

  it("suspension is reversible; permanent revocation is NOT", async () => {
    const { registry } = setup();
    await registry.revokeMandate("m-susp", { purpose: "suspension" });
    expect(await registry.isRevoked("m-susp")).toMatchObject({ purpose: "suspension" });
    await registry.unsuspendMandate("m-susp", "prem");
    expect(await registry.isRevoked("m-susp")).toBeNull();

    await registry.revokeMandate("m-perm");
    await expect(registry.unsuspendMandate("m-perm")).rejects.toThrow(/cannot be reinstated/);
    expect(await registry.isRevoked("m-perm")).not.toBeNull();
  });

  it("refuses to assign past the list capacity", async () => {
    const { registry } = setup({ entries: 8 });
    for (let i = 0; i < 8; i++) await registry.assignIndex(`m-${i}`, "agent-1");
    await expect(registry.assignIndex("m-overflow", "agent-1")).rejects.toThrow(
      /status list is full/,
    );
  });

  it("serializes concurrent revocations without losing any", async () => {
    const { registry } = setup();
    const ids = Array.from({ length: 12 }, (_, i) => `m-${i}`);
    await Promise.all(ids.map((id) => registry.revokeMandate(id)));
    const snap = await registry.snapshot();
    expect(snap.records).toHaveLength(12);
    // Every mandate got a DISTINCT bit — no index collision under concurrency.
    expect(new Set(snap.records.map((r) => r.index)).size).toBe(12);
  });
});

describe("published status list", () => {
  it("publishes a verifiable list where revoked bits read as revoked", async () => {
    const { registry } = setup();
    const idx1 = await registry.assignIndex("m-1", "agent-1");
    const idx2 = await registry.assignIndex("m-2", "agent-1");
    await registry.revokeMandate("m-2", { reason: "compromised" });

    const credential = await registry.publish(1);
    expect(credential.statusPurpose).toBe("revocation");
    expect(credential.version).toBe(1);

    // A third party with only the public key + credential can check status.
    const active = checkStatus(credential, idx1, { publicKeyPem: keys.publicKeyPem });
    expect(active).toMatchObject({ valid: true, revoked: false });

    const revoked = checkStatus(credential, idx2, { publicKeyPem: keys.publicKeyPem });
    expect(revoked).toMatchObject({ valid: false, revoked: true });
  });

  it("fails closed on a tampered list", async () => {
    const { registry } = setup();
    const idx = await registry.assignIndex("m-1", "agent-1");
    await registry.revokeMandate("m-1");
    const credential = await registry.publish(1);

    // Attacker rewrites the bitstring to clear the revocation, keeping the
    // old signature — the signature no longer covers the body.
    const clean = new Bitstring(credential.entries);
    const forged = { ...credential, encodedList: clean.encode() };
    const check = checkStatus(forged, idx, { publicKeyPem: keys.publicKeyPem });
    expect(check.valid).toBe(false);
    expect(check.code).toBe("SIGNATURE_INVALID");
  });

  it("an EXPIRED list is unavailable, never 'not revoked'", async () => {
    const bits = new Bitstring();
    const credential = publishStatusList(bits, {
      id: "list",
      issuer: "prem",
      statusPurpose: "revocation",
      privateKeyPem: keys.privateKeyPem,
      version: 1,
      ttlMs: 1000,
      now: () => new Date(0),
    });
    // Index 5 is NOT revoked, but the list is stale — must still fail closed.
    const check = checkStatus(credential, 5, {
      publicKeyPem: keys.publicKeyPem,
      now: () => new Date(60_000),
    });
    expect(check.valid).toBe(false);
    expect(check.revoked).toBe(false);
    expect(check.code).toBe("STATUS_LIST_EXPIRED");
  });

  it("rejects a wrong-purpose list and an under-minimum list", async () => {
    const small = new Bitstring(64);
    const credential = publishStatusList(small, {
      id: "list",
      issuer: "prem",
      statusPurpose: "suspension",
      privateKeyPem: keys.privateKeyPem,
      version: 1,
    });
    expect(
      checkStatus(credential, 1, {
        publicKeyPem: keys.publicKeyPem,
        expectedPurpose: "revocation",
      }).code,
    ).toBe("PURPOSE_MISMATCH");
    expect(
      checkStatus(credential, 1, { publicKeyPem: keys.publicKeyPem }).code,
    ).toBe("STATUS_LIST_LENGTH_ERROR");
  });

  it("an out-of-range index raises RANGE_ERROR (fail closed)", async () => {
    const { registry } = setup();
    const credential = await registry.publish(1);
    const check = checkStatus(credential, 999_999_999, {
      publicKeyPem: keys.publicKeyPem,
    });
    expect(check.valid).toBe(false);
    expect(check.code).toBe("RANGE_ERROR");
  });

  it("a list signed by the WRONG key does not verify", async () => {
    const attacker = generateMandateKeyPair();
    const credential = publishStatusList(new Bitstring(), {
      id: "list",
      issuer: "prem",
      statusPurpose: "revocation",
      privateKeyPem: attacker.privateKeyPem,
      version: 1,
    });
    expect(
      checkStatus(credential, 1, { publicKeyPem: keys.publicKeyPem }).code,
    ).toBe("SIGNATURE_INVALID");
  });
});
