import { describe, expect, it, vi } from "vitest";
import {
  AuditLedger,
  MandateManager,
  MemoryLedgerStore,
  PaygentGuard,
  generateMandateKeyPair,
  type PaymentIntent,
  type SpendPolicy,
} from "@paygent/guard";
import {
  Bitstring,
  MemoryRevocationStore,
  RevocationRegistry,
  allChecks,
  createRegistryCheck,
  createStatusListCheck,
  publishStatusList,
  type StatusListCredential,
} from "../src/index.js";

const keys = generateMandateKeyPair();

function policy(over: Partial<SpendPolicy> = {}): SpendPolicy {
  return {
    id: "p",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 5_000, perDayMinor: 50_000 },
    ...over,
  };
}

let seq = 0;
function intent(over: Partial<PaymentIntent> = {}): PaymentIntent {
  seq += 1;
  return {
    id: `intent-${seq}`,
    agentId: "agent-1",
    merchant: { id: "openai", url: "https://api.openai.com" },
    amount: { amountMinor: 500, currency: "USD" },
    rail: "mock",
    requestedAt: new Date().toISOString(),
    ...over,
  };
}

function setup(extra: Partial<ConstructorParameters<typeof PaygentGuard>[0]> = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const store = new MemoryRevocationStore();
  const mandates = new MandateManager(keys, ledger);
  const registry = new RevocationRegistry({
    issuer: "prem",
    listId: "https://paygent.example/status/1",
    privateKeyPem: keys.privateKeyPem,
    store,
    ledger,
  });
  const guard = new PaygentGuard({
    policy: policy(),
    ledger,
    mandates,
    revocationCheck: createRegistryCheck(registry),
    ...extra,
  });
  return { ledger, store, registry, guard, mandates };
}

/** Issue a real mandate and register it via the registry's PUBLIC api. */
async function issue(
  mandates: MandateManager,
  registry: RevocationRegistry,
  agentId = "agent-1",
  maxUses = 10,
) {
  const mandate = await mandates.issue({
    issuer: "prem",
    agentId,
    constraints: {
      maxAmountMinor: 5_000,
      currency: "USD",
      validFrom: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
      maxUses,
    },
  });
  await registry.assignIndex(mandate.id, agentId);
  return mandate;
}

describe("revocation is ENFORCED at authorization time", () => {
  it("a revoked mandate cannot spend again", async () => {
    const { registry, store, guard, mandates } = setup();
    const mandate = await issue(mandates, registry);

    const before = await guard.execute(intent({ mandateId: mandate.id }), async () => "ok");
    expect(before.status).toBe("executed");

    await registry.revokeMandate(mandate.id, { reason: "compromised" });

    let ran = false;
    const after = await guard.execute(intent({ mandateId: mandate.id }), async () => {
      ran = true;
      return "ok";
    });
    expect(ran).toBe(false);
    expect(after.status).toBe("denied");
    if (after.status !== "denied") throw new Error("unreachable");
    expect(after.policyResult.reasons.some((r) => r.code === "MANDATE_REVOKED")).toBe(true);
  });

  it("revoking an AGENT stops every payment from it, including new mandates", async () => {
    const { registry, store, guard, mandates } = setup();
    await registry.revokeAgent("agent-1", { reason: "kill switch" });

    // A mandate issued AFTER the kill (e.g. by a stale issuer) is still dead,
    // because the agent itself is blocked.
    const fresh = await issue(mandates, registry);
    let ran = false;
    const result = await guard.execute(intent({ mandateId: fresh.id }), async () => {
      ran = true;
      return "ok";
    });
    expect(ran).toBe(false);
    expect(result.status).toBe("denied");
    if (result.status !== "denied") throw new Error("unreachable");
    expect(result.policyResult.reasons.some((r) => r.code === "AGENT_REVOKED")).toBe(true);

    // A different agent still works (no mandate needed — none is attached).
    const other = await guard.execute(intent({ agentId: "agent-2" }), async () => "ok");
    expect(other.status).toBe("executed");
  });

  it("THE RACE: revocation during a pending human approval still wins", async () => {
    // The approval blocks; we revoke while it is pending. Because the guard
    // re-checks revocation INSIDE the critical section (after approval), the
    // kill switch must beat the approval that was granted moments earlier.
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const store = new MemoryRevocationStore();
    const mandates = new MandateManager(keys, ledger);
    const registry = new RevocationRegistry({
      issuer: "prem",
      listId: "l",
      privateKeyPem: keys.privateKeyPem,
      store,
      ledger,
    });
    const mandate = await issue(mandates, registry);

    let releaseApproval: (() => void) | undefined;
    const approvalGate = new Promise<void>((resolve) => {
      releaseApproval = resolve;
    });

    const guard = new PaygentGuard({
      policy: policy({ approval: { always: true } }),
      ledger,
      mandates,
      revocationCheck: createRegistryCheck(registry),
      approvalHandler: async () => {
        await approvalGate;
        return { approved: true, approver: "prem" };
      },
    });

    let ran = false;
    const pending = guard.execute(intent({ mandateId: mandate.id }), async () => {
      ran = true;
      return "ok";
    });

    // Operator pulls the kill switch while the human is still deciding.
    await registry.revokeMandate(mandate.id, { reason: "kill switch mid-approval" });
    releaseApproval!();

    const result = await pending;
    expect(ran).toBe(false);
    expect(result.status).toBe("denied");
    if (result.status !== "denied") throw new Error("unreachable");
    expect(result.policyResult.reasons.some((r) => r.code === "MANDATE_REVOKED")).toBe(true);
  });

  it("a suspended mandate is denied, and works again once lifted", async () => {
    const { registry, store, guard, mandates } = setup();
    const mandate = await issue(mandates, registry);
    await registry.revokeMandate(mandate.id, { purpose: "suspension" });

    const denied = await guard.execute(intent({ mandateId: mandate.id }), async () => "ok");
    expect(denied.status).toBe("denied");
    if (denied.status !== "denied") throw new Error("unreachable");
    expect(denied.policyResult.reasons.some((r) => r.code === "MANDATE_SUSPENDED")).toBe(true);

    await registry.unsuspendMandate(mandate.id);
    const allowed = await guard.execute(intent({ mandateId: mandate.id }), async () => "ok");
    expect(allowed.status).toBe("executed");
  });

  it("FAILS CLOSED when the registry cannot answer (outage != not revoked)", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const guard = new PaygentGuard({
      policy: policy(),
      ledger,
      revocationCheck: async () => {
        throw new Error("registry unreachable");
      },
    });
    let ran = false;
    const result = await guard.execute(intent(), async () => {
      ran = true;
      return "ok";
    });
    expect(ran).toBe(false);
    expect(result.status).toBe("denied");
    if (result.status !== "denied") throw new Error("unreachable");
    expect(
      result.policyResult.reasons.some((r) => r.code === "REVOCATION_CHECK_FAILED"),
    ).toBe(true);
  });

  it("revocation composes with mandate consume-once (both gates apply)", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const mandates = new MandateManager(keys, ledger);
    const store = new MemoryRevocationStore();
    const registry = new RevocationRegistry({
      issuer: "prem",
      listId: "l",
      privateKeyPem: keys.privateKeyPem,
      store,
      ledger,
    });
    const guard = new PaygentGuard({
      policy: policy(),
      ledger,
      mandates,
      revocationCheck: createRegistryCheck(registry),
    });
    const mandate = await mandates.issue({
      issuer: "prem",
      agentId: "agent-1",
      constraints: {
        maxAmountMinor: 5_000,
        currency: "USD",
        validFrom: new Date(Date.now() - 1000).toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        maxUses: 5,
      },
    });
    await registry.assignIndex(mandate.id, "agent-1");

    expect(
      (await guard.execute(intent({ mandateId: mandate.id }), async () => "ok")).status,
    ).toBe("executed");

    await registry.revokeMandate(mandate.id);

    const after = await guard.execute(
      intent({ mandateId: mandate.id }),
      async () => "ok",
    );
    expect(after.status).toBe("denied");
    if (after.status !== "denied") throw new Error("unreachable");
    // Revocation is checked BEFORE the mandate is consumed, so a revoked
    // mandate does not burn a use.
    expect(after.policyResult.reasons.some((r) => r.code === "MANDATE_REVOKED")).toBe(true);
  });
});

describe("createStatusListCheck — third-party verifier side", () => {
  function makeList(revokedIndices: number[], version: number, now?: () => Date) {
    const bits = new Bitstring();
    for (const i of revokedIndices) bits.set(i, true);
    return publishStatusList(bits, {
      id: "https://paygent.example/status/1",
      issuer: "prem",
      statusPurpose: "revocation",
      privateKeyPem: keys.privateKeyPem,
      version,
      ...(now ? { now } : {}),
    });
  }

  it("allows an active entry and denies a revoked one", async () => {
    const check = createStatusListCheck({
      fetchList: async () => makeList([7], 1),
      publicKeyPem: keys.publicKeyPem,
      indexFor: (i) => (i.mandateId === "revoked" ? 7 : 3),
    });
    expect(await check(intent({ mandateId: "active" }))).toEqual({ allowed: true });
    const denied = await check(intent({ mandateId: "revoked" }));
    expect(denied.allowed).toBe(false);
    if (denied.allowed) throw new Error("unreachable");
    expect(denied.code).toBe("MANDATE_REVOKED");
  });

  it("fails closed when the list cannot be fetched", async () => {
    const check = createStatusListCheck({
      fetchList: async () => {
        throw new Error("network down");
      },
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 1,
    });
    const verdict = await check(intent());
    expect(verdict.allowed).toBe(false);
    if (verdict.allowed) throw new Error("unreachable");
    expect(verdict.code).toBe("STATUS_RETRIEVAL_ERROR");
  });

  it("fails closed when a mandate has no assigned index", async () => {
    const check = createStatusListCheck({
      fetchList: async () => makeList([], 1),
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => undefined,
    });
    const verdict = await check(intent());
    expect(verdict.allowed).toBe(false);
    if (verdict.allowed) throw new Error("unreachable");
    expect(verdict.code).toBe("NO_STATUS_INDEX");
  });

  it("rejects a ROLLED-BACK list (replay of a pre-revocation snapshot)", async () => {
    const fresh = makeList([7], 5); // v5: index 7 revoked
    const stale = makeList([], 4); // v4: index 7 still clean — attacker replay
    let serve: StatusListCredential = fresh;
    const check = createStatusListCheck({
      fetchList: async () => serve,
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 7,
    });
    // First observation pins version 5 and denies (revoked).
    const first = await check(intent());
    expect(first.allowed).toBe(false);

    // Attacker now serves the older, still-signed, still-fresh v4.
    serve = stale;
    const replay = await check(intent());
    expect(replay.allowed).toBe(false);
    if (replay.allowed) throw new Error("unreachable");
    expect(replay.code).toBe("STATUS_LIST_ROLLBACK");
  });

  it("REGRESSION: a sibling SUSPENSION list cannot substitute for the revocation list", async () => {
    // The purpose gate used to be `expectedPurpose: credential.statusPurpose`
    // — a tautology. An attacker served the issuer's own suspension list
    // (same key, same id, revocation bits clear) and every permanently
    // revoked mandate read as active.
    const bits = new Bitstring(); // no bits set
    const siblingSuspensionList = publishStatusList(bits, {
      id: "https://paygent.example/status/1", // SAME id
      issuer: "prem", // SAME issuer
      statusPurpose: "suspension", // different purpose
      privateKeyPem: keys.privateKeyPem, // SAME key — signature is genuine
      version: 9,
    });
    const check = createStatusListCheck({
      fetchList: async () => siblingSuspensionList,
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 7,
      expectedPurpose: "revocation",
      expectedListId: "https://paygent.example/status/1",
      expectedIssuer: "prem",
    });
    const verdict = await check(intent());
    expect(verdict.allowed).toBe(false);
    if (verdict.allowed) throw new Error("unreachable");
    expect(verdict.code).toBe("STATUS_PURPOSE_MISMATCH");
  });

  it("REGRESSION: a list from another id/issuer is rejected even with a valid signature", async () => {
    const foreign = publishStatusList(new Bitstring(), {
      id: "https://paygent.example/status/OTHER",
      issuer: "prem",
      statusPurpose: "revocation",
      privateKeyPem: keys.privateKeyPem,
      version: 3,
    });
    const check = createStatusListCheck({
      fetchList: async () => foreign,
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 1,
      expectedListId: "https://paygent.example/status/1",
      expectedIssuer: "prem",
    });
    const verdict = await check(intent());
    expect(verdict.allowed).toBe(false);
    if (verdict.allowed) throw new Error("unreachable");
    expect(verdict.code).toBe("STATUS_LIST_MISMATCH");
  });

  it("REGRESSION: a DIFFERENT list at the SAME version is rejected", async () => {
    // A `<`-only floor waved same-version snapshots through.
    const revoked = makeList([7], 5);
    const clean = makeList([], 5); // same version, different bytes
    let serve = revoked;
    const check = createStatusListCheck({
      fetchList: async () => serve,
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 7,
    });
    expect((await check(intent())).allowed).toBe(false); // pins v5
    serve = clean;
    const replay = await check(intent());
    expect(replay.allowed).toBe(false);
    if (replay.allowed) throw new Error("unreachable");
    expect(replay.code).toBe("STATUS_LIST_ROLLBACK");
  });

  it("REGRESSION: a future-dated list is rejected (cannot poison the version floor)", async () => {
    const future = publishStatusList(new Bitstring(), {
      id: "l",
      issuer: "prem",
      statusPurpose: "revocation",
      privateKeyPem: keys.privateKeyPem,
      version: 999_999,
      now: () => new Date(Date.now() + 86_400_000),
    });
    const check = createStatusListCheck({
      fetchList: async () => future,
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 1,
    });
    const verdict = await check(intent());
    expect(verdict.allowed).toBe(false);
    if (verdict.allowed) throw new Error("unreachable");
    expect(verdict.code).toBe("STATUS_STATUS_LIST_NOT_YET_VALID");
  });

  it("the rollback floor can be seeded so a cold start is not defenceless", async () => {
    const stale = makeList([], 4);
    const check = createStatusListCheck({
      fetchList: async () => stale,
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 7,
      initialVersionFloor: 5, // persisted from a previous instance
    });
    const verdict = await check(intent());
    expect(verdict.allowed).toBe(false);
    if (verdict.allowed) throw new Error("unreachable");
    expect(verdict.code).toBe("STATUS_LIST_ROLLBACK");
  });

  it("allChecks denies if ANY source says revoked", async () => {
    const permissive = createStatusListCheck({
      fetchList: async () => makeList([], 1),
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 1,
    });
    const strict = createStatusListCheck({
      fetchList: async () => makeList([1], 1),
      publicKeyPem: keys.publicKeyPem,
      indexFor: () => 1,
    });
    expect(await allChecks(permissive, permissive)(intent())).toEqual({ allowed: true });
    const denied = await allChecks(permissive, strict)(intent());
    expect(denied.allowed).toBe(false);
  });
});
