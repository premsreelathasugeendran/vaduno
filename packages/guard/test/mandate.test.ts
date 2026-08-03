import { describe, expect, it } from "vitest";
import {
  MandateManager,
  generateMandateKeyPair,
} from "../src/mandate/mandate.js";
import { makeIntent } from "./helpers.js";

function manager(now?: () => Date) {
  const keys = generateMandateKeyPair();
  return {
    keys,
    mm: new MandateManager(
      { publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem },
      undefined,
      now,
    ),
  };
}

const baseConstraints = {
  maxAmountMinor: 1_000,
  currency: "USD",
  validFrom: "2000-01-01T00:00:00.000Z",
  expiresAt: "2100-01-01T00:00:00.000Z",
  maxUses: 1,
};

describe("MandateManager", () => {
  it("issues and validates a mandate", async () => {
    const { mm } = manager();
    const mandate = await mm.issue({
      issuer: "human@example.com",
      agentId: "agent-1",
      constraints: { ...baseConstraints },
    });
    const check = mm.check(mandate.id, makeIntent({ amount: { amountMinor: 500, currency: "USD" } }));
    expect(check.ok).toBe(true);
  });

  it("rejects a tampered mandate (signature)", async () => {
    const { mm } = manager();
    const mandate = await mm.issue({
      issuer: "human@example.com",
      agentId: "agent-1",
      constraints: { ...baseConstraints },
    });
    // Tamper with the registered copy.
    mandate.constraints.maxAmountMinor = 1_000_000;
    const check = mm.check(mandate.id, makeIntent());
    expect(check.ok).toBe(false);
    expect(check.code).toBe("SIGNATURE_INVALID");
  });

  it("rejects mandates signed by a different key", async () => {
    const a = manager();
    const foreign = new MandateManager({
      publicKeyPem: generateMandateKeyPair().publicKeyPem,
    });
    const mandate = await a.mm.issue({
      issuer: "human@example.com",
      agentId: "agent-1",
      constraints: { ...baseConstraints },
    });
    foreign.register(mandate);
    const check = foreign.check(mandate.id, makeIntent());
    expect(check.ok).toBe(false);
    // Since 0.3.0 a mandate names its signing key, so a verifier that does not
    // hold that key says so precisely instead of reporting a bad signature.
    // Both refuse; this one tells the operator which problem they have.
    expect(check.code).toBe("KEY_UNKNOWN");
  });

  it("enforces expiry and validFrom", async () => {
    const { mm } = manager();
    const expired = await mm.issue({
      issuer: "h",
      agentId: "agent-1",
      constraints: { ...baseConstraints, expiresAt: "2001-01-01T00:00:00.000Z" },
    });
    expect(mm.check(expired.id, makeIntent()).code).toBe("EXPIRED");

    const future = await mm.issue({
      issuer: "h",
      agentId: "agent-1",
      constraints: { ...baseConstraints, validFrom: "2099-01-01T00:00:00.000Z" },
    });
    expect(mm.check(future.id, makeIntent()).code).toBe("NOT_YET_VALID");
  });

  it("consume is atomic: a single-use mandate cannot be consumed twice", async () => {
    const { mm } = manager();
    const mandate = await mm.issue({
      issuer: "h",
      agentId: "agent-1",
      constraints: { ...baseConstraints, maxUses: 1 },
    });
    const intent = makeIntent({ amount: { amountMinor: 100, currency: "USD" } });
    const [first, second] = await Promise.all([
      mm.consume(mandate.id, intent),
      mm.consume(mandate.id, makeIntent({ amount: { amountMinor: 100, currency: "USD" } })),
    ]);
    const oks = [first.ok, second.ok].filter(Boolean);
    expect(oks.length).toBe(1);
  });

  it("enforces amount, agent, merchant and revocation", async () => {
    const { mm } = manager();
    const mandate = await mm.issue({
      issuer: "h",
      agentId: "agent-1",
      constraints: { ...baseConstraints, merchants: ["openai"] },
    });

    expect(
      mm.check(
        mandate.id,
        makeIntent({ amount: { amountMinor: 5_000, currency: "USD" } }),
      ).code,
    ).toBe("AMOUNT_EXCEEDS_MANDATE");

    expect(
      mm.check(mandate.id, makeIntent({ agentId: "agent-2" })).code,
    ).toBe("AGENT_MISMATCH");

    expect(
      mm.check(
        mandate.id,
        makeIntent({ merchant: { id: "different-shop" } }),
      ).code,
    ).toBe("MERCHANT_NOT_COVERED");

    await mm.revoke(mandate.id);
    expect(mm.check(mandate.id, makeIntent()).code).toBe("REVOKED");
  });

  it("expiry honors non-UTC ISO offsets (fail closed)", async () => {
    const now = () => new Date("2026-01-01T02:00:00.000Z");
    const { mm } = manager(now);
    const m = await mm.issue({
      issuer: "h",
      agentId: "agent-1",
      constraints: {
        ...baseConstraints,
        validFrom: "2020-01-01T00:00:00.000Z",
        expiresAt: "2026-01-01T05:30:00+05:30", // == 00:00Z, already past
      },
    });
    expect(mm.check(m.id, makeIntent()).code).toBe("EXPIRED");
  });

  it("issue rejects unparseable constraint timestamps", async () => {
    const { mm } = manager();
    await expect(
      mm.issue({
        issuer: "h",
        agentId: "agent-1",
        constraints: { ...baseConstraints, expiresAt: "whenever" },
      }),
    ).rejects.toThrow();
  });
});

describe("MandateManager.hydrateFromLedger (consume-once survives restart)", () => {
  it("a consumed single-use mandate cannot be replayed into a fresh manager", async () => {
    const { AuditLedger } = await import("../src/ledger/ledger.js");
    const { MemoryLedgerStore } = await import(
      "../src/ledger/stores/memory.js"
    );
    const keys = generateMandateKeyPair();
    const ledger = new AuditLedger(new MemoryLedgerStore());

    const a = new MandateManager(
      { publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem },
      ledger,
    );
    const mandate = await a.issue({
      issuer: "h",
      agentId: "agent-1",
      constraints: { ...baseConstraints, maxUses: 1 },
    });
    const first = await a.consume(
      mandate.id,
      makeIntent({ amount: { amountMinor: 100, currency: "USD" } }),
    );
    expect(first.ok).toBe(true);

    // Fresh manager (simulating a restart / second process) sharing the ledger.
    const b = new MandateManager({ publicKeyPem: keys.publicKeyPem }, ledger);
    await b.hydrateFromLedger();
    const replay = b.check(
      mandate.id,
      makeIntent({ amount: { amountMinor: 100, currency: "USD" } }),
    );
    expect(replay.ok).toBe(false);
    expect(replay.code).toBe("USES_EXHAUSTED");
  });
});
