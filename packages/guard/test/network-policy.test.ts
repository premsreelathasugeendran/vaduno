import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../src/policy/engine.js";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { emptyHistory, makeIntent, makePolicy } from "./helpers.js";

/**
 * FINDING A — the PaymentIntent had no chain/network dimension, so a policy
 * could not express "only Base Sepolia". With an entirely ordinary multi-chain
 * asset registry (Base Sepolia USDC and Ethereum Sepolia USDC, both symbol
 * "USDC"), a transfer on chainId 11155111 was authorized by a deployment
 * targeting 84532: same intent shape, same currency, wrong chain. The only
 * chain gate was the caller's asset registry, which is caller config, not a
 * policy control.
 */

const BASE_SEPOLIA = "eip155:84532";
const ETH_SEPOLIA = "eip155:11155111";

describe("network policy (chain constraint)", () => {
  it("denies an intent on a network outside the allowlist", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: ETH_SEPOLIA }),
      makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_NOT_ALLOWED");
  });

  it("allows an intent on an allowlisted network", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: BASE_SEPOLIA }),
      makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("allow");
  });

  it("matches networks case-insensitively and ignores surrounding whitespace", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: "  EIP155:84532 " }),
      makePolicy({ networks: { allow: ["eip155:84532"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("allow");
  });

  it("does NOT treat a namespace as a wildcard for its chains", async () => {
    // "eip155" must not silently authorize every EVM chain — implicit
    // permissiveness is what caused this finding.
    const result = await evaluatePolicy(
      makeIntent({ network: ETH_SEPOLIA }),
      makePolicy({ networks: { allow: ["eip155"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_NOT_ALLOWED");
  });

  it("blocklists a network, and block wins over allow", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: "eip155:1" }),
      makePolicy({ networks: { allow: ["eip155:1"], block: ["eip155:1"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_BLOCKED");
  });

  it("DENIES an intent that states no network once a network policy exists", async () => {
    // A missing network is a denial, never a skip — the same rule
    // MERCHANT_KEY_MISSING follows. An operator who configured a network
    // allowlist and then got an intent that declined to say which chain it
    // was on is exactly the case this finding is about.
    for (const networks of [
      { allow: [BASE_SEPOLIA] },
      { block: ["eip155:1"] },
    ]) {
      const result = await evaluatePolicy(
        makeIntent(),
        makePolicy({ networks }),
        emptyHistory,
      );
      expect(result.decision).toBe("deny");
      expect(result.reasons.map((r) => r.code)).toContain("NETWORK_MISSING");
    }
  });

  it("denies a blank network string once a network policy exists", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: "   " }),
      makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_MISSING");
  });

  it("stays additive: no networks policy means no network constraint", async () => {
    // Every pre-existing caller. Silently allowing any chain is what caused
    // this finding, but a default that denies every existing deployment is a
    // worse answer than one that hands them a control they can switch on.
    for (const intent of [makeIntent(), makeIntent({ network: ETH_SEPOLIA })]) {
      const result = await evaluatePolicy(intent, makePolicy(), emptyHistory);
      expect(result.decision).toBe("allow");
    }
  });

  it("blocks the wrong-chain payment end-to-end and never runs the executor", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const guard = new VadunoGuard({
      policy: makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
      ledger,
    });
    let ran = false;
    const result = await guard.execute(makeIntent({ network: ETH_SEPOLIA }), async () => {
      ran = true;
      return null;
    });
    expect(result.status).toBe("denied");
    expect(ran).toBe(false);
    expect(result.policyResult.reasons.map((r) => r.code)).toContain(
      "NETWORK_NOT_ALLOWED",
    );
  });

  it("records the network on the evidence rows of an executed payment", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const guard = new VadunoGuard({
      policy: makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
      ledger,
    });
    const result = await guard.execute(
      makeIntent({ network: BASE_SEPOLIA }),
      async () => ({ ok: true }),
    );
    expect(result.status).toBe("executed");
    const row = (await ledger.all()).find((e) => e.type === "execution_result");
    expect((row!.data as { network?: unknown }).network).toBe(BASE_SEPOLIA);
  });

  it("carries the network through a two-phase authorize/settle", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const guard = new VadunoGuard({
      policy: makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
      ledger,
    });
    const intent = makeIntent({ network: BASE_SEPOLIA });
    const auth = await guard.authorize(intent);
    expect(auth.status).toBe("authorized");
    await guard.settle(intent.id, { status: "executed" });
    const row = (await ledger.all()).find((e) => e.type === "execution_result");
    expect((row!.data as { network?: unknown }).network).toBe(BASE_SEPOLIA);
  });

  it("refuses a network allowlist made of unusable entries rather than enforcing nothing", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: BASE_SEPOLIA }),
      makePolicy({ networks: { allow: ["  ", ""] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_POLICY_INVALID");
  });

  it("an empty networks object declares no constraint", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: ETH_SEPOLIA }),
      makePolicy({ networks: {} }),
      emptyHistory,
    );
    expect(result.decision).toBe("allow");
  });

  it("an empty allow list admits nothing, like merchants.allow", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: BASE_SEPOLIA }),
      makePolicy({ networks: { allow: [] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_NOT_ALLOWED");
  });

  it("denies a non-string network on the intent", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: 84532 as unknown as string }),
      makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_MISSING");
  });
});
