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

/**
 * The network id arrives in a 402 from an UNTRUSTED SELLER. A comparison that
 * is merely textual (trim + lowercase) lets that seller spell the same chain a
 * way the blocklist does not — "eip155:084532" for "eip155:84532" — and a
 * block entry a counterparty can spell around is not a control. CAIP-2-shaped
 * ids are therefore parsed structurally (namespace + reference, the eip155
 * reference canonicalized numerically), and a colon-bearing id that does not
 * parse is REFUSED, never passed through.
 */
describe("network ids from an untrusted counterparty are canonicalized", () => {
  const BLOCK_BASE = { networks: { block: [BASE_SEPOLIA] } };

  it("a leading-zero eip155 reference cannot evade the blocklist", async () => {
    for (const spelling of ["eip155:084532", "eip155:0084532", "EIP155:084532"]) {
      const result = await evaluatePolicy(
        makeIntent({ network: spelling }),
        makePolicy(BLOCK_BASE),
        emptyHistory,
      );
      expect(result.decision).toBe("deny");
      expect(result.reasons.map((r) => r.code)).toContain("NETWORK_BLOCKED");
    }
  });

  it("a non-canonical spelling that does not even parse is refused, not passed through", async () => {
    // Hex chain id, internal whitespace, empty reference, extra colon: none of
    // these are CAIP-2, and under a block-only policy every one of them used
    // to sail past the blocklist as "did not match, therefore not blocked".
    for (const spelling of [
      "eip155:0x14a34",
      "eip155: 84532",
      "eip155:",
      "eip155:84532:extra",
    ]) {
      const result = await evaluatePolicy(
        makeIntent({ network: spelling }),
        makePolicy(BLOCK_BASE),
        emptyHistory,
      );
      expect(result.decision).toBe("deny");
      expect(result.reasons.map((r) => r.code)).toContain("NETWORK_UNPARSEABLE");
    }
  });

  it("a policy entry that cannot be canonicalized poisons the whole constraint (fail closed)", async () => {
    // An operator's hex-spelled block entry would otherwise silently never
    // match anything — a blocklist with a hole it cannot see. Refuse loudly.
    const result = await evaluatePolicy(
      makeIntent({ network: BASE_SEPOLIA }),
      makePolicy({ networks: { allow: [BASE_SEPOLIA], block: ["eip155:0x1"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_POLICY_INVALID");
  });

  it("a leading-zero entry ON THE POLICY side blocks the canonical spelling too", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: BASE_SEPOLIA }),
      makePolicy({ networks: { block: ["eip155:084532"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("NETWORK_BLOCKED");
  });

  it("the ALLOW side stays fail-closed for every variant of a chain it does not list", async () => {
    for (const spelling of [
      "eip155:011155111", // leading-zero variant of a FORBIDDEN chain
      "eip155:0x14a34", // hex variant of the allowed chain: unparseable, refused
      "eip156:84532", // different namespace entirely
      "eip155:845320", // different chain, shared prefix
    ]) {
      const result = await evaluatePolicy(
        makeIntent({ network: spelling }),
        makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
        emptyHistory,
      );
      expect(result.decision).toBe("deny");
    }
  });

  it("the allow side recognizes a leading-zero spelling of the SAME chain (canonical equality)", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: "eip155:084532" }),
      makePolicy({ networks: { allow: [BASE_SEPOLIA] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("allow");
  });

  it("bare rail-native names (no colon) keep their trim+lowercase semantics", async () => {
    const result = await evaluatePolicy(
      makeIntent({ network: "  Base-Sepolia " }),
      makePolicy({ networks: { allow: ["base-sepolia"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("allow");
  });

  it("non-eip155 CAIP-2 ids compare structurally without numeric folding", async () => {
    const blocked = await evaluatePolicy(
      makeIntent({ network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" }),
      makePolicy({ networks: { block: ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"] } }),
      emptyHistory,
    );
    expect(blocked.decision).toBe("deny");
    expect(blocked.reasons.map((r) => r.code)).toContain("NETWORK_BLOCKED");

    const other = await evaluatePolicy(
      makeIntent({ network: "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z" }),
      makePolicy({ networks: { allow: ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"] } }),
      emptyHistory,
    );
    expect(other.decision).toBe("deny");
  });
});
