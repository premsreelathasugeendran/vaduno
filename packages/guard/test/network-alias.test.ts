/**
 * REATTACK FINDING (r4) — `networks.block` could be spelled around not by
 * mangling a CAIP-2 id, but by using the OTHER wire spelling of the same
 * chain. x402 v1 names the network "base-sepolia"; x402 v2 names the same
 * chain "eip155:84532". normNetwork treated bare names and CAIP-2 ids as
 * DISJOINT key spaces, so `block: ["eip155:84532"]` did not block an intent
 * whose network was "base-sepolia" — and the same @vaduno/x402 adapter
 * naturally produces BOTH spellings (v1 requirements carry the name, v2
 * requirements carry the CAIP-2 id). Measured end to end: with
 * `allow: ["base-sepolia","eip155:84532"], block: ["eip155:84532"]` a
 * hostile 402 server answering with the v1 name was PAID.
 *
 * The fix: a curated v1-name -> CAIP-2 alias table (the EVM networks the
 * x402 registry defines) applied inside normNetwork, so both spellings of
 * one chain canonicalize to one comparison key — on the intent, the allow
 * list and the block list alike. The engine's own rationale applies
 * verbatim: a blocklist a counterparty can spell around is not a control.
 */
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../src/policy/engine.js";
import { emptyHistory, makeIntent, makePolicy } from "./helpers.js";

const codes = async (network: string, networks: { allow?: string[]; block?: string[] }) => {
  const r = await evaluatePolicy(
    makeIntent({ network }),
    makePolicy({ networks }),
    emptyHistory,
  );
  return { decision: r.decision, codes: r.reasons.map((x) => x.code) };
};

describe("v1 network names and CAIP-2 ids are ONE chain to the blocklist", () => {
  it("block by CAIP-2 id catches the v1 spelling (the measured exploit)", async () => {
    const r = await codes("base-sepolia", {
      allow: ["base-sepolia", "eip155:84532"],
      block: ["eip155:84532"],
    });
    expect(r.decision).toBe("deny");
    expect(r.codes).toContain("NETWORK_BLOCKED");
  });

  it("block by v1 name catches the CAIP-2 spelling (the mirror exploit)", async () => {
    const r = await codes("eip155:84532", {
      allow: ["base-sepolia", "eip155:84532"],
      block: ["base-sepolia"],
    });
    expect(r.decision).toBe("deny");
    expect(r.codes).toContain("NETWORK_BLOCKED");
  });

  it("leading-zero CAIP-2 spellings still collapse into the same block", async () => {
    const r = await codes("eip155:084532", { block: ["base-sepolia"] });
    expect(r.decision).toBe("deny");
    expect(r.codes).toContain("NETWORK_BLOCKED");
  });

  it("allow lists unify the same way: v1 entry admits the CAIP-2 spelling of the SAME chain", async () => {
    const r = await codes("eip155:84532", { allow: ["base-sepolia"] });
    expect(r.decision).toBe("allow");
  });

  it("aliasing is per-chain, never namespace-wide: base does not admit base-sepolia", async () => {
    const r = await codes("base-sepolia", { allow: ["base"] });
    expect(r.decision).toBe("deny");
    expect(r.codes).toContain("NETWORK_NOT_ALLOWED");
  });

  it("mainnet/testnet pairs stay distinct chains under aliasing", async () => {
    const r = await codes("eip155:8453", { block: ["base-sepolia"] });
    expect(r.decision).toBe("allow");
  });

  it("non-curated bare names keep their trim+lowercase semantics", async () => {
    const allowed = await codes("  Stripe-Live ", { allow: ["stripe-live"] });
    expect(allowed.decision).toBe("allow");
    const blocked = await codes("stripe-live", { block: ["stripe-live"] });
    expect(blocked.decision).toBe("deny");
    expect(blocked.codes).toContain("NETWORK_BLOCKED");
  });

  it("a non-curated bare name is NOT unified with a CAIP-2 id (documented limit)", async () => {
    // "upi" has no CAIP-2 alias; nothing changes for rail-native names.
    const r = await codes("upi", { block: ["eip155:84532"] });
    expect(r.decision).toBe("allow");
  });

  it("every curated alias round-trips both directions", async () => {
    const pairs: Array<[string, string]> = [
      ["base", "eip155:8453"],
      ["base-sepolia", "eip155:84532"],
      ["avalanche", "eip155:43114"],
      ["avalanche-fuji", "eip155:43113"],
      ["polygon", "eip155:137"],
      ["polygon-amoy", "eip155:80002"],
      ["iotex", "eip155:4689"],
      ["sei", "eip155:1329"],
      ["sei-testnet", "eip155:1328"],
    ];
    for (const [name, caip2] of pairs) {
      const a = await codes(name, { block: [caip2] });
      expect(a.decision, `${name} should be blocked by ${caip2}`).toBe("deny");
      const b = await codes(caip2, { block: [name] });
      expect(b.decision, `${caip2} should be blocked by ${name}`).toBe("deny");
    }
  });
});
