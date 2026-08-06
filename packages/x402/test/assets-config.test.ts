/**
 * REATTACK FINDING (r8, minor) — a malformed operator-supplied `assets`
 * registry entry (e.g. `address:` written instead of `asset:`) crashed the
 * payer mid-match with a raw "TypeError: Cannot read properties of undefined
 * (reading 'toLowerCase')" — fail closed on money, but the diagnosis pointed
 * at nothing an operator could act on. Configuration must refuse LOUDLY and
 * BY NAME, at wrap time, before any request is in flight.
 */
import { describe, expect, it } from "vitest";
import { createX402Fetch } from "../src/fetch.js";
import type { AssetInfo } from "../src/fetch.js";
import { makeGuard } from "./helpers.js";

const base = () => {
  const { guard } = makeGuard();
  return {
    guard,
    agentId: "agent-1",
    pay: async () => "sig",
  };
};

describe("the assets registry is validated at wrap time", () => {
  const badEntries: Array<[string, unknown]> = [
    ["asset key misspelled as address", { network: "base-sepolia", address: "0xUSDC", symbol: "USDC", decimals: 6 }],
    ["missing network", { asset: "0xUSDC", symbol: "USDC", decimals: 6 }],
    ["non-string asset", { network: "base-sepolia", asset: 42, symbol: "USDC", decimals: 6 }],
    ["blank network", { network: "  ", asset: "0xUSDC", symbol: "USDC", decimals: 6 }],
    ["non-string symbol", { network: "base-sepolia", asset: "0xUSDC", symbol: 6, decimals: 6 }],
    ["non-number decimals", { network: "base-sepolia", asset: "0xUSDC", symbol: "USDC", decimals: "6" }],
    ["null entry", null],
  ];

  for (const [label, entry] of badEntries) {
    it(`${label}: createX402Fetch refuses by name, not with a TypeError`, () => {
      expect(() =>
        createX402Fetch({ ...base(), assets: [entry as unknown as AssetInfo] }),
      ).toThrowError(/assets\[0\]/);
    });
  }

  it("a well-formed registry constructs fine (control)", () => {
    expect(() =>
      createX402Fetch({
        ...base(),
        assets: [
          { network: "base-sepolia", asset: "0xUSDC", symbol: "USDC", decimals: 6 },
          { network: "eip155:84532", asset: "0xUSDC", symbol: "USDC", decimals: 6 },
        ],
      }),
    ).not.toThrow();
  });
});
