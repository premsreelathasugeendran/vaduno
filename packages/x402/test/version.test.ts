/**
 * Version detection: refuse x402 v2 by name rather than by accident.
 *
 * Before this, a v2 body died on `accepts[0].maxAmountRequired must be a
 * non-empty string` — which reads as "that server is broken", not "this adapter
 * only speaks v1". The distinction matters because one of those sends you to
 * file a bug against someone else's implementation.
 *
 * The refusal is deliberate and is NOT a step toward a partial v2 parse.
 * `validateRequirement` builds its result from a fixed allowlist that copies no
 * unknown keys, so accepting v2's `amount` there without also threading it
 * through to the requirement handed to `pay()` would let policy approve one
 * amount while the signer signs another. Refusing is strictly safer than a
 * half-patch.
 */
import { describe, expect, it } from "vitest";
import {
  parsePaymentRequired,
  X402ProtocolError,
  X402VersionUnsupportedError,
} from "../src/parse.js";

const v1Requirement = {
  scheme: "exact",
  network: "base",
  maxAmountRequired: "1000",
  resource: "https://api.example.com/thing",
  payTo: "0xdead",
  asset: "0xA0b8",
};

describe("x402 v2 is refused by name", () => {
  it("refuses a body that declares x402Version 2", () => {
    expect(() =>
      parsePaymentRequired({ x402Version: 2, accepts: [v1Requirement] }),
    ).toThrow(X402VersionUnsupportedError);
  });

  it("refuses a v2-shaped requirement even with no declared version", () => {
    // The rename is the real wire incompatibility, so field shape alone is
    // enough to refuse — a server need not announce its version.
    const v2 = {
      scheme: "exact",
      network: "eip155:8453",
      amount: "1000",
      resource: "https://api.example.com/thing",
      payTo: "0xdead",
      asset: "0xA0b8",
    };
    expect(() => parsePaymentRequired({ accepts: [v2] })).toThrow(
      X402VersionUnsupportedError,
    );
  });

  it("the error names the version and says no payment was attempted", () => {
    try {
      parsePaymentRequired({ x402Version: 2, accepts: [v1Requirement] });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(X402VersionUnsupportedError);
      const e = err as X402VersionUnsupportedError;
      expect(e.detectedVersion).toBe(2);
      expect(e.message).toContain("not supported");
      expect(e.message).toContain("No payment was attempted");
    }
  });

  it("is NOT an X402ProtocolError — the server is fine, the adapter is behind", () => {
    try {
      parsePaymentRequired({ x402Version: 2, accepts: [v1Requirement] });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).not.toBeInstanceOf(X402ProtocolError);
    }
  });
});

describe("v1 still parses — detection must not be trigger-happy", () => {
  it("parses a plain v1 body", () => {
    const parsed = parsePaymentRequired({ accepts: [v1Requirement] });
    expect(parsed.x402Version).toBe(1);
    expect(parsed.accepts[0]?.maxAmountRequired).toBe("1000");
  });

  it("parses a body that explicitly declares version 1", () => {
    const parsed = parsePaymentRequired({ x402Version: 1, accepts: [v1Requirement] });
    expect(parsed.accepts).toHaveLength(1);
  });

  it("tolerates unknown extra keys — forward-compatible servers add fields", () => {
    const parsed = parsePaymentRequired({
      accepts: [{ ...v1Requirement, someFutureKey: "whatever" }],
    });
    expect(parsed.accepts[0]?.maxAmountRequired).toBe("1000");
  });

  it("a requirement carrying BOTH amount and maxAmountRequired is treated as v1", () => {
    // A transitional server may send both. maxAmountRequired is present, so v1
    // parsing is well-defined and safe; refusing would be needlessly strict.
    const parsed = parsePaymentRequired({
      accepts: [{ ...v1Requirement, amount: "1000" }],
    });
    expect(parsed.accepts[0]?.maxAmountRequired).toBe("1000");
  });

  it("a malformed v1 body is still a PROTOCOL error, not a version error", () => {
    const { maxAmountRequired: _drop, ...missingAmount } = v1Requirement;
    expect(() => parsePaymentRequired({ accepts: [missingAmount] })).toThrow(
      X402ProtocolError,
    );
  });
});
