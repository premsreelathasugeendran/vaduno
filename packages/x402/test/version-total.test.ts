/**
 * The version discriminant must be TOTAL: every possible `x402Version` value
 * has a DEFINED outcome on each carrier, and a non-v1 declaration is never
 * coerced to 1.
 *
 * The attack this closes: the old read was
 * `typeof v === "number" ? v : 1`, so the STRING "2" silently became 1 — a
 * hostile or sloppy server could present v2 data under a v1 reading (a
 * downgrade channel) — and 0 / -7 / 1.5 passed through verbatim as if
 * declared. Nothing routed on the field then; now that v2 exists, it does.
 */
import { describe, expect, it } from "vitest";
import {
  parsePaymentRequired,
  parsePaymentRequiredV2,
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

const v1Body = (x402Version: unknown) =>
  x402Version === undefined
    ? { accepts: [v1Requirement] }
    : { x402Version, accepts: [v1Requirement] };

describe("body carrier (v1): total version outcomes", () => {
  it("absent -> parsed as v1 (documented back-compat)", () => {
    expect(parsePaymentRequired(v1Body(undefined)).x402Version).toBe(1);
  });

  it("integer 1 -> parsed as v1", () => {
    expect(parsePaymentRequired(v1Body(1)).x402Version).toBe(1);
  });

  it("integer 2 -> refused by name (v2 travels in the PAYMENT-REQUIRED header)", () => {
    try {
      parsePaymentRequired(v1Body(2));
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(X402VersionUnsupportedError);
      expect((err as X402VersionUnsupportedError).detectedVersion).toBe(2);
      expect((err as Error).message).toContain("PAYMENT-REQUIRED");
    }
  });

  it('the STRING "2" is refused — never coerced to 1 (the downgrade channel)', () => {
    // The body is otherwise a perfectly valid v1 body: if the version read
    // were not total, this would parse as v1 and the declaration would vanish.
    expect(() => parsePaymentRequired(v1Body("2"))).toThrow(X402ProtocolError);
  });

  it('the STRING "1" is also refused — strings are never versions', () => {
    expect(() => parsePaymentRequired(v1Body("1"))).toThrow(X402ProtocolError);
  });

  it.each([
    ["zero", 0],
    ["a negative integer", -7],
    ["a non-integer number", 1.5],
    ["null", null],
    ["an object", {}],
    ["an array", []],
    ["a boolean", true],
  ])("%s is refused as a protocol error, not treated as v1", (_label, version) => {
    expect(() => parsePaymentRequired(v1Body(version))).toThrow(X402ProtocolError);
  });

  it("integer 3+ -> X402VersionUnsupportedError naming the version (adapter behind)", () => {
    try {
      parsePaymentRequired(v1Body(3));
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(X402VersionUnsupportedError);
      expect((err as X402VersionUnsupportedError).detectedVersion).toBe(3);
      expect((err as Error).message).toContain("No payment was attempted");
    }
  });
});

describe("header carrier (v2): total version outcomes — stricter, no absent default", () => {
  const v2Body = (x402Version: unknown) => ({
    ...(x402Version === undefined ? {} : { x402Version }),
    resource: { url: "https://api.example.com/data" },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:84532",
        amount: "1000",
        payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        asset: "0xUSDCContract",
        maxTimeoutSeconds: 60,
      },
    ],
  });

  it("integer 2 -> parsed as v2", () => {
    expect(parsePaymentRequiredV2(v2Body(2)).x402Version).toBe(2);
  });

  it("absent -> refused (the v2 carrier REQUIRES the declaration; no back-compat exists)", () => {
    expect(() => parsePaymentRequiredV2(v2Body(undefined))).toThrow(X402ProtocolError);
  });

  it("integer 1 -> refused as version confusion (v1 declared on the v2-only carrier)", () => {
    expect(() => parsePaymentRequiredV2(v2Body(1))).toThrow(X402ProtocolError);
  });

  it.each([
    ['the string "2"', "2"],
    ["zero", 0],
    ["a negative integer", -7],
    ["a non-integer number", 1.5],
    ["null", null],
    ["an object", {}],
    ["an array", []],
  ])("%s is refused, never guessed at", (_label, version) => {
    expect(() => parsePaymentRequiredV2(v2Body(version))).toThrow(X402ProtocolError);
  });

  it("integer 3+ -> X402VersionUnsupportedError naming the version", () => {
    try {
      parsePaymentRequiredV2(v2Body(3));
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(X402VersionUnsupportedError);
      expect((err as X402VersionUnsupportedError).detectedVersion).toBe(3);
    }
  });
});

describe("v2-shape detection no longer depends on `amount` being a string", () => {
  it("a NUMERIC amount with no maxAmountRequired is a VERSION error, not a field error", () => {
    // The old heuristic required `typeof amount === "string"`, so this exact
    // body produced "maxAmountRequired must be a non-empty string" — the
    // misleading error the version detection exists to prevent.
    const body = {
      accepts: [
        {
          scheme: "exact",
          network: "eip155:8453",
          amount: 1000,
          payTo: "0xdead",
          asset: "0xA0b8",
          maxTimeoutSeconds: 60,
        },
      ],
    };
    expect(() => parsePaymentRequired(body)).toThrow(X402VersionUnsupportedError);
  });

  it("an amount of ANY type triggers detection (boolean, object, null)", () => {
    for (const amount of [true, { atomic: "1000" }, null]) {
      const body = { accepts: [{ scheme: "exact", amount }] };
      expect(() => parsePaymentRequired(body)).toThrow(X402VersionUnsupportedError);
    }
  });

  it("a top-level `resource` OBJECT is a v2 marker (v1 has no top-level resource)", () => {
    const body = {
      resource: { url: "https://api.example.com/data" },
      accepts: [v1Requirement],
    };
    expect(() => parsePaymentRequired(body)).toThrow(X402VersionUnsupportedError);
  });

  it("a top-level resource STRING is tolerated as an unknown key (not a v2 shape)", () => {
    const body = { resource: "https://api.example.com/data", accepts: [v1Requirement] };
    expect(parsePaymentRequired(body).accepts).toHaveLength(1);
  });

  it("still not trigger-happy: both amount and maxAmountRequired present stays v1", () => {
    const body = { accepts: [{ ...v1Requirement, amount: "1000" }] };
    expect(parsePaymentRequired(body).accepts[0]?.maxAmountRequired).toBe("1000");
  });

  it("missing BOTH amount fields stays a protocol error (nothing implies v2)", () => {
    const { maxAmountRequired: _drop, ...rest } = v1Requirement;
    expect(() => parsePaymentRequired({ accepts: [rest] })).toThrow(X402ProtocolError);
  });
});
