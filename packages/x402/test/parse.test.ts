import { describe, expect, it } from "vitest";
import {
  X402ProtocolError,
  decodeSettlementResponse,
  encodePaymentHeader,
  parsePaymentRequired,
} from "../src/parse.js";
import { atomic, parseAtomicAmount, requirementToIntent, usdc } from "../src/intent.js";

describe("parsePaymentRequired", () => {
  const good = {
    x402Version: 1,
    accepts: [
      {
        scheme: "exact",
        network: "base-sepolia",
        maxAmountRequired: "1000000",
        resource: "https://api.example.com/data",
        payTo: "0xabc",
        asset: "0xUSDC",
      },
    ],
  };

  it("parses a valid body", () => {
    const parsed = parsePaymentRequired(good);
    expect(parsed.accepts).toHaveLength(1);
    expect(parsed.accepts[0]!.scheme).toBe("exact");
  });

  it("throws on missing accepts", () => {
    expect(() => parsePaymentRequired({ x402Version: 1 })).toThrow(
      X402ProtocolError,
    );
  });

  it("throws on empty accepts", () => {
    expect(() => parsePaymentRequired({ x402Version: 1, accepts: [] })).toThrow(
      X402ProtocolError,
    );
  });

  it("throws when a requirement is missing required fields", () => {
    expect(() =>
      parsePaymentRequired({ accepts: [{ scheme: "exact" }] }),
    ).toThrow(X402ProtocolError);
  });

  it("throws on non-object body", () => {
    expect(() => parsePaymentRequired(null)).toThrow(X402ProtocolError);
    expect(() => parsePaymentRequired("nope")).toThrow(X402ProtocolError);
  });

  describe("extra validation", () => {
    const withExtra = (extra: unknown) => ({
      ...good,
      accepts: [{ ...good.accepts[0]!, extra }],
    });

    it("throws X402ProtocolError on a non-string extra.symbol (not a downstream TypeError)", () => {
      expect(() => parsePaymentRequired(withExtra({ symbol: 12345 }))).toThrow(
        X402ProtocolError,
      );
    });

    it("throws on non-string extra.name / extra.version", () => {
      expect(() => parsePaymentRequired(withExtra({ name: { evil: true } }))).toThrow(
        X402ProtocolError,
      );
      expect(() => parsePaymentRequired(withExtra({ version: 2 }))).toThrow(
        X402ProtocolError,
      );
    });

    it("throws on a non-integer / out-of-range extra.decimals", () => {
      for (const decimals of ["6", 1.5, -1, 256, Number.NaN]) {
        expect(() => parsePaymentRequired(withExtra({ decimals }))).toThrow(
          X402ProtocolError,
        );
      }
    });

    it("throws on a non-object extra (string, array)", () => {
      expect(() => parsePaymentRequired(withExtra("USDC"))).toThrow(X402ProtocolError);
      expect(() => parsePaymentRequired(withExtra(["USDC"]))).toThrow(X402ProtocolError);
    });

    it("treats a null extra as absent", () => {
      expect(parsePaymentRequired(withExtra(null)).accepts[0]!.extra).toBeUndefined();
    });

    it("keeps unknown scheme-specific keys (e.g. Solana's feePayer)", () => {
      const parsed = parsePaymentRequired(
        withExtra({ symbol: "USDC", decimals: 6, feePayer: "FeePayerPubkey" }),
      );
      const extra = parsed.accepts[0]!.extra as Record<string, unknown>;
      expect(extra.symbol).toBe("USDC");
      expect(extra.feePayer).toBe("FeePayerPubkey");
    });

    it("defensively copies extra — later mutation of the body cannot reach the requirement", () => {
      const extra = { symbol: "USDC", decimals: 6 };
      const parsed = parsePaymentRequired(withExtra(extra));
      extra.symbol = "EVIL";
      expect(parsed.accepts[0]!.extra!.symbol).toBe("USDC");
    });
  });
});

describe("header codecs", () => {
  it("round-trips a settlement response", () => {
    const header = encodePaymentHeader({ success: true, transaction: "0xdead" });
    const decoded = decodeSettlementResponse(header);
    expect(decoded?.success).toBe(true);
    expect(decoded?.transaction).toBe("0xdead");
  });

  it("returns null for absent or garbage settlement headers", () => {
    expect(decodeSettlementResponse(null)).toBeNull();
    expect(decodeSettlementResponse("!!!not base64 json!!!")).toBeNull();
  });
});

describe("amount helpers", () => {
  it("usdc converts human dollars to 6-decimal atomic units", () => {
    expect(usdc(1)).toBe(1_000_000);
    expect(usdc(1.5)).toBe(1_500_000);
    expect(usdc(0.01)).toBe(10_000);
  });

  it("atomic does exact integer math without float drift", () => {
    expect(atomic(0.1, 6)).toBe(100_000);
    expect(atomic(0.000001, 6)).toBe(1);
    expect(atomic(123.456789, 6)).toBe(123_456_789);
  });

  it("atomic rejects exponential notation instead of silently returning 0", () => {
    expect(() => atomic(0.0000003, 6)).toThrow();
    expect(() => usdc(0.0000003)).toThrow();
  });

  it("atomic rejects amounts more precise than the token's decimals", () => {
    expect(() => atomic(1.2345678, 6)).toThrow();
  });

  it("parseAtomicAmount rejects non-integer / unsafe / negative strings", () => {
    expect(parseAtomicAmount("1000000")).toBe(1_000_000);
    expect(Number.isNaN(parseAtomicAmount("1.5"))).toBe(true);
    expect(Number.isNaN(parseAtomicAmount("-5"))).toBe(true);
    expect(Number.isNaN(parseAtomicAmount("99999999999999999999999"))).toBe(true);
    expect(Number.isNaN(parseAtomicAmount("abc"))).toBe(true);
  });
});

describe("requirementToIntent", () => {
  it("maps a requirement into a Vaduno intent, binding merchant.url to the REAL request url", () => {
    const intent = requirementToIntent(
      {
        scheme: "exact",
        network: "base",
        maxAmountRequired: "2500000",
        resource: "https://server-claims-this.example/premium",
        payTo: "0xMerchant",
        asset: "0xUSDC",
        extra: { symbol: "USDC", decimals: 6, name: "Example API" },
      },
      { agentId: "agent-1", intentId: "i-1", requestUrl: "https://real-endpoint.example/data" },
    );
    expect(intent.rail).toBe("x402");
    expect(intent.amount).toEqual({ amountMinor: 2_500_000, currency: "USDC" });
    expect(intent.merchant.id).toBe("0xMerchant"); // payTo (recipient)
    // merchant.url is the ACTUAL endpoint, not the server's `resource` claim.
    expect(intent.merchant.url).toBe("https://real-endpoint.example/data");
    const meta = intent.metadata as { network: string; resourceClaimed: string; requestUrl: string };
    expect(meta.network).toBe("base");
    expect(meta.resourceClaimed).toBe("https://server-claims-this.example/premium");
    expect(meta.requestUrl).toBe("https://real-endpoint.example/data");
  });

  it("uses a trusted currency override instead of the server symbol", () => {
    const intent = requirementToIntent(
      {
        scheme: "exact",
        network: "base",
        maxAmountRequired: "1000000",
        resource: "https://api.example.com/x",
        payTo: "0xM",
        asset: "0xToken",
        extra: { symbol: "SPOOFED", decimals: 6 },
      },
      { agentId: "a", intentId: "i", requestUrl: "https://api.example.com/x", currency: "USDC" },
    );
    expect(intent.amount.currency).toBe("USDC");
  });
});
