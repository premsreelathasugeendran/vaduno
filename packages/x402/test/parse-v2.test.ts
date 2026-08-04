/**
 * v2 PaymentRequired parsing (PAYMENT-REQUIRED header carrier). The parser is
 * deliberately STRICTER than v1's: it has no tolerant legacy to preserve, and
 * every requirement it emits is built from a fixed allowlist so nothing
 * unvalidated can reach policy, the intent, or the payer.
 */
import { describe, expect, it } from "vitest";
import {
  MAX_PAYMENT_REQUIRED_HEADER_CHARS,
  parsePaymentRequiredHeader,
  parsePaymentRequiredV2,
  X402ProtocolError,
} from "../src/parse.js";
import { b64, v2PaymentRequired, v2Requirement } from "./helpers-v2.js";

describe("parsePaymentRequiredV2", () => {
  it("parses a valid v2 PaymentRequired", () => {
    const parsed = parsePaymentRequiredV2(v2PaymentRequired());
    expect(parsed.x402Version).toBe(2);
    expect(parsed.resource.url).toBe("https://api.example.com/data");
    expect(parsed.accepts).toHaveLength(1);
    expect(parsed.accepts[0]!.amount).toBe("1000000");
    expect(parsed.accepts[0]!.network).toBe("eip155:84532");
    expect(parsed.accepts[0]!.maxTimeoutSeconds).toBe(60);
  });

  it("parses the spec's own example structure (transports-v2/http.md)", () => {
    const specExample = {
      x402Version: 2,
      error: "PAYMENT-SIGNATURE header is required",
      resource: {
        url: "https://api.example.com/premium-data",
        description: "Access to premium market data",
        mimeType: "application/json",
      },
      accepts: [
        {
          scheme: "exact",
          network: "eip155:84532",
          amount: "10000",
          asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
          maxTimeoutSeconds: 60,
          extra: { name: "USDC", version: "2" },
        },
      ],
    };
    const parsed = parsePaymentRequiredV2(specExample);
    expect(parsed.error).toBe("PAYMENT-SIGNATURE header is required");
    expect(parsed.resource.description).toBe("Access to premium market data");
    expect(parsed.accepts[0]!.extra).toEqual({ name: "USDC", version: "2" });
  });

  describe("ResourceInfo (required in v2)", () => {
    it("refuses a missing resource", () => {
      const { resource: _drop, ...body } = v2PaymentRequired();
      expect(() => parsePaymentRequiredV2(body)).toThrow(X402ProtocolError);
    });

    it("refuses a non-object / array / string resource", () => {
      for (const resource of ["https://api.example.com", ["x"], 42, null]) {
        expect(() =>
          parsePaymentRequiredV2({ ...v2PaymentRequired(), resource }),
        ).toThrow(X402ProtocolError);
      }
    });

    it("refuses resource.url missing or empty", () => {
      for (const resource of [{}, { url: "" }, { url: 42 }]) {
        expect(() =>
          parsePaymentRequiredV2({ ...v2PaymentRequired(), resource }),
        ).toThrow(X402ProtocolError);
      }
    });

    it("refuses wrong-typed description/mimeType (fail closed, no silent drop)", () => {
      for (const resource of [
        { url: "https://a.example", description: 42 },
        { url: "https://a.example", mimeType: { evil: true } },
      ]) {
        expect(() =>
          parsePaymentRequiredV2({ ...v2PaymentRequired(), resource }),
        ).toThrow(X402ProtocolError);
      }
    });
  });

  describe("CAIP-2 network enforcement (stricter than the reference SDK)", () => {
    it.each([
      "base", // v1 name — not a CAIP-2 id
      "eip155", // no reference
      "EIP155:8453", // namespace must be lowercase
      "e:1", // namespace too short
      "eip155:", // empty reference
      ":8453", // empty namespace
      "eip155:8453 ", // trailing space would defeat exact registry matching
      "eip155:8453:extra",
    ])("refuses %s", (network) => {
      expect(() =>
        parsePaymentRequiredV2(v2PaymentRequired({ network })),
      ).toThrow(X402ProtocolError);
    });

    it.each([
      "eip155:8453",
      "eip155:84532",
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      "ach:us",
    ])("accepts %s", (network) => {
      expect(
        parsePaymentRequiredV2(v2PaymentRequired({ network })).accepts[0]!.network,
      ).toBe(network);
    });
  });

  describe("requirement field strictness", () => {
    it("refuses a non-string amount (declared v2 dies on the field, clearly)", () => {
      expect(() =>
        parsePaymentRequiredV2(v2PaymentRequired({ requirementOverrides: { amount: 10000 } })),
      ).toThrow(/amount must be a non-empty string/);
    });

    it("refuses missing / non-positive / non-number maxTimeoutSeconds (REQUIRED in v2)", () => {
      for (const maxTimeoutSeconds of [undefined, 0, -1, "60", Number.NaN, Infinity]) {
        const body = v2PaymentRequired();
        const req = body.accepts[0] as Record<string, unknown>;
        if (maxTimeoutSeconds === undefined) delete req.maxTimeoutSeconds;
        else req.maxTimeoutSeconds = maxTimeoutSeconds;
        expect(() => parsePaymentRequiredV2(body)).toThrow(/maxTimeoutSeconds/);
      }
    });

    it("refuses v1 `maxAmountRequired` inside a v2 requirement (mixed-version money field)", () => {
      // The seam this closes: a server showing one amount to v1 readers and
      // another to v2 readers. Money fields get exactly one reading.
      expect(() =>
        parsePaymentRequiredV2(
          v2PaymentRequired({ requirementOverrides: { maxAmountRequired: "1" } }),
        ),
      ).toThrow(/maxAmountRequired/);
    });

    it("refuses a per-requirement `resource` (mixed-version binding field)", () => {
      expect(() =>
        parsePaymentRequiredV2(
          v2PaymentRequired({
            requirementOverrides: { resource: "https://elsewhere.example/x" },
          }),
        ),
      ).toThrow(/resource/);
    });

    it("drops unknown requirement keys — the fixed allowlist copies nothing extra", () => {
      const parsed = parsePaymentRequiredV2(
        v2PaymentRequired({
          requirementOverrides: { outputSchema: { evil: 1 }, somethingElse: "x" },
        }),
      );
      const req = parsed.accepts[0] as unknown as Record<string, unknown>;
      expect("outputSchema" in req).toBe(false);
      expect("somethingElse" in req).toBe(false);
    });

    it("validates extra by key AND type on the v2 path (same rules as v1)", () => {
      expect(() =>
        parsePaymentRequiredV2(v2PaymentRequired({ extra: { symbol: 12345 } })),
      ).toThrow(X402ProtocolError);
      expect(() =>
        parsePaymentRequiredV2(v2PaymentRequired({ extra: { decimals: "6" } })),
      ).toThrow(X402ProtocolError);
    });

    it("defensively copies extra — later mutation of the input cannot reach the requirement", () => {
      const extra = { symbol: "USDC", decimals: 6 };
      const body = v2PaymentRequired({ extra });
      const parsed = parsePaymentRequiredV2(body);
      extra.symbol = "EVIL";
      expect(parsed.accepts[0]!.extra!.symbol).toBe("USDC");
    });

    it("caps accepts at 32 and refuses an empty accepts", () => {
      const one = v2Requirement();
      expect(() =>
        parsePaymentRequiredV2({
          x402Version: 2,
          resource: { url: "https://a.example" },
          accepts: Array.from({ length: 33 }, () => ({ ...one })),
        }),
      ).toThrow(/too many/);
      expect(() =>
        parsePaymentRequiredV2({
          x402Version: 2,
          resource: { url: "https://a.example" },
          accepts: [],
        }),
      ).toThrow(/empty/);
    });
  });

  describe("extensions (an untrusted reflection channel — capped before it can be echoed)", () => {
    const withExt = (extensions: unknown) => ({ ...v2PaymentRequired(), extensions });

    it("accepts well-formed extensions", () => {
      const parsed = parsePaymentRequiredV2(
        withExt({ "payment-identifier": { info: { id: "abc" }, schema: { type: "object" } } }),
      );
      expect(parsed.extensions!["payment-identifier"]!.info).toEqual({ id: "abc" });
    });

    it("treats null extensions as absent", () => {
      expect(parsePaymentRequiredV2(withExt(null)).extensions).toBeUndefined();
    });

    it("refuses an entry missing info or schema (both are required objects)", () => {
      for (const ext of [
        { e: { schema: {} } },
        { e: { info: {} } },
        { e: { info: "x", schema: {} } },
        { e: { info: {}, schema: [] } },
        { e: "not-an-object" },
      ]) {
        expect(() => parsePaymentRequiredV2(withExt(ext))).toThrow(X402ProtocolError);
      }
    });

    it("caps the number of extensions (16)", () => {
      const many: Record<string, unknown> = {};
      for (let i = 0; i < 17; i += 1) many[`ext-${i}`] = { info: {}, schema: {} };
      expect(() => parsePaymentRequiredV2(withExt(many))).toThrow(/too many extensions/);
    });

    it("caps an extension id at 128 chars", () => {
      expect(() =>
        parsePaymentRequiredV2(withExt({ ["x".repeat(129)]: { info: {}, schema: {} } })),
      ).toThrow(/extension id/);
    });

    it("caps the total serialized size (32 KB)", () => {
      expect(() =>
        parsePaymentRequiredV2(
          withExt({ big: { info: { blob: "a".repeat(40 * 1024) }, schema: {} } }),
        ),
      ).toThrow(/too large/);
    });

    it("defensively copies — mutating the input after parse cannot change the echo source", () => {
      const info: Record<string, unknown> = { id: "abc" };
      const parsed = parsePaymentRequiredV2(withExt({ e: { info, schema: {} } }));
      info.id = "EVIL";
      expect(parsed.extensions!.e!.info).toEqual({ id: "abc" });
    });
  });
});

describe("parsePaymentRequiredHeader (base64 carrier)", () => {
  it("round-trips a valid header value", () => {
    const parsed = parsePaymentRequiredHeader(b64(v2PaymentRequired()));
    expect(parsed.x402Version).toBe(2);
  });

  it("refuses garbage that is not base64 JSON", () => {
    expect(() => parsePaymentRequiredHeader("!!!not base64 json!!!")).toThrow(
      X402ProtocolError,
    );
  });

  it("refuses base64 of a non-object (JSON scalar)", () => {
    expect(() =>
      parsePaymentRequiredHeader(Buffer.from('"hello"', "utf8").toString("base64")),
    ).toThrow(X402ProtocolError);
  });

  it("caps the header size BEFORE decoding (DoS guard)", () => {
    const huge = "A".repeat(MAX_PAYMENT_REQUIRED_HEADER_CHARS + 1);
    expect(() => parsePaymentRequiredHeader(huge)).toThrow(/too large/);
  });

  it("an empty header value is a protocol error, not a fallback", () => {
    expect(() => parsePaymentRequiredHeader("")).toThrow(X402ProtocolError);
  });
});

describe("a hostile server must not get to send two prices and pick which is policed", () => {
  // Headers.get() joins repeated headers with ", ". Node's base64 decoder skips
  // characters outside its alphabet and stops at padding, so that separator
  // vanishes and two conflicting headers silently resolve to one — with the
  // SERVER choosing which, via its own padding. Measured before the fix: values
  // quoting 1 and 999999 minor units decoded to the 1.
  const cheap = b64(v2PaymentRequired({ amount: "1" }));
  const dear = b64(v2PaymentRequired({ amount: "999999" }));

  it("refuses two PAYMENT-REQUIRED headers joined by the transport", () => {
    const h = new Headers();
    h.append("PAYMENT-REQUIRED", cheap);
    h.append("PAYMENT-REQUIRED", dear);
    expect(() => parsePaymentRequiredHeader(h.get("PAYMENT-REQUIRED")!)).toThrow(X402ProtocolError);
  });

  it("refuses the join under every padding variant, not just the one observed", () => {
    // Which value survives a lenient decode depends on the padding the server
    // chose, so the refusal must not depend on it either.
    for (const sep of [", ", ",", " , "]) {
      expect(() => parsePaymentRequiredHeader(`${cheap}${sep}${dear}`)).toThrow(X402ProtocolError);
    }
  });

  it("refuses stray characters a lenient decoder would skip", () => {
    for (const bad of [`!!!${cheap}`, `${cheap}\t${dear}`, `${cheap}\r\n`, `${cheap} garbage`]) {
      expect(() => parsePaymentRequiredHeader(bad)).toThrow(X402ProtocolError);
    }
  });

  it("still accepts a single canonical header", () => {
    expect(parsePaymentRequiredHeader(cheap).accepts[0]!.amount).toBe("1");
  });
});

describe("extension ids are data, never prototype levers", () => {
  // On a plain {}, `out["__proto__"] = v` replaces the prototype instead of
  // adding a key, so the entry is SILENTLY DROPPED. The client would then omit
  // an extension the spec obliges it to echo, and the server could reject the
  // request AFTER the payment signature was transmitted — a counted spend that
  // buys nothing.
  for (const id of ["__proto__", "constructor", "prototype"]) {
    it(`refuses an extension named ${id} rather than dropping it`, () => {
      const body = v2PaymentRequired({
        extensions: { [id]: { info: {}, schema: {} } },
      });
      expect(() => parsePaymentRequiredHeader(b64(body))).toThrow(X402ProtocolError);
    });
  }

  it("leaves the returned extensions map free of an inherited prototype", () => {
    const body = v2PaymentRequired({ extensions: { legit: { info: {}, schema: {} } } });
    const parsed = parsePaymentRequiredHeader(b64(body));
    const ext = parsed.extensions!;
    expect(Object.keys(ext)).toEqual(["legit"]);
    // A null-prototype map cannot be steered through Object.prototype at all.
    expect(Object.getPrototypeOf(ext)).toBeNull();
  });
});
