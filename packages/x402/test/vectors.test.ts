/**
 * Conformance against the committed x402 carrier vectors.
 *
 * These tests read `spec/vectors/x402-http-v{1,2}.json` — committed constants,
 * regenerated only deliberately via `node scripts/gen-vectors.mjs` — and
 * assert the implementation reproduces them. The v2 blobs are VERBATIM from
 * the x402 spec's transports-v2/http.md examples, so a failure here means
 * this adapter disagrees with the spec's own wire examples. A failure is
 * never a reason to regenerate the vectors until the test passes.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  decodeSettlementResponse,
  parsePaymentRequired,
  parsePaymentRequiredHeader,
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  X_PAYMENT_HEADER,
  X_PAYMENT_RESPONSE_HEADER,
} from "../src/parse.js";

const vectorsDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "spec",
  "vectors",
);
const load = <T>(name: string): T =>
  JSON.parse(readFileSync(join(vectorsDir, name), "utf8")) as T;

interface VersionOutcome {
  x402Version: string;
  body: unknown;
  outcome: string;
  detectedVersion?: number;
  value?: unknown;
}

function observe(fn: () => unknown): VersionOutcome {
  try {
    return { x402Version: "", body: null, outcome: "parsed", value: fn() };
  } catch (err) {
    const e = err as Error & { detectedVersion?: number };
    return {
      x402Version: "",
      body: null,
      outcome: e.name,
      ...(e.detectedVersion !== undefined ? { detectedVersion: e.detectedVersion } : {}),
    };
  }
}

describe("x402-http-v1.json (frozen v1 carrier conformance)", () => {
  const vec = load<{
    headers: { payment: string; settlement: string };
    body: unknown;
    parsed: unknown;
    versionOutcomes: VersionOutcome[];
  }>("x402-http-v1.json");

  it("header names match the committed constants", () => {
    expect(X_PAYMENT_HEADER).toBe(vec.headers.payment);
    expect(X_PAYMENT_RESPONSE_HEADER).toBe(vec.headers.settlement);
  });

  it("parsePaymentRequired reproduces the committed normalized output", () => {
    expect(parsePaymentRequired(vec.body)).toEqual(vec.parsed);
  });

  it("reproduces EVERY committed version outcome — the discriminant is total", () => {
    expect(vec.versionOutcomes.length).toBeGreaterThanOrEqual(13);
    for (const expected of vec.versionOutcomes) {
      const actual = observe(() => parsePaymentRequired(expected.body));
      expect(actual.outcome, `x402Version=${expected.x402Version}`).toBe(expected.outcome);
      expect(actual.detectedVersion, `x402Version=${expected.x402Version}`).toBe(
        expected.detectedVersion,
      );
      if (expected.outcome === "parsed") {
        expect(actual.value, `x402Version=${expected.x402Version}`).toEqual(expected.value);
      }
    }
  });

  it("the table refuses the downgrade channel: only absent and integer 1 parse", () => {
    const parsedLabels = vec.versionOutcomes
      .filter((o) => o.outcome === "parsed")
      .map((o) => o.x402Version)
      .sort();
    expect(parsedLabels).toEqual(["1", "absent"]);
  });
});

describe("x402-http-v2.json (frozen v2 carrier conformance, spec-verbatim blobs)", () => {
  const vec = load<{
    headers: { paymentRequired: string; payment: string; settlement: string };
    specExample: {
      paymentRequiredHeader: string;
      paymentRequiredDecoded: unknown;
      parsed: unknown;
      paymentSignatureHeader: string;
      paymentSignatureDecoded: unknown;
      settlementOkHeader: string;
      settlementOkDecoded: unknown;
      settlementFailHeader: string;
      settlementFailDecoded: unknown;
    };
    versionOutcomes: VersionOutcome[];
  }>("x402-http-v2.json");

  it("header names match the committed constants", () => {
    expect(PAYMENT_REQUIRED_HEADER).toBe(vec.headers.paymentRequired);
    expect(PAYMENT_SIGNATURE_HEADER).toBe(vec.headers.payment);
    expect(PAYMENT_RESPONSE_HEADER).toBe(vec.headers.settlement);
  });

  it("each spec blob decodes to exactly the committed JSON (the vectors are self-consistent)", () => {
    const decode = (b64: string) =>
      JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
    expect(decode(vec.specExample.paymentRequiredHeader)).toEqual(
      vec.specExample.paymentRequiredDecoded,
    );
    expect(decode(vec.specExample.paymentSignatureHeader)).toEqual(
      vec.specExample.paymentSignatureDecoded,
    );
    expect(decode(vec.specExample.settlementOkHeader)).toEqual(
      vec.specExample.settlementOkDecoded,
    );
    expect(decode(vec.specExample.settlementFailHeader)).toEqual(
      vec.specExample.settlementFailDecoded,
    );
  });

  it("parsePaymentRequiredHeader reproduces the committed parse of the spec's PAYMENT-REQUIRED blob", () => {
    expect(parsePaymentRequiredHeader(vec.specExample.paymentRequiredHeader)).toEqual(
      vec.specExample.parsed,
    );
  });

  it("decodeSettlementResponse reproduces the committed settlement decodes (success and failure)", () => {
    expect(decodeSettlementResponse(vec.specExample.settlementOkHeader)).toEqual(
      vec.specExample.settlementOkDecoded,
    );
    const fail = decodeSettlementResponse(vec.specExample.settlementFailHeader);
    expect(fail).toEqual(vec.specExample.settlementFailDecoded);
    expect(fail?.success).toBe(false);
    expect(fail?.errorReason).toBe("insufficient_funds");
  });

  it("reproduces EVERY committed version outcome — the discriminant is total", () => {
    expect(vec.versionOutcomes.length).toBeGreaterThanOrEqual(11);
    for (const expected of vec.versionOutcomes) {
      const header = Buffer.from(JSON.stringify(expected.body), "utf8").toString("base64");
      const actual = observe(() => parsePaymentRequiredHeader(header));
      expect(actual.outcome, `x402Version=${expected.x402Version}`).toBe(expected.outcome);
      expect(actual.detectedVersion, `x402Version=${expected.x402Version}`).toBe(
        expected.detectedVersion,
      );
      if (expected.outcome === "parsed") {
        expect(actual.value, `x402Version=${expected.x402Version}`).toEqual(expected.value);
      }
    }
  });

  it("the table admits exactly one version on the v2 carrier: the integer 2", () => {
    const parsedLabels = vec.versionOutcomes
      .filter((o) => o.outcome === "parsed")
      .map((o) => o.x402Version);
    expect(parsedLabels).toEqual(["2"]);
  });
});
