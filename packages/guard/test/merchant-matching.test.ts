import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { evaluatePolicy, merchantMatches } from "../src/policy/engine.js";
import { emptyHistory, makeIntent, makePolicy } from "./helpers.js";

/**
 * FINDING B — the honest guarantee of merchant pattern matching.
 *
 * `policy/engine.ts` used to document `id:` patterns as WEAK ("merchant.id is
 * not verified") and host patterns as the strong form. Both statements are
 * about the SAME kind of value: `merchant.url` is set by the caller exactly as
 * `merchant.id` is, and the threat model already assumes the agent controls
 * every field of the intent. Host patterns are not stronger in TRUST — only in
 * MATCHING PRECISION (URL host parsing plus a dot boundary, so `evil-x402.org`
 * cannot pass as `x402.org`).
 *
 * The worked example that makes the old ranking backwards: in a signer-level
 * integration the guard sees `merchant.id` = the payee address extracted from
 * the bytes about to be signed (the strongest fact available) and
 * `merchant.url` = a constant fixed once at construction. A policy of
 * `merchants.allow: ["host:x402.org"]` then matches for EVERY recipient.
 *
 * The code defect that shipped alongside the overstatement: a host-form entry
 * in `merchants.block` silently fails to block when the intent carries no
 * usable URL — not-matching means "not blocked", so an agent evades an entire
 * blocklist by omitting one optional field.
 */

const engineSrc = readFileSync(
  fileURLToPath(new URL("../src/policy/engine.ts", import.meta.url)),
  "utf8",
);
const securityMd = readFileSync(
  fileURLToPath(new URL("../../../SECURITY.md", import.meta.url)),
  "utf8",
);

describe("merchant blocklist cannot be evaded by omitting merchant.url", () => {
  it("denies when a host-form BLOCK pattern cannot be evaluated (no url)", async () => {
    const result = await evaluatePolicy(
      makeIntent({ merchant: { id: "totally-fine" } }),
      makePolicy({ merchants: { block: ["evil.com"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain(
      "MERCHANT_URL_UNVERIFIABLE",
    );
  });

  it("denies when a host-form BLOCK pattern cannot be evaluated (unparseable url)", async () => {
    const result = await evaluatePolicy(
      makeIntent({ merchant: { id: "x", url: "not a url" } }),
      makePolicy({ merchants: { block: ["host:evil"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain(
      "MERCHANT_URL_UNVERIFIABLE",
    );
  });

  it("still blocks normally when the url IS present", async () => {
    const result = await evaluatePolicy(
      makeIntent({ merchant: { id: "x", url: "https://evil.com/pay" } }),
      makePolicy({ merchants: { block: ["evil.com"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("MERCHANT_BLOCKED");
  });

  it("an id-form blocklist alone does NOT require a url", async () => {
    // Only host-form patterns need a URL to mean anything. An id-only
    // blocklist is fully evaluable against an intent that carries no url.
    const result = await evaluatePolicy(
      makeIntent({ merchant: { id: "openai" } }),
      makePolicy({ merchants: { block: ["id:evil-corp"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("allow");
  });

  it("an ALLOW-only host policy stays a plain deny, not a url error", async () => {
    // Allow-side failure to match is already fail-closed; it must keep
    // reporting MERCHANT_NOT_ALLOWED rather than being reclassified.
    const result = await evaluatePolicy(
      makeIntent({ merchant: { id: "openai" } }),
      makePolicy({ merchants: { allow: ["openai.com"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    const codes = result.reasons.map((r) => r.code);
    expect(codes).toContain("MERCHANT_NOT_ALLOWED");
    expect(codes).not.toContain("MERCHANT_URL_UNVERIFIABLE");
  });
});

describe("merchantMatches semantics that must not drift", () => {
  it("host patterns match the caller-supplied url, at a dot boundary only", () => {
    const at = (url?: string) =>
      merchantMatches(makeIntent({ merchant: { id: "anything", ...(url ? { url } : {}) } }), "x402.org");
    expect(at("https://x402.org/protected")).toBe(true);
    expect(at("https://api.x402.org/protected")).toBe(true);
    expect(at("https://evil-x402.org/protected")).toBe(false);
    expect(at("https://x402.org.evil.com/")).toBe(false);
    expect(at(undefined)).toBe(false);
  });

  it("a host pattern is blind to the payee: the same url matches every merchant.id", () => {
    // This is the honest guarantee, pinned. A constant merchant.url makes a
    // host pattern match for ANY recipient, so the pattern is only as strong
    // as the caller's discipline in deriving merchant.url per intent.
    const constUrl = "https://x402.org/protected";
    for (const id of ["0xdeadbeef", "0x0000000000000000000000000000000000000001", "anyone"]) {
      expect(
        merchantMatches(makeIntent({ merchant: { id, url: constUrl } }), "host:x402.org"),
      ).toBe(true);
    }
  });
});

describe("the documented claim matches the evidence", () => {
  it("engine.ts no longer ranks host patterns as trust-stronger than id patterns", () => {
    // A doc claim that outruns the evidence is a defect in this project. The
    // old text called id patterns WEAK because "merchant.id is not verified",
    // implying merchant.url IS — it is not; the caller sets both.
    expect(engineSrc).not.toContain("WEAK: merchant.id is not verified");
    // and it must say the honest thing instead
    expect(engineSrc).toContain("NEITHER FORM VERIFIES THE PAYEE");
  });

  it("SECURITY.md no longer claims host patterns escape attacker-controlled fields", () => {
    expect(securityMd).not.toContain(
      "never the attacker-controlled `merchant.id`",
    );
    expect(securityMd).toContain("`merchant.url` is caller-supplied");
  });
});
