import { describe, expect, it } from "vitest";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { makeIntent, makePolicy } from "./helpers.js";

/**
 * FINDING C — an intent carrying a value JSON cannot represent used to be
 * refused with AUDIT_WRITE_FAILED and ZERO ledger entries: the refusal was
 * correct, the RECORD of it vanished. A normal deny writes two entries
 * (intent_received + policy_decision); the malformed one wrote none, so the
 * one attempt an operator most wants to see was the one attempt with no
 * evidence at all.
 */

function setup(policyOver = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({ policy: makePolicy(policyOver), ledger });
  return { ledger, guard };
}

const never = async () => {
  throw new Error("executor must never run for a malformed intent");
};

/** The evidence a normal (well-formed) deny leaves, for comparison. */
async function normalDenyEntryCount(): Promise<number> {
  const { guard, ledger } = setup();
  const r = await guard.execute(
    makeIntent({ amount: { amountMinor: 999_999_999, currency: "USD" } }),
    never,
  );
  expect(r.status).toBe("denied");
  return (await ledger.all()).length;
}

describe("intent validation is audited, never an audit-write failure", () => {
  const badAmounts: Array<[string, number]> = [
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
  ];

  for (const [label, amountMinor] of badAmounts) {
    it(`denies INVALID_AMOUNT and audits it for amountMinor = ${label}`, async () => {
      const { guard, ledger } = setup();
      const result = await guard.execute(
        makeIntent({ amount: { amountMinor, currency: "USD" } }),
        never,
      );

      expect(result.status).toBe("denied");
      const codes = result.policyResult.reasons.map((r) => r.code);
      expect(codes).toContain("INVALID_AMOUNT");
      expect(codes).not.toContain("AUDIT_WRITE_FAILED");

      const entries = await ledger.all();
      // The refusal must leave the SAME evidence a well-formed deny leaves.
      expect(entries.length).toBe(await normalDenyEntryCount());
      expect(entries.map((e) => e.type)).toEqual([
        "intent_received",
        "policy_decision",
      ]);
      expect((await ledger.verify()).ok).toBe(true);
    });
  }

  const otherBadAmounts: Array<[string, number]> = [
    ["negative", -100],
    ["zero", 0],
    ["negative zero", -0],
    ["non-integer minor units", 12.5],
    ["beyond safe-integer range", Number.MAX_SAFE_INTEGER + 2],
  ];

  for (const [label, amountMinor] of otherBadAmounts) {
    it(`denies INVALID_AMOUNT and audits it for a ${label} amount`, async () => {
      const { guard, ledger } = setup();
      const result = await guard.execute(
        makeIntent({ amount: { amountMinor, currency: "USD" } }),
        never,
      );
      expect(result.status).toBe("denied");
      expect(result.policyResult.reasons.map((r) => r.code)).toContain(
        "INVALID_AMOUNT",
      );
      const entries = await ledger.all();
      expect(entries.map((e) => e.type)).toEqual([
        "intent_received",
        "policy_decision",
      ]);
    });
  }

  it("denies a non-number amountMinor with INVALID_AMOUNT, audited", async () => {
    const { guard, ledger } = setup();
    const result = await guard.execute(
      // A JSON config that shipped "500" instead of 500. Never coerced.
      makeIntent({ amount: { amountMinor: "500" as unknown as number, currency: "USD" } }),
      never,
    );
    expect(result.status).toBe("denied");
    expect(result.policyResult.reasons.map((r) => r.code)).toContain(
      "INVALID_AMOUNT",
    );
    expect((await ledger.all()).map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
    ]);
  });

  it("denies a non-finite value ANYWHERE in the intent, audited", async () => {
    const { guard, ledger } = setup();
    const result = await guard.execute(
      makeIntent({ metadata: { retryBudget: Number.POSITIVE_INFINITY } }),
      never,
    );
    expect(result.status).toBe("denied");
    const codes = result.policyResult.reasons.map((r) => r.code);
    expect(codes).toContain("INTENT_NOT_SERIALIZABLE");
    expect(codes).not.toContain("AUDIT_WRITE_FAILED");
    const entries = await ledger.all();
    expect(entries.map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
    ]);
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("denies a bigint in the intent, audited", async () => {
    const { guard, ledger } = setup();
    const result = await guard.execute(
      makeIntent({ metadata: { onChainValue: 10_000n } }),
      never,
    );
    expect(result.status).toBe("denied");
    expect(result.policyResult.reasons.map((r) => r.code)).toContain(
      "INTENT_NOT_SERIALIZABLE",
    );
    expect((await ledger.all()).map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
    ]);
  });

  it("audits the same way on the two-phase authorize() path", async () => {
    const { guard, ledger } = setup();
    const result = await guard.authorize(
      makeIntent({ amount: { amountMinor: Number.NaN, currency: "USD" } }),
    );
    expect(result.status).toBe("denied");
    expect((await ledger.all()).map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
    ]);
  });

  /**
   * THE REGRESSION intent-shape.ts EXISTED TO KILL, resurfaced through the
   * ENTRY REFS. inspectIntentShape sanitizes what lands in `data` — but the
   * guard also passed RAW `safe.id` / `safe.agentId` as append refs, which
   * AuditLedger places as TOP-LEVEL entry fields, and entryHash()
   * canonicalizes the WHOLE entry. So a canonicalJson-hostile value in
   * intent.id or intent.agentId made the FIRST append throw:
   * AUDIT_WRITE_FAILED, zero ledger rows — while the sanitized intent copy
   * sat unused in the entry that never got written. Measured before the fix:
   * 500 refused attempts, 0 rows.
   */
  // The expected index is TYPE-TAGGED and injective per value (a constant
  // "(unknown)" sentinel merged distinct hostile ids into one trail — see
  // intent-id-refs.test.ts).
  const hostileRefValues: Array<[string, unknown, string]> = [
    ["a bigint", 10n, "(bigint 10)"],
    ["NaN", Number.NaN, "(number NaN)"],
    ["Infinity", Number.POSITIVE_INFINITY, "(number Infinity)"],
    // structuredClone preserves it; canonicalJson refuses it
    ["a Date", new Date(0), "(date 1970-01-01T00:00:00.000Z)"],
  ];

  for (const [label, value, taggedRef] of hostileRefValues) {
    it(`denies and AUDITS an intent whose id is ${label} — two rows, never zero`, async () => {
      const { guard, ledger } = setup();
      const result = await guard.execute(
        makeIntent({ id: value as unknown as string }),
        never,
      );
      expect(result.status).toBe("denied");
      const codes = result.policyResult.reasons.map((r) => r.code);
      expect(codes).toContain("INTENT_NOT_SERIALIZABLE");
      expect(codes).not.toContain("AUDIT_WRITE_FAILED");

      const entries = await ledger.all();
      expect(entries.map((e) => e.type)).toEqual([
        "intent_received",
        "policy_decision",
      ]);
      // The non-string id cannot ride the entry as an index; the honest
      // index for it is a bounded type-tagged rendering — injective, so
      // distinct hostile ids cannot deliberately collide into one trail.
      expect(entries[0]!.intentId).toBe(taggedRef);
      expect((await ledger.verify()).ok).toBe(true);
    });

    it(`denies and AUDITS an intent whose agentId is ${label} — two rows, never zero`, async () => {
      const { guard, ledger } = setup();
      const result = await guard.execute(
        makeIntent({ agentId: value as unknown as string }),
        never,
      );
      expect(result.status).toBe("denied");
      expect(result.policyResult.reasons.map((r) => r.code)).toContain(
        "INTENT_NOT_SERIALIZABLE",
      );
      const entries = await ledger.all();
      expect(entries.map((e) => e.type)).toEqual([
        "intent_received",
        "policy_decision",
      ]);
      expect(entries[0]!.agentId).toBe(taggedRef);
      expect((await ledger.verify()).ok).toBe(true);
    });
  }

  it("hostile-id refusals keep accumulating evidence — N attempts leave 2N rows, not zero", async () => {
    const { guard, ledger } = setup();
    for (let i = 0; i < 5; i += 1) {
      await guard.execute(makeIntent({ id: 10n as unknown as string }), never);
    }
    expect((await ledger.all()).length).toBe(10);
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("a string id — even a prototype-named one — still rides the entry refs verbatim", async () => {
    const { guard, ledger } = setup();
    await guard.execute(
      makeIntent({
        id: "__proto__",
        amount: { amountMinor: 999_999_999, currency: "USD" },
      }),
      never,
    );
    const entries = await ledger.all();
    expect(entries[0]!.intentId).toBe("__proto__");
    expect((await ledger.trailFor("__proto__")).length).toBe(2);
  });

  it("the recorded intent_received is readable and names the problem", async () => {
    const { guard, ledger } = setup();
    await guard.execute(
      makeIntent({ amount: { amountMinor: Number.NaN, currency: "USD" } }),
      never,
    );
    const [received] = await ledger.all();
    const data = received!.data as {
      intent?: { amount?: { amountMinor?: unknown } };
      intentSanitized?: boolean;
      problems?: string[];
    };
    // The offending value cannot be recorded verbatim (that is what broke the
    // append), so it is recorded as a redaction marker — and the entry says so.
    expect(data.intentSanitized).toBe(true);
    expect(Array.isArray(data.problems)).toBe(true);
    expect(data.problems!.join(" ")).toContain("amountMinor");
    expect(typeof data.intent?.amount?.amountMinor).toBe("string");
  });
});
