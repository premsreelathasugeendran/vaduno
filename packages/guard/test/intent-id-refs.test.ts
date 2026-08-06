/**
 * REATTACK FINDINGS (r5) — two related identity defects around non-string
 * intent ids:
 *
 * 1. REGRESSION: the refs sanitization mapped EVERY distinct non-string
 *    id to the same constant "(unknown)" ledger index, so distinct denied
 *    attempts (bigint ids 111n / 222n) merged under one trail — their
 *    policy_decision rows became unattributable. In a per-payment audit
 *    product, an index a hostile agent can deliberately collide is a defect.
 *    Fix: a TYPE-TAGGED injective rendering — "(bigint 111)", "(number 42)".
 *
 * 2. A canonicalizable non-string id (the number 42, null, undefined) passed
 *    shape inspection and EXECUTED, with GuardResult.intentId returning the
 *    raw non-string at runtime despite the declared `string` type — three
 *    identities for one payment (raw 42 in the result, "(unknown)" in the
 *    ledger, string per the type). Fix: intent.id / intent.agentId that are
 *    not strings are now DENIED (INTENT_ID_NOT_STRING) with the usual two
 *    audited rows, before any budget or mandate use is touched.
 */
import { describe, expect, it } from "vitest";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { makeIntent, makePolicy } from "./helpers.js";
import type { PaymentIntent } from "../src/types.js";

function setup() {
  const store = new MemoryLedgerStore();
  const ledger = new AuditLedger(store);
  const guard = new VadunoGuard({ policy: makePolicy(), ledger });
  return { ledger, guard };
}

const never = async () => {
  throw new Error("executor must never run for a non-string id");
};

const asIntent = (over: Record<string, unknown>): PaymentIntent =>
  makeIntent(over as Partial<PaymentIntent>);

describe("non-string intent.id / agentId are denied, never executed", () => {
  const cases: Array<[string, unknown]> = [
    ["number", 42],
    ["null", null],
    ["undefined", undefined],
    ["boolean", true],
  ];

  for (const [label, id] of cases) {
    it(`intent.id = ${label} is denied INTENT_ID_NOT_STRING with two rows`, async () => {
      const { guard, ledger } = setup();
      const r = await guard.execute(asIntent({ id }), never);
      expect(r.status).toBe("denied");
      if (r.status === "denied") {
        expect(r.policyResult.reasons.map((x) => x.code)).toContain(
          "INTENT_ID_NOT_STRING",
        );
        expect(typeof r.intentId).toBe("string");
      }
      const entries = await ledger.all();
      expect(entries.map((e) => e.type)).toEqual([
        "intent_received",
        "policy_decision",
      ]);
      expect((await ledger.verify()).ok).toBe(true);
    });
  }

  it("agentId = number is denied the same way", async () => {
    const { guard, ledger } = setup();
    const r = await guard.execute(asIntent({ agentId: 7 }), never);
    expect(r.status).toBe("denied");
    if (r.status === "denied") {
      expect(r.policyResult.reasons.map((x) => x.code)).toContain(
        "INTENT_ID_NOT_STRING",
      );
    }
    expect((await ledger.all())).toHaveLength(2);
  });

  it("authorize() denies identically (two-phase path)", async () => {
    const { guard } = setup();
    const r = await guard.authorize(asIntent({ id: 42 }));
    expect(r.status).toBe("denied");
  });
});

describe("distinct non-string ids leave DISTINCT ledger indexes", () => {
  it("number ids 42 and 99 do not share a trail", async () => {
    const { guard, ledger } = setup();
    await guard.execute(asIntent({ id: 42 }), never);
    await guard.execute(asIntent({ id: 99 }), never);
    const t42 = await ledger.trailFor("(number 42)");
    const t99 = await ledger.trailFor("(number 99)");
    expect(t42).toHaveLength(2);
    expect(t99).toHaveLength(2);
    expect(await ledger.trailFor("(unknown)")).toHaveLength(0);
  });

  it("bigint ids 111n and 222n do not share a trail (shape-deny path)", async () => {
    const { guard, ledger } = setup();
    await guard.execute(asIntent({ id: 111n }), never);
    await guard.execute(asIntent({ id: 222n }), never);
    const a = await ledger.trailFor("(bigint 111)");
    const b = await ledger.trailFor("(bigint 222)");
    expect(a).toHaveLength(2);
    expect(b).toHaveLength(2);
    expect(await ledger.trailFor("(unknown)")).toHaveLength(0);
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("GuardResult.intentId equals the ledger index (one identity per attempt)", async () => {
    const { guard, ledger } = setup();
    const r = await guard.execute(asIntent({ id: 42 }), never);
    expect(r.intentId).toBe("(number 42)");
    expect(await ledger.trailFor(r.intentId)).toHaveLength(2);
  });

  it("a legitimate string id that LOOKS like a tag rides verbatim", async () => {
    const { guard, ledger } = setup();
    const odd = "(number 42)";
    const r = await guard.execute(
      makeIntent({ id: odd, amount: { amountMinor: 999_999_999, currency: "USD" } }),
      never,
    );
    expect(r.status).toBe("denied");
    expect(r.intentId).toBe(odd);
    expect(await ledger.trailFor(odd)).toHaveLength(2);
  });
});
