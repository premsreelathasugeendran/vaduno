import { describe, expect, it } from "vitest";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import * as intentShape from "../src/policy/intent-shape.js";
import { inspectIntentShape } from "../src/policy/intent-shape.js";

// Resolved dynamically so this suite RUNS (and demonstrably fails) against the
// unfixed module, which does not export the cap yet.
const MAX_REPORTED_PROBLEMS =
  (intentShape as { MAX_REPORTED_PROBLEMS?: number }).MAX_REPORTED_PROBLEMS ?? 8;
import { makeIntent, makePolicy } from "./helpers.js";

/**
 * THE AMPLIFICATION DEFECT. The DEFECT-7 fix ("a refusal the ledger cannot
 * record must still be refused WITH a record") reported problems EXHAUSTIVELY
 * and un-truncated over attacker-influenced input. Measured before this fix:
 * n=100,000 bad values in one intent produced 18,678,768 bytes of ledger — a
 * steady ~62x amplification, linear and uncapped — because every offending
 * value produced a full {path, problem} record in the intent_received row AND
 * was re-joined into one policy_decision reason message. A tamper-evident,
 * append-only ledger that a counterparty can inflate at will is a
 * denial-of-service surface.
 *
 * THE BOUND THESE TESTS PIN: evidence for a refusal is O(1) in attacker input.
 *  - at most MAX_REPORTED_PROBLEMS problem records are retained, path and
 *    description each truncated to a fixed length; the rest are COUNTED
 *    ("N problems, first K shown"), never enumerated;
 *  - the policy_decision reasons are bounded by a constant;
 *  - the sanitized copy is bounded: containers are truncated at a fixed entry
 *    cap and the whole walk at a fixed node budget, so even a sparse
 *    100-million-slot array (O(1) caller bytes) cannot mint megabytes of rows;
 *  - the sanitized copy is built ONLY when there are problems — a clean intent
 *    (the common case) must not pay for a throwaway deep copy.
 * The refusal stays AUDITED — that was the point of DEFECT 7 and it is kept.
 */

function setup() {
  const store = new MemoryLedgerStore();
  const ledger = new AuditLedger(store);
  const guard = new VadunoGuard({ policy: makePolicy(), ledger });
  return { guard, ledger };
}

async function ledgerBytes(ledger: AuditLedger): Promise<number> {
  return (await ledger.all()).reduce(
    (n, e) => n + JSON.stringify(e).length,
    0,
  );
}

describe("refusal evidence is bounded — no attacker-driven ledger amplification", () => {
  it("50,000 unrepresentable values leave bounded, still-audited evidence", async () => {
    const { guard, ledger } = setup();
    const intent = makeIntent({
      metadata: { blob: new Array(50_000).fill(1n) as unknown as number[] },
    });

    const result = await guard.authorize(intent);
    expect(result.status).toBe("denied");

    // The refusal is still AUDITED: same two rows as any deny.
    const entries = await ledger.all();
    expect(entries.map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
    ]);

    // The problem LIST is capped; the total is COUNTED, not enumerated.
    const received = entries[0]!.data as {
      intentSanitized?: boolean;
      problems?: string[];
      problemsTotal?: number;
    };
    expect(received.intentSanitized).toBe(true);
    expect(received.problems!.length).toBeLessThanOrEqual(MAX_REPORTED_PROBLEMS);
    // 10,000 inspected bad values + 1 container-truncation problem: the cap
    // stops ENUMERATION, and the truncation problem carries the real scale.
    expect(received.problemsTotal).toBe(10_001);

    // No reason message is attacker-sized. Before the fix the
    // INTENT_NOT_SERIALIZABLE message alone was ~4.6 MB for this intent.
    if (result.status === "denied") {
      for (const r of result.policyResult.reasons) {
        expect(r.message.length).toBeLessThan(4_096);
      }
      // The count still tells the operator the true scale.
      const joined = result.policyResult.reasons.map((r) => r.message).join(" ");
      expect(joined).toContain("10001 problems total");
      // Both kinds are present and REPORTED SEPARATELY: 10,000 bigints are
      // unrecordable values; the container cap breach is a size problem, and
      // calling it "cannot record exactly" would be false.
      const codes = result.policyResult.reasons.map((r) => r.code);
      expect(codes).toContain("INTENT_NOT_SERIALIZABLE");
      expect(codes).toContain("INTENT_TOO_LARGE");
    }

    // The sanitized copy's truncation marker names what was NOT inspected —
    // the truth is counted, never silently dropped.
    const rowJson = JSON.stringify(entries[0]);
    expect(rowJson).toContain("array of 50000 entries exceeds");
    expect(rowJson).toContain("40000 not inspected");

    // Whole-ledger bound: markers are short and containers are capped, so the
    // rows stay far below the ~9 MB the unfixed path wrote for this intent.
    expect(await ledgerBytes(ledger)).toBeLessThan(600_000);
  });

  it("a sparse giant array (O(1) caller bytes) cannot mint megabytes of rows", async () => {
    const { guard, ledger } = setup();
    // 100M slots, zero elements: near-zero caller memory. The unfixed walk
    // visits every index; the unfixed record enumerates every one it flags.
    const intent = makeIntent({
      metadata: { sparse: new Array(100_000_000) as unknown as number[] },
    });
    const t0 = performance.now();
    const result = await guard.authorize(intent);
    const ms = performance.now() - t0;
    expect(result.status).toBe("denied");
    expect(ms).toBeLessThan(5_000); // walk is budgeted, not O(array length)
    expect(await ledgerBytes(ledger)).toBeLessThan(600_000);
    if (result.status === "denied") {
      const codes = result.policyResult.reasons.map((r) => r.code);
      // BOTH codes are correct here and the pairing is the point: an array
      // HOLE reads as `undefined`, which JSON renders as null — a different
      // value — so it is genuinely unrepresentable; and the array is also far
      // past the container cap, which is a size problem. The next test pins
      // the pure-size case, where only INTENT_TOO_LARGE may appear.
      expect(codes).toContain("INTENT_TOO_LARGE");
      expect(codes).toContain("INTENT_NOT_SERIALIZABLE");
    }
  });

  it("a representable-but-huge intent is INTENT_TOO_LARGE, never mislabelled", async () => {
    // 25,000 ordinary strings: every value is perfectly canonicalizable. The
    // refusal is honest about WHY — an inspection bound, not a bad value.
    const { guard } = setup();
    const result = await guard.authorize(
      makeIntent({
        metadata: { rows: Array.from({ length: 25_000 }, (_, i) => `row-${i}`) },
      }),
    );
    expect(result.status).toBe("denied");
    if (result.status === "denied") {
      const codes = result.policyResult.reasons.map((r) => r.code);
      expect(codes).toEqual(["INTENT_TOO_LARGE"]);
    }
  });

  it("attacker-controlled keys cannot inflate paths or reasons", async () => {
    const { guard, ledger } = setup();
    const bigKey = "K".repeat(100_000);
    const intent = makeIntent({
      metadata: { [bigKey]: { [bigKey]: 1n as unknown as number } },
    });
    const result = await guard.authorize(intent);
    expect(result.status).toBe("denied");
    if (result.status === "denied") {
      for (const r of result.policyResult.reasons) {
        expect(r.message.length).toBeLessThan(4_096);
      }
    }
    const received = (await ledger.all())[0]!.data as { problems?: string[] };
    for (const p of received.problems ?? []) {
      expect(p.length).toBeLessThan(512);
    }
  });

  it("the amount problem survives truncation even when it is not among the first K", async () => {
    // 20,000 problems land in metadata BEFORE the walk reaches amount (object
    // key order); the amount's own problem must still be reported as
    // INVALID_AMOUNT, not lost to the cap.
    const intent = {
      id: "i-amount-late",
      agentId: "a",
      // metadata first so its problems fill the retained window.
      metadata: { blob: new Array(20_000).fill(1n) },
      merchant: { id: "m" },
      amount: { amountMinor: Number.NaN, currency: "USD" },
      rail: "mock",
      requestedAt: new Date().toISOString(),
    };
    const { guard } = setup();
    const result = await guard.authorize(intent as never);
    expect(result.status).toBe("denied");
    if (result.status === "denied") {
      const codes = result.policyResult.reasons.map((r) => r.code);
      expect(codes).toContain("INVALID_AMOUNT");
      expect(codes).toContain("INTENT_NOT_SERIALIZABLE");
    }
  });

  it("a SMALL bad array is still detected (detect pass walks array elements)", async () => {
    // Regression: the detect pass once skipped array children entirely
    // (`out?.push(walk(...))` short-circuits when out is null), so a
    // two-element bigint array read as CLEAN, the raw intent hit the ledger,
    // canonicalJson threw, and the refusal was a zero-row AUDIT_WRITE_FAILED
    // — the exact evidence-vanishing defect this file exists to prevent.
    const { guard, ledger } = setup();
    const result = await guard.authorize(
      makeIntent({ metadata: { blob: [1n, 2n] as unknown as number[] } }),
    );
    expect(result.status).toBe("denied");
    if (result.status === "denied") {
      const codes = result.policyResult.reasons.map((r) => r.code);
      expect(codes).toContain("INTENT_NOT_SERIALIZABLE");
      expect(codes).not.toContain("AUDIT_WRITE_FAILED");
    }
    expect((await ledger.all()).map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
    ]);
  });

  it("a clean intent does not build (or retain) a sanitized deep copy", () => {
    // Measured before this fix: a clean 2^18-path DAG intent retained +27 MB
    // of materialized copy that was then thrown away (probe-3-baseline 3c).
    const report = inspectIntentShape(makeIntent());
    expect(report.problems).toEqual([]);
    expect(report.sanitized).toBeUndefined();
  });

  it("a malformed intent still records a sanitized copy the ledger can append", async () => {
    const { guard, ledger } = setup();
    const intent = makeIntent({
      metadata: { a: 1n as unknown as number, b: Number.NaN },
    });
    const result = await guard.authorize(intent);
    expect(result.status).toBe("denied");
    const received = (await ledger.all())[0]!.data as {
      intent: { metadata: Record<string, unknown> };
      intentSanitized: boolean;
    };
    expect(received.intentSanitized).toBe(true);
    expect(typeof received.intent.metadata.a).toBe("string");
    expect(typeof received.intent.metadata.b).toBe("string");
    // And the whole ledger verifies — the record was canonicalizable.
    expect((await ledger.verify()).ok).toBe(true);
  });
});
