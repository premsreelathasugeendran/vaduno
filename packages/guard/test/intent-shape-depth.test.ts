import { describe, expect, it } from "vitest";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import * as intentShape from "../src/policy/intent-shape.js";
import { inspectIntentShape } from "../src/policy/intent-shape.js";
import { canonicalJson } from "../src/ledger/hash.js";
import { makeIntent, makePolicy } from "./helpers.js";

/**
 * DEPTH IS MEASURED FROM THE ROOT canonicalJson ACTUALLY SERIALIZES.
 *
 * THE DEFECT THESE TESTS PIN. intent-shape.ts walked the INTENT from depth 0
 * with the same MAX_DEPTH as canonicalJson (256) — but canonicalJson
 * serializes the LEDGER ENTRY, where the intent sits at `entry.data.intent`,
 * two levels deeper. So a WELL-FORMED, fully valid, about-to-execute payment
 * nested a little past the walker's blind spot passed inspection with zero
 * problems and then blew up inside entryHash(): AUDIT_WRITE_FAILED, ZERO
 * ledger rows, no execution. Worse, the window had NO upper recovery bound:
 * once the walker DID flag the depth (past its own 256), the sanitization
 * marker it wrote sat one level below the over-deep value — still too deep
 * for the entry — so d=263, d=300, d=1000 all wrote zero rows too. The
 * "sanitize so the append always succeeds" machinery produced an
 * unappendable sanitized copy.
 *
 * THE PROPERTY: for ANY intent depth structuredClone can even produce, the
 * outcome is either (a) executed with its full trail, or (b) denied with the
 * same two rows any deny leaves. Zero rows is never an outcome.
 */

// Resolved dynamically so this suite RUNS (and demonstrably fails) against
// the unfixed module, which does not export the depth limit yet.
const MAX_INTENT_DEPTH =
  (intentShape as { MAX_INTENT_DEPTH?: number }).MAX_INTENT_DEPTH ?? 253;

function setup() {
  const store = new MemoryLedgerStore();
  const ledger = new AuditLedger(store);
  const guard = new VadunoGuard({ policy: makePolicy(), ledger });
  return { guard, ledger };
}

/** `levels` nested plain objects around a string leaf. nested(0) === "leaf". */
function nested(levels: number): unknown {
  let v: unknown = "leaf";
  for (let i = 0; i < levels; i += 1) v = { a: v };
  return v;
}

/**
 * An otherwise ordinary, policy-passing intent whose DEEPEST node (the leaf
 * string) sits at exactly `depth` levels below the intent root.
 * `metadata` itself is at depth 1, so it wraps `depth - 1` object levels.
 */
function intentOfDepth(depth: number) {
  return makeIntent({
    metadata: nested(depth - 1) as Record<string, unknown>,
  });
}

describe("intent depth is measured from the LEDGER-ENTRY root, not the intent root", () => {
  it(`a valid intent at the deepest recordable depth (${MAX_INTENT_DEPTH}) EXECUTES, with its full trail on the ledger`, async () => {
    const { guard, ledger } = setup();
    const result = await guard.execute(
      intentOfDepth(MAX_INTENT_DEPTH),
      async () => "paid",
    );
    expect(result.status).toBe("executed");
    const entries = await ledger.all();
    expect(entries.map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
      "execution_started",
      "execution_result",
    ]);
    // The premise the depth limit rests on: the intent rides at
    // entry.data.intent — TWO envelope levels above it. If the envelope ever
    // deepens, this round-trip through the real ledger is the test that fails.
    const received = entries[0]!.data as { intent?: unknown };
    expect(received.intent).toBeDefined();
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("one level past the limit is DENIED INTENT_TOO_LARGE with the same two rows as any deny — not AUDIT_WRITE_FAILED with zero", async () => {
    const { guard, ledger } = setup();
    const result = await guard.execute(intentOfDepth(MAX_INTENT_DEPTH + 1), async () => {
      throw new Error("executor must not run for an unrecordable intent");
    });
    expect(result.status).toBe("denied");
    if (result.status === "denied") {
      const codes = result.policyResult.reasons.map((r) => r.code);
      expect(codes).toContain("INTENT_TOO_LARGE");
      expect(codes).not.toContain("AUDIT_WRITE_FAILED");
    }
    const entries = await ledger.all();
    expect(entries.map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
    ]);
    expect((await ledger.verify()).ok).toBe(true);
  });

  // CORRECTION 2 FROM THE ADJUDICATION: the zero-row window was NOT a bounded
  // band — every depth past the boundary wrote zero rows, without an upper
  // recovery bound. So the fix is proven across the whole range structured-
  // clone can produce, not just past the first few depths.
  const depths = [
    MAX_INTENT_DEPTH + 1,
    MAX_INTENT_DEPTH + 2, // formerly: passed inspection, entry too deep -> 0 rows
    MAX_INTENT_DEPTH + 5,
    MAX_INTENT_DEPTH + 10,
    MAX_INTENT_DEPTH + 47, // ~300
    500,
    1000,
  ];
  for (const d of depths) {
    it(`depth ${d}: denied with two rows and a verifying chain (no upper recovery bound)`, async () => {
      const { guard, ledger } = setup();
      const result = await guard.execute(intentOfDepth(d), async () => {
        throw new Error("executor must not run");
      });
      expect(result.status).toBe("denied");
      if (result.status === "denied") {
        expect(result.policyResult.reasons.map((r) => r.code)).toContain(
          "INTENT_TOO_LARGE",
        );
      }
      const entries = await ledger.all();
      expect(entries.map((e) => e.type)).toEqual([
        "intent_received",
        "policy_decision",
      ]);
      expect((await ledger.verify()).ok).toBe(true);
    });
  }

  it("a depth even structuredClone refuses still leaves a trace and never executes", async () => {
    // ~20,000 levels: structuredClone itself throws RangeError, so this rides
    // the non-cloneable path (best-effort policy_decision), not the walker.
    // The point stays the same: no depth reaches the executor unrecorded.
    const { guard, ledger } = setup();
    let ran = false;
    const result = await guard.execute(intentOfDepth(20_000), async () => {
      ran = true;
      return "paid";
    });
    expect(ran).toBe(false);
    expect(result.status).toBe("denied");
    if (result.status === "denied") {
      expect(result.policyResult.reasons.map((r) => r.code)).toContain(
        "INTENT_NOT_SERIALIZABLE",
      );
    }
    expect((await ledger.all()).length).toBeGreaterThanOrEqual(1);
  });

  it("unit: the sanitized copy of an over-deep intent canonicalizes AT LEDGER-ENTRY NESTING for any depth", () => {
    for (const d of [MAX_INTENT_DEPTH + 1, 300, 1000, 5000, 100_000]) {
      // Direct walk (no structuredClone), so this covers depths beyond what
      // the guard path can even snapshot.
      const report = inspectIntentShape({ metadata: nested(d - 1) });
      expect(report.totalProblems).toBeGreaterThan(0);
      expect(report.oversize).toBe(true);
      // The exact envelope the guard appends: entry.data.intent.
      expect(() =>
        canonicalJson({
          seq: 0,
          timestamp: "2026-01-01T00:00:00.000Z",
          type: "intent_received",
          data: { intent: report.sanitized, intentSanitized: true },
          prevHash: "0".repeat(64),
        }),
      ).not.toThrow();
    }
  });

  it("unit: the deepest ACCEPTED intent canonicalizes at ledger-entry nesting too", () => {
    const intent = { metadata: nested(MAX_INTENT_DEPTH - 1) };
    const report = inspectIntentShape(intent);
    expect(report.totalProblems).toBe(0);
    expect(() =>
      canonicalJson({
        seq: 0,
        timestamp: "2026-01-01T00:00:00.000Z",
        type: "intent_received",
        data: { intent },
        prevHash: "0".repeat(64),
      }),
    ).not.toThrow();
  });
});
