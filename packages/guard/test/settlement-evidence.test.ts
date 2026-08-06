/**
 * REATTACK FINDING (r6) — settle() lost its execution_result row on hostile
 * caller input: `guard.settle(id, { status: "failed", error: 10n })` made the
 * best-effort append throw inside canonicalJson, so the settlement outcome of
 * a REAL authorization went unrecorded (3 rows instead of 4, auditDegraded
 * flagged, chain verifying). Fail-closed on money, but the same generalized
 * shape as the fixed zero-row defects: caller-side input was never sanitized
 * before an evidence write.
 *
 * Fix: the settlement outcome's `error` (and the intentId ref) are sanitized
 * before the append, so the row always lands — with the non-string value
 * recorded in a bounded, type-tagged form.
 */
import { describe, expect, it } from "vitest";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { makeIntent, makePolicy } from "./helpers.js";

function setup() {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({ policy: makePolicy(), ledger });
  return { ledger, guard };
}

describe("settle() records its execution_result even for hostile outcome values", () => {
  const hostiles: Array<[string, unknown]> = [
    ["bigint", 10n],
    ["NaN", Number.NaN],
    ["object with bigint", { code: 10n }],
    ["undefined-in-array", [undefined]],
  ];

  for (const [label, error] of hostiles) {
    it(`error = ${label} still lands a 4th row`, async () => {
      const { guard, ledger } = setup();
      const id = `settle-${label}`;
      const auth = await guard.authorize(makeIntent({ id }));
      expect(auth.status).toBe("authorized");

      await guard.settle(id, {
        status: "failed",
        error: error as unknown as string,
      });

      const trail = await ledger.trailFor(id);
      expect(trail.map((e) => e.type)).toEqual([
        "intent_received",
        "policy_decision",
        "execution_started",
        "execution_result",
      ]);
      expect(guard.isAuditDegraded()).toBe(false);
      expect((await ledger.verify()).ok).toBe(true);
    });
  }

  it("a normal string error is recorded verbatim (control)", async () => {
    const { guard, ledger } = setup();
    const auth = await guard.authorize(makeIntent({ id: "settle-ok" }));
    expect(auth.status).toBe("authorized");
    await guard.settle("settle-ok", { status: "failed", error: "card_declined" });
    const trail = await ledger.trailFor("settle-ok");
    const result = trail.find((e) => e.type === "execution_result");
    expect((result?.data as { error?: unknown }).error).toBe("card_declined");
  });
});
