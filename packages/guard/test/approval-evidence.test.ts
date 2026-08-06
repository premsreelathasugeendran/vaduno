/**
 * REATTACK FINDING (r7) — a hostile (or merely buggy) approval-handler
 * response converted a human APPROVAL into a deny and lost the
 * approval_resolved row: with step-up triggered and a handler returning
 * `{ approved: true, note: 10n }`, the hard `approval_resolved` append threw
 * inside canonicalJson, the outer catch denied GUARD_INTERNAL_ERROR, and the
 * one row missing from the trail was the human's actual decision — while the
 * deny reason misdirected (internal error, not "handler returned an
 * unrecordable response").
 *
 * Fix: the handler's response is sanitized (same inspector the intent goes
 * through) before the append, so the decision row always lands and the
 * human's verdict is honored.
 */
import { describe, expect, it } from "vitest";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { makeIntent, makePolicy } from "./helpers.js";
import type { ApprovalResponse } from "../src/types.js";

function setup(response: ApprovalResponse) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: makePolicy({ approval: { aboveMinor: 100 } }),
    ledger,
    approvalHandler: async () => response,
  });
  return { ledger, guard };
}

describe("hostile approval-handler responses cannot erase the human's decision", () => {
  it("approved:true with a bigint note still EXECUTES with the full trail", async () => {
    const { guard, ledger } = setup({
      approved: true,
      note: 10n as unknown as string,
    });
    const r = await guard.execute(makeIntent({ id: "appr-1" }), async () => "paid");
    expect(r.status).toBe("executed");
    const types = (await ledger.trailFor("appr-1")).map((e) => e.type);
    expect(types).toContain("approval_requested");
    expect(types).toContain("approval_resolved");
    expect(types).toContain("execution_result");
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("approved:false with hostile extras still records the rejection row", async () => {
    const { guard, ledger } = setup({
      approved: false,
      note: [undefined] as unknown as string,
    });
    const r = await guard.execute(makeIntent({ id: "appr-2" }), async () => "paid");
    expect(r.status).toBe("approval_rejected");
    const types = (await ledger.trailFor("appr-2")).map((e) => e.type);
    expect(types).toContain("approval_resolved");
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("the sanitized row says it was sanitized (evidence stays honest)", async () => {
    const { guard, ledger } = setup({
      approved: true,
      note: 10n as unknown as string,
    });
    await guard.execute(makeIntent({ id: "appr-3" }), async () => "paid");
    const row = (await ledger.trailFor("appr-3")).find(
      (e) => e.type === "approval_resolved",
    );
    expect(row).toBeDefined();
    const data = row!.data as { responseSanitized?: unknown; response?: { approved?: unknown } };
    expect(data.responseSanitized).toBe(true);
    expect(data.response?.approved).toBe(true);
  });

  it("a clean response is recorded verbatim, untagged (control)", async () => {
    const { guard, ledger } = setup({ approved: true, approver: "prem" });
    const r = await guard.execute(makeIntent({ id: "appr-4" }), async () => "paid");
    expect(r.status).toBe("executed");
    const row = (await ledger.trailFor("appr-4")).find(
      (e) => e.type === "approval_resolved",
    );
    const data = row!.data as { responseSanitized?: unknown; response?: { approver?: unknown } };
    expect(data.responseSanitized).toBeUndefined();
    expect(data.response?.approver).toBe("prem");
  });
});
