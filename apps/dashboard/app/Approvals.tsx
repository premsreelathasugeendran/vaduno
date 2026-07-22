"use client";

import { useState, useTransition } from "react";
import type { PendingApproval } from "@paygent/guard";
import { resolveApproval } from "./actions";
import { formatAmount, shortId } from "../lib/format";

export function Approvals({ pending }: { pending: PendingApproval[] }) {
  if (pending.length === 0) {
    return <div className="empty">No payments waiting for approval.</div>;
  }
  return (
    <>
      {pending.map((p) => (
        <ApprovalItem key={p.intentId} p={p} />
      ))}
    </>
  );
}

function ApprovalItem({ p }: { p: PendingApproval }) {
  const [isPending, startTransition] = useTransition();
  const [done, setDone] = useState<null | "approved" | "declined">(null);

  const act = (approved: boolean) => {
    startTransition(async () => {
      await resolveApproval(p.intentId, approved);
      setDone(approved ? "approved" : "declined");
    });
  };

  const reason = p.policyReasons[0]?.message ?? "requires approval";

  return (
    <div className="approval">
      <div className="head">
        <span className="amt">{formatAmount(p.amount.amountMinor, p.amount.currency)}</span>
        <span className="who">
          {p.agentId} → {p.merchant.id}
        </span>
      </div>
      <div className="reason">
        {reason} · intent {shortId(p.intentId)}
      </div>
      {done ? (
        <div className="who">
          {done === "approved" ? "✅ Approved" : "🚫 Declined"} — the waiting agent has been released.
        </div>
      ) : (
        <div className="actions">
          <button className="btn approve" disabled={isPending} onClick={() => act(true)}>
            {isPending ? "…" : "Approve"}
          </button>
          <button className="btn reject" disabled={isPending} onClick={() => act(false)}>
            Decline
          </button>
        </div>
      )}
    </div>
  );
}
