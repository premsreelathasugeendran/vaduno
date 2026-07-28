"use client";

import { useState, useTransition } from "react";
import type { PendingApproval } from "@vaduno/guard";
import { resolveApproval } from "../actions";
import { Money } from "./Money";
import { Seal } from "./Seal";
import { shortId } from "../../lib/format";

export function ApprovalRail({ pending }: { pending: PendingApproval[] }) {
  return (
    <aside className="rail reveal s4">
      <div className="rail-head">
        <span className="eyebrow">Awaiting your signature</span>
        <h2>
          Approval inbox <span className="count">· {pending.length}</span>
        </h2>
      </div>
      <div className="rail-body">
        <ApprovalCards pending={pending} />
      </div>
    </aside>
  );
}

export function ApprovalCards({ pending }: { pending: PendingApproval[] }) {
  if (pending.length === 0) {
    return (
      <div className="rail-empty">
        <div className="watermark" aria-hidden>
          <Seal variant="verified" size={44} />
        </div>
        All clear. No agent charges awaiting your signature.
      </div>
    );
  }
  return (
    <>
      {pending.map((p) => (
        <ApprovalCard key={p.intentId} p={p} />
      ))}
    </>
  );
}

function ApprovalCard({ p }: { p: PendingApproval }) {
  const [pending, startTransition] = useTransition();
  const [done, setDone] = useState<null | "approved" | "declined">(null);

  const act = (approved: boolean) =>
    startTransition(async () => {
      const res = await resolveApproval(p.intentId, approved);
      if (res.ok) setDone(approved ? "approved" : "declined");
    });

  const reason = p.policyReasons[0]?.message ?? "requires approval";

  return (
    <div className={`appr${done ? " resolving" : ""}`}>
      <div className="top">
        <span className="amt">
          <Money amountMinor={p.amount.amountMinor} currency={p.amount.currency} />
        </span>
        <span className="who">
          <b>{p.agentId}</b>
          <br />→ {p.merchant.id}
        </span>
      </div>
      <div className="rule">
        {reason}
        <br />
        intent {shortId(p.intentId)}
      </div>
      {done ? (
        <div className="done">
          <Seal variant={done === "approved" ? "verified" : "blocked"} size={16} />
          {done === "approved" ? "Approved — agent released." : "Declined — charge blocked."}
        </div>
      ) : (
        <div className="actions">
          <button className="btn btn-gold" disabled={pending} onClick={() => act(true)}>
            {pending ? "Signing…" : "Approve"}
          </button>
          <button className="btn btn-ghost" disabled={pending} onClick={() => act(false)}>
            Decline
          </button>
        </div>
      )}
    </div>
  );
}
