"use client";

import { useMemo, useState, useTransition } from "react";
import type { LedgerEntry } from "@paygent/guard";
import { fetchTrail } from "../(dash)/ledger/actions";
import { shortId, timeAgo } from "../../lib/format";

const TYPE_LABEL: Record<string, string> = {
  intent_received: "intent",
  policy_decision: "decision",
  approval_requested: "approval req",
  approval_resolved: "approval res",
  mandate_issued: "mandate+",
  mandate_consumed: "mandate✓",
  execution_started: "exec start",
  execution_result: "exec result",
  policy_updated: "policy",
  guard_frozen: "frozen",
  guard_unfrozen: "unfrozen",
};

const FILTERS = [
  { key: "all", label: "All" },
  { key: "execution_result", label: "Executions" },
  { key: "policy_decision", label: "Decisions" },
  { key: "approval_resolved", label: "Approvals" },
  { key: "mandate_consumed", label: "Mandates" },
];

export function LedgerExplorer({ entries, nowMs }: { entries: LedgerEntry[]; nowMs: number }) {
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState<LedgerEntry | null>(null);
  const [trail, setTrail] = useState<LedgerEntry[]>([]);
  const [pending, startTransition] = useTransition();

  const rows = useMemo(
    () => (filter === "all" ? entries : entries.filter((e) => e.type === filter)),
    [entries, filter],
  );

  const openRow = (e: LedgerEntry) => {
    setSelected(e);
    setTrail([]);
    if (e.intentId) {
      startTransition(async () => setTrail(await fetchTrail(e.intentId!)));
    }
  };

  const exportEvidence = () => {
    if (!selected) return;
    const payload = { intentId: selected.intentId ?? null, entry: selected, trail };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `paygent-evidence-${selected.intentId?.slice(0, 8) ?? selected.seq}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <div className="filter-bar reveal s2">
        {FILTERS.map((f) => (
          <button key={f.key} className={`filter-chip${filter === f.key ? " active" : ""}`} onClick={() => setFilter(f.key)}>
            {f.label}
          </button>
        ))}
        <span className="filter-count mono">{rows.length} entries</span>
      </div>

      <div className="panel reveal s3" style={{ padding: 0, overflow: "hidden" }}>
        <div className="table-scroll">
        <table className="ledger-table dense">
          <thead>
            <tr>
              <th>Seq</th>
              <th>Event</th>
              <th>Intent</th>
              <th>Agent</th>
              <th>Hash</th>
              <th className="right">When</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.seq} className="clickable" onClick={() => openRow(e)}>
                <td className="mono" style={{ color: "var(--text-faint)" }}>#{e.seq}</td>
                <td><span className="type-tag">{TYPE_LABEL[e.type] ?? e.type}</span></td>
                <td className="mono">{e.intentId ? shortId(e.intentId) : "—"}</td>
                <td>{e.agentId ?? "—"}</td>
                <td className="mono" style={{ color: "var(--text-faint)" }}>{e.hash.slice(0, 10)}…</td>
                <td className="cell-time">{timeAgo(e.timestamp, nowMs)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </div>

      {selected && (
        <div className="drawer-overlay" onClick={() => setSelected(null)}>
          <aside className="drawer" onClick={(ev) => ev.stopPropagation()}>
            <div className="drawer-head">
              <div>
                <span className="eyebrow">Ledger entry</span>
                <h2 className="drawer-title">{TYPE_LABEL[selected.type] ?? selected.type} · #{selected.seq}</h2>
              </div>
              <button className="drawer-close" onClick={() => setSelected(null)} aria-label="Close">✕</button>
            </div>

            {selected.intentId && (
              <div className="drawer-section">
                <div className="drawer-label">
                  Intent trail
                  {pending && <span className="mono" style={{ color: "var(--text-faint)" }}> · loading…</span>}
                </div>
                <div className="timeline">
                  {trail.map((t) => (
                    <div key={t.seq} className={`tl-item${t.seq === selected.seq ? " current" : ""}`}>
                      <span className="tl-dot" />
                      <span className="tl-type">{TYPE_LABEL[t.type] ?? t.type}</span>
                      <span className="tl-time mono">{timeAgo(t.timestamp, nowMs)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="drawer-section">
              <div className="drawer-label">Raw entry</div>
              <pre className="drawer-json">{JSON.stringify(selected, null, 2)}</pre>
            </div>

            <button className="btn btn-gold btn-block" onClick={exportEvidence}>
              Download evidence packet
            </button>
          </aside>
        </div>
      )}
    </>
  );
}
