import type { ActivityRow } from "../../lib/data";
import { Money } from "./Money";
import { Seal } from "./Seal";
import { avatarColor, timeAgo } from "../../lib/format";

export function ActivityLedger({
  rows,
  currency,
  nowMs,
}: {
  rows: ActivityRow[];
  currency: string;
  nowMs: number;
}) {
  return (
    <table className="ledger-table">
      <thead>
        <tr>
          <th>Agent</th>
          <th>Merchant</th>
          <th>Rail</th>
          <th className="right">Amount</th>
          <th>Status</th>
          <th className="right">When</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.key}>
            <td>
              <div className="agent-cell">
                <span className="avatar" style={{ background: avatarColor(r.agentId) }}>
                  {r.agentId.slice(0, 1).toUpperCase()}
                </span>
                <span>{r.agentId}</span>
              </div>
            </td>
            <td>
              {r.merchantId}
              {r.reason && <div className="reason-tag">{r.reason}</div>}
            </td>
            <td className="rail-tag">{r.rail}</td>
            <td className="right cell-amt">
              {r.amountMinor != null ? <Money amountMinor={r.amountMinor} currency={r.currency ?? currency} /> : "—"}
            </td>
            <td>
              <span className={`pill ${r.status}`}>
                <Seal
                  variant={r.status === "executed" ? "verified" : r.status === "denied" ? "blocked" : "pending"}
                  size={13}
                />
                {r.status === "executed" ? "settled" : r.status === "denied" ? "blocked" : "failed"}
              </span>
            </td>
            <td className="cell-time">{timeAgo(r.timestamp, nowMs)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
