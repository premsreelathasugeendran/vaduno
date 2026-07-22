import { loadOverview } from "../../../lib/data";
import { formatAmount, avatarColor } from "../../../lib/format";
import { Money } from "../../components/Money";

export const dynamic = "force-dynamic";

export default async function MerchantsPage() {
  const data = await loadOverview();
  const cur = data.currency;

  const map = new Map<string, { spend: number; charges: number; blocked: number; currency: string }>();
  for (const r of data.activity) {
    const rec = map.get(r.merchantId) ?? { spend: 0, charges: 0, blocked: 0, currency: r.currency ?? cur };
    if (r.status === "executed") {
      rec.spend += r.amountMinor ?? 0;
      rec.charges += 1;
    } else if (r.status === "denied") {
      rec.blocked += 1;
    }
    map.set(r.merchantId, rec);
  }
  const merchants = [...map.entries()].map(([id, v]) => ({ id, ...v })).sort((a, b) => b.spend - a.spend);
  const maxSpend = Math.max(1, ...merchants.map((m) => m.spend));

  return (
    <>
      <div className="page-lead reveal s1">
        <h1 className="lead-title">Merchants</h1>
        <p className="lead-sub">Where your agents' money went — and where the firewall stopped it.</p>
      </div>
      <div className="panel reveal s2">
        <table className="ledger-table">
          <thead>
            <tr>
              <th>Merchant</th>
              <th>Share</th>
              <th className="right">Charges</th>
              <th className="right">Blocked</th>
              <th className="right">Spend</th>
            </tr>
          </thead>
          <tbody>
            {merchants.map((m) => (
              <tr key={m.id}>
                <td>
                  <div className="agent-cell">
                    <span className="avatar" style={{ background: avatarColor(m.id) }}>{m.id.slice(0, 1).toUpperCase()}</span>
                    <span>{m.id}</span>
                  </div>
                </td>
                <td style={{ width: "34%" }}>
                  <span className="m-track"><span className="m-fill" style={{ width: `${(m.spend / maxSpend) * 100}%` }} /></span>
                </td>
                <td className="right mono">{m.charges}</td>
                <td className="right mono" style={{ color: m.blocked ? "var(--critical)" : "var(--text-faint)" }}>{m.blocked || "—"}</td>
                <td className="right cell-amt"><Money amountMinor={m.spend} currency={m.currency} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
