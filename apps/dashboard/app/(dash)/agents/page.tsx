import { loadOverview } from "../../../lib/data";
import { formatAmount, avatarColor } from "../../../lib/format";
import { Money } from "../../components/Money";

export const dynamic = "force-dynamic";

export default async function AgentsPage() {
  const data = await loadOverview();
  const cur = data.currency;

  const map = new Map<string, { spend: number; charges: number; blocked: number; currency: string }>();
  for (const r of data.activity) {
    const rec = map.get(r.agentId) ?? { spend: 0, charges: 0, blocked: 0, currency: r.currency ?? cur };
    if (r.status === "executed") {
      rec.spend += r.amountMinor ?? 0;
      rec.charges += 1;
    } else if (r.status === "denied") {
      rec.blocked += 1;
    }
    map.set(r.agentId, rec);
  }
  const agents = [...map.entries()].map(([id, v]) => ({ id, ...v })).sort((a, b) => b.spend - a.spend);
  const maxSpend = Math.max(1, ...agents.map((a) => a.spend));

  return (
    <>
      <div className="page-lead reveal s1">
        <h1 className="lead-title">Agents</h1>
        <p className="lead-sub">Every autonomous spender under the firewall, ranked by settled spend.</p>
      </div>
      <div className="card-grid reveal s2">
        {agents.map((a) => (
          <div className="entity-card" key={a.id}>
            <div className="entity-head">
              <span className="avatar lg" style={{ background: avatarColor(a.id) }}>{a.id.slice(0, 1).toUpperCase()}</span>
              <div>
                <div className="entity-name">{a.id}</div>
                <div className="entity-meta mono">{a.charges} charges · {a.blocked} blocked</div>
              </div>
            </div>
            <div className="entity-figure"><Money amountMinor={a.spend} currency={a.currency} /></div>
            <div className="entity-track"><span className="entity-fill" style={{ width: `${(a.spend / maxSpend) * 100}%` }} /></div>
            <div className="entity-foot mono">{formatAmount(a.spend, a.currency)} settled</div>
          </div>
        ))}
      </div>
    </>
  );
}
