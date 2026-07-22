import { loadOverview } from "../../lib/data";
import { formatCompact, toMajor } from "../../lib/format";
import { Kpi } from "../components/Kpi";
import { SpendChart } from "../components/SpendChart";
import { ActivityLedger } from "../components/ActivityLedger";
import { CountUp } from "../components/CountUp";
import { Money } from "../components/Money";

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const data = await loadOverview();
  const nowMs = Date.now();
  const cur = Object.entries(data.totalsByCurrency).sort((a, b) => b[1] - a[1])[0]?.[0] ?? data.currency;
  const total = data.totalsByCurrency[cur] ?? 0;
  const totalMajor = toMajor(total, cur);
  const chargesChrono = [...data.activity].reverse();
  const activityTop = data.activity.slice(0, 12);

  return (
    <>
      <div className="kpi-row">
        <Kpi eyebrow="Total spent" gold sub={`across ${data.executedCount} settled charges`} spark={data.spendByDay.map((d) => d.minor)} firewall={data.firewallDailyMinor} stagger="s1">
          <CountUp value={totalMajor} decimals={2} prefix="$" faintFraction />
        </Kpi>
        <Kpi eyebrow="Blocked by firewall" sub="policy-denied attempts" stagger="s2">
          <CountUp value={data.deniedCount} />
        </Kpi>
        <Kpi eyebrow="Prevented spend" sub="stopped at the wall" stagger="s3">
          <CountUp value={toMajor(data.blockedMinor, cur)} decimals={2} prefix="$" faintFraction />
        </Kpi>
        <Kpi eyebrow="Awaiting approval" sub="need your signature" stagger="s4">
          <CountUp value={data.pending.length} />
        </Kpi>
      </div>

      <div className="hero-row">
        <div className="panel reveal s3">
          <div className="panel-head">
            <div>
              <span className="eyebrow" style={{ display: "block", marginBottom: 8 }}>Spend vs firewall</span>
              <div className="hero-figure">
                <CountUp value={totalMajor} decimals={2} prefix="$" faintFraction />
              </div>
              <div className="hero-sub">{data.executedCount} charges under the wall · {data.deniedCount} breaches blocked</div>
            </div>
            <div className="chart-legend">
              <span className="legend-item"><span className="legend-swatch" style={{ background: "var(--accent)" }} /> Charge</span>
              <span className="legend-item"><span className="legend-swatch" style={{ background: "var(--critical)" }} /> Breach</span>
            </div>
          </div>
          <SpendChart charges={chargesChrono} firewallMinor={data.firewallTxnMinor} currency={cur} />
        </div>

        <div className="panel reveal s4">
          <div className="panel-head"><h2>Top merchants</h2><span className="meta">{cur}</span></div>
          {data.spendByMerchant.slice(0, 6).map((m) => {
            const max = data.spendByMerchant[0]?.minor ?? 1;
            return (
              <div className="mbar" key={m.merchantId}>
                <span className="m-name">{m.merchantId}</span>
                <span className="m-track"><span className="m-fill" style={{ width: `${(m.minor / max) * 100}%` }} /></span>
                <span className="m-amt">{formatCompact(m.minor, m.currency)}</span>
              </div>
            );
          })}
        </div>
      </div>

      <div className="panel reveal s5">
        <div className="panel-head"><h2>Activity ledger</h2><span className="meta">hash-chained · append-only</span></div>
        <ActivityLedger rows={activityTop} currency={cur} nowMs={nowMs} />
      </div>
    </>
  );
}
