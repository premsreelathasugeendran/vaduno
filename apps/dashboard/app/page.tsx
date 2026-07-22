import { loadOverview } from "../lib/data";
import { formatCompact, moneyParts } from "../lib/format";
import { Sidebar } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { Kpi } from "./components/Kpi";
import { SpendChart } from "./components/SpendChart";
import { ActivityLedger } from "./components/ActivityLedger";
import { ApprovalRail } from "./components/ApprovalRail";
import { Money } from "./components/Money";

export const dynamic = "force-dynamic";

export default async function Page() {
  const data = await loadOverview();

  if (!data.ok) {
    return (
      <div className="login-shell">
        <div className="login-card">
          <div className="login-mark">
            <span className="seal-dot" aria-hidden />
            <span className="brand-word">Paygent</span>
          </div>
          <h1 className="login-title">{data.errored ? "Ledger unreadable." : "No ledger yet."}</h1>
          <p className="login-sub">
            Run <code>npm run dashboard:seed</code> to generate a sample ledger, then reload.
          </p>
        </div>
      </div>
    );
  }

  const nowMs = Date.now();
  const primaryCurrency =
    Object.entries(data.totalsByCurrency).sort((a, b) => b[1] - a[1])[0]?.[0] ?? data.currency;
  const primaryTotal = data.totalsByCurrency[primaryCurrency] ?? 0;
  const hero = moneyParts(primaryTotal, primaryCurrency);
  const chargesChrono = [...data.activity].reverse();
  const activityTop = data.activity.slice(0, 12);

  return (
    <div className="shell">
      <Sidebar entries={data.entryCount} />

      <main className="main">
        <Topbar chain={data.chain} />
        <div className="content">
          {/* KPI ROW */}
          <div className="kpi-row">
            <Kpi
              eyebrow="Total spent"
              gold
              sub={`across ${data.executedCount} settled charges`}
              spark={data.spendByDay.map((d) => d.minor)}
              firewall={data.firewallDailyMinor}
              stagger="s1"
            >
              {hero.unknown ? (
                `${hero.whole} ${hero.suffix}`
              ) : (
                <>
                  <span style={{ color: "var(--text-faint)", fontSize: "0.7em" }}>{hero.symbol}</span>
                  {hero.whole}
                  {hero.fraction && <span style={{ color: "var(--text-faint)", fontSize: "0.62em" }}>.{hero.fraction}</span>}
                </>
              )}
            </Kpi>

            <Kpi eyebrow="Blocked by firewall" sub="policy-denied attempts" stagger="s2">
              {data.deniedCount}
            </Kpi>

            <Kpi eyebrow="Prevented spend" sub="stopped at the wall" stagger="s3">
              <Money amountMinor={data.blockedMinor} currency={primaryCurrency} />
            </Kpi>

            <Kpi eyebrow="Awaiting approval" sub="need your signature" stagger="s4">
              {data.pending.length}
            </Kpi>
          </div>

          {/* HERO */}
          <div className="hero-row">
            <div className="panel reveal s3">
              <div className="panel-head">
                <div>
                  <span className="eyebrow" style={{ display: "block", marginBottom: 8 }}>
                    Spend vs firewall
                  </span>
                  <div className="hero-figure">
                    {hero.unknown ? (
                      `${hero.whole} ${hero.suffix}`
                    ) : (
                      <>
                        <span className="sym">{hero.symbol}</span>
                        {hero.whole}
                        {hero.fraction && <span className="cents">.{hero.fraction}</span>}
                      </>
                    )}
                  </div>
                  <div className="hero-sub">
                    {data.executedCount} charges under the wall · {data.deniedCount} breaches blocked
                  </div>
                </div>
                <div className="chart-legend">
                  <span className="legend-item">
                    <span className="legend-swatch" style={{ background: "var(--accent)" }} /> Charge
                  </span>
                  <span className="legend-item">
                    <span className="legend-swatch" style={{ background: "var(--critical)" }} /> Breach
                  </span>
                </div>
              </div>
              <SpendChart charges={chargesChrono} firewallMinor={data.firewallTxnMinor} currency={primaryCurrency} />
            </div>

            <div className="panel reveal s4">
              <div className="panel-head">
                <h2>Top merchants</h2>
                <span className="meta">{primaryCurrency}</span>
              </div>
              {data.spendByMerchant.slice(0, 6).map((m, i) => {
                const max = data.spendByMerchant[0]?.minor ?? 1;
                return (
                  <div className="mbar" key={m.merchantId}>
                    <span className="m-name">{m.merchantId}</span>
                    <span className="m-track">
                      <span className="m-fill" style={{ width: `${(m.minor / max) * 100}%` }} />
                    </span>
                    <span className="m-amt">{formatCompact(m.minor, m.currency)}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ACTIVITY */}
          <div className="panel reveal s5">
            <div className="panel-head">
              <h2>Activity ledger</h2>
              <span className="meta">hash-chained · append-only</span>
            </div>
            <ActivityLedger rows={activityTop} currency={primaryCurrency} nowMs={nowMs} />
          </div>
        </div>
      </main>

      <ApprovalRail pending={data.pending} />
    </div>
  );
}
