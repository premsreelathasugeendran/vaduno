import { loadOverview, loadActivePolicy } from "../../../lib/data";
import { formatAmount } from "../../../lib/format";
import { Money } from "../../components/Money";

export const dynamic = "force-dynamic";

export default async function FirewallPage() {
  const [data, policy] = await Promise.all([loadOverview(), loadActivePolicy()]);
  const cur = policy?.currency ?? data.currency;
  const perTxn = policy?.limits?.perTransactionMinor ?? null;
  const perDay = policy?.limits?.perDayMinor ?? null;
  const approval = policy?.approval?.aboveMinor ?? null;

  const latestDay = data.spendByDay[data.spendByDay.length - 1];
  const daySpend = latestDay?.minor ?? 0;
  const dayPct = perDay && perDay > 0 ? Math.min(100, (daySpend / perDay) * 100) : perDay === 0 ? 100 : 0;
  const meterState = dayPct >= 100 ? "critical" : dayPct >= 80 ? "caution" : "ok";

  return (
    <>
      <div className="page-lead reveal s1">
        <h1 className="lead-title">Firewall</h1>
        <p className="lead-sub">
          The deterministic wall every agent charge is measured against · policy{" "}
          <span className="mono">{policy?.id ?? "—"} v{policy?.version ?? "?"}</span>
        </p>
      </div>

      <div className="gauge-row reveal s2">
        <div className="gauge">
          <span className="eyebrow">Per-transaction cap</span>
          <div className="gauge-fig gold">{perTxn != null ? <Money amountMinor={perTxn} currency={cur} /> : "—"}</div>
          <div className="gauge-sub">the wall a single charge can't cross</div>
        </div>
        <div className="gauge">
          <span className="eyebrow">Per-day cap</span>
          <div className="gauge-fig gold">{perDay != null ? <Money amountMinor={perDay} currency={cur} /> : "—"}</div>
          <div className="gauge-sub">rolling 24h ceiling, guard-wide</div>
        </div>
        <div className="gauge">
          <span className="eyebrow">Human approval above</span>
          <div className="gauge-fig">{approval != null ? <Money amountMinor={approval} currency={cur} /> : "—"}</div>
          <div className="gauge-sub">charges over this need a signature</div>
        </div>
      </div>

      <div className="panel reveal s3">
        <div className="panel-head">
          <h2>Today's headroom</h2>
          <span className="meta mono">
            {formatAmount(daySpend, cur)} {perDay != null ? `of ${formatAmount(perDay, cur)}` : ""}
          </span>
        </div>
        <div className={`meter ${meterState}`}>
          <div className="meter-fill" style={{ width: `${dayPct}%` }} />
          <div className="meter-notch" />
        </div>
        <div className="meter-legend mono">
          {perDay == null
            ? "No daily cap configured."
            : perDay === 0
              ? "Daily cap is 0 — every charge is blocked."
              : dayPct >= 100
                ? "Daily wall reached — further charges are blocked."
                : `${(100 - dayPct).toFixed(0)}% headroom before the daily wall.`}
        </div>
      </div>
    </>
  );
}
