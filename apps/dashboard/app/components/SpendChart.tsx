import { formatCompact } from "../../lib/format";

interface Charge {
  amountMinor: number | null;
  status: "executed" | "denied" | "failed";
  timestamp: string;
}

/**
 * The hero: each agent charge plotted over time against the per-transaction
 * FIREWALL LINE (engraved gold). Charges under the line render gold; a charge
 * that breaches the wall (a blocked over-limit attempt) spikes above it in red.
 */
export function SpendChart({
  charges,
  firewallMinor,
  currency,
}: {
  charges: Charge[];
  firewallMinor: number | null;
  currency: string;
}) {
  const W = 760;
  const H = 240;
  const padX = 8;
  const padTop = 24;
  const padBottom = 22;

  const pts = charges
    .filter((c) => c.amountMinor != null)
    .map((c) => ({ v: c.amountMinor as number, status: c.status, ts: c.timestamp }));

  if (pts.length === 0) {
    return <div className="rail-empty">No charges in range.</div>;
  }

  const maxData = Math.max(...pts.map((p) => p.v));
  const maxY = Math.max(maxData, firewallMinor ?? 0) * 1.18 || 1;
  const n = pts.length;
  const x = (i: number) => (n === 1 ? W / 2 : padX + (i / (n - 1)) * (W - padX * 2));
  const y = (v: number) => padTop + (1 - v / maxY) * (H - padTop - padBottom);

  const linePath = pts.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p.v).toFixed(1)}`).join(" ");
  const areaPath = `${linePath} L${x(n - 1).toFixed(1)},${H - padBottom} L${x(0).toFixed(1)},${H - padBottom} Z`;
  const fwY = firewallMinor != null ? y(firewallMinor) : null;

  const gridVals = [0.25, 0.5, 0.75].map((f) => padTop + f * (H - padTop - padBottom));

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" preserveAspectRatio="none" style={{ display: "block" }} role="img" aria-label="Spend vs firewall">
      <defs>
        <linearGradient id="spendfill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.22" />
          <stop offset="82%" stopColor="var(--accent)" stopOpacity="0" />
        </linearGradient>
        <pattern id="guilloche" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <line x1="0" y1="0" x2="0" y2="6" stroke="var(--accent)" strokeOpacity="0.5" strokeWidth="0.6" />
        </pattern>
      </defs>

      {gridVals.map((gy, i) => (
        <line key={i} x1="0" y1={gy} x2={W} y2={gy} stroke="var(--border)" strokeWidth="1" />
      ))}

      <path className="area-fade" d={areaPath} fill="url(#spendfill)" />
      <path className="draw" d={linePath} fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />

      {/* breach markers: any point above the firewall spikes red */}
      {fwY != null &&
        pts.map((p, i) =>
          p.v > (firewallMinor as number) ? (
            <g key={`b${i}`}>
              <line x1={x(i)} y1={fwY} x2={x(i)} y2={y(p.v)} stroke="var(--critical)" strokeWidth="2" />
              <circle cx={x(i)} cy={y(p.v)} r="3.5" fill="var(--critical)" />
            </g>
          ) : null,
        )}

      {/* point dots (gold, under the wall) */}
      {pts.map((p, i) =>
        fwY == null || p.v <= (firewallMinor as number) ? (
          <circle key={`p${i}`} cx={x(i)} cy={y(p.v)} r="2.4" fill="var(--accent)" />
        ) : null,
      )}

      {/* THE FIREWALL LINE */}
      {fwY != null && (
        <>
          <line className="fw-draw" x1="0" y1={fwY} x2={W} y2={fwY} stroke="url(#guilloche)" strokeWidth="3" />
          <line x1="0" y1={fwY} x2={W} y2={fwY} stroke="var(--accent)" strokeOpacity="0.35" strokeWidth="1" />
          <text x={W - 4} y={fwY - 6} textAnchor="end" fontFamily="var(--font-mono)" fontSize="10.5" fill="var(--accent)" opacity="0.85">
            firewall · {formatCompact(firewallMinor as number, currency)}/txn
          </text>
        </>
      )}

      <text x={4} y={H - 6} fontFamily="var(--font-mono)" fontSize="10" fill="var(--text-faint)">
        {pts[0]!.ts.slice(0, 10)}
      </text>
      <text x={W - 4} y={H - 6} textAnchor="end" fontFamily="var(--font-mono)" fontSize="10" fill="var(--text-faint)">
        {pts[n - 1]!.ts.slice(0, 10)}
      </text>
    </svg>
  );
}
