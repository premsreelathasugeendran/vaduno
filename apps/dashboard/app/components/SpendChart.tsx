"use client";

import { useRef, useState } from "react";
import { formatAmount, formatCompact } from "../../lib/format";

interface Charge {
  amountMinor: number | null;
  status: "executed" | "denied" | "failed";
  timestamp: string;
}

/**
 * The hero: each agent charge plotted over time against the per-transaction
 * FIREWALL LINE (engraved gold). Charges under the line render gold; a charge
 * that breaches it spikes above in red. Hover shows a crosshair + tooltip.
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
  const wrapRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);

  const pts = charges
    .filter((c) => c.amountMinor != null)
    .map((c) => ({ v: c.amountMinor as number, status: c.status, ts: c.timestamp }));

  if (pts.length === 0) return <div className="rail-empty">No charges in range.</div>;

  const maxData = Math.max(...pts.map((p) => p.v));
  const maxY = Math.max(maxData, firewallMinor ?? 0) * 1.18 || 1;
  const n = pts.length;
  const x = (i: number) => (n === 1 ? W / 2 : padX + (i / (n - 1)) * (W - padX * 2));
  const y = (v: number) => padTop + (1 - v / maxY) * (H - padTop - padBottom);

  const linePath = pts.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p.v).toFixed(1)}`).join(" ");
  const areaPath = `${linePath} L${x(n - 1).toFixed(1)},${H - padBottom} L${x(0).toFixed(1)},${H - padBottom} Z`;
  const fwY = firewallMinor != null ? y(firewallMinor) : null;
  const gridVals = [0.25, 0.5, 0.75].map((f) => padTop + f * (H - padTop - padBottom));

  const onMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!rect) return;
    const fx = (e.clientX - rect.left) / rect.width;
    setHover(Math.max(0, Math.min(n - 1, Math.round(fx * (n - 1)))));
  };

  const hp = hover != null ? pts[hover] : null;

  return (
    <div ref={wrapRef} className="chart-interactive" onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
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

        {fwY != null &&
          pts.map((p, i) =>
            p.v > (firewallMinor as number) ? (
              <g key={`b${i}`}>
                <line x1={x(i)} y1={fwY} x2={x(i)} y2={y(p.v)} stroke="var(--critical)" strokeWidth="2" />
                <circle cx={x(i)} cy={y(p.v)} r="3.5" fill="var(--critical)" />
              </g>
            ) : null,
          )}

        {pts.map((p, i) =>
          fwY == null || p.v <= (firewallMinor as number) ? (
            <circle key={`p${i}`} cx={x(i)} cy={y(p.v)} r={hover === i ? "3.6" : "2.4"} fill="var(--accent)" />
          ) : null,
        )}

        {fwY != null && (
          <>
            <line className="fw-draw" x1="0" y1={fwY} x2={W} y2={fwY} stroke="url(#guilloche)" strokeWidth="3" />
            <line x1="0" y1={fwY} x2={W} y2={fwY} stroke="var(--accent)" strokeOpacity="0.35" strokeWidth="1" />
            <text x={W - 4} y={fwY - 6} textAnchor="end" fontFamily="var(--font-mono)" fontSize="10.5" fill="var(--accent)" opacity="0.85">
              firewall · {formatCompact(firewallMinor as number, currency)}/txn
            </text>
          </>
        )}

        {hp && (
          <line x1={x(hover!)} y1={padTop} x2={x(hover!)} y2={H - padBottom} stroke="var(--accent-2)" strokeOpacity="0.5" strokeWidth="1" strokeDasharray="3 3" />
        )}

        <text x={4} y={H - 6} fontFamily="var(--font-mono)" fontSize="10" fill="var(--text-faint)">{pts[0]!.ts.slice(0, 10)}</text>
        <text x={W - 4} y={H - 6} textAnchor="end" fontFamily="var(--font-mono)" fontSize="10" fill="var(--text-faint)">{pts[n - 1]!.ts.slice(0, 10)}</text>
      </svg>

      {hp && (
        <div
          className="chart-tip"
          style={{ left: `${(x(hover!) / W) * 100}%`, top: `${(y(hp.v) / H) * 100}%` }}
        >
          <div className={`tip-amt ${hp.status === "denied" ? "crit" : ""}`}>{formatAmount(hp.v, currency)}</div>
          <div className="tip-meta">
            {hp.status === "denied" ? "blocked" : hp.status} · {hp.ts.slice(0, 10)}
          </div>
        </div>
      )}
    </div>
  );
}
