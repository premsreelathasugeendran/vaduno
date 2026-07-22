/**
 * A single-tone sparkline carrying a faint gold firewall hairline — the
 * signature motif miniaturized for KPI tiles.
 */
export function Sparkline({
  data,
  firewall,
  color = "var(--accent)",
  width = 240,
  height = 34,
}: {
  data: number[];
  firewall?: number | null;
  color?: string;
  width?: number;
  height?: number;
}) {
  if (data.length === 0) return <svg className="spark" viewBox={`0 0 ${width} ${height}`} />;
  const pad = 3;
  const maxVal = Math.max(1, ...data, firewall ?? 0);
  const n = data.length;
  const x = (i: number) => (n === 1 ? width / 2 : pad + (i / (n - 1)) * (width - pad * 2));
  const y = (v: number) => height - pad - (v / maxVal) * (height - pad * 2);

  const line = data.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L${x(n - 1).toFixed(1)},${height} L${x(0).toFixed(1)},${height} Z`;
  const fwY = firewall != null ? y(firewall) : null;
  const gid = `spk-${Math.round(maxVal)}-${n}`;

  return (
    <svg className="spark" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gid})`} />
      {fwY != null && (
        <line x1="0" y1={fwY} x2={width} y2={fwY} stroke="var(--accent)" strokeOpacity="0.4" strokeWidth="0.75" strokeDasharray="2 3" />
      )}
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={x(n - 1)} cy={y(data[n - 1]!)} r="1.8" fill={color} />
    </svg>
  );
}
