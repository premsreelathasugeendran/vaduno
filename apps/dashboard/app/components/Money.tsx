import { moneyParts } from "../../lib/format";

const faint = { color: "var(--text-faint)" };

export function Money({
  amountMinor,
  currency,
  className,
}: {
  amountMinor: number;
  currency: string;
  className?: string;
}) {
  const p = moneyParts(amountMinor, currency);
  const cls = `mono${className ? " " + className : ""}`;
  if (p.unknown) {
    return (
      <span className={cls}>
        {p.whole} <span style={faint}>{p.suffix}</span>
      </span>
    );
  }
  return (
    <span className={cls}>
      {p.symbol && <span style={faint}>{p.symbol}</span>}
      {p.whole}
      {p.fraction && <span style={faint}>.{p.fraction}</span>}
      {p.suffix && <span style={faint}> {p.suffix}</span>}
    </span>
  );
}
