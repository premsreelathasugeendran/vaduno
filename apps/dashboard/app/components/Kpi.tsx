import type { ReactNode } from "react";
import { Sparkline } from "./Sparkline";

export function Kpi({
  eyebrow,
  children,
  sub,
  spark,
  firewall,
  gold,
  stagger,
}: {
  eyebrow: string;
  children: ReactNode;
  sub?: ReactNode;
  spark?: number[];
  firewall?: number | null;
  gold?: boolean;
  stagger?: string;
}) {
  return (
    <div className={`kpi reveal${stagger ? " " + stagger : ""}`}>
      <span className="eyebrow">{eyebrow}</span>
      <div className={`figure${gold ? " gold" : ""}`}>{children}</div>
      {sub && <div className="sub">{sub}</div>}
      {spark && spark.length > 1 && (
        <div className="spark">
          <Sparkline data={spark} firewall={firewall ?? null} height={34} />
        </div>
      )}
    </div>
  );
}
