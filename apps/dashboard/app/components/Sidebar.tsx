"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export const NAV = [
  { label: "Overview", href: "/", icon: "grid" },
  { label: "Firewall", href: "/firewall", icon: "shield" },
  { label: "Agents", href: "/agents", icon: "bot" },
  { label: "Ledger", href: "/ledger", icon: "list" },
  { label: "Merchants", href: "/merchants", icon: "store" },
  { label: "Rules", href: "/rules", icon: "sliders" },
  { label: "Audit", href: "/audit", icon: "seal" },
];

const PATHS: Record<string, string> = {
  grid: "M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z",
  shield: "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z",
  bot: "M12 3v3M6 8h12v10H6zM9 12h.01M15 12h.01",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  store: "M4 9l1-5h14l1 5M5 9v11h14V9M5 9h14",
  sliders: "M4 6h10M18 6h2M4 12h2M10 12h10M4 18h13M20 18h.01",
  seal: "M12 3l2.5 2 3-1 1 3 2.5 2-1 3 1 3-2.5 2-1 3-3-1-2.5 2-2.5-2-3 1-1-3L4 15l1-3-1-3 2.5-2 1-3 3 1z",
  gear: "M12 9a3 3 0 100 6 3 3 0 000-6zM19.4 15a1.6 1.6 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.6 1.6 0 00-2.7.7 2 2 0 01-3.8 0 1.6 1.6 0 00-2.7-.7l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.6 1.6 0 00-1.3-2.7 2 2 0 010-3.8 1.6 1.6 0 001.3-2.7l-.1-.1a2 2 0 112.8-2.8l.1.1a1.6 1.6 0 002.7-.7 2 2 0 013.8 0 1.6 1.6 0 002.7.7l.1-.1a2 2 0 112.8 2.8l-.1.1a1.6 1.6 0 001.3 2.7 2 2 0 010 3.8 1.6 1.6 0 00-1.3 1z",
};

function Ico({ name }: { name: string }) {
  return (
    <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d={PATHS[name]} />
    </svg>
  );
}

export function Sidebar({ entries }: { entries: number }) {
  const pathname = usePathname();
  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  return (
    <aside className="sidebar">
      <div className="side-brand">
        <span className="seal-dot" aria-hidden />
        <span className="brand-word">Swale</span>
      </div>
      <nav className="side-nav">
        {NAV.map((n) => (
          <Link key={n.label} href={n.href} className={`nav-item${isActive(n.href) ? " active" : ""}`}>
            <Ico name={n.icon} />
            {n.label}
          </Link>
        ))}
      </nav>
      <div className="side-section eyebrow">System</div>
      <nav className="side-nav">
        <Link href="/settings" className={`nav-item${isActive("/settings") ? " active" : ""}`}>
          <Ico name="gear" />
          Settings
        </Link>
      </nav>
      <div className="side-foot">
        <div className="org">Acme AI · Team plan</div>
        <div className="mono" style={{ marginTop: 4 }}>{entries} ledger entries</div>
      </div>
    </aside>
  );
}
