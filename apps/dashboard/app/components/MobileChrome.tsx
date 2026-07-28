"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { PendingApproval, VerifyResult } from "@vaduno/guard";
import { NAV } from "./Sidebar";
import { ApprovalCards } from "./ApprovalRail";
import { useCommandPalette } from "./CommandPalette";

const TITLES: Record<string, string> = {
  "/": "Overview",
  "/firewall": "Firewall",
  "/agents": "Agents",
  "/ledger": "Ledger",
  "/merchants": "Merchants",
  "/rules": "Rules",
  "/audit": "Audit",
  "/settings": "Settings",
};

export function MobileChrome({ pending, chain }: { pending: PendingApproval[]; chain: VerifyResult }) {
  const [nav, setNav] = useState(false);
  const [appr, setAppr] = useState(false);
  const pathname = usePathname();
  const openCmd = useCommandPalette();

  // Close overlays on route change.
  useEffect(() => {
    setNav(false);
    setAppr(false);
  }, [pathname]);

  const title =
    TITLES[pathname] ?? TITLES[Object.keys(TITLES).find((k) => k !== "/" && pathname.startsWith(k)) ?? "/"] ?? "Overview";
  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  return (
    <>
      <header className="mobile-top">
        <button className="m-icon-btn" onClick={() => setNav(true)} aria-label="Open menu">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <div className="m-title">
          <span className="seal-dot sm" aria-hidden />
          <span>{title}</span>
        </div>
        <button className="m-icon-btn" onClick={() => openCmd()} aria-label="Search">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4-4" strokeLinecap="round" />
          </svg>
        </button>
        <button className="m-icon-btn bell" onClick={() => setAppr(true)} aria-label="Approvals">
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0" />
          </svg>
          {pending.length > 0 && <span className="m-badge">{pending.length}</span>}
        </button>
      </header>

      {nav && (
        <div className="m-overlay" onClick={() => setNav(false)}>
          <nav className="m-drawer left" onClick={(e) => e.stopPropagation()}>
            <div className="side-brand">
              <span className="seal-dot" aria-hidden />
              <span className="brand-word">Vaduno</span>
            </div>
            <div className="m-nav">
              {NAV.map((n) => (
                <Link key={n.label} href={n.href} className={`m-nav-item${isActive(n.href) ? " active" : ""}`}>
                  {n.label}
                </Link>
              ))}
              <Link href="/settings" className={`m-nav-item${isActive("/settings") ? " active" : ""}`}>
                Settings
              </Link>
            </div>
            <div className="m-drawer-foot">
              <span className={`chain-badge ${chain.ok ? "ok" : "bad"}`}>
                <span className="dot" /> {chain.ok ? `Chain verified · ${chain.entries}` : "Tampering detected"}
              </span>
            </div>
          </nav>
        </div>
      )}

      {appr && (
        <div className="m-overlay" onClick={() => setAppr(false)}>
          <aside className="m-drawer right" onClick={(e) => e.stopPropagation()}>
            <div className="rail-head">
              <span className="eyebrow">Awaiting your signature</span>
              <h2>
                Approval inbox <span className="count">· {pending.length}</span>
              </h2>
            </div>
            <div className="rail-body">
              <ApprovalCards pending={pending} />
            </div>
          </aside>
        </div>
      )}
    </>
  );
}
