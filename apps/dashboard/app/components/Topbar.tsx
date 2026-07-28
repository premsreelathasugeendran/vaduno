"use client";

import { usePathname } from "next/navigation";
import type { VerifyResult } from "@swale/guard";
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

export function Topbar({ chain }: { chain: VerifyResult }) {
  const pathname = usePathname();
  const open = useCommandPalette();
  const title =
    TITLES[pathname] ?? TITLES[Object.keys(TITLES).find((k) => k !== "/" && pathname.startsWith(k)) ?? "/"] ?? "Overview";

  return (
    <header className="topbar">
      <div className="left">
        <span className="page-title">{title}</span>
        <span className="env-chip">
          <span className="dot" /> LIVE
        </span>
      </div>
      <div className="left" style={{ gap: 12 }}>
        <button className="fake-search" onClick={open} aria-label="Open command palette">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4-4" strokeLinecap="round" />
          </svg>
          Search agents, merchants…
          <span className="kbd">⌘K</span>
        </button>
        {chain.ok ? (
          <span className="chain-badge ok">
            <span className="dot" /> Audit chain verified · {chain.entries}
          </span>
        ) : (
          <span className="chain-badge bad">
            <span className="dot" /> Tampering detected · seq {chain.firstBadSeq}
          </span>
        )}
      </div>
    </header>
  );
}
