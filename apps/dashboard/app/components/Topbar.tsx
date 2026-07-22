import type { VerifyResult } from "@paygent/guard";

export function Topbar({ chain }: { chain: VerifyResult }) {
  return (
    <header className="topbar reveal">
      <div className="left">
        <span className="page-title">Overview</span>
        <span className="env-chip">
          <span className="dot" /> LIVE
        </span>
      </div>
      <div className="left" style={{ gap: 12 }}>
        <div className="fake-search">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4-4" strokeLinecap="round" />
          </svg>
          Search agents, merchants…
          <span className="kbd">⌘K</span>
        </div>
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
