const NAV = [
  { label: "Overview", icon: "grid", active: true },
  { label: "Firewall", icon: "shield" },
  { label: "Agents", icon: "bot" },
  { label: "Ledger", icon: "list" },
  { label: "Merchants", icon: "store" },
  { label: "Rules", icon: "sliders" },
  { label: "Audit", icon: "seal" },
];

const PATHS: Record<string, string> = {
  grid: "M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z",
  shield: "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z",
  bot: "M12 3v3M6 8h12v10H6zM9 12h.01M15 12h.01",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  store: "M4 9l1-5h14l1 5M5 9v11h14V9M5 9h14",
  sliders: "M4 6h10M18 6h2M4 12h2M10 12h10M4 18h13M20 18h.01",
  seal: "M12 3l2.5 2 3-1 1 3 2.5 2-1 3 1 3-2.5 2-1 3-3-1-2.5 2-2.5-2-3 1-1-3L4 15l1-3-1-3 2.5-2 1-3 3 1z",
};

function Ico({ name }: { name: string }) {
  return (
    <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d={PATHS[name]} />
    </svg>
  );
}

export function Sidebar({ entries }: { entries: number }) {
  return (
    <aside className="sidebar">
      <div className="side-brand">
        <span className="seal-dot" aria-hidden />
        <span className="brand-word">Paygent</span>
      </div>
      <nav className="side-nav">
        {NAV.map((n) => (
          <div key={n.label} className={`nav-item${n.active ? " active" : ""}`}>
            <Ico name={n.icon} />
            {n.label}
          </div>
        ))}
      </nav>
      <div className="side-section eyebrow">System</div>
      <nav className="side-nav">
        <div className="nav-item">
          <Ico name="sliders" />
          Settings
        </div>
      </nav>
      <div className="side-foot">
        <div className="org">Acme AI · Team plan</div>
        <div className="mono" style={{ marginTop: 4 }}>{entries} ledger entries</div>
      </div>
    </aside>
  );
}
