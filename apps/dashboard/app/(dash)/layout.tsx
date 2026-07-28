import type { ReactNode } from "react";
import { loadOverview } from "../../lib/data";
import { Sidebar } from "../components/Sidebar";
import { Topbar } from "../components/Topbar";
import { ApprovalRail } from "../components/ApprovalRail";
import { MobileChrome } from "../components/MobileChrome";
import { CommandPaletteProvider } from "../components/CommandPalette";

export const dynamic = "force-dynamic";

export default async function DashLayout({ children }: { children: ReactNode }) {
  const data = await loadOverview();

  if (!data.ok) {
    return (
      <div className="login-shell">
        <div className="login-card">
          <div className="login-mark">
            <span className="seal-dot" aria-hidden />
            <span className="brand-word">Swale</span>
          </div>
          <h1 className="login-title">{data.errored ? "Ledger unreadable." : "No ledger yet."}</h1>
          <p className="login-sub">
            Run <code>npm run dashboard:seed</code> to generate a sample ledger, then reload.
          </p>
        </div>
      </div>
    );
  }

  return (
    <CommandPaletteProvider>
      <MobileChrome pending={data.pending} chain={data.chain} />
      <div className="shell">
        <Sidebar entries={data.entryCount} />
        <main className="main">
          <Topbar chain={data.chain} />
          <div className="content">{children}</div>
        </main>
        <ApprovalRail pending={data.pending} />
      </div>
    </CommandPaletteProvider>
  );
}
