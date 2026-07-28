import { usingDefaultPasscode } from "../../../lib/auth";
import { logout } from "./actions";

export const dynamic = "force-dynamic";

export default function SettingsPage() {
  const isDefault = usingDefaultPasscode();

  return (
    <>
      <div className="page-lead reveal s1">
        <h1 className="lead-title">Settings</h1>
        <p className="lead-sub">Workspace &amp; access for this Vaduno console.</p>
      </div>

      <div className="panel reveal s2">
        <div className="panel-head"><h2>Access</h2></div>
        <div className="setting-row">
          <div>
            <div className="setting-name">Operator passcode</div>
            <div className="setting-desc">
              {isDefault
                ? "Using the demo default. Set VADUNO_DASHBOARD_PASSCODE for production."
                : "Configured via VADUNO_DASHBOARD_PASSCODE."}
            </div>
          </div>
          <span className={`tag ${isDefault ? "caution" : "ok"}`}>{isDefault ? "demo" : "configured"}</span>
        </div>
        <div className="setting-row">
          <div>
            <div className="setting-name">Session</div>
            <div className="setting-desc">Signed HMAC cookie, 12-hour expiry. Approvals re-check it server-side.</div>
          </div>
          <form action={logout}>
            <button className="btn btn-ghost" type="submit">Sign out</button>
          </form>
        </div>
      </div>

      <div className="panel reveal s3">
        <div className="panel-head"><h2>About</h2></div>
        <div className="setting-desc" style={{ lineHeight: 1.7 }}>
          Vaduno governs and records AI-agent payments — it never holds funds or keys.
          This console reads the tamper-evident ledger produced by <code>@vaduno/guard</code> and
          resolves the approvals your agents are blocking on. Rail adapters: x402 (live), Stripe issuing (planned).
        </div>
      </div>
    </>
  );
}
