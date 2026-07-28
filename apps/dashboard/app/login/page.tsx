import { login } from "./actions";
import { serverMisconfigured, usingDefaultPasscode } from "../../lib/auth";

export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  const isDefault = usingDefaultPasscode();
  const misconfigured = serverMisconfigured();

  if (misconfigured) {
    return (
      <div className="login-shell">
        <div className="login-card reveal">
          <div className="login-mark">
            <span className="seal-dot" aria-hidden />
            <span className="brand-word">Swale</span>
          </div>
          <h1 className="login-title">Server not configured.</h1>
          <p className="login-sub">
            This console approves real agent payments, so it refuses to run in production without an
            operator passcode. Set <code>SWALE_DASHBOARD_PASSCODE</code> (and optionally{" "}
            <code>SWALE_SESSION_SECRET</code>) and restart.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="login-shell">
      <div className="login-card reveal">
        <div className="login-mark">
          <span className="seal-dot" aria-hidden />
          <span className="brand-word">Swale</span>
        </div>
        <h1 className="login-title">The vault is sealed.</h1>
        <p className="login-sub">
          Authenticate to review agent charges awaiting your signature.
        </p>
        <form action={login} className="login-form">
          <label className="field-label" htmlFor="passcode">
            Operator passcode
          </label>
          <input
            id="passcode"
            name="passcode"
            type="password"
            autoFocus
            autoComplete="current-password"
            className="field-input"
            placeholder="••••••••"
          />
          {error && <div className="login-error">Incorrect passcode.</div>}
          <button className="btn btn-gold btn-block" type="submit">
            Unlock
          </button>
        </form>
        {isDefault && (
          <div className="login-hint">
            Demo mode — passcode is <code>swale</code>. Set{" "}
            <code>SWALE_DASHBOARD_PASSCODE</code> for production.
          </div>
        )}
      </div>
    </div>
  );
}
