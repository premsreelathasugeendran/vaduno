import { login } from "./actions";
import { usingDefaultPasscode } from "../../lib/auth";

export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  const isDefault = usingDefaultPasscode();

  return (
    <div className="login-shell">
      <div className="login-card reveal">
        <div className="login-mark">
          <span className="seal-dot" aria-hidden />
          <span className="brand-word">Paygent</span>
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
            Demo mode — passcode is <code>paygent</code>. Set{" "}
            <code>PAYGENT_DASHBOARD_PASSCODE</code> for production.
          </div>
        )}
      </div>
    </div>
  );
}
