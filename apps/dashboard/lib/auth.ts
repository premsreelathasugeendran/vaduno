// Portable session auth usable in BOTH the edge middleware and Node server
// actions — uses Web Crypto (globalThis.crypto.subtle), available in both.
//
// The dashboard can approve real agent payments, so it must FAIL CLOSED:
//  - In production, if no operator passcode is configured, no session is
//    minted or accepted (the app refuses access rather than falling back to a
//    public default). The default "paygent" passcode is a DEV-ONLY convenience.
//  - The session token binds an expiry into the signature (can't be extended
//    without the key) and mixes in an optional server secret so the cookie is
//    not derivable from the passcode alone.

export const SESSION_COOKIE = "paygent_session";
const SESSION_VERSION = "v2";
const TTL_MS = 12 * 60 * 60 * 1000;

export function configuredPasscode(): string {
  return process.env.PAYGENT_DASHBOARD_PASSCODE || "paygent";
}

export function usingDefaultPasscode(): boolean {
  return !process.env.PAYGENT_DASHBOARD_PASSCODE;
}

/**
 * True when the server must refuse all sessions: production build, no operator
 * passcode set, and the insecure default not explicitly opted into. The local
 * demo (`npm run dashboard`) sets PAYGENT_ALLOW_DEFAULT_PASSCODE=1 to use the
 * default on purpose; a real deployment that forgets both fails closed.
 */
export function serverMisconfigured(): boolean {
  return (
    usingDefaultPasscode() &&
    process.env.NODE_ENV === "production" &&
    !process.env.PAYGENT_ALLOW_DEFAULT_PASSCODE
  );
}

// The HMAC key is the passcode plus an optional independent server secret, so a
// leaked/guessed passcode alone does not let an attacker mint tokens if a
// secret is set, and operators can rotate all sessions by changing the secret.
function signingKeyMaterial(): string {
  return `${configuredPasscode()}|${process.env.PAYGENT_SESSION_SECRET ?? ""}`;
}

const encoder = new TextEncoder();

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(signingKeyMaterial()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

/** Constant-time-ish string compare (equal length, XOR accumulate). */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Returns a signed, expiring session token if the passcode is correct, else null. */
export async function mintSession(passcode: string): Promise<string | null> {
  if (serverMisconfigured()) return null;
  if (!safeEqual(passcode, configuredPasscode())) return null;
  const exp = Date.now() + TTL_MS;
  const sig = await hmacHex(`${SESSION_VERSION}:${exp}`);
  return `${exp}.${sig}`;
}

export async function isValidSession(token: string | undefined): Promise<boolean> {
  if (serverMisconfigured()) return false;
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot <= 0) return false;
  const expStr = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  return safeEqual(sig, await hmacHex(`${SESSION_VERSION}:${exp}`));
}
