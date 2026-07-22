// Portable session auth usable in BOTH the edge middleware and Node server
// actions — uses Web Crypto (globalThis.crypto.subtle), available in both.
//
// The dashboard can approve real agent payments, so every route and the
// resolve action are gated. The session cookie is an HMAC that cannot be
// forged without the passcode. For a local demo the passcode defaults to
// "paygent"; production MUST set PAYGENT_DASHBOARD_PASSCODE.

export const SESSION_COOKIE = "paygent_session";
const SESSION_MESSAGE = "paygent-session-v1";

export function configuredPasscode(): string {
  return process.env.PAYGENT_DASHBOARD_PASSCODE || "paygent";
}

export function usingDefaultPasscode(): boolean {
  return !process.env.PAYGENT_DASHBOARD_PASSCODE;
}

const encoder = new TextEncoder();

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sessionToken(): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(configuredPasscode()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(SESSION_MESSAGE));
  return toHex(sig);
}

/** Constant-time-ish string compare (equal length, XOR accumulate). */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function isValidSession(token: string | undefined): Promise<boolean> {
  if (!token) return false;
  return safeEqual(token, await sessionToken());
}

/** Returns a session token if the passcode is correct, else null. */
export async function mintSession(passcode: string): Promise<string | null> {
  if (!safeEqual(passcode, configuredPasscode())) return null;
  return sessionToken();
}
