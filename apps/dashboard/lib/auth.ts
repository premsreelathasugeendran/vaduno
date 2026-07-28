// Portable session auth usable in BOTH the edge middleware and Node server
// actions — uses Web Crypto (globalThis.crypto.subtle), available in both.
//
// SECURITY MODEL (hardened after red-team):
//  - The HMAC signing key is a MANDATORY high-entropy VADUNO_SESSION_SECRET.
//    The passcode is ONLY a login credential, never key material, so a
//    known/guessed passcode cannot forge a cookie.
//  - Fail closed INDEPENDENT of NODE_ENV: if no signing secret is available,
//    no session is minted or accepted (the app refuses access).
//  - The local demo opts into an INSECURE built-in key + default passcode
//    explicitly via VADUNO_ALLOW_DEFAULT_PASSCODE=1 (localhost only). A real
//    deployment MUST set VADUNO_SESSION_SECRET (>=16 chars, 32+ recommended).

export const SESSION_COOKIE = "vaduno_session";
const SESSION_VERSION = "v3";
const TTL_MS = 12 * 60 * 60 * 1000;
const DEMO_KEY = "vaduno-demo-session-key-INSECURE-localhost-only";

function allowDefault(): boolean {
  return !!process.env.VADUNO_ALLOW_DEFAULT_PASSCODE;
}

export function usingDefaultPasscode(): boolean {
  return !process.env.VADUNO_DASHBOARD_PASSCODE;
}

/** The login credential. Empty (no valid passcode) unless configured or demo. */
export function configuredPasscode(): string {
  return process.env.VADUNO_DASHBOARD_PASSCODE || (allowDefault() ? "vaduno" : "");
}

/** The HMAC signing secret, or null if none is available (=> fail closed). */
function sessionSecret(): string | null {
  const s = process.env.VADUNO_SESSION_SECRET;
  if (s && s.length >= 16) return s;
  if (allowDefault()) return DEMO_KEY; // explicit insecure localhost demo
  return null;
}

/** True when the server must refuse all sessions (no signing secret). */
export function serverMisconfigured(): boolean {
  return sessionSecret() === null || configuredPasscode() === "";
}

const encoder = new TextEncoder();

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

/** Constant-time compare of two equal-length strings. */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Verify the login passcode against the configured one. Compares fixed-length
 * SHA-256 digests so neither the compare nor its length leaks the passcode.
 */
async function passcodeMatches(candidate: string): Promise<boolean> {
  const expected = configuredPasscode();
  if (expected === "") return false;
  const [a, b] = await Promise.all([
    hmacHex(DEMO_KEY, `pc:${candidate}`),
    hmacHex(DEMO_KEY, `pc:${expected}`),
  ]);
  return safeEqual(a, b);
}

/** Returns a signed, expiring session token if the passcode is correct, else null. */
export async function mintSession(passcode: string): Promise<string | null> {
  const secret = sessionSecret();
  if (secret === null) return null; // fail closed
  if (!(await passcodeMatches(passcode))) return null;
  const exp = Date.now() + TTL_MS;
  const sig = await hmacHex(secret, `${SESSION_VERSION}:${exp}`);
  return `${exp}.${sig}`;
}

export async function isValidSession(token: string | undefined): Promise<boolean> {
  const secret = sessionSecret();
  if (secret === null) return false; // fail closed
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot <= 0) return false;
  const exp = Number(token.slice(0, dot));
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  return safeEqual(token.slice(dot + 1), await hmacHex(secret, `${SESSION_VERSION}:${exp}`));
}
