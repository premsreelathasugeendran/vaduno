/**
 * Timestamp handling for policies and mandates.
 *
 * Integrator- and attacker-supplied timestamps may carry any ISO offset
 * ("+05:30", "Z", or none). Lexicographic string comparison of those is
 * WRONG — "2026-01-01T05:30:00+05:30" sorts after "...T02:00:00Z" as text
 * but is the SAME instant. We always compare epoch milliseconds, and treat
 * an unparseable timestamp as a hard failure (fail closed).
 */
export function parseMs(iso: string): number {
  return Date.parse(iso);
}

export function isParseable(iso: string): boolean {
  return !Number.isNaN(Date.parse(iso));
}
