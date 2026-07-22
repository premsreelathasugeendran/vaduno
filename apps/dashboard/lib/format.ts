// Minor-unit decimals by currency for display. amountMinor is always integer;
// this only affects rendering. For a currency NOT in this table we do NOT
// silently assume 2 decimals (that could misrepresent the amount to an
// approver) — we surface the raw integer with an explicit marker instead.
const DECIMALS: Record<string, number> = {
  USDC: 6,
  USDT: 6,
  DAI: 18,
  USD: 2,
  INR: 2,
  EUR: 2,
  GBP: 2,
};

export function knownCurrency(currency: string): boolean {
  return currency.toUpperCase() in DECIMALS;
}

export function decimalsFor(currency: string): number | null {
  return DECIMALS[currency.toUpperCase()] ?? null;
}

const SYMBOLS: Record<string, string> = { USD: "$", EUR: "€", GBP: "£", INR: "₹" };

export interface MoneyParts {
  symbol: string;
  whole: string;
  fraction: string;
  suffix: string; // currency code when there's no glyph
  unknown: boolean;
}

/** Decompose an amount into banknote parts (symbol / whole / fraction). */
export function moneyParts(amountMinor: number, currency: string): MoneyParts {
  const cur = currency.toUpperCase();
  const d = decimalsFor(cur);
  if (d === null) {
    return { symbol: "", whole: amountMinor.toLocaleString("en-US"), fraction: "", suffix: cur, unknown: true };
  }
  const major = amountMinor / 10 ** d;
  const displayFrac = Math.min(d, 2);
  const [whole, fraction = ""] = major.toFixed(displayFrac).split(".");
  const grouped = Number(whole).toLocaleString("en-US");
  return {
    symbol: SYMBOLS[cur] ?? "",
    whole: grouped,
    fraction,
    suffix: SYMBOLS[cur] ? "" : cur,
    unknown: false,
  };
}

export function formatAmount(amountMinor: number, currency: string): string {
  const p = moneyParts(amountMinor, currency);
  if (p.unknown) return `${p.whole} ${p.suffix}`;
  const body = p.fraction ? `${p.symbol}${p.whole}.${p.fraction}` : `${p.symbol}${p.whole}`;
  return p.suffix ? `${body} ${p.suffix}` : body;
}

/** Compact form for KPI tiles / axes: $1.2M, $12.4K. */
export function formatCompact(amountMinor: number, currency: string): string {
  const d = decimalsFor(currency);
  if (d === null) return `${amountMinor.toLocaleString("en-US")} ${currency.toUpperCase()}`;
  const major = amountMinor / 10 ** d;
  const sym = SYMBOLS[currency.toUpperCase()] ?? "";
  const suffix = sym ? "" : ` ${currency.toUpperCase()}`;
  const compact = new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(major);
  return `${sym}${compact}${suffix}`;
}

/** Major-unit number (for count-up animations). */
export function toMajor(amountMinor: number, currency: string): number {
  const d = decimalsFor(currency);
  return d === null ? amountMinor : amountMinor / 10 ** d;
}

export function shortId(id: string, head = 8): string {
  return id.length > head + 1 ? `${id.slice(0, head)}…` : id;
}

export function timeAgo(iso: string, nowMs: number): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const diff = Math.max(0, nowMs - t);
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
