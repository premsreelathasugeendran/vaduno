import "server-only";
import { stat } from "node:fs/promises";
import {
  AuditLedger,
  FileApprovalStore,
  JsonlLedgerStore,
  type LedgerEntry,
  type PendingApproval,
  type VerifyResult,
} from "@swale/guard";
import { APPROVALS_PATH, LEDGER_PATH } from "./paths";

export function getLedger(): AuditLedger {
  return new AuditLedger(new JsonlLedgerStore(LEDGER_PATH));
}

export function getApprovalStore(): FileApprovalStore {
  return new FileApprovalStore(APPROVALS_PATH);
}

export interface DayPoint {
  day: string;
  minor: number;
  currency: string;
}

export interface Overview {
  ok: boolean;
  errored: boolean;
  entryCount: number;
  chain: VerifyResult;
  currency: string;
  firewallDailyMinor: number | null;
  firewallTxnMinor: number | null;
  totalsByCurrency: Record<string, number>;
  executedCount: number;
  failedCount: number;
  deniedCount: number;
  blockedMinor: number;
  spendByDay: DayPoint[];
  spendByMerchant: Array<{ merchantId: string; minor: number; currency: string }>;
  spendByAgent: Array<{ agentId: string; minor: number; currency: string }>;
  activity: ActivityRow[];
  pending: PendingApproval[];
}

export interface ActivityRow {
  key: string;
  status: "executed" | "denied" | "failed";
  merchantId: string;
  agentId: string;
  rail: string;
  amountMinor: number | null;
  currency: string | null;
  timestamp: string;
  reason?: string;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

// Light cross-request cache keyed on the ledger file's mtime — avoids
// re-reading + re-hashing the whole chain on every reload (the route is also
// auth-gated, so this is not an anonymous amplification target).
let cache: { mtimeMs: number; approvalsMtime: number; overview: Overview } | null = null;

async function mtimeOf(path: string): Promise<number> {
  try {
    return (await stat(path)).mtimeMs;
  } catch {
    return -1;
  }
}

export async function loadOverview(): Promise<Overview> {
  const [ledgerM, approvalsM] = await Promise.all([mtimeOf(LEDGER_PATH), mtimeOf(APPROVALS_PATH)]);
  if (cache && cache.mtimeMs === ledgerM && cache.approvalsMtime === approvalsM) {
    return cache.overview;
  }
  const overview = await computeOverview();
  cache = { mtimeMs: ledgerM, approvalsMtime: approvalsM, overview };
  return overview;
}

async function computeOverview(): Promise<Overview> {
  const empty = (errored: boolean): Overview => ({
    ok: false,
    errored,
    entryCount: 0,
    chain: { ok: true, entries: 0 },
    currency: "USD",
    firewallDailyMinor: null,
    firewallTxnMinor: null,
    totalsByCurrency: {},
    executedCount: 0,
    failedCount: 0,
    deniedCount: 0,
    blockedMinor: 0,
    spendByDay: [],
    spendByMerchant: [],
    spendByAgent: [],
    activity: [],
    pending: [],
  });

  const ledger = getLedger();
  let entries: LedgerEntry[];
  let chain: VerifyResult;
  let pending: PendingApproval[];
  try {
    [entries, chain, pending] = await Promise.all([
      ledger.all(),
      ledger.verify(),
      getApprovalStore().listPending().catch(() => []),
    ]);
  } catch {
    return empty(true);
  }
  if (entries.length === 0) return { ...empty(false), pending: [] };

  // Latest policy (logged via setPolicy) drives currency + the firewall line.
  let currency = "USD";
  let firewallDailyMinor: number | null = null;
  let firewallTxnMinor: number | null = null;
  for (const e of entries) {
    if (e.type === "policy_updated" && isObj(e.data) && isObj(e.data.policy)) {
      const p = e.data.policy as { currency?: unknown; limits?: unknown };
      if (typeof p.currency === "string") currency = p.currency;
      if (isObj(p.limits)) {
        if (Number.isSafeInteger(p.limits.perDayMinor)) firewallDailyMinor = p.limits.perDayMinor as number;
        if (Number.isSafeInteger(p.limits.perTransactionMinor)) firewallTxnMinor = p.limits.perTransactionMinor as number;
      }
    }
  }

  const intentInfo = new Map<string, { merchantId: string; agentId: string; rail: string; amountMinor: number; currency: string }>();
  for (const e of entries) {
    if (e.type === "intent_received" && isObj(e.data) && isObj(e.data.intent) && e.intentId) {
      const i = e.data.intent as Record<string, unknown>;
      const m = isObj(i.merchant) ? i.merchant : {};
      const a = isObj(i.amount) ? i.amount : {};
      intentInfo.set(e.intentId, {
        merchantId: typeof m.id === "string" ? m.id : "?",
        agentId: e.agentId ?? "?",
        rail: typeof i.rail === "string" ? i.rail : "?",
        amountMinor: Number.isFinite(a.amountMinor) ? (a.amountMinor as number) : 0,
        currency: typeof a.currency === "string" ? a.currency : "?",
      });
    }
  }

  const totalsByCurrency: Record<string, number> = {};
  const byDay = new Map<string, DayPoint>();
  const byMerchant = new Map<string, { minor: number; currency: string }>();
  const byAgent = new Map<string, { minor: number; currency: string }>();
  let executedCount = 0;
  let failedCount = 0;
  let deniedCount = 0;
  let blockedMinor = 0;
  const activity: ActivityRow[] = [];

  for (const e of entries) {
    if (e.type === "execution_result" && isObj(e.data)) {
      const d = e.data;
      const success = d.success === true;
      const amountMinor = Number.isFinite(d.amountMinor) ? (d.amountMinor as number) : null;
      const cur = typeof d.currency === "string" ? d.currency : "?";
      const merchantId = typeof d.merchantId === "string" ? d.merchantId : "?";
      const rail = typeof d.rail === "string" ? d.rail : "?";
      const ts = typeof e.timestamp === "string" ? e.timestamp : "";
      if (success) {
        executedCount++;
        if (amountMinor !== null) {
          totalsByCurrency[cur] = (totalsByCurrency[cur] ?? 0) + amountMinor;
          const day = ts.slice(0, 10);
          const dk = `${day}|${cur}`;
          const rec = byDay.get(dk) ?? { day, minor: 0, currency: cur };
          rec.minor += amountMinor;
          byDay.set(dk, rec);
          const mr = byMerchant.get(merchantId) ?? { minor: 0, currency: cur };
          mr.minor += amountMinor;
          byMerchant.set(merchantId, mr);
          const ar = byAgent.get(e.agentId ?? "?") ?? { minor: 0, currency: cur };
          ar.minor += amountMinor;
          byAgent.set(e.agentId ?? "?", ar);
        }
      } else {
        failedCount++;
      }
      activity.push({
        key: `${e.seq}`,
        status: success ? "executed" : "failed",
        merchantId,
        agentId: e.agentId ?? "?",
        rail,
        amountMinor,
        currency: cur,
        timestamp: ts,
      });
    } else if (
      e.type === "policy_decision" &&
      isObj(e.data) &&
      isObj(e.data.policyResult) &&
      (e.data.policyResult as { decision?: unknown }).decision === "deny"
    ) {
      deniedCount++;
      const pr = e.data.policyResult as { reasons?: Array<{ code?: unknown }> };
      const info = e.intentId ? intentInfo.get(e.intentId) : undefined;
      if (info) blockedMinor += info.amountMinor;
      activity.push({
        key: `${e.seq}`,
        status: "denied",
        merchantId: info?.merchantId ?? "?",
        agentId: info?.agentId ?? e.agentId ?? "?",
        rail: info?.rail ?? "?",
        amountMinor: info?.amountMinor ?? null,
        currency: info?.currency ?? "?",
        timestamp: typeof e.timestamp === "string" ? e.timestamp : "",
        reason: Array.isArray(pr.reasons)
          ? pr.reasons.map((r) => (typeof r.code === "string" ? r.code : "")).filter(Boolean).slice(0, 2).join(", ")
          : undefined,
      });
    }
  }

  const spendByDay = [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day));
  const spendByMerchant = [...byMerchant.entries()]
    .map(([merchantId, v]) => ({ merchantId, minor: v.minor, currency: v.currency }))
    .sort((a, b) => b.minor - a.minor);
  const spendByAgent = [...byAgent.entries()]
    .map(([agentId, v]) => ({ agentId, minor: v.minor, currency: v.currency }))
    .sort((a, b) => b.minor - a.minor);
  activity.sort((a, b) => b.timestamp.localeCompare(a.timestamp));

  return {
    ok: true,
    errored: false,
    entryCount: entries.length,
    chain,
    currency,
    firewallDailyMinor,
    firewallTxnMinor,
    totalsByCurrency,
    executedCount,
    failedCount,
    deniedCount,
    blockedMinor,
    spendByDay,
    spendByMerchant,
    spendByAgent,
    activity,
    pending,
  };
}

export interface RawLedger {
  ok: boolean;
  entries: LedgerEntry[];
  chain: VerifyResult;
  head: { seq: number; hash: string; entries: number };
}

/** Raw ledger entries (most-recent first, capped) + chain + head. */
export async function loadRawLedger(limit = 500): Promise<RawLedger> {
  const ledger = getLedger();
  try {
    const [all, chain, head] = await Promise.all([ledger.all(), ledger.verify(), ledger.head()]);
    const entries = [...all].reverse().slice(0, limit);
    return { ok: true, entries, chain, head };
  } catch {
    return { ok: false, entries: [], chain: { ok: true, entries: 0 }, head: { seq: -1, hash: "", entries: 0 } };
  }
}

export async function loadIntentTrail(intentId: string): Promise<LedgerEntry[]> {
  try {
    return await getLedger().trailFor(intentId);
  } catch {
    return [];
  }
}

export interface ActivePolicy {
  id: string;
  version: number;
  currency: string;
  limits?: Record<string, number>;
  merchants?: { allow?: string[]; block?: string[] };
  categories?: { allow?: string[]; block?: string[] };
  rails?: { allow?: string[] };
  approval?: { aboveMinor?: number; always?: boolean };
  velocity?: { maxTransactions?: { count: number; perSeconds: number } };
  updatedAt: string | null;
}

/** The latest policy the guard logged (via setPolicy), for the Firewall view. */
export async function loadActivePolicy(): Promise<ActivePolicy | null> {
  let entries: LedgerEntry[];
  try {
    entries = await getLedger().all();
  } catch {
    return null;
  }
  let policy: ActivePolicy | null = null;
  for (const e of entries) {
    if (e.type === "policy_updated" && isObj(e.data) && isObj(e.data.policy)) {
      const p = e.data.policy as Record<string, unknown>;
      policy = {
        id: typeof p.id === "string" ? p.id : "policy",
        version: typeof p.version === "number" ? p.version : 1,
        currency: typeof p.currency === "string" ? p.currency : "USD",
        limits: isObj(p.limits) ? (p.limits as Record<string, number>) : undefined,
        merchants: isObj(p.merchants) ? (p.merchants as ActivePolicy["merchants"]) : undefined,
        categories: isObj(p.categories) ? (p.categories as ActivePolicy["categories"]) : undefined,
        rails: isObj(p.rails) ? (p.rails as ActivePolicy["rails"]) : undefined,
        approval: isObj(p.approval) ? (p.approval as ActivePolicy["approval"]) : undefined,
        velocity: isObj(p.velocity) ? (p.velocity as ActivePolicy["velocity"]) : undefined,
        updatedAt: typeof e.timestamp === "string" ? e.timestamp : null,
      };
    }
  }
  return policy;
}
