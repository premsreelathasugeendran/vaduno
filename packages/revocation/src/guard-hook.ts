import type { PaymentIntent } from "@vaduno/guard";
import type { RevocationRegistry } from "./registry.js";
import { checkStatus, type StatusListCredential, type StatusPurpose } from "./status-list.js";

/**
 * Wiring that makes revocation ENFORCED, not advisory.
 *
 * Vaduno's guard consults a `RevocationCheck` at authorization time and fails
 * closed: a revoked mandate, a blocked agent, or an UNANSWERABLE registry all
 * deny the payment. "Unanswerable" is the important case — a registry outage
 * must never read as "not revoked", or an attacker could disable the kill
 * switch by knocking the registry offline.
 */

export type RevocationVerdict =
  | { allowed: true }
  | { allowed: false; code: string; message: string };

export type RevocationCheck = (intent: PaymentIntent) => Promise<RevocationVerdict>;

/**
 * Local (issuer-side) check against the live registry — instant and
 * authoritative for mandates this registry governs. Use inside the process
 * that owns the registry.
 */
export function createRegistryCheck(registry: RevocationRegistry): RevocationCheck {
  return async (intent) => {
    try {
      if (await registry.isAgentBlocked(intent.agentId)) {
        return {
          allowed: false,
          code: "AGENT_REVOKED",
          message: `agent "${intent.agentId}" has been revoked`,
        };
      }
      if (intent.mandateId) {
        const record = await registry.isRevoked(intent.mandateId);
        if (record) {
          return {
            allowed: false,
            code: record.purpose === "suspension" ? "MANDATE_SUSPENDED" : "MANDATE_REVOKED",
            message: `mandate ${record.mandateId} was ${record.purpose === "suspension" ? "suspended" : "revoked"} at ${record.revokedAt}${record.reason ? ` (${record.reason})` : ""}`,
          };
        }
      }
      return { allowed: true };
    } catch (err) {
      // FAIL CLOSED: we could not determine status, so we must not authorize.
      return {
        allowed: false,
        code: "REVOCATION_CHECK_FAILED",
        message: `revocation status could not be determined (fail closed): ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  };
}

export interface StatusListCheckOptions {
  /** Fetch the newest published list. Throwing = fail closed. */
  fetchList: () => Promise<StatusListCredential>;
  publicKeyPem: string;
  /** Map an intent to its mandate's status-list index. */
  indexFor: (intent: PaymentIntent) => number | undefined;
  /**
   * Which list this verifier is FOR. Pin these: a signature proves who signed,
   * not which list — without pinning, any list the issuer key ever signed
   * (including a sibling suspension list whose revocation bits are clear)
   * substitutes for this one and silently un-revokes everything.
   */
  expectedListId?: string;
  expectedIssuer?: string;
  expectedPurpose?: StatusPurpose;
  /**
   * Reject a list whose version is lower than the highest seen — stops an
   * attacker replaying an OLD (pre-revocation) but still-fresh snapshot.
   */
  rejectRollback?: boolean;
  /**
   * Seed the rollback floor from durable storage. The floor is otherwise
   * per-instance memory, so a cold start (serverless, a new replica, a
   * restart) accepts a pre-revocation snapshot for its whole TTL. Persist
   * `onFloorAdvance` and seed it back here.
   */
  initialVersionFloor?: number;
  /** Called whenever the floor advances, so it can be persisted. */
  onFloorAdvance?: (version: number, encodedList: string) => void;
  now?: () => Date;
}

/**
 * Remote (verifier-side) check for a party that does NOT own the registry:
 * fetch the signed status list, verify it, and read the mandate's bit.
 * Everything fails closed — bad signature, stale list, rolled-back version,
 * fetch failure, or a mandate with no assigned index.
 */
export function createStatusListCheck(opts: StatusListCheckOptions): RevocationCheck {
  let highestVersion = opts.initialVersionFloor ?? -1;
  /** Bitstring of the credential that set the current floor, so a DIFFERENT
   * list at the SAME version cannot slip past a `<`-only comparison. */
  let floorContent: string | null = null;
  return async (intent) => {
    const index = opts.indexFor(intent);
    if (index === undefined) {
      return {
        allowed: false,
        code: "NO_STATUS_INDEX",
        message: "intent's mandate carries no status list index — status is unknown (fail closed)",
      };
    }
    let credential: StatusListCredential;
    try {
      credential = await opts.fetchList();
    } catch (err) {
      return {
        allowed: false,
        code: "STATUS_RETRIEVAL_ERROR",
        message: `could not retrieve the status list (fail closed): ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (opts.rejectRollback ?? true) {
      if (credential.version < highestVersion) {
        return {
          allowed: false,
          code: "STATUS_LIST_ROLLBACK",
          message: `status list version ${credential.version} is older than ${highestVersion} already seen (replay of a pre-revocation snapshot)`,
        };
      }
      // Same version, DIFFERENT CONTENT: someone published twice under one
      // version, or is serving a sibling/older list. A `<`-only floor would
      // wave this through, so treat it as a rollback too. Compared on the
      // bitstring rather than the signature, so an issuer legitimately
      // re-stamping identical content (refreshed TTL) is not rejected.
      if (
        credential.version === highestVersion &&
        floorContent !== null &&
        credential.encodedList !== floorContent
      ) {
        return {
          allowed: false,
          code: "STATUS_LIST_ROLLBACK",
          message: `a DIFFERENT status list was served at the same version (${credential.version}) — versions must strictly increase`,
        };
      }
    }
    const check = checkStatus(credential, index, {
      publicKeyPem: opts.publicKeyPem,
      // Pin identity from the CALLER's expectations, never from the credential
      // itself (that would be a tautology). Defaults keep a caller that
      // supplied none from silently accepting a foreign list's purpose.
      expectedPurpose: opts.expectedPurpose ?? "revocation",
      ...(opts.expectedListId !== undefined ? { expectedListId: opts.expectedListId } : {}),
      ...(opts.expectedIssuer !== undefined ? { expectedIssuer: opts.expectedIssuer } : {}),
      ...(opts.now ? { now: opts.now } : {}),
    });
    // Advance the rollback floor whenever the CREDENTIAL itself verified as
    // authentic and fresh (code "OK"), independent of whether this particular
    // entry was set. Gating it on `valid` would mean a list that REVOKED our
    // mandate never pinned its version — letting an attacker replay the older
    // pre-revocation snapshot afterwards, which is exactly what the floor
    // exists to stop.
    if (check.code === "OK" && credential.version >= highestVersion) {
      highestVersion = credential.version;
      floorContent = credential.encodedList;
      opts.onFloorAdvance?.(credential.version, credential.encodedList);
    }
    if (!check.valid) {
      return {
        allowed: false,
        code: check.revoked ? "MANDATE_REVOKED" : `STATUS_${check.code}`,
        message: check.message,
      };
    }
    return { allowed: true };
  };
}

/**
 * Compose several checks — e.g. the local registry AND a partner's published
 * list. ALL must allow; the first denial wins (fail closed under any doubt).
 */
export function allChecks(...checks: RevocationCheck[]): RevocationCheck {
  return async (intent) => {
    for (const check of checks) {
      const verdict = await check(intent);
      if (!verdict.allowed) return verdict;
    }
    return { allowed: true };
  };
}
