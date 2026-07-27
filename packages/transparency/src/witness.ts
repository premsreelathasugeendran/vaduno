import { createHash } from "node:crypto";
import { verifyConsistency, type ConsistencyProof } from "./merkle.js";
import { verifyTreeHead, type SignedTreeHead } from "./sth.js";
import {
  parseNote,
  verifyNoteSignature,
  type Checkpoint,
  type ParsedNote,
} from "./checkpoint.js";
import { cosignCheckpoint, type CosignatureRecord } from "./cosign.js";

/**
 * A witness is any party (a client, a second machine, a friend's server) that
 * retains the last signed tree head it accepted and refuses to advance to a
 * new one unless the log PROVES append-only consistency from the old head.
 *
 * With one external witness, a log operator that rewrites history gets caught
 * the next time that witness asks for a consistency proof. With k independent
 * witnesses comparing heads, showing different histories to different parties
 * (split-view/equivocation) requires all k to collude. This module is the
 * client half; publishing heads somewhere public is the operator half.
 */
export interface WitnessState {
  logId: string;
  /** The log operator's Ed25519 public key (PEM). */
  publicKeyPem: string;
  /** Last head this witness accepted; null before the first observation. */
  lastHead: SignedTreeHead | null;
}

export type WitnessResult =
  | { ok: true; state: WitnessState }
  | {
      ok: false;
      code:
        | "BAD_SIGNATURE"
        | "WRONG_LOG"
        | "TREE_SHRANK"
        | "ROOT_CHANGED_WITHOUT_GROWTH"
        | "CONSISTENCY_PROOF_MISSING"
        | "CONSISTENCY_PROOF_INVALID";
      message: string;
    };

/**
 * Observe a new signed head. Fails closed: on any failure the witness state
 * is NOT advanced and the reason names what the operator could not prove.
 *
 * `proof` must cover lastHead.treeSize -> sth.treeSize when the tree grew;
 * it is not needed for the first observation or an identical re-observation.
 */
export function witnessObserve(
  state: WitnessState,
  sth: SignedTreeHead,
  proof?: ConsistencyProof,
): WitnessResult {
  if (sth.logId !== state.logId) {
    return {
      ok: false,
      code: "WRONG_LOG",
      message: `head is for log "${sth.logId}", witness follows "${state.logId}"`,
    };
  }
  if (!verifyTreeHead(sth, state.publicKeyPem)) {
    return {
      ok: false,
      code: "BAD_SIGNATURE",
      message: "signed tree head signature does not verify",
    };
  }
  const prev = state.lastHead;
  if (prev === null) {
    // Trust-on-first-use: the first head is the baseline everything after
    // must stay consistent with.
    return { ok: true, state: { ...state, lastHead: sth } };
  }
  if (sth.treeSize < prev.treeSize) {
    return {
      ok: false,
      code: "TREE_SHRANK",
      message: `tree shrank from ${prev.treeSize} to ${sth.treeSize} (history truncated)`,
    };
  }
  if (sth.treeSize === prev.treeSize) {
    if (sth.rootHash !== prev.rootHash) {
      return {
        ok: false,
        code: "ROOT_CHANGED_WITHOUT_GROWTH",
        message: "same tree size but a different root (history rewritten)",
      };
    }
    return { ok: true, state: { ...state, lastHead: sth } };
  }
  if (prev.treeSize === 0) {
    // The empty tree is a prefix of EVERY tree — growth from it is trivially
    // append-only and no consistency proof exists for first=0 (RFC 9162
    // defines proofs for 0 < first). Without this case a witness whose
    // baseline predates the first leaf could never advance.
    return { ok: true, state: { ...state, lastHead: sth } };
  }
  if (!proof) {
    return {
      ok: false,
      code: "CONSISTENCY_PROOF_MISSING",
      message: `no consistency proof for ${prev.treeSize} -> ${sth.treeSize}`,
    };
  }
  if (
    proof.first !== prev.treeSize ||
    proof.second !== sth.treeSize ||
    !verifyConsistency(prev.rootHash, sth.rootHash, proof)
  ) {
    return {
      ok: false,
      code: "CONSISTENCY_PROOF_INVALID",
      message: `consistency proof does not prove ${prev.treeSize} -> ${sth.treeSize} append-only`,
    };
  }
  return { ok: true, state: { ...state, lastHead: sth } };
}

/**
 * State a COSIGNING witness retains: the last checkpoint it put its name to.
 * This is the memory that makes the whole scheme work — a witness with no
 * durable state cannot detect equivocation and is worth nothing.
 */
export interface CosigningWitnessState {
  /** Log identity, matched against the checkpoint's origin line. */
  origin: string;
  /** The LOG's public key, to verify the log signed this checkpoint. */
  logPublicKeyPem: string;
  /** Name the log uses on its signature line (usually == origin). */
  logKeyName: string;
  /**
   * Last checkpoint this witness cosigned; null before the first.
   *
   * `bodyHash` covers the ENTIRE signed body, not just (treeSize, rootHash) —
   * otherwise a log could equivocate on extension lines, presenting two
   * different-but-same-size checkpoints and getting both cosigned.
   */
  lastCosigned: { treeSize: number; rootHash: string; bodyHash: string } | null;
}

function bodyHashOf(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

export type CosignResult =
  | {
      ok: true;
      cosignature: CosignatureRecord;
      state: CosigningWitnessState;
    }
  | {
      ok: false;
      code:
        | "MALFORMED_NOTE"
        | "WRONG_ORIGIN"
        | "LOG_SIGNATURE_INVALID"
        | "TREE_SHRANK"
        | "ROOT_CHANGED_WITHOUT_GROWTH"
        | "BODY_CHANGED_WITHOUT_GROWTH"
        | "CONSISTENCY_PROOF_MISSING"
        | "CONSISTENCY_PROOF_INVALID";
      message: string;
    };

/**
 * The witness half of the C2SP tlog-witness protocol: verify a checkpoint is
 * (a) for the right log, (b) genuinely signed by that log, and (c) append-only
 * consistent with the last checkpoint THIS witness cosigned — and only then
 * cosign it.
 *
 * The refusal is the entire point. A witness that cosigns whatever it is
 * handed provides no non-equivocation guarantee at all; it is the "I will not
 * put my name to a history that contradicts the one I already signed" rule
 * that forces an equivocating operator to either give up or corrupt k
 * independent parties.
 *
 * Fails closed: on ANY failure no cosignature is produced and the witness's
 * state is left untouched.
 */
export function witnessCosign(
  state: CosigningWitnessState,
  note: string,
  opts: {
    name: string;
    privateKeyPem: string;
    publicKeyPem: string;
    /** Consistency proof lastCosigned.treeSize -> checkpoint.treeSize. */
    proof?: ConsistencyProof;
    timestamp?: number;
  },
): CosignResult {
  let parsed: ParsedNote;
  try {
    parsed = parseNote(note);
  } catch (err) {
    return {
      ok: false,
      code: "MALFORMED_NOTE",
      message: err instanceof Error ? err.message : String(err),
    };
  }
  const cp: Checkpoint = parsed.checkpoint;
  if (cp.origin !== state.origin) {
    return {
      ok: false,
      code: "WRONG_ORIGIN",
      message: `checkpoint origin "${cp.origin}" != witnessed log "${state.origin}"`,
    };
  }
  if (
    !verifyNoteSignature(parsed, {
      name: state.logKeyName,
      publicKeyPem: state.logPublicKeyPem,
    })
  ) {
    return {
      ok: false,
      code: "LOG_SIGNATURE_INVALID",
      message: "checkpoint is not signed by the log key this witness follows",
    };
  }
  const prev = state.lastCosigned;
  if (prev !== null) {
    if (cp.treeSize < prev.treeSize) {
      return {
        ok: false,
        code: "TREE_SHRANK",
        message: `tree shrank from ${prev.treeSize} to ${cp.treeSize} (history truncated)`,
      };
    }
    if (cp.treeSize === prev.treeSize) {
      if (cp.rootHash !== prev.rootHash) {
        // THE equivocation signal: same size, different root.
        return {
          ok: false,
          code: "ROOT_CHANGED_WITHOUT_GROWTH",
          message: "same tree size but a different root — the log is showing two histories",
        };
      }
      if (bodyHashOf(parsed.body) !== prev.bodyHash) {
        // Same size and root, but a different signed body — e.g. equivocation
        // hidden in extension lines. Refuse: we would otherwise put our name
        // to two contradictory statements about the same tree state.
        return {
          ok: false,
          code: "BODY_CHANGED_WITHOUT_GROWTH",
          message:
            "same tree size and root but a different checkpoint body (extension lines differ)",
        };
      }
      // Identical re-observation: safe to cosign again (refreshes freshness).
    } else if (prev.treeSize > 0) {
      if (!opts.proof) {
        return {
          ok: false,
          code: "CONSISTENCY_PROOF_MISSING",
          message: `no consistency proof for ${prev.treeSize} -> ${cp.treeSize}`,
        };
      }
      if (
        opts.proof.first !== prev.treeSize ||
        opts.proof.second !== cp.treeSize ||
        !verifyConsistency(prev.rootHash, cp.rootHash, opts.proof)
      ) {
        return {
          ok: false,
          code: "CONSISTENCY_PROOF_INVALID",
          message: `consistency proof does not prove ${prev.treeSize} -> ${cp.treeSize} append-only`,
        };
      }
    }
    // prev.treeSize === 0: the empty tree is a prefix of every tree.
  }
  const cosignature = cosignCheckpoint(parsed, {
    name: opts.name,
    privateKeyPem: opts.privateKeyPem,
    publicKeyPem: opts.publicKeyPem,
    ...(opts.timestamp !== undefined ? { timestamp: opts.timestamp } : {}),
  });
  return {
    ok: true,
    cosignature,
    state: {
      ...state,
      lastCosigned: {
        treeSize: cp.treeSize,
        rootHash: cp.rootHash,
        bodyHash: bodyHashOf(parsed.body),
      },
    },
  };
}

/**
 * A witness with state it actually owns.
 *
 * `witnessCosign` is a pure function: it returns the NEW state and trusts the
 * caller to store it. Under concurrency that is a read-modify-write race —
 * two requests both read the old state, both pass the consistency check, and
 * the witness ends up having cosigned two conflicting checkpoints, which is
 * precisely the failure it exists to prevent.
 *
 * This wrapper serializes cosign requests through a promise queue and commits
 * the new state before releasing the next one, so a witness cannot contradict
 * itself no matter how the requests arrive. Persist `state` (see
 * `onCommit`) — a witness that forgets its state across restarts has no
 * baseline to contradict and is worth nothing.
 */
export class CosigningWitness {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private state: CosigningWitnessState,
    private readonly identity: {
      name: string;
      privateKeyPem: string;
      publicKeyPem: string;
    },
    /** Called with each committed state so it can be persisted durably. */
    private readonly onCommit?: (state: CosigningWitnessState) => void | Promise<void>,
  ) {}

  /** Current state (a copy; mutating it does not affect the witness). */
  getState(): CosigningWitnessState {
    return { ...this.state };
  }

  /**
   * Cosign a checkpoint if and only if it is consistent with everything this
   * witness has already cosigned. Serialized: concurrent calls are applied
   * one at a time, each seeing the previous one's committed state.
   */
  cosign(
    note: string,
    opts: { proof?: ConsistencyProof; timestamp?: number } = {},
  ): Promise<CosignResult> {
    const task = this.queue.then(async (): Promise<CosignResult> => {
      const result = witnessCosign(this.state, note, {
        ...this.identity,
        ...(opts.proof !== undefined ? { proof: opts.proof } : {}),
        ...(opts.timestamp !== undefined ? { timestamp: opts.timestamp } : {}),
      });
      if (result.ok) {
        // Commit BEFORE releasing the queue, so the next request cannot read
        // a stale baseline.
        this.state = result.state;
        await this.onCommit?.(result.state);
      }
      return result;
    });
    this.queue = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }
}

export interface SplitViewResult {
  consistent: boolean;
  /** Two VERIFIED heads, same size, different roots — signed equivocation. */
  conflict?: [SignedTreeHead, SignedTreeHead];
  /** Heads whose signature did not verify; excluded from comparison. */
  unverified: SignedTreeHead[];
}

/**
 * Compare heads gathered from independent witnesses of the same log. Each
 * head's signature is verified first — an unverifiable head is set aside,
 * never treated as evidence. Two VERIFIED heads of the SAME size with
 * DIFFERENT roots are cryptographic proof of operator equivocation (both
 * carry the operator's signature).
 *
 * Honest scope: this offline check only catches same-size forks. Different-
 * size forks are caught by `witnessObserve`, which demands a consistency
 * proof from each witness's retained head — run both.
 */
export function detectSplitView(
  heads: readonly SignedTreeHead[],
  publicKeyPem: string,
): SplitViewResult {
  const unverified: SignedTreeHead[] = [];
  const bySize = new Map<number, SignedTreeHead>();
  for (const h of heads) {
    if (!verifyTreeHead(h, publicKeyPem)) {
      unverified.push(h);
      continue;
    }
    const seen = bySize.get(h.treeSize);
    if (seen && seen.rootHash !== h.rootHash) {
      return { consistent: false, conflict: [seen, h], unverified };
    }
    bySize.set(h.treeSize, h);
  }
  return { consistent: true, unverified };
}
