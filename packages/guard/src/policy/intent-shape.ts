/**
 * Up-front structural inspection of a PaymentIntent, so that an intent the
 * audit ledger cannot record is REFUSED WITH A RECORD rather than refused
 * silently.
 *
 * THE BUG THIS EXISTS TO KILL. The ledger hashes entries with `canonicalJson`,
 * which (correctly) throws on anything JSON cannot represent exactly — NaN,
 * ±Infinity, bigint, Date, Map, a class instance, `undefined` inside an array.
 * The guard's very first act is to append `intent_received` carrying the whole
 * intent, so an intent holding ANY such value made that append throw. The guard
 * then returned AUDIT_WRITE_FAILED and wrote ZERO ledger entries — versus two
 * for an ordinary deny. The refusal was right; the record of it vanished. The
 * one attempt an operator most wants to see afterwards — a malformed,
 * possibly hostile intent — was the one attempt that left no evidence at all.
 *
 * THE FIX SHAPE. Inspect first, then record a SANITIZED copy (offending values
 * replaced by a marker string, so the entry is always canonicalizable) tagged
 * `intentSanitized: true` with a BOUNDED list of problems, and deny with a real
 * policy code. Evidence is never traded for correctness in either direction:
 * the payment is still refused, and the refusal is still on the chain.
 *
 * EVIDENCE IS BOUNDED — THE AMPLIFICATION DEFECT. The first version of this
 * file reported problems EXHAUSTIVELY and un-truncated: every offending value
 * produced a full {path, problem} record, and the caller joined them all into
 * one deny-reason message. Measured: 100,000 bad values in one intent wrote
 * 18,678,768 bytes of ledger (~62x amplification, linear, uncapped), and a
 * sparse 100M-slot array (O(1) caller bytes) drove the walk itself out of
 * memory. A tamper-evident, append-only ledger a counterparty can inflate at
 * will — or a validator it can OOM — is a denial-of-service surface. So every
 * dimension of this file's output is now capped by a named constant below, and
 * the truth is preserved by COUNTING what is not enumerated ("N problems,
 * first K shown"). A bounded, truthful trace still satisfies the DEFECT-7
 * requirement that suspicious refusals leave evidence.
 *
 * VALUE SPACE relative to `canonicalJson`: everything this file PASSES,
 * canonicalJson accepts — any change to the accepted per-value space belongs
 * in both files. This file may additionally REFUSE structures canonicalJson
 * would accept (a container over MAX_CONTAINER_ENTRIES, a walk over
 * MAX_WALK_NODES): that direction is fail-closed and exists precisely so the
 * ledger row stays bounded.
 */

/** Mirrors canonicalJson's MAX_DEPTH: deeper input is a problem, not a crash. */
const MAX_DEPTH = 256;

/**
 * How many problem RECORDS are retained (with path + description). Everything
 * beyond is counted in `totalProblems`, never enumerated. Eight localizes a
 * malformed intent for an operator (a real intent has a handful of independent
 * defects; thousands means hostile input, and the COUNT says so) while
 * bounding the record at ~2.3 KB worst case.
 */
export const MAX_REPORTED_PROBLEMS = 8;

/** Longest retained path string. Keys are attacker-controlled; clamp them. */
export const MAX_PATH_CHARS = 160;

/** Longest retained per-problem description. */
export const MAX_PROBLEM_CHARS = 120;

/**
 * Per-container inspection cap (array elements / object keys). A container
 * larger than this is itself a problem: the remainder is summarized by one
 * marker, not walked. Kills the sparse-array attack (`new Array(1e8)` is O(1)
 * caller bytes but 1e8 walk steps) and bounds marker fan-out. Far above any
 * real payment intent — the x402 adapter's 402 body is capped at 64 KB, which
 * cannot encode this many meaningful entries.
 */
export const MAX_CONTAINER_ENTRIES = 10_000;

/**
 * Whole-walk node budget — the backstop that bounds CPU and output when many
 * containers each stay under MAX_CONTAINER_ENTRIES. On breach the walk stops
 * descending and the remainder is summarized.
 *
 * THE EXACT CEILING these constants buy (see the file docblock for why):
 * at most MAX_WALK_NODES values are ever walked, each contributing at most one
 * ≤ ~120-byte marker to the sanitized copy. So the intent_received row is
 * ≤ min(~1× the intent's own bytes + constant, ~2.4 MB absolute), the
 * policy_decision reasons are ≤ ~2.4 KB, and NOTHING grows linearly with
 * attacker input past these caps. Measured after the fix: the
 * flat-100,000-bad-values intent that wrote 18,678,768 bytes now writes
 * 592,130 bytes (the single-container cap), and the same intent at any larger
 * n writes the same 592,130 bytes.
 */
export const MAX_WALK_NODES = 20_000;

export interface IntentShapeProblem {
  /** JSON-path-ish location, e.g. "$.amount.amountMinor" (clamped). */
  path: string;
  /** Why this value cannot be recorded (clamped). */
  problem: string;
  /**
   * "unrepresentable" — the VALUE cannot be recorded exactly (NaN, bigint, a
   * cycle, a class instance). "oversize" — the value is perfectly
   * representable but the intent exceeds an inspection bound, so it was not
   * walked. Kept apart because they are different operator problems with
   * different fixes, and reporting a 25,000-element array of strings as
   * "holds values the audit trail cannot record exactly" would be false.
   */
  kind: "unrepresentable" | "oversize";
}

export interface IntentShapeReport {
  /**
   * The first MAX_REPORTED_PROBLEMS problems, strings clamped. NEVER the full
   * enumeration — see `totalProblems` for the true count.
   */
  problems: IntentShapeProblem[];
  /** True count of problems found (may far exceed problems.length). */
  totalProblems: number;
  /**
   * A deep copy in which every offending value is replaced by a marker string
   * and over-cap containers are truncated with a marker. Guaranteed
   * canonicalizable, so it can always be appended to the ledger.
   *
   * Present ONLY when totalProblems > 0. A clean intent — the common case —
   * is recorded as itself by the caller, so building (and discarding) a deep
   * copy for it was pure waste: measured at +27 MB retained for one clean
   * 2^18-path DAG intent.
   */
  sanitized?: unknown;
  /** True when `$.amount.amountMinor` itself is one of the problems. */
  amountUnrepresentable: boolean;
  /**
   * The amount's own problem description (clamped), whenever
   * amountUnrepresentable is true — carried separately so the cap on
   * `problems` can never truncate away the one problem the operator-facing
   * INVALID_AMOUNT reason needs.
   */
  amountProblem?: string;
  /** True when at least one problem was an inspection-bound breach. */
  oversize: boolean;
  /** True when at least one problem was a genuinely unrecordable value. */
  unrepresentable: boolean;
}

const AMOUNT_PATH = "$.amount.amountMinor";

interface WalkState {
  problems: IntentShapeProblem[];
  totalProblems: number;
  nodes: number;
  amountProblem: string | undefined;
  oversize: boolean;
  unrepresentable: boolean;
  /** Build the sanitized copy? False on the first (detect-only) pass. */
  build: boolean;
}

function freshState(build: boolean): WalkState {
  return {
    problems: [],
    totalProblems: 0,
    nodes: 0,
    amountProblem: undefined,
    oversize: false,
    unrepresentable: false,
    build,
  };
}

export function inspectIntentShape(intent: unknown): IntentShapeReport {
  // PASS 1 — detect only. No copy is allocated: the common case is a clean
  // intent, and it must not pay for a throwaway deep clone.
  const detect = freshState(false);
  walk(intent, 0, "$", new Set<object>(), detect);
  if (detect.totalProblems === 0) {
    return {
      problems: [],
      totalProblems: 0,
      amountUnrepresentable: false,
      oversize: false,
      unrepresentable: false,
    };
  }

  // PASS 2 — same walk, now building the sanitized copy. Only malformed
  // intents (rare, and about to be denied) pay for this.
  const build = freshState(true);
  const sanitized = walk(intent, 0, "$", new Set<object>(), build);
  return {
    problems: build.problems,
    totalProblems: build.totalProblems,
    sanitized,
    amountUnrepresentable: build.amountProblem !== undefined,
    oversize: build.oversize,
    unrepresentable: build.unrepresentable,
    ...(build.amountProblem !== undefined
      ? { amountProblem: build.amountProblem }
      : {}),
  };
}

function clamp(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/** Extend a path by one segment, clamped so hostile keys cannot inflate it. */
function childPath(parent: string, segment: string): string {
  if (parent.length > MAX_PATH_CHARS) return parent; // already clamped
  return clamp(parent + segment, MAX_PATH_CHARS);
}

/**
 * Record a problem (bounded) and return the marker that stands in for the
 * offending value in the sanitized copy. The marker carries only the SHORT
 * problem text — details beyond the retained window live in the count.
 */
function flag(
  state: WalkState,
  path: string,
  problem: string,
  kind: IntentShapeProblem["kind"] = "unrepresentable",
): string {
  const clamped = clamp(problem, MAX_PROBLEM_CHARS);
  state.totalProblems += 1;
  if (kind === "oversize") state.oversize = true;
  else state.unrepresentable = true;
  if (state.problems.length < MAX_REPORTED_PROBLEMS) {
    state.problems.push({
      path: clamp(path, MAX_PATH_CHARS),
      problem: clamped,
      kind,
    });
  }
  if (path === AMOUNT_PATH && state.amountProblem === undefined) {
    state.amountProblem = clamped;
  }
  // The IN-COPY marker is clamped separately from the problems list: it can
  // repeat up to MAX_WALK_NODES times, so its length multiplies into the
  // ledger-row ceiling. 100 chars keeps every self-generated container
  // truncation message intact ("array of N entries exceeds the K-entry cap;
  // M not inspected" — the only place the true scale of an over-cap container
  // is recorded) while still bounding the ceiling.
  return `<unrepresentable: ${clamp(problem, 100)}>`;
}

function walk(
  v: unknown,
  depth: number,
  path: string,
  ancestors: Set<object>,
  state: WalkState,
): unknown {
  state.nodes += 1;
  if (state.nodes > MAX_WALK_NODES) {
    // Budget breach is ONE problem per breach site, and the walk stops
    // descending: output stays bounded no matter what the input does.
    return flag(
      state,
      path,
      `intent exceeds the ${MAX_WALK_NODES}-node inspection budget; not inspected further`,
      "oversize",
    );
  }
  if (depth > MAX_DEPTH) {
    return flag(state, path, `nesting exceeds max depth ${MAX_DEPTH}`, "oversize");
  }
  if (v === null) return null;

  const t = typeof v;
  if (t === "string" || t === "boolean") return v;

  if (t === "number") {
    if (!Number.isFinite(v as number)) {
      // The headline case. `null` is what JSON would render it as, and null
      // means something else entirely, so it cannot be recorded as itself.
      return flag(state, path, `${String(v)} is not a finite number`);
    }
    return v;
  }
  if (t === "bigint") {
    return flag(state, path, "bigint (no unambiguous JSON encoding)");
  }
  if (t === "undefined") {
    return flag(state, path, "undefined (would collide with null)");
  }
  if (t === "function" || t === "symbol") {
    return flag(state, path, `${t} cannot be recorded`);
  }

  const obj = v as object;
  if (ancestors.has(obj)) {
    // structuredClone preserves cycles, so a cyclic intent reaches this file
    // intact and would otherwise recurse to the depth cap.
    return flag(state, path, "circular reference");
  }
  // Add/remove around the subtree: same ancestor-chain semantics as copying
  // the set per node (a DAG node shared between SIBLINGS is legal; only a
  // node that is its own ancestor is a cycle) without O(depth) allocation at
  // every object.
  ancestors.add(obj);
  try {
    if (Array.isArray(v)) {
      const capped = v.length > MAX_CONTAINER_ENTRIES;
      const bound = capped ? MAX_CONTAINER_ENTRIES : v.length;
      const out: unknown[] | null = state.build ? [] : null;
      let i = 0;
      // The budget break lives in THIS loop, before each child: letting the
      // children discover the breach one call at a time would still walk (and
      // mark) every remaining position — unbounded CPU and output for nested
      // containers.
      for (; i < bound && state.nodes < MAX_WALK_NODES; i += 1) {
        // The child walk MUST be evaluated on its own line: `out?.push(walk(…))`
        // short-circuits the WHOLE expression when out is null (detect pass),
        // silently skipping inspection of every array element — which is how a
        // two-element bad array once slipped detection entirely and regressed
        // the refusal to a zero-row AUDIT_WRITE_FAILED.
        const child = walk(v[i], depth + 1, childPath(path, `[${i}]`), ancestors, state);
        if (out) out.push(child);
      }
      const skipped = v.length - i;
      if (skipped > 0) {
        const marker = flag(
          state,
          path,
          capped
            ? `array of ${v.length} entries exceeds the ${MAX_CONTAINER_ENTRIES}-entry cap; ${skipped} not inspected`
            : `array truncated by the ${MAX_WALK_NODES}-node inspection budget; ${skipped} entries not inspected`,
          "oversize",
        );
        out?.push(marker);
      }
      return out;
    }

    const proto = Object.getPrototypeOf(obj);
    if (proto !== Object.prototype && proto !== null) {
      const name =
        (obj as { constructor?: { name?: string } }).constructor?.name ?? "object";
      return flag(state, path, `${clamp(name, 40)} is not a plain object`);
    }

    const keys = Object.keys(obj as Record<string, unknown>);
    const capped = keys.length > MAX_CONTAINER_ENTRIES;
    const bound = capped ? MAX_CONTAINER_ENTRIES : keys.length;
    const out: Record<string, unknown> | null = state.build ? {} : null;
    let i = 0;
    for (; i < bound && state.nodes < MAX_WALK_NODES; i += 1) {
      const k = keys[i]!;
      const val = (obj as Record<string, unknown>)[k];
      // canonicalJson's one deliberate omission: an own property whose value is
      // undefined is "absent", not a problem. Match it exactly.
      if (val === undefined) continue;
      const child = walk(val, depth + 1, childPath(path, `.${k}`), ancestors, state);
      // defineProperty, not assignment: an own "__proto__" key must land as an
      // ordinary key (canonicalJson hashes it as one) instead of mutating a
      // prototype and silently disappearing from the recorded copy.
      if (out) {
        Object.defineProperty(out, k, {
          value: child,
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
    }
    const skipped = keys.length - i;
    if (skipped > 0) {
      const marker = flag(
        state,
        path,
        capped
          ? `object of ${keys.length} keys exceeds the ${MAX_CONTAINER_ENTRIES}-entry cap; ${skipped} not inspected`
          : `object truncated by the ${MAX_WALK_NODES}-node inspection budget; ${skipped} keys not inspected`,
        "oversize",
      );
      if (out) {
        Object.defineProperty(out, "<truncated>", {
          value: marker,
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
    }
    return out;
  } finally {
    ancestors.delete(obj);
  }
}
