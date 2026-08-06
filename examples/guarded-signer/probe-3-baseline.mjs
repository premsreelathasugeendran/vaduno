/**
 * PROBE 3 — isolate the NEW cost from the pre-existing cost.
 *
 * Before the fix the first thing that touched a malformed intent was
 * canonicalJson (inside ledger.append), which THROWS on the first offending
 * value. After the fix, inspectIntentShape walks the whole thing first.
 */
import { canonicalJson } from "../../packages/guard/dist/ledger/hash.js";
import { inspectIntentShape } from "../../packages/guard/dist/policy/intent-shape.js";

const base = (metadata) => ({
  id: "i-1", agentId: "probe",
  merchant: { id: "seller" },
  amount: { amountMinor: 1000, currency: "USDC" },
  rail: "x402", metadata,
  requestedAt: new Date().toISOString(),
});

const time = (fn) => {
  const t0 = performance.now();
  let note = "ok";
  try { fn(); } catch (e) { note = `threw ${e?.name}`; }
  return { ms: performance.now() - t0, note };
};

console.log("=== 3a. MALFORMED intent: old first-touch (canonicalJson) vs new (inspect) ===");
for (const n of [1_000, 100_000, 1_000_000]) {
  const intent = base({ blob: new Array(n).fill(1n) });
  const oldPath = time(() => canonicalJson({ intent }));
  const newPath = time(() => {
    const r = inspectIntentShape(intent);
    // what guard.ts then does with it:
    return r.problems.map((p) => `${p.path} (${p.problem})`).join("; ");
  });
  const rep = inspectIntentShape(intent);
  const msgBytes = rep.problems.map((p) => `${p.path} (${p.problem})`).join("; ").length;
  console.log(
    `  n=${String(n).padStart(9)}  OLD canonicalJson: ${oldPath.ms.toFixed(1)} ms (${oldPath.note})` +
      `   NEW inspect+join: ${newPath.ms.toFixed(1)} ms  -> ${rep.problems.length} problems, ` +
      `one reason message of ${(msgBytes / 1e6).toFixed(2)} MB`,
  );
}

console.log("\n=== 3b. WELL-FORMED intent: the sanitized deep copy is built and thrown away ===");
for (const depth of [16, 20, 22]) {
  let x = { leaf: 1 };
  for (let i = 0; i < depth; i += 1) x = { a: x, b: x };
  const intent = base({ dag: x });
  const oldPath = time(() => canonicalJson({ intent }));
  const newPath = time(() => inspectIntentShape(intent));
  console.log(
    `  2^${depth} paths (${depth + 1} distinct objects):  OLD canonicalJson alone ${oldPath.ms.toFixed(0)} ms` +
      `   NEW inspect adds ${newPath.ms.toFixed(0)} ms  (total ${(oldPath.ms + newPath.ms).toFixed(0)} ms)`,
  );
}

console.log("\n=== 3c. peak allocation: does `sanitized` get built even with zero problems? ===");
{
  // HARNESS CORRECTION. This block used to call its fixture a "clean intent"
  // while printing `problems=8` in the same sentence — the shared-node DAG
  // below breaches the walk's node bound, so it is a MALFORMED intent by
  // construction and the copy it pays for is the copy the fix intends it to
  // pay for. Read literally, the old line said the laziness fix had not landed.
  // So measure both cases and let each speak for itself.
  const clean = base({ note: "nothing wrong here" });
  const cleanRep = inspectIntentShape(clean);
  console.log(
    `  genuinely clean intent: problems=${cleanRep.totalProblems}, ` +
      `sanitized=${cleanRep.sanitized === undefined ? "undefined (no copy allocated)" : "MATERIALIZED"}`,
  );

  let x = { leaf: 1 };
  for (let i = 0; i < 18; i += 1) x = { a: x, b: x };
  const intent = base({ dag: x });
  const rep = inspectIntentShape(intent);
  const before = process.memoryUsage().heapUsed;
  const held = inspectIntentShape(intent).sanitized;
  const after = process.memoryUsage().heapUsed;
  console.log(
    `  bound-breaching intent: problems=${rep.totalProblems} -> sanitized is a materialized deep copy: ` +
      `+${((after - before) / 1e6).toFixed(0)} MB retained, typeof=${typeof held} ` +
      `(this one is about to be DENIED, which is who the second pass is for)`,
  );
}

console.log("\n=== 3d. how big can ONE reason message get from a small hostile intent? ===");
{
  // Keys are attacker-controlled and land in the path of every problem.
  const k = "K".repeat(200);
  const md = {};
  md[k] = new Array(5_000).fill(undefined).map(() => undefined);
  const intent = base({ nested: { [k]: new Array(5_000).fill(1n) } });
  const rep = inspectIntentShape(intent);
  const msg = rep.problems.map((p) => `${p.path} (${p.problem})`).join("; ");
  const src = JSON.stringify({ n: 5000, keyLen: 200 }).length + 5000 * 3 + 200;
  console.log(
    `  hostile intent ~${src} B of payload -> reason message ${(msg.length / 1e6).toFixed(2)} MB ` +
      `(${(msg.length / src).toFixed(0)}x), sanitized copy also written to the ledger`,
  );
}
