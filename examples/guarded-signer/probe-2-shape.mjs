/**
 * PROBE 2 — the NEW `inspectIntentShape` path in the shipped guard.
 *
 * The fix turned "malformed intent -> AUDIT_WRITE_FAILED, zero ledger rows"
 * into "malformed intent -> sanitized copy recorded + exhaustive problem list".
 * Exhaustive over attacker-controlled input is an amplifier. Measure it.
 */
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";

function rig() {
  const store = new MemoryLedgerStore();
  const ledger = new AuditLedger(store);
  const guard = new VadunoGuard({
    policy: {
      id: "probe", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000 },
      merchants: { allow: ["id:seller"] },
    },
    ledger,
    limiter: new MemorySpendLimiter(),
  });
  return { guard, ledger };
}

const base = (metadata) => ({
  id: `i-${Math.random().toString(16).slice(2)}`,
  agentId: "probe",
  merchant: { id: "seller" },
  amount: { amountMinor: 1000, currency: "USDC" },
  rail: "x402",
  metadata,
  requestedAt: new Date().toISOString(),
});

const ledgerBytes = async (ledger) =>
  (await ledger.all()).reduce((n, e) => n + JSON.stringify(e).length, 0);

console.log("=== 2a. AMPLIFICATION: N unrepresentable values in one intent ===");
console.log("    intent bytes -> ledger bytes written, and wall time\n");
for (const n of [10, 1_000, 20_000, 100_000]) {
  const { guard, ledger } = rig();
  const intent = base({ blob: new Array(n).fill(1n) }); // N bigints
  const intentBytes = n * 3; // ~"1n," worth of caller-side payload
  const t0 = performance.now();
  const r = await guard.authorize(intent);
  const ms = performance.now() - t0;
  const bytes = await ledgerBytes(ledger);
  const reasons = r.policyResult?.reasons ?? [];
  const longest = Math.max(0, ...reasons.map((x) => x.message.length));
  console.log(
    `  n=${String(n).padStart(7)}  status=${r.status}  ledger=${String(bytes).padStart(10)} B` +
      `  amplification=${(bytes / Math.max(intentBytes, 1)).toFixed(0)}x` +
      `  longestReason=${String(longest).padStart(9)} B  ${ms.toFixed(0)} ms`,
  );
}

console.log("\n=== 2b. what the SAME intent did BEFORE the fix (canonicalJson throws first) ===");
{
  const { canonicalJson } = await import("@vaduno/guard/dist/ledger/hash.js").catch(() => ({}));
  console.log(
    "    (canonicalJson threw on the FIRST offending value: O(1) work, 0 ledger rows.",
  );
  console.log(
    "     the new path walks every value and concatenates every problem into one message.)",
  );
}

console.log("\n=== 2c. DAG blow-up: a 40-node intent that expands to 2^20 walk steps ===");
{
  const { guard, ledger } = rig();
  let x = { leaf: 1 };
  for (let i = 0; i < 20; i += 1) x = { a: x, b: x }; // 41 distinct objects, 2^20 paths
  const intent = base({ dag: x });
  const t0 = performance.now();
  let status;
  try {
    const r = await guard.authorize(intent);
    status = r.status;
  } catch (err) {
    status = `THREW ${err?.name}`;
  }
  const ms = performance.now() - t0;
  console.log(
    `  41 objects, shared -> status=${status}, ${ms.toFixed(0)} ms, ledger=${await ledgerBytes(ledger)} B`,
  );
}

console.log("\n=== 2d. same DAG, one level deeper (2^22) ===");
{
  const { guard } = rig();
  let x = { leaf: 1 };
  for (let i = 0; i < 22; i += 1) x = { a: x, b: x };
  const t0 = performance.now();
  let status;
  try {
    status = (await guard.authorize(base({ dag: x }))).status;
  } catch (err) {
    status = `THREW ${err?.name}`;
  }
  console.log(`  43 objects, shared -> status=${status}, ${(performance.now() - t0).toFixed(0)} ms`);
}

console.log("\n=== 2e. does a DENIED/malformed intent leak spend budget or velocity? ===");
{
  const { guard, ledger } = rig();
  for (let i = 0; i < 5; i += 1) await guard.authorize(base({ bad: 1n }));
  const ok = await guard.authorize(base({}));
  console.log(`  after 5 malformed denials, a clean intent is: ${ok.status}`);
  console.log(`  ledger rows: ${(await ledger.all()).length}`);
}
