/**
 * ATTACK D — the replay/idempotency window.
 *
 * The wrapper's design counts an authorization ONCE and re-issues the same
 * signature on retry. Between `authorize()` returning and `settle(executed)`
 * committing, the reservation is "reserved", not "committed". What happens to
 * a concurrent retry that lands inside that window?
 */
import { rig, typedData, tag } from "./attack-harness.mjs";

const { guarded, realAccount, ledger } = rig();

console.log("=== ATTACK D: 5 PARALLEL signs of the IDENTICAL authorization ===\n");
const td = typedData({ from: realAccount.address, value: 50_000n });
const out = await Promise.allSettled(Array.from({ length: 5 }, () => guarded.signTypedData(td)));
const ok = out.filter((r) => r.status === "fulfilled");
console.log("  fulfilled:", ok.length, " rejected:", out.length - ok.length);
console.log("  distinct signatures:", new Set(ok.map((r) => r.value)).size);
console.log("  rejection codes:", [...new Set(out.filter((r) => r.status === "rejected").map((r) => tag(r.reason)))].join(", ") || "(none)");

console.log("\n=== sequential retry of the SAME authorization (the documented path) ===");
const s1 = await guarded.signTypedData(td);
const s2 = await guarded.signTypedData(td);
console.log("  same signature re-issued:", s1 === s2);

const ents = await ledger.all();
const succ = ents.filter((e) => e.type === "execution_result" && e.data?.success === true);
console.log("\n  countable success rows:", succ.length, "(spend counted:", succ.reduce((a, e) => a + (e.data.amountMinor ?? 0), 0) + ")");

console.log("\n=== remaining budget check: how much more can be signed? ===");
let more = 0;
for (let i = 0; i < 6; i++) {
  try { await guarded.signTypedData(typedData({ from: realAccount.address, value: 50_000n })); more++; }
  catch { break; }
}
console.log("  further 50000 signs accepted:", more, "=> total counted:", (more + 1) * 50_000, "/ cap 200000");
console.log("  VERDICT:", (more + 1) * 50_000 <= 200_000 ? "cap held" : "*** CAP EXCEEDED ***");
