/**
 * ATTACK C — the accounting and the audit trail.
 *
 * 1. concurrency: fire many signs in parallel; can they jointly exceed the cap?
 * 2. denial residue: does a denied attempt leave a phantom reservation?
 * 3. thrown-after-authorize: is the spend released, held, or lost?
 * 4. audit coverage: which refusals reach the tamper-evident ledger at all?
 * 5. intent id: does it actually vary per authorization?
 * 6. replay: is the id a function of ALL the signed bytes, or only some?
 */
import { hashTypedData } from "viem";
import {
  rig, typedData, SELLER, USDC, CHAIN_ID, eip3009Types, randomNonce, tag,
} from "./attack-harness.mjs";

const line = (s) => console.log(`\n===== ${s} =====`);

// ---------------------------------------------------------------- 1. parallel
line("1. CONCURRENCY: 12 parallel signs of 50000 against a 200000/day cap");
{
  const { guarded, realAccount, ledger } = rig();
  const jobs = Array.from({ length: 12 }, () =>
    guarded.signTypedData(typedData({ from: realAccount.address, value: 50_000n })),
  );
  const out = await Promise.allSettled(jobs);
  const signed = out.filter((r) => r.status === "fulfilled");
  const uniqueSigs = new Set(signed.map((r) => r.value));
  console.log("  signatures produced :", signed.length, "(unique:", uniqueSigs.size + ")");
  console.log("  refused             :", out.filter((r) => r.status === "rejected").length);
  console.log("  reasons             :", [...new Set(out.filter((r) => r.status === "rejected").map((r) => tag(r.reason)))].join(", "));
  console.log("  total signed value  :", signed.length * 50_000, "vs cap 200000");
  console.log("  VERDICT:", signed.length <= 4 ? "cap HELD under parallelism" : "*** CAP RACED ***");
  const ents = await ledger.all();
  console.log("  ledger verify       :", JSON.stringify(await ledger.verify()));
  console.log("  execution_result rows:", ents.filter((e) => e.type === "execution_result").length);
}

// ------------------------------------------------------- 2. denial residue
line("2. DENIAL RESIDUE: does a denied sign hold budget (phantom charge)?");
{
  const { guarded, realAccount } = rig();
  // 3 denials: over-cap, bad merchant, unknown asset.
  const denials = [
    typedData({ from: realAccount.address, value: 60_000n }),
    typedData({ from: realAccount.address, to: "0x000000000000000000000000000000000000dEaD" }),
    typedData({ from: realAccount.address, chainId: 8453, asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" }),
  ];
  for (const d of denials) {
    try { await guarded.signTypedData(d); console.log("  UNEXPECTED signature"); }
    catch (e) { console.log("  denied:", tag(e)); }
  }
  // Now spend the FULL daily budget. If denials left phantom holds, this fails.
  let ok = 0;
  for (let i = 0; i < 4; i++) {
    try { await guarded.signTypedData(typedData({ from: realAccount.address, value: 50_000n })); ok++; }
    catch (e) { console.log("  post-denial sign failed:", tag(e)); }
  }
  console.log("  full budget still available after 3 denials:", ok === 4, `(${ok * 50_000}/200000)`);
  console.log("  VERDICT:", ok === 4 ? "no phantom charge" : "*** DENIALS BURNED BUDGET ***");
}

// -------------------------------------------- 3. throw after authorize
line("3. THROW AFTER AUTHORIZE: local signer fails — is the spend released?");
{
  const { guard, realAccount, ledger } = rig();
  const { createGuardedAccount } = await import("./guarded-account.mjs");
  let fail = true;
  const flaky = {
    address: realAccount.address,
    async signTypedData(t) {
      if (fail) throw new Error("HSM unavailable");
      return realAccount.signTypedData(t);
    },
  };
  const g = createGuardedAccount({
    account: flaky, guard, agentId: "attack-rig",
    assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
  });
  for (let i = 0; i < 3; i++) {
    try { await g.signTypedData(typedData({ from: realAccount.address, value: 50_000n })); }
    catch (e) { console.log("  sign threw:", e.message); }
  }
  fail = false;
  let ok = 0;
  for (let i = 0; i < 4; i++) {
    try { await g.signTypedData(typedData({ from: realAccount.address, value: 50_000n })); ok++; }
    catch (e) { console.log("  later sign refused:", tag(e)); }
  }
  console.log("  successful signs after 3 provable local failures:", ok, "/4");
  console.log("  VERDICT:", ok === 4 ? "budget correctly reclaimed (no phantom)" : "*** FAILED SIGNS BURNED BUDGET ***");
  const ents = await ledger.all();
  const fails = ents.filter((e) => e.type === "execution_result" && e.data?.success === false);
  const succ = ents.filter((e) => e.type === "execution_result" && e.data?.success === true);
  console.log("  ledger: failure rows =", fails.length, " success rows =", succ.length);
}

// ------------------------------------------------------- 4. audit coverage
line("4. AUDIT COVERAGE: which refusals land in the tamper-evident ledger?");
{
  const { guarded, ledger, realAccount } = rig();
  const probes = [
    ["over per-txn cap", () => guarded.signTypedData(typedData({ from: realAccount.address, value: 60_000n }))],
    ["non-allowlisted payee", () => guarded.signTypedData(typedData({ from: realAccount.address, to: "0x000000000000000000000000000000000000dEaD" }))],
    ["Base MAINNET USDC", () => guarded.signTypedData(typedData({ from: realAccount.address, chainId: 8453, asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" }))],
    ["EIP-2612 unlimited Permit", () => guarded.signTypedData({
        domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
        types: { Permit: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] },
        primaryType: "Permit",
        message: { owner: realAccount.address, spender: SELLER, value: 2n ** 256n - 1n, nonce: 0n, deadline: 2n ** 48n },
      })],
    ["malformed EIP-3009 (bad nonce)", () => guarded.signTypedData(typedData({ from: realAccount.address, nonce: "0x00" }))],
    ["signTransaction()", () => guarded.signTransaction({ to: SELLER, value: 0n, chainId: CHAIN_ID })],
    ["signMessage()", () => guarded.signMessage({ message: "drain me" })],
  ];
  for (const [label, fn] of probes) {
    const before = (await ledger.all()).length;
    let code = "NO REFUSAL (!!)";
    try { await fn(); } catch (e) { code = tag(e); }
    const after = (await ledger.all()).length;
    console.log(
      `  ${after - before > 0 ? "AUDITED  " : "INVISIBLE"}  ${String(label).padEnd(32)} [${code}]  +${after - before} rows`,
    );
  }
}

// ------------------------------------------------------- 5. id variation
line("5. INTENT ID: does it vary per authorization?");
{
  const { realAccount } = rig();
  const { createHash } = await import("node:crypto");
  const ids = new Set();
  for (let i = 0; i < 500; i++) {
    const t = typedData({ from: realAccount.address });
    ids.add(createHash("sha256").update([
      "eip3009", "TransferWithAuthorization", String(CHAIN_ID), USDC.toLowerCase(),
      realAccount.address.toLowerCase(), SELLER.toLowerCase(), "10000", "0",
      String(t.message.validBefore), t.message.nonce,
    ].join("|")).digest("hex"));
  }
  console.log("  distinct ids over 500 authorizations:", ids.size, ids.size === 500 ? "(varies correctly)" : "*** COLLISION ***");
}

// -------------------------------------------- 6. id covers only part of bytes
line("6. REPLAY SCOPE: is the intent id a function of ALL the signed bytes?");
{
  const { guarded, ledger, realAccount } = rig();
  const nonce = randomNonce();
  const validBefore = BigInt(Math.floor(Date.now() / 1000) + 300);
  const base = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore, nonce },
  };
  const sig1 = await guarded.signTypedData(base);
  const rowsAfterFirst = (await ledger.all()).length;

  // Same policed fields, DIFFERENT EIP-712 domain => different signed digest,
  // identical intent id => the guard reports "replayed / already executed" and
  // the wrapper re-signs without any policy evaluation.
  const variant = { ...base, domain: { ...base.domain, name: "Evil Token", version: "9" } };
  let sig2, err;
  try { sig2 = await guarded.signTypedData(variant); } catch (e) { err = e; }
  const rowsAfterSecond = (await ledger.all()).length;

  console.log("  digest #1 (approved) :", hashTypedData(base));
  console.log("  digest #2 (variant)  :", hashTypedData(variant));
  console.log("  digests differ       :", hashTypedData(base) !== hashTypedData(variant));
  if (err) {
    console.log("  variant refused:", tag(err));
  } else {
    console.log("  signature #1         :", sig1.slice(0, 24) + "...");
    console.log("  signature #2         :", sig2.slice(0, 24) + "...");
    console.log("  DIFFERENT signature returned for unvetted bytes:", sig1 !== sig2);
  }
  console.log("  new ledger rows for the second call:", rowsAfterSecond - rowsAfterFirst);
}
