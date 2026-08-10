/**
 * The AGENT process — and the point of this example: it holds NO key.
 *
 * This file never reads a wallet, never generates a key, and never receives
 * one: the only thing it is constructed from is a child process handle and a
 * (public) address. Every payment authorization is produced by asking the
 * signer-host process, and the host answers only through the policy gate.
 * There is nothing in THIS process for injected code to steal or route
 * around: the strongest thing a full compromise here can do is ASK for
 * signatures, every one of which is policed and written to the host's
 * ledger, out of this process's reach.
 *
 * That is the configuration the README used to describe as future work:
 * "the raw key kept where only the wrapper reaches it — a separate process".
 * This demo IS that separate process arrangement, over plain stdio.
 *
 * Default run: offline. The host generates a throwaway key; nothing is
 * broadcast; every check below must pass or the process exits 1.
 *
 * `--live`: the host loads the examples/x402-live wallet (Base Sepolia
 * faucet USDC, worthless) and this process makes the same real x402 v2
 * purchase as examples/guarded-signer/pay.mjs — except that the payment
 * signature comes from the other process, through the policy gate, and this
 * process could not have produced it any other way.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync } from "node:fs";
import { createPublicClient, http, erc20Abi, parseEventLogs, recoverTypedDataAddress } from "viem";
import { baseSepolia } from "viem/chains";
import { connectRemoteSigner, GuardSignerRefusedError } from "@vaduno/cloudflare";

const here = dirname(fileURLToPath(import.meta.url));
const live = process.argv.includes("--live");

// ---- rails ----------------------------------------------------------------
const CHAIN_ID = 84532;
const NETWORK = "eip155:84532";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const MAX_UNITS = 100_000n; // 0.10 USDC hard abort, same as every live example
const TARGET = "https://x402.org/protected";

// ---- spawn the key-holder and speak newline-delimited JSON to it ----------
const child = spawn(process.execPath, [join(here, "host.mjs"), ...(live ? ["--live"] : [])], {
  stdio: ["pipe", "pipe", "inherit"],
});
const fromHost = createInterface({ input: child.stdout, crlfDelay: Infinity });

/** Every string that crosses the boundary, both directions — evidence. */
const wireLog = { out: [], in: [] };

const pending = [];
let helloResolve;
const hello = new Promise((resolve) => {
  helloResolve = resolve;
});
fromHost.on("line", (line) => {
  const parsed = JSON.parse(line);
  if (parsed.hello) {
    helloResolve(parsed.hello);
    return;
  }
  wireLog.in.push(line);
  const next = pending.shift();
  if (next) next(line);
});

/** The transport: one request line out, one response line back, in order. */
const send = (requestJson) =>
  new Promise((resolve, reject) => {
    if (child.exitCode !== null) {
      reject(new Error("signer host process has exited"));
      return;
    }
    pending.push(resolve);
    wireLog.out.push(requestJson);
    child.stdin.write(`${requestJson}\n`, (err) => {
      if (err) reject(err);
    });
  });

const hostInfo = await hello;
console.log(`signer host up (pid ${child.pid}), address ${hostInfo.address}, live=${hostInfo.live}`);

const signer = await connectRemoteSigner(send);
if (signer.address.toLowerCase() !== String(hostInfo.address).toLowerCase()) {
  console.error("FATAL: connectRemoteSigner and the hello disagree about the address");
  process.exit(1);
}

// ---- helpers ---------------------------------------------------------------
const eip3009Types = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};
const randomNonce = () =>
  `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;

function transferTypedData({ to, value, chainId = CHAIN_ID, asset = USDC }) {
  return {
    domain: { name: "USDC", version: "2", chainId, verifyingContract: asset },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: signer.address,
      to,
      value,
      validAfter: 0n,
      validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
      nonce: randomNonce(),
    },
  };
}

let failures = 0;
function check(ok, label) {
  console.log(`  ${ok ? "pass" : "FAIL"}  ${label}`);
  if (!ok) failures += 1;
}

async function mustRefuse(label, fn, expectedCode) {
  try {
    await fn();
  } catch (err) {
    const code = err instanceof GuardSignerRefusedError ? err.code : err.name;
    const ok = expectedCode === undefined || code === expectedCode;
    check(ok, `refused [${code}] — ${label}`);
    return;
  }
  check(false, `"${label}" was NOT refused — a signature exists`);
}

// ---- phase 1: this process cannot get an ungated signature -----------------
console.log("\n[1/3] the agent process cannot reach an ungated capability:");

await mustRefuse(
  "0.01 USDC to a NON-allowlisted recipient",
  () => signer.signTypedData(transferTypedData({ to: "0xdeAD00000000000000000000000000000000dEAd", value: 10_000n })),
  "MERCHANT_NOT_ALLOWED",
);
await mustRefuse(
  "0.06 USDC to the allowlisted seller (over the 0.05 per-txn cap)",
  () => signer.signTypedData(transferTypedData({ to: SELLER, value: 60_000n })),
);
await mustRefuse(
  "0.01 'USDC' on Base MAINNET (chain 8453 — unregistered asset)",
  () =>
    signer.signTypedData(
      transferTypedData({
        to: SELLER,
        value: 10_000n,
        chainId: 8453,
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      }),
    ),
);
// The host recognizes exactly one method. Probe for doors by hand.
for (const method of ["signTransaction", "signMessage", "sign", "exportKey"]) {
  const res = JSON.parse(await send(JSON.stringify({ v: 1, method })));
  check(
    res.ok === false && res.code === "HOST_METHOD_DISABLED",
    `host refuses method "${method}" [${res.code}]`,
  );
}
// Garbage must be refused without killing the host.
const garbage = JSON.parse(await send("this is not json"));
check(garbage.ok === false, `host survives unparseable input [${garbage.code}]`);

// The remote signer object itself: an address and one function. Nothing else.
const surface = Object.getOwnPropertyNames(signer).sort().join(",");
check(surface === "address,signTypedData", `agent-side surface is exactly {address, signTypedData}`);
check(Object.isFrozen(signer), "agent-side signer object is frozen");

// ---- phase 2: an allowed payment still works, from a keyless process -------
if (!live) {
  console.log("\n[2/3] an allowed payment signs (offline; throwaway key; nothing broadcast):");
  const typed = transferTypedData({ to: SELLER, value: 10_000n });
  const signature = await signer.signTypedData(typed);
  check(/^0x[0-9a-fA-F]+$/.test(signature), "signature returned across the boundary");
  const recovered = await recoverTypedDataAddress({ ...typed, signature });
  check(
    recovered.toLowerCase() === signer.address.toLowerCase(),
    "signature recovers to the HOST's key — a key this process has never seen",
  );
  const replay = await signer.signTypedData(typed);
  check(replay === signature, "byte-identical replay re-issues the same signature (counted once)");
} else {
  console.log("\n[2/3] live x402 v2 purchase — the signature comes from the other process:");
  const chain = createPublicClient({ chain: baseSepolia, transport: http() });
  const first = await fetch(TARGET);
  if (first.status !== 402) {
    console.error(`  expected 402, got ${first.status} — aborting`);
    process.exit(1);
  }
  const paymentRequired = JSON.parse(
    Buffer.from(first.headers.get("PAYMENT-REQUIRED") ?? "", "base64").toString("utf8"),
  );
  const req = (paymentRequired.accepts ?? []).find(
    (r) =>
      r?.scheme === "exact" &&
      r?.network === NETWORK &&
      r?.asset?.toLowerCase() === USDC.toLowerCase(),
  );
  if (!req || !/^\d+$/.test(req.amount) || BigInt(req.amount) > MAX_UNITS) {
    console.error("  no acceptable exact/eip155:84532/USDC requirement under 0.10 — aborting");
    process.exit(1);
  }
  console.log(`  requirement: ${req.amount} units to ${req.payTo} on ${req.network}`);
  const authorization = {
    from: signer.address,
    to: req.payTo,
    value: BigInt(req.amount),
    validAfter: 0n,
    validBefore: BigInt(Math.floor(Date.now() / 1000) + (req.maxTimeoutSeconds ?? 300)),
    nonce: randomNonce(),
  };
  const typedData = {
    domain: {
      name: req.extra?.name ?? "USDC",
      version: req.extra?.version ?? "2",
      chainId: CHAIN_ID,
      verifyingContract: req.asset,
    },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: authorization,
  };
  // THE ONLY WAY THIS PROCESS CAN SIGN. Policy, budget and ledger all run in
  // the other process, against bytes this one cannot alter after the fact.
  const signature = await signer.signTypedData(typedData);
  console.log("  host allowed; EIP-3009 authorization signed out-of-process");
  const payload = {
    x402Version: 2,
    resource: paymentRequired.resource,
    accepted: {
      scheme: req.scheme,
      network: req.network,
      amount: req.amount,
      payTo: req.payTo,
      asset: req.asset,
      maxTimeoutSeconds: req.maxTimeoutSeconds,
      extra: req.extra,
    },
    payload: {
      signature,
      authorization: {
        from: authorization.from,
        to: authorization.to,
        value: authorization.value.toString(),
        validAfter: authorization.validAfter.toString(),
        validBefore: authorization.validBefore.toString(),
        nonce: authorization.nonce,
      },
    },
  };
  const paid = await fetch(TARGET, {
    headers: {
      "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(payload), "utf8").toString("base64"),
    },
  });
  console.log("  HTTP", paid.status);
  const settlementHeader = paid.headers.get("PAYMENT-RESPONSE");
  if (settlementHeader) {
    const settlement = JSON.parse(Buffer.from(settlementHeader, "base64").toString("utf8"));
    console.log("  settlement:", JSON.stringify(settlement));
    writeFileSync(join(here, "last-settlement.json"), JSON.stringify(settlement, null, 2));
    if (typeof settlement?.transaction === "string") {
      console.log(`  waiting for settlement tx ${settlement.transaction} …`);
      const receipt = await chain.waitForTransactionReceipt({ hash: settlement.transaction });
      console.log(`  mined in block ${receipt.blockNumber}, status: ${receipt.status}`);
      const transfers = parseEventLogs({
        abi: erc20Abi,
        eventName: "Transfer",
        logs: receipt.logs,
      }).filter(
        (l) =>
          l.address.toLowerCase() === USDC.toLowerCase() &&
          l.args.from.toLowerCase() === signer.address.toLowerCase(),
      );
      for (const t of transfers) {
        console.log(
          `  moved ${(Number(t.args.value) / 1e6).toFixed(6)} USDC -> ${t.args.to} ` +
            "(decoded from the settlement transaction's own log)",
        );
      }
      check(transfers.length === 1, "exactly one USDC Transfer from the host's wallet, on-chain");
    }
  } else {
    console.log("  no settlement header returned");
  }
}

// ---- phase 3: the capability dies with the host ----------------------------
console.log("\n[3/3] kill the host; the agent's signing capability must die with it:");
child.stdin.end();
await new Promise((resolve) => child.on("exit", resolve));
try {
  await signer.signTypedData(transferTypedData({ to: SELLER, value: 10_000n }));
  check(false, "signing still works after the host exited");
} catch (err) {
  const code = err instanceof GuardSignerRefusedError ? err.code : err.name;
  check(true, `refused [${code}] — no host process, no signatures, anywhere`);
}

// ---- evidence about the boundary itself ------------------------------------
// Everything this process ever sent or received is a JSON line. Assert the
// obvious-but-load-bearing: no request ever carried anything but typed data,
// and no response ever carried anything but a signature/refusal envelope.
const wellFormed = wireLog.out.filter((l) => {
  let p;
  try {
    p = JSON.parse(l);
  } catch {
    return false; // the deliberate garbage probe above
  }
  return (
    p !== null &&
    typeof p === "object" &&
    p.v === 1 &&
    (p.method === "signTypedData" || p.method === "address") &&
    Object.keys(p).every((k) => ["v", "method", "typedData"].includes(k))
  );
});
check(
  wireLog.out.length - wellFormed.length <= 5, // the deliberate probes above
  `wire traffic: ${wireLog.out.length} requests out; every non-probe request is wire-shaped`,
);
console.log(
  `\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`} — ` +
    "the agent process held no key at any point; the host's ledger holds the evidence.",
);
process.exit(failures === 0 ? 0 : 1);
