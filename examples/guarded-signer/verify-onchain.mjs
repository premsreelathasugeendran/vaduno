/**
 * INDEPENDENT on-chain verification for the guarded-signer experiments.
 * Reads the chain directly with viem — trusts nothing the seller returned.
 *
 * Usage:
 *   node verify-onchain.mjs balance            -> print payer USDC balance (atomic units)
 *   node verify-onchain.mjs receipt <txHash> <expectedBeforeAtomic>
 *      -> fetch the receipt, decode the USDC Transfer log, compare balances
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, http, erc20Abi, parseEventLogs } from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

const here = dirname(fileURLToPath(import.meta.url));
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // Base Sepolia USDC
const payer = privateKeyToAccount(
  readFileSync(join(here, "..", "x402-live", ".wallet"), "utf8").trim(),
).address;

const chain = createPublicClient({ chain: baseSepolia, transport: http() });

const balance = () =>
  chain.readContract({ address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [payer] });

const [mode, txHash, expectedBefore] = process.argv.slice(2);

if (mode === "balance") {
  console.log(String(await balance()));
  process.exit(0);
}

if (mode === "receipt") {
  const receipt = await chain.getTransactionReceipt({ hash: txHash });
  console.log("tx:          ", receipt.transactionHash);
  console.log("status:      ", receipt.status);
  console.log("block:       ", receipt.blockNumber.toString());
  console.log("chainId:     ", chain.chain.id, `(${chain.chain.name})`);

  const transfers = parseEventLogs({ abi: erc20Abi, eventName: "Transfer", logs: receipt.logs })
    .filter((l) => l.address.toLowerCase() === USDC.toLowerCase());
  for (const t of transfers) {
    console.log(
      `Transfer log: ${t.args.from} -> ${t.args.to} value=${t.args.value} (contract ${t.address})`,
    );
  }
  const mine = transfers.find((t) => t.args.from.toLowerCase() === payer.toLowerCase());
  if (!mine) {
    console.error("FAIL: no USDC Transfer from the payer in this receipt");
    process.exit(1);
  }

  const after = await balance();
  console.log("payer:        ", payer);
  console.log("balance after:", String(after), "atomic units");
  if (expectedBefore !== undefined) {
    const before = BigInt(expectedBefore);
    const spent = before - after;
    console.log("balance before (independently read pre-run):", String(before));
    console.log("delta:", String(spent), "atomic units =", (Number(spent) / 1e6).toFixed(6), "USDC");
    if (spent !== mine.args.value) {
      console.error("FAIL: balance delta does not equal the Transfer log value");
      process.exit(1);
    }
  }
  console.log(
    "VERIFIED: receipt status", receipt.status + ",",
    "USDC Transfer of", String(mine.args.value), "units from payer decoded from the log",
    expectedBefore !== undefined ? "and balance dropped by exactly that amount" : "",
  );
  process.exit(0);
}

console.error("usage: node verify-onchain.mjs balance | receipt <txHash> [expectedBeforeAtomic]");
process.exit(1);
