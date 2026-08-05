/**
 * Mint a THROWAWAY Base Sepolia key and print only its address.
 *
 * The key is written to .wallet (gitignored) and never printed. It exists to
 * hold faucet tokens on one testnet and nothing else: do not reuse it, do not
 * send it anything of value, and delete it when you are done.
 *
 * Vaduno never sees this key. It belongs to the HOST app's signer, which is the
 * whole architectural point — the guard decides whether a payment may happen and
 * records that it did; your signer is what actually authorizes the transfer.
 */
import { writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const here = dirname(fileURLToPath(import.meta.url));
const walletPath = join(here, ".wallet");

if (existsSync(walletPath)) {
  const { privateKeyToAccount: p } = await import("viem/accounts");
  const existing = (await import("node:fs")).readFileSync(walletPath, "utf8").trim();
  console.log("Wallet already exists.");
  console.log("ADDRESS:", p(existing).address);
  console.log("\nFund it with Base Sepolia USDC at https://faucet.circle.com");
  process.exit(0);
}

const key = generatePrivateKey();
const account = privateKeyToAccount(key);
writeFileSync(walletPath, key, { mode: 0o600 });

console.log("Throwaway testnet wallet created (.wallet, gitignored).");
console.log();
console.log("ADDRESS:", account.address);
console.log();
console.log("Fund it at https://faucet.circle.com — pick Base Sepolia, paste the");
console.log("address, solve the captcha. 20 USDC per address; a payment costs $0.01.");
