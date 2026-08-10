/**
 * The KEY-HOLDING process. Run by demo.mjs as a separate OS process — never
 * import this into an agent.
 *
 * What lives here: the raw account, the guard (policy + spend limiter +
 * hash-chained audit ledger), and a `createSignerHost` whose ONLY capability
 * is the policy-gated `signTypedData`. What leaves here: one line of JSON per
 * request — a signature or a refusal. The key has no other door, because this
 * process does not offer one.
 *
 * Protocol: newline-delimited JSON over stdio. The first line out is
 * `{"hello":{"address":…}}`; every subsequent line in is a wire request for
 * the signer host, answered with exactly one line out. JSON.stringify never
 * emits a newline, so the framing cannot be confused by content.
 *
 * Modes:
 *   (default)  a fresh throwaway key — offline, broadcasts nothing
 *   --live     the examples/x402-live wallet (Base Sepolia faucet USDC only)
 */
import { createInterface } from "node:readline";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  AuditLedger,
  JsonlLedgerStore,
  MemoryLedgerStore,
  MemorySpendLimiter,
  VadunoGuard,
} from "@vaduno/guard";
import { createSignerHost } from "@vaduno/cloudflare";

const here = dirname(fileURLToPath(import.meta.url));
const live = process.argv.includes("--live");

// ---- rails (identical to the sibling live examples) ------------------------
const NETWORK = "eip155:84532"; // Base Sepolia ONLY. Never mainnet.
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // Base Sepolia USDC
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"; // x402.org payTo

let privateKey;
if (live) {
  const walletPath = join(here, "..", "x402-live", ".wallet");
  if (!existsSync(walletPath)) {
    process.stderr.write("host: no wallet — run `npm -w x402-live run keygen` first\n");
    process.exit(1);
  }
  privateKey = readFileSync(walletPath, "utf8").trim();
} else {
  privateKey = generatePrivateKey(); // throwaway; never funded, never broadcast
}
const account = privateKeyToAccount(privateKey);

const ledger = new AuditLedger(
  live ? new JsonlLedgerStore(join(here, "ledger.jsonl")) : new MemoryLedgerStore(),
);
const guard = new VadunoGuard({
  policy: {
    id: "keyless-agent-host",
    version: 1,
    currency: "USDC", // minor units below are USDC atomic units
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 }, // 0.05 / 0.20
    merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    networks: { allow: [NETWORK] },
  },
  ledger,
  limiter: new MemorySpendLimiter(),
});

const host = createSignerHost({
  account,
  guard,
  agentId: "keyless-agent",
  assets: [{ network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 }],
  currencyDecimals: 6,
});

process.stdout.write(`${JSON.stringify({ hello: { address: host.address, live } })}\n`);

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
let chain = Promise.resolve();
lines.on("line", (line) => {
  // Serialize responses so replies leave in request order — the demo's
  // transport matches them positionally.
  chain = chain.then(async () => {
    const response = await host.handle(line);
    process.stdout.write(`${response}\n`);
  });
});
lines.on("close", () => {
  void chain.then(() => process.exit(0));
});
