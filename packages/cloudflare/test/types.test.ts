/**
 * Compile-time contract tests, enforced by `tsc -p tsconfig.test.json` in the
 * package's test script (vitest strips types; tsc is what fails the build).
 *
 * The point of importing the REAL upstream types instead of restating them:
 * if `@x402/evm` changes the `ClientEvmSigner` shape, or the Cloudflare
 * Agents SDK changes what `withX402Client` accepts, this file stops
 * compiling — a loud upstream-drift alarm instead of a silent runtime
 * mismatch.
 */
import { describe, expect, it } from "vitest";
import type { ClientEvmSigner } from "@x402/evm";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { guardedSigner, type GuardedSigner, type WrappableAccount } from "../src/index.js";
import { NETWORK, USDC, rig } from "./rig.js";

// --- compile-time assertions (never executed) ------------------------------

type WithX402Options = Parameters<typeof import("agents/x402").withX402Client>[1];

// Never executed — the assignments below are the assertions, checked by tsc.
function _compileTimeContracts(
  guarded: GuardedSigner,
  local: ReturnType<typeof privateKeyToAccount>,
): void {
  // A GuardedSigner IS a ClientEvmSigner, structurally, against the real
  // exported type from @x402/evm.
  const asClientSigner: ClientEvmSigner = guarded;
  void asClientSigner;
  // ...and it satisfies what the Cloudflare Agents SDK's withX402Client
  // accepts as `account` — the real option type, via a type-only import so no
  // Workers runtime code is loaded here.
  const asAgentsAccount: WithX402Options["account"] = guarded;
  void asAgentsAccount;
  // A plain viem LocalAccount is wrappable without adapters: the host's
  // privateKeyToAccount output goes straight in.
  const asWrappable: WrappableAccount = local;
  void asWrappable;
}
void _compileTimeContracts;

// --- runtime smoke of the same claims --------------------------------------

describe("type contract", () => {
  it("accepts a real privateKeyToAccount output and returns an object the x402 signer surface accepts", () => {
    const { guard } = rig();
    const account = privateKeyToAccount(generatePrivateKey());
    const signer: ClientEvmSigner = guardedSigner({
      account,
      guard,
      assets: [{ network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 }],
    });
    expect(signer.address).toBe(account.address);
    expect(typeof signer.signTypedData).toBe("function");
  });
});
