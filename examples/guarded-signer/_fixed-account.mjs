/**
 * GuardedAccount — a viem-compatible account whose ONLY working capability is
 * policy-gated `signTypedData`.
 *
 * WHY THIS SHAPE: the shipped Cloudflare Agents SDK x402 client takes an
 * `account: ClientEvmSigner` — a STRUCTURAL type whose required surface is
 * exactly `{ address, signTypedData }` — and every payment authorization the
 * SDK can produce (EIP-3009, Permit2, v1 and v2) terminates in that one
 * method. Wrap it, and policy runs before ANY signature exists. Deny, and no
 * signature ever exists. That is the difference between a firewall and
 * telemetry: the optional `confirmationCallback` can be skipped; the signer
 * cannot, because the signer is where signatures come from.
 *
 * WHAT THE WRAPPER DOES on each signTypedData call:
 *   1. Extract the payment facts from the typed data itself — the payee
 *      (message.to), the amount (message.value), the asset
 *      (domain.verifyingContract) and the chain (domain.chainId). These are
 *      the EXACT values being signed, after any upstream selection logic, so
 *      there is no gap between what policy vets and what the key signs.
 *   2. Map them onto a Vaduno PaymentIntent and run guard.authorize() —
 *      policy + atomic spend limiter + hash-chained audit ledger.
 *   3. Only on "authorized": delegate to the real account, then settle the
 *      reserved spend as executed.
 *   4. On any other outcome: throw. No signature is produced.
 *
 * IDEMPOTENCY: the intent id is a hash of the authorization's own content
 * (chain, asset, from, to, value, validity window, nonce — the EIP-3009 nonce
 * is unique per authorization by design). A retry of the SAME authorization
 * maps to the same intent id, the guard reports it as a replay, and — if the
 * original was counted as executed — the wrapper re-issues the identical
 * signature WITHOUT counting new spend. Same content, same single-use nonce,
 * zero new spending power. A different authorization reusing a nonce hashes to
 * a different id and is evaluated (and counted) on its own.
 *
 * CAPABILITY HONESTY: every raw-key capability other than the gated
 * signTypedData — signTransaction, signMessage, sign, signAuthorization — is
 * replaced by a throwing stub. `signTransaction` in particular is the
 * @x402/evm gas-sponsoring extension path that signs an UNLIMITED
 * (maxUint256) ERC-20 approval; leaving it reachable would make the typed-data
 * gate decorative. The wrapped account lives ONLY in this module's closure:
 * the returned object holds no property that references it, and it is frozen.
 *
 * WHAT THIS CANNOT DO (read README.md, this is the honest part): nothing
 * forces a developer to wrap their account before handing it to
 * withX402Client, and code that can read the raw key from the same
 * environment can always sign outside any wrapper. The wrapper makes the
 * guard mandatory FOR EVERY SIGNATURE THIS OBJECT CAN PRODUCE; making it
 * mandatory for the deployment means keeping the raw key where only the
 * wrapper reaches it (a separate process, Durable Object, or KMS).
 */
import { createHash } from "node:crypto";

export class GuardSignerRefusedError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string, intentId?: string, reasons?: Array<{code: string, message: string}> }} [details]
   */
  constructor(message, details = {}) {
    super(message);
    this.name = "GuardSignerRefusedError";
    this.code = details.code ?? "DENIED";
    if (details.intentId !== undefined) this.intentId = details.intentId;
    if (details.reasons !== undefined) this.reasons = details.reasons;
  }
}

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const BYTES32_RE = /^0x[0-9a-fA-F]{64}$/;

function normAddress(v) {
  return typeof v === "string" && ADDRESS_RE.test(v) ? v.toLowerCase() : null;
}

/** Accept bigint | integer number | decimal string; anything else -> null. */
function asBigInt(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
  return null;
}

function asChainId(v) {
  const b = asBigInt(v);
  if (b === null || b < 0n || b > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(b);
}

/**
 * Pull the payment facts out of a typed-data signing request, keyed on
 * primaryType. Returns null when the request is not a payment shape this
 * wrapper understands — and unknown shapes are REFUSED by the caller, never
 * signed on faith.
 *
 * Two shapes are understood:
 *  - EIP-3009 TransferWithAuthorization / ReceiveWithAuthorization (the
 *    default x402 `exact` EVM path): asset = domain.verifyingContract,
 *    payee = message.to, amount = message.value.
 *  - Permit2 PermitWitnessTransferFrom (@x402/evm's alternate path):
 *    asset = message.permitted.token, payee = message.witness.to,
 *    amount = message.permitted.amount — the MAXIMUM the signature permits,
 *    which is the correct pessimistic number to police.
 *
 * Deliberately NOT understood, therefore refused: EIP-2612 "Permit" and any
 * other approval shape. An approval is open-ended spending power, not a
 * bounded payment, and default-deny is the only honest treatment.
 */
function extractPayment(typed) {
  const primaryType = typed?.primaryType;
  const domain = typed?.domain ?? {};
  const message = typed?.message ?? {};

  if (primaryType === "TransferWithAuthorization" || primaryType === "ReceiveWithAuthorization") {
    const chainId = asChainId(domain.chainId);
    const asset = normAddress(domain.verifyingContract);
    const from = normAddress(message.from);
    const payee = normAddress(message.to);
    const nonce = typeof message.nonce === "string" && BYTES32_RE.test(message.nonce)
      ? message.nonce.toLowerCase()
      : null;
    if (chainId === null || asset === null || from === null || payee === null || nonce === null) {
      return null;
    }
    return {
      kind: "eip3009",
      primaryType,
      chainId,
      asset,
      payee,
      value: asBigInt(message.value), // null -> audited INVALID_AMOUNT deny
      idFields: [
        "eip3009",
        primaryType,
        String(chainId),
        asset,
        from,
        payee,
        String(asBigInt(message.value)),
        String(asBigInt(message.validAfter)),
        String(asBigInt(message.validBefore)),
        nonce,
      ],
    };
  }

  if (primaryType === "PermitWitnessTransferFrom") {
    const chainId = asChainId(domain.chainId);
    const asset = normAddress(message.permitted?.token);
    const payee = normAddress(message.witness?.to);
    const nonce = asBigInt(message.nonce);
    if (chainId === null || asset === null || payee === null || nonce === null) return null;
    return {
      kind: "permit2",
      primaryType,
      chainId,
      asset,
      payee,
      value: asBigInt(message.permitted?.amount),
      idFields: [
        "permit2",
        String(chainId),
        normAddress(domain.verifyingContract) ?? "?",
        asset,
        normAddress(message.spender) ?? "?",
        payee,
        String(asBigInt(message.permitted?.amount)),
        String(asBigInt(message.deadline)),
        String(nonce),
      ],
    };
  }

  return null;
}

/**
 * @param {object} opts
 * @param {{ address: `0x${string}`, signTypedData: (t: unknown) => Promise<`0x${string}`> }} opts.account
 *   The REAL viem account. Held in closure only — never exposed on the
 *   returned object.
 * @param {import("@vaduno/guard").VadunoGuard} opts.guard
 * @param {string} opts.agentId
 * @param {Array<{ chainId: number, address: string, symbol: string, decimals: number }>} opts.assets
 *   Trusted asset registry. The currency the guard polices comes from HERE,
 *   never from server-supplied data. A signing request whose
 *   (chainId, asset) pair is not registered is handed to the guard with the
 *   asset address as its currency, which the policy's base-currency check
 *   denies — an AUDITED refusal, so the attempt lands in the ledger.
 * @param {string} [opts.merchantUrl]
 *   Optional: the request URL this signer is being used against, for host
 *   allowlists. The typed data itself does NOT carry the resource URL — that
 *   is a real blind spot of signer-level policy, documented in the README.
 */
export function createGuardedAccount({ account, guard, agentId, assets, merchantUrl }) {
  if (!account || typeof account.signTypedData !== "function") {
    throw new Error("createGuardedAccount: `account` must expose signTypedData()");
  }
  const registry = new Map();
  for (const a of assets ?? []) {
    registry.set(`${a.chainId}:${a.address.toLowerCase()}`, a);
  }

  async function gatedSignTypedData(untrustedTypedData) {
    // THE FIX under test: pin the request to an inert snapshot BEFORE reading
    // it, and sign the SNAPSHOT — never the caller's live object. Mirrors
    // VadunoGuard.run()'s own `structuredClone(intent)`. structuredClone
    // flattens getters to values, strips Proxy behaviour, and preserves
    // bigint/string/number, so what policy reads and what the key hashes are
    // the same immutable bytes.
    let typedData;
    try {
      typedData = structuredClone(untrustedTypedData);
    } catch {
      throw new GuardSignerRefusedError(
        "typed data could not be safely snapshotted (default-deny)",
        { code: "TYPED_DATA_NOT_SERIALIZABLE" },
      );
    }
    const p = extractPayment(typedData);
    if (p === null) {
      // Structurally unmappable: no faithful intent can be built, so this is
      // refused locally (fail closed) rather than guessed at.
      throw new GuardSignerRefusedError(
        `refusing to sign primaryType ${JSON.stringify(typedData?.primaryType)}: ` +
          "not a recognized payment authorization shape (default-deny)",
        { code: "UNRECOGNIZED_TYPED_DATA" },
      );
    }

    const known = registry.get(`${p.chainId}:${p.asset}`);
    // Unknown asset -> currency that cannot match the policy's base currency
    // -> audited deny. Known asset -> the registry's trusted symbol.
    const currency = known ? known.symbol.toUpperCase() : `UNKNOWN:${p.asset}`;
    // Token atomic units ARE the currency's minor units when the registry
    // defines the currency at token granularity (USDC: 6 decimals, minor unit
    // = 1e-6 USDC = 1 atomic unit). Out-of-range or missing -> NaN, which the
    // policy engine denies as an invalid amount. No floats anywhere.
    const amountMinor =
      p.value !== null && p.value >= 0n && p.value <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(p.value)
        : NaN;

    const intentId = "sig:" + createHash("sha256").update(p.idFields.join("|")).digest("hex");
    const intent = {
      id: intentId,
      agentId,
      merchant: {
        id: p.payee,
        ...(merchantUrl !== undefined ? { url: merchantUrl } : {}),
      },
      amount: { amountMinor, currency },
      rail: "x402",
      description: `${p.primaryType} of ${String(p.value)} atomic units of ${currency} to ${p.payee}`,
      metadata: {
        primaryType: p.primaryType,
        chainId: p.chainId,
        asset: p.asset,
        ...(known ? { decimals: known.decimals } : {}),
      },
      requestedAt: new Date().toISOString(),
    };

    const result = await guard.authorize(intent);

    switch (result.status) {
      case "authorized": {
        let signature;
        try {
          signature = await account.signTypedData(typedData);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          // The local signer threw BEFORE producing a signature: provably no
          // authorization exists, so the outcome is recorded as failed and the
          // reserved budget is given back. (Contrast an on-rail failure, where
          // money may have moved and the reservation must keep counting.)
          await guard.settle(intentId, { status: "failed", error: msg });
          await guard.releaseSpend(intentId);
          throw err;
        }
        // The signature EXISTS from this instant — that is the economic event
        // the guard counts, because a signed EIP-3009 authorization is money
        // in motion the moment anyone submits it.
        await guard.settle(intentId, { status: "executed" });
        return signature;
      }
      case "replayed": {
        if (result.original.status === "executed") {
          // Same authorization content (the id is a hash of it), already
          // counted once. Re-issuing the identical signature grants no new
          // spending power — the nonce is single-use on-chain — so this
          // supports SDK retry loops without double-counting.
          return account.signTypedData(typedData);
        }
        throw new GuardSignerRefusedError(
          `refusing to re-sign: an earlier attempt for this same authorization is ${result.original.status}; ` +
            "reconcile before retrying",
          { code: "REPLAY_UNRESOLVED", intentId },
        );
      }
      case "denied":
      case "approval_rejected":
      case "failed": {
        const reasons = result.policyResult?.reasons ?? [];
        const codes = reasons.map((r) => r.code).join(", ") || result.status.toUpperCase();
        throw new GuardSignerRefusedError(
          `payment authorization refused by Vaduno guard [${codes}]` +
            (reasons.length ? `: ${reasons.map((r) => r.message).join("; ")}` : ""),
          { code: codes, intentId, reasons },
        );
      }
      default:
        throw new GuardSignerRefusedError(
          `unexpected guard status ${JSON.stringify(result.status)} (fail closed)`,
          { code: "UNEXPECTED_GUARD_STATUS", intentId },
        );
    }
  }

  const guarded = {
    address: account.address,
    ...(account.publicKey !== undefined ? { publicKey: account.publicKey } : {}),
    ...(account.source !== undefined ? { source: account.source } : {}),
    ...(account.type !== undefined ? { type: account.type } : {}),
    signTypedData: gatedSignTypedData,
  };

  // Every OTHER function-valued member of the real account is a raw-key
  // capability (signTransaction, signMessage, sign, signAuthorization, ...)
  // and is replaced with a throwing stub: present, so consumers that probe for
  // the member still construct, but structurally incapable of producing a
  // signature. In @x402/evm specifically, an ABSENT-or-unusable
  // signTransaction disables the unlimited-ERC-20-approval extension path.
  for (const key of Object.keys(account)) {
    if (key in guarded) continue;
    if (typeof account[key] === "function") {
      guarded[key] = async () => {
        throw new GuardSignerRefusedError(
          `${key}() is disabled on a GuardedAccount: it is a raw-key capability that would ` +
            "bypass payment policy. Only policy-gated signTypedData is available.",
          { code: "UNGATED_CAPABILITY_DISABLED" },
        );
      };
    }
    // Non-function members beyond the allowlist above are deliberately NOT
    // copied: nothing in the x402 path needs them, and default-deny beats
    // forwarding a member we have not reasoned about.
  }

  return Object.freeze(guarded);
}
