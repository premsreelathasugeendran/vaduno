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
 * THE INVARIANT THIS FILE EXISTS TO HOLD: **sign exactly the bytes you
 * policed.** Everything below is a consequence of it.
 *
 * WHAT THE WRAPPER DOES on each signTypedData call:
 *   1. SNAPSHOT the request (`structuredClone`) before reading a single field,
 *      and use the snapshot for BOTH the policy decision and the signature.
 *      The caller's object is never read twice and never signed.
 *   2. Extract the payment facts from that snapshot — the payee, the amount,
 *      the asset (domain.verifyingContract) and the chain (domain.chainId).
 *   3. Scale the token's atomic units into the policy currency's minor units
 *      using the trusted registry's decimals, rounding UP so the guard can
 *      only ever police MORE than the true value, never less.
 *   4. Identify the authorization by its EIP-712 DIGEST — a function of every
 *      byte that will be signed — and run guard.authorize().
 *   5. Only on "authorized": delegate to the real account with the snapshot,
 *      then settle the reserved spend as executed.
 *   6. On any other outcome: throw. No signature is produced. Every refusal,
 *      including the ones decided locally, is written to the audit ledger.
 *
 * IDEMPOTENCY: the intent id is `sig:` + the EIP-712 digest of the request.
 * Two calls collide on an id if and only if they would produce the SAME
 * signature over the SAME bytes, so the "replay" branch can only ever re-issue
 * a signature that was already policed and counted. Anything that differs by
 * even one byte — a domain name, a Permit2 witness field, a validity window in
 * a different numeric encoding — is a different authorization and is policed
 * and counted on its own.
 *
 * COLLECTOR-ALIASED SCHEMES: `@x402/evm`'s auth-capture scheme signs an
 * EIP-3009 authorization whose `to` is a hardcoded token-collector contract,
 * never the merchant; the true payee is committed only inside the opaque
 * `nonce`. Policing `to` there polices the collector, so such a request is
 * REFUSED by default. A caller that owns the PaymentInfo can declare it via
 * `resolveAuthCapture`, and the wrapper re-derives the nonce from that
 * declaration — a declaration that does not reproduce the signed nonce is
 * rejected, so the caller cannot lie about the payee. See README.md.
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
import { randomBytes } from "node:crypto";
import {
  encodeAbiParameters,
  getAddress,
  getTypesForEIP712Domain,
  hashTypedData,
  keccak256,
  zeroAddress,
} from "viem";

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

/**
 * Token-collector contracts that stand in for the merchant in the shipped
 * @x402/evm auth-capture scheme. An EIP-3009 authorization paying one of these
 * is NOT a payment to that address — it is a payment to whoever is named
 * inside the nonce preimage. Policing `to` here would police the collector.
 */
const DEFAULT_AUTH_CAPTURE_COLLECTORS = [
  "0x0e3df9510de65469c4518d7843919c0b8c7a7757", // EIP3009_TOKEN_COLLECTOR_ADDRESS
  "0x992476b9ee81d52a5bda0622c333938d0af0ab26", // PERMIT2_TOKEN_COLLECTOR_ADDRESS
];
// The PERMIT2 entry above is reached ONLY through the unsupported-flavour check
// below, never through extractPayment: that flavour signs `PermitTransferFrom`,
// which is not a recognized payment shape. Leaving it addressable only from a
// branch that cannot run would have been a list entry pretending to be a
// control — the list must not contain addresses nothing ever compares against.
/** The escrow the auth-capture PaymentInfo hash is domain-separated by. */
const AUTH_CAPTURE_ESCROW_ADDRESS = "0xBdEA0D1bcC5966192B070Fdf62aB4EF5b4420cff";
const PAYMENT_INFO_TYPEHASH = keccak256(
  new TextEncoder().encode(
    "PaymentInfo(address operator,address payer,address receiver,address token,uint120 maxAmount," +
      "uint48 preApprovalExpiry,uint48 authorizationExpiry,uint48 refundExpiry,uint16 minFeeBps," +
      "uint16 maxFeeBps,address feeReceiver,uint256 salt)",
  ),
);

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
 * Fee basis points, as a value the canonical-JSON ledger can actually hold.
 * bigint is the natural type here and is what the nonce re-derivation consumes,
 * but it is not representable in canonical JSON, so the audit copy is narrowed
 * to a number (or a decimal string if it somehow exceeds safe-integer range).
 */
function bpsToNumber(v) {
  const b = asBigInt(v);
  if (b === null) return null;
  return b >= 0n && b <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(b) : String(b);
}

/**
 * Re-derive the auth-capture `nonce` from a declared PaymentInfo.
 *
 * This is the whole reason a declaration can be trusted: the nonce the signer
 * is being asked to sign is `keccak256(chainId, escrow, keccak256(PaymentInfo))`
 * with the payer zeroed, so a declaration naming a different receiver,
 * operator, fee recipient, fee ceiling or deadline simply does not reproduce
 * it. The caller supplies the parts that are NOT in the signed bytes; every
 * part that IS in the signed bytes is taken from the signed bytes.
 *
 * Mirrors @x402/evm's computePayerAgnosticPaymentInfoHash. The regression
 * suite cross-checks this against a genuine run of the shipped scheme.
 */
function deriveAuthCaptureNonce({ chainId, token, maxAmount, preApprovalExpiry, declared }) {
  const paymentInfoEncoded = encodeAbiParameters(
    [
      { name: "typehash", type: "bytes32" },
      { name: "operator", type: "address" },
      { name: "payer", type: "address" },
      { name: "receiver", type: "address" },
      { name: "token", type: "address" },
      { name: "maxAmount", type: "uint120" },
      { name: "preApprovalExpiry", type: "uint48" },
      { name: "authorizationExpiry", type: "uint48" },
      { name: "refundExpiry", type: "uint48" },
      { name: "minFeeBps", type: "uint16" },
      { name: "maxFeeBps", type: "uint16" },
      { name: "feeReceiver", type: "address" },
      { name: "salt", type: "uint256" },
    ],
    [
      PAYMENT_INFO_TYPEHASH,
      getAddress(declared.operator),
      zeroAddress,
      getAddress(declared.receiver),
      getAddress(token),
      maxAmount,
      preApprovalExpiry,
      BigInt(declared.authorizationExpiry),
      BigInt(declared.refundExpiry),
      BigInt(declared.minFeeBps),
      BigInt(declared.maxFeeBps),
      getAddress(declared.feeRecipient),
      BigInt(declared.salt),
    ],
  );
  const outerEncoded = encodeAbiParameters(
    [
      { name: "chainId", type: "uint256" },
      { name: "escrow", type: "address" },
      { name: "paymentInfoHash", type: "bytes32" },
    ],
    [BigInt(chainId), AUTH_CAPTURE_ESCROW_ADDRESS, keccak256(paymentInfoEncoded)],
  );
  return keccak256(outerEncoded).toLowerCase();
}

/**
 * Convert a token's atomic units into the policy currency's MINOR units.
 *
 * Recording `decimals` and then treating atomic units as minor units — which
 * this wrapper used to do — is a silent unit confusion: 10000 atomic units of
 * a 2-decimal dollar token (GUSD and EURS are real ones) is $100.00, and was
 * counted as 10000 of a currency whose minor unit is 1e-6, i.e. $0.01. A
 * 10,000x under-count under a per-transaction cap.
 *
 * Scaling DOWN rounds UP, never down: a fraction of a minor unit must cost a
 * whole minor unit, because the alternative is dust that costs nothing and
 * therefore has no cap. The guard can over-count by at most one minor unit; it
 * can never under-count.
 */
function scaleToMinor(atomic, tokenDecimals, minorDecimals) {
  if (tokenDecimals === minorDecimals) return { minor: atomic, rounded: false };
  if (minorDecimals > tokenDecimals) {
    return { minor: atomic * 10n ** BigInt(minorDecimals - tokenDecimals), rounded: false };
  }
  const divisor = 10n ** BigInt(tokenDecimals - minorDecimals);
  const quotient = atomic / divisor;
  const remainder = atomic % divisor;
  return remainder === 0n
    ? { minor: quotient, rounded: false }
    : { minor: quotient + 1n, rounded: true };
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
 *
 * NOTE what is NOT here anymore: the hand-written list of fields that used to
 * form the intent id. Any such list is a list of the bytes an attacker may
 * vary for free — domain.name, a Permit2 witness's facilitator, a validity
 * window written in hex. The id is now the EIP-712 digest, computed by the
 * caller of this function over the same snapshot that gets signed.
 */
/**
 * Does the EIP-712 type declaration actually COMMIT to the fields we read?
 *
 * This is the difference between `message` and the signed bytes, and it is the
 * single root cause of a whole family of defects. `message` is a plain object;
 * the digest is computed ONLY over the fields listed in `types[primaryType]`,
 * in that order, with those types. A caller can therefore put `to: <seller>` in
 * `message`, omit `to` from `types`, and obtain a signature over a struct with
 * no recipient at all — while the extractor, reading `message.to` by name,
 * tells the guard the seller is the payee and the ledger certifies it.
 *
 * Measured consequences before this check existed: `types` omitting `to` signed
 * with a policed payee the signature did not carry; omitting `value` counted an
 * amount the signature did not carry; and a Permit2 witness type omitting `to`
 * made digest(to=SELLER) === digest(to=ATTACKER) — one signature, two payees,
 * one audit row.
 *
 * The rule: every field the guard is TOLD about must be a field the signature
 * COMMITS to, with the expected ABI type. Anything else is refused.
 *
 * @param {Record<string, Array<{name:string,type:string}>>} types
 * @param {string} structName
 * @param {Array<[string, string]>} required  [fieldName, abiType] pairs
 * @returns {string|null} null if committed, else a human reason
 */
function missingCommitment(types, structName, required) {
  const decl = types?.[structName];
  if (!Array.isArray(decl)) {
    return `types.${structName} is not declared, so the signed struct is unknown`;
  }
  for (const [name, type] of required) {
    const field = decl.find((f) => f && f.name === name);
    if (!field) {
      return `types.${structName} does not declare "${name}", so the signature does not commit to it`;
    }
    if (String(field.type) !== type) {
      return `types.${structName}.${name} is declared "${field.type}", expected "${type}"`;
    }
  }
  return null;
}

/**
 * The EIP-712 DOMAIN has the same problem, one level up.
 *
 * viem infers EIP712Domain from whichever domain fields are present when the
 * caller does NOT declare it — in that case every present field is committed
 * and there is nothing to check. But an EXPLICIT `types.EIP712Domain` narrows
 * what the digest covers, and the wrapper reads `domain.chainId` (the policed
 * network) and `domain.verifyingContract` (the asset, hence the DECIMALS) from
 * it. Narrowed away, the same signature is valid at a different token: measured
 * at digest(verifyingContract=USDC) === digest(verifyingContract=2-decimal
 * token), i.e. the guard counts $0.01 for bytes worth $100.00 — the decimals
 * fix walked around rather than defeated.
 */
function missingDomainCommitment(types, needed) {
  if (!Array.isArray(types?.EIP712Domain)) return null; // inferred: all present fields committed
  for (const [name, type] of needed) {
    const field = types.EIP712Domain.find((f) => f && f.name === name);
    if (!field) {
      return `types.EIP712Domain omits "${name}", so the signature does not commit to it ` +
        "(the same bytes would be valid with a different one)";
    }
    if (String(field.type) !== type) {
      return `types.EIP712Domain.${name} is declared "${field.type}", expected "${type}"`;
    }
  }
  return null;
}

/**
 * The set of fields the EIP-712 digest ACTUALLY COVERS, as evidence.
 *
 * The digest alone binds the ledger row to a specific signature, which is what
 * lets an auditor say "these bytes were policed". It does NOT say WHICH FACTS
 * those bytes carry — and that is the question every defect in this family
 * turned on. A `TransferWithAuthorization` whose `types` omits `to` hashes to a
 * perfectly valid digest; so does one that declares all six fields. Two ledger
 * rows, two digests, and nothing in either recording that one of them was a
 * struct with no recipient. (It is refused now — but "refused now" is a
 * property of today's code, and the ledger outlives today's code. An archive
 * that cannot answer the question retroactively is an archive that has to be
 * trusted rather than checked.)
 *
 * The domain half is taken from viem's own `getTypesForEIP712Domain` when the
 * caller did not declare `types.EIP712Domain`, because that is precisely the
 * inference `hashTypedData` just used — reimplementing it here would be a
 * second opinion about the bytes, and a second opinion is exactly the kind of
 * thing this file exists to eliminate.
 *
 * Struct types are walked transitively from `primaryType`, so a Permit2 record
 * carries `TokenPermissions` and the witness struct rather than claiming to
 * cover fields whose own declaration was never inspected.
 */
function committedFieldSet(typed) {
  const types = typed?.types ?? {};
  const domain = Array.isArray(types.EIP712Domain)
    ? types.EIP712Domain.map((f) => String(f?.name))
    : getTypesForEIP712Domain({ domain: typed?.domain ?? {} }).map((f) => f.name);

  const struct = {};
  const visit = (name, depth) => {
    if (depth > 32 || Object.hasOwn(struct, name)) return;
    const decl = types[name];
    if (!Array.isArray(decl)) return;
    // defineProperty, not assignment: a struct literally named "__proto__" must
    // land as an ordinary key instead of mutating a prototype and vanishing
    // from the record.
    Object.defineProperty(struct, name, {
      value: decl.map((f) => String(f?.name)),
      enumerable: true,
      writable: true,
      configurable: true,
    });
    for (const f of decl) {
      const ref = resolveStructRef(types, String(f?.type ?? ""));
      if (ref !== null && ref !== "EIP712Domain") visit(ref, depth + 1);
    }
  };
  visit(String(typed?.primaryType), 0);
  return { domain, struct };
}

/**
 * Which `types` key does a field of declared type `type` actually hash against?
 *
 * THIS MUST MATCH viem'S PRECEDENCE EXACTLY, and the obvious reading of it is
 * wrong. `encodeField` tests `types[type] !== undefined` on the FULL declared
 * name BEFORE it looks at the array suffix, so a field declared `Witness[]`
 * hashes against `types["Witness[]"]` whenever that key exists — the brackets
 * are stripped only as a fallback, one level at a time (`Foo[2][3]` ->
 * `Foo[2]` -> `Foo`). Stripping first instead recorded a DIFFERENT struct's
 * field list when both keys were declared, and nothing at all when only the
 * bracketed one was.
 *
 * That was an evidence defect, not a signing hole — the payee commitment check
 * passes the declared type name through verbatim, so it was already right —
 * but it is the evidence that has to answer "was this fact policeable?" long
 * after the code is gone, and it was answering with a field list the digest
 * does not cover.
 *
 * THE STRIP LOOP ALLOCATES NOTHING, and that is not micro-optimisation. The
 * obvious version recurses on `type.slice(0, open)`, one fresh string per
 * level. `types` is attacker-controlled, so a field declared with 100,000
 * array levels made that version allocate O(n²) characters and kill the
 * process with `FATAL ERROR: Reached heap limit` — while viem itself hashed
 * the very same input in 37 ms and the OLD one-shot regex took 2 ms. A crash
 * is strictly worse than a refusal here: this process is the one writing the
 * audit ledger. So candidate names are tested by LENGTH + PREFIX COMPARISON
 * against the declared keys, which materialises nothing, and the answer is a
 * key that already exists.
 *
 * Past ARRAY_NESTING_LIMIT levels the reference is not resolved but THROWN on,
 * never silently dropped: an unresolved reference would quietly omit a struct
 * from the record, which is the exact defect this function was written to fix.
 * The caller turns the throw into an audited refusal.
 *
 * @returns {string|null} the key to record, or null when nothing is declared.
 */
const ARRAY_NESTING_LIMIT = 32;

function resolveStructRef(types, type) {
  const keys = Object.keys(types);
  /** Is `type[0..end)` a declared key? Returns it, without slicing. */
  const declaredPrefix = (end) => {
    for (const key of keys) {
      if (key.length !== end) continue;
      if (!type.startsWith(key)) continue;
      if (Array.isArray(types[key])) return key;
    }
    return null;
  };

  let end = type.length;
  for (let level = 0; level <= ARRAY_NESTING_LIMIT; level += 1) {
    const hit = declaredPrefix(end);
    if (hit !== null) return hit;
    // viem strips at the LAST "[", whatever lies between it and the end.
    if (end === 0 || type[end - 1] !== "]") return null;
    const open = type.lastIndexOf("[", end - 1);
    if (open <= 0) return null;
    end = open;
  }
  throw new Error(
    `type reference "${type.slice(0, 40)}…" nests more than ${ARRAY_NESTING_LIMIT} array ` +
      "levels; the committed-field record cannot be derived for it",
  );
}

/**
 * Is an UNRECOGNIZED shape actually a collector-aliased scheme in disguise?
 *
 * `@x402/evm`'s auth-capture scheme has two flavours. The EIP-3009 one is
 * recognized, and its unpoliceable payee is rescued by `resolveAuthCapture`.
 * The permit2 one signs `primaryType: "PermitTransferFrom"` — no witness, no
 * recipient field at all — with the PERMIT2 token collector as `spender`. There
 * is nothing in those bytes a declaration could be verified against, so it is
 * not rescuable; it is refusable, and it should be refused BY NAME.
 *
 * Falling through to the generic unknown-shape refusal was fail-closed but
 * undiagnosable: an operator saw "not a recognized payment authorization shape"
 * for a payment their own SDK had just constructed, with nothing pointing at
 * `assetTransferMethod: "permit2"` as the cause.
 */
function collectorInUnpoliceableShape(typed, collectors) {
  const m = typed?.message ?? {};
  for (const v of [m.spender, m.to, m.witness?.to]) {
    const a = normAddress(v);
    if (a !== null && collectors.has(a)) return a;
  }
  return null;
}

const EIP3009_REQUIRED = [
  ["from", "address"],
  ["to", "address"],
  ["value", "uint256"],
  ["validAfter", "uint256"],
  ["validBefore", "uint256"],
  ["nonce", "bytes32"],
];
const DOMAIN_REQUIRED = [
  ["chainId", "uint256"],
  ["verifyingContract", "address"],
];

function extractPayment(typed, collectors) {
  const primaryType = typed?.primaryType;
  const domain = typed?.domain ?? {};
  const message = typed?.message ?? {};

  if (primaryType === "TransferWithAuthorization" || primaryType === "ReceiveWithAuthorization") {
    const chainId = asChainId(domain.chainId);
    const asset = normAddress(domain.verifyingContract);
    const from = normAddress(message.from);
    const payee = normAddress(message.to);
    const nonce =
      typeof message.nonce === "string" && BYTES32_RE.test(message.nonce)
        ? message.nonce.toLowerCase()
        : null;
    if (chainId === null || asset === null || from === null || payee === null || nonce === null) {
      return null;
    }
    const uncommitted =
      missingDomainCommitment(typed?.types, DOMAIN_REQUIRED) ??
      missingCommitment(typed?.types, primaryType, EIP3009_REQUIRED);
    return {
      kind: "eip3009",
      primaryType,
      chainId,
      asset,
      from,
      payee,
      nonce,
      uncommitted,
      validAfter: asBigInt(message.validAfter),
      value: asBigInt(message.value), // null -> audited INVALID_AMOUNT deny
      validBefore: asBigInt(message.validBefore),
      // A payee that is a known token collector is NOT the payee.
      collector: collectors.has(payee) ? payee : null,
    };
  }

  if (primaryType === "PermitWitnessTransferFrom") {
    const chainId = asChainId(domain.chainId);
    const asset = normAddress(message.permitted?.token);
    const payee = normAddress(message.witness?.to);
    const nonce = asBigInt(message.nonce);
    if (chainId === null || asset === null || payee === null || nonce === null) return null;

    // The witness struct's type name is whatever PermitWitnessTransferFrom
    // declares for its `witness` field; `to` must be committed THERE, not just
    // present in the message object.
    const witnessType = typed?.types?.PermitWitnessTransferFrom?.find(
      (f) => f && f.name === "witness",
    )?.type;
    const uncommitted =
      missingDomainCommitment(typed?.types, DOMAIN_REQUIRED) ??
      missingCommitment(typed?.types, "PermitWitnessTransferFrom", [
        ["permitted", "TokenPermissions"],
        ["spender", "address"],
        ["nonce", "uint256"],
        ["deadline", "uint256"],
      ]) ??
      missingCommitment(typed?.types, "TokenPermissions", [
        ["token", "address"],
        ["amount", "uint256"],
      ]) ??
      (typeof witnessType === "string" && witnessType.length > 0
        ? missingCommitment(typed?.types, witnessType, [["to", "address"]])
        : "types.PermitWitnessTransferFrom does not declare a `witness` field, so the payee " +
          "read from message.witness.to is not in the signed bytes");

    const spender = normAddress(message.spender);
    return {
      kind: "permit2",
      primaryType,
      chainId,
      asset,
      from: normAddress(typed?.message?.from) ?? null,
      payee,
      nonce: String(nonce),
      uncommitted,
      // The party the signature actually empowers to pull the tokens. Policing
      // witness.to while ignoring this was a hole: witness.to is a hint the
      // downstream contract may or may not honour, `spender` is the authority.
      spender,
      validAfter: null,
      value: asBigInt(message.permitted?.amount),
      validBefore: asBigInt(message.deadline),
      collector:
        collectors.has(spender ?? "") ? spender : collectors.has(payee) ? payee : null,
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
 * @param {number} [opts.currencyDecimals]
 *   How many decimal places the POLICY currency's minor unit has: 6 for a
 *   policy denominated in USDC atomic units, 2 for one denominated in cents.
 *   Token atomic units are scaled into this. When omitted it is derived from
 *   the registry, and a currency whose registered assets disagree about
 *   decimals is UNRESOLVABLE — every request against it is refused rather than
 *   guessed at, because guessing is what let a 2-decimal token spend 10,000x
 *   its cap.
 * @param {string} [opts.merchantUrl]
 *   Optional: the request URL this signer is being used against, for host
 *   allowlists. The typed data itself does NOT carry the resource URL — that
 *   is a real blind spot of signer-level policy, documented in the README.
 * @param {(ctx: {chainId: number, token: string, payer: string, maxAmount: bigint,
 *   preApprovalExpiry: bigint, nonce: string, collector: string}) => (object|null|undefined)}
 *   [opts.resolveAuthCapture]
 *   Declares the PaymentInfo behind a collector-aliased auth-capture
 *   authorization: `{ operator, receiver, feeRecipient, minFeeBps, maxFeeBps,
 *   authorizationExpiry, refundExpiry, salt }`. The wrapper re-derives the
 *   nonce from it and refuses unless the derivation reproduces the nonce being
 *   signed, so this is a way to TELL the guard the payee, not a way to choose
 *   one. Without it, collector-aliased requests are refused.
 * @param {string[]} [opts.authCaptureCollectors]
 *   Override the known token-collector addresses.
 */
export function createGuardedAccount({
  account,
  guard,
  agentId,
  assets,
  merchantUrl,
  currencyDecimals,
  resolveAuthCapture,
  authCaptureCollectors,
  maxValiditySeconds,
  permit2Spenders: permit2SpendersOpt,
}) {
  const permit2Spenders = new Set(
    (permit2SpendersOpt ?? []).map((a) => String(a).toLowerCase()),
  );
  if (
    maxValiditySeconds !== undefined &&
    (!Number.isInteger(maxValiditySeconds) || maxValiditySeconds <= 0)
  ) {
    throw new Error("createGuardedAccount: `maxValiditySeconds` must be a positive integer");
  }
  if (!account || typeof account.signTypedData !== "function") {
    throw new Error("createGuardedAccount: `account` must expose signTypedData()");
  }
  const registry = new Map();
  /** currency -> Set(decimals) seen for it, to detect an unresolvable registry. */
  const decimalsByCurrency = new Map();
  for (const a of assets ?? []) {
    registry.set(`${a.chainId}:${a.address.toLowerCase()}`, a);
    const cur = String(a.symbol).toUpperCase();
    if (!decimalsByCurrency.has(cur)) decimalsByCurrency.set(cur, new Set());
    decimalsByCurrency.get(cur).add(a.decimals);
  }
  const collectors = new Set(
    (authCaptureCollectors ?? DEFAULT_AUTH_CAPTURE_COLLECTORS).map((a) => String(a).toLowerCase()),
  );
  if (
    currencyDecimals !== undefined &&
    (!Number.isInteger(currencyDecimals) || currencyDecimals < 0 || currencyDecimals > 36)
  ) {
    throw new Error("createGuardedAccount: `currencyDecimals` must be an integer in [0, 36]");
  }

  // ------------------------------------------- HOST PATTERNS POLICE NOTHING HERE
  // A host pattern in `merchants.allow` is matched against `intent.merchant.url`.
  // In a fetch-level integration that URL is derived per payment from where the
  // request is actually going, so the pattern polices something real. HERE it is
  // `merchantUrl`, a constant fixed at wrap time — identical for every payment
  // this account will ever sign. So `allow: ["host:x402.org"]` matches for ANY
  // recipient, and a transfer to an arbitrary address is authorized while the
  // policy reads as though it names a merchant.
  //
  // THE SECURITY CONTROL IS NOT THIS CHECK — it is that `merchant.url` is
  // never populated from `merchantUrl` at all (see the sign path), so a
  // host-form pattern has no URL to match and fails closed regardless of what
  // this block can see. This check is a DIAGNOSTIC: it turns a policy that
  // will now silently deny everything into a loud error at construction, and
  // it is best-effort by design — a guard wrapper that does not forward
  // getPolicy() simply skips it, which is why it must not be load-bearing.
  if (merchantUrl !== undefined && typeof guard?.getPolicy === "function") {
    const allow = guard.getPolicy()?.merchants?.allow ?? [];
    const hostForms = allow.filter((p) => {
      const raw = String(p).trim();
      const lower = raw.toLowerCase();
      if (lower.startsWith("id:")) return false;
      if (lower.startsWith("host:")) return true;
      return raw.includes("."); // bare token with a dot == host pattern
    });
    if (hostForms.length > 0) {
      throw new Error(
        "createGuardedAccount: policy merchants.allow contains host-form pattern(s) " +
          `${JSON.stringify(hostForms)} while merchantUrl is a constant fixed at wrap time. ` +
          "A host pattern is matched against merchant.url, so here it would match for EVERY " +
          "payee and authorize a transfer to an arbitrary address. Use the id: form " +
          '(e.g. "id:0xabc…", the payee taken from the signed bytes), or omit merchantUrl.',
      );
    }
  }

  /**
   * Record a LOCAL refusal in the tamper-evident ledger.
   *
   * Before this, the refusals decided inside the wrapper — an unrecognized
   * typed-data shape, a disabled raw-key capability — appended ZERO ledger
   * rows, while cap and merchant denials appended two each. For a project
   * whose claim is evidence, the most suspicious requests (someone asking for
   * an unlimited approval, someone reaching for signTransaction) were exactly
   * the ones that left no trace.
   *
   * It is routed through `guard.authorize()` rather than a second write path
   * so a refusal row is indistinguishable in shape and hashing from a policy
   * denial. `amountMinor: 0` guarantees the verdict: the policy engine denies
   * a non-positive amount unconditionally, and 0 (unlike NaN, which is not
   * representable in the ledger's canonical JSON and made the append THROW)
   * always serializes. The wrapper throws regardless of what comes back — the
   * guard is being used here as an audited denial, never as an authority that
   * could allow.
   */
  async function auditRefusal(code, message, facts = {}) {
    const intentId = `refused:${code}:0x${randomBytes(16).toString("hex")}`;
    try {
      const result = await guard.authorize({
        id: intentId,
        agentId,
        // No `url`: see the note at the `merchant` construction on the sign
        // path. The wrap-time URL is evidence, not a policy input.
        merchant: { id: facts.payee ?? `refusal:${code}` },
        // Denied twice over, by two independent unconditional rules.
        amount: { amountMinor: 0, currency: `REFUSED:${code}` },
        rail: "x402",
        description: `signer refusal [${code}]: ${message}`,
        metadata: { refusal: code, ...facts },
        requestedAt: new Date().toISOString(),
      });
      // Cannot happen (amountMinor 0 is denied unconditionally), but if the
      // policy engine ever changed, give back anything that was reserved
      // rather than silently holding budget for a payment that never existed.
      if (result?.status === "authorized") {
        await guard.settle(intentId, { status: "failed", error: `refused locally: ${code}` });
        await guard.releaseSpend(intentId);
      }
    } catch {
      // The audit write is best-effort; the refusal itself is not. Never let
      // a ledger problem turn a refusal into a signature.
    }
    return intentId;
  }

  async function refuse(code, message, facts) {
    const intentId = await auditRefusal(code, message, facts);
    throw new GuardSignerRefusedError(message, { code, intentId });
  }

  async function gatedSignTypedData(untrustedTypedData) {
    // ---------------------------------------------------------------- SNAPSHOT
    // Pin the request to an inert copy BEFORE reading a single field, and sign
    // THE COPY. structuredClone flattens getters to values, strips Proxy
    // behaviour, and preserves bigint — so what policy reads and what the key
    // hashes are the same immutable bytes. This mirrors what VadunoGuard.run()
    // already does to the intent, for exactly the same reason.
    //
    // Without it there were two working bypasses, neither exotic: accessors
    // that returned a benign payee during the checks and a hostile one at
    // signing, and — needing no accessors at all — a caller that simply did not
    // await, mutating its own plain object across the wrapper's first await.
    // Both produced a VALID signature for 100 USDC to an attacker while the
    // hash-chained ledger certified 0.01 USDC to the legitimate seller: an
    // audit trail that is cryptographically intact and materially false, which
    // is worse than having no audit trail at all.
    let typedData;
    try {
      typedData = structuredClone(untrustedTypedData);
    } catch {
      await refuse(
        "TYPED_DATA_NOT_SERIALIZABLE",
        "typed data could not be safely snapshotted (default-deny)",
      );
    }

    const p = extractPayment(typedData, collectors);
    if (p === null) {
      // Before the generic refusal: is this a collector-aliased scheme whose
      // flavour has no policeable payee at all? Same verdict, actionable reason.
      const aliased = collectorInUnpoliceableShape(typedData, collectors);
      if (aliased !== null) {
        const primaryType = String(typedData?.primaryType ?? "(none)");
        // Say only what is known. `PermitTransferFrom` naming a collector IS the
        // shipped permit2 auth-capture flavour and the operator can act on that;
        // any OTHER unrecognized shape naming a collector is something this
        // wrapper has not seen, and asserting a scheme for it would be a claim
        // ahead of the evidence.
        await refuse(
          "AUTH_CAPTURE_FLAVOUR_UNSUPPORTED",
          `refusing to sign a ${primaryType} naming the token collector ${aliased}: the signed ` +
            "struct carries no policeable payee — in the collector-aliased schemes the receiver, " +
            "capture operator and fee recipient exist only inside the opaque nonce, and there is " +
            "nothing in these bytes a resolveAuthCapture() declaration could be checked against, " +
            "so supplying a resolver does not change this outcome. " +
            (primaryType === "PermitTransferFrom"
              ? "This is the permit2 flavour of @x402/evm's auth-capture scheme " +
                '(extra.assetTransferMethod: "permit2"); the EIP-3009 flavour — omit that field, ' +
                'or set it to "eip3009" — signs a struct whose nonce CAN be re-derived from a ' +
                "declaration, and is policeable."
              : "This shape is not one this wrapper recognizes, so no claim is made about which " +
                "scheme produced it."),
          { collector: aliased, primaryType },
        );
      }
      // Structurally unmappable: no faithful intent can be built, so this is
      // refused (fail closed) rather than guessed at.
      await refuse(
        "UNRECOGNIZED_TYPED_DATA",
        `refusing to sign primaryType ${JSON.stringify(typedData?.primaryType)}: ` +
          "not a recognized payment authorization shape (default-deny)",
        { primaryType: String(typedData?.primaryType ?? "(none)") },
      );
    }

    // ------------------------------------------------- COMMITMENT / BINDING
    // Every fact the guard is about to be TOLD must be a fact the signature
    // CARRIES. These four checks are all the same idea applied to different
    // fields, and each one closes a measured hole where the ledger certified
    // something the bytes did not commit to.

    if (p.uncommitted) {
      await refuse("TYPED_DATA_NOT_COMMITTED", `refusing to sign: ${p.uncommitted}`, {
        primaryType: p.primaryType,
      });
    }

    // The payer. EIP-3009 contracts require ecrecover(digest) === `from`, so a
    // mismatch can never settle — but it SIGNS, and the guard counts the spend,
    // so an agent could exhaust the daily cap with authorizations no contract
    // will ever accept. A denial-of-service against the budget, and the ledger
    // records it as real spend.
    if (p.from !== null && p.from !== String(account.address).toLowerCase()) {
      await refuse(
        "PAYER_NOT_THIS_SIGNER",
        `refusing to sign an authorization whose payer is ${p.from}, not this wallet ` +
          `(${String(account.address).toLowerCase()}): it can never settle, but it would ` +
          "consume budget and be recorded as spend",
        { from: p.from, signer: String(account.address).toLowerCase() },
      );
    }

    // Validity window. An ALREADY-EXPIRED authorization is the same budget-burn
    // shape as the above. An authorization with no practical expiry is a
    // permanent bearer instrument for that nonce and amount — within cap and to
    // an allowlisted payee, so nothing else refuses it.
    const nowSec = BigInt(Math.floor(Date.now() / 1000));
    if (p.validBefore !== null && p.validBefore <= nowSec) {
      await refuse(
        "AUTHORIZATION_EXPIRED",
        `refusing to sign an authorization that expired at ${p.validBefore} (now ${nowSec}): ` +
          "it cannot settle, but it would consume budget and be recorded as spend",
        { validBefore: String(p.validBefore), now: String(nowSec) },
      );
    }
    if (maxValiditySeconds !== undefined && p.validBefore !== null) {
      const startsAt = p.validAfter !== null && p.validAfter > 0n ? p.validAfter : nowSec;
      const window = p.validBefore - startsAt;
      if (window > BigInt(maxValiditySeconds)) {
        await refuse(
          "VALIDITY_WINDOW_TOO_LONG",
          `refusing to sign an authorization valid for ${window}s, over the configured ` +
            `maxValiditySeconds of ${maxValiditySeconds}`,
          { validBefore: String(p.validBefore), windowSeconds: String(window) },
        );
      }
    }

    // Permit2: `spender` is the address the signature EMPOWERS to pull the
    // tokens. witness.to is a hint the downstream contract may or may not
    // honour; spender is the authority. Policing the former while ignoring the
    // latter let a signature that named an allowlisted seller in the witness
    // grant an arbitrary spender the right to move the funds anywhere.
    if (p.kind === "permit2") {
      if (p.spender === null) {
        await refuse("PERMIT2_SPENDER_UNKNOWN", "refusing to sign: `spender` is not an address", {
          primaryType: p.primaryType,
        });
      }
      if (!permit2Spenders.has(p.spender)) {
        await refuse(
          "PERMIT2_SPENDER_NOT_ALLOWED",
          `refusing to sign a Permit2 authorization empowering spender ${p.spender}: ` +
            "that address, not the witness recipient, is what the signature authorizes to move " +
            "the tokens. Declare permitted spenders via the permit2Spenders option.",
          { spender: p.spender, witnessTo: p.payee, primaryType: p.primaryType },
        );
      }
    }

    // ------------------------------------------------------------ IDENTITY
    // The intent id is the EIP-712 digest of the snapshot: a function of
    // EVERY byte that will be signed, including the parts a hand-written
    // field list kept missing — domain.name/version/salt, the `types`
    // definition itself, a Permit2 witness's facilitator, and validity
    // windows in any numeric encoding. Two requests share an id only if they
    // would produce the same signature, so the guard's "replay" branch can
    // only ever re-issue a signature that was already policed and counted.
    //
    // The committed-field SET is derived from the SAME object, immediately
    // after, and is equally mandatory: it is a statement about these bytes, and
    // a statement about these bytes that could be skipped when inconvenient
    // would be decoration. If either cannot be computed, nothing is signed.
    //
    // They are two `try`s rather than one so the refusal names the right
    // thing. Sharing a catch meant a record that could not be derived was
    // reported as a digest that could not be computed — a false diagnosis in a
    // file whose whole subject is refusals that point at the wrong cause.
    let digest;
    let committed;
    try {
      digest = hashTypedData(typedData);
    } catch (err) {
      await refuse(
        "DIGEST_UNCOMPUTABLE",
        `refusing to sign: the EIP-712 digest could not be computed (${err instanceof Error ? err.message : String(err)})`,
        { primaryType: p.primaryType },
      );
    }
    try {
      committed = committedFieldSet(typedData);
    } catch (err) {
      await refuse(
        "COMMITMENT_RECORD_UNCOMPUTABLE",
        `refusing to sign: the digest is computable but the set of fields it commits to is ` +
          `not, so the ledger row could not state what was policed ` +
          `(${err instanceof Error ? err.message : String(err)})`,
        { primaryType: p.primaryType },
      );
    }
    const intentId = `sig:${digest}`;

    // ------------------------------------------------------- COLLECTOR ALIAS
    // An authorization whose payee is a known token collector is not a payment
    // to that address. Resolve the real payee cryptographically, or refuse.
    let payee = p.payee;
    let authCaptureMeta;
    if (p.collector !== null) {
      if (typeof resolveAuthCapture !== "function") {
        await refuse(
          "AUTH_CAPTURE_UNPOLICEABLE",
          `refusing to sign a ${p.primaryType} paying the token collector ${p.collector}: ` +
            "in this scheme the true payee, capture operator and fee recipient are committed " +
            "only inside the opaque nonce, so a merchant allowlist keyed on the payee would " +
            "police the collector. Supply resolveAuthCapture() to declare the PaymentInfo.",
          { collector: p.collector, primaryType: p.primaryType, asset: p.asset, chainId: p.chainId },
        );
      }
      if (p.value === null || p.validBefore === null) {
        await refuse(
          "AUTH_CAPTURE_UNPOLICEABLE",
          "refusing to sign a collector-aliased authorization whose amount or validity window " +
            "is not a plain integer: the nonce cannot be re-derived from it",
          { collector: p.collector },
        );
      }
      let declared;
      try {
        // SNAPSHOT THE DECLARATION, for exactly the reason the request itself
        // is snapshotted. Every field below is read more than once — the nonce
        // re-derivation reads `receiver`, then merchant.id reads it again, then
        // the audit metadata reads `feeRecipient`/`operator` again. Without a
        // snapshot, a declaration whose getters return different values on
        // successive reads passes the nonce check on read 1 (proving read 1 was
        // the attacker) and is policed and audited on read 2 (the allowlisted
        // seller): cryptographically intact and materially false, which is the
        // failure this check exists to prevent. structuredClone flattens the
        // getters to values once. Non-cloneable declarations are refused, not
        // trusted.
        declared = structuredClone(
          await resolveAuthCapture({
            chainId: p.chainId,
            token: p.asset,
            payer: p.from,
            maxAmount: p.value,
            preApprovalExpiry: p.validBefore,
            nonce: p.nonce,
            collector: p.collector,
          }),
        );
      } catch (err) {
        declared = null;
      }
      if (!declared || typeof declared !== "object") {
        await refuse(
          "AUTH_CAPTURE_UNRESOLVED",
          "resolveAuthCapture() did not declare a PaymentInfo for this authorization, so the " +
            "real payee is unknown (default-deny)",
          { collector: p.collector, nonce: p.nonce },
        );
      }
      let derived = null;
      try {
        derived = deriveAuthCaptureNonce({
          chainId: p.chainId,
          token: p.asset,
          maxAmount: p.value,
          preApprovalExpiry: p.validBefore,
          declared,
        });
      } catch {
        derived = null;
      }
      if (derived !== p.nonce) {
        // The declaration is not what was signed. This is the load-bearing
        // check: it is what makes a caller-supplied payee trustworthy, because
        // the nonce is a hash over the whole PaymentInfo and cannot be forged
        // to match a different receiver.
        await refuse(
          "AUTH_CAPTURE_MISMATCH",
          "the declared PaymentInfo does not re-derive the nonce being signed: the declaration " +
            `names receiver ${String(declared.receiver)}, which is not what these bytes authorize`,
          { collector: p.collector, nonce: p.nonce, derived: derived ?? "(underivable)" },
        );
      }
      payee = normAddress(String(declared.receiver));
      if (payee === null) {
        await refuse("AUTH_CAPTURE_MISMATCH", "declared receiver is not an address", {
          collector: p.collector,
        });
      }
      authCaptureMeta = {
        scheme: "auth-capture",
        collector: p.collector,
        operator: normAddress(String(declared.operator)),
        feeRecipient: normAddress(String(declared.feeRecipient)),
        // Normalized, because the natural EVM type for these is bigint (it is
        // what viem hands you) and the intent-shape inspector correctly refuses
        // bigint in metadata. The nonce re-derivation above already accepted
        // this declaration, so refusing it here would deny an honest, verified
        // payment over a JSON type — the code would be inviting the type it
        // then refuses.
        minFeeBps: bpsToNumber(declared.minFeeBps),
        maxFeeBps: bpsToNumber(declared.maxFeeBps),
      };
    }

    // -------------------------------------------------------------- CURRENCY
    const known = registry.get(`${p.chainId}:${p.asset}`);
    // Unknown asset -> currency that cannot match the policy's base currency
    // -> audited deny. Known asset -> the registry's trusted symbol.
    const currency = known ? String(known.symbol).toUpperCase() : `UNKNOWN:${p.asset}`;

    // ---------------------------------------------------------------- AMOUNT
    // Token atomic units are NOT automatically the policy currency's minor
    // units — that assumption is what let 10000 units of a 2-decimal dollar
    // token ($100.00) pass a cap that thought it was seeing $0.01.
    let amountMinor = 0; // 0 is denied unconditionally: the fail-closed value.
    let scaleNote;
    if (!known) {
      // Unknown asset: there is no trusted granularity to scale by, so the
      // amount stays at the fail-closed 0 (denied by INVALID_AMOUNT as well as
      // by CURRENCY_MISMATCH). The attempted atomic value still goes into the
      // evidence — a denial that does not record how much was asked for is a
      // worse audit record than one that does.
      scaleNote = { atomic: String(p.value), unregisteredAsset: true };
    } else {
      const seen = decimalsByCurrency.get(currency);
      const minorDecimals =
        currencyDecimals !== undefined
          ? currencyDecimals
          : seen && seen.size === 1
            ? [...seen][0]
            : null;
      if (minorDecimals === null) {
        await refuse(
          "AMBIGUOUS_CURRENCY_DECIMALS",
          `currency ${currency} is registered with more than one token granularity ` +
            `(${[...seen].join(", ")} decimals) and no currencyDecimals was declared, so an ` +
            "amount in atomic units cannot be converted to policy minor units without guessing",
          { currency, chainId: p.chainId, asset: p.asset },
        );
      }
      if (!Number.isInteger(known.decimals) || known.decimals < 0 || known.decimals > 36) {
        await refuse(
          "INVALID_ASSET_DECIMALS",
          `registry entry for ${p.asset} declares decimals=${String(known.decimals)}, which is not ` +
            "a usable token granularity",
          { currency, asset: p.asset },
        );
      }
      if (p.value !== null && p.value >= 0n) {
        const scaled = scaleToMinor(p.value, known.decimals, minorDecimals);
        scaleNote = {
          atomic: String(p.value),
          tokenDecimals: known.decimals,
          minorDecimals,
          ...(scaled.rounded ? { roundedUp: true } : {}),
        };
        if (scaled.minor > BigInt(Number.MAX_SAFE_INTEGER)) {
          // THE VERDICT WAS RIGHT AND THE DIAGNOSIS WAS WRONG.
          //
          // `amountMinor` is a JS number, so a scaled value past 2^53-1 cannot
          // be handed to the policy engine. Collapsing it to the fail-closed 0
          // reached the correct refusal by a lie: the engine then denied
          // INVALID_AMOUNT, which reads as "the payment's amount is malformed".
          // That is one of the two things it can mean, and the wrapper knows
          // which inputs it saw while the reader of the log does not.
          //
          // Both causes are stated, because the wrapper genuinely cannot tell
          // them apart from one request: 1e18 atomic units of an 18-decimal
          // token is an ordinary single token that a currencyDecimals=18
          // deployment cannot express (every payment of that token fails
          // identically), and 2^200 atomic units of USDC is an absurd amount
          // that no configuration should express. Naming one and hiding the
          // other would just relocate the misdirection. A refusal that sends
          // its reader to audit the wrong thing is a defect even when the
          // refusal itself is correct.
          await refuse(
            "AMOUNT_NOT_REPRESENTABLE",
            `refusing to sign: ${p.value} atomic units of a ${known.decimals}-decimal token is ` +
              `${scaled.minor} minor units at currencyDecimals=${minorDecimals}, past the ` +
              `${Number.MAX_SAFE_INTEGER} the policy engine can represent. Either the requested ` +
              "amount is absurd for this currency (check the payment), or currencyDecimals is " +
              "finer than the payments denominated in it (check the configuration: a coarser " +
              "unit, e.g. cents or the token's own granularity, makes ordinary payments fit). " +
              "This is NOT a cap decision — policy never ran on this amount.",
            {
              currency,
              asset: p.asset,
              atomic: String(p.value),
              tokenDecimals: known.decimals,
              minorDecimals,
              scaledMinor: String(scaled.minor),
            },
          );
        }
        amountMinor = Number(scaled.minor);
      }
    }

    const intent = {
      id: intentId,
      agentId,
      // `merchant.url` is deliberately NOT set from `merchantUrl`.
      //
      // A host pattern in merchants.allow/block is matched against
      // merchant.url. In a fetch-level integration that URL is derived per
      // payment from where the request is actually going, so the pattern
      // polices something real. HERE the only URL available is `merchantUrl`,
      // a constant fixed at wrap time and identical for every payment this
      // account will ever sign — so `allow: ["host:x402.org"]` matched for ANY
      // payee and authorized a transfer to an arbitrary address while the
      // policy read as though it named a merchant.
      //
      // Withholding it is the structural fix rather than the polite one: with
      // no URL, a host-form ALLOW pattern cannot match (→ denied) and a
      // host-form BLOCK pattern makes evaluatePolicy refuse outright. Both
      // fail closed. The `id:` form is the control that means something here —
      // merchant.id is the payee extracted from the bytes about to be signed.
      //
      // The URL is still recorded, as metadata.merchantUrl below, because it
      // is useful evidence. It is just not something policy can be fooled by.
      merchant: { id: payee },
      amount: { amountMinor, currency },
      rail: "x402",
      // The SETTLEMENT NETWORK, as a first-class intent field so the policy
      // can actually gate it. It used to live only in `metadata.chainId`,
      // which no policy rule reads: with an ordinary two-chain asset registry
      // (Base Sepolia USDC and Ethereum Sepolia USDC, both symbol "USDC") a
      // transfer on 11155111 was authorized by a deployment targeting 84532 —
      // same intent shape, same currency, wrong chain. The only chain gate was
      // this registry, which is caller config, not a policy control.
      // CAIP-2 form, matching what @vaduno/x402 v2 emits.
      network: `eip155:${p.chainId}`,
      description: `${p.primaryType} of ${String(p.value)} atomic units of ${currency} to ${payee}`,
      metadata: {
        primaryType: p.primaryType,
        chainId: p.chainId,
        asset: p.asset,
        digest,
        // WHICH FIELDS that digest covers. The digest says "these bytes were
        // policed"; this says which facts those bytes actually carry, which is
        // the question the whole uncommitted-field family of defects turned on.
        committed,
        // Evidence only — deliberately NOT merchant.url. See above.
        ...(merchantUrl !== undefined ? { merchantUrl } : {}),
        // The validity window, recorded so an auditor can tell a 5-minute
        // authorization from a 6-million-year one. It used to appear nowhere in
        // the intent, which made two materially different payments produce
        // indistinguishable audit rows.
        ...(p.validBefore !== null ? { validBefore: String(p.validBefore) } : {}),
        ...(p.validAfter !== null ? { validAfter: String(p.validAfter) } : {}),
        ...(p.kind === "permit2" && p.spender ? { permit2Spender: p.spender } : {}),
        ...(known ? { decimals: known.decimals } : {}),
        ...(scaleNote ? { scale: scaleNote } : {}),
        ...(authCaptureMeta ? { authCapture: authCaptureMeta } : {}),
      },
      requestedAt: new Date().toISOString(),
    };

    const result = await guard.authorize(intent);

    switch (result.status) {
      case "authorized": {
        let signature;
        try {
          // THE SNAPSHOT, never the caller's object.
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
          // The id IS the digest, so a replay is BYTE-IDENTICAL to what was
          // already policed and counted; re-issuing its signature grants no
          // new spending power (the nonce is single-use on-chain). This is
          // what supports SDK retry loops without double-counting — and, now
          // that the id covers the whole digest, it can no longer be used to
          // launder a different authorization through an old approval.
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
  //
  // The refusal is AUDITED. A caller reaching for signTransaction is one of
  // the most interesting things that can happen to this object, and it used to
  // leave no trace at all.
  for (const key of Object.keys(account)) {
    if (key in guarded) continue;
    if (typeof account[key] === "function") {
      guarded[key] = async () => {
        await refuse(
          "UNGATED_CAPABILITY_DISABLED",
          `${key}() is disabled on a GuardedAccount: it is a raw-key capability that would ` +
            "bypass payment policy. Only policy-gated signTypedData is available.",
          { capability: key },
        );
      };
    }
    // Non-function members beyond the allowlist above are deliberately NOT
    // copied: nothing in the x402 path needs them, and default-deny beats
    // forwarding a member we have not reasoned about.
  }

  return Object.freeze(guarded);
}
