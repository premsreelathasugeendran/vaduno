#!/usr/bin/env node
/**
 * Regenerate spec/vectors/*.json from the CURRENT implementation.
 *
 * Run deliberately, never in CI:
 *   node scripts/gen-vectors.mjs
 *
 * WHY THIS IS A SCRIPT AND NOT A TEST HELPER: the vectors are the frozen
 * definition of Vaduno's signed formats. The tests read the committed JSON and
 * compare it to what the code produces, so a change to any preimage FAILS —
 * which is the entire point. Before this existed, hash.test.ts compared the
 * implementation to itself and no hardcoded digest existed anywhere in the
 * repo, so every signed format could have drifted silently.
 *
 * If a diff appears here, that is a wire-format change. It should be
 * deliberate, it should bump the domain tag's version, and it breaks every
 * existing signature. Do not regenerate to make a test go green.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import {
  canonicalJson,
  sha256Hex,
  mandateContextHash,
  mandateKeyId,
  MANDATE_DOMAIN,
  MANDATE_V2_DOMAIN,
  MANDATE_V2_ALGS,
  MLDSA44_PUBLIC_KEY_BYTES,
  MLDSA44_SIGNATURE_BYTES,
  mlDsa44KeyId,
  mlDsa44SpkiFromRawPublicKey,
  MandateManager,
  AuditLedger,
  MemoryLedgerStore,
  intentDigest,
} from "../packages/guard/dist/index.js";
import { mlDsa44CosignaturePayload } from "../packages/transparency/dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "spec", "vectors");
mkdirSync(outDir, { recursive: true });

/**
 * A FIXED Ed25519 key pair. Hardcoded, not generated, so every vector below is
 * reproducible by anyone — including a second implementation in another
 * language. This key signs nothing real and exists only in this file.
 */
const TEST_KEYS = {
  privateKeyPem:
    "-----BEGIN PRIVATE KEY-----\n" +
    "MC4CAQAwBQYDK2VwBCIEIH1uW7T2rXGMnU8YQ0S1kAVLKKvbxmc8s0dnKQGVU3rM\n" +
    "-----END PRIVATE KEY-----\n",
  publicKeyPem: "", // filled in below from the private key
};

import { createPrivateKey, createPublicKey } from "node:crypto";
TEST_KEYS.publicKeyPem = createPublicKey(createPrivateKey(TEST_KEYS.privateKeyPem))
  .export({ type: "spki", format: "pem" })
  .toString();

const write = (name, data) => {
  const path = join(outDir, name);
  writeFileSync(path, JSON.stringify(data, null, 2) + "\n", "utf8");
  console.log(`  wrote spec/vectors/${name}`);
};

// ── 1. Canonicalization ─────────────────────────────────────────────────────
// The foundation: every preimage below is built on this, so if it drifts,
// everything drifts.
const canonicalCases = [
  { note: "key order is normalized", input: { b: 1, a: 2 } },
  { note: "nested objects sorted, array order preserved", input: { x: [{ b: 1, a: 2 }], a: 1 } },
  { note: "undefined own properties are omitted", input: { a: 1, b: undefined } },
  { note: "__proto__ is an ordinary key and is committed to", input: JSON.parse('{"__proto__":{"x":1},"a":2}') },
  { note: "empty object and empty array", input: { o: {}, a: [] } },
  { note: "unicode is escaped by JSON.stringify rules", input: { k: "ünïcødé " } },
  { note: "integers and negative zero", input: { a: 0, b: -0, c: -1, d: 1e21 } },
  { note: "nulls and booleans", input: { n: null, t: true, f: false } },
];
write("canonical-json.json", {
  description:
    "canonicalJson output for fixed inputs. Distinct inputs MUST produce distinct output; " +
    "see rejected-inputs for the values that must throw instead of being coerced.",
  cases: canonicalCases.map((c) => ({ ...c, canonical: canonicalJson(c.input) })),
  rejected: [
    { note: "bigint would collide with the string spelling it", expr: "{ n: 1n }" },
    { note: "Date would collide with its own ISO string", expr: "{ d: new Date(0) }" },
    { note: "NaN would collide with null", expr: "{ x: NaN }" },
    { note: "Infinity would collide with null", expr: "{ x: Infinity }" },
    { note: "undefined in an ARRAY would collide with null", expr: "[undefined]" },
    { note: "non-plain objects all collapsed to {}", expr: "{ v: new Map([[1,2]]) }" },
  ],
});

// ── 2. sha256Hex ────────────────────────────────────────────────────────────
write("sha256.json", {
  description: "sha256Hex over UTF-8 input.",
  cases: [
    { input: "abc", hash: sha256Hex("abc") },
    { input: "", hash: sha256Hex("") },
    { input: "ünïcødé", hash: sha256Hex("ünïcødé") },
  ],
});

// ── 3. Mandate signing ──────────────────────────────────────────────────────
const unsignedMandate = {
  v: 1,
  alg: "Ed25519",
  kid: mandateKeyId(TEST_KEYS.publicKeyPem),
  id: "11111111-2222-3333-4444-555555555555",
  issuer: "human@example.com",
  agentId: "agent-1",
  constraints: {
    maxAmountMinor: 10000,
    currency: "USD",
    merchants: ["openai.com"],
    validFrom: "2026-01-01T00:00:00.000Z",
    expiresAt: "2026-12-31T23:59:59.000Z",
    maxUses: 1,
  },
  createdAt: "2026-01-01T00:00:00.000Z",
};
write("mandate.json", {
  description:
    "Mandate signing preimage: MANDATE_DOMAIN followed by canonicalJson of every " +
    "field except `signature`. The kid is inside the preimage, so relabelling a " +
    "mandate to name a different key breaks its signature.",
  domain: MANDATE_DOMAIN,
  formatVersion: 1,
  alg: "Ed25519",
  testKeys: TEST_KEYS,
  keyIdDerivation: "first 8 bytes of SHA-256('vaduno-mandate-key/v1\\n' || SPKI DER), hex",
  expectedKeyId: mandateKeyId(TEST_KEYS.publicKeyPem),
  unsigned: unsignedMandate,
  preimage: MANDATE_DOMAIN + canonicalJson(unsignedMandate),
  preimageSha256: sha256Hex(MANDATE_DOMAIN + canonicalJson(unsignedMandate)),
});

// ── 4. Mandate context binding ──────────────────────────────────────────────
const context = { agentId: "agent-1", merchantId: "openai", taskRunId: "run-42" };
write("mandate-context.json", {
  description: "mandateContextHash: SHA-256 over a domain tag and the canonical context blob.",
  domain: "vaduno-mandate-ctx/v1\n",
  context,
  hash: mandateContextHash(context),
});

// ── 5. Consume-once intent digest ───────────────────────────────────────────
const intent = {
  id: "intent-1",
  agentId: "agent-1",
  merchant: { id: "openai", url: "https://api.openai.com" },
  amount: { amountMinor: 900, currency: "USD" },
  rail: "x402",
  mandateId: "11111111-2222-3333-4444-555555555555",
  requestedAt: "2026-01-01T00:00:00.000Z",
};
write("intent-digest.json", {
  description:
    "intentDigest commits to the MONEY-AFFECTING fields only, so a replayed intent id " +
    "carrying different money is detected while harmless metadata changes are not.",
  domain: "vaduno-consume-digest/v1\n",
  intent,
  digest: intentDigest(intent),
});

// ── 6. Ledger entry hash ────────────────────────────────────────────────────
const entry = {
  seq: 0,
  type: "policy_decision",
  at: "2026-01-01T00:00:00.000Z",
  data: { decision: "allow" },
  prevHash: "0".repeat(64),
  intentId: "intent-1",
  agentId: "agent-1",
};
write("ledger-entry.json", {
  description:
    "Ledger entry hash: sha256Hex(canonicalJson(entry-without-hash)). Each entry commits " +
    "to prevHash, so any edit, deletion or reorder is detectable.",
  entry,
  hash: sha256Hex(canonicalJson(entry)),
  genesisPrevHash: "0".repeat(64),
});

// ── 7. Merkle tree (RFC 9162) ───────────────────────────────────────────────
const leafHash = (data) =>
  createHash("sha256").update(Buffer.concat([Buffer.from([0x00]), Buffer.from(data, "utf8")])).digest("hex");
const nodeHash = (l, r) =>
  createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(l, "hex"), Buffer.from(r, "hex")]))
    .digest("hex");
const l0 = leafHash("a");
const l1 = leafHash("b");
write("merkle.json", {
  description:
    "RFC 9162 / RFC 6962 hashing. Leaf = SHA-256(0x00 || data); interior = " +
    "SHA-256(0x01 || left || right). The prefixes are what prevent a leaf from " +
    "being presented as an interior node.",
  leafPrefix: "0x00",
  nodePrefix: "0x01",
  emptyTreeRoot: createHash("sha256").update(Buffer.alloc(0)).digest("hex"),
  cases: [
    { leaf: "a", leafHash: l0 },
    { leaf: "b", leafHash: l1 },
    { note: "two-leaf root", left: l0, right: l1, root: nodeHash(l0, l1) },
  ],
});

// ── 8. Domain tags in one place ─────────────────────────────────────────────
write("domains.json", {
  description:
    "Every domain separator in the project. A signature is bound to what its bytes MEAN " +
    "only if the preimage is tagged; an untagged structure shares a signature space with " +
    "any other whose canonical form could coincide.",
  domains: {
    mandate: MANDATE_DOMAIN,
    mandateKeyId: "vaduno-mandate-key/v1\n",
    mandateContext: "vaduno-mandate-ctx/v1\n",
    consumeIntentDigest: "vaduno-consume-digest/v1\n",
    transparencyLeaf: "vaduno-ledger-entry/v1\n",
    transparencySth: "vaduno-tlog-sth/v1\n",
    statusListCredential: "vaduno-status-list/v1\n",
  },
  note:
    "The ledger entry hash is deliberately UNTAGGED: it is an internal chain link, not a " +
    "signed assertion, and it is wrapped by the transparency leaf tag when published.",
});

// ── 9. Hybrid (v2) mandate signing — ADDITIVE, v1 vectors above unchanged ───
// The ML-DSA-44 "test key" is a SYNTACTIC FIXTURE: 1312 deterministic bytes
// wrapped in a real id-ml-dsa-44 SPKI, derived so any implementation can
// reproduce it without native ML-DSA. It exists for kid derivation and
// structure only — it is NOT a functional key, and the vector cannot pin
// ML-DSA signature bytes anyway because FIPS 204 signing is hedged
// (randomized) by default. What IS pinned: the exact preimage, its SHA-256,
// both kid derivations, the Ed25519 signature (deterministic), and the exact
// decoded signature lengths.
import { sign as edSignRaw } from "node:crypto";
const MLDSA_FIXTURE_SEED = "vaduno-vector-mldsa44-key";
const mldsaFixtureRaw = (() => {
  const blocks = [];
  let produced = 0;
  for (let i = 0; produced < MLDSA44_PUBLIC_KEY_BYTES; i++) {
    const b = createHash("sha256").update(MLDSA_FIXTURE_SEED, "utf8").update(Buffer.from([i])).digest();
    blocks.push(b);
    produced += b.length;
  }
  return Buffer.concat(blocks).subarray(0, MLDSA44_PUBLIC_KEY_BYTES);
})();
const mldsaFixturePem = mlDsa44SpkiFromRawPublicKey(mldsaFixtureRaw);
const unsignedMandateV2 = {
  v: 2,
  algs: [...MANDATE_V2_ALGS],
  kids: {
    Ed25519: mandateKeyId(TEST_KEYS.publicKeyPem),
    "ML-DSA-44": mlDsa44KeyId(mldsaFixturePem),
  },
  id: "22222222-3333-4444-5555-666666666666",
  issuer: "human@example.com",
  agentId: "agent-1",
  constraints: {
    maxAmountMinor: 10000,
    currency: "USD",
    merchants: ["openai.com"],
    validFrom: "2026-01-01T00:00:00.000Z",
    expiresAt: "2026-12-31T23:59:59.000Z",
    maxUses: 1,
  },
  createdAt: "2026-01-01T00:00:00.000Z",
};
const v2Preimage = MANDATE_V2_DOMAIN + canonicalJson(unsignedMandateV2);
write("mandate-v2.json", {
  description:
    "HYBRID (v2) mandate signing preimage: MANDATE_V2_DOMAIN followed by canonicalJson of " +
    "every field except `signatures`. Both the Ed25519 and the ML-DSA-44 signature cover " +
    "these same bytes. v1 (mandate.json) is FROZEN and unchanged by this addition.",
  domain: MANDATE_V2_DOMAIN,
  formatVersion: 2,
  algs: [...MANDATE_V2_ALGS],
  signatureBytes: { Ed25519: 64, "ML-DSA-44": MLDSA44_SIGNATURE_BYTES },
  testKeys: {
    ed25519: TEST_KEYS,
    mlDsa44: {
      note:
        "SYNTACTIC FIXTURE, not a functional key: raw = first 1312 bytes of " +
        "SHA-256('" + MLDSA_FIXTURE_SEED + "' || uint8(blockIndex)) blocks, wrapped in the " +
        "fixed id-ml-dsa-44 SPKI header. Usable for kid derivation on any runtime.",
      publicKeyPem: mldsaFixturePem,
      rawSha256: createHash("sha256").update(mldsaFixtureRaw).digest("hex"),
    },
  },
  keyIdDerivation:
    "both families: first 8 bytes of SHA-256('vaduno-mandate-key/v1\\n' || SPKI DER), hex — " +
    "verifiers MUST look keys up by (algorithm, kid); the 64-bit id alone is truncated and " +
    "collidable",
  expectedKids: unsignedMandateV2.kids,
  unsigned: unsignedMandateV2,
  preimage: v2Preimage,
  preimageSha256: sha256Hex(v2Preimage),
  ed25519Signature: edSignRaw(
    null,
    Buffer.from(v2Preimage, "utf8"),
    createPrivateKey(TEST_KEYS.privateKeyPem),
  ).toString("base64"),
  mlDsa44SignatureNote:
    "not pinned: FIPS 204 signing is hedged (randomized) by default. A conforming v2 " +
    "mandate carries a base64 signature decoding to exactly 2420 bytes that verifies over " +
    "the preimage under the kid-named ML-DSA-44 key.",
});

// ── 10. C2SP tlog-cosignature 0x06 payload (ML-DSA-44) ──────────────────────
// A BINARY struct, not the 0x04 text payload with a different algorithm.
const cosignPayload = mlDsa44CosignaturePayload({
  cosignerName: "witness.example/a",
  timestamp: 1780000000,
  origin: "vaduno.example/ledger",
  treeSize: 42,
  rootHash: "ab".repeat(32),
});
write("cosign-mldsa44-payload.json", {
  description:
    "C2SP tlog-cosignature ML-DSA-44 (key-id algorithm byte 0x06) signed payload: " +
    "label[12]='subtree/v1\\n\\0' || opaque cosigner_name<1..255> || uint64 timestamp || " +
    "opaque log_origin<1..255> || uint64 start (MUST be 0 for checkpoints) || uint64 end " +
    "(= tree size) || raw 32-byte root hash. Length-prefixed fields carry a single length " +
    "byte. NOTE the coverage asymmetry: this struct covers (origin, size, root) only — " +
    "extension lines are covered by 0x04 text cosignatures, never by 0x06.",
  input: {
    cosignerName: "witness.example/a",
    timestamp: 1780000000,
    origin: "vaduno.example/ledger",
    treeSize: 42,
    rootHashHex: "ab".repeat(32),
  },
  payloadHex: cosignPayload.toString("hex"),
  payloadSha256: createHash("sha256").update(cosignPayload).digest("hex"),
  signature:
    "keyID[4] = SHA-256(name || 0x0A || 0x06 || raw 1312-byte public key)[:4]; line blob = " +
    "keyID || uint64BE timestamp || 2420-byte ML-DSA-44 signature",
});

// ── 11. x402 HTTP carrier conformance (v1 and v2) — ADDITIVE ────────────────
// These are CONFORMANCE vectors for the x402 adapter's carrier handling, not
// signed Vaduno structures: no domain tags, nothing here is hashed or signed
// by Vaduno. They freeze (a) what a well-formed carrier of each version looks
// like, (b) the exact normalized output the parser must produce from it, and
// (c) the TOTAL version decision table — every possible x402Version value has
// a committed outcome, so a future edit that re-opens the "string '2' reads
// as 1" downgrade channel diffs these files.
import {
  parsePaymentRequired,
  parsePaymentRequiredHeader,
  decodeSettlementResponse,
} from "../packages/x402/dist/index.js";

const outcomeOf = (fn) => {
  try {
    return { outcome: "parsed", value: fn() };
  } catch (err) {
    return {
      outcome: err.name,
      ...(err.detectedVersion !== undefined ? { detectedVersion: err.detectedVersion } : {}),
    };
  }
};

const V1_REQUIREMENT = {
  scheme: "exact",
  network: "base-sepolia",
  maxAmountRequired: "10000",
  resource: "https://api.example.com/premium-data",
  description: "Access to premium market data",
  mimeType: "application/json",
  payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
  maxTimeoutSeconds: 60,
  asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  extra: { name: "USDC", version: "2" },
};

// The body-carrier version decision table. `body` omits x402Version for the
// "absent" case; every other case declares the literal shown.
const v1VersionCases = [
  { label: "absent", body: { accepts: [V1_REQUIREMENT] } },
  ...[1, 2, "2", "1", 0, -7, 1.5, null, {}, [], 3, true].map((v) => ({
    label: JSON.stringify(v) ?? String(v),
    body: { x402Version: v, accepts: [V1_REQUIREMENT] },
  })),
];

write("x402-http-v1.json", {
  description:
    "x402 v1 HTTP carrier conformance: PaymentRequired travels as the 402 JSON body; the " +
    "client pays via the X-PAYMENT header; settlement returns via X-PAYMENT-RESPONSE. " +
    "`parsed` is the exact normalized output parsePaymentRequired must produce. " +
    "`versionOutcomes` freezes the TOTAL version decision table for this carrier: a " +
    "non-integer or non-{1} declaration is REFUSED by the named error, never coerced to 1 " +
    "(absent is the one documented back-compat default).",
  headers: { payment: "X-PAYMENT", settlement: "X-PAYMENT-RESPONSE" },
  body: { x402Version: 1, accepts: [V1_REQUIREMENT] },
  parsed: parsePaymentRequired({ x402Version: 1, accepts: [V1_REQUIREMENT] }),
  versionOutcomes: v1VersionCases.map(({ label, body }) => ({
    x402Version: label,
    body,
    ...outcomeOf(() => parsePaymentRequired(body)),
  })),
});

// The v2 blobs below are VERBATIM from the x402 spec's HTTP transport
// (coinbase/x402 specs/transports-v2/http.md, commit dd927a26) — the spec's
// own examples used as conformance vectors, not re-authored. Each decodes to
// the compact JSON committed beside it (verify: base64(JSON.stringify(json))
// reproduces the blob exactly).
const SPEC_V2_PAYMENT_REQUIRED =
  "eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQQVlNRU5ULVNJR05BVFVSRSBoZWFkZXIgaXMgcmVxdWlyZWQiLCJyZXNvdXJjZSI6eyJ1cmwiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbS9wcmVtaXVtLWRhdGEiLCJkZXNjcmlwdGlvbiI6IkFjY2VzcyB0byBwcmVtaXVtIG1hcmtldCBkYXRhIiwibWltZVR5cGUiOiJhcHBsaWNhdGlvbi9qc29uIn0sImFjY2VwdHMiOlt7InNjaGVtZSI6ImV4YWN0IiwibmV0d29yayI6ImVpcDE1NTo4NDUzMiIsImFtb3VudCI6IjEwMDAwIiwiYXNzZXQiOiIweDAzNkNiRDUzODQyYzU0MjY2MzRlNzkyOTU0MWVDMjMxOGYzZENGN2UiLCJwYXlUbyI6IjB4MjA5NjkzQmM2YWZjMEM1MzI4YkEzNkZhRjAzQzUxNEVGMzEyMjg3QyIsIm1heFRpbWVvdXRTZWNvbmRzIjo2MCwiZXh0cmEiOnsibmFtZSI6IlVTREMiLCJ2ZXJzaW9uIjoiMiJ9fV19";
const SPEC_V2_PAYMENT_SIGNATURE =
  "eyJ4NDAyVmVyc2lvbiI6MiwicmVzb3VyY2UiOnsidXJsIjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20vcHJlbWl1bS1kYXRhIiwiZGVzY3JpcHRpb24iOiJBY2Nlc3MgdG8gcHJlbWl1bSBtYXJrZXQgZGF0YSIsIm1pbWVUeXBlIjoiYXBwbGljYXRpb24vanNvbiJ9LCJhY2NlcHRlZCI6eyJzY2hlbWUiOiJleGFjdCIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MzIiLCJhbW91bnQiOiIxMDAwMCIsImFzc2V0IjoiMHgwMzZDYkQ1Mzg0MmM1NDI2NjM0ZTc5Mjk1NDFlQzIzMThmM2RDRjdlIiwicGF5VG8iOiIweDIwOTY5M0JjNmFmYzBDNTMyOGJBMzZGYUYwM0M1MTRFRjMxMjI4N0MiLCJtYXhUaW1lb3V0U2Vjb25kcyI6NjAsImV4dHJhIjp7Im5hbWUiOiJVU0RDIiwidmVyc2lvbiI6IjIifX0sInBheWxvYWQiOnsic2lnbmF0dXJlIjoiMHgyZDZhNzU4OGQ2YWNjYTUwNWNiZjBkOWE0YTIyN2UwYzUyYzZjMzQwMDhjOGU4OTg2YTEyODMyNTk3NjQxNzM2MDhhMmNlNjQ5NjY0MmUzNzdkNmRhOGRiYmY1ODM2ZTliZDE1MDkyZjllY2FiMDVkZWQzZDYyOTNhZjE0OGI1NzFjIiwiYXV0aG9yaXphdGlvbiI6eyJmcm9tIjoiMHg4NTdiMDY1MTlFOTFlM0E1NDUzODc5MWJEYmIwRTIyMzczZTM2YjY2IiwidG8iOiIweDIwOTY5M0JjNmFmYzBDNTMyOGJBMzZGYUYwM0M1MTRFRjMxMjI4N0MiLCJ2YWx1ZSI6IjEwMDAwIiwidmFsaWRBZnRlciI6IjE3NDA2NzIwODkiLCJ2YWxpZEJlZm9yZSI6IjE3NDA2NzIxNTQiLCJub25jZSI6IjB4ZjM3NDY2MTNjMmQ5MjBiNWZkYWJjMDg1NmYyYWViMmQ0Zjg4ZWU2MDM3YjhjYzVkMDRhNzFhNDQ2MmYxMzQ4MCJ9fX0=";
const SPEC_V2_SETTLEMENT_OK =
  "eyJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IjB4MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZiIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MzIiLCJwYXllciI6IjB4ODU3YjA2NTE5RTkxZTNBNTQ1Mzg3OTFiRGJiMEUyMjM3M2UzNmI2NiJ9";
const SPEC_V2_SETTLEMENT_FAIL =
  "eyJzdWNjZXNzIjpmYWxzZSwiZXJyb3JSZWFzb24iOiJpbnN1ZmZpY2llbnRfZnVuZHMiLCJ0cmFuc2FjdGlvbiI6IiIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MzIiLCJwYXllciI6IjB4ODU3YjA2NTE5RTkxZTNBNTQ1Mzg3OTFiRGJiMEUyMjM3M2UzNmI2NiJ9";

const decodeB64Json = (b) => JSON.parse(Buffer.from(b, "base64").toString("utf8"));

const v2VersionCases = [
  {
    label: "absent",
    body: {
      resource: { url: "https://api.example.com/premium-data" },
      accepts: decodeB64Json(SPEC_V2_PAYMENT_REQUIRED).accepts,
    },
  },
  ...[2, 1, "2", 0, -7, 1.5, null, {}, [], 3].map((v) => ({
    label: JSON.stringify(v) ?? String(v),
    body: {
      x402Version: v,
      resource: { url: "https://api.example.com/premium-data" },
      accepts: decodeB64Json(SPEC_V2_PAYMENT_REQUIRED).accepts,
    },
  })),
];

write("x402-http-v2.json", {
  description:
    "x402 v2 HTTP carrier conformance. All protocol data travels in headers: the 402 " +
    "carries PAYMENT-REQUIRED (base64 JSON PaymentRequired; the body is a server " +
    "implementation concern), the paid retry carries PAYMENT-SIGNATURE (base64 JSON " +
    "PaymentPayload, built by the HOST's payer — Vaduno polices the requirement and never " +
    "constructs or signs the payload), settlement returns via PAYMENT-RESPONSE. The four " +
    "base64 blobs are VERBATIM from the spec's transports-v2/http.md examples " +
    "(coinbase/x402 @ dd927a26). `parsed` is the exact normalized output " +
    "parsePaymentRequiredHeader must produce from the spec's PAYMENT-REQUIRED blob. " +
    "`versionOutcomes` freezes the TOTAL version decision table for this carrier: only the " +
    "integer 2 parses; absent and 1 are refusals (version confusion on a v2-only carrier), " +
    "and no non-integer is ever guessed at.",
  headers: {
    paymentRequired: "PAYMENT-REQUIRED",
    payment: "PAYMENT-SIGNATURE",
    settlement: "PAYMENT-RESPONSE",
  },
  specExample: {
    paymentRequiredHeader: SPEC_V2_PAYMENT_REQUIRED,
    paymentRequiredDecoded: decodeB64Json(SPEC_V2_PAYMENT_REQUIRED),
    parsed: parsePaymentRequiredHeader(SPEC_V2_PAYMENT_REQUIRED),
    paymentSignatureHeader: SPEC_V2_PAYMENT_SIGNATURE,
    paymentSignatureDecoded: decodeB64Json(SPEC_V2_PAYMENT_SIGNATURE),
    settlementOkHeader: SPEC_V2_SETTLEMENT_OK,
    settlementOkDecoded: decodeSettlementResponse(SPEC_V2_SETTLEMENT_OK),
    settlementFailHeader: SPEC_V2_SETTLEMENT_FAIL,
    settlementFailDecoded: decodeSettlementResponse(SPEC_V2_SETTLEMENT_FAIL),
  },
  versionOutcomes: v2VersionCases.map(({ label, body }) => ({
    x402Version: label,
    body,
    ...outcomeOf(() =>
      parsePaymentRequiredHeader(Buffer.from(JSON.stringify(body), "utf8").toString("base64")),
    ),
  })),
});

console.log("\nvectors regenerated — a diff here is a WIRE FORMAT CHANGE");
