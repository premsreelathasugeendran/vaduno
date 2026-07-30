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
  MandateManager,
  AuditLedger,
  MemoryLedgerStore,
  intentDigest,
} from "../packages/guard/dist/index.js";

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

console.log("\nvectors regenerated — a diff here is a WIRE FORMAT CHANGE");
