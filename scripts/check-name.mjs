#!/usr/bin/env node
/**
 * Name clearance gate.  Usage:  node scripts/check-name.mjs <candidate>
 *
 * WHY THIS EXISTS: this project collided twice in one day — "Paygent" (an
 * existing npm package + company) and "Swale" (SWALE IO, INC. holds a pending
 * USPTO mark in classes 009 + 042, our exact classes). Both were preventable.
 * Both times npm/GitHub/domains were checked and the TRADEMARK check was left
 * as an advisory step — so it didn't happen until after publishing.
 *
 * The lesson is not "check trademarks". It is "an advisory step is a step that
 * does not happen". So this gate FAILS CLOSED: it cannot report success unless
 * a human has pasted in what the USPTO search actually returned.
 *
 * The classes that matter for a developer-tools / payments project:
 *   IC 009 — downloadable software (an npm package IS class 009)
 *   IC 042 — SaaS, software-as-a-service
 *   IC 036 — financial services, payments
 * A live mark in ANY of those is disqualifying. A live mark in an unrelated
 * class (landscaping, disc jockeys, furniture) is not.
 */
import { createInterface } from "node:readline/promises";
import { stdin, stdout, argv, exit } from "node:process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const name = (argv[2] ?? "").trim().toLowerCase();

if (!name || !/^[a-z][a-z0-9-]{1,38}$/.test(name)) {
  console.error("usage: node scripts/check-name.mjs <candidate>   (lowercase, a-z0-9-)");
  exit(2);
}

const OK = "\x1b[32m✅\x1b[0m";
const NO = "\x1b[31m❌\x1b[0m";
const WARN = "\x1b[33m⚠️ \x1b[0m";

async function head(url) {
  try {
    const { stdout: out } = await run("curl", [
      "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L", "--max-time", "15", "--ssl-no-revoke", url,
    ]);
    return out.trim();
  } catch {
    return "000";
  }
}

async function json(url) {
  try {
    const { stdout: out } = await run("curl", ["-s", "--max-time", "15", "--ssl-no-revoke", url]);
    return out;
  } catch {
    return "";
  }
}

async function dnsFree(host) {
  try {
    const { stdout: out, stderr } = await run("nslookup", [host]);
    return /NXDOMAIN|can't find|No answer/i.test(out + stderr);
  } catch (e) {
    // nslookup exits non-zero on NXDOMAIN
    return /NXDOMAIN|can't find|No answer/i.test(String(e.stdout ?? "") + String(e.stderr ?? ""));
  }
}

console.log(`\n  Clearance check for "${name}"\n  ${"─".repeat(50)}`);

const blockers = [];
const notes = [];

// 1. npm package name — this is what blocks creating an org of the same name.
const pkg = await json(`https://registry.npmjs.org/${name}`);
const pkgFree = /"error":"[Nn]ot found"/.test(pkg);
console.log(`  ${pkgFree ? OK : NO} npm package  ${name}`);
if (!pkgFree) blockers.push(`npm package "${name}" exists — this also BLOCKS creating the @${name} org`);

// 2. npm username — also blocks org creation.
const user = await json(`https://registry.npmjs.org/-/user/org.couchdb.user:${name}`);
const userFree = /"ok":false|"error"/.test(user);
console.log(`  ${userFree ? OK : NO} npm user     ${name}`);
if (!userFree) blockers.push(`an npm user named "${name}" exists — blocks the org`);

// 3. GitHub org / user.
const gh = await head(`https://github.com/${name}`);
const ghFree = gh === "404";
console.log(`  ${ghFree ? OK : NO} github.com/${name}${ghFree ? "" : `  (HTTP ${gh})`}`);
if (!ghFree) notes.push(`github.com/${name} is taken — you can still use ${name}hq or ${name}-dev`);

// 4. Domains.
const tlds = ["com", "dev", "io", "sh", "co"];
const domains = [];
for (const t of tlds) {
  const free = await dnsFree(`${name}.${t}`);
  domains.push([`${name}.${t}`, free]);
}
console.log(
  "  " + domains.map(([d, f]) => `${f ? OK : NO} ${d}`).join("   "),
);
const anyDomain = domains.some(([, f]) => f);
if (!anyDomain) blockers.push("no domain free on .com/.dev/.io/.sh/.co");

// 5. A same-named company anywhere is the signal that caught neither collision
//    in time. If a domain is TAKEN, say who — that is the thread we failed to
//    pull on swale.io.
const takenDomains = domains.filter(([, f]) => !f).map(([d]) => d);
if (takenDomains.length) {
  console.log(`\n  ${WARN} These resolve — check WHO owns them before proceeding:`);
  for (const d of takenDomains) console.log(`       https://${d}`);
  console.log(`     A same-space company here is disqualifying even with no trademark.`);
}

// 6. TRADEMARK — the step that must never be skipped again.
console.log(`\n  ${"─".repeat(50)}\n  TRADEMARK (this is the check that failed twice)\n`);
console.log(`  Open:  https://tmsearch.uspto.gov/search/search-results?q=${encodeURIComponent(name)}`);
console.log(`
  1. Untick "Dead" in the Status filter — dead marks do not matter.
  2. For each LIVE result, read the "Class" line.
  3. DISQUALIFYING classes:  009 (software)  ·  042 (SaaS)  ·  036 (financial)
     Any other class (landscaping, DJs, furniture, chemicals) is fine.
`);

const rl = createInterface({ input: stdin, output: stdout });
const live = (await rl.question("  How many LIVE marks are in class 009, 036 or 042? (number, or 'skip') > ")).trim();
rl.close();

console.log(`\n  ${"─".repeat(50)}`);

if (live.toLowerCase() === "skip" || live === "") {
  console.log(`  ${NO} NOT CLEARED — the trademark check was skipped.`);
  console.log(`     Skipping this exact step is what cost this project two names.`);
  exit(1);
}
const conflicts = Number(live);
if (!Number.isInteger(conflicts) || conflicts < 0) {
  console.log(`  ${NO} NOT CLEARED — answer not understood.`);
  exit(1);
}
if (conflicts > 0) {
  blockers.push(`${conflicts} live USPTO mark(s) in class 009/036/042 — disqualifying`);
}

if (blockers.length) {
  console.log(`  ${NO} NOT CLEARED\n`);
  for (const b of blockers) console.log(`     • ${b}`);
  if (notes.length) {
    console.log("");
    for (const n of notes) console.log(`     ${WARN} ${n}`);
  }
  console.log("");
  exit(1);
}

console.log(`  ${OK} CLEARED — "${name}" is free on npm, GitHub, a domain, and USPTO 009/036/042.`);
if (notes.length) for (const n of notes) console.log(`     ${WARN} ${n}`);
console.log(`
  Reminder: this is a screening check, not legal clearance, and it covers the
  US register only (EUIPO is separate). Good enough to publish MIT open source;
  not good enough to bet a company on.
`);
