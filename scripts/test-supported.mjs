#!/usr/bin/env node
/**
 * Run each package's tests, skipping any package whose declared `engines.node`
 * excludes the Node currently running.
 *
 * WHY THIS EXISTS. CI tests the matrix down to Node 18 because seven of the
 * eight packages genuinely support it. @vaduno/cloudflare does not: its test rig
 * calls viem's `generatePrivateKey()`, which needs global WebCrypto, and
 * `globalThis.crypto` only became a global in Node 19. viem declares no
 * `engines` of its own, so nothing announced that requirement — it surfaced as
 * `crypto is not defined` on one matrix leg and a red build on every push.
 *
 * The fix is NOT to drop Node 18 from the matrix (that would delete real
 * coverage for the seven packages that support it) and NOT to hardcode "skip
 * cloudflare on 18" (a list that must be remembered will drift, which this repo
 * has now been bitten by twice). Instead each package states the truth in its
 * own `engines`, and this script reads it. A package that later drops Node 18
 * needs no CI change; one that regains support needs none either.
 *
 * The check is deliberately simple — `>=X` / `>=X.Y.Z` on the major — because
 * that is the only form these packages use. Anything it cannot parse is RUN
 * rather than skipped: an unparseable range must not silently delete coverage,
 * which is the failure mode this whole script exists to avoid.
 */
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const current = Number(process.versions.node.split(".")[0]);

/** Minimum major a range demands, or null when it does not constrain one. */
function minimumMajor(range) {
  if (typeof range !== "string") return null;
  const m = /^\s*>=\s*v?(\d+)/.exec(range);
  return m ? Number(m[1]) : null;
}

const packages = readdirSync(join(root, "packages"), { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(join(root, "packages", d.name, "package.json")))
  .map((d) => d.name)
  .sort();

const skipped = [];
let ran = 0;

for (const dir of packages) {
  const pkg = JSON.parse(readFileSync(join(root, "packages", dir, "package.json"), "utf8"));
  const min = minimumMajor(pkg.engines?.node);

  if (min !== null && current < min) {
    skipped.push(`${pkg.name} (needs node >=${min}, running ${current})`);
    continue;
  }

  console.log(`\n─── ${pkg.name} ───`);
  execFileSync("npm", ["run", "test", "-w", pkg.name], {
    cwd: root,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  ran += 1;
}

// Say what was skipped and why. A silent skip is indistinguishable from a pass,
// and this repo keeps finding that exact shape of bug.
console.log(`\n${ran} package(s) tested on node ${current}.`);
if (skipped.length) {
  console.log(`${skipped.length} skipped by declared engines:`);
  for (const s of skipped) console.log(`  - ${s}`);
}
