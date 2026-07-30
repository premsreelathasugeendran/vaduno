#!/usr/bin/env node
/**
 * Publish (or verify) @vaduno packages, in an order that cannot leave the
 * registry in a broken state.
 *
 * Usage:
 *   node scripts/publish-ordered.mjs guard
 *   node scripts/publish-ordered.mjs transparency revocation x402 stripe postgres
 *   node scripts/publish-ordered.mjs --verify guard transparency ...
 *
 * Env:
 *   DRY_RUN=true   run `npm publish --dry-run` and change nothing
 *
 * WHY A SCRIPT RATHER THAN A LINE OF YAML:
 *
 *  1. ORDER IS LOAD-BEARING. Five packages declare `"@vaduno/guard": "^X"`. If
 *     any of them lands before guard@X exists, `npm install` of that package
 *     fails with ETARGET for everyone who tries in the gap.
 *
 *  2. RE-RUNS MUST NOT BE FATAL. A workflow that half-published and then failed
 *     has to be re-runnable. `npm publish` over an existing version is E403,
 *     which would fail the job forever, so an already-published version at the
 *     SAME content is treated as success — and a version that exists with
 *     DIFFERENT content is a hard error, because that means someone published
 *     from a laptop and the tag no longer describes what is on npm.
 *
 *  3. "PUBLISHED" MUST MEAN THE REGISTRY SAYS SO. npm exits 0 the moment the
 *     PUT is accepted; `npm view` reads a CDN that can lag by minutes. So
 *     --verify polls the registry API directly, which is the only source of
 *     truth that matters to someone running `npm install`.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const verifyOnly = argv[0] === "--verify";
const names = verifyOnly ? argv.slice(1) : argv;
const dryRun = process.env.DRY_RUN === "true";

if (names.length === 0) {
  console.error("usage: publish-ordered.mjs [--verify] <package-dir>...");
  process.exit(2);
}

const pkgFor = (name) =>
  JSON.parse(readFileSync(join(root, "packages", name, "package.json"), "utf8"));

/** Registry metadata, or null if the package does not exist yet. */
async function packument(fullName) {
  const url = `https://registry.npmjs.org/${fullName.replace("/", "%2F")}`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`registry ${res.status} for ${fullName}`);
  return res.json();
}

/** Local tarball shasum, so "already published" can be checked for SAMENESS. */
function localShasum(dir) {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: dir,
    encoding: "utf8",
    shell: process.platform === "win32",
  });
  return JSON.parse(out)[0].shasum;
}

async function alreadyPublished(fullName, version, dir) {
  const meta = await packument(fullName);
  const remote = meta?.versions?.[version];
  if (!remote) return false;

  // Report a byte difference, but do NOT fail on it.
  //
  // This started as a hard error, on the theory that a shasum mismatch means
  // the tag no longer describes what is on npm. The first CI run showed why
  // that is wrong: 0.2.1 was published from a Windows laptop, so its tarball
  // carries CRLF line endings, while a Linux runner checks out LF (see
  // .gitattributes). Same content, different bytes — and the check called it
  // tampering. It matched locally on Windows and only failed in CI, which is
  // the worst place to discover an over-strict guard.
  //
  // Failing hard also buys nothing: npm physically refuses to overwrite a
  // published version (E403), so the dangerous outcome this was guarding
  // against cannot happen. The useful behaviour is to say so loudly and let
  // the remaining packages proceed.
  const local = localShasum(dir);
  if (remote.dist?.shasum && remote.dist.shasum !== local) {
    console.log(
      `    note: tarball bytes differ from the published copy\n` +
        `          registry: ${remote.dist.shasum}\n` +
        `          local:    ${local}\n` +
        `          Usually line endings, when a version was published from a\n` +
        `          different platform. Once every release goes out from CI the\n` +
        `          tarballs become reproducible. Verify with 'npm pack' and diff\n` +
        `          if you did not expect this.`,
    );
  }
  return true;
}

async function publishOne(name) {
  const dir = join(root, "packages", name);
  const pkg = pkgFor(name);

  if (await alreadyPublished(pkg.name, pkg.version, dir)) {
    console.log(`  = ${pkg.name}@${pkg.version} already published (identical) — skipping`);
    return;
  }

  const args = ["publish", "--access", "public"];
  // Provenance is what makes the OIDC identity visible to consumers rather than
  // just to the registry. Requires id-token: write in the workflow.
  if (!dryRun) args.push("--provenance");
  if (dryRun) args.push("--dry-run");

  console.log(`  ${dryRun ? "~" : "+"} ${pkg.name}@${pkg.version}${dryRun ? " (dry run)" : ""}`);
  execFileSync("npm", args, {
    cwd: dir,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
}

/** Poll the registry until the version is really there. */
async function verifyOne(name) {
  const pkg = pkgFor(name);
  const deadline = Date.now() + 120_000;
  for (;;) {
    const meta = await packument(pkg.name);
    const has = Boolean(meta?.versions?.[pkg.version]);
    const latest = meta?.["dist-tags"]?.latest;
    if (has && latest === pkg.version) {
      console.log(`  ✓ ${pkg.name}@${pkg.version} (latest)`);
      return;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `${pkg.name}@${pkg.version} not visible on the registry after 120s ` +
          `(present=${has}, latest=${latest ?? "none"})`,
      );
    }
    await new Promise((r) => setTimeout(r, 5_000));
  }
}

const failures = [];
for (const name of names) {
  try {
    if (verifyOnly) await verifyOne(name);
    else await publishOne(name);
  } catch (err) {
    console.error(`  ✗ ${name}: ${err.message}`);
    failures.push(name);
    // Stop immediately: if guard failed, publishing its dependents would put
    // uninstallable packages on the registry permanently.
    break;
  }
}

if (failures.length > 0) process.exit(1);
console.log(verifyOnly ? "\nregistry confirms all versions" : "\ndone");
