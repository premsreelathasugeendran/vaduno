#!/usr/bin/env node
/**
 * Archive and remove stale linked git worktrees — without ever being able to
 * destroy work that was not first archived and proven restorable.
 *
 * Usage:
 *   node scripts/clean-worktrees.mjs                  # DRY RUN: report only, change nothing
 *   node scripts/clean-worktrees.mjs --apply          # actually archive + delete
 *   node scripts/clean-worktrees.mjs --apply --max-age-hours 48
 *   node scripts/clean-worktrees.mjs --root path/to/worktrees --archive-dir D:\backups\wt
 *
 * Run with --help for the full flag and exit-code reference.
 *
 * WHY THIS SCRIPT IS SHAPED THE WAY IT IS — every rule below was learned from a
 * real 16-worktree, 3.8 GB manual cleanup that nearly went wrong, or from an
 * adversarial review of this script that found a way to lose data:
 *
 *  1. DRY RUN IS THE DEFAULT, AND THERE IS NO UNATTENDED MODE. An unattended
 *     cleanup hook silently deletes a worktree whose diff was never actually
 *     reviewed — the exact "reports success while dropping what it could not
 *     handle" bug this project keeps re-finding, automated. One safe command,
 *     run on purpose.
 *
 *  2. UNTRACKED FILES ARE PART OF THE ARCHIVE. `git diff` does not see
 *     untracked files. The obvious "archive the diffs then delete" plan feels
 *     thorough and would have silently destroyed 39 real files — whole new
 *     test suites and new source — in the cleanup that motivated this tool.
 *
 *  3. GITIGNORED FILES ARE PART OF THE ARCHIVE TOO. `git diff` AND the plain
 *     untracked list are both blind to .env files, local keys, and other
 *     ignored-but-precious state. Everything git reports as ignored is
 *     archived as well, EXCEPT directories on the short build-output list
 *     (node_modules, dist, coverage, .turbo, .next, .nuxt) — and those are
 *     excluded only when git itself says they are ignored. An untracked file
 *     under one of those names that is NOT gitignored blocks that worktree's
 *     deletion entirely: the tool refuses to guess whether it is build
 *     output. Every excluded path is named in the report — an unlisted
 *     exclusion would be a silent drop.
 *
 *  4. STAGED AND UNSTAGED STATE ARE ARCHIVED SEPARATELY. A single
 *     `git diff HEAD` flattens the index into the working tree: when a file's
 *     staged version differs from its working-tree version, one of the two is
 *     silently lost. Two patches are kept: <name>.staged.patch (base → index)
 *     and <name>.patch (base → working tree).
 *
 *  5. NOTHING IS DELETED UNTIL ITS ARCHIVE IS PROVEN RESTORABLE. "The file
 *     exists" is not proof. Before any deletion: the base SHA must resolve to
 *     a commit, every archived copy must hash-match what was read from the
 *     worktree, both patch files must hash-match what was written, and each
 *     non-empty patch must pass `git apply --check` against a temporary
 *     detached worktree created at the base SHA (removed afterwards). If any
 *     check fails, that worktree is skipped ENTIRELY and the run exits
 *     non-zero. Fail closed.
 *
 *  6. THE WORKTREE IS RE-CHECKED IMMEDIATELY BEFORE DELETION. A file created
 *     after the archive snapshot (an agent still writing) would be deleted
 *     unarchived. Right before removal the tool re-fingerprints the worktree
 *     (both diffs, every untracked/ignored file hash); any difference from
 *     the archived fingerprint aborts that deletion.
 *
 *  7. ARCHIVE NAMES CANNOT COLLIDE, AND A USED ARCHIVE DIR IS NEVER REUSED.
 *     Two worktrees with the same basename get distinct archive names, and a
 *     non-empty --archive-dir is refused outright — it may hold the only copy
 *     of work that was already deleted.
 *
 *  8. DELETION ORDER IS LOAD-BEARING ON WINDOWS. `git worktree remove --force`
 *     failed on 10 of 16 worktrees due to Windows file locks. The sequence
 *     that actually works: attempt `remove --force` per worktree, then run
 *     `git worktree prune` REGARDLESS of individual failures (prune cleans the
 *     metadata, demoting locked directories to ordinary folders), then plain
 *     recursive deletion of any directory git no longer tracks.
 *
 *  9. COMMITS ARE NEVER ORPHANED. A worktree's branch is deleted only if its
 *     tip is an ancestor of the default branch (`git merge-base
 *     --is-ancestor`); a branch holding unmerged commits is reported and kept
 *     — the archive captures uncommitted changes, not commits, so the branch
 *     is the only home those commits have. A DETACHED HEAD holding unmerged
 *     commits has no branch, so before deletion its commit is pinned by a
 *     `refs/worktree-archive/<name>` ref; otherwise `git gc` would destroy
 *     both the commits and the base the archive's patches apply to.
 *
 * 10. STALENESS NEEDS MORE THAN FILE MTIMES. File mtimes can be backdated,
 *     copied, or skewed. A worktree is stale only if its newest file mtime,
 *     its directory creation time, AND its git administrative directory
 *     (index/HEAD, touched by every git operation in the worktree) are all
 *     older than the threshold.
 *
 * 11. EVERY SKIP IS REPORTED WITH ITS REASON, AND EVERY SAFETY SKIP FAILS THE
 *     RUN. A silent skip is indistinguishable from a success, and that
 *     confusion is this project's most-repeated bug. A wrapper must not be
 *     able to mistake a partial run for a clean one.
 *
 * 12. DRY RUN IS BYTE-PURE. Every git call passes --no-optional-locks so even
 *     the index stat-cache refresh is suppressed: a dry run leaves the repo —
 *     including .git — bit-for-bit identical.
 *
 * ARCHIVE LAYOUT (per worktree <name>, matching the proven manual-recovery shape):
 *   <archive-dir>/<name>.patch          `git diff --binary HEAD` (base → working tree)
 *   <archive-dir>/<name>.staged.patch   `git diff --binary --cached` (base → index)
 *   <archive-dir>/<name>.base-sha       the commit both patches apply to
 *   <archive-dir>/<name>.untracked/...  every kept untracked AND ignored file, tree preserved
 *   <archive-dir>/<name>.meta.json      branch, hashes, counts, exclusions, fingerprint
 *   <archive-dir>/RESTORE.md            how to restore, written whenever anything is archived
 *
 * KNOWN LIMITS (deliberate, documented rather than silently absorbed):
 *   - Files inside a directory that is BOTH gitignored AND on the excluded
 *     list (e.g. hand-written notes inside an ignored dist/) are treated as
 *     build output and are not archived. The exclusion is printed per path.
 *   - The pre-deletion re-check closes the archive→delete race, but a write
 *     that lands in the microseconds between the re-check and the removal
 *     itself is fundamentally unwinnable. Do not run this against worktrees
 *     an agent is actively using — that is what the age threshold is for.
 *
 * TEST-ONLY FAULT INJECTION via VADUNO_CLEAN_WORKTREES_SABOTAGE:
 *   corrupt-patch:<name>  corrupts <name>'s archived patch after writing, so
 *                         the test suite can prove `git apply --check` fails
 *                         closed.
 *   plant-file:<name>     plants a file in <name>'s worktree after archiving,
 *                         so the test suite can prove the pre-deletion
 *                         re-check aborts the deletion.
 * Both print a loud warning and have no effect unless the variable is set.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

// ─── configuration ──────────────────────────────────────────────────────────

/**
 * Directory names treated as build output / dependencies and NOT archived —
 * but ONLY when git itself reports them as ignored. A path under one of these
 * names that git does NOT ignore blocks the worktree instead (fail closed):
 * git considering it real work and the name claiming build output is a
 * contradiction this tool refuses to resolve by guessing. Every excluded path
 * is named in the report.
 */
const EXCLUDED_DIR_NAMES = new Set([
  "node_modules",
  "dist",
  "coverage",
  ".turbo",
  ".next",
  ".nuxt",
]);

// Never descend into these when computing the age of a worktree (but their own
// mtime still counts — an `npm install` touching node_modules marks activity).
const AGE_SCAN_SKIP = new Set([...EXCLUDED_DIR_NAMES, ".git"]);

const DEFAULT_MAX_AGE_HOURS = 24;

const HELP = `usage: node scripts/clean-worktrees.mjs [flags]

Archives and removes stale linked git worktrees. DRY RUN by default: without
--apply it only reports what it would do and changes nothing — not even the
git index (every git call runs with --no-optional-locks).

The archive taken before any deletion captures, per worktree:
  - the tracked diff (base -> working tree) as <name>.patch
  - the staged state (base -> index) separately as <name>.staged.patch,
    because a single diff would lose staged-vs-worktree divergence
  - every untracked file AND every gitignored file (.env and friends),
    individually sha256-hashed — git diff is blind to both
  - build-output directories (node_modules, dist, coverage, .turbo, .next,
    .nuxt) are excluded ONLY when gitignored, and each exclusion is printed;
    a non-ignored file under such a name blocks that worktree entirely
Nothing is deleted until the archive is verified: base SHA resolves, every
copy hash-matches, and both patches pass git apply --check at the base SHA.
The worktree is re-fingerprinted immediately before removal; any change since
archiving aborts that deletion. Detached HEADs holding unmerged commits are
pinned with a refs/worktree-archive/* ref before removal; unmerged branches
are kept. A non-empty --archive-dir is refused.

Flags:
  --apply                 execute. Without it this is a dry run.
  --repo <dir>            repository to operate on (default: repo containing cwd)
  --root <dir>            only consider worktrees under this directory
                          (default: any linked worktree inside the repo
                          checkout). With an explicit --root, unregistered
                          directories there are reported and never touched.
  --archive-dir <dir>     where the archive goes (default:
                          <repo-parent>/<repo>-worktree-archive/<stamp>).
                          Must not already contain files.
  --max-age-hours <n>     skip worktrees with any activity newer than this
                          (default: ${DEFAULT_MAX_AGE_HOURS}). Activity = newest file mtime, the
                          worktree's creation time, or its git admin dir.
  --default-branch <name> branch merged work must be an ancestor of
                          (default: origin/HEAD, then main, then master)
  --help, -h              this text

Exit codes:
  0  clean run. Skips for freshness or a git lock are normal and reported.
  1  a SAFETY condition: archive verification failed, the worktree changed
     after archiving, a directory could not be deleted, an unmerged branch or
     detached commit was kept/pinned, a non-ignored file sat under an
     excluded name, or an unregistered directory was found under --root.
  2  usage error (bad flag, unresolvable branch, non-empty archive dir).
`;

// ─── small helpers ──────────────────────────────────────────────────────────

function git(args, opts = {}) {
  // --no-optional-locks: reads must not mutate the repo (a bare `git status`
  // otherwise rewrites the index stat-cache, breaking dry-run purity).
  const res = spawnSync("git", ["--no-optional-locks", ...args], {
    encoding: opts.binary ? "buffer" : "utf8",
    cwd: opts.cwd,
    maxBuffer: 256 * 1024 * 1024,
  });
  if (res.error) throw res.error;
  if (res.status !== 0 && !opts.allowFail) {
    const err = opts.binary ? res.stderr?.toString() : res.stderr;
    throw new Error(`git ${args.join(" ")} failed (exit ${res.status}): ${err ?? ""}`.trim());
  }
  return res;
}

const hashBytes = (buf) => createHash("sha256").update(buf).digest("hex");
const sha256File = (path) => hashBytes(readFileSync(path));

const norm = (p) => {
  const r = resolve(p);
  return process.platform === "win32" ? r.toLowerCase() : r;
};
const isInside = (child, parent) => norm(child).startsWith(norm(parent) + sep);

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(2);
}

// ─── argument parsing ───────────────────────────────────────────────────────

function parseArgs(argv) {
  const opts = {
    apply: false,
    repo: null,
    root: null,
    archiveDir: null,
    maxAgeHours: DEFAULT_MAX_AGE_HOURS,
    defaultBranch: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) fail(`${a} requires a value`);
      return argv[++i];
    };
    if (a === "--apply") opts.apply = true;
    else if (a === "--repo") opts.repo = next();
    else if (a === "--root") opts.root = next();
    else if (a === "--archive-dir") opts.archiveDir = next();
    else if (a === "--default-branch") opts.defaultBranch = next();
    else if (a === "--max-age-hours") {
      opts.maxAgeHours = Number(next());
      if (!Number.isFinite(opts.maxAgeHours) || opts.maxAgeHours < 0)
        fail("--max-age-hours must be a number >= 0");
    } else if (a === "--help" || a === "-h") {
      console.log(HELP);
      process.exit(0);
    } else fail(`unknown argument: ${a}`);
  }
  return opts;
}

// ─── discovery ──────────────────────────────────────────────────────────────

/** Parse `git worktree list --porcelain` into worktree records. */
function listWorktrees(repoRoot) {
  const out = git(["-C", repoRoot, "worktree", "list", "--porcelain"]).stdout;
  const worktrees = [];
  let cur = null;
  for (const line of out.split(/\r?\n/)) {
    if (line.startsWith("worktree ")) {
      cur = { path: resolve(line.slice("worktree ".length)), branch: null, head: null, locked: false, detached: false };
      worktrees.push(cur);
    } else if (!cur) continue;
    else if (line.startsWith("HEAD ")) cur.head = line.slice(5).trim();
    else if (line.startsWith("branch refs/heads/")) cur.branch = line.slice("branch refs/heads/".length).trim();
    else if (line === "detached") cur.detached = true;
    else if (line === "locked" || line.startsWith("locked ")) cur.locked = true;
  }
  return worktrees;
}

function resolveDefaultBranch(repoRoot, requested) {
  if (requested) {
    const r = git(["-C", repoRoot, "rev-parse", "--verify", "--quiet", requested], { allowFail: true });
    if (r.status !== 0) fail(`--default-branch ${requested} does not resolve in this repo`);
    return requested;
  }
  const originHead = git(["-C", repoRoot, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], { allowFail: true });
  if (originHead.status === 0) {
    const short = originHead.stdout.trim().replace("refs/remotes/origin/", "");
    // prefer the local branch of that name if it exists, else the remote ref
    const local = git(["-C", repoRoot, "rev-parse", "--verify", "--quiet", `refs/heads/${short}`], { allowFail: true });
    return local.status === 0 ? short : `origin/${short}`;
  }
  for (const cand of ["main", "master"]) {
    const r = git(["-C", repoRoot, "rev-parse", "--verify", "--quiet", `refs/heads/${cand}`], { allowFail: true });
    if (r.status === 0) return cand;
  }
  fail("could not determine the default branch; pass --default-branch");
}

/** Newest mtime (ms) anywhere in the tree; excluded dirs count by their own mtime only. */
function newestMtimeMs(dir) {
  let newest = statSync(dir).mtimeMs;
  const stack = [dir];
  while (stack.length > 0) {
    const d = stack.pop();
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      continue; // unreadable dir: its own mtime already counted
    }
    for (const e of entries) {
      const p = join(d, e.name);
      let st;
      try {
        st = lstatSync(p);
      } catch {
        continue;
      }
      if (st.mtimeMs > newest) newest = st.mtimeMs;
      if (e.isDirectory() && !AGE_SCAN_SKIP.has(e.name)) stack.push(p);
    }
  }
  return newest;
}

/**
 * Newest evidence of activity for a worktree. File mtimes alone are not
 * evidence of recency (they can be backdated, copied, or skewed), so the
 * worktree's own creation time and its git administrative directory — which
 * every git operation in the worktree touches — count too.
 */
function newestActivityMs(wt) {
  let newest = newestMtimeMs(wt.path);
  try {
    const st = statSync(wt.path);
    if (st.birthtimeMs > newest) newest = st.birthtimeMs;
  } catch {
    /* fall through: mtimes still counted */
  }
  const gd = git(["-C", wt.path, "rev-parse", "--absolute-git-dir"], { allowFail: true });
  if (gd.status === 0) {
    const adminDir = resolve(gd.stdout.trim());
    if (existsSync(adminDir)) {
      const m = newestMtimeMs(adminDir);
      if (m > newest) newest = m;
    }
  }
  return newest;
}

// ─── worktree state snapshot (archive source + TOCTOU fingerprint) ──────────

/**
 * Classify everything `git status` reports as untracked (`??`) or ignored
 * (`!!`, via --ignored=matching so wholly-ignored directories appear as one
 * entry). Returns:
 *   kept:     entries to archive ({rel, ignored, isDir})
 *   excluded: IGNORED entries under an excluded build-output name
 *   blockers: NON-ignored entries under an excluded name — git calls them
 *             real work, the name says build output; fail closed.
 */
function classifyStatus(wtPath) {
  const out = git(["-C", wtPath, "status", "--porcelain=v1", "-z", "--ignored=matching", "-uall"]).stdout;
  const kept = [];
  const excluded = [];
  const blockers = [];
  for (const entry of out.split("\0")) {
    const code = entry.slice(0, 3);
    if (code !== "?? " && code !== "!! ") continue;
    const rel = entry.slice(3);
    const ignored = code === "!! ";
    const isDir = rel.endsWith("/");
    const matchesExcluded = rel.replace(/\/$/, "").split("/").some((s) => EXCLUDED_DIR_NAMES.has(s));
    if (matchesExcluded) (ignored ? excluded : blockers).push(rel);
    else kept.push({ rel, ignored, isDir });
  }
  excluded.sort();
  blockers.sort();
  return { kept, excluded, blockers };
}

/** Expand kept entries into individual files (walking kept directories). */
function expandKeptFiles(wtPath, kept) {
  const files = [];
  for (const k of kept) {
    if (!k.isDir) {
      files.push({ rel: k.rel, ignored: k.ignored });
      continue;
    }
    const stack = [k.rel.replace(/\/$/, "")];
    while (stack.length > 0) {
      const d = stack.pop();
      for (const e of readdirSync(join(wtPath, d), { withFileTypes: true })) {
        const rel = `${d}/${e.name}`;
        if (e.isDirectory()) stack.push(rel);
        else files.push({ rel, ignored: k.ignored });
      }
    }
  }
  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return files;
}

/**
 * Full snapshot of a worktree's restorable state: both diffs, every kept
 * untracked/ignored file with its hash, and a fingerprint over all of it.
 * The same snapshot is used to WRITE the archive and, recomputed, to detect
 * any change immediately before deletion (TOCTOU guard).
 */
function snapshotWorktree(wtPath) {
  const cls = classifyStatus(wtPath);
  const patch = git(["-C", wtPath, "diff", "--binary", "HEAD"], { binary: true }).stdout;
  const staged = git(["-C", wtPath, "diff", "--binary", "--cached"], { binary: true }).stdout;
  const untracked = expandKeptFiles(wtPath, cls.kept).map((f) => {
    const abs = join(wtPath, f.rel);
    return { path: f.rel, ignored: f.ignored, bytes: statSync(abs).size, sha256: sha256File(abs) };
  });
  const fingerprint = hashBytes(
    JSON.stringify({
      patch: hashBytes(patch),
      staged: hashBytes(staged),
      files: untracked.map(({ path, sha256 }) => ({ path, sha256 })),
      excluded: cls.excluded,
      blockers: cls.blockers,
    }),
  );
  return { cls, patch, staged, untracked, fingerprint };
}

// ─── archive ────────────────────────────────────────────────────────────────

/** Collision-proof archive names: duplicate basenames get a path-hash suffix. */
function assignArchiveNames(worktrees) {
  const counts = new Map();
  for (const wt of worktrees) {
    const base = wt.path.split(sep).pop();
    counts.set(base, (counts.get(base) ?? 0) + 1);
  }
  const names = new Map();
  for (const wt of worktrees) {
    const base = wt.path.split(sep).pop();
    names.set(
      wt.path,
      counts.get(base) > 1 ? `${base}-${hashBytes(norm(wt.path)).slice(0, 8)}` : base,
    );
  }
  return names;
}

function archiveWorktree(wt, name, archiveDir, snap) {
  mkdirSync(archiveDir, { recursive: true });

  const baseSha = git(["-C", wt.path, "rev-parse", "HEAD"]).stdout.trim();

  // Test-only fault injection — proves the verify step fails closed. It
  // corrupts a hunk body (a "-" context line) so the patch no longer matches
  // the base; merely appending garbage is NOT enough, because `git apply`
  // silently tolerates trailing non-patch text. The corruption happens BEFORE
  // hashing, so the hash check passes and `git apply --check` itself is what
  // must catch it.
  let patchBytes = snap.patch;
  if (process.env.VADUNO_CLEAN_WORKTREES_SABOTAGE === `corrupt-patch:${name}`) {
    console.log(`  !! SABOTAGE (test-only): corrupting archived patch for ${name}`);
    patchBytes = Buffer.from(
      snap.patch.toString("utf8").replace(/^-(?!--)(.*)$/m, "-CORRUPTED LINE THAT CANNOT MATCH THE BASE"),
    );
  }

  writeFileSync(join(archiveDir, `${name}.patch`), patchBytes);
  writeFileSync(join(archiveDir, `${name}.staged.patch`), snap.staged);
  writeFileSync(join(archiveDir, `${name}.base-sha`), baseSha + "\n");

  for (const f of snap.untracked) {
    const dst = join(archiveDir, `${name}.untracked`, f.path);
    mkdirSync(dirname(dst), { recursive: true });
    copyFileSync(join(wt.path, f.path), dst);
  }

  const meta = {
    name,
    worktree: wt.path,
    branch: wt.branch,
    detached: wt.detached,
    head: wt.head,
    baseSha,
    archivedAt: new Date().toISOString(),
    patchBytes: patchBytes.length,
    patchSha256: hashBytes(patchBytes),
    stagedPatchBytes: snap.staged.length,
    stagedPatchSha256: hashBytes(snap.staged),
    untracked: snap.untracked,
    excludedUntracked: snap.cls.excluded,
    fingerprint: snap.fingerprint,
  };
  writeFileSync(join(archiveDir, `${name}.meta.json`), JSON.stringify(meta, null, 2) + "\n");
  return meta;
}

function writeRestoreDoc(archiveDir) {
  writeFileSync(
    join(archiveDir, "RESTORE.md"),
    `# Restoring an archived worktree

For an archive named \`<name>\`:

    git worktree add --detach <dir> $(cat <name>.base-sha)
    git -C <dir> apply --check <name>.staged.patch   # verify first (skip if empty)
    git -C <dir> apply --cached <name>.staged.patch  # restores the INDEX (staged state)
    git -C <dir> apply --check <name>.patch          # verify first (skip if empty)
    git -C <dir> apply <name>.patch                  # restores the working tree
    cp -r <name>.untracked/. <dir>/                  # untracked AND gitignored files
                                                     # (the /. form also copies dotfiles like .env)

\`<name>.meta.json\` lists the branch the worktree was on, a sha256 for every
archived file, and any paths excluded as build output. If the worktree was on
a detached HEAD with unmerged commits, those commits are pinned by a
\`refs/worktree-archive/<name>\` ref (see meta.keepRef); delete the ref only
after the commits are merged or exported.
`,
  );
}

// ─── verify (the gate in front of every deletion) ───────────────────────────

/**
 * Prove the archive is restorable. Returns a list of problems; empty = proven.
 * Never throws for a verification failure — a throw here must not be confused
 * with "verified".
 */
function verifyArchive(repoRoot, name, archiveDir, meta) {
  const problems = [];

  const reachable = git(["-C", repoRoot, "cat-file", "-e", `${meta.baseSha}^{commit}`], { allowFail: true });
  if (reachable.status !== 0) problems.push(`base SHA ${meta.baseSha} is not a reachable commit`);

  for (const f of meta.untracked) {
    const copy = join(archiveDir, `${name}.untracked`, f.path);
    if (!existsSync(copy)) {
      problems.push(`archived copy missing: ${f.path}`);
      continue;
    }
    if (sha256File(copy) !== f.sha256) problems.push(`archived copy hash mismatch: ${f.path}`);
  }

  const patches = [
    { file: join(archiveDir, `${name}.patch`), bytes: meta.patchBytes, sha: meta.patchSha256, label: "patch" },
    { file: join(archiveDir, `${name}.staged.patch`), bytes: meta.stagedPatchBytes, sha: meta.stagedPatchSha256, label: "staged patch" },
  ];
  for (const p of patches) {
    if (!existsSync(p.file)) {
      problems.push(`${p.label} file missing`);
    } else if (statSync(p.file).size !== p.bytes || sha256File(p.file) !== p.sha) {
      problems.push(`${p.label} on disk does not match what was written`);
    }
  }

  if (problems.length === 0 && patches.some((p) => p.bytes > 0)) {
    // Real proof: each non-empty patch must apply cleanly to a fresh detached
    // worktree at the base SHA. Both patches are diffs against the base, so
    // both are checked against the same pristine worktree.
    const scratch = mkdtempSync(join(tmpdir(), "vaduno-wt-verify-"));
    const tmpWt = join(scratch, "wt");
    try {
      git(["-C", repoRoot, "worktree", "add", "--detach", tmpWt, meta.baseSha]);
      for (const p of patches) {
        if (p.bytes === 0) continue;
        const check = git(["-C", tmpWt, "apply", "--check", p.file], { allowFail: true });
        if (check.status !== 0) {
          problems.push(`${p.label} does not apply at base SHA: ${(check.stderr || "").trim().split("\n")[0]}`);
        }
      }
    } finally {
      git(["-C", repoRoot, "worktree", "remove", "--force", tmpWt], { allowFail: true });
      git(["-C", repoRoot, "worktree", "prune"], { allowFail: true });
      rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
  return problems;
}

// ─── deletion (only ever reached for archived + verified worktrees) ─────────

/** Refuse to recursively delete anything that is not a known worktree path. */
function guardedRm(dir, repoRoot, knownWorktreePaths) {
  const target = norm(dir);
  if (target === norm(repoRoot) || isInside(repoRoot, dir)) {
    throw new Error(`refusing to delete ${dir}: it is or contains the repository root`);
  }
  if (!knownWorktreePaths.has(target)) {
    throw new Error(`refusing to delete ${dir}: not a worktree this run archived`);
  }
  rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}

// ─── main ───────────────────────────────────────────────────────────────────

function main() {
  const opts = parseArgs(process.argv.slice(2));

  const repoProbe = git(["-C", opts.repo ?? process.cwd(), "rev-parse", "--show-toplevel"], { allowFail: true });
  if (repoProbe.status !== 0) fail(`not a git repository: ${opts.repo ?? process.cwd()}`);
  const repoRoot = resolve(repoProbe.stdout.trim());
  const defaultBranch = resolveDefaultBranch(repoRoot, opts.defaultBranch);
  const maxAgeMs = opts.maxAgeHours * 3600 * 1000;
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  const archiveDir = resolve(
    opts.archiveDir ?? join(dirname(repoRoot), `${repoRoot.split(sep).pop()}-worktree-archive`, stamp),
  );
  const scopeRoot = opts.root ? (isAbsolute(opts.root) ? resolve(opts.root) : resolve(repoRoot, opts.root)) : null;

  // A used archive dir may hold the ONLY copy of work that was already
  // deleted. Never write into it again — not even in a dry run's plan.
  if (existsSync(archiveDir) && readdirSync(archiveDir).length > 0) {
    fail(
      `archive dir ${archiveDir} already contains files — it may be the only copy of previously deleted work; use a fresh directory`,
    );
  }

  const all = listWorktrees(repoRoot);
  const candidates = all.filter((wt) => {
    if (norm(wt.path) === norm(repoRoot)) return false; // the main checkout itself
    return scopeRoot ? isInside(wt.path, scopeRoot) : isInside(wt.path, repoRoot);
  });

  console.log(
    opts.apply
      ? "worktree cleanup — APPLY mode"
      : "worktree cleanup — DRY RUN (no changes will be made; pass --apply to execute)",
  );
  console.log(`  repo:           ${repoRoot}`);
  console.log(`  scope:          ${scopeRoot ?? `linked worktrees inside the repo checkout`}`);
  console.log(`  archive dir:    ${archiveDir}`);
  console.log(`  age threshold:  ${opts.maxAgeHours}h since most recent activity`);
  console.log(`  default branch: ${defaultBranch}`);
  console.log(`  found:          ${candidates.length} worktree(s) in scope\n`);

  // Directories under an explicit --root that git no longer tracks: report,
  // never touch. There is no git metadata left to archive them safely from.
  const safetySkips = [];
  if (scopeRoot && existsSync(scopeRoot)) {
    const tracked = new Set(all.map((w) => norm(w.path)));
    for (const e of readdirSync(scopeRoot, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      const p = join(scopeRoot, e.name);
      if (!tracked.has(norm(p))) {
        console.log(`  ! SKIP ${p}`);
        console.log(`      not a registered worktree — no git metadata to archive from; inspect and remove manually`);
        safetySkips.push(`${p}: unregistered directory in worktree root`);
      }
    }
  }

  const infoSkips = [];
  const eligible = [];
  const now = Date.now();

  for (const wt of candidates) {
    const rel = relative(repoRoot, wt.path) || wt.path;
    if (wt.locked) {
      console.log(`  - SKIP ${rel}: locked by git (respecting the lock)`);
      infoSkips.push(`${rel}: locked`);
      continue;
    }
    if (!existsSync(wt.path)) {
      console.log(`  - SKIP ${rel}: directory missing (metadata only — 'git worktree prune' will clean it)`);
      infoSkips.push(`${rel}: directory missing`);
      continue;
    }
    const ageMs = now - newestActivityMs(wt);
    if (ageMs < maxAgeMs) {
      const h = (ageMs / 3600000).toFixed(1);
      console.log(`  - SKIP ${rel}: active ${h}h ago (threshold ${opts.maxAgeHours}h) — may be in use`);
      infoSkips.push(`${rel}: fresh (${h}h)`);
      continue;
    }
    eligible.push(wt);
  }

  // Plan / execute per eligible worktree: snapshot → archive → verify.
  const archiveNames = assignArchiveNames(eligible);
  const deletable = [];
  let archivedAny = false;
  for (const wt of eligible) {
    const rel = relative(repoRoot, wt.path) || wt.path;
    const name = archiveNames.get(wt.path);

    let snap;
    try {
      snap = snapshotWorktree(wt.path);
    } catch (err) {
      console.log(`  !! SKIP ${rel}: could not snapshot worktree state: ${err.message}`);
      safetySkips.push(`${rel}: snapshot failed (${err.message})`);
      continue;
    }

    if (snap.cls.blockers.length > 0) {
      console.log(`  !! SKIP ${rel}: ${snap.cls.blockers.length} file(s) under an excluded directory name are NOT gitignored:`);
      for (const b of snap.cls.blockers) console.log(`       ? ${b}`);
      console.log(`      git says these are real work but the directory name says build output —`);
      console.log(`      refusing to guess. Gitignore them (build output) or move them (real work), then rerun.`);
      safetySkips.push(`${rel}: non-ignored file(s) under excluded name (${snap.cls.blockers.join(", ")})`);
      continue;
    }

    const modified = git(["-C", wt.path, "diff", "--name-only", "HEAD"]).stdout.split("\n").filter(Boolean);
    const stagedFiles = git(["-C", wt.path, "diff", "--name-only", "--cached"]).stdout.split("\n").filter(Boolean);
    const detachedUnmerged =
      wt.detached &&
      wt.head &&
      git(["-C", repoRoot, "merge-base", "--is-ancestor", wt.head, defaultBranch], { allowFail: true }).status !== 0;
    const branchNote = wt.branch
      ? git(["-C", repoRoot, "merge-base", "--is-ancestor", wt.branch, defaultBranch], { allowFail: true }).status === 0
        ? `branch ${wt.branch} would be deleted (tip is an ancestor of ${defaultBranch})`
        : `branch ${wt.branch} would be KEPT — it holds commits not merged into ${defaultBranch}`
      : detachedUnmerged
        ? `detached HEAD ${(wt.head ?? "").slice(0, 7)} holds commits not merged into ${defaultBranch} — would be pinned as refs/worktree-archive/${name}`
        : "detached HEAD (merged), no branch to delete";

    console.log(`  ${opts.apply ? "+" : "~"} ${rel}  (base ${(wt.head ?? "").slice(0, 7)}, archive name '${name}')`);
    console.log(
      `      archive: ${modified.length} modified tracked file(s), ${stagedFiles.length} staged file(s), ${snap.untracked.length} untracked/ignored file(s)`,
    );
    for (const f of snap.untracked) console.log(`        ${f.ignored ? "i" : "u"} ${f.path}`);
    if (snap.cls.excluded.length > 0) {
      console.log(`      excluded as build output/dependencies (gitignored) (${snap.cls.excluded.length}):`);
      for (const f of snap.cls.excluded) console.log(`        x ${f}`);
    }
    console.log(`      ${branchNote}`);

    if (!opts.apply) continue;

    let meta;
    try {
      meta = archiveWorktree(wt, name, archiveDir, snap);
      archivedAny = true;
    } catch (err) {
      console.log(`      !! ARCHIVE FAILED — worktree left untouched: ${err.message}`);
      safetySkips.push(`${rel}: archive failed (${err.message})`);
      continue;
    }
    const problems = verifyArchive(repoRoot, name, archiveDir, meta);
    if (problems.length > 0) {
      console.log(`      !! ARCHIVE VERIFICATION FAILED — worktree left untouched:`);
      for (const p of problems) console.log(`         - ${p}`);
      safetySkips.push(`${rel}: verification failed (${problems.join("; ")})`);
      continue;
    }
    console.log(
      `      archive verified restorable (${meta.untracked.length} file copy(ies) hash-checked, patches checked at base)`,
    );
    deletable.push({ wt, rel, name, meta, detachedUnmerged });
  }

  if (!opts.apply) {
    console.log(`\ndry run: ${eligible.length} worktree(s) in plan, ${infoSkips.length} skipped as not eligible.`);
    console.log("nothing was changed. Pass --apply to execute.");
    // Safety conditions (unregistered directories, non-ignored files under
    // excluded names) exit non-zero even in a dry run: this tool cannot clean
    // those at all, and a wrapper must see that.
    if (safetySkips.length > 0) {
      console.log(`\n!! ${safetySkips.length} SAFETY condition(s) found — exiting non-zero:`);
      for (const s of safetySkips) console.log(`  - ${s}`);
      process.exit(1);
    }
    process.exit(0);
  }

  if (archivedAny) writeRestoreDoc(archiveDir);

  // Deletion, in the order that works on Windows (see header, rule 8) — with
  // a re-check first: anything that changed since archiving is NOT deleted.
  const knownPaths = new Set(deletable.map((d) => norm(d.wt.path)));
  const removable = [];
  for (const d of deletable) {
    // Test-only fault injection: simulate a write landing after the archive
    // snapshot, to prove the re-check aborts the deletion.
    if (process.env.VADUNO_CLEAN_WORKTREES_SABOTAGE === `plant-file:${d.name}`) {
      console.log(`  !! SABOTAGE (test-only): planting a file in ${d.rel} after archiving`);
      writeFileSync(join(d.wt.path, "planted-after-archive.txt"), "work the archive does not have\n");
    }

    let current;
    try {
      current = snapshotWorktree(d.wt.path);
    } catch (err) {
      console.log(`  !! ${d.rel}: could not re-check state before deletion (${err.message}) — leaving it alone`);
      safetySkips.push(`${d.rel}: pre-deletion re-check failed (${err.message})`);
      continue;
    }
    if (current.fingerprint !== d.meta.fingerprint) {
      console.log(`  !! ${d.rel}: worktree CHANGED AFTER ARCHIVING — leaving it untouched (the archive is stale)`);
      safetySkips.push(`${d.rel}: changed after archiving, deletion aborted`);
      continue;
    }

    // Pin unmerged detached commits BEFORE the worktree (and with it the only
    // reflog that knows them) disappears; otherwise gc destroys the commits
    // and the very base SHA the archive's patches apply to.
    if (d.detachedUnmerged) {
      const ref = `refs/worktree-archive/${d.name}`;
      const pin = git(["-C", repoRoot, "update-ref", ref, d.wt.head], { allowFail: true });
      if (pin.status !== 0) {
        console.log(`  !! ${d.rel}: could not pin detached HEAD ${d.wt.head} as ${ref} — leaving worktree alone`);
        safetySkips.push(`${d.rel}: failed to pin detached HEAD`);
        continue;
      }
      d.meta.keepRef = ref;
      writeFileSync(join(archiveDir, `${d.name}.meta.json`), JSON.stringify(d.meta, null, 2) + "\n");
      console.log(`  !! ${d.rel}: detached HEAD ${d.wt.head.slice(0, 7)} is NOT merged into ${defaultBranch}`);
      console.log(`     pinned as ${ref} so gc cannot destroy it; review and merge or delete the ref deliberately`);
      safetySkips.push(`${d.rel}: unmerged detached HEAD pinned as ${ref}`);
    }

    removable.push(d);
    const removed = git(["-C", repoRoot, "worktree", "remove", "--force", d.wt.path], { allowFail: true });
    if (removed.status !== 0) {
      console.log(`  ~ 'git worktree remove' failed for ${d.rel} (likely file locks) — will prune + delete directly`);
    }
  }
  git(["-C", repoRoot, "worktree", "prune"], { allowFail: true });
  const stillTracked = new Set(listWorktrees(repoRoot).map((w) => norm(w.path)));

  for (const d of removable) {
    d.dirGone = false;
    if (existsSync(d.wt.path)) {
      if (stillTracked.has(norm(d.wt.path))) {
        console.log(`  !! ${d.rel}: still registered after remove+prune — leaving it alone`);
        safetySkips.push(`${d.rel}: still registered after remove+prune`);
        continue;
      }
      try {
        guardedRm(d.wt.path, repoRoot, knownPaths);
      } catch (err) {
        console.log(`  !! ${d.rel}: could not delete directory: ${err.message}`);
        safetySkips.push(`${d.rel}: directory deletion failed (${err.message})`);
        continue;
      }
    }
    if (existsSync(d.wt.path)) {
      console.log(`  !! ${d.rel}: directory still present after deletion attempt`);
      safetySkips.push(`${d.rel}: directory survived deletion`);
      continue;
    }
    d.dirGone = true;
    console.log(`  ✓ deleted ${d.rel}`);
  }

  // Branches — only for worktrees whose directory is actually gone, and only
  // when the tip is provably an ancestor of the default branch.
  for (const d of removable) {
    if (!d.dirGone || !d.wt.branch) continue;
    if (d.wt.branch === defaultBranch) continue; // never touch the default branch
    const isAncestor = git(["-C", repoRoot, "merge-base", "--is-ancestor", d.wt.branch, defaultBranch], { allowFail: true });
    if (isAncestor.status !== 0) {
      console.log(`  !! KEEPING branch ${d.wt.branch}: it holds commits not merged into ${defaultBranch}`);
      console.log(`     (the archive holds uncommitted changes only — this branch is the only home of those commits)`);
      safetySkips.push(`branch ${d.wt.branch}: unmerged, kept`);
      continue;
    }
    const del = git(["-C", repoRoot, "branch", "-D", d.wt.branch], { allowFail: true });
    if (del.status !== 0) {
      console.log(`  !! could not delete branch ${d.wt.branch}: ${(del.stderr || "").trim()}`);
      safetySkips.push(`branch ${d.wt.branch}: deletion failed`);
    } else {
      console.log(`  ✓ deleted branch ${d.wt.branch} (tip was an ancestor of ${defaultBranch})`);
    }
  }

  const cleaned = removable.filter((d) => d.dirGone).length;
  console.log(`\n${cleaned} worktree(s) archived and deleted; archive at ${archivedAny ? archiveDir : "(nothing archived)"}`);
  if (infoSkips.length > 0) {
    console.log(`${infoSkips.length} skipped as not eligible (normal):`);
    for (const s of infoSkips) console.log(`  - ${s}`);
  }
  if (safetySkips.length > 0) {
    console.log(`\n!! ${safetySkips.length} SAFETY skip(s) — this run is NOT clean, exiting non-zero:`);
    for (const s of safetySkips) console.log(`  - ${s}`);
    process.exit(1);
  }
}

main();
