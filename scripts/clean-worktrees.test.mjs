/**
 * Tests for scripts/clean-worktrees.mjs.
 *
 * These build REAL git repositories with REAL worktrees in a temp directory —
 * no mocked git. Each safety property the tool claims is exercised against a
 * fixture where violating it would be observable:
 *
 *   1. untracked files are captured in the archive (the property whose absence
 *      nearly destroyed 39 files in the manual cleanup this tool encodes)
 *   2. a worktree whose archive fails verification is NOT deleted (fail closed)
 *   3. dry run (the default) changes nothing
 *   4. the age threshold protects a freshly-modified worktree
 *   5. a branch holding unmerged commits is kept, and the run exits non-zero
 *   6. a git-locked worktree is respected
 *   7. two worktrees with the same basename cannot clobber each other's archive
 *   8. gitignored files (.env, secrets/) are archived — git diff and plain
 *      status are both blind to them
 *   9. a NON-ignored file under an excluded directory name fails closed
 *  10. a detached HEAD holding unmerged commits is pinned by a ref that
 *      survives git gc
 *  11. a pre-existing non-empty archive dir is refused (never overwrite the
 *      sole copy of already-deleted work)
 *  12. staleness needs more than file mtimes — a just-created worktree with
 *      backdated files is not stale
 *  13. staged-vs-worktree divergence is archived as two patches
 *  14. a file planted after archiving (TOCTOU) aborts that deletion
 *  15. a Windows file lock on the delete path fails the run loudly (never
 *      exit 0 over a half-deleted worktree)
 *  16. dry run leaves every byte of the repo — including .git — untouched
 *  17. --help names every flag and every exit code, accurately
 *  18. a deleted worktree restores byte-identically from its archive
 *
 * Run: node --test scripts/clean-worktrees.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "clean-worktrees.mjs");

function git(cwd, ...args) {
  // ALLOW_ANY_GIT_IDENTITY: fixture repos live in a temp dir, are never pushed,
  // and use a deliberately fake identity; a machine-local identity hook may
  // otherwise block their commits. Harmless where no such hook exists.
  const res = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, ALLOW_ANY_GIT_IDENTITY: "1" },
  });
  if (res.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout;
}

/**
 * A repo with one commit on master, plus a helper for adding worktrees.
 * The .gitignore is part of the fixture: real harness worktrees have one, and
 * the tool's exclusion policy is deliberately scoped to IGNORED paths only.
 */
function makeFixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "vaduno-cwt-fixture-"));
  t.after(() => {
    // Windows needs retries: git may hold handles briefly after child exit.
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    } catch {
      /* leftover temp dir is harmless */
    }
  });
  const repo = join(dir, "repo");
  mkdirSync(repo);
  git(repo, "init", "-b", "master");
  git(repo, "config", "user.email", "fixture@example.invalid");
  git(repo, "config", "user.name", "fixture");
  git(repo, "config", "commit.gpgsign", "false");
  git(repo, "config", "core.autocrlf", "false");
  writeFileSync(join(repo, "README.md"), "fixture\n");
  writeFileSync(join(repo, ".gitignore"), "node_modules/\n.env\nsecrets/\n");
  mkdirSync(join(repo, "src"));
  writeFileSync(join(repo, "src", "a.txt"), "original content\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-m", "initial");
  return { dir, repo };
}

function addWorktree(repo, name) {
  const wtPath = join(repo, "wt", name);
  git(repo, "worktree", "add", wtPath, "-b", `worktree-${name}`);
  return wtPath;
}

function runTool(repo, args, env = {}) {
  const res = spawnSync(process.execPath, [SCRIPT, "--repo", repo, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  return { status: res.status, out: `${res.stdout}\n${res.stderr}` };
}

const worktreeRegistered = (repo, wtPath) =>
  git(repo, "worktree", "list", "--porcelain").includes(wtPath.replaceAll("\\", "/"));

const branchExists = (repo, name) =>
  spawnSync("git", ["rev-parse", "--verify", "--quiet", `refs/heads/${name}`], { cwd: repo }).status === 0;

/** rel path (posix separators) → sha256 hex, for every file under root. */
function snapshotTree(root, { exclude = [] } = {}) {
  const map = new Map();
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      const rel = relative(root, p).replaceAll("\\", "/");
      if (exclude.includes(rel)) continue;
      if (e.isDirectory()) walk(p);
      else map.set(rel, createHash("sha256").update(readFileSync(p)).digest("hex"));
    }
  };
  walk(root);
  return map;
}

/** rel path → {mtimeMs, sha256} for every file under root (dirs contribute mtime). */
function snapshotTreeWithMtimes(root) {
  const map = new Map();
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      const rel = relative(root, p).replaceAll("\\", "/");
      const st = statSync(p);
      if (e.isDirectory()) {
        map.set(rel + "/", { mtimeMs: st.mtimeMs });
        walk(p);
      } else {
        map.set(rel, {
          mtimeMs: st.mtimeMs,
          sha256: createHash("sha256").update(readFileSync(p)).digest("hex"),
        });
      }
    }
  };
  walk(root);
  return map;
}

function backdateTree(root, when) {
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      utimesSync(p, when, when);
    }
  };
  walk(root);
  utimesSync(root, when, when);
}

/** Find every file with the given basename under root; returns full paths. */
function findFiles(root, basename) {
  const hits = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name === basename) hits.push(p);
    }
  };
  walk(root);
  return hits;
}

// ─── 1. untracked-file capture ──────────────────────────────────────────────

test("apply archives untracked files and the tracked diff, then deletes the worktree", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt1");

  // a tracked modification, an untracked source file, and gitignored build junk
  writeFileSync(join(wt, "src", "a.txt"), "modified in worktree\n");
  mkdirSync(join(wt, "src", "newmod"), { recursive: true });
  writeFileSync(join(wt, "src", "newmod", "brand-new.ts"), "export const fresh = 1;\n");
  mkdirSync(join(wt, "node_modules", "junk"), { recursive: true });
  writeFileSync(join(wt, "node_modules", "junk", "index.js"), "// dependency junk\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 0, `expected clean exit, got ${r.status}:\n${r.out}`);

  // the untracked source file is in the archive, byte-for-byte
  const archivedCopy = join(archive, "wt1.untracked", "src", "newmod", "brand-new.ts");
  assert.ok(existsSync(archivedCopy), `archived untracked file missing: ${archivedCopy}\n${r.out}`);
  assert.equal(readFileSync(archivedCopy, "utf8"), "export const fresh = 1;\n");

  // gitignored build junk was excluded, and the exclusion is REPORTED, not silent
  assert.ok(!existsSync(join(archive, "wt1.untracked", "node_modules")), "node_modules must not be archived");
  assert.match(r.out, /excluded as build output/);
  assert.match(r.out, /node_modules\//);

  // the tracked diff and base SHA are archived
  const patch = readFileSync(join(archive, "wt1.patch"), "utf8");
  assert.match(patch, /modified in worktree/);
  const baseSha = readFileSync(join(archive, "wt1.base-sha"), "utf8").trim();
  assert.match(baseSha, /^[0-9a-f]{40}$/);

  // the worktree is gone (directory and registration), branch was merged → deleted
  assert.ok(!existsSync(wt), "worktree directory should be deleted");
  assert.ok(!worktreeRegistered(repo, wt), "worktree should be unregistered");
  assert.ok(!branchExists(repo, "worktree-wt1"), "fully-merged branch should be deleted");
});

// ─── 2. fail closed when verification fails ─────────────────────────────────

test("a worktree whose archive fails verification is skipped entirely and the run exits non-zero", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt2");
  writeFileSync(join(wt, "src", "a.txt"), "modified so the patch is non-empty\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive], {
    VADUNO_CLEAN_WORKTREES_SABOTAGE: "corrupt-patch:wt2",
  });

  assert.equal(r.status, 1, `expected exit 1 for a safety skip, got ${r.status}:\n${r.out}`);
  assert.match(r.out, /ARCHIVE VERIFICATION FAILED/);
  assert.ok(existsSync(wt), "worktree must NOT be deleted when its archive cannot be verified");
  assert.ok(worktreeRegistered(repo, wt), "worktree must stay registered");
  assert.ok(branchExists(repo, "worktree-wt2"), "branch must be kept");
});

// ─── 3. dry run changes nothing ─────────────────────────────────────────────

test("dry run (the default) reports the plan and changes nothing", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt3");
  writeFileSync(join(wt, "untracked-note.md"), "do not lose me\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /DRY RUN/);
  assert.match(r.out, /untracked-note\.md/, "dry run must show exactly what it would archive");
  assert.ok(existsSync(wt), "dry run must not delete the worktree");
  assert.ok(worktreeRegistered(repo, wt), "dry run must not unregister the worktree");
  assert.ok(!existsSync(archive), "dry run must not write an archive");
  assert.ok(branchExists(repo, "worktree-wt3"), "dry run must not delete branches");
});

// ─── 4. age threshold protects fresh worktrees ──────────────────────────────

test("a freshly-modified worktree is skipped even with --apply (default age threshold)", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt4");
  writeFileSync(join(wt, "in-progress.txt"), "an agent may be mid-flight here\n");

  const archive = join(dir, "archive");
  // no --max-age-hours: the conservative default applies
  const r = runTool(repo, ["--apply", "--archive-dir", archive]);

  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /SKIP .*wt4.*(modified|active) .*h ago/, "the skip and its reason must be reported");
  assert.ok(existsSync(wt), "fresh worktree must not be deleted");
  assert.ok(worktreeRegistered(repo, wt), "fresh worktree must stay registered");
  assert.ok(!existsSync(archive), "nothing eligible → nothing archived");
});

// ─── 5. unmerged branches are kept ──────────────────────────────────────────

test("a branch with commits not merged into the default branch is kept and reported, exit non-zero", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt5");

  // commit real work on the worktree branch, never merged into master
  writeFileSync(join(wt, "unmerged-feature.ts"), "export const notInMaster = true;\n");
  git(wt, "add", "-A");
  git(wt, "commit", "-m", "unmerged work");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 1, `keeping an unmerged branch is a safety skip → non-zero exit:\n${r.out}`);
  assert.match(r.out, /KEEPING branch worktree-wt5/);
  assert.ok(!existsSync(wt), "the worktree itself is safe to delete — the commits live on the branch");
  assert.ok(branchExists(repo, "worktree-wt5"), "unmerged branch must be kept");
});

// ─── 6. locked worktrees are respected ──────────────────────────────────────

test("a git-locked worktree is skipped with a reason", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt6");
  git(repo, "worktree", "lock", wt);

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /SKIP .*wt6.*locked/);
  assert.ok(existsSync(wt), "locked worktree must not be deleted");
  assert.ok(worktreeRegistered(repo, wt), "locked worktree must stay registered");
});

// ─── 7. same-basename worktrees must not clobber each other's archive ───────

test("two worktrees with the same basename get distinct archives, both fully captured", (t) => {
  const { dir, repo } = makeFixture(t);
  const wtA = join(repo, "wt", "agents-a", "task");
  const wtB = join(repo, "wt", "agents-b", "task");
  git(repo, "worktree", "add", wtA, "-b", "collide-a");
  git(repo, "worktree", "add", wtB, "-b", "collide-b");
  writeFileSync(join(wtA, "only-in-a.txt"), "distinct work in A\n");
  writeFileSync(join(wtB, "only-in-b.txt"), "distinct work in B\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 0, `expected clean exit, got ${r.status}:\n${r.out}`);
  assert.ok(!existsSync(wtA) && !existsSync(wtB), "both worktrees should be deleted");

  // BOTH distinct untracked files must exist in the archive, byte-identical.
  const aCopies = findFiles(archive, "only-in-a.txt");
  const bCopies = findFiles(archive, "only-in-b.txt");
  assert.equal(aCopies.length, 1, `A's untracked file must be archived exactly once:\n${r.out}`);
  assert.equal(bCopies.length, 1, `B's untracked file must be archived exactly once:\n${r.out}`);
  assert.equal(readFileSync(aCopies[0], "utf8"), "distinct work in A\n");
  assert.equal(readFileSync(bCopies[0], "utf8"), "distinct work in B\n");

  // and two distinct meta files — one archive per worktree, no overwrite
  const metas = readdirSync(archive).filter((f) => f.endsWith(".meta.json"));
  assert.equal(metas.length, 2, `expected 2 meta files, got: ${metas.join(", ")}\n${r.out}`);
});

// ─── 8. gitignored files are precious too ───────────────────────────────────

test("gitignored files (.env, secrets/) are archived before deletion; ignored build dirs are excluded loudly", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt8");
  writeFileSync(join(wt, ".env"), "DO_NOT_LOSE_SECRET=1\n");
  mkdirSync(join(wt, "secrets", "deep"), { recursive: true });
  writeFileSync(join(wt, "secrets", "deep", "key.pem"), "-----FAKE KEY-----\n");
  mkdirSync(join(wt, "node_modules", "dep"), { recursive: true });
  writeFileSync(join(wt, "node_modules", "dep", "index.js"), "junk\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 0, `expected clean exit, got ${r.status}:\n${r.out}`);
  assert.ok(!existsSync(wt), "worktree should be deleted");

  const envCopy = join(archive, "wt8.untracked", ".env");
  assert.ok(existsSync(envCopy), `.env must be archived — git diff and plain status are blind to it:\n${r.out}`);
  assert.equal(readFileSync(envCopy, "utf8"), "DO_NOT_LOSE_SECRET=1\n");

  const keyCopy = join(archive, "wt8.untracked", "secrets", "deep", "key.pem");
  assert.ok(existsSync(keyCopy), `files inside an ignored directory must be archived:\n${r.out}`);
  assert.equal(readFileSync(keyCopy, "utf8"), "-----FAKE KEY-----\n");

  assert.ok(!existsSync(join(archive, "wt8.untracked", "node_modules")), "node_modules stays excluded");
  assert.match(r.out, /node_modules\//, "the exclusion must be named in the report");
});

// ─── 9. non-ignored files under excluded names fail closed ──────────────────

test("an untracked file under an excluded name that git does NOT ignore blocks deletion (fail closed)", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt9");
  // dist/ is NOT in the fixture .gitignore: git says this file is real work
  mkdirSync(join(wt, "dist"));
  writeFileSync(join(wt, "dist", "README.md"), "hand-written, not build output\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 1, `deleting non-ignored work under an excluded name must fail the run:\n${r.out}`);
  assert.match(r.out, /dist\/README\.md/, "the blocking file must be named");
  assert.ok(existsSync(join(wt, "dist", "README.md")), "the file must survive");
  assert.ok(worktreeRegistered(repo, wt), "the worktree must stay registered");
});

// ─── 10. detached HEAD with unmerged commits is pinned against gc ───────────

test("a detached HEAD holding unmerged commits is pinned by a ref that survives git gc", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = join(repo, "wt", "wt10");
  git(repo, "worktree", "add", "--detach", wt);
  writeFileSync(join(wt, "committed-only-here.ts"), "export const orphanRisk = true;\n");
  git(wt, "add", "-A");
  git(wt, "commit", "-m", "local commit on detached HEAD");
  const localSha = git(wt, "rev-parse", "HEAD").trim();
  writeFileSync(join(wt, "uncommitted-note.md"), "also archive me\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 1, `unmerged detached commits are a safety condition → non-zero exit:\n${r.out}`);
  assert.ok(!existsSync(wt), "the worktree directory itself can go — the commit is pinned");

  // The pin must exist, point at the local commit, and keep it alive through gc.
  const refs = git(repo, "for-each-ref", "--format=%(refname) %(objectname)", "refs/worktree-archive/");
  assert.match(refs, new RegExp(localSha), `a refs/worktree-archive/* ref must pin ${localSha}:\n${refs}\n${r.out}`);
  git(repo, "gc", "--prune=now");
  const alive = spawnSync("git", ["cat-file", "-e", `${localSha}^{commit}`], { cwd: repo });
  assert.equal(alive.status, 0, "the unmerged commit must survive git gc — it is the archive's own base");
});

// ─── 11. a used archive dir is never overwritten ────────────────────────────

test("a pre-existing non-empty --archive-dir is refused before anything is touched", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt11");
  writeFileSync(join(wt, "work.txt"), "current work\n");

  const archive = join(dir, "archive");
  mkdirSync(archive, { recursive: true });
  writeFileSync(join(archive, "previous-run.patch"), "sole copy of already-deleted work\n");

  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 2, `reusing an archive dir is a usage error:\n${r.out}`);
  assert.equal(
    readFileSync(join(archive, "previous-run.patch"), "utf8"),
    "sole copy of already-deleted work\n",
    "the previous archive must be untouched",
  );
  assert.ok(existsSync(wt), "nothing may be deleted on a refused run");
  assert.ok(worktreeRegistered(repo, wt), "worktree must stay registered");
});

// ─── 12. staleness is not just file mtimes ──────────────────────────────────

test("a just-created worktree with backdated file mtimes is NOT judged stale", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt12");
  writeFileSync(join(wt, "current-work.txt"), "created seconds ago\n");
  // An attacker (or a copy that preserves mtimes, or clock skew) makes every
  // file in the tree look 3 days old. The worktree itself is seconds old.
  backdateTree(wt, new Date(Date.now() - 72 * 3600 * 1000));

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--archive-dir", archive]); // default 24h threshold

  assert.equal(r.status, 0, r.out);
  assert.ok(existsSync(wt), "a seconds-old worktree must not be deleted on mtime evidence alone");
  assert.ok(worktreeRegistered(repo, wt), "worktree must stay registered");
  assert.match(r.out, /SKIP .*wt12/, "the skip must be reported");
});

// ─── 13. staged and unstaged states are both archived ───────────────────────

test("when the staged version differs from the working tree, both are archived", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt13");
  writeFileSync(join(wt, "src", "a.txt"), "STAGED-CONTENT-A\n");
  git(wt, "add", "src/a.txt");
  writeFileSync(join(wt, "src", "a.txt"), "WORKTREE-CONTENT-B\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

  assert.equal(r.status, 0, `expected clean exit, got ${r.status}:\n${r.out}`);
  const stagedPatch = join(archive, "wt13.staged.patch");
  assert.ok(existsSync(stagedPatch), `staged state must be archived separately — a single diff HEAD loses it:\n${r.out}`);
  assert.match(readFileSync(stagedPatch, "utf8"), /STAGED-CONTENT-A/);
  assert.match(readFileSync(join(archive, "wt13.patch"), "utf8"), /WORKTREE-CONTENT-B/);
});

// ─── 14. TOCTOU: changes after archiving abort the deletion ─────────────────

test("a file planted after the archive snapshot but before deletion aborts that deletion", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt14");
  writeFileSync(join(wt, "src", "a.txt"), "modified\n");

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive], {
    VADUNO_CLEAN_WORKTREES_SABOTAGE: "plant-file:wt14",
  });

  assert.equal(r.status, 1, `a worktree that changed after archiving is a safety skip:\n${r.out}`);
  assert.match(r.out, /changed after archiving/i);
  assert.ok(existsSync(wt), "the changed worktree must NOT be deleted");
  assert.ok(worktreeRegistered(repo, wt), "the changed worktree must stay registered");
  assert.ok(
    existsSync(join(wt, "planted-after-archive.txt")),
    "the planted file (the work the archive does not have) must survive",
  );
});

// ─── 15. Windows file locks on the delete path fail loudly ──────────────────

test(
  "a file lock held without delete-sharing fails the run (never exit 0 over a half-deleted worktree)",
  { skip: process.platform !== "win32" ? "Windows-only: POSIX allows unlinking open files" : false },
  (t) => {
    const { dir, repo } = makeFixture(t);
    const wt = addWorktree(repo, "wt15");
    writeFileSync(join(wt, "src", "a.txt"), "modified\n");
    const lockedFile = join(wt, "locked-by-another-process.txt");
    writeFileSync(lockedFile, "held open during the run\n");

    // Node's own openSync passes FILE_SHARE_DELETE, which does NOT block
    // deletion. A real lock (the kind AV scanners and editors hold) shares
    // Read only — hold one from a separate process for the duration.
    const marker = join(dir, "lock-held.marker");
    const holder = spawn("powershell", [
      "-NoProfile",
      "-Command",
      `$f=[System.IO.File]::Open('${lockedFile.replaceAll("'", "''")}','Open','Read','Read'); ` +
        `New-Item -ItemType File -Path '${marker.replaceAll("'", "''")}' | Out-Null; Start-Sleep 120`,
    ]);
    t.after(() => holder.kill());
    const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    for (let i = 0; i < 100 && !existsSync(marker); i++) sleepSync(100);
    assert.ok(existsSync(marker), "the lock-holder process must signal it holds the file");

    const archive = join(dir, "archive");
    const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);

    assert.equal(r.status, 1, `a worktree that cannot be fully deleted must fail the run:\n${r.out}`);
    assert.match(r.out, /could not delete|survived deletion|still registered/);
    assert.ok(existsSync(lockedFile), "the locked file itself must still exist");
    // whatever remains on disk, the archive of the work is intact
    assert.ok(existsSync(join(archive, "wt15.patch")), "the archive must exist");
    assert.match(readFileSync(join(archive, "wt15.patch"), "utf8"), /modified/);
  },
);

// ─── 16. dry-run purity: not one byte, anywhere, including .git ─────────────

test("dry run leaves every byte of the repo — including .git — untouched", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt16");
  writeFileSync(join(wt, "src", "a.txt"), "tracked modification\n");
  writeFileSync(join(wt, "untracked.txt"), "untracked\n");

  const before = snapshotTreeWithMtimes(dir);
  const r = runTool(repo, ["--max-age-hours", "0", "--archive-dir", join(dir, "archive")]);
  assert.equal(r.status, 0, r.out);
  const after = snapshotTreeWithMtimes(dir);

  assert.deepEqual(
    [...after.keys()].sort(),
    [...before.keys()].sort(),
    "dry run must not create or delete any file",
  );
  for (const [rel, b] of before) {
    const a = after.get(rel);
    assert.deepEqual(a, b, `dry run modified ${rel} (mtime or content changed)`);
  }
});

// ─── 17. --help is accurate and complete ────────────────────────────────────

test("--help names every flag, both patches, ignored-file archiving, and every exit code", () => {
  const res = spawnSync(process.execPath, [SCRIPT, "--help"], { encoding: "utf8" });
  assert.equal(res.status, 0);
  const out = res.stdout;
  for (const flag of ["--apply", "--repo", "--root", "--archive-dir", "--max-age-hours", "--default-branch"]) {
    assert.ok(out.includes(flag), `help must document ${flag}`);
  }
  assert.match(out, /dry.?run/i, "help must state that dry run is the default");
  assert.match(out, /ignored/i, "help must state that gitignored files are archived");
  assert.match(out, /staged/i, "help must state that staged state is archived separately");
  for (const code of ["0", "1", "2"]) {
    assert.match(out, new RegExp(`^\\s*${code}\\s`, "m"), `help must document exit code ${code}`);
  }
});

// ─── 18. the only proof that matters: restore byte-identically ──────────────

test("a deleted worktree restores byte-identically from its archive (RESTORE.md steps)", (t) => {
  const { dir, repo } = makeFixture(t);
  const wt = addWorktree(repo, "wt18");
  // every category of state at once:
  writeFileSync(join(wt, "src", "a.txt"), "STAGED-A\n");
  git(wt, "add", "src/a.txt");
  writeFileSync(join(wt, "src", "a.txt"), "WORKTREE-B\n"); // staged ≠ worktree
  writeFileSync(join(wt, "README.md"), "tracked modification\n");
  mkdirSync(join(wt, "src", "newmod"));
  writeFileSync(join(wt, "src", "newmod", "new-code.ts"), "export const x = 42;\n");
  writeFileSync(join(wt, ".env"), "SECRET=byte-identical\n");
  mkdirSync(join(wt, "secrets"));
  writeFileSync(join(wt, "secrets", "k.pem"), "key material\n");

  const wantTree = snapshotTree(wt, { exclude: [".git"] });
  const wantStaged = git(wt, "diff", "--cached").toString();

  const archive = join(dir, "archive");
  const r = runTool(repo, ["--apply", "--max-age-hours", "0", "--archive-dir", archive]);
  assert.equal(r.status, 0, `expected clean exit, got ${r.status}:\n${r.out}`);
  assert.ok(!existsSync(wt), "worktree deleted");
  assert.ok(existsSync(join(archive, "RESTORE.md")), "RESTORE.md must be written");

  // Restore exactly as RESTORE.md prescribes.
  const restored = join(dir, "restored");
  const baseSha = readFileSync(join(archive, "wt18.base-sha"), "utf8").trim();
  git(repo, "worktree", "add", "--detach", restored, baseSha);
  const stagedPatch = join(archive, "wt18.staged.patch");
  if (statSync(stagedPatch).size > 0) git(restored, "apply", "--cached", stagedPatch);
  const patch = join(archive, "wt18.patch");
  if (statSync(patch).size > 0) git(restored, "apply", patch);
  // copy the untracked tree back
  const untrackedRoot = join(archive, "wt18.untracked");
  const copyBack = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const src = join(d, e.name);
      const rel = relative(untrackedRoot, src);
      const dst = join(restored, rel);
      if (e.isDirectory()) {
        mkdirSync(dst, { recursive: true });
        copyBack(src);
      } else {
        mkdirSync(dirname(dst), { recursive: true });
        writeFileSync(dst, readFileSync(src));
      }
    }
  };
  copyBack(untrackedRoot);

  const gotTree = snapshotTree(restored, { exclude: [".git"] });
  assert.deepEqual([...gotTree.keys()].sort(), [...wantTree.keys()].sort(), "same file set");
  for (const [rel, hash] of wantTree) {
    assert.equal(gotTree.get(rel), hash, `restored ${rel} must be byte-identical`);
  }
  const gotStaged = git(restored, "diff", "--cached").toString();
  assert.equal(gotStaged, wantStaged, "the staged state (index) must restore identically");
});
