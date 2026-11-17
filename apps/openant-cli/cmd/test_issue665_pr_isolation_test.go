package cmd

// #665, the cycle-2 RED (arms 2+3, the remaining scope the Sep-24
// partial-fix receipt names): the --pr path must never mutate the user's
// checkout, and two --pr resolutions must never share a tree. The
// class-(a) RED pair compiles on pristine master and fails on BEHAVIOR:
// selectMode's FetchPR runs `git checkout --detach` in the user's clone
// (the Arm-2 mutation) and a second fetch re-points that shared tree (the
// Arm-3 wrong-head manifest).
//
// The offline drive follows the #767 convention: a PATH-shimmed `gh`
// printing a fixed baseRefName, a local file-path `origin` carrying
// refs/pull/7/head and refs/pull/8/head, and the shim's reachability
// checked BEFORE the drive (a missing shim inside selectMode is an
// os.Exit(2) that kills the whole test binary).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
)

// issue665Env builds the offline two-PR environment: a bare `origin` whose
// main is at `base`, with refs/pull/7/head one commit ahead (b.txt) and
// refs/pull/8/head one commit ahead on the other side (c.txt), plus a clone
// sitting CLEAN on main at `base`, and a PATH-shimmed `gh` that answers any
// `pr view` with baseRefName main. The clone's HEAD must differ from both
// PR heads — otherwise "the tree moved" is indistinguishable from "it did
// not".
func issue665Env(t *testing.T) (repoDir string, binDir string, base string, prHeads map[int]string) {
	t.Helper()

	// #767/r1-F2: the `#!/bin/sh` gh shim is unreachable through Go's
	// exec.LookPath on windows (PATHEXT), so FetchPR would find the real gh
	// (or none) and selectMode's error path os.Exit(2)s the WHOLE test
	// binary. Skip on Windows; the pinned behavior is OS-neutral.
	if runtime.GOOS == "windows" {
		t.Skip("the offline gh shim is a #!/bin/sh script; PATH resolution on windows cannot see it")
	}

	origin := t.TempDir()
	if out, err := exec.Command("git", "init", "--bare", "-q", "-b", "main", origin).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
	repoDir = t.TempDir()
	run := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = repoDir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	run("config", "commit.gpgsign", "false")
	// the offline env's submodule children are local file paths; git >= 2.38
	// blocks the file transport for submodules by default, and Apple's 2.50
	// ignores a LOCAL-scope allowance for the submodule clone — so redirect
	// the GLOBAL config to a test file that allows it. The env var is
	// inherited by every git subprocess, including the scratch's submodule
	// update inside FetchPR (the production path never weakens the setting
	// for real runs — real submodules are https).
	gcfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(gcfg, []byte("[protocol \"file\"]\n\tallow = always\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", gcfg)
	if err := os.WriteFile(filepath.Join(repoDir, "a.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "base")
	base = issue665Rev(t, repoDir, "HEAD")
	run("remote", "add", "origin", origin)
	run("push", "-q", "origin", "main")

	prHeads = map[int]string{}
	for _, pr := range []struct {
		number int
		ref    string
		name   string
		body   string
	}{
		{7, "refs/pull/7/head", "b.txt", "pr7\n"},
		{8, "refs/pull/8/head", "c.txt", "pr8\n"},
	} {
		if err := os.WriteFile(filepath.Join(repoDir, pr.name), []byte(pr.body), 0o644); err != nil {
			t.Fatal(err)
		}
		run("add", ".")
		run("commit", "-q", "-m", "pr head")
		prHeads[pr.number] = issue665Rev(t, repoDir, "HEAD")
		// Publish the PR head BEFORE moving the working tree back: the
		// pull ref must name the PR commit, not the base.
		run("push", "-q", "origin", "HEAD:"+pr.ref)
		// Move the working tree back to the base commit so the clone sits
		// clean on main, distinguishably far from either PR head.
		run("reset", "--hard", base)
	}

	binDir = t.TempDir()
	gh := filepath.Join(binDir, "gh")
	script := "#!/bin/sh\necho '{\"baseRefName\":\"main\"}'\n"
	if err := os.WriteFile(gh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if base == prHeads[7] || base == prHeads[8] || prHeads[7] == prHeads[8] {
		t.Fatalf("expected distinct base/pr7/pr8 SHAs, got %s %s %s", base, prHeads[7], prHeads[8])
	}
	return repoDir, binDir, base, prHeads
}

func issue665Rev(t *testing.T, dir, ref string) string {
	t.Helper()
	c := exec.Command("git", "-C", dir, "rev-parse", ref)
	out, err := c.Output()
	if err != nil {
		t.Fatalf("git rev-parse %s: %v", ref, err)
	}
	return string(trimSpaces(out))
}

func trimSpaces(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != '\n' && c != '\r' && c != ' ' {
			out = append(out, c)
		}
	}
	return out
}

// TestIssue665UserTreeNeverMutated is the Arm-2 witness: resolving --pr
// must leave the user's checkout exactly where it was — same branch, same
// HEAD. On pristine master selectMode's FetchPR detaches the clone at the
// PR head and leaves it there (the mutation the issue's repro prints as
// "moved, never restored").
func TestIssue665UserTreeNeverMutated(t *testing.T) {
	repoDir, binDir, base, _ := issue665Env(t)
	issue665Preflight(t, binDir)
	// raw-git cleanup (this witness must compile at pristine base, so it
	// cannot name the new cleanup API): the test leaves no workspace or
	// ref behind whatever the head under test did.
	t.Cleanup(func() {
		out, _ := exec.Command("git", "-C", repoDir, "for-each-ref",
			"--format=%(refname)", "refs/openant/pr/").Output()
		for _, r := range strings.Fields(string(out)) {
			_ = exec.Command("git", "-C", repoDir, "update-ref", "-d", r).Run()
		}
		wl, _ := exec.Command("git", "-C", repoDir, "worktree", "list", "--porcelain").Output()
		for _, line := range strings.Split(string(wl), "\n") {
			if w, ok := strings.CutPrefix(line, "worktree "); ok {
				w = strings.TrimSpace(w)
				if strings.Contains(filepath.Base(w), "openant-pr-") {
					_ = exec.Command("git", "-C", repoDir, "worktree", "remove", "--force", w).Run()
				}
			}
		}
	})

	beforeBranch := issue665Branch(t, repoDir)
	if beforeBranch != "main" {
		t.Fatalf("precondition: the clone should start on main, got %q", beforeBranch)
	}
	if got := issue665Rev(t, repoDir, "HEAD"); got != base {
		t.Fatalf("precondition: the clone should start at base %s, got %s", base, got)
	}

	if _, err := selectMode(modeOpts{pr: 7, repoPath: repoDir}); err != nil {
		t.Fatalf("selectMode --pr 7: %v", err)
	}

	if got := issue665Rev(t, repoDir, "HEAD"); got != base {
		t.Errorf("#665 arm 2: --pr moved the user's checkout: HEAD %s -> %s — the tree must never be mutated", base, got)
	}
	if got := issue665Branch(t, repoDir); got != beforeBranch {
		t.Errorf("#665 arm 2: --pr moved the user's branch: %s -> %s", beforeBranch, got)
	}
	if out := issue665Status(t, repoDir); out != "" {
		t.Errorf("#665 arm 2: --pr dirtied the user's tree:\n%s", out)
	}
}

func issue665Branch(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		t.Fatalf("git rev-parse --abbrev-ref HEAD: %v", err)
	}
	return string(trimSpaces(out))
}

func issue665Status(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		t.Fatalf("git status --porcelain: %v", err)
	}
	return string(out)
}

// issue665Preflight asserts the PATH shim is what `gh` resolves to before
// the drive: a missing shim inside selectMode is an os.Exit(2) that kills
// the whole test binary, not a t.Fatal (#767/r1-F3).
func issue665Preflight(t *testing.T, binDir string) {
	t.Helper()
	got, err := exec.LookPath("gh")
	if err != nil || filepath.Dir(got) != binDir {
		t.Fatalf("the gh PATH shim at %s is not what gh resolves to (got %q, err %v) — FetchPR would run a real gh", binDir, got, err)
	}
}

// The class-(b) battery: the new-API witnesses (absence-red at pristine
// master — the package does not compile there; the build failure IS the
// red). These pin the isolation contract the (a) test can only gesture at:
// the per-run worktree, the cleanup, the crash-residue sweep, and the
// manifest parity with the in-place flow.

// TestIssue665PRWorktreeIsolatedPerPR is the Arm-3 witness: two --pr
// resolutions each carry their OWN worktree, each manifest built there
// carries ITS OWN PR's head, and the user's tree never moves — the
// deterministic form of the concurrent wrong-head race (the issue's
// observed out-pr1/diff_manifest.json carrying PR 2's head).
func TestIssue665PRWorktreeIsolatedPerPR(t *testing.T) {
	repoDir, binDir, base, prHeads := issue665Env(t)
	issue665Preflight(t, binDir)

	d7, err := selectMode(modeOpts{pr: 7, repoPath: repoDir})
	if err != nil {
		t.Fatalf("selectMode --pr 7: %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, d7.PRWorktree, d7.PRRef)
	d8, err := selectMode(modeOpts{pr: 8, repoPath: repoDir})
	if err != nil {
		t.Fatalf("selectMode --pr 8: %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, d8.PRWorktree, d8.PRRef)

	if d7.PRWorktree == "" || d8.PRWorktree == "" {
		t.Fatalf("expected two worktrees in the decisions, got %q and %q", d7.PRWorktree, d8.PRWorktree)
	}
	if d7.PRWorktree == d8.PRWorktree {
		t.Fatalf("the two --pr runs share one worktree: %q", d7.PRWorktree)
	}
	if d7.PRRef == d8.PRRef {
		t.Fatalf("the two --pr runs share one ref: %q", d7.PRRef)
	}

	// The manifest for PR 7 built AFTER PR 8 resolved: the shared-tree
	// race shape, made deterministic. Each carries its OWN PR's head and
	// its OWN changed files.
	m7, err := git.BuildManifest(d7.PRWorktree, "origin/main", git.ScopeChangedFunctions, 7)
	if err != nil {
		t.Fatalf("build manifest on worktree 7: %v", err)
	}
	m8, err := git.BuildManifest(d8.PRWorktree, "origin/main", git.ScopeChangedFunctions, 8)
	if err != nil {
		t.Fatalf("build manifest on worktree 8: %v", err)
	}
	if m7.HeadSHA != prHeads[7] {
		t.Errorf("the PR-7 manifest carries the wrong head: got %s want %s (the shared-tree race shape)", m7.HeadSHA, prHeads[7])
	}
	if m8.HeadSHA != prHeads[8] {
		t.Errorf("the PR-8 manifest carries the wrong head: got %s want %s", m8.HeadSHA, prHeads[8])
	}
	if len(m7.ChangedFiles) != 1 || m7.ChangedFiles[0] != "b.txt" {
		t.Errorf("the PR-7 manifest carries the wrong changed files: %v", m7.ChangedFiles)
	}
	if len(m8.ChangedFiles) != 1 || m8.ChangedFiles[0] != "c.txt" {
		t.Errorf("the PR-8 manifest carries the wrong changed files: %v", m8.ChangedFiles)
	}

	if got := issue665Rev(t, repoDir, "HEAD"); got != base {
		t.Errorf("#665 arm 2: the user's checkout moved: %s -> %s", base, got)
	}
}

// TestIssue665CleanupDeletesRefAndWorktree is the residue witness: the
// cleanup removes BOTH the worktree and the unique ref (the cycle-1
// residue was one leaked ref per --pr invocation).
func TestIssue665CleanupDeletesRefAndWorktree(t *testing.T) {
	repoDir, binDir, _, _ := issue665Env(t)
	issue665Preflight(t, binDir)

	d, err := selectMode(modeOpts{pr: 7, repoPath: repoDir})
	if err != nil {
		t.Fatalf("selectMode --pr 7: %v", err)
	}
	if d.PRWorktree == "" || d.PRRef == "" {
		t.Fatalf("the decision carries no workspace: %+v", d)
	}
	if _, err := os.Stat(d.PRWorktree); err != nil {
		t.Fatalf("the worktree does not exist before cleanup: %v", err)
	}
	if refs := issue665PRRefs(t, repoDir); len(refs) != 1 {
		t.Fatalf("expected exactly the run's unique ref before cleanup, got %v", refs)
	}

	git.CleanupPRWorktree(repoDir, d.PRWorktree, d.PRRef)

	if _, err := os.Stat(d.PRWorktree); !os.IsNotExist(err) {
		t.Errorf("the worktree dir survived cleanup: stat err %v", err)
	}
	if refs := issue665PRRefs(t, repoDir); len(refs) != 0 {
		t.Errorf("the unique ref survived cleanup: %v", refs)
	}
	// the no-op contract: callers call it unconditionally
	git.CleanupPRWorktree(repoDir, "", "")
}

// TestIssue665CrashResidueSweptByNextRun is the self-heal witness, and the
// same-SHA sibling-safety regression (the fable-F1 class): a crashed run
// and a LIVE run of the SAME PR share one commit — the sweep's name-pid
// tie must sweep the dead residue and spare the live sibling (a SHA join
// would destroy the live sibling's tree mid-scan).
func TestIssue665CrashResidueSweptByNextRun(t *testing.T) {
	repoDir, binDir, _, _ := issue665Env(t)
	issue665Preflight(t, binDir)

	// A genuinely dead pid: spawn a child, reap it, reuse its number.
	dead := exec.Command("sleep", "0")
	if err := dead.Start(); err != nil {
		t.Fatalf("spawn the dead-pid child: %v", err)
	}
	deadPID := dead.Process.Pid
	if err := dead.Wait(); err != nil {
		t.Fatalf("reap the dead-pid child: %v", err)
	}

	// The LIVE sibling FIRST: the same PR, the same commit, its own pid —
	// created BEFORE the dead residue so a later sweep runs while BOTH
	// exist (the coexistence is the fable-F1 race: a SHA join would
	// destroy this live worktree).
	sib, err := selectMode(modeOpts{pr: 7, repoPath: repoDir})
	if err != nil {
		t.Fatalf("selectMode --pr 7 (the live sibling at the PR-7 commit): %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, sib.PRWorktree, sib.PRRef)

	// The crashed run's residue, fabricated exactly as a dead FetchPR
	// leaves it: the unique ref under a DEAD pid, plus a surviving
	// pid-named scratch worktree (the SIGKILL shape — the OS never
	// reaped it) — at the SAME commit as the live sibling above.
	crashRef := "refs/openant/pr/7/" + strconv.Itoa(deadPID)
	crashDir := filepath.Join(t.TempDir(), "openant-pr-"+strconv.Itoa(deadPID)+"-crashed")
	if out, err := exec.Command("git", "-C", repoDir, "fetch", "-q", "origin",
		"pull/7/head:"+crashRef).CombinedOutput(); err != nil {
		t.Fatalf("fabricate the crashed ref: %v: %s", err, out)
	}
	if out, err := exec.Command("git", "-C", repoDir, "worktree", "add",
		"--detach", "--", crashDir, crashRef).CombinedOutput(); err != nil {
		t.Fatalf("fabricate the crashed worktree: %v: %s", err, out)
	}
	if _, err := os.Stat(crashDir); err != nil {
		t.Fatalf("precondition: the crashed worktree should exist: %v", err)
	}

	// The triggering run: its FetchPR sweep fires while the live sibling
	// and the dead residue COEXIST at the same commit.
	trigger, err := selectMode(modeOpts{pr: 8, repoPath: repoDir})
	if err != nil {
		t.Fatalf("selectMode --pr 8 (the triggering run): %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, trigger.PRWorktree, trigger.PRRef)

	// the dead residue is swept
	if _, err := os.Stat(crashDir); !os.IsNotExist(err) {
		t.Errorf("the crashed run's worktree dir survived the sweep: stat err %v", err)
	}
	// the live sibling at the SAME commit survives the sweep intact
	if _, err := os.Stat(sib.PRWorktree); err != nil {
		t.Errorf("the live sibling's worktree was destroyed by the sweep (the name-pid tie regression): %v", err)
	}
	refs := issue665PRRefs(t, repoDir)
	want := map[string]bool{sib.PRRef: true, trigger.PRRef: true}
	if len(refs) != 2 || !want[refs[0]] || !want[refs[1]] {
		t.Errorf("the sweep misbehaved (want the live sibling's + the trigger's refs): %v", refs)
	}
}

// TestIssue665PrepareDiffManifestIsolation pins the parse --pr plumbing:
// prepareDiffManifest builds the manifest against the ISOLATED worktree
// (head_sha = the PR head, changed files = the PR's), returns the
// workspace for the caller's cleanup, and leaves the user's tree alone.
func TestIssue665PrepareDiffManifestIsolation(t *testing.T) {
	repoDir, binDir, base, prHeads := issue665Env(t)
	issue665Preflight(t, binDir)
	outDir := t.TempDir()

	manifestPath, prwt, err := prepareDiffManifest(repoDir, outDir, diffOpts{pr: 7, scope: git.ScopeChangedFiles})
	if err != nil {
		t.Fatalf("prepareDiffManifest --pr 7: %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, prwt.Worktree, prwt.Ref)

	if prwt.Worktree == "" || prwt.Ref == "" {
		t.Fatalf("no workspace returned: %+v", prwt)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m git.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if m.HeadSHA != prHeads[7] {
		t.Errorf("the manifest carries the wrong head: got %s want %s", m.HeadSHA, prHeads[7])
	}
	if len(m.ChangedFiles) != 1 || m.ChangedFiles[0] != "b.txt" {
		t.Errorf("the manifest carries the wrong changed files: %v", m.ChangedFiles)
	}
	if got := issue665Rev(t, repoDir, "HEAD"); got != base {
		t.Errorf("the user's checkout moved: %s -> %s", base, got)
	}
}

// TestIssue665ManifestParityWithInPlace is the no-behavior-regression
// differential for the MANIFEST: the isolated-worktree build is
// field-identical to what the pre-isolation in-place detached flow built
// (same base, head, changed files, hunks). The TREES are not identical in
// content: the worktree is a clean checkout of the PR head, so the
// user's untracked/ignored files are not scanned and submodules init
// best-effort — the documented contract sharpening (--pr scans the PR's
// committed tree, not the user's working-directory residue).
func TestIssue665ManifestParityWithInPlace(t *testing.T) {
	repoDir, binDir, _, prHeads := issue665Env(t)
	issue665Preflight(t, binDir)

	d, err := selectMode(modeOpts{pr: 7, repoPath: repoDir})
	if err != nil {
		t.Fatalf("selectMode --pr 7: %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, d.PRWorktree, d.PRRef)

	mScratch, err := git.BuildManifest(d.PRWorktree, "origin/main", git.ScopeChangedFunctions, 7)
	if err != nil {
		t.Fatalf("build manifest on the worktree: %v", err)
	}

	// The in-place equivalent: detach the user's clone at the same unique
	// ref exactly the way the pre-isolation flow did, build the manifest
	// there, then put the tree back.
	if out, err := exec.Command("git", "-C", repoDir, "checkout", "-q", "--detach", d.PRRef).CombinedOutput(); err != nil {
		t.Fatalf("in-place detach: %v: %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("git", "-C", repoDir, "checkout", "-q", "main").Run()
	})
	mInPlace, err := git.BuildManifest(repoDir, "origin/main", git.ScopeChangedFunctions, 7)
	if err != nil {
		t.Fatalf("build manifest in place: %v", err)
	}

	// field-identical means the WHOLE struct: base, head, ref, scope,
	// PR number, changed files, and hunk maps (a count-only compare
	// overclaims — the astra-audit catch)
	if !reflect.DeepEqual(mScratch, mInPlace) {
		t.Errorf("the manifests are not field-identical:\nscratch: %+v\nin place: %+v", mScratch, mInPlace)
	}
	if mScratch.HeadSHA != prHeads[7] {
		t.Errorf("both manifests carry the wrong head: got %s want %s", mScratch.HeadSHA, prHeads[7])
	}
}

// TestIssue665SubmoduleParity pins the submodule contract (the
// fable-delta + fable-re-round catch chain): the scratch populates
// EXACTLY the user's active submodule set — including a path containing
// SPACES — a PR-ADDED submodule is never populated (parity with the
// in-place checkout, which never auto-initialized it) and NEVER written
// into the user's shared .git/config.
func TestIssue665SubmoduleParity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the gh shim and the local submodule paths are unix-shaped")
	}

	// the child repos
	mkChild := func(name, body string) string {
		dir := t.TempDir()
		run := func(args ...string) {
			c := exec.Command("git", args...)
			c.Dir = dir
			if out, err := c.CombinedOutput(); err != nil {
				t.Fatalf("git %v (child %s): %v: %s", args, name, err, out)
			}
		}
		run("init", "-q", "-b", "main")
		run("config", "user.email", "test@example.com")
		run("config", "user.name", "Test")
		run("config", "commit.gpgsign", "false")
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		run("add", ".")
		run("commit", "-q", "-m", "child "+name)
		return dir
	}
	child1 := mkChild("readme.txt", "one\n")
	child2 := mkChild("readme2.txt", "two\n")

	// the parent env, offline (the issue665Env pattern + submodules)
	origin := t.TempDir()
	if out, err := exec.Command("git", "init", "--bare", "-q", "-b", "main", origin).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
	repoDir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = repoDir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	run("config", "commit.gpgsign", "false")
	// the offline env's submodule children are local file paths; git >= 2.38
	// blocks the file transport for submodules by default, and Apple's 2.50
	// ignores a LOCAL-scope allowance for the submodule clone — so redirect
	// the GLOBAL config to a test file that allows it. The env var is
	// inherited by every git subprocess, including the scratch's submodule
	// update inside FetchPR (the production path never weakens the setting
	// for real runs — real submodules are https).
	gcfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(gcfg, []byte("[protocol \"file\"]\n\tallow = always\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", gcfg)
	if err := os.WriteFile(filepath.Join(repoDir, "a.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "base")
	run("remote", "add", "origin", origin)
	// the user's ACTIVE submodule — a path with a SPACE (the F5 class)
	run("submodule", "add", "-q", child1, "my libs/one")
	run("commit", "-q", "-m", "submodule")
	run("push", "-q", "origin", "main")
	base := issue665Rev(t, repoDir, "HEAD")

	// the PR head adds a SECOND submodule
	run("submodule", "add", "-q", child2, "libs/new")
	run("commit", "-q", "-m", "pr head")
	prHead := issue665Rev(t, repoDir, "HEAD")
	run("push", "-q", "origin", "HEAD:refs/pull/7/head")
	run("reset", "--hard", base)
	// emulate a user who NEVER authored the new submodule: the authoring
	// `submodule add` wrote submodule.libs/new.* into this clone's config,
	// and reset --hard does not remove config sections — a user who never
	// touched it carries no such keys (the fable-F1 counterexample's shape)
	if out, err := exec.Command("git", "-C", repoDir, "config", "--local",
		"--remove-section", "submodule.libs/new").CombinedOutput(); err != nil {
		t.Logf("the libs/new section was absent (fine): %s", out)
	}

	// the gh shim
	binDir := t.TempDir()
	gh := filepath.Join(binDir, "gh")
	if err := os.WriteFile(gh, []byte("#!/bin/sh\necho '{\"baseRefName\":\"main\"}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	issue665Preflight(t, binDir)

	// the user's config snapshot — the run must not write it
	cfgBefore := issue665Config(t, repoDir)

	d, err := selectMode(modeOpts{pr: 7, repoPath: repoDir})
	if err != nil {
		t.Fatalf("selectMode --pr 7: %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, d.PRWorktree, d.PRRef)
	if d.PRWorktree == "" {
		t.Fatal("no workspace returned")
	}

	// the user's ACTIVE submodule IS populated in the scratch (spaces intact)
	if _, err := os.Stat(filepath.Join(d.PRWorktree, "my libs/one", "readme.txt")); err != nil {
		t.Errorf("the user's active submodule (a path with a space) is not populated in the scratch: %v", err)
	}
	// the PR-added submodule is NOT populated (parity: the in-place checkout never auto-initialized it)
	if _, err := os.Stat(filepath.Join(d.PRWorktree, "libs", "new", "readme2.txt")); err == nil {
		t.Error("the PR-added submodule is populated in the scratch — parity broken (the in-place checkout never auto-initialized it)")
	}
	// the user's shared .git/config gained NOTHING
	if cfgAfter := issue665Config(t, repoDir); cfgAfter != cfgBefore {
		t.Errorf("the run wrote the user's .git/config:\nbefore:\n%s\nafter:\n%s", cfgBefore, cfgAfter)
	}
	_ = prHead

	// THE RECURSIVE-CLONE SHAPE (the fable-re-round F7 fixture): a user
	// who got the repo via `git clone --recurse-submodules` carries NO
	// per-name .active config keys — only the submodule.active pathspec
	// and per-name .url — so any config-key derivation is dead code for
	// the most common populated shape. The content+gitlink oracle must
	// populate their scratch (the pre-fix in-place scan read their
	// populated submodule).
	user2 := filepath.Join(t.TempDir(), "user2")
	if out, err := exec.Command("git", "clone", "-q", "--recurse-submodules",
		origin, user2).CombinedOutput(); err != nil {
		t.Fatalf("the recursive clone: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(user2, "my libs/one", "readme.txt")); err != nil {
		t.Fatalf("precondition: the recursive clone should carry the populated submodule: %v", err)
	}
	d2, err := selectMode(modeOpts{pr: 7, repoPath: user2})
	if err != nil {
		t.Fatalf("selectMode --pr 7 (the recursive-clone user): %v", err)
	}
	defer git.CleanupPRWorktree(user2, d2.PRWorktree, d2.PRRef)
	if _, err := os.Stat(filepath.Join(d2.PRWorktree, "my libs/one", "readme.txt")); err != nil {
		t.Errorf("the recursive-clone user's populated submodule is not populated in the scratch (the F7 shape): %v", err)
	}

	// THE DELIBERATE OPT-OUT SHAPE (the fable-F10 fixture): a user who
	// hand-set submodule."my libs/one".active=false (content still
	// present, gitlink still at HEAD) — the run must neither populate it
	// in the scratch nor flip the user's shared config flag.
	if out, err := exec.Command("git", "-C", repoDir, "config", "--local",
		"submodule.my libs/one.active", "false").CombinedOutput(); err != nil {
		t.Fatalf("hand-set the opt-out flag: %v: %s", err, out)
	}
	d3, err := selectMode(modeOpts{pr: 7, repoPath: repoDir})
	if err != nil {
		t.Fatalf("selectMode --pr 7 (the opted-out user): %v", err)
	}
	if _, err := os.Stat(filepath.Join(d3.PRWorktree, "my libs/one", "readme.txt")); err == nil {
		t.Error("the opted-out submodule is populated in the scratch — the deliberate opt-out was ignored")
	}
	if out, err := exec.Command("git", "-C", repoDir, "config", "--bool",
		"submodule.my libs/one.active").Output(); err != nil || strings.TrimSpace(string(out)) != "false" {
		t.Errorf("the user's explicit .active=false flag did not survive the run: out %q err %v", out, err)
	}
	git.CleanupPRWorktree(repoDir, d3.PRWorktree, d3.PRRef)
}

func issue665Config(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "config", "--local", "--list").Output()
	if err != nil {
		t.Fatalf("git config --local --list: %v", err)
	}
	return string(out)
}

// TestInitPRCleansWorkspaceAndKeepsUserTree is the runInit WIRING guard
// (the C4 green-revert closure — the E1/E2 class): the #767 pattern drives
// the FULL init --pr flow in-process (no python needed), so the
// normal-end cleanup and the stamp-swap wiring are exercised end-to-end:
// after runInit the user's checkout is unmoved, the workspace (worktree +
// unique ref) is GONE, the stamp names the PR head, and the scan meta's
// branch reads "" (the worktree's detached HEAD — the pre-isolation
// in-place value).
func TestInitPRCleansWorkspaceAndKeepsUserTree(t *testing.T) {
	repoDir, binDir, first, head, prHead := initPRTestEnv(t)
	initPRDriveFlags(t, repoDir, "p665-wiring", "", 7)
	initPRPreflight(t, binDir)

	_ = captureStderr(t, func() { runInit(nil, []string{repoDir}) })

	// the stamp names the PR head (the #669 contract through the worktree)
	if got := persistedCommitSHA(t, "p665-wiring"); got != prHead {
		t.Errorf("stamped SHA = %s, want the PR head %s (pre-checkout HEAD %s, seed %s)", got, prHead, head, first)
	}
	// the user's checkout never moved
	if got := issue665Rev(t, repoDir, "HEAD"); got != head {
		t.Errorf("runInit moved the user's checkout: HEAD %s -> %s", head, got)
	}
	if got := issue665Branch(t, repoDir); got != "main" {
		t.Errorf("runInit moved the user's branch: main -> %s", got)
	}
	// the workspace is GONE (the normal-end cleanup wiring)
	if refs := issue665PRRefs(t, repoDir); len(refs) != 0 {
		t.Errorf("the unique refs survived runInit: %v", refs)
	}
	var worktrees []string
	out, err := exec.Command("git", "-C", repoDir, "worktree", "list", "--porcelain").Output()
	if err != nil {
		t.Fatalf("worktree list: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if w, ok := strings.CutPrefix(line, "worktree "); ok {
			if strings.Contains(filepath.Base(strings.TrimSpace(w)), "openant-pr-") {
				worktrees = append(worktrees, strings.TrimSpace(w))
			}
		}
	}
	if len(worktrees) != 0 {
		t.Errorf("the scratch worktrees survived runInit: %v", worktrees)
	}
	// the scan meta's branch names the SCANNED tree ("" — detached)
	metaBranch := issueScanMetaBranch(t, "p665-wiring", config.ShortSHA(persistedCommitSHA(t, "p665-wiring")))
	if metaBranch != "" {
		t.Errorf("the scan meta's branch = %q, want \"\" (the worktree's detached HEAD — the pre-isolation value)", metaBranch)
	}
}

func issueScanMetaBranch(t *testing.T, name, shortSHA string) string {
	t.Helper()
	// the meta lives at the config package's own path:
	// projects/<name>/scans/<shortSHA>/<language>/meta.json (the
	// initPRDriveFlags language is go)
	runDir, err := config.ScanRunDir(name, shortSHA)
	if err != nil {
		return "(no run dir)"
	}
	raw, err := os.ReadFile(filepath.Join(runDir, "go", "meta.json"))
	if err != nil {
		return "(no meta)"
	}
	var meta struct {
		Branch string `json:"branch"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	return meta.Branch
}

func issue665PRRefs(t *testing.T, dir string) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "for-each-ref", "--format=%(refname)", "refs/openant/pr/").Output()
	if err != nil {
		t.Fatalf("git for-each-ref refs/openant/pr/: %v", err)
	}
	var refs []string
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			refs = append(refs, line)
		}
	}
	return refs
}

// TestIssue665AdoptionRefetchesPRHead pins the F1 catch (the cycle-3 r1
// round): a pending `init --pr N` decision adopted by a FLAGLESS scan must
// RE-FETCH the PR head into the scan's own isolated worktree. The
// pre-isolation era left the head checked out in the user's tree, so a
// bare {Kind, Base, Scope} adoption scanned the right tree by that
// mechanism; with the checkout gone it silently scanned the USER's tree
// while stamping the PR head's SHA (zero changed files, exit 0 — a
// false-negative generator). At the pre-cycle-3 head this test fails with
// PRWorktree="" (no fetch); the record carries no PR either.
func TestIssue665AdoptionRefetchesPRHead(t *testing.T) {
	repoDir, binDir, base, prHeads := issue665Env(t)
	issue665Preflight(t, binDir)

	withTempHome(t)
	// the pending --pr decision created by the REAL runInit path (pins the
	// writeInitScanMeta stamp too — the E1/E2 catch: seeding the meta by
	// hand left init's stamping unguarded)
	xdg := initPRDriveFlags(t, repoDir, "p665-adopt", "", 7)
	initPRPreflight(t, binDir)
	_ = captureStderr(t, func() { runInit(nil, []string{repoDir}) })
	persisted := persistedCommitSHA(t, "p665-adopt")
	if persisted != prHeads[7] {
		t.Fatalf("init stamped %s, want the PR head %s", persisted, prHeads[7])
	}
	stamped, err := config.LoadScanMeta("p665-adopt", config.ShortSHA(prHeads[7]), "go")
	if err != nil {
		t.Fatalf("load init's meta: %v", err)
	}
	if stamped.PR != 7 {
		t.Fatalf("init's meta carries PR=%d, want 7 (the F1 record)", stamped.PR)
	}
	_ = xdg

	// the flagless scan state: NO mode flags, the language matching the record
	savedLang, savedPR, savedBase, savedFull, savedInc, savedStaged := scanLanguage, scanPR, scanDiffBase, scanFull, scanIncremental, scanStaged
	scanLanguage, scanPR, scanDiffBase, scanFull, scanIncremental, scanStaged = "go", 0, "", false, false, false
	t.Cleanup(func() { scanLanguage, scanPR, scanDiffBase, scanFull, scanIncremental, scanStaged = savedLang, savedPR, savedBase, savedFull, savedInc, savedStaged })

	ctx := &projectContext{Project: &config.Project{Name: "p665-adopt", CommitSHAShort: config.ShortSHA(prHeads[7]), Language: "go"}, RepoPath: repoDir}

	got, err := resolveScanMode(ctx, repoDir)
	if err != nil {
		t.Fatalf("the flagless adoption errored: %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, got.PRWorktree, got.PRRef)

	if got.PR != 7 {
		t.Errorf("the adopted decision lost the PR: got %d, want 7", got.PR)
	}
	if got.PRWorktree == "" {
		t.Fatal("the flagless adoption did NOT re-fetch: PRWorktree empty — the scan would scan the USER's tree with a PR-head stamp (the F1 regression)")
	}
	// the worktree holds the PR HEAD, not the user's tree
	if rev := issue665Rev(t, got.PRWorktree, "HEAD"); rev != prHeads[7] {
		t.Errorf("the adopted worktree HEAD = %s, want the PR head %s (the user tree is at %s)", rev, prHeads[7], base)
	}
	// the user's checkout still never moved
	if rev := issue665Rev(t, repoDir, "HEAD"); rev != base {
		t.Errorf("the adoption moved the user's checkout: %s -> %s", base, rev)
	}
}

// TestIssue665NoKeyExitsBeforeFetch pins the F2 catch (the cycle-3 r1
// round): a `scan --pr` with NO API key must exit BEFORE the fetch creates
// anything. requireAPIKey() os.Exit(2)s, and it was previously evaluated
// as an ARGUMENT to python.Invoke — after the fetch — so the no-key run
// stranded a full PR checkout in $TMPDIR plus its ref and worktree entry.
// Driven through the same re-exec harness as the CLI-witness tests (the
// real rootCmd, the fake engine resolving cleanly so the flow WOULD reach
// Invoke), with NO --api-key and the env key cleared: at the pre-cycle-3
// head the fetch has already run when the key check exits, and the
// workspace strands — this test fails on the residue.
func TestIssue665NoKeyExitsBeforeFetch(t *testing.T) {
	repoDir, binDir, base, _ := issue665Env(t)
	issue665Preflight(t, binDir)
	out := t.TempDir()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	proc := exec.Command(exe,
		"-test.run=TestIssue665HelperCLI",
		"--", "scan", repoDir, "--pr", "7", "--skip-dynamic-test", "-o", out, "--no-report")
	// an ISOLATED home + XDG in the child: otherwise the child reads the
	// REAL machine's config.json and a key may resolve there (the dev
	// machine runs OpenAnt) — the no-key arm would never fire
	childHome := t.TempDir()
	childXDG := t.TempDir()
	proc.Env = append(os.Environ(),
		issue665RoleEnv+"="+issue665RoleCLI,
		"OPENANT_PYTHON="+exe,
		"OPENANT_TEST_665_USERCLONE="+repoDir,
		"OPENANT_API_KEY=",
		"HOME="+childHome,
		"XDG_CONFIG_HOME="+childXDG,
	)
	outb, err := proc.CombinedOutput()
	rc := 0
	if exit, ok := err.(*exec.ExitError); ok {
		rc = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("re-exec the CLI: %v: %s", err, outb)
	}
	if rc != 2 {
		t.Errorf("the no-key exit code = %d, want 2: %s", rc, lastLines(outb))
	}
	if !strings.Contains(string(outb), "No API key configured") {
		t.Errorf("the no-key message missing: %s", lastLines(outb))
	}
	// THE F2 assertion: nothing was created before the exit
	if refs := issue665PRRefs(t, repoDir); len(refs) != 0 {
		t.Errorf("the no-key exit stranded PR refs (the fetch ran before the key check — the F2 arm): %v", refs)
	}
	var worktrees []string
	wout, err := exec.Command("git", "-C", repoDir, "worktree", "list", "--porcelain").Output()
	if err != nil {
		t.Fatalf("worktree list: %v", err)
	}
	for _, line := range strings.Split(string(wout), "\n") {
		if w, ok := strings.CutPrefix(line, "worktree "); ok {
			if strings.Contains(filepath.Base(strings.TrimSpace(w)), "openant-pr-") {
				worktrees = append(worktrees, strings.TrimSpace(w))
			}
		}
	}
	if len(worktrees) != 0 {
		t.Errorf("the no-key exit stranded worktrees (the F2 arm): %v", worktrees)
	}
	_ = base
}

// TestIssue665ResolveScanModeBranchStamp pins the branch-stamp block
// in-process (the r2 D2 catch: the defense-in-depth claim's "cannot be
// executed" premise was false — resolveScanMode is directly drivable, the
// same entry the adoption pin uses). The mutant (branchRepo := repoPath)
// survives the battery; this test kills it.
func TestIssue665ResolveScanModeBranchStamp(t *testing.T) {
	repoDir, binDir, base, prHeads := issue665Env(t)
	issue665Preflight(t, binDir)

	withTempHome(t)
	// no pending record: the scan --pr flag path writes the running meta
	// with the branch stamped from the WORKTREE (detached: "")
	savedLang, savedPR, savedBase, savedFull, savedInc, savedStaged, savedSkip := scanLanguage, scanPR, scanDiffBase, scanFull, scanIncremental, scanStaged, scanSkipDynamicTest
	scanLanguage, scanPR, scanDiffBase, scanFull, scanIncremental, scanStaged, scanSkipDynamicTest = "go", 7, "", false, false, false, true
	t.Cleanup(func() { scanLanguage, scanPR, scanDiffBase, scanFull, scanIncremental, scanStaged, scanSkipDynamicTest = savedLang, savedPR, savedBase, savedFull, savedInc, savedStaged, savedSkip })

	ctx := &projectContext{Project: &config.Project{Name: "p665-branchstamp", CommitSHAShort: config.ShortSHA(prHeads[7]), Language: "go", CommitSHA: prHeads[7]}, RepoPath: repoDir}

	d, err := resolveScanMode(ctx, repoDir)
	if err != nil {
		t.Fatalf("resolveScanMode --pr: %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, d.PRWorktree, d.PRRef)

	meta, err := config.LoadScanMeta("p665-branchstamp", config.ShortSHA(prHeads[7]), "go")
	if err != nil {
		t.Fatalf("load the running meta: %v", err)
	}
	if meta.Branch != "" {
		t.Errorf("the running meta's branch = %q, want \"\" (the WORKTREE's detached HEAD — the detached-PR-head stamp; the user's tree is on main at %s)", meta.Branch, base[:8])
	}
	if meta.PR != 7 {
		t.Errorf("the running meta's PR = %d, want 7 (the r2 D1 catch: the running record carries the PR)", meta.PR)
	}
}

// TestIssue665ParseAdoptionCarriesPR pins the r3 F1 catch (the parse
// verb's twin of the scan adoption fix): a flagless `parse` after
// `init --pr N` must carry the PR so prepareDiffManifest re-fetches into
// the run's own isolated worktree. At the pre-cycle-3 head the fallback
// returned a bare {base, scope} — the manifest was built on the USER's
// tree (zero changed files) while the dataset was stamped with the PR
// head's SHA.
func TestIssue665ParseAdoptionCarriesPR(t *testing.T) {
	repoDir, binDir, _, prHeads := issue665Env(t)
	issue665Preflight(t, binDir)

	withTempHome(t)
	initPRDriveFlags(t, repoDir, "p665-parse-adopt", "", 7)
	initPRPreflight(t, binDir)
	_ = captureStderr(t, func() { runInit(nil, []string{repoDir}) })
	stamped, err := config.LoadScanMeta("p665-parse-adopt", config.ShortSHA(prHeads[7]), "go")
	if err != nil {
		t.Fatalf("load init's meta: %v", err)
	}
	if stamped.PR != 7 {
		t.Fatalf("init's meta carries PR=%d, want 7", stamped.PR)
	}

	// the flagless parse fallback, exactly as runParse resolves it
	ctx := &projectContext{Project: &config.Project{Name: "p665-parse-adopt", CommitSHAShort: config.ShortSHA(prHeads[7]), Language: "go", CommitSHA: prHeads[7]}, RepoPath: repoDir}
	opts, err := resolveStepDiffOpts(ctx, "", 0, "")
	if err != nil {
		t.Fatalf("the flagless parse fallback errored: %v", err)
	}
	if opts.pr != 7 {
		t.Fatalf("the flagless parse fallback dropped the PR: opts=%+v — the manifest would build on the USER's tree (the r3 F1 class)", opts)
	}

	// and the manifest built from it fetches into a real isolated worktree
	out := t.TempDir()
	manifestPath, prwt, err := prepareDiffManifest(repoDir, out, opts)
	if err != nil {
		t.Fatalf("prepareDiffManifest: %v", err)
	}
	defer git.CleanupPRWorktree(repoDir, prwt.Worktree, prwt.Ref)
	if prwt.Worktree == "" {
		t.Fatal("the flagless parse did NOT fetch: prwt empty — the engine would parse the USER's tree with a PR-stamped dataset")
	}
	if rev := issue665Rev(t, prwt.Worktree, "HEAD"); rev != prHeads[7] {
		t.Errorf("the fetched worktree HEAD = %s, want the PR head %s", rev, prHeads[7])
	}
	// the manifest's head names the PR head (read the struct, the parity
	// test's own accessor)
	m, err := git.BuildManifest(prwt.Worktree, "origin/main", opts.scope, 7)
	if err != nil {
		t.Fatalf("re-derive the manifest: %v", err)
	}
	if m.HeadSHA != prHeads[7] {
		t.Errorf("the manifest head = %s, want the PR head %s", m.HeadSHA, prHeads[7])
	}
	if len(m.ChangedFiles) == 0 {
		t.Error("the manifest carries zero changed files — the PR head's b.txt is missing (the user-tree manifest class)")
	}
	_ = manifestPath
}
