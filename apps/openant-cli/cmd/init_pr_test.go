package cmd

// #767: PR #672's body promised a composed-path regression test for
// `init --pr` — the stamped-SHA fix (the checkout SHA, not the
// pre-checkout HEAD) and the `--commit` guard. The PR shipped cmd/init.go
// only; both changes were regression-unpinned with the promise on the
// merged record. This file is that test.
//
// The PR checkout (`git.FetchPR`) shells `gh` directly, so the drive is
// offline: a PATH-shimmed `gh` printing a fixed baseRefName, a local
// file-path `origin` carrying refs/pull/7/head, and XDG_CONFIG_HOME
// redirected per-test so the config writes land in the test's temp dir.
// The assertions read the persisted project.json — the stamped SHA is the
// contract the scan dirs and meta.json key off (the #669 fix's subject).

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
)

// initPRTestEnv builds an offline PR-checkout environment:
// a local repo whose HEAD is `head` whose `origin` (a bare repo) carries
// refs/heads/main at `head` and refs/pull/7/head at `prHead` (one commit
// ahead), plus a PATH-shimmed `gh` printing {"baseRefName":"main"}.
// Returns the repo dir, the shim's bin dir (for initPRPreflight), and
// the seed/base/PR-head SHAs.
func initPRTestEnv(t *testing.T) (repoDir string, binDir string, first string, head string, prHead string) {
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
	if err := os.WriteFile(filepath.Join(repoDir, "seed.txt"), []byte("s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "seed")
	first = revParse(t, repoDir, "HEAD")
	if err := os.WriteFile(filepath.Join(repoDir, "a.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "base")
	run("remote", "add", "origin", origin)
	run("push", "-q", "origin", "main")
	head = revParse(t, repoDir, "HEAD")

	// The PR head: one commit ahead of main, published as refs/pull/7/head.
	if err := os.WriteFile(filepath.Join(repoDir, "b.txt"), []byte("y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "pr head")
	prHead = revParse(t, repoDir, "HEAD")
	// Publish the PR head BEFORE moving the working tree back: refs/pull/7/head
	// must name the PR commit, not the base.
	run("push", "-q", "origin", "HEAD:refs/pull/7/head")
	// Move the working tree back to the base commit: the pre-checkout HEAD
	// differs from the PR head, so a stamp of HEAD (the #672 pre-fix
	// behavior) is distinguishable from a stamp of the checkout.
	run("reset", "--hard", head)

	// The PATH-shimmed gh: FetchPR's `gh pr view` reads a fixed baseRefName.
	binDir = t.TempDir()
	gh := filepath.Join(binDir, "gh")
	script := "#!/bin/sh\necho '{\"baseRefName\":\"main\"}'\n"
	if err := os.WriteFile(gh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if first == head || head == prHead || first == prHead {
		t.Fatalf("expected distinct seed/base/pr SHAs, got %s %s %s", first, head, prHead)
	}
	return repoDir, binDir, first, head, prHead
}

// initPRDriveFlags snapshots the package flag vars, points them at the
// offline PR environment, and restores them (and the redirected homes) on
// cleanup. The returned XDG root covers only config.json (the
// active-project pointer); the project and scan writes route through the
// redirected HOME.
func initPRDriveFlags(t *testing.T, repoDir, name, commit string, pr int) string {
	t.Helper()
	old := initPRState()
	initPR = pr
	initCommit = commit
	initName = name
	initLanguage = "go"
	initFull, initIncremental = false, false
	initDiffBase, initDiffScope = "", ""
	// #767/r1-F1: the project + scan writes route through
	// config.DataDir() = UserHomeDir()/.openant — NOT XDG — so redirect the
	// home itself (withTempHome handles USERPROFILE on windows too); XDG
	// still covers config.json (the active-project pointer).
	withTempHome(t)
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Cleanup(func() { initPRRestore(old) })
	return xdg
}

type initFlags struct {
	pr       int
	commit   string
	name     string
	language string
	full     bool
	inc      bool
	diffBase string
	scope    string
}

func initPRState() initFlags {
	return initFlags{initPR, initCommit, initName, initLanguage, initFull, initIncremental, initDiffBase, initDiffScope}
}

func initPRRestore(f initFlags) {
	initPR, initCommit, initName, initLanguage = f.pr, f.commit, f.name, f.language
	initFull, initIncremental, initDiffBase, initDiffScope = f.full, f.inc, f.diffBase, f.scope
}

// initPRPreflight asserts the PATH shim is what `gh` resolves to before
// the drive: a missing shim inside runInit is an os.Exit(2) that kills the
// whole test binary (selectMode's error path), not a t.Fatal — so the shim
// is checked HERE, where a failure is a named test failure (#767/r1-F3).
func initPRPreflight(t *testing.T, binDir string) {
	t.Helper()
	got, err := exec.LookPath("gh")
	if err != nil || filepath.Dir(got) != binDir {
		t.Fatalf("gh resolved to %q (%v), want the shim in %q — runInit would os.Exit(2) the binary", got, err, binDir)
	}
}

// captureStderr swaps os.Stderr for a pipe around fn and returns what fn
// printed (the guard's PrintWarning lands there).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	fn()
	os.Stderr = old
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	all, _ := io.ReadAll(r)
	_ = r.Close()
	return string(all)
}

// persistedCommitSHA reads the stamped SHA out of the run's project.json.
func persistedCommitSHA(t *testing.T, name string) string {
	t.Helper()
	projDir, err := config.ProjectDir(name)
	if err != nil {
		t.Fatalf("ProjectDir: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(projDir, "project.json"))
	if err != nil {
		t.Fatalf("read project.json: %v", err)
	}
	var proj struct {
		CommitSHA string `json:"commit_sha"`
	}
	if err := json.Unmarshal(raw, &proj); err != nil {
		t.Fatalf("parse project.json: %v: %s", err, raw)
	}
	if proj.CommitSHA == "" {
		t.Fatalf("project.json carries no commit_sha: %s", raw)
	}
	return proj.CommitSHA
}

// TestInitPRWithCommitIgnoresCommitAndStampsCheckout is the #672 composed
// path, case 1: `init --pr 7 --commit <sha>` on a repo whose PR head differs
// from the current HEAD — the guard warns that --commit is ignored, and the
// stamped SHA is the PR checkout's (never the pre-checkout HEAD, never the
// ignored --commit argument).
func TestInitPRWithCommitIgnoresCommitAndStampsCheckout(t *testing.T) {
	repoDir, binDir, first, head, prHead := initPRTestEnv(t)
	initPRDriveFlags(t, repoDir, "p767-a", first, 7)
	initPRPreflight(t, binDir)

	stderr := captureStderr(t, func() { runInit(nil, []string{repoDir}) })

	if !strings.Contains(stderr, "--commit ignored: the PR checkout determines the stamped SHA") {
		t.Errorf("missing the --commit-ignored guard warning; stderr:\n%s", stderr)
	}
	if got := persistedCommitSHA(t, "p767-a"); got != prHead {
		t.Errorf("stamped SHA = %s, want the PR checkout %s (pre-checkout HEAD %s; the ignored --commit %s)",
			got, prHead, head, first)
	}
}

// TestInitPRAloneStampsCheckout is case 2: `init --pr 7` alone — the
// stamped SHA is the PR checkout's (the re-resolution PR #672 was titled
// for), and no --commit warning fires.
func TestInitPRAloneStampsCheckout(t *testing.T) {
	repoDir, binDir, _, head, prHead := initPRTestEnv(t)
	initPRDriveFlags(t, repoDir, "p767-b", "", 7)
	initPRPreflight(t, binDir)

	stderr := captureStderr(t, func() { runInit(nil, []string{repoDir}) })

	if strings.Contains(stderr, "--commit ignored") {
		t.Errorf("no --commit was given; unexpected guard warning; stderr:\n%s", stderr)
	}
	if got := persistedCommitSHA(t, "p767-b"); got != prHead {
		t.Errorf("stamped SHA = %s, want the PR checkout %s (pre-checkout HEAD %s)", got, prHead, head)
	}
}

// TestInitPRWithCommitEqualCheckoutStillGuards pins the guard's
// as-shipped branch (#767/r1-F5): the warning fires even when the explicit
// --commit EQUALS the PR checkout — the checkout, not the --commit value,
// is the stamp's authority, and the guard is unconditional.
func TestInitPRWithCommitEqualCheckoutStillGuards(t *testing.T) {
	repoDir, binDir, _, head, prHead := initPRTestEnv(t)
	initPRDriveFlags(t, repoDir, "p767-c", prHead, 7)
	initPRPreflight(t, binDir)

	stderr := captureStderr(t, func() { runInit(nil, []string{repoDir}) })

	if !strings.Contains(stderr, "--commit ignored: the PR checkout determines the stamped SHA") {
		t.Errorf("the guard is unconditional: --commit == the checkout still warns; stderr:\n%s", stderr)
	}
	if got := persistedCommitSHA(t, "p767-c"); got != prHead {
		t.Errorf("stamped SHA = %s, want the PR checkout %s (pre-checkout HEAD %s)", got, prHead, head)
	}
}
