package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// initCommitTestRepo makes a throwaway git repo with two commits and returns
// (repoDir, firstCommitSHA, headSHA). HEAD is the second commit.
func initCommitTestRepo(t *testing.T) (dir, first, head string) {
	t.Helper()
	dir = t.TempDir()
	run := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	run("config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "first")
	first = revParse(t, dir, "HEAD")
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "second")
	head = revParse(t, dir, "HEAD")
	if first == head {
		t.Fatalf("expected two distinct commits, got %s == %s", first, head)
	}
	return dir, first, head
}

func revParse(t *testing.T, dir, ref string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", ref).Output()
	if err != nil {
		t.Fatalf("rev-parse %s: %v", ref, err)
	}
	return strings.TrimSpace(string(out))
}

// resolveLocalCommit must reflect what will ACTUALLY be scanned, since openant
// references local repos in place and never checks them out. A --commit that
// differs from HEAD, or that cannot be resolved, must be warned about and
// ignored (record HEAD) — not silently recorded (finding
// gocli-local-commit-no-checkout).
func TestResolveLocalCommit(t *testing.T) {
	dir, first, head := initCommitTestRepo(t)

	// (1) No --commit: record HEAD, no warning.
	sha, warn, err := resolveLocalCommit(dir, "")
	if err != nil {
		t.Fatalf("empty requested: unexpected err: %v", err)
	}
	if sha != head {
		t.Errorf("empty requested: sha=%s want HEAD %s", sha, head)
	}
	if warn != "" {
		t.Errorf("empty requested: unexpected warn %q", warn)
	}

	// (2) --commit matches HEAD: record full HEAD SHA, no warning.
	sha, warn, err = resolveLocalCommit(dir, head)
	if err != nil {
		t.Fatalf("head requested: unexpected err: %v", err)
	}
	if sha != head {
		t.Errorf("head requested: sha=%s want %s", sha, head)
	}
	if warn != "" {
		t.Errorf("head requested: unexpected warn %q", warn)
	}

	// (3) --commit is a valid commit that is NOT checked out (older commit).
	// The working tree is at HEAD, so we must record HEAD and WARN — never
	// silently record `first` (which the working tree is not at).
	sha, warn, err = resolveLocalCommit(dir, first)
	if err != nil {
		t.Fatalf("older requested: unexpected err: %v", err)
	}
	if sha != head {
		t.Errorf("older requested: sha=%s want HEAD %s (repo is not checked out to %s)", sha, head, first)
	}
	if warn == "" {
		t.Errorf("older requested: expected a warning that --commit is not checked out")
	}

	// (4) --commit is unresolvable garbage: warn and fall back to HEAD; never
	// silently record the bogus ref.
	sha, warn, err = resolveLocalCommit(dir, "deadbeefdeadbeef")
	if err != nil {
		t.Fatalf("bogus requested: unexpected err: %v", err)
	}
	if sha == "deadbeefdeadbeef" {
		t.Errorf("bogus requested: recorded unresolved ref verbatim %q", sha)
	}
	if sha != head {
		t.Errorf("bogus requested: sha=%s want HEAD %s", sha, head)
	}
	if warn == "" {
		t.Errorf("bogus requested: expected a warning about unresolvable --commit")
	}
}
