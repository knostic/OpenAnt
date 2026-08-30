package python

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// #59 (ar7casper, the extra-care protocol): end-user installs must be
// deterministic — requirements.txt (the exact pins CI uses) is installed
// first, then the editable install; the deps staleness hash covers BOTH
// files so a change to either triggers a reinstall.
// ---------------------------------------------------------------------------

func TestInstallCommandRunsRequirementsThenEditable(t *testing.T) {
	cmds := installOpenantCmds("python3", t.TempDir())
	// a temp dir has no requirements.txt — the degrade path is 1 cmd (the old behavior)
	_ = cmds
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("x==1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmds = installOpenantCmds("python3", dir)
	if len(cmds) != 2 {
		t.Fatalf("expected requirements+editable (2 commands), got %d", len(cmds))
	}
	reqArgs := cmds[0].Args
	foundReqs := false
	for _, a := range reqArgs {
		if a == "-r" {
			foundReqs = true
		}
	}
	if !foundReqs {
		t.Errorf("the FIRST command must install requirements.txt (the exact CI pins); got %v", reqArgs)
	}
	foundEditable := false
	for _, a := range cmds[1].Args {
		if a == "-e" {
			foundEditable = true
		}
	}
	if !foundEditable {
		t.Errorf("the SECOND command must install the editable package; got %v", cmds[1].Args)
	}
}

func TestInstallCommandDegradedWithoutRequirements(t *testing.T) {
	cmds := installOpenantCmds("python3", t.TempDir())
	if len(cmds) != 1 {
		t.Fatalf("a dir without requirements.txt degrades to the editable install alone (1 command), got %d", len(cmds))
	}
}

func TestDepsHashCoversRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	req := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(req, []byte("anthropic==1.2.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("name='x'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h1, err := depsHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(req, []byte("anthropic==1.3.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2, err := depsHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Errorf("a requirements.txt change must trigger a reinstall (the hash must cover both files)")
	}
}

func TestDepsHashStillCoversCorePath(t *testing.T) {
	// the pre-existing key: two worktrees with identical files must NOT share one hash
	a := t.TempDir()
	b := t.TempDir()
	for _, d := range []string{a, b} {
		if err := os.WriteFile(filepath.Join(d, "pyproject.toml"), []byte("name='x'\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "requirements.txt"), []byte("anthropic==1.2.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ha, _ := depsHash(a)
	hb, _ := depsHash(b)
	if ha == hb {
		t.Errorf("corePath must stay in the key (the two-worktrees-silent-import hazard)")
	}
}

func TestDepsHashMissingRequirementsAbstains(t *testing.T) {
	// a core dir without requirements.txt (a dev layout that dropped it?):
	// the staleness check must degrade gracefully, not error every run
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("name='x'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := depsHash(dir); err != nil {
		t.Errorf("a missing requirements.txt must not error the staleness check (the caller skips on error — an error every run would break installs): %v", err)
	}
}
