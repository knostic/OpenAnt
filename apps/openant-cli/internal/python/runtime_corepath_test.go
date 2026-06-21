package python

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression test: the dependency-staleness check keyed only on
// pyproject.toml content, blind to corePath. The managed venv is a single global path shared across
// all worktrees; with two worktrees whose pyproject.toml is identical, the staleness check reports
// "not stale" even though the venv's editable install (`pip install -e <corePath>`) points at the
// OTHER worktree's source — so a binary built in worktree B silently imports worktree A's Python.
// Fix: key staleness on corePath as well, so switching the editable-install source is detected.
func TestDepsStalenessDetectsCorePathChange(t *testing.T) {
	const pyproject = "[project]\nname = \"openant\"\nversion = \"1.0.0\"\n"

	coreA := t.TempDir()
	coreB := t.TempDir()
	if err := os.WriteFile(filepath.Join(coreA, "pyproject.toml"), []byte(pyproject), 0644); err != nil {
		t.Fatal(err)
	}
	// coreB has BYTE-IDENTICAL pyproject.toml — only the corePath differs.
	if err := os.WriteFile(filepath.Join(coreB, "pyproject.toml"), []byte(pyproject), 0644); err != nil {
		t.Fatal(err)
	}

	hashPath := filepath.Join(t.TempDir(), ".deps-hash")

	// Baseline: install was done from coreA -> stamp coreA's hash.
	_, hashA, err := depsStalenessAt(coreA, hashPath)
	if err != nil {
		t.Fatalf("depsStalenessAt(coreA): %v", err)
	}
	if err := writeHashAt(hashPath, hashA); err != nil {
		t.Fatalf("writeHashAt: %v", err)
	}

	// Same corePath -> not stale.
	if staleA, _, _ := depsStalenessAt(coreA, hashPath); staleA {
		t.Fatalf("same corePath reported stale (should be up-to-date)")
	}

	// Different corePath, identical pyproject -> MUST be stale: otherwise the two worktrees share
	// one editable install and the binary imports the wrong source.
	staleB, _, err := depsStalenessAt(coreB, hashPath)
	if err != nil {
		t.Fatalf("depsStalenessAt(coreB): %v", err)
	}
	if !staleB {
		t.Fatalf("corePath change (identical pyproject) not detected as stale -> worktrees share the editable install")
	}
}
