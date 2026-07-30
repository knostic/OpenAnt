package main

// Executable containment test for the Go scanner. It was missing: the shared
// contract test (tests/test_scanner_contract.py) drives only the Python-family
// scanners and its docstring claimed "Node, Go ... covered by their own runtime's
// suite" — a suite that did not exist. That false comfort is how the Go
// file-symlink exfiltration hole shipped: filepath.Walk lstat's each entry, so a
// symlinked file `leak.go -> /outside/secret` was added with a .go extension and
// read THROUGH the link into the dataset (and thence the model provider). These
// tests exercise the refuse-every-symlink guard against real symlinks on disk.

import (
	"os"
	"path/filepath"
	"testing"
)

// A symlinked file pointing outside the repo, and a symlinked directory, must
// both be refused — never added to Files, and counted as coverage gaps.
func TestScan_RefusesSymlinkedFileAndDir(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRET-CANARY\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "real.go"),
		[]byte("package main\nfunc real() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// leak.go -> outside secret (the exfiltration vector), and a dir symlink.
	if err := os.Symlink(secret, filepath.Join(repo, "leak.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "sub", "vendordir")); err != nil {
		t.Fatal(err)
	}

	result, err := NewScanner(repo, true).Scan()
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range result.Files {
		if f.Path == "leak.go" {
			t.Fatalf("symlinked file leak.go was scanned (followed out of repo); Files=%v", result.Files)
		}
	}
	if result.Statistics.TotalFiles != 1 {
		t.Errorf("expected only real.go scanned, got TotalFiles=%d (%v)",
			result.Statistics.TotalFiles, result.Files)
	}
	if result.Statistics.SymlinksSkipped != 2 {
		t.Errorf("expected symlinks_skipped=2 (file + dir), got %d",
			result.Statistics.SymlinksSkipped)
	}
	if len(result.Statistics.SymlinkExamples) == 0 {
		t.Error("expected symlink_examples to be recorded")
	}
}

// Negative control: a clean repo scans all real files, and symlinks_skipped is
// present at 0 — the "0" marks the parser as coverage-instrumented (present),
// distinguishing it from a parser that reports no coverage at all (absent).
func TestScan_CleanRepoReportsZeroSkipped(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "a.go"),
		[]byte("package main\nfunc a() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := NewScanner(repo, true).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if result.Statistics.TotalFiles != 1 {
		t.Errorf("expected 1 real file, got %d", result.Statistics.TotalFiles)
	}
	if result.Statistics.SymlinksSkipped != 0 {
		t.Errorf("clean repo should skip no symlinks, got %d", result.Statistics.SymlinksSkipped)
	}
	if result.Statistics.DirectoriesUnreadable != 0 {
		t.Errorf("clean repo should have no unreadable dirs, got %d",
			result.Statistics.DirectoriesUnreadable)
	}
}

// An unreadable directory is a counted coverage gap, not a silent skip — a
// silent skip is a false negative, the worst direction for a SAST tool.
func TestScan_UnreadableDirIsCounted(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "a.go"),
		[]byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(repo, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "b.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) }) // let TempDir cleanup succeed

	result, err := NewScanner(repo, true).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if result.Statistics.DirectoriesUnreadable != 1 {
		t.Errorf("expected directories_unreadable=1, got %d", result.Statistics.DirectoriesUnreadable)
	}
	if len(result.Statistics.UnreadableExamples) == 0 {
		t.Error("expected unreadable_examples to be recorded")
	}
}
