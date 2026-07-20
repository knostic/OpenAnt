package languages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Go detector had no tests at all before this file — cmd/ has no
// init_test.go. That is how the tie-break nondeterminism below survived.

func writeTree(t *testing.T, root string, files []string) {
	t.Helper()
	for _, rel := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func TestSupportedMatchesConfig(t *testing.T) {
	got, err := Supported()
	if err != nil {
		t.Fatalf("Supported() error: %v", err)
	}
	want := []string{"c", "go", "javascript", "php", "python", "ruby", "zig"}
	if len(got) != len(want) {
		t.Fatalf("Supported() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Supported() = %v, want %v", got, want)
		}
	}
}

func TestFlagHelpIsDerivedFromConfig(t *testing.T) {
	help := FlagHelp()
	for _, lang := range []string{"python", "javascript", "go", "c", "ruby", "php", "zig"} {
		if !strings.Contains(help, lang) {
			t.Errorf("FlagHelp() omits %q: %s", lang, help)
		}
	}
	if !strings.Contains(help, "auto") {
		t.Errorf("FlagHelp() omits auto: %s", help)
	}
}

func TestDetectLanguagesCountsPerLanguage(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, []string{
		"a.py", "b.py", "c.py",
		"x.ts", "y.js",
		"main.go",
	})

	counts, err := DetectLanguages(dir)
	if err != nil {
		t.Fatalf("DetectLanguages error: %v", err)
	}
	want := map[string]int{"python": 3, "javascript": 2, "go": 1}
	if len(counts) != len(want) {
		t.Fatalf("counts = %v, want %v", counts, want)
	}
	for lang, n := range want {
		if counts[lang] != n {
			t.Errorf("counts[%s] = %d, want %d", lang, counts[lang], n)
		}
	}
}

func TestSkipDirsArePruned(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, []string{
		"app.py",
		"node_modules/pkg/index.js",
		"node_modules/pkg/deep/nested/more.js",
		"vendor/lib.go",
		".git/hooks/thing.py",
	})

	counts, err := DetectLanguages(dir)
	if err != nil {
		t.Fatalf("DetectLanguages error: %v", err)
	}
	if counts["javascript"] != 0 {
		t.Errorf("node_modules not pruned: javascript=%d", counts["javascript"])
	}
	if counts["go"] != 0 {
		t.Errorf("vendor not pruned: go=%d", counts["go"])
	}
	if counts["python"] != 1 {
		t.Errorf("python = %d, want 1 (.git must be pruned)", counts["python"])
	}
}

// TestTieBreakIsDeterministic fails on the pre-refactor implementation.
//
// The old loop kept the first strictly-greater count while iterating a Go map,
// whose order is randomized per run. On a tie it returned an arbitrary winner —
// and could disagree with the Python detector on the same repo.
func TestTieBreakIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, []string{"a.py", "b.py", "x.js", "y.js"})

	first, err := DetectLanguage(dir)
	if err != nil {
		t.Fatalf("DetectLanguage error: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, err := DetectLanguage(dir)
		if err != nil {
			t.Fatalf("DetectLanguage error on run %d: %v", i, err)
		}
		if got != first {
			t.Fatalf("nondeterministic tie-break: run 0 = %q, run %d = %q", first, i, got)
		}
	}
	// Alphabetical on a tie, matching the Python side.
	if first != "javascript" {
		t.Errorf("tie between javascript and python resolved to %q, want %q", first, "javascript")
	}
}

func TestDetectLanguagePicksDominant(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, []string{"a.py", "b.py", "c.py", "x.js"})

	got, err := DetectLanguage(dir)
	if err != nil {
		t.Fatalf("DetectLanguage error: %v", err)
	}
	if got != "python" {
		t.Errorf("DetectLanguage = %q, want python", got)
	}
}

func TestEmptyRepoErrors(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, []string{"README.md", "Makefile"})

	if _, err := DetectLanguage(dir); err == nil {
		t.Fatal("expected an error for a repo with no supported source files")
	}
}

func TestRankedOrdersByCountThenName(t *testing.T) {
	got := Ranked(map[string]int{"go": 2, "python": 5, "zig": 2, "c": 9})
	want := []string{"c", "python", "go", "zig"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Ranked = %v, want %v", got, want)
		}
	}
}

func TestUnreadableDirIsTolerated(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, []string{"a.py"})
	// A walk error on one entry must not abort the whole detection.
	if _, err := DetectLanguages(filepath.Join(dir, "does-not-exist")); err != nil {
		t.Fatalf("walking a missing dir should degrade, got: %v", err)
	}
}
