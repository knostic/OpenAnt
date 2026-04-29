package git

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// initTestRepo creates a throwaway git repo at dir and commits a single
// initial file so HEAD exists. Subsequent commits are made by the test.
func initTestRepo(t *testing.T, dir string) {
	t.Helper()
	runCmd(t, dir, "git", "init", "-q", "-b", "main")
	runCmd(t, dir, "git", "config", "user.email", "test@example.com")
	runCmd(t, dir, "git", "config", "user.name", "Test")
	runCmd(t, dir, "git", "config", "commit.gpgsign", "false")
}

func runCmd(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, stderr.String())
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestChangedFilesAndHunks(t *testing.T) {
	dir := t.TempDir()
	initTestRepo(t, dir)

	// Commit 1: initial state.
	writeFile(t, dir, "a.txt", "line1\nline2\nline3\nline4\nline5\n")
	writeFile(t, dir, "b.txt", "hello\nworld\n")
	runCmd(t, dir, "git", "add", ".")
	runCmd(t, dir, "git", "commit", "-q", "-m", "init")

	base, err := gitRevParse(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}

	// Commit 2: modify a.txt (add/change lines), delete b.txt entirely,
	// add a new file c.txt.
	writeFile(t, dir, "a.txt", "line1\nline2 MODIFIED\nline3\nline4\nline5\nline6 ADDED\n")
	if err := os.Remove(filepath.Join(dir, "b.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "c.txt", "brand new\n")
	runCmd(t, dir, "git", "add", "-A")
	runCmd(t, dir, "git", "commit", "-q", "-m", "changes")

	files, err := ChangedFiles(dir, base)
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	want := []string{"a.txt", "b.txt", "c.txt"}
	sort.Strings(files)
	if !reflect.DeepEqual(files, want) {
		t.Errorf("ChangedFiles = %v, want %v", files, want)
	}

	// a.txt: one hunk for the modified line (line 2), one hunk for the
	// added line (line 6). Exact count=0 hunks should be filtered; a.txt
	// has no pure-deletion hunks on the new side.
	hunksA, err := HunksForFile(dir, base, "a.txt")
	if err != nil {
		t.Fatalf("HunksForFile a.txt: %v", err)
	}
	if len(hunksA) == 0 {
		t.Fatalf("expected hunks on a.txt, got none")
	}
	// Ensure every returned range is positive and non-degenerate.
	for _, h := range hunksA {
		if h[0] < 1 || h[1] < h[0] {
			t.Errorf("bad hunk range %v", h)
		}
	}

	// b.txt is fully deleted on the new side — no content survives in
	// HEAD. Every hunk should be count=0 and therefore skipped.
	hunksB, err := HunksForFile(dir, base, "b.txt")
	if err != nil {
		t.Fatalf("HunksForFile b.txt: %v", err)
	}
	if len(hunksB) != 0 {
		t.Errorf("expected no hunks for deleted file b.txt, got %v", hunksB)
	}

	// c.txt is brand new — one hunk starting at line 1.
	hunksC, err := HunksForFile(dir, base, "c.txt")
	if err != nil {
		t.Fatalf("HunksForFile c.txt: %v", err)
	}
	if len(hunksC) != 1 || hunksC[0][0] != 1 {
		t.Errorf("unexpected hunks on c.txt: %v", hunksC)
	}
}

func TestChangedFilesDetectsRenames(t *testing.T) {
	dir := t.TempDir()
	initTestRepo(t, dir)

	// Commit 1: file at old path.
	writeFile(t, dir, "old.txt", strings.Repeat("same content line\n", 20))
	runCmd(t, dir, "git", "add", ".")
	runCmd(t, dir, "git", "commit", "-q", "-m", "init")

	base, err := gitRevParse(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}

	// Commit 2: rename only (no content change).
	runCmd(t, dir, "git", "mv", "old.txt", "new.txt")
	runCmd(t, dir, "git", "commit", "-q", "-m", "rename")

	files, err := ChangedFiles(dir, base)
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	// With --find-renames, git reports only the new path.
	if len(files) != 1 || files[0] != "new.txt" {
		t.Errorf("want [new.txt], got %v", files)
	}
}

func TestBuildManifestChangedFilesScope(t *testing.T) {
	dir := t.TempDir()
	initTestRepo(t, dir)

	writeFile(t, dir, "a.txt", "one\ntwo\n")
	runCmd(t, dir, "git", "add", ".")
	runCmd(t, dir, "git", "commit", "-q", "-m", "init")

	writeFile(t, dir, "a.txt", "one\ntwo changed\nthree\n")
	runCmd(t, dir, "git", "commit", "-aq", "-m", "edit")

	m, err := BuildManifest(dir, "HEAD~1", ScopeChangedFiles, 0)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if m.Scope != ScopeChangedFiles {
		t.Errorf("scope = %q, want %q", m.Scope, ScopeChangedFiles)
	}
	if m.Hunks != nil {
		t.Errorf("hunks should be nil for changed_files scope, got %v", m.Hunks)
	}
	if len(m.ChangedFiles) != 1 || m.ChangedFiles[0] != "a.txt" {
		t.Errorf("ChangedFiles = %v", m.ChangedFiles)
	}
	if m.BaseSHA == "" || m.HeadSHA == "" || m.BaseSHA == m.HeadSHA {
		t.Errorf("unexpected shas base=%s head=%s", m.BaseSHA, m.HeadSHA)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "diff_manifest.json")

	want := &Manifest{
		BaseRef:      "origin/main",
		BaseSHA:      "abc",
		HeadSHA:      "def",
		Scope:        ScopeChangedFunctions,
		PRNumber:     123,
		ChangedFiles: []string{"a.py", "b.py"},
		Hunks: map[string][][2]int{
			"a.py": {{10, 20}, {30, 31}},
			"b.py": {{1, 1}},
		},
	}
	if err := WriteManifest(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch:\n got  %+v\n want %+v", got, want)
	}
}

func TestIsValidScope(t *testing.T) {
	valid := []string{ScopeChangedFiles, ScopeChangedFunctions, ScopeCallers}
	for _, s := range valid {
		if !IsValidScope(s) {
			t.Errorf("IsValidScope(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "foo", "CHANGED_FILES"} {
		if IsValidScope(s) {
			t.Errorf("IsValidScope(%q) = true, want false", s)
		}
	}
}

func TestHunkHeaderRegex(t *testing.T) {
	cases := []struct {
		line      string
		wantStart int
		wantCount int // 0 = no match expected
	}{
		{"@@ -1,3 +1,5 @@", 1, 5},
		{"@@ -10 +20 @@", 20, 1},          // implicit count=1
		{"@@ -5,0 +12,3 @@", 12, 3},
		{"@@ -5,2 +0,0 @@", 0, 0},          // pure deletion — count=0
		{"not a hunk header", 0, 0},
	}
	for _, c := range cases {
		m := hunkHeaderRe.FindStringSubmatch(c.line)
		if m == nil {
			if c.wantCount != 0 || strings.HasPrefix(c.line, "@@") {
				// Only fail when we expected a match or it really did look
				// like a hunk header.
				if c.wantStart != 0 {
					t.Errorf("regex failed on %q", c.line)
				}
			}
			continue
		}
		if got := m[1]; got == "" || itoaEq(got, c.wantStart) == false {
			t.Errorf("%q: start = %q, want %d", c.line, m[1], c.wantStart)
		}
	}
}

func itoaEq(s string, n int) bool {
	var acc int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
		acc = acc*10 + int(ch-'0')
	}
	return acc == n
}
