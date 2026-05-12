package python

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// venvPython / venvDir
// ---------------------------------------------------------------------------

func TestVenvPython_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("test only runs on Windows")
	}

	vp := venvPython()
	expected := filepath.Join(os.Getenv("USERPROFILE"), ".openant", "venv", "Scripts", "python.exe")
	if vp != expected {
		t.Errorf("venvPython() = %q, want %q", vp, expected)
	}

	if !filepath.IsAbs(vp) {
		t.Errorf("venvPython() should return absolute path, got %q", vp)
	}
}

func TestVenvPython_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix-like systems")
	}

	vp := venvPython()
	if !filepath.IsAbs(vp) {
		t.Errorf("venvPython() should return absolute path, got %q", vp)
	}

	if !strings.HasSuffix(vp, filepath.Join("bin", "python")) {
		t.Errorf("venvPython() on Unix should end with bin/python, got %q", vp)
	}
}

func TestVenvDir_ReturnsAbsolutePath(t *testing.T) {
	vd := venvDir()
	if !filepath.IsAbs(vd) {
		t.Errorf("venvDir() should return absolute path, got %q", vd)
	}
}

// ---------------------------------------------------------------------------
// hashFile
// ---------------------------------------------------------------------------

func TestHashFile_KnownContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	content := []byte("[project]\nname = \"openant\"\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile returned error: %v", err)
	}

	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("hashFile = %q, want %q", got, want)
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile returned error: %v", err)
	}

	sum := sha256.Sum256([]byte{})
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("hashFile = %q, want %q", got, want)
	}
}

func TestHashFile_MissingFile(t *testing.T) {
	_, err := hashFile(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestHashFile_DifferentContent(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.toml")
	pathB := filepath.Join(dir, "b.toml")
	os.WriteFile(pathA, []byte("version 1"), 0644)
	os.WriteFile(pathB, []byte("version 2"), 0644)

	hashA, _ := hashFile(pathA)
	hashB, _ := hashFile(pathB)
	if hashA == hashB {
		t.Error("different files should produce different hashes")
	}
}

// ---------------------------------------------------------------------------
// readStoredHash / writeStoredHash
// ---------------------------------------------------------------------------

// readStoredHash / writeStoredHash delegate to readHashAt/writeHashAt with
// a path under the user's real ~/.openant/venv/. The tests exercise the
// underlying readHashAt/writeHashAt helpers directly to avoid touching the
// real venv directory.

func TestWriteAndReadHashAt_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".deps-hash")

	hash := "abc123def456"
	if err := writeHashAt(path, hash); err != nil {
		t.Fatalf("writeHashAt: %v", err)
	}

	got := readHashAt(path)
	if got != hash {
		t.Errorf("readHashAt = %q, want %q (trailing newline should be trimmed)", got, hash)
	}
}

func TestReadHashAt_MissingFile_ReturnsEmpty(t *testing.T) {
	got := readHashAt(filepath.Join(t.TempDir(), "nonexistent"))
	if got != "" {
		t.Errorf("readHashAt missing file = %q, want \"\"", got)
	}
}

func TestReadHashAt_TrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".deps-hash")
	if err := os.WriteFile(path, []byte("  abc\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := readHashAt(path); got != "abc" {
		t.Errorf("readHashAt = %q, want %q", got, "abc")
	}
}

func TestReadStoredHash_DoesNotPanic(t *testing.T) {
	// Smoke test: reading from the real ~/.openant/venv/.deps-hash must
	// not panic regardless of whether the file exists.
	_ = readStoredHash()
}

func TestWriteHashAt_CreatesMissingParentDir(t *testing.T) {
	dir := t.TempDir()
	// nested directory that does not yet exist
	path := filepath.Join(dir, "a", "b", ".deps-hash")
	if err := writeHashAt(path, "deadbeef"); err != nil {
		t.Fatalf("writeHashAt should create missing parents: %v", err)
	}
	if got := readHashAt(path); got != "deadbeef" {
		t.Errorf("readHashAt after writeHashAt = %q, want %q", got, "deadbeef")
	}
}

// ---------------------------------------------------------------------------
// depsStalenessAt — covers the trigger detection logic without invoking pip
// ---------------------------------------------------------------------------

// writeFakeCore creates a minimal pyproject.toml under a fake core dir and
// returns the core dir path.
func writeFakeCore(t *testing.T, contents string) string {
	t.Helper()
	core := t.TempDir()
	if err := os.WriteFile(filepath.Join(core, "pyproject.toml"), []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return core
}

func TestDepsStalenessAt_FreshState_NoHashStored_IsStale(t *testing.T) {
	core := writeFakeCore(t, "[project]\nname = \"x\"\n")
	hashPath := filepath.Join(t.TempDir(), ".deps-hash")

	stale, cur, err := depsStalenessAt(core, hashPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stale {
		t.Error("expected stale=true when no hash has been stored")
	}
	if cur == "" {
		t.Error("expected non-empty current hash")
	}
}

func TestDepsStalenessAt_MatchingHash_NotStale(t *testing.T) {
	core := writeFakeCore(t, "[project]\nname = \"x\"\n")
	hashPath := filepath.Join(t.TempDir(), ".deps-hash")

	// First call: capture the hash and write it out.
	_, cur, err := depsStalenessAt(core, hashPath)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := writeHashAt(hashPath, cur); err != nil {
		t.Fatal(err)
	}

	// Second call: hash matches, should not be stale.
	stale, _, err := depsStalenessAt(core, hashPath)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if stale {
		t.Error("expected stale=false when stored hash matches current")
	}
}

func TestDepsStalenessAt_ModifiedPyproject_IsStale(t *testing.T) {
	core := writeFakeCore(t, "[project]\nname = \"x\"\nversion = \"0.1\"\n")
	hashPath := filepath.Join(t.TempDir(), ".deps-hash")

	_, originalHash, err := depsStalenessAt(core, hashPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeHashAt(hashPath, originalHash); err != nil {
		t.Fatal(err)
	}

	// Mutate pyproject.toml — simulating a `git pull` that bumped a dep.
	if err := os.WriteFile(
		filepath.Join(core, "pyproject.toml"),
		[]byte("[project]\nname = \"x\"\nversion = \"0.2\"\ndependencies = [\"requests\"]\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	stale, newHash, err := depsStalenessAt(core, hashPath)
	if err != nil {
		t.Fatal(err)
	}
	if !stale {
		t.Error("expected stale=true after pyproject.toml was modified")
	}
	if newHash == originalHash {
		t.Error("expected new hash to differ from original after content change")
	}
}

func TestDepsStalenessAt_MissingPyproject_ReturnsError(t *testing.T) {
	core := t.TempDir() // no pyproject.toml inside
	hashPath := filepath.Join(t.TempDir(), ".deps-hash")

	stale, _, err := depsStalenessAt(core, hashPath)
	if err == nil {
		t.Error("expected error when pyproject.toml is missing")
	}
	if stale {
		t.Error("expected stale=false on error")
	}
}

func TestDepsStalenessAt_StoredHashEqualsEmpty_StillStale(t *testing.T) {
	// If the hash file is present but empty (e.g. truncated write), the
	// stored hash trims to "" and we should treat the deps as stale so the
	// next run heals the state by reinstalling.
	core := writeFakeCore(t, "[project]\nname = \"x\"\n")
	hashPath := filepath.Join(t.TempDir(), ".deps-hash")
	if err := os.WriteFile(hashPath, []byte("\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stale, _, err := depsStalenessAt(core, hashPath)
	if err != nil {
		t.Fatal(err)
	}
	if !stale {
		t.Error("expected stale=true when stored hash is empty")
	}
}

// ---------------------------------------------------------------------------
// CheckDepsStale — integration-style tests with temp dirs
// ---------------------------------------------------------------------------

func TestCheckDepsStale_SkipsWhenCoreNotFound(t *testing.T) {
	err := checkDepsStaleWith("/nonexistent/python", func() (string, error) {
		return "", errors.New("simulated: core not found")
	})
	if err != nil {
		t.Errorf("expected nil when core not found, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// fileExists
// ---------------------------------------------------------------------------

func TestFileExists_True(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.txt")
	os.WriteFile(path, []byte("hi"), 0644)

	if !fileExists(path) {
		t.Error("fileExists should return true for existing file")
	}
}

func TestFileExists_False_Missing(t *testing.T) {
	if fileExists(filepath.Join(t.TempDir(), "nope")) {
		t.Error("fileExists should return false for missing file")
	}
}

func TestFileExists_False_Directory(t *testing.T) {
	dir := t.TempDir()
	if fileExists(dir) {
		t.Error("fileExists should return false for directories")
	}
}
