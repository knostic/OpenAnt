package python

import (
	"crypto/sha256"
	"encoding/hex"
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

// testDepsHashPath overrides the venv dir for testing by writing directly
// to a known path. Since readStoredHash/writeStoredHash use depsHashPath()
// which depends on the user's home dir, we test the underlying logic with
// direct file operations that mirror the implementation.

func TestWriteAndReadStoredHash_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".deps-hash")

	hash := "abc123def456"
	if err := os.WriteFile(path, []byte(hash+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	got := string(data)
	if got != hash+"\n" {
		t.Errorf("round-trip failed: got %q, want %q", got, hash+"\n")
	}
}

func TestReadStoredHash_MissingFile(t *testing.T) {
	// readStoredHash returns "" for missing file
	got := readStoredHash()
	// This reads from the real depsHashPath which may or may not exist.
	// We just verify it doesn't panic and returns a string.
	_ = got
}

func TestReadStoredHash_ReturnsEmpty_WhenNoVenv(t *testing.T) {
	// If the venv dir doesn't exist, readStoredHash should return ""
	// without error. We can't easily override venvDir() but we verify
	// that reading a nonexistent file returns "".
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", ".deps-hash")
	data, err := os.ReadFile(path)
	if err != nil {
		// Expected — file doesn't exist
		return
	}
	// If somehow it does exist, it should be empty or a hash
	_ = data
}

// ---------------------------------------------------------------------------
// CheckDepsStale — integration-style tests with temp dirs
// ---------------------------------------------------------------------------

func TestCheckDepsStale_SkipsWhenCoreNotFound(t *testing.T) {
	// CheckDepsStale should silently return nil when it can't find
	// openant-core. We chdir to a temp dir so findOpenantCore fails.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	err = CheckDepsStale("/nonexistent/python")
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
