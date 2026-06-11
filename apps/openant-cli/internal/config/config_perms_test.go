package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// CWE-732: Save() does not enforce restrictive
// permissions on a PRE-EXISTING config file. os.WriteFile only applies the mode argument
// when it creates the file; if the config (which may hold an API key) already exists with
// looser perms (e.g. 0644), the secret stays world-readable after Save().
func TestSaveEnforcesRestrictivePermsOnPreexistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode bits not enforced on Windows")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	dir := filepath.Join(tmp, "openant")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")

	// Pre-existing config file with loose (world/group-readable) permissions.
	if err := os.WriteFile(path, []byte(`{"api_key":"old"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil { // defeat umask so the file is genuinely 0644
		t.Fatal(err)
	}

	if err := Save(&Config{APIKey: "sk-secret-value"}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("secret config perms = %#o, want 0600 (CWE-732: pre-existing loose perms not enforced)", perm)
	}
}
