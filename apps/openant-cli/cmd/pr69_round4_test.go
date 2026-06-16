package cmd

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// R4-4 — secret hygiene. The setup wizard echoed the pasted API key
// (no no-echo read) and `set-api-key` only accepted the key as an argv
// (leaks via shell history / `ps`). The fix:
//   - promptSecret reads with no echo on a TTY, and falls back to the
//     reader-based promptString when stdin is NOT a terminal (so piped /
//     scripted input and the existing tests keep working).
//   - `set-api-key` makes the <key> argv OPTIONAL; when omitted it reads
//     the key via the no-echo prompt.
// ---------------------------------------------------------------------------

// TestPromptSecret_FallsBackToReaderWhenNotTTY proves the no-echo helper
// degrades to a normal reader-based line read when stdin is not a terminal
// (the case for pipes, CI, and every test in this package). Without the
// fallback, ReadPassword on a non-TTY fd errors and breaks scripted input.
func TestPromptSecret_FallsBackToReaderWhenNotTTY(t *testing.T) {
	// os.Pipe fds are never terminals, so this exercises the fallback path.
	reader := bufio.NewReader(strings.NewReader("sk-piped-secret\n"))

	// Silence the prompt written to stderr.
	origStderr := os.Stderr
	devnull, _ := os.Open(os.DevNull)
	os.Stderr = devnull
	t.Cleanup(func() {
		os.Stderr = origStderr
		devnull.Close()
	})

	got, err := promptSecret(reader, "API key")
	if err != nil {
		t.Fatalf("promptSecret returned error on non-TTY fallback: %v", err)
	}
	if got != "sk-piped-secret" {
		t.Errorf("promptSecret = %q, want %q", got, "sk-piped-secret")
	}
}

// TestSetAPIKey_ReadsKeyFromStdinWhenNoArgv proves `set-api-key` works with
// NO positional argument by reading the key from stdin via the no-echo
// prompt (which falls back to the reader on a non-TTY). Before the fix the
// command required exactly one argv, so this path did not exist.
func TestSetAPIKey_ReadsKeyFromStdinWhenNoArgv(t *testing.T) {
	configPath := resolveConfigPathForTest(t)

	// Stub the Anthropic validation endpoint to 200 so the key is accepted.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	orig := anthropicAPIURL
	defer func() { anthropicAPIURL = orig }()
	anthropicAPIURL = server.URL

	// Feed the key on stdin (a pipe — not a TTY — so promptSecret falls back
	// to the reader path).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString("sk-from-stdin\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = origStdin
		r.Close()
	})

	// Silence stderr.
	origStderr := os.Stderr
	devnull, _ := os.Open(os.DevNull)
	os.Stderr = devnull
	t.Cleanup(func() {
		os.Stderr = origStderr
		devnull.Close()
	})

	// Run with NO argv — this must succeed by reading the key from stdin.
	runSetAPIKey(setAPIKeyCmd, []string{})

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config not written (key from stdin was not saved): %v", err)
	}
	if !strings.Contains(string(data), "sk-from-stdin") {
		t.Errorf("config does not contain the stdin-provided key; got: %s", string(data))
	}
}

// TestSetAPIKey_AcceptsAtMostOneArg locks the Args contract: the argv key is
// now OPTIONAL (back-compat) but capped at one positional argument.
func TestSetAPIKey_AcceptsAtMostOneArg(t *testing.T) {
	if setAPIKeyCmd.Args == nil {
		t.Fatal("setAPIKeyCmd.Args is nil")
	}
	// Zero args must be allowed (read from stdin).
	if err := setAPIKeyCmd.Args(setAPIKeyCmd, []string{}); err != nil {
		t.Errorf("set-api-key must accept zero args (read from stdin), got: %v", err)
	}
	// One arg is the back-compat path.
	if err := setAPIKeyCmd.Args(setAPIKeyCmd, []string{"sk-x"}); err != nil {
		t.Errorf("set-api-key must accept one arg (back-compat), got: %v", err)
	}
	// Two args must be rejected.
	if err := setAPIKeyCmd.Args(setAPIKeyCmd, []string{"sk-x", "sk-y"}); err == nil {
		t.Error("set-api-key must reject two args")
	}
}

// resolveConfigPathForTest points the config layer at a fresh temp dir and
// returns the resolved config.json path. Local copy so this file is
// self-contained.
func resolveConfigPathForTest(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", tmp)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tmp)
	}
	return filepath.Join(tmp, "openant", "config.json")
}
