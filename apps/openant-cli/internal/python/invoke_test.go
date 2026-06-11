package python

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// writeHangScript creates an executable script that ignores its arguments,
// prints nothing on stdout, and sleeps far longer than any test deadline.
// It stands in for a hung Python parser (infinite loop / I/O deadlock).
func writeHangScript(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("hang-subprocess test uses a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "hang.sh")
	// Sleep well past the test's deadline; never produces stdout.
	script := "#!/bin/sh\nsleep 600\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write hang script: %v", err)
	}
	return path
}

// TestInvoke_HangingSubprocessIsBoundedByTimeout asserts that a hung Python
// subprocess must be bounded by an automatic timeout so Invoke returns
// instead of blocking forever on cmd.Wait().
//
// Pre-fix invoke.go:33 uses exec.Command (no context, no deadline), so
// Invoke blocks on io.Copy/cmd.Wait for the full 600s sleep and this test
// hangs until `go test` kills it — i.e. it does NOT return within the
// bounded window. Post-fix (exec.CommandContext + a default timeout) the
// command is killed at the deadline and Invoke returns promptly.
func TestInvoke_HangingSubprocessIsBoundedByTimeout(t *testing.T) {
	hang := writeHangScript(t)

	// Shrink the automatic deadline so the test is fast. The default is
	// far larger; this knob is the wiring the fix must expose.
	prev := defaultInvokeTimeout
	defaultInvokeTimeout = 500 * time.Millisecond
	t.Cleanup(func() { defaultInvokeTimeout = prev })

	// Generous wall-clock budget: comfortably larger than the deadline but
	// far smaller than the 600s the subprocess would otherwise sleep.
	const budget = 10 * time.Second

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Invoke(hang, []string{"parse", "."}, "", true, "")
	}()

	select {
	case <-done:
		// Invoke returned within budget — the timeout bounded the hang.
	case <-time.After(budget):
		t.Fatalf("Invoke did not return within %v on a hung subprocess; "+
			"expected the automatic timeout (%v) to bound it", budget, defaultInvokeTimeout)
	}
}
