//go:build unix

package python

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Invoke must bound a DETACHED descendant holding the stdout write-end at
// child-exit + WaitDelay, not at the invoke deadline. The engine's subprocesses
// inherit the Go-side pipes (core/reporter.py / parser_adapter.py pass
// stdout/stderr through), so a descendant that outlives its Python parent while
// holding only the pipe write-end is a live shape — and with Invoke's manual
// StdoutPipe reads, Wait (the only thing that starts WaitDelay) was never
// reached: the watchdog closed the read-end at the DEADLINE, so a run that
// finished in seconds surfaced minutes later under a deadline note (#431's
// cost 2). The managed-writer refactor (invoke_ctx.go's pattern) routes
// cmd.Stdout/cmd.Stderr through os/exec's own copy goroutines, which Wait
// drains and WaitDelay bounds at child-exit + 5s.
func TestInvokeBoundsDetachedStdoutHolderAtWaitDelay(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	// A fake python: prints a complete envelope to stdout, then leaves a
	// detached session holding the stdout write-end, then exits 0.
	fake := filepath.Join(t.TempDir(), "fake-python")
	if err := os.WriteFile(fake, []byte(`#!/bin/sh
echo '{"status":"success"}'
(sleep 30 </dev/null &)
exit 0
`), 0o755); err != nil {
		t.Fatal(err)
	}
	// A deadline well above WaitDelay: on the pre-#431 shape the watchdog
	// closes the read-end at THIS deadline (the whole budget elapses);
	// the fixed shape returns at child-exit + WaitDelay (5s).
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "20s")

	start := time.Now()
	res, err := Invoke(fake, []string{"scan", "x"}, "", true, "")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Invoke errored after %v: %v", elapsed, err)
	}
	if elapsed > 12*time.Second {
		t.Errorf("a run that completed in <1s returned after %v; the held stdout write-end was bounded by the DEADLINE, not WaitDelay (want ~5s)", elapsed)
	}
	if res == nil || res.Envelope.Status != "success" {
		t.Fatalf("the printed envelope must win: %+v", res)
	}
}

// The normal path: no pipe holder, prompt return, envelope + stderr intact.
func TestInvokeManagedWritersNormalExit(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	fake := filepath.Join(t.TempDir(), "fake-python")
	if err := os.WriteFile(fake, []byte(`#!/bin/sh
echo 'progress line' 1>&2
echo '{"status":"success"}'
exit 0
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "20s")

	start := time.Now()
	res, err := Invoke(fake, []string{"scan", "x"}, "", false, "")
	if err != nil {
		t.Fatalf("Invoke errored: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("normal exit took %v — no WaitDelay penalty without a pipe holder", time.Since(start))
	}
	if res == nil || res.Envelope.Status != "success" {
		t.Fatalf("envelope missing: %+v", res)
	}
}
