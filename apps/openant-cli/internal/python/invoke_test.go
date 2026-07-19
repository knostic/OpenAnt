package python

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
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

// TestNormalizeExit pins the documented exit-code contract
// (openant/cli.py:16 — 0=clean, 1=vulnerabilities found, 2=error) that
// normalizeExit enforces before scan.go does os.Exit(result.ExitCode).
func TestNormalizeExit(t *testing.T) {
	cases := []struct {
		name    string
		code    int
		isError bool
		want    int
	}{
		{"success clean", 0, false, 0},
		{"success vulns-found", 1, false, 1},
		{"success signal-killed", -1, false, 2},
		{"error exit0", 0, true, 2},
		{"error exit1", 1, true, 2},
		{"error signal-killed", -1, true, 2},
		{"error already-2", 2, true, 2},
		{"success already-2 preserved", 2, false, 2},
		{"success high code preserved", 3, false, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeExit(tc.code, tc.isError); got != tc.want {
				t.Fatalf("normalizeExit(%d, %v) = %d, want %d", tc.code, tc.isError, got, tc.want)
			}
		})
	}
}

// writeEmptyStdoutScript creates an executable script that exits 0 and prints
// nothing — standing in for a Python child that exited cleanly but never
// emitted its JSON envelope on stdout.
func writeEmptyStdoutScript(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("empty-stdout test uses a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}
	return path
}

// TestInvoke_EmptyStdoutSurfacesErrorCode asserts the WIRING (not just the pure
// helper): a child that exits 0 but produced no envelope must surface as the
// documented error code 2, i.e. normalizeExit is actually applied on the
// empty-stdout return path. A revert to `ExitCode: exitCode` would yield 0 here.
func TestInvoke_EmptyStdoutSurfacesErrorCode(t *testing.T) {
	script := writeEmptyStdoutScript(t)
	res, err := Invoke(script, []string{"parse", "."}, "", true, "")
	if err != nil {
		t.Fatalf("Invoke returned error: %v", err)
	}
	if res.Envelope.Status != "error" {
		t.Fatalf("expected error envelope, got Status=%q", res.Envelope.Status)
	}
	if res.ExitCode != 2 {
		t.Fatalf("empty-stdout error must surface as exit 2, got %d", res.ExitCode)
	}
}

// writeEnvelopeThenTrapScript creates a script that immediately prints a valid
// success envelope on stdout, then traps SIGINT/SIGTERM and exits 0 cleanly
// while sleeping. It models a Python child that fully completed the scan (a
// real success/vuln envelope, clean exit 0) just before a late/spurious SIGINT
// reaches the CLI process.
func writeEnvelopeThenTrapScript(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("late-interrupt test uses POSIX signals and a shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "envelope_then_trap.sh")
	// Print a full success envelope, then trap the forwarded signal and exit 0
	// (the child already finished its work). A short-sleep poll loop (not a
	// single long `sleep`) keeps the child alive until the signal arrives yet
	// lets the trap run promptly — bash defers a trap until the current
	// foreground command returns, so a lone `sleep 30` would swallow it.
	script := "#!/bin/sh\n" +
		"trap 'exit 0' INT TERM\n" +
		"printf '%s\\n' '{\"status\":\"success\",\"data\":null,\"errors\":[]}'\n" +
		"while true; do sleep 0.1; done\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}
	return path
}

// TestInvoke_LateInterruptDoesNotDiscardEnvelope models the FA2/FA3 precedence
// regression: the child produced a fully-parsed success/vuln envelope AND a
// late SIGINT set `interrupted`. A hoisted interrupt short-circuit would
// discard the real result and report interrupted/130. The correct precedence
// is that a usable envelope (rawJSON != "") wins: Invoke must return the REAL
// envelope with its normalized exit code, never interrupted/130.
func TestInvoke_LateInterruptDoesNotDiscardEnvelope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("late-interrupt test uses POSIX signals")
	}
	script := writeEnvelopeThenTrapScript(t)

	// Backstop deadline so the test never hangs.
	prev := defaultInvokeTimeout
	defaultInvokeTimeout = 8 * time.Second
	t.Cleanup(func() { defaultInvokeTimeout = prev })

	type outcome struct {
		res *InvokeResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		r, e := Invoke(script, []string{"scan", "."}, "", true, "")
		ch <- outcome{r, e}
	}()

	// Let the child print its envelope (captured by io.Copy) and install the
	// signal handler, then deliver a late SIGINT to this process. Invoke's
	// signal.Notify intercepts it so the test runner is not killed.
	time.Sleep(400 * time.Millisecond)
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess(self): %v", err)
	}
	if err := p.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("deliver SIGINT: %v", err)
	}

	var got outcome
	select {
	case got = <-ch:
	case <-time.After(15 * time.Second):
		t.Fatalf("Invoke did not return after late SIGINT within budget")
	}
	if got.err != nil {
		t.Fatalf("Invoke returned error: %v", got.err)
	}
	if got.res.Envelope.Status != "success" {
		t.Fatalf("late SIGINT discarded the real envelope: got Status=%q, want \"success\"",
			got.res.Envelope.Status)
	}
	if got.res.ExitCode == 130 {
		t.Fatalf("late SIGINT masked a fully-parsed envelope as interrupted/130; "+
			"the real result must win")
	}
	if got.res.ExitCode != 0 {
		t.Fatalf("expected normalized exit 0 for clean success, got %d", got.res.ExitCode)
	}
}
