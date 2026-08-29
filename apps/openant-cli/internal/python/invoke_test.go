package python

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeHangScript creates an executable script that ignores its arguments,
// prints nothing on stdout, and sleeps far longer than any test deadline.
// It stands in for a hung Python parser (infinite loop / I/O deadlock).
func writeHangScript(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("hang-subprocess test uses a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "hang.sh")
	sentinel := filepath.Join(dir, "ready")
	// Touch the sentinel once running, then sleep past the test deadline and
	// never produce stdout. The sentinel is the readiness barrier: the test
	// waits for it before signalling, so the SIGINT cannot arrive before the
	// child (and Invoke's signal.Notify) exists. A fixed sleep was a wall-clock
	// guess that raced the child under CPU load.
	script := "#!/bin/sh\ntouch " + shellQuote(sentinel) + "\nsleep 600\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write hang script: %v", err)
	}
	return path, sentinel
}

// shellQuote single-quotes a path for safe embedding in a /bin/sh script.
func shellQuote(p string) string {
	return "'" + strings.ReplaceAll(p, "'", "'\\''") + "'"
}

// waitForSentinel blocks until path exists or the deadline passes, failing the
// test loudly on timeout. That loud failure is what makes the barrier
// load-bearing rather than a longer sleep: if the child never signals
// readiness, the test says so instead of racing.
func waitForSentinel(t *testing.T, path string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("child never created readiness sentinel %q within %s", path, within)
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
	hang, _ := writeHangScript(t)

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
func writeEnvelopeThenTrapScript(t *testing.T) (string, string) {
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
	sentinel := filepath.Join(dir, "ready")
	// Touch the sentinel ONLY after the trap is installed and the envelope is
	// printed — the two preconditions this scenario needs. The test waits on it
	// before signalling, replacing a 400ms sleep that raced the child under load
	// (reproduced: 27/30 failures at high CPU).
	script := "#!/bin/sh\n" +
		"trap 'exit 0' INT TERM\n" +
		"printf '%s\\n' '{\"status\":\"success\",\"data\":null,\"errors\":[]}'\n" +
		"touch " + shellQuote(sentinel) + "\n" +
		"while true; do sleep 0.1; done\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}
	return path, sentinel
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
	script, sentinel := writeEnvelopeThenTrapScript(t)

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

	// Wait for the child to signal it has installed its trap AND printed the
	// envelope, then deliver a late SIGINT to this process. Invoke's
	// signal.Notify intercepts it so the test runner is not killed.
	waitForSentinel(t, sentinel, 5*time.Second)
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
		t.Fatalf("late SIGINT masked a fully-parsed envelope as interrupted/130; " +
			"the real result must win")
	}
	if got.res.ExitCode != 0 {
		t.Fatalf("expected normalized exit 0 for clean success, got %d", got.res.ExitCode)
	}
}

func TestInvoke_TimeoutErrorNamesTheDeadline(t *testing.T) {
	// #161 (jblu42, the extra-care protocol): the deadline kill used to
	// surface as the cryptic "failed to read stdout: read |0: file already
	// closed" — the exact error the reporter hit against a local Ollama
	// model (~1 min/unit; the deadline fires after ~20-40 entries). The
	// surfaced error must carry the DIAGNOSIS: the deadline, the env
	// override (#237's surface — regression-tested by driving it here, not
	// a test hook), and the checkpoint-resume path.
	// C1 (fable need-check): assert diagnosis-PRESENCE, not the racy
	// literal string — which error surfaces first post-kill is a race.
	hang, _ := writeHangScript(t)
	// C2: shrink the deadline via the PUBLIC override — no test hooks.
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "1") // 1 second

	_, err := Invoke(hang, []string{"parse", "."}, "", true, "")
	if err == nil {
		t.Fatalf("expected the deadline to fire on a hung subprocess")
	}
	msg := err.Error()
	for _, want := range []string{"invoke deadline", "OPENANT_INVOKE_TIMEOUT", "checkpoint"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the timeout error must name %q; got: %s", want, msg)
		}
	}
	// C5.6: the effective deadline (the override's 1s) must appear —
	// confirms to an override user that their setting took effect.
	if !strings.Contains(msg, "1s") {
		t.Errorf("the error must show the effective deadline value; got: %s", msg)
	}
}

func TestInvoke_NonDeadlineDeathDoesNotClaimADeadline(t *testing.T) {
	// C4 (the negative control): a subprocess death WITHOUT the deadline
	// expired must NOT be mis-diagnosed as a timeout — a false "you hit
	// the deadline" is worse than no diagnosis. Also pins the #313
	// interaction: a non-timeout death keeps its own semantics.
	dir := t.TempDir()
	script := filepath.Join(dir, "failer.py")
	if err := os.WriteFile(script, []byte("import sys; sys.exit(3)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "600") // far beyond this test's run

	_, err := Invoke("python3", []string{"-c", fmt.Sprintf(
		"import runpy,sys; sys.argv=['failer']; runpy.run_path(%q)", script)}, "", true, "")
	if err != nil {
		if strings.Contains(err.Error(), "invoke deadline") {
			t.Errorf("a non-deadline death must not claim a deadline; got: %s", err)
		}
	}
}
