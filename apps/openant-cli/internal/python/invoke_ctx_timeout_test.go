package python

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// #320: the server (web UI) path ran its Python subprocess with no deadline
// at all — the job context was cancel-only and InvokeCtx/InvokeCtxCapture
// never consulted resolveInvokeTimeout, so OPENANT_INVOKE_TIMEOUT had no
// effect; a wedged subprocess held one of four server scan slots forever.
// The CLI path was bounded (30m default); the server path was not. The
// maintainers' own pattern (DNS 5s, git clone 15m) bounds each runaway
// subprocess locally — the invoke never got it (PR #237's stated follow-up).

func writeCtxScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("hang-subprocess test uses a POSIX shell script (the package convention, invoke_test.go:18)")
	}
	p := filepath.Join(t.TempDir(), "s.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInvokeCtx_DeadlineFiresWithNamedError(t *testing.T) {
	// the runtime case-sensitivity probes for other packages; here just the
	// deadline mechanics on any platform
	s := writeCtxScript(t, "sleep 30\n")
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "200ms")
	start := time.Now()
	_, _, err := InvokeCtxCapture(context.Background(), s, []string{"scan", "x"}, "", "", nil)
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("the deadline did not bound the run: %v", el)
	}
	if err == nil {
		t.Fatal("a deadline kill must surface an error (the silent -1 path is the CANCEL contract)")
	}
	if !errors.Is(err, ErrInvokeDeadline) {
		t.Fatalf("the error must be ErrInvokeDeadline (a distinct status for the UI); got: %v", err)
	}
	if !strings.Contains(err.Error(), "OPENANT_INVOKE_TIMEOUT") {
		t.Fatalf("the error must name the operator override; got: %v", err)
	}
	if !strings.Contains(err.Error(), "200ms") {
		t.Fatalf("the error must state the effective value; got: %v", err)
	}
}

func TestInvokeCtx_EnvOverrideHonored(t *testing.T) {
	// OPENANT_INVOKE_TIMEOUT is the operator escape hatch the server path
	// never honored (#320): the override must apply here too.
	s := writeCtxScript(t, "sleep 5\n")
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "300ms")
	start := time.Now()
	_, _, err := InvokeCtxCapture(context.Background(), s, []string{"scan"}, "", "", nil)
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the override was not honored: %v", time.Since(start))
	}
	if !errors.Is(err, ErrInvokeDeadline) {
		t.Fatalf("want ErrInvokeDeadline; got: %v", err)
	}
}

func TestInvokeCtx_CancelPathUnchanged(t *testing.T) {
	// The job context stays cancel-only: a CANCELLED parent returns
	// ("", -1, nil) — the server's "cancelled, don't mark error" contract.
	// The deadline must not conflate cancellation with expiry.
	s := writeCtxScript(t, "sleep 30\n")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30m") // far beyond the cancel
	stdout, code, err := InvokeCtxCapture(ctx, s, []string{"scan"}, "", "", nil)
	if err != nil {
		t.Fatalf("the cancel path returns no error (the server contract); got: %v", err)
	}
	if code != -1 || stdout != "" {
		t.Fatalf("the cancel contract is ('', -1, nil); got (%q, %d, %v)", stdout, code, err)
	}
}

func TestInvokeCtx_NaturalFinishUnaffected(t *testing.T) {
	// A fast, successful run under a generous deadline is byte-identical to
	// the pre-fix behavior.
	s := writeCtxScript(t, "printf 'hello'\n")
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30m")
	stdout, code, err := InvokeCtxCapture(context.Background(), s, []string{"x"}, "", "", nil)
	if err != nil || code != 0 || stdout != "hello" {
		t.Fatalf("got (%q, %d, %v)", stdout, code, err)
	}
}

func TestInvokeCtx_EnvelopeWinsOverDeadline(t *testing.T) {
	// #433's principle on the CLI path (wave r1 finding 4, now honored on
	// the server path too): a COMPLETE captured envelope beats the deadline —
	// a child that wrote its result then lingered in teardown is a completed
	// run, not a kill. The envelope returns with NO error (the wave r1
	// finding 4: the server discarded it and marked the job timeout).
	s := writeCtxScript(t, `printf '{"status":"success"}'
sleep 5 &
sleep 30`)
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "400ms")
	stdout, code, err := InvokeCtxCapture(context.Background(), s, []string{"x"}, "", "", nil)
	if err != nil {
		t.Fatalf("the complete envelope must win over the deadline: %v", err)
	}
	if !strings.Contains(stdout, `"status":"success"`) {
		t.Fatalf("the envelope must surface; got %q", stdout)
	}
	// wave r3: the kill's exit artifact must NOT leak (-1 on Unix — the
	// server read it as a generic error; 1 on Windows — "vulnerabilities
	// found"). The envelope's status drives the code.
	if code != 0 {
		t.Fatalf("a recovered success envelope must surface code 0, not the kill artifact; got %d", code)
	}
}

func TestInvokeCtx_ZombieKillWindowKeepsSuccess(t *testing.T) {
	// deep-refute finding 4: the child exits 0 at once, a descendant holds
	// the pipe, the deadline fires inside WaitDelay — Wait returns
	// ErrWaitDelay under DeadlineExceeded; the exit-0 success must win.
	s := writeCtxScript(t, `printf '{"status":"success"}'
sleep 30 &
exit 0`)
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "400ms")
	stdout, code, err := InvokeCtxCapture(context.Background(), s, []string{"x"}, "", "", nil)
	if err != nil {
		t.Fatalf("the exited-0 success must beat the deadline: %v", err)
	}
	if code != 0 {
		t.Fatalf("code = %d, want 0 (the natural exit)", code)
	}
	if !strings.Contains(stdout, `"status":"success"`) {
		t.Fatalf("the envelope must surface; got %q", stdout)
	}
}

func TestInvokeCtx_DiscardStdoutNaturalExitZeroNotADeadline(t *testing.T) {
	// deep-refute finding 3: the discard-stdout InvokeCtx mode — a
	// successful exit-0 child (a descendant holding the pipe) must NOT be
	// reported as a deadline kill.
	// deep-refute (fable, vacuous-green finding): the script was
	// `exit 0` THEN `sleep 30 &` — the shell exits on line 1 and the
	// descendant never spawns, so the test exercised nothing but a clean
	// exit-0 and passed vacuously. The descendant must spawn BEFORE exit
	// for the pipe to actually be held.
	s := writeCtxScript(t, `sleep 30 &
exit 0`)
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "400ms")
	code, err := InvokeCtx(context.Background(), s, []string{"x"}, "", "", nil)
	if err != nil {
		t.Fatalf("a natural exit-0 is not a deadline kill: %v", err)
	}
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}
