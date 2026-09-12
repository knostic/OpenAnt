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

// envelopeRecoveredMarker is the stable substring of the recovery notice
// deadlineOutcome emits (invoke_ctx.go) when a killed run's buffer carries
// a usable envelope — the envelope-recovery branch's only observable
// signature. The CLI path's notice (invoke.go) carries the same phrase;
// the sibling pins live at invoke_round3_test.go / invoke_envelope_test.go.
const envelopeRecoveredMarker = "result envelope was recovered"

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
	// #585 (the start-window class): the budget must also survive a loaded
	// runner's fork+exec stall — if the deadline fires during cmd.Start the
	// error shape is "start: context deadline exceeded", not the named
	// deadline error. 1s clears the common sub-1s stall shape.
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "1s")
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
	if !strings.Contains(err.Error(), "1s") {
		t.Fatalf("the error must state the effective value; got: %v", err)
	}
}

func TestInvokeCtx_EnvOverrideHonored(t *testing.T) {
	// OPENANT_INVOKE_TIMEOUT is the operator escape hatch the server path
	// never honored (#320): the override must apply here too.
	s := writeCtxScript(t, "sleep 5\n")
	// #585 (the start-window class): 1s survives a loaded runner's
	// fork+exec stall; the override assertion (vs the 30m default) is
	// unaffected.
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "1s")
	start := time.Now()
	_, _, err := InvokeCtxCapture(context.Background(), s, []string{"scan"}, "", "", nil)
	// The elapsed allowance is SCHEDULING TOLERANCE, not the override pin:
	// the real pin is the ErrInvokeDeadline assertion below (an ignored
	// override lets `sleep 5` complete naturally and returns a nil error).
	// The kill + pipe teardown under load can exceed the nominal 1s by
	// seconds; 15s is still far below the 30m default the override replaces.
	if time.Since(start) > 15*time.Second {
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
	// #585: the deadline is the fast-phase margin — the child's spawn +
	// printf must complete before it fires. The 400ms this replaced flaked
	// under full-suite load. The budget follows the envelope family's own
	// incident-bought rule (invoke_envelope_test.go:30-37): the other
	// packages' spawn storms were measured delaying a child's first output
	// past 2s AND 6s, CPU hogs do not reproduce it, and the tail is
	// unbounded from the test's side — "a budget that a stalled child can
	// still beat is the only shape that keeps the recovery assertions
	// non-vacuous; anything shorter is flaky." 30s, like the family.
	// The foreground linger is 120s — far past the 30s deadline (a sleep
	// EQUAL to the deadline leaves only spawn-latency (~3ms) between the
	// natural exit and the kill: a ms-class race at the presence pin).
	s := writeCtxScript(t, `printf '{"status":"success"}'
sleep 5 &
sleep 120`)
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")
	var logs []string
	start := time.Now()
	stdout, code, err := InvokeCtxCapture(context.Background(), s, []string{"x"}, "", "", func(msg string) { logs = append(logs, msg) })
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
	// #585 branch pin: this test's path is the envelope RECOVERY (the
	// deadline killed the still-alive child; deadlineOutcome scanned the
	// buffer and returned the envelope). The recovery notice is that
	// branch's only observable signature — assert it fired (the sibling
	// zombie test asserts the same notice does NOT fire there).
	if !strings.Contains(strings.Join(logs, "\n"), envelopeRecoveredMarker) {
		t.Fatalf("the envelope-recovery branch must be the one taken — the recovery notice is absent from %v", logs)
	}
	// Sanity window, not a branch discriminator: the kill IS the deadline
	// (the child stays alive), so the return cannot precede it; the upper
	// bound bounds the test's own patience (a truly hung run is caught by
	// the go-test timeout, not by an elapsed check — and the vacuous-pass
	// shape is already caught by the presence pin above, which a natural
	// no-deadline exit cannot satisfy).
	if el := time.Since(start); el < 27*time.Second || el > 60*time.Second {
		t.Fatalf("elapsed %v outside the sanity window [27s, 60s] — the deadline did not fire as designed (or the run hung)", el)
	}
}

func TestInvokeCtx_ZombieKillWindowKeepsSuccess(t *testing.T) {
	// deep-refute finding 4: the child exits 0 at once, a descendant holds
	// the pipe, the deadline fires — the exit-0 success must win.
	//
	// The mechanism (not "group cancellation returns ErrWaitDelay" — Go's
	// os/exec only calls Cancel while the process is unreaped, so once the
	// direct child exits nothing kills the descendant): Wait blocks on the
	// open pipe until cmd.WaitDelay (5s) force-closes it; at that point
	// ctx.Err() is DeadlineExceeded (the deadline fired long before) and
	// ProcessState.Success() holds, so the zombie-window return wins.
	//
	// #585: the deadline is the fast-phase margin (the child's spawn +
	// printf + exit must complete before it fires — 400ms flaked under
	// load). CEILING INVARIANT, asserted: the deadline MUST stay strictly
	// below invokeWaitDelay — at or above it the ctx check races the
	// pipe-close and the test silently flips to the ErrWaitDelay branch
	// (ctx.Err() == nil), where these pins pass vacuously without ever
	// exercising the zombie window.
	// 4s: the maximum under the ceiling with 1s of timer slack. RESIDUAL
	// (documented): the measured full-suite stall band (2s-6s+, the
	// envelope family's receipts) overlaps any sub-5s budget — a stall
	// past 4s re-fires this test, but LOUDLY (the pins below name the
	// wrong branch), never as a silent wrong-path pass. The structural
	// way out is a production invokeWaitDelay raise — a maintainer
	// decision, deliberately out of this test-only fix's scope.
	const testDeadline = 4 * time.Second
	if !(testDeadline < invokeWaitDelay) {
		t.Fatalf("the test deadline %v must stay strictly below invokeWaitDelay %v — the zombie-window branch is unreachable otherwise", testDeadline, invokeWaitDelay)
	}
	s := writeCtxScript(t, `printf '{"status":"success"}'
sleep 30 &
exit 0`)
	// Bound to the asserted const — a literal here could drift past the
	// ceiling while the assertion above still passes (the silent-flip
	// shape the assertion exists to prevent).
	t.Setenv("OPENANT_INVOKE_TIMEOUT", testDeadline.String())
	var logs []string
	start := time.Now()
	stdout, code, err := InvokeCtxCapture(context.Background(), s, []string{"x"}, "", "", func(msg string) { logs = append(logs, msg) })
	if err != nil {
		t.Fatalf("the exited-0 success must beat the deadline: %v", err)
	}
	if code != 0 {
		t.Fatalf("code = %d, want 0 (the natural exit)", code)
	}
	if !strings.Contains(stdout, `"status":"success"`) {
		t.Fatalf("the envelope must surface; got %q", stdout)
	}
	// #585 branch pin: the zombie-window return is SILENT — no recovery
	// notice (that is the envelope-recovery branch's signature, and the
	// ErrWaitDelay-with-no-deadline branch is equally silent but requires
	// an override regression this file's EnvOverrideHonored test pins
	// separately). ANY log line here means the wrong branch was taken.
	if len(logs) != 0 {
		t.Fatalf("the zombie window is silent — a log line means the wrong branch: %v", logs)
	}
	// Sanity window, not a branch discriminator. The lower bound sits
	// ABOVE the deadline: the correct path returns at child-exit +
	// invokeWaitDelay (~5s), while any sub-deadline return (e.g. a
	// WaitDelay reduced below the deadline) means the pipes closed before
	// the ctx ever fired — the ErrWaitDelay branch, not the zombie window.
	if el := time.Since(start); el < 4500*time.Millisecond || el > 15*time.Second {
		t.Fatalf("elapsed %v outside the sanity window [4.5s, 15s]", el)
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
	//
	// #585: the deadline is the fast-phase margin (400ms flaked under
	// load; this test can never recover — discard mode has no envelope to
	// scan — so a slow child is a hard FAIL here). Same asserted CEILING
	// INVARIANT as the zombie test: strictly below invokeWaitDelay, and
	// the same above-deadline lower bound (any sub-deadline return is the
	// ErrWaitDelay branch, not the zombie window).
	// 4s: the maximum under the ceiling — the same documented RESIDUAL as
	// the zombie test (the stall band overlaps any sub-5s budget; the
	// failure is loud, never a silent wrong-path pass).
	const testDeadline = 4 * time.Second
	if !(testDeadline < invokeWaitDelay) {
		t.Fatalf("the test deadline %v must stay strictly below invokeWaitDelay %v", testDeadline, invokeWaitDelay)
	}
	s := writeCtxScript(t, `sleep 30 &
exit 0`)
	t.Setenv("OPENANT_INVOKE_TIMEOUT", testDeadline.String())
	start := time.Now()
	code, err := InvokeCtx(context.Background(), s, []string{"x"}, "", "", nil)
	if err != nil {
		t.Fatalf("a natural exit-0 is not a deadline kill: %v", err)
	}
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	// Sanity window (the correct path returns at child-exit + WaitDelay,
	// ~5s; the lower bound rejects sub-deadline returns — a hung run is
	// the go-test timeout's job, not an elapsed check's).
	if el := time.Since(start); el < 4500*time.Millisecond || el > 15*time.Second {
		t.Fatalf("elapsed %v outside the sanity window [4.5s, 15s]", el)
	}
}
