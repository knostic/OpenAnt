package python

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Regression shapes for the #161 follow-up: the envelope-wins rule.
//
// The #413 fix gated the deadline diagnosis on HOW the process died (the
// pipe-close error, or ExitCode < 0) instead of on WHETHER a usable envelope
// exists. Three verified consequences (executed at 60c4c40, see the wave
// probes): a child that wrote a COMPLETE envelope and exited — with a
// descendant holding a pipe write-end past the deadline — had the envelope
// DISCARDED and was told "killed mid-run and its output discarded" (false);
// the exit-0 zombie-kill window and the Windows kill surface (TerminateProcess
// yields exit code 1, never negative) never saw the diagnosis at all.
//
// The invariant (the #313 principle, made uniform): a fully-parsed envelope in
// the stdout buffer wins over the deadline on EVERY kill surface; the
// diagnosis fires only when NO usable envelope exists AND the deadline fired —
// which makes its wording ("no complete result recovered") true by
// construction.

// The deadline-dependent tests below use a 30s budget on purpose: under the
// full-suite run, the other packages' heavy-python spawn storms were measured
// delaying a child's first output past 2s AND 6s (the empty-buffer failures
// at exactly the deadline) — CPU hogs alone do NOT reproduce it, so the lag
// is spawn-path/memory pressure, and its tail is unbounded from the test's
// side. A budget that a stalled child can still beat is the only shape that
// keeps the recovery assertions non-vacuous; anything shorter is flaky, and
// a stall that beats 30s means the machine itself is unusable.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script children (the package convention — see writeHangScript)")
	}
	p := filepath.Join(t.TempDir(), "s.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// A complete success envelope was written and the child exited 0, but a
// descendant holds the stdout write-end past the deadline: the envelope MUST
// be recovered, not discarded.
func TestInvoke_DeadlineRecoversCompleteEnvelope_StdoutHeld(t *testing.T) {
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")
	s := writeScript(t, `printf '{"status":"success","errors":[]}'
sleep 60 &
exec >&-
exit 0
`)
	// quiet=false + stderr capture: the recovery NOTICE is the assertion
	// that the deadline actually fired — without it this test cannot tell
	// "recovered after a kill" from "nothing happened" (if the deadline
	// ever stopped firing, io.Copy would just wait for sleep 30 and the
	// test would still pass, green and meaningless, 30s later).
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	res, err := Invoke(s, []string{"analyze", "."}, "", false, "")
	os.Stderr = old
	w.Close()
	b, _ := io.ReadAll(r)
	if err != nil {
		t.Fatalf("a complete envelope must win over the deadline: %v", err)
	}
	if res.Envelope.Status != "success" {
		t.Fatalf("envelope status = %q, want success", res.Envelope.Status)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(string(b), "result envelope was recovered") {
		t.Fatalf("the recovery notice must be visible on stderr when not quiet; got: %q", string(b))
	}
}

// Same, exit 1 (vulns found): the code is preserved with the recovered
// envelope.
func TestInvoke_DeadlineRecoversCompleteEnvelope_Exit1(t *testing.T) {
	start := time.Now()
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")
	s := writeScript(t, `printf '{"status":"success","errors":[]}'
sleep 60 &
exec >&-
exit 1
`)
	res, err := Invoke(s, []string{"analyze", "."}, "", true, "")
	if el := time.Since(start); el > 45*time.Second {
		t.Fatalf("the deadline must fire (~30s); took %v — the envelope 'recovery' would be vacuous", el)
	}
	if err != nil {
		t.Fatalf("a complete envelope must win over the deadline: %v", err)
	}
	if res.Envelope.Status != "success" || res.ExitCode != 1 {
		t.Fatalf("got status=%q exit=%d, want success/1", res.Envelope.Status, res.ExitCode)
	}
}

// The exit-0 zombie-kill window: stdout EOFs cleanly (only stderr is held);
// the deadline lands on the unreaped child and Wait returns the context error
// (not an ExitError). The envelope must still win.
func TestInvoke_DeadlineRecoversCompleteEnvelope_WaitPathWindow(t *testing.T) {
	start := time.Now()
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")
	s := writeScript(t, `printf '{"status":"success","errors":[]}'
sleep 60 >&- &
exec >&-
exit 0
`)
	res, err := Invoke(s, []string{"analyze", "."}, "", true, "")
	if el := time.Since(start); el > 45*time.Second {
		t.Fatalf("the deadline must fire (~30s); took %v — the envelope 'recovery' would be vacuous", el)
	}
	if err != nil {
		t.Fatalf("the exit-0 window must recover the envelope: %v", err)
	}
	if res.Envelope.Status != "success" {
		t.Fatalf("envelope status = %q, want success", res.Envelope.Status)
	}
}

// No usable output + the deadline: the diagnosis fires — and names the
// checkpoint hint ONLY for checkpointed subcommands. parse is not one: the
// pre-fix message promised a resume that cannot happen (parse writes no
// checkpoints; the deadline's own design target is a hung parser).
func TestInvoke_DeadlineDiagnosis_HintGatedBySubcommand(t *testing.T) {
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "300ms")
	s := writeScript(t, "sleep 3\n")
	// parse: no checkpoint clause
	_, err := Invoke(s, []string{"parse", "."}, "", true, "")
	if err == nil {
		t.Fatal("want the deadline diagnosis for a no-output hang")
	}
	if !strings.Contains(err.Error(), "invoke deadline") {
		t.Fatalf("diagnosis missing: %v", err)
	}
	if strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("parse writes no checkpoints — the resume hint is false-in-context: %v", err)
	}
	if !strings.Contains(err.Error(), "OPENANT_INVOKE_TIMEOUT") {
		t.Fatalf("the override hint must always be present: %v", err)
	}
	// analyze: the checkpoint clause is true
	_, err = Invoke(s, []string{"analyze", "."}, "", true, "")
	if err == nil {
		t.Fatal("want the deadline diagnosis for a no-output hang")
	}
	if !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("analyze checkpoints — the resume hint belongs here: %v", err)
	}
}

// An invalid override must warn exactly once, INCLUDING on the deadline
// path (the pre-fix code re-resolved the timeout while formatting the
// diagnosis — the second call site only existed there, so a fast-exit child
// could never see the double warning: the old shape passed on pre-fix code).
// The discriminating shape: a hung child under the (invalid-override-fallen-
// back) default — shrunk here so it fires.
func TestInvoke_InvalidOverrideWarnsOnce(t *testing.T) {
	oldDefault := defaultInvokeTimeout
	defaultInvokeTimeout = 300 * time.Millisecond
	defer func() { defaultInvokeTimeout = oldDefault }()
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "not-a-duration")
	s := writeScript(t, "sleep 3\n")
	// capture stderr: streamStderr writes to os.Stderr; the warning comes
	// from resolveInvokeTimeout. Run through Invoke with a fast-exit child
	// and count the warning lines in os.Stderr via a pipe swap.
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	_, _ = Invoke(s, []string{"parse", "."}, "", true, "")
	os.Stderr = old
	w.Close()
	b, _ := io.ReadAll(r)
	n := strings.Count(string(b), "ignoring invalid OPENANT_INVOKE_TIMEOUT")
	if n != 1 {
		t.Fatalf("invalid-override warning printed %d times, want exactly 1: %s", n, string(b))
	}
}
