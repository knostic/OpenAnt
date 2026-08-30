package python

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Wave round-2 regression tests (each finding verified by execution before
// the fix).

// flow#1 (executed): a NATURAL crash — traceback to stderr, exit 1, empty
// stdout — with a descendant holding the stdout write-end past the deadline.
// The kill diagnosis ("the run was killed... raise the budget") was wrong on
// every count: the child was not killed, the advice misdirects, and the real
// exit status was masked. The honest answer is the no-output error envelope
// carrying the natural exit code — and NO deadline claim.
func TestInvoke_NaturalCrashWithHeldPipeIsNotADeadlineKill(t *testing.T) {
	start := time.Now()
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")
	s := writeScript(t, `echo 'Traceback: boom' >&2
sleep 60 &
exec >&-
exit 1
`)
	res, err := Invoke(s, []string{"analyze", "."}, "", true, "")
	if el := time.Since(start); el > 45*time.Second {
		t.Fatalf("the deadline must fire (~30s); took %v — the test would be vacuous", el)
	}
	if err != nil {
		t.Fatalf("a natural crash must surface its own failure, not an error: %v", err)
	}
	if res.Envelope.Status != "error" {
		t.Fatalf("status = %q, want error", res.Envelope.Status)
	}
	for _, e := range res.Envelope.Errors {
		if strings.Contains(e, "invoke deadline") {
			t.Fatalf("a natural crash must not be diagnosed as a deadline kill: %s", e)
		}
	}
	if res.ExitCode != 2 { // exit 1 + error envelope -> normalizeExit -> 2
		t.Fatalf("exit = %d, want 2 (the crash's own status, error-normalized)", res.ExitCode)
	}
}

// msg#1 (the regression the round-1 fix introduced): calling Wait before the
// stderr streamer drained truncates the child's FINAL stderr lines on normal
// exits (StderrPipe's contract — Wait closes the read-end on reap, dropping
// the kernel pipe buffer). The traceback's last line is the one the operator
// needs.
func TestInvoke_StderrTailSurvivesNormalExit(t *testing.T) {
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "60s")
	s := writeScript(t, `i=0
while [ $i -lt 400 ]; do printf 'frame %03d File "x.py", line 1\n' $i >&2; i=$((i+1)); done
printf 'ValueError: THE ACTUAL ERROR\n' >&2
exit 2
`)
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	_, _ = Invoke(s, []string{"analyze", "."}, "", false, "")
	os.Stderr = old
	w.Close()
	b, _ := io.ReadAll(r)
	got := string(b)
	if !strings.Contains(got, "THE ACTUAL ERROR") {
		t.Fatalf("stderr tail lost — the final line must survive: got %d frames, tail missing", strings.Count(got, "frame "))
	}
}

// flow#3 (the real test): a user Ctrl+C inside the deadline's final
// seconds wins over the deadline diagnosis — interrupted/130, not failed/2.
// The child TRAPS SIGINT (ignores the forwarded signal) so the only exits
// are the deadline's kill; the self-SIGINT sets the flag. Pre-round-2
// ordering returned the deadline diagnosis here.
func TestInvoke_InterruptWinsOverDeadlineDiagnosis(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("self-SIGINT delivery")
	}
	sentinel := filepath.Join(t.TempDir(), "ready")
	s := writeScript(t, "trap '' INT TERM\ntouch "+shellQuote(sentinel)+"\nsleep 600\n")
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")

	go func() {
		// Poll up to 20s for the child's readiness: under the full-suite
		// spawn storms a child's start can lag seconds (see writeScript's
		// comment) — the interrupt must land after the child is up but
		// comfortably before the 30s deadline.
		for i := 0; i < 1000; i++ {
			if _, err := os.Stat(sentinel); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		// The child is running and ignoring SIGINT; deliver ours.
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	res, err := Invoke(s, []string{"analyze", "."}, "", true, "")
	if err != nil {
		t.Fatalf("the interrupt must win over the deadline diagnosis: %v", err)
	}
	if res.Envelope.Status != "interrupted" || res.ExitCode != 130 {
		t.Fatalf("got status=%q exit=%d, want interrupted/130", res.Envelope.Status, res.ExitCode)
	}
}

// checkpointedSubcommand over the FULL subcommand list (wave round-3: the
// gate is the point of the fix — two cases do not cover a misclassification
// of the other ten). Checkpointing: enhance/analyze/verify (the three
// DetectViaPython steps in cmd/scan.go) plus dynamic-test (which
// auto-derives its own dynamic_test_checkpoints dir —
// utilities/dynamic_tester/__init__.py:148-156) and scan (one invocation
// runs the phases). Every other verb excluded. The list mirrors the
// openant/cli.py add_parser set reachable via python.Invoke.
func TestCheckpointedSubcommandTable(t *testing.T) {
	cases := map[string]bool{
		// checkpointing: the three DetectViaPython steps + dynamic-test
		// (its own auto-derived dir) + scan (one invocation runs the
		// phases)
		"scan": true, "enhance": true, "analyze": true, "verify": true, "dynamic-test": true,
		// everything else writes no per-unit checkpoints
		"parse": false, "generate-context": false, "build-output": false,
		"report": false, "report-data": false, "checkpoint-status": false,
		"threat-model": false,
		"":             false,
	}
	for sub, want := range cases {
		var args []string
		if sub != "" {
			args = []string{sub}
		}
		if got := checkpointedSubcommand(args); got != want {
			t.Errorf("checkpointedSubcommand(%q) = %v, want %v", sub, got, want)
		}
	}
}

// Round-4 pin: the zombie-window classification (confirm#2). A child that
// exited 0 ON ITS OWN with no output, while a descendant holds the pipe past
// the deadline, must NOT be diagnosed as a kill — Wait's context
// substitution happens only for an already-successfully-exited child; the
// honest answer is the no-output envelope. (RED against the round-2 code,
// which classified the whole non-ExitError branch as a kill.)
func TestInvoke_Exit0WithHeldPipeIsNotADeadlineKill(t *testing.T) {
	start := time.Now()
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")
	s := writeScript(t, `sleep 60 &
exec >&-
exit 0
`)
	res, err := Invoke(s, []string{"analyze", "."}, "", true, "")
	if el := time.Since(start); el > 45*time.Second {
		t.Fatalf("the deadline must fire (~30s); took %v — the test would be vacuous", el)
	}
	if err != nil {
		t.Fatalf("a natural exit-0 must not surface an error: %v", err)
	}
	if res.Envelope.Status != "error" {
		t.Fatalf("status = %q, want the no-output error envelope", res.Envelope.Status)
	}
	for _, e := range res.Envelope.Errors {
		if strings.Contains(e, "invoke deadline") {
			t.Fatalf("an exit-0 child must not be diagnosed as killed: %s", e)
		}
	}
}

// Round-7 pin (r7-opus finding 4 — the most likely PRODUCTION shape of
// envelope-wins, previously unpinned): the child writes a complete envelope
// and then hangs in teardown (atexit / a worker-pool join / Docker teardown)
// until the deadline SIGKILLs it. The contract: the envelope is recovered
// (status success), the kill's artifact exit code (-1) maps through
// normalizeExit's conservative policy to 2, and the recovery note fires —
// the operator gets the complete result AND a non-zero exit signaling the
// anomalous invocation.
func TestInvoke_EnvelopeThenGenuineKill_Exit2WithSuccess(t *testing.T) {
	start := time.Now()
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")
	s := writeScript(t, `printf '{"status":"success","errors":[]}'
sleep 60
`)
	res, err := Invoke(s, []string{"analyze", "."}, "", true, "")
	if el := time.Since(start); el > 45*time.Second {
		t.Fatalf("the deadline must fire (~30s); took %v — the test would be vacuous", el)
	}
	if err != nil {
		t.Fatalf("the complete envelope must be recovered even from a genuine kill: %v", err)
	}
	if res.Envelope.Status != "success" {
		t.Fatalf("status = %q, want success (recovered)", res.Envelope.Status)
	}
	if res.ExitCode != 2 {
		t.Fatalf("exit = %d, want 2 (the kill artifact's conservative mapping — a completed result, an anomalous invocation)", res.ExitCode)
	}
}

// Round-7 pin (r7-opus finding 1): valid JSON that is not a result envelope
// (the null-guard's own target) — the error must not format a nil error.
func TestInvoke_NullStdoutIsNotAnEnvelope(t *testing.T) {
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "60s")
	s := writeScript(t, `printf 'null'
`)
	res, err := Invoke(s, []string{"analyze", "."}, "", true, "")
	if err != nil {
		t.Fatalf("valid-but-not-an-envelope stdout surfaces as an error envelope, not an error: %v", err)
	}
	if res.Envelope.Status != "error" {
		t.Fatalf("status = %q, want error", res.Envelope.Status)
	}
	if len(res.Envelope.Errors) == 0 {
		t.Fatal("want the not-an-envelope error")
	}
	if strings.Contains(res.Envelope.Errors[0], "<nil>") {
		t.Fatalf("the nil parseErr must not be formatted: %s", res.Envelope.Errors[0])
	}
	if !strings.Contains(res.Envelope.Errors[0], "not a result envelope") {
		t.Fatalf("want the not-an-envelope message; got: %s", res.Envelope.Errors[0])
	}
}
