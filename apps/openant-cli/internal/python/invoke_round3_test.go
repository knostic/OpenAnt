package python

import (
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Round-3 panel findings, locked by execution:
//
// 1. Stderr-drain bound. The #433 rework bounded the READ-ERROR path's
// stderr drain via Wait-first, but the NORMAL path's <-stderrDone was
// bounded only by the deadline: a descendant holding ONLY the stderr
// write-end kept the streamer blocked until ctx.Done() fired the
// watchdog. Executed probe (pre-fix binary, 15s budget): a child that
// printed a complete envelope and exited in 0.1s hung the invocation
// 15.77s and returned under a spurious "deadline fired ... recovered"
// note. The stderrDrainGrace close bounds the drain by the CHILD's exit
// (+grace), not the deadline.
//
// 2. Kill-artifact exit code. In the recovered-envelope branch the child's
// exit code under a fired deadline is the KILL's artifact — Unix a negative
// signal code (normalizeExit maps to the conservative 2), Windows
// TerminateProcess's exit 1, which is indistinguishable from a legitimate
// vulnerabilities-found exit, so a killed Windows run surfaced exit 1 for a
// recovered envelope. exitErrIsKillArtifact now routes every platform to the
// conservative 2. (Unix-only test — the Windows branch needs a Windows
// runner; the mapping is the same statement of code.)

// A complete envelope is in hand and the child has exited, but a descendant
// holds ONLY the stderr write-end: the invocation must return promptly
// (bounded by the child's exit + stderrDrainGrace, NOT the deadline), with
// no deadline ever firing.
func TestInvoke_StderrOnlyDescendantDoesNotHang(t *testing.T) {
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "30s")
	old := stderrDrainGrace
	stderrDrainGrace = 1 * time.Second
	t.Cleanup(func() { stderrDrainGrace = old })
	s := writeScript(t, `printf '{"status":"success","errors":[]}'
sleep 60 >&2 &
exit 0
`)
	start := time.Now()
	res, err := Invoke(s, []string{"analyze", "."}, "", true, "")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("envelope must be returned despite the stderr descendant: %v", err)
	}
	if res.Envelope.Status != "success" {
		t.Fatalf("envelope status = %q, want success", res.Envelope.Status)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("the drain must be bounded by the child's exit (+grace), not the deadline: took %v", elapsed)
	}
}

// A child that wrote a complete envelope and was then KILLED by the deadline
// (signal death) surfaces the conservative exit 2 with the envelope's own
// status preserved — never the kill artifact's code through the 0/1/2
// contract. Unix-only (signal death); Windows maps the same statement via
// exitErrIsKillArtifact's TerminateProcess branch.
func TestInvoke_KillArtifactExitCodeIsConservative(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signal-death artifact is Unix; Windows takes the same mapping via exitErrIsKillArtifact")
	}
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "2s")
	s := writeScript(t, `printf '{"status":"success","errors":[]}'
exec sleep 60
`)
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	res, err := Invoke(s, []string{"analyze", "."}, "", false, "")
	os.Stderr = old
	w.Close()
	b, _ := io.ReadAll(r)
	if err != nil {
		t.Fatalf("a complete envelope must win over the deadline kill: %v", err)
	}
	if res.Envelope.Status != "success" {
		t.Fatalf("envelope status = %q, want success", res.Envelope.Status)
	}
	if res.ExitCode != 2 {
		t.Fatalf("exit code = %d, want the conservative 2 — the kill artifact must never surface as clean/vulns-found", res.ExitCode)
	}
	if !strings.Contains(string(b), "result envelope was recovered") {
		t.Fatalf("the recovery notice must be visible on stderr when not quiet; got: %q", string(b))
	}
}
