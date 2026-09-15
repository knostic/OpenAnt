//go:build unix

package python

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// invoke_ctx relies on cmd.Stderr = *lineWriter (a managed writer) + Setpgid +
// cmd.Cancel + WaitDelay so a scanned process that leaves a DETACHED child (new
// session) holding the stderr write-end cannot wedge cmd.Wait forever. This test
// exercises that exact pattern: without WaitDelay + a managed writer, Wait would
// block until the 30s sleeper closed stderr; with them it returns within
// WaitDelay after the parent exits, and the lines already written are delivered.
func TestStderrManagedWriterBoundsDetachedChild(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c",
		"echo a 1>&2; echo b 1>&2; (sleep 30 </dev/null 1>&2 &) ; exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	var got []string
	cmd.Stderr = &lineWriter{onLog: func(s string) { got = append(got, s) }}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	err := cmd.Wait()
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("Wait wedged on detached child: %v (want ~WaitDelay, not the 30s sleep)", elapsed)
	}
	if len(got) < 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("stderr lines not delivered before the bound fired: %v", got)
	}
	// invokeCtxInner relies on this exact shape: the process exited 0 but a pipe
	// holder tripped WaitDelay, so Wait returns ErrWaitDelay (NOT an *ExitError)
	// while ProcessState carries the real exit code 0. The fix must translate
	// that to success, not discard the completed scan.
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Errorf("expected ErrWaitDelay on the detached-child path, got %v", err)
	}
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 0 {
		t.Errorf("ProcessState should carry exit 0 on the WaitDelay path, got %v", cmd.ProcessState)
	}
}

// Normal exit must return promptly (no WaitDelay penalty) with lines intact.
func TestStderrManagedWriterNormalExit(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c", "echo hello 1>&2; echo world 1>&2")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	var got []string
	cmd.Stderr = &lineWriter{onLog: func(s string) { got = append(got, s) }}

	start := time.Now()
	cmd.Start()
	_ = cmd.Wait()
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("normal exit slow: %v", elapsed)
	}
	if len(got) != 2 || got[0] != "hello" || got[1] != "world" {
		t.Errorf("normal-exit lines = %v, want [hello world]", got)
	}
}
