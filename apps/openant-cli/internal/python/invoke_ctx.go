package python

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// lineWriter forwards complete stderr lines to onLog as they arrive. Used as
// cmd.Stderr (a managed io.Writer) instead of a StderrPipe scanner so os/exec
// owns the copy goroutine and WaitDelay can force-close a pipe a detached child
// still holds. A single partial line is capped so a repo can't exhaust memory.
type lineWriter struct {
	onLog func(string)
	buf   []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			if len(w.buf) > 1024*1024 { // flush a pathologically long partial line
				w.emit(w.buf)
				w.buf = w.buf[:0]
			}
			break
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

func (w *lineWriter) emit(line []byte) {
	if w.onLog != nil {
		w.onLog(string(line))
	}
}

// flush emits any buffered trailing line with no newline. Call after cmd.Wait,
// which guarantees the copy goroutine has finished (no concurrent Write).
func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.emit(w.buf)
		w.buf = w.buf[:0]
	}
}

// InvokeCtx runs `python -m openant <args>` with context-cancellation support.
// Each stderr line is passed to onLog in real time.  stdout is discarded.
// On context cancellation, SIGKILL is sent to the entire process group so all
// child processes (e.g. parallel workers) are killed.
// Returns the exit code and any error (cancelled runs return exit code -1, nil).
func InvokeCtx(ctx context.Context, pythonPath string, args []string, workDir, apiKey string, onLog func(string)) (int, error) {
	_, code, err := invokeCtxInner(ctx, pythonPath, args, workDir, apiKey, onLog, false)
	return code, err
}

// InvokeCtxCapture runs `python -m openant <args>` like InvokeCtx but also
// captures and returns the full stdout content (e.g. JSON output).
func InvokeCtxCapture(ctx context.Context, pythonPath string, args []string, workDir, apiKey string, onLog func(string)) (stdout string, exitCode int, err error) {
	return invokeCtxInner(ctx, pythonPath, args, workDir, apiKey, onLog, true)
}

func invokeCtxInner(ctx context.Context, pythonPath string, args []string, workDir, apiKey string, onLog func(string), captureStdout bool) (string, int, error) {
	// -P keeps the process working directory off sys.path so a hostile openant/
	// package inside the scanned, untrusted repo can't shadow the real module on
	// import. The web UI is the untrusted-repo-scanning path, so it needs the same
	// guard the CLI's Invoke uses (see invoke.go); it also propagates to the report
	// subprocesses the engine spawns.
	cmdArgs := append([]string{"-P", "-m", "openant"}, args...)
	cmd := exec.CommandContext(ctx, pythonPath, cmdArgs...)

	if workDir != "" {
		cmd.Dir = workDir
	}
	cmd.Env = os.Environ()
	if apiKey != "" {
		cmd.Env = setEnv(cmd.Env, "ANTHROPIC_API_KEY", apiKey)
	}
	// New process group so we can kill all descendants at once (unix; no-op
	// elsewhere). os/exec drives cancellation: its watch goroutine calls Cancel
	// once and stops before Wait reaps the child, so there is no window to SIGKILL
	// a recycled pgid after reaping.
	setProcGroupKill(cmd)
	cmd.WaitDelay = 5 * time.Second

	var stdoutBuf bytes.Buffer
	if captureStdout {
		cmd.Stdout = &stdoutBuf
	} else {
		cmd.Stdout = io.Discard
	}
	// Managed line-writer for stderr instead of StderrPipe: os/exec runs the copy
	// goroutine, so WaitDelay can force-close the pipe if a killed OR a naturally
	// exited process leaves a detached child holding the write end. A StderrPipe
	// scanner read before Wait() would instead deadlock there — the read never
	// sees EOF, so Wait (which starts WaitDelay) is never reached.
	lw := &lineWriter{onLog: onLog}
	cmd.Stderr = lw

	if err := cmd.Start(); err != nil {
		return "", 0, fmt.Errorf("start: %w", err)
	}

	exitErr := cmd.Wait()
	lw.flush() // emit any trailing partial line; Wait has drained the copy goroutine

	if exitErr != nil {
		if ee, ok := exitErr.(*exec.ExitError); ok {
			return stdoutBuf.String(), ee.ExitCode(), nil
		}
		if ctx.Err() != nil {
			return "", -1, nil
		}
		// The process itself exited but a lingering pipe holder tripped WaitDelay;
		// the scan completed, so keep its captured stdout + real exit code rather
		// than discarding a successful run as a failure.
		if errors.Is(exitErr, exec.ErrWaitDelay) && cmd.ProcessState != nil {
			return stdoutBuf.String(), cmd.ProcessState.ExitCode(), nil
		}
		return "", 0, fmt.Errorf("wait: %w", exitErr)
	}
	return stdoutBuf.String(), 0, nil
}
