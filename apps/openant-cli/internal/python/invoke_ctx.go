package python

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ErrInvokeDeadline is returned when the invoke's own deadline (the
// OPENANT_INVOKE_TIMEOUT budget, default 30m — #320: the server/web-UI path
// previously ran with NO deadline at all, so a wedged subprocess held one of
// four server scan slots forever) fires. The server maps it to a distinct
// "timeout" status; a CANCELLED parent context keeps the silent ("", -1,
// nil) contract.
var ErrInvokeDeadline = errors.New("the invoke deadline fired")

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

// deadlineOutcome is the #320 deadline surface, with the #433
// envelope-wins rule: a COMPLETE captured envelope beats the deadline (a
// child that wrote its result then lingered in teardown is a completed
// run, not a kill) — only when the buffer carries no usable envelope is it
// a deadline kill, reported with the distinct named cause + the operator
// override.
func deadlineOutcome(stdoutBuf *bytes.Buffer, invokeTimeout time.Duration, onLog func(string)) (string, int, error) {
	// deep-refute (fable, strictness finding): the whole-buffer single-JSON
	// requirement is stricter than the server's own noise premise —
	// envelopeErrors exists because the stream can carry non-JSON log noise
	// around the envelope. Scan lines bottom-up for the last well-formed
	// envelope, the same tolerance; only when NO usable envelope exists is
	// it a deadline kill.
	recovered := ""
	for _, line := range strings.Split(stdoutBuf.String(), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var probe struct {
			Status string `json:"status"`
		}
		if json.Unmarshal([]byte(line), &probe) == nil && probe.Status != "" {
			recovered = line
			break
		}
	}
	if recovered != "" {
		s := recovered
		var probe struct {
			Status string `json:"status"`
		}
		if json.Unmarshal([]byte(s), &probe) == nil && probe.Status != "" {
			// #320 (wave r3/r4): the recovered envelope must NOT hand the
			// server the kill's exit artifact — the Unix signal death
			// reports -1 (read as a generic error) and the Windows
			// TerminateProcess reports 1 (read as "vulnerabilities found").
			// The SERVER's own contract differs from the CLI's here (the
			// CLI conservatively fails a killed run; the server has the
			// on-disk results and builds its report from them, and a
			// conservative 2 would route to setError and lose BOTH the
			// report and the timeout state): the envelope's status drives
			// the code so the server continues down its normal result
			// path — success -> 0; anything else -> 2.
			code := 2
			if probe.Status == "success" {
				code = 0
			}
			if onLog != nil {
				onLog("[openant] the invoke deadline fired after " + invokeTimeout.String() +
					", but a complete result envelope was recovered — returning it" +
					" (the run may be incomplete; raise OPENANT_INVOKE_TIMEOUT for long runs)")
			}
			return s, code, nil
		}
	}
	return stdoutBuf.String(), -1, fmt.Errorf(
		"openant: the invoke deadline fired after %v — the run was "+
			"killed and no complete result was recovered. To finish a "+
			"long run outright, raise the budget via "+
			"OPENANT_INVOKE_TIMEOUT (e.g. OPENANT_INVOKE_TIMEOUT=2h): %w",
		invokeTimeout, ErrInvokeDeadline)
}

func invokeCtxInner(ctx context.Context, pythonPath string, args []string, workDir, apiKey string, onLog func(string), captureStdout bool) (string, int, error) {
	// #320: bound the subprocess with the operator-tunable invoke deadline —
	// the same budget the CLI's Invoke applies (invoke.go:91). Derived from
	// the CALLER's context so the job cancel still propagates (the parent);
	// the deadline is the local bound the maintainers' own pattern gives
	// every other runaway subprocess (DNS 5s, git clone 15m). Resolved ONCE
	// into a local (the invalid-override warning prints a single time —
	// resolving again in the diagnosis would print it twice).
	invokeTimeout := resolveInvokeTimeout()
	ctx, cancel := context.WithTimeout(ctx, invokeTimeout)
	defer cancel()
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
			// #320 (the #413 lesson, mirrored — including its #433 Windows
			// fix): the kill can surface as an ExitError FIRST (the race
			// with the pipe-close path). Gate on the KILL ITSELF under the
			// fired deadline — a child that finished legitimately in the
			// window just before the deadline keeps its envelope. On Unix a
			// signal death reports a NEGATIVE code; on Windows
			// TerminateProcess yields exit code 1 (never negative — the exact
			// gap the CLI's #433 fix closed by branching on GOOS).
			killUnderDeadline := false
			if ctx.Err() == context.DeadlineExceeded {
				if runtime.GOOS == "windows" {
					killUnderDeadline = true
				} else {
					killUnderDeadline = ee.ExitCode() < 0
				}
			}
			if killUnderDeadline {
				return deadlineOutcome(&stdoutBuf, invokeTimeout, onLog)
			}
			return stdoutBuf.String(), ee.ExitCode(), nil
		}
		if ctx.Err() == context.DeadlineExceeded {
			// The kill tripped the pipe-close path instead. The zombie-kill
			// window (invoke.go:274-285's #319): the child already exited —
			// SUCCESSFULLY — and only a descendant held a pipe; the
			// watchdog's Cancel fired on the reaped zombie. A usable
			// envelope wins; only when there is none is it a deadline kill.
			if cmd.ProcessState != nil && cmd.ProcessState.Success() {
				// (deep-refute: Success() alone — the Len()>0 conjunct made
				// the discard-stdout InvokeCtx mode report a successful
				// exit-0 child as a deadline kill)
				return stdoutBuf.String(), cmd.ProcessState.ExitCode(), nil
			}
			return deadlineOutcome(&stdoutBuf, invokeTimeout, onLog)
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
