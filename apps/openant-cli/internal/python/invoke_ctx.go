package python

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

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
	cmdArgs := append([]string{"-m", "openant"}, args...)
	cmd := exec.Command(pythonPath, cmdArgs...)

	if workDir != "" {
		cmd.Dir = workDir
	}
	cmd.Env = os.Environ()
	if apiKey != "" {
		cmd.Env = setEnv(cmd.Env, "ANTHROPIC_API_KEY", apiKey)
	}
	// New process group so we can kill all descendants at once.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", 0, fmt.Errorf("stderr pipe: %w", err)
	}

	var stdoutBuf bytes.Buffer
	if captureStdout {
		cmd.Stdout = &stdoutBuf
	} else {
		cmd.Stdout = nil // discard
	}

	if err := cmd.Start(); err != nil {
		return "", 0, fmt.Errorf("start: %w", err)
	}

	// Kill process group when context is cancelled.
	stopKiller := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		case <-stopKiller:
		}
	}()

	// Stream stderr to onLog.
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if onLog != nil {
				onLog(sc.Text())
			}
		}
	}()

	// If capturing stdout we need to drain it; cmd.Stdout = &stdoutBuf handles that.
	// For non-capture, stdout goes to /dev/null via nil.
	// Wait for stderr to finish before cmd.Wait().
	<-stderrDone

	// Also drain any remaining stdout bytes (belt-and-suspenders for the pipe).
	if captureStdout {
		_, _ = io.Copy(&stdoutBuf, bytes.NewReader(nil)) // no-op; already set via cmd.Stdout
	}

	exitErr := cmd.Wait()
	close(stopKiller)

	if exitErr != nil {
		if ee, ok := exitErr.(*exec.ExitError); ok {
			return stdoutBuf.String(), ee.ExitCode(), nil
		}
		if ctx.Err() != nil {
			return "", -1, nil
		}
		return "", 0, fmt.Errorf("wait: %w", exitErr)
	}
	return stdoutBuf.String(), 0, nil
}
