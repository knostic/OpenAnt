// Package python provides subprocess invocation of the Python CLI.
package python

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/knostic/open-ant-cli/internal/types"
)

// defaultInvokeTimeout bounds how long Invoke will wait on the Python
// subprocess before the process is killed and Invoke returns. It guards
// against a hung parser (infinite loop, I/O deadlock, pathological repo)
// wedging the CLI forever, which matters most for headless/automated
// callers that cannot deliver a manual Ctrl+C. It is a package var so
// tests can shrink it.
var defaultInvokeTimeout = 30 * time.Minute

// InvokeResult holds the result of a Python CLI invocation.
type InvokeResult struct {
	Envelope types.Envelope
	ExitCode int
}

// Invoke runs `python -m openant <args>` and returns the parsed JSON result.
//
// - stderr is streamed to the terminal in real-time (progress messages)
// - stdout is captured and parsed as JSON
// - Working directory is set to the openant-core lib directory if provided
// - If apiKey is non-empty, it is injected as ANTHROPIC_API_KEY in the subprocess
func Invoke(pythonPath string, args []string, workDir string, quiet bool, apiKey string) (*InvokeResult, error) {
	cmdArgs := append([]string{"-m", "openant"}, args...)

	// Bound the subprocess with an automatic deadline so a hung parser
	// cannot wedge the CLI forever on cmd.Wait(). When the context expires
	// CommandContext kills the process. This is the only recovery path for
	// headless/automated callers, which never deliver the manual SIGINT the
	// signal goroutine below relies on. Mirrors the pattern at cmd/docker.go.
	ctx, cancel := context.WithTimeout(context.Background(), defaultInvokeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonPath, cmdArgs...)

	// Killing the process is not sufficient on its own: a descendant the
	// parser spawned can keep the stdout/stderr pipe write-ends open, leaving
	// the io.Copy below blocked forever even after the parent is dead.
	// WaitDelay tells os/exec to force-close those inherited pipe FDs shortly
	// after the context is done, and the explicit read-end close in the
	// watchdog goroutine (below) unblocks the in-flight reads.
	cmd.WaitDelay = 5 * time.Second

	if workDir != "" {
		cmd.Dir = workDir
	}

	// Pass through environment (Python needs ANTHROPIC_API_KEY, etc.)
	// If an API key is provided via flag or config, inject it into the
	// subprocess environment so Python picks it up regardless of .env files.
	cmd.Env = os.Environ()
	if apiKey != "" {
		cmd.Env = setEnv(cmd.Env, "ANTHROPIC_API_KEY", apiKey)
	}

	// Capture stdout (JSON output)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Stream stderr to terminal (progress messages)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start Python process: %w", err)
	}

	// Watchdog: when the timeout (or any context cancellation) fires, close
	// the pipe read-ends so io.Copy(stdout) and streamStderr(stderr) return
	// promptly instead of blocking on a descendant that still holds the
	// write-ends open. Without this, the deadline would kill the parser but
	// the CLI would still hang in io.Copy. watchdogDone stops the goroutine
	// on the normal (non-timeout) exit path.
	watchdogDone := make(chan struct{})
	defer close(watchdogDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = stdout.Close()
			_ = stderr.Close()
		case <-watchdogDone:
		}
	}()

	// Forward SIGINT/SIGTERM to the Python subprocess so Ctrl+C kills it.
	sigChan := make(chan os.Signal, 1)
	interrupted := false
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig, ok := <-sigChan
		if !ok {
			return // channel closed, normal exit
		}
		interrupted = true
		// Forward signal to Python subprocess
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
		// Give Python a few seconds to exit gracefully, then force kill
		time.AfterFunc(5*time.Second, func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		})
	}()
	defer func() {
		signal.Stop(sigChan)
		close(sigChan)
	}()

	// Stream stderr in a goroutine
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		streamStderr(stderr, quiet)
	}()

	// Read all stdout
	var stdoutBuf strings.Builder
	if _, err := io.Copy(&stdoutBuf, stdout); err != nil {
		return nil, fmt.Errorf("failed to read stdout: %w", err)
	}

	// Wait for stderr streaming to finish
	<-stderrDone

	// Wait for process to exit
	exitErr := cmd.Wait()
	exitCode := 0
	if exitErr != nil {
		if ee, ok := exitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return nil, fmt.Errorf("failed waiting for Python process: %w", exitErr)
		}
	}

	// Parse JSON from stdout
	rawJSON := strings.TrimSpace(stdoutBuf.String())
	if rawJSON == "" {
		if interrupted {
			// User interrupted with Ctrl+C — not an error
			return &InvokeResult{
				Envelope: types.Envelope{
					Status: "interrupted",
					Errors: []string{},
				},
				ExitCode: 130, // standard SIGINT exit code
			}, nil
		}
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "error",
				Errors: []string{"Python process produced no output on stdout"},
			},
			ExitCode: exitCode,
		}, nil
	}

	var envelope types.Envelope
	if err := json.Unmarshal([]byte(rawJSON), &envelope); err != nil {
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "error",
				Errors: []string{
					fmt.Sprintf("Failed to parse JSON output: %s", err),
					fmt.Sprintf("Raw output: %s", truncate(rawJSON, 500)),
				},
			},
			ExitCode: exitCode,
		}, nil
	}

	return &InvokeResult{
		Envelope: envelope,
		ExitCode: exitCode,
	}, nil
}

// streamStderr reads stderr line by line and writes to os.Stderr.
// If quiet is true, stderr output is suppressed.
func streamStderr(r io.Reader, quiet bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if !quiet {
			fmt.Fprintln(os.Stderr, scanner.Text())
		}
	}
}

// setEnv sets or replaces an environment variable in a []string env slice.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// truncate shortens a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
