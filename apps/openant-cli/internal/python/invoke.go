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
	"sync/atomic"
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
	// -P keeps the process working directory off sys.path. `-m openant` otherwise
	// prepends the CWD, and this engine inherits the user's shell CWD — which in the
	// standard `git clone X && cd X && openant ...` flow is inside the scanned,
	// untrusted repository. A hostile `openant/` package there would shadow the real
	// one and execute on import. -P closes that; it also propagates via the
	// environment to the report subprocesses the engine spawns.
	cmdArgs := append([]string{"-P", "-m", "openant"}, args...)

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
	// interrupted is written by the signal goroutine below and read on the
	// main goroutine after cmd.Wait; use atomic.Bool so the two accesses are
	// synchronized (a plain bool is a data race — go test -race flags it and a
	// stale read would mislabel a user Ctrl+C as a Failed scan instead of 130).
	var interrupted atomic.Bool
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig, ok := <-sigChan
		if !ok {
			return // channel closed, normal exit
		}
		interrupted.Store(true)
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
		_ = cmd.Wait() // reap the child even on read error so it isn't leaked (R2C-2)
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
		// The interrupt short-circuit fires ONLY here, where the child produced
		// no usable success/vuln envelope (empty stdout). A fully-parsed
		// envelope below MUST win over a late/spurious SIGINT — reporting 130
		// then would discard a real scan result. Empty stdout + interrupted is
		// the only case where 130 is the correct answer.
		if interrupted.Load() {
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
			ExitCode: normalizeExit(exitCode, true),
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
			ExitCode: normalizeExit(exitCode, true),
		}, nil
	}

	// Normalize the parsed-envelope exit code against the documented 0/1/2
	// contract: an error envelope must not surface as clean/vulns-found, and a
	// non-interrupt signal kill (negative code) is an error. A legitimate
	// success + code 1 (vulns found) is preserved.
	return &InvokeResult{
		Envelope: envelope,
		ExitCode: normalizeExit(exitCode, envelope.Status == "error"),
	}, nil
}

// normalizeExit maps a child exit code onto the tool's documented contract
// (openant/cli.py:16 — 0 = clean, 1 = vulnerabilities found, 2 = error) before
// scan.go does os.Exit(result.ExitCode). User interrupts (SIGINT -> 130) are
// handled earlier and never reach here.
//   - A negative code (Go reports -1 for a signal-killed child: OOM/SIGKILL/
//     segfault) is abnormal termination -> 2, regardless of any flushed envelope.
//   - When the result is an error envelope, clean (0)/vulns-found (1) -> 2.
//   - Otherwise the code is preserved (a legitimate success + 1 = vulns found).
func normalizeExit(code int, isError bool) int {
	if code < 0 {
		return 2
	}
	if isError && code < 2 {
		return 2
	}
	return code
}

// streamStderr reads stderr line by line and writes to os.Stderr.
// If quiet is true, stderr output is suppressed.
func streamStderr(r io.Reader, quiet bool) {
	// bufio.Reader (not bufio.Scanner) so a stderr line larger than the
	// scanner's default 64k token buffer is not truncated/dropped — a long
	// Python traceback on one line can exceed that and would lose diagnostics.
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 && !quiet {
			fmt.Fprint(os.Stderr, line)
		}
		if err != nil {
			return
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
