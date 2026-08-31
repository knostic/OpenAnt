// Package python provides subprocess invocation of the Python CLI.
package python

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
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
//
// 30m is enough for typical repos but a large one (hundreds of LLM units) can
// legitimately run longer; when it does, the deadline kills the invocation.
// A COMPLETE result envelope in the stdout buffer always wins over the
// deadline (the envelope is the run's final act, so a recovered envelope is
// a completed run); otherwise the surfaced error carries the diagnosis —
// the deadline, the OPENANT_INVOKE_TIMEOUT override, and (for subcommands
// that checkpoint) the resume path.
// resolveInvokeTimeout lets an operator raise the budget via
// OPENANT_INVOKE_TIMEOUT without recompiling.
var defaultInvokeTimeout = 30 * time.Minute

// stderrDrainGrace bounds how long the normal exit path waits on the stderr
// drain AFTER the child's stdout already closed (i.e. the child has exited):
// a descendant holding ONLY the stderr write-end would otherwise keep the
// streamer blocked until the deadline's watchdog fired — the full
// OPENANT_INVOKE_TIMEOUT hang for a result that was already in hand. Package
// var so tests can shrink it, mirroring defaultInvokeTimeout.
var stderrDrainGrace = 5 * time.Second

// resolveInvokeTimeout returns the invoke deadline, honoring the
// OPENANT_INVOKE_TIMEOUT env override. The value is either a Go duration
// (e.g. "2h", "90m") or a bare positive integer interpreted as seconds. An
// unset, empty, malformed, or non-positive value falls back to
// defaultInvokeTimeout (a warning is printed for a non-empty invalid value).
func resolveInvokeTimeout() time.Duration {
	v := strings.TrimSpace(os.Getenv("OPENANT_INVOKE_TIMEOUT"))
	if v == "" {
		return defaultInvokeTimeout
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	// Bare integer = seconds. Guard the multiply: n*time.Second overflows int64
	// for n beyond ~9.2e9 (≈292 years) and wraps NEGATIVE, which would make the
	// deadline already-expired and kill the subprocess immediately — the exact
	// failure this knob prevents. Such an absurd value falls back to the default.
	if n, err := strconv.Atoi(v); err == nil && n > 0 &&
		int64(n) <= int64(math.MaxInt64)/int64(time.Second) {
		return time.Duration(n) * time.Second
	}
	fmt.Fprintf(os.Stderr,
		"[openant] ignoring invalid OPENANT_INVOKE_TIMEOUT=%q; using default %v\n",
		v, defaultInvokeTimeout)
	return defaultInvokeTimeout
}

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
	// Resolved ONCE — resolveInvokeTimeout warns on an invalid override, and
	// re-resolving it while formatting the deadline diagnosis printed the
	// warning a second time.
	invokeTimeout := resolveInvokeTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), invokeTimeout)
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

	// Read all stdout. A read error is CAPTURED, not returned: the buffer
	// may already hold a complete envelope (a descendant holding the pipe
	// write-end past the child's exit is exactly the case the watchdog
	// comment above describes) — the envelope-wins rule below recovers it.
	var stdoutBuf strings.Builder
	_, copyErr := io.Copy(&stdoutBuf, stdout)

	// Reap and drain. ORDER MATTERS and differs by path:
	//   * normal path (no read error): drain stderr FIRST, then Wait —
	//     StderrPipe's contract is explicit ("It is thus incorrect to call
	//     Wait before all reads from the pipe have completed"): Wait closes
	//     the read-end on reap, and a read still pending then fails with
	//     ErrClosed, dropping whatever is still in the kernel pipe buffer —
	//     the child's FINAL stderr lines (a traceback's last line is the
	//     one the operator needs) would be lost.
	//   * read-error path: the watchdog (or the fd failure) has already
	//     closed the stdout read-end; Wait FIRST (it reaps the child and
	//     closes the stderr read-end, which unblocks the streamer — that
	//     close, not the deadline, is what bounds a descendant holding the
	//     stderr write-end), then drain.
	var exitErr error
	if copyErr != nil {
		exitErr = cmd.Wait()
		<-stderrDone
	} else {
		// Round-3 panel finding (executed probe): the stdout read is
		// bounded by the child's exit, but this drain was bounded only
		// by the deadline — a descendant holding ONLY the stderr
		// write-end kept <-stderrDone blocked until ctx.Done() fired
		// the watchdog: a 0.1s child with a complete envelope in hand
		// hung the FULL OPENANT_INVOKE_TIMEOUT (15s probe on a 15s
		// budget) and returned under a spurious "deadline fired"
		// recovery note. Grace-close the stderr read-end
		// stderrDrainGrace after the child's stdout closed (mirroring
		// cmd.WaitDelay's own bound): a streamer still blocked by then
		// is reading an EMPTY kernel buffer — the real output drained
		// the moment it arrived — so closing loses nothing and
		// unblocks the drain.
		stderrGrace := time.AfterFunc(stderrDrainGrace, func() { _ = stderr.Close() })
		<-stderrDone
		stderrGrace.Stop()
		exitErr = cmd.Wait()
	}

	deadlineFired := ctx.Err() == context.DeadlineExceeded

	// Was the CHILD itself killed by the deadline — or did it exit on its
	// own, with only a descendant holding a pipe write-end past the
	// deadline? A natural exit must NOT be diagnosed as a kill: "raise the
	// budget" advice for a crashed child misdirects the operator AND masks
	// the real exit status (wave round-2 finding, executed: a traceback +
	// exit 1 + a held pipe produced the kill diagnosis). Unix-precise: a
	// signal death (ExitCode < 0), or the zombie-kill window (Wait returned
	// the context error, not an ExitError). Windows cannot distinguish
	// (TerminateProcess yields exit code 1, same as a natural exit 1) —
	// there the deadline diagnosis is the best available answer; a
	// documented residual.
	naturalExitCode := 0
	exitErrIsKillArtifact := false
	if ee, ok := exitErr.(*exec.ExitError); ok {
		naturalExitCode = ee.ExitCode()
		// Unix: a signal death reports a negative code. Windows:
		// TerminateProcess yields exit code 1 — INDISTINGUISHABLE from a
		// natural exit 1, so there the deadline firing is accepted as the
		// kill signal (a natural crash under a fired deadline gets the
		// diagnosis too — the documented trade-off; the alternative is
		// no diagnosis at all on the platform).
		if runtime.GOOS == "windows" {
			exitErrIsKillArtifact = true
		} else {
			exitErrIsKillArtifact = naturalExitCode < 0
		}
	} else if exitErr != nil {
		// Non-ExitError from Wait: os/exec substitutes the context error
		// when the child had ALREADY exited (successfully) when the
		// deadline's Cancel fired — by construction NOT a kill of a
		// running child. ProcessState distinguishes (the same idiom as
		// invoke_ctx.go:125): only a non-success state is the kill.
		// Residual: a GENUINE wait failure under a fired deadline leaves
		// ProcessState nil and reads as the kill here — the real cause is
		// still wrapped as "Underlying error", only the headline is
		// wrong. Practically unreachable (waitpid-class failures).
		exitErrIsKillArtifact = deadlineFired &&
			!(cmd.ProcessState != nil && cmd.ProcessState.Success())
	}
	childKilled := deadlineFired && exitErrIsKillArtifact

	// #161 follow-up — the envelope-wins rule, uniform across EVERY kill
	// surface (the #313 principle: a fully-parsed envelope MUST win over a
	// late/expired context). The #413 fix gated the deadline diagnosis on
	// HOW the process died (the pipe-close error, or ExitCode < 0), so:
	//   * a complete envelope was discarded whenever a descendant held a
	//     pipe write-end past the deadline — with a message claiming the
	//     output was discarded while it sat in the buffer;
	//   * the exit-0 zombie-kill window (Wait returns the context error, not
	//     an ExitError) and the Windows kill (TerminateProcess yields exit
	//     code 1, never negative) never saw the diagnosis at all.
	// Parse the buffer FIRST; only when there is no usable envelope AND the
	// deadline fired does the diagnosis return — which makes its wording
	// ("no complete result was recovered") true by construction.
	rawJSON := strings.TrimSpace(stdoutBuf.String())
	var envelope types.Envelope
	var parseErr error
	if rawJSON != "" {
		parseErr = json.Unmarshal([]byte(rawJSON), &envelope)
	}
	// envelope.Status != "" guards a literal "null" stdout (unmarshals to
	// a zero Envelope, which is not a result) — not reachable via
	// _output_json, defense-in-depth.
	envelopeOK := rawJSON != "" && parseErr == nil && envelope.Status != ""

	if envelopeOK {
		if deadlineFired {
			// Recovered, not discarded: say so. A recovered envelope is a
			// COMPLETED run — the Python CLI emits its result envelope as
			// its final act, so a partial envelope cannot exist; the
			// deadline caught the process at exit (or a descendant holding
			// the pipe). Residuals (documented): a Unix signal-death code
			// here is the kill's artifact and stays a conservative exit 2
			// (normalizeExit's pre-existing policy) even with
			// status=success; on Windows the kill artifact (exit code 1)
			// is indistinguishable from a legitimate vulns-found exit.
			if !quiet {
				fmt.Fprintf(os.Stderr,
					"[openant] the invoke deadline fired after %v, but a complete result envelope was recovered — returning it (the envelope is the run's final act, so the run completed)\n",
					invokeTimeout)
			}
		}
		exitCode := 0
		if ee, ok := exitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		}
		if exitErrIsKillArtifact {
			// Round-3 panel finding: the exit code here is the KILL's
			// artifact, not the run's outcome — Unix a negative signal
			// code, Windows TerminateProcess's exit 1, which is the
			// SAME code as a legitimate vulnerabilities-found exit, so
			// a killed Windows run surfaced exit 1 ("vulnerabilities
			// found") for a recovered envelope. The envelope cannot
			// distinguish clean from vulns-found (both travel as the
			// success envelope; the distinction lived in the intended
			// exit code the kill destroyed), so the honest uniform
			// mapping is the conservative error code: the run was
			// killed. Unix already behaved this way through the
			// negative code; Windows now matches.
			exitCode = -1
		}
		return &InvokeResult{
			Envelope: envelope,
			ExitCode: normalizeExit(exitCode, envelope.Status == "error"),
		}, nil
	}

	// No usable envelope. A user interrupt wins over the deadline diagnosis
	// in the overlap window (Ctrl+C inside the deadline's final seconds: the
	// USER initiated the stop — interrupted/130 is the honest answer, not
	// failed/2).
	if rawJSON == "" && interrupted.Load() {
		// User interrupted with Ctrl+C — not an error. Empty stdout +
		// interrupted is the only case where 130 is correct (a parsed
		// envelope above already won over a late/spurious SIGINT).
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "interrupted",
				Errors: []string{},
			},
			ExitCode: 130, // standard SIGINT exit code
		}, nil
	}

	// No usable envelope AND the child was actually killed by the deadline:
	// the diagnosis — the same text on every surface, with the underlying
	// cause wrapped when there is one.
	if childKilled {
		return nil, deadlineDiagnosis(invokeTimeout, args, copyErr, exitErr)
	}

	// Non-deadline failures, in the original precedence. The watchdog's
	// read-end close under a fired deadline is an ARTIFACT (os.ErrClosed),
	// not a real I/O failure — suppressed so the honest
	// no-output/parse-failure paths below report the child's own outcome.
	// A genuine non-ErrClosed read error still surfaces, deadline or not.
	if copyErr != nil && !(deadlineFired && errors.Is(copyErr, os.ErrClosed)) {
		return nil, fmt.Errorf("failed to read stdout: %w", copyErr)
	}
	if exitErr != nil {
		if _, ok := exitErr.(*exec.ExitError); !ok {
			// The context-substitution wait error for an
			// already-successfully-exited child under a fired deadline
			// is the same artifact class — the honest answer is the
			// child's own (empty) outcome below, not a wait failure.
			if !(deadlineFired && cmd.ProcessState != nil && cmd.ProcessState.Success()) {
				return nil, fmt.Errorf("failed waiting for Python process: %w", exitErr)
			}
		}
	}

	exitCode := naturalExitCode
	if rawJSON == "" {
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "error",
				Errors: []string{"Python process produced no output on stdout"},
			},
			ExitCode: normalizeExit(exitCode, true),
		}, nil
	}

	if !envelopeOK {
		// Non-empty stdout that is not a usable envelope. parseErr != nil
		// is malformed JSON; parseErr == nil is VALID JSON that is not a
		// result envelope (a literal null, {}, or any object without a
		// status field — the null-guard's target case; formatting a nil
		// error would print %!s(<nil>)).
		parseMsg := "stdout was valid JSON but not a result envelope (no status field)"
		if parseErr != nil {
			parseMsg = fmt.Sprintf("Failed to parse JSON output: %s", parseErr)
		}
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "error",
				Errors: []string{
					parseMsg,
					fmt.Sprintf("Raw output: %s", truncate(rawJSON, 500)),
				},
			},
			ExitCode: normalizeExit(exitCode, true),
		}, nil
	}

	// Unreachable: envelopeOK returned above, and every non-OK shape has
	// returned by now — kept as a defensive net for future edits.
	return &InvokeResult{
		Envelope: envelope,
		ExitCode: normalizeExit(exitCode, envelope.Status == "error"),
	}, nil
}

// deadlineDiagnosis builds the ONE deadline message every kill surface
// returns (#161): the deadline and its effective value, the recovery paths,
// and the underlying cause wrapped when there is one. The checkpoint-resume
// hint is emitted only for subcommands that actually checkpoint — parse,
// generate-context, build-output, report, report-data and checkpoint-status
// write none, and promising a resume that cannot happen misdirects the
// operator on the very path (a hung parser) the deadline exists for.
func deadlineDiagnosis(timeout time.Duration, args []string, copyErr, exitErr error) error {
	var b strings.Builder
	fmt.Fprintf(&b, "openant: the invoke deadline fired after %v — the run "+
		"was killed and no complete result was recovered. ", timeout)
	if checkpointedSubcommand(args) {
		// Conditional on purpose: a scan killed in its parse phase has
		// ZERO completed units — the sentence must not send the operator
		// hunting for checkpoint dirs that do not exist yet.
		// Conditional on the output dir too: an ad-hoc run (no --output,
		// no project) of scan/verify/analyze/dynamic-test writes its
		// checkpoints into a fresh tempfile.mkdtemp dir (cli.py:138, :515,
		// :714 — enhance is the exception, deriving from the dataset path)
		// that a re-run will not see — the resume only happens with the
		// same --output or project.
		b.WriteString("Units that completed before the kill are checkpointed " +
			"under the run's output dir (a re-run with the same --output or " +
			"project resumes from them); ")
	}
	b.WriteString("to finish a long run outright, raise the budget via " +
		"OPENANT_INVOKE_TIMEOUT (e.g. OPENANT_INVOKE_TIMEOUT=2h).")
	// exitErr first: "signal: killed" is the honest cause on the plain
	// hang-kill (the #161 shape) — the copy error there is the watchdog's
	// own read-end close, the artifact this whole fix exists to stop
	// headlining.
	cause := exitErr
	if cause == nil {
		cause = copyErr
	}
	if cause != nil {
		return fmt.Errorf("%s Underlying error: %w", b.String(), cause)
	}
	return fmt.Errorf("%s", b.String())
}

// checkpointedSubcommand reports whether the invoked Python subcommand writes
// per-unit checkpoints a re-run can resume from (the four DetectViaPython
// steps, plus scan which runs them all under its single invocation).
func checkpointedSubcommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	// The three DetectViaPython steps (cmd/scan.go: enhance/analyze/verify)
	// + dynamic-test (its own auto-derived dir — see
	// utilities/dynamic_tester/__init__.py:148-156) + scan (one invocation
	// runs the phases).
	switch args[0] {
	case "scan", "enhance", "analyze", "verify", "dynamic-test":
		return true
	}
	return false
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
