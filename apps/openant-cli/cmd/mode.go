package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
	isatty "github.com/mattn/go-isatty"
)

// modeOpts collects the inputs to selectMode. Flag values come from the
// caller's cobra command; projectName / repoPath come from the resolved
// project context.
type modeOpts struct {
	full        bool
	incremental bool
	diffBase    string
	pr          int
	scope       string
	projectName string
	repoPath    string
}

// modeDecision is the resolved mode for a scan-run. Fields beyond Kind
// are only set when Kind == ScanKindDiff.
type modeDecision struct {
	Kind  string
	Base  string // ref used for diff (may be a SHA or named ref)
	Scope string
}

// errBaselineNonInteractive is returned when init/scan is invoked without
// any mode flag, has a baseline to fall back on, and stdin is not a TTY
// so we cannot prompt.
var errBaselineNonInteractive = errors.New(
	"this project has a previous scan; specify one of --full, --incremental, --diff-base <ref>, or --pr <n>")

// selectMode is the single source of truth for "full vs incremental?".
// Used by `openant init` today; will be reused by `openant scan` once the
// chain refactor lands.
//
// Decision precedence:
//  1. Validate flag combinations.
//  2. --full → full
//  3. --pr → diff against PR base (mutates working tree)
//  4. --diff-base → diff against ref
//  5. --incremental → diff against last successful scan (errors if none)
//  6. No flag, no baseline → full (silent)
//  7. No flag, baseline + TTY → prompt (Enter = full)
//  8. No flag, baseline + non-TTY → error
func selectMode(o modeOpts) (modeDecision, error) {
	if err := validateModeFlags(o); err != nil {
		return modeDecision{}, err
	}

	if o.full {
		return modeDecision{Kind: config.ScanKindFull}, nil
	}

	scope := o.scope
	if scope == "" {
		scope = git.ScopeChangedFunctions
	}

	if o.pr > 0 {
		baseRef, err := git.FetchPR(o.repoPath, o.pr, nil)
		if err != nil {
			return modeDecision{}, err
		}
		return modeDecision{Kind: config.ScanKindDiff, Base: baseRef, Scope: scope}, nil
	}

	if o.diffBase != "" {
		return modeDecision{Kind: config.ScanKindDiff, Base: o.diffBase, Scope: scope}, nil
	}

	if o.incremental {
		baseline, _, err := config.LatestScanMeta(o.projectName)
		if err != nil {
			return modeDecision{}, fmt.Errorf("--incremental: %w", err)
		}
		if baseline == nil {
			return modeDecision{}, errors.New(
				"--incremental: no successful prior scan found for this project; run a full scan first")
		}
		return modeDecision{Kind: config.ScanKindDiff, Base: baseline.Commit, Scope: scope}, nil
	}

	// No flags. Look for a baseline.
	baseline, _, err := config.LatestScanMeta(o.projectName)
	if err != nil {
		return modeDecision{}, err
	}
	if baseline == nil {
		// First scan on this project — full, silent.
		return modeDecision{Kind: config.ScanKindFull}, nil
	}

	// Baseline exists. Prompt or error.
	if !isStdinTTY() {
		return modeDecision{}, errBaselineNonInteractive
	}
	return promptMode(baseline, scope, os.Stdin, os.Stderr)
}

// validateModeFlags checks for conflicting flag combinations. Pure
// (no I/O), unit-tested.
func validateModeFlags(o modeOpts) error {
	diffFlagCount := 0
	if o.diffBase != "" {
		diffFlagCount++
	}
	if o.pr > 0 {
		diffFlagCount++
	}
	if o.incremental {
		diffFlagCount++
	}
	if o.full && diffFlagCount > 0 {
		return errors.New("--full cannot be combined with --incremental, --diff-base, or --pr")
	}
	if diffFlagCount > 1 {
		return errors.New("--incremental, --diff-base, and --pr are mutually exclusive")
	}
	if o.scope != "" && !git.IsValidScope(o.scope) {
		return fmt.Errorf(
			"invalid --diff-scope %q (expected changed_files|changed_functions|callers)", o.scope)
	}
	return nil
}

// isStdinTTY reports whether stdin is connected to a terminal.
// Uses go-isatty (already a dep via cmd/report.go) — a naive
// os.ModeCharDevice check would falsely treat /dev/null as a TTY,
// since /dev/null is also a character device.
func isStdinTTY() bool {
	return isatty.IsTerminal(os.Stdin.Fd())
}

// promptMode prints a recap of the prior scan and reads the user's choice.
// Default on bare Enter: full (the safer choice — accidental Enter gives
// the more thorough scan, not the cheaper one).
func promptMode(prev *config.ScanMeta, scope string, in io.Reader, out io.Writer) (modeDecision, error) {
	short := config.ShortSHA(prev.Commit)
	when := humanizeTimestamp(prev.StartedAt)
	fmt.Fprintf(out, "Found previous scan: %s at %s on %s.\n", prev.Kind, short, when)
	fmt.Fprintf(out, "Run [f]ull scan or [i]ncremental from %s? [F/i]: ", short)

	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return modeDecision{}, fmt.Errorf("read prompt: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	switch answer {
	case "", "f", "full":
		return modeDecision{Kind: config.ScanKindFull}, nil
	case "i", "incremental":
		return modeDecision{Kind: config.ScanKindDiff, Base: prev.Commit, Scope: scope}, nil
	default:
		return modeDecision{}, fmt.Errorf("invalid answer %q (expected f or i)", answer)
	}
}

// resolveStepDiffOpts produces the diff opts for a standalone step verb
// (parse, etc.). Step verbs are silent power-user surfaces: explicit
// flags win, otherwise honor the project's meta.json (so a prior
// `openant init --incremental` flows through), otherwise no incremental.
// Never prompts.
//
// Empty defaultScope is treated as "changed_functions" (matching the flag
// default on each verb).
func resolveStepDiffOpts(ctx *projectContext, flagBase string, flagPR int, flagScope string) (diffOpts, error) {
	scope := flagScope
	if scope == "" {
		scope = git.ScopeChangedFunctions
	}

	// Explicit flags win.
	if flagBase != "" || flagPR > 0 {
		opts := diffOpts{base: flagBase, pr: flagPR, scope: scope}
		if err := opts.validate(); err != nil {
			return diffOpts{}, err
		}
		return opts, nil
	}

	// No explicit flags — fall back to meta.json from init.
	if ctx == nil || ctx.Project == nil {
		return diffOpts{}, nil
	}
	meta, err := config.LoadScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort)
	if err != nil {
		// No meta (legacy / not yet inited under new scheme) — silent full.
		return diffOpts{}, nil
	}
	if meta.Kind != config.ScanKindDiff {
		return diffOpts{}, nil
	}
	return diffOpts{base: meta.Base, scope: meta.Scope}, nil
}

// humanizeTimestamp formats a stored RFC3339 timestamp into something
// human-friendly for the prompt recap. Returns the input unchanged when
// parsing fails.
func humanizeTimestamp(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	delta := time.Since(t)
	switch {
	case delta < 2*time.Minute:
		return "just now"
	case delta < time.Hour:
		mins := int(delta.Minutes())
		return fmt.Sprintf("%s (%d min ago)", t.Format("2006-01-02"), mins)
	case delta < 24*time.Hour:
		hours := int(delta.Hours())
		return fmt.Sprintf("%s (%d h ago)", t.Format("2006-01-02"), hours)
	default:
		days := int(delta.Hours() / 24)
		return fmt.Sprintf("%s (%d days ago)", t.Format("2006-01-02"), days)
	}
}
