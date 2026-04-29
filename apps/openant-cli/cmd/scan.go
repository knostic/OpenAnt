package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/checkpoint"
	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [repository-path]",
	Short: "Scan a repository for vulnerabilities (full pipeline)",
	Long: `Scan runs the full pipeline:
  init → parse → app-context → enhance → analyze → verify → build-output → dynamic-test → report

This is the recommended command for most users. It produces a complete
vulnerability report with false positive elimination.

If no repository path is given, the active project is used (see: openant init).

Dynamic testing runs by default and requires Docker. Use --skip-dynamic-test
to opt out.

Each step writes a {step}.report.json file with timing, cost, and metadata.
A final scan.report.json aggregates all step reports.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runScan,
}

var (
	scanOutput      string
	scanLanguage    string
	scanLevel       string
	scanVerify      bool
	scanNoContext   bool
	scanNoEnhance   bool
	scanEnhanceMode string
	scanNoReport        bool
	scanSkipDynamicTest bool
	scanLimit           int
	scanModel       string
	scanWorkers     int
	scanBackoff     int
	scanFull        bool
	scanIncremental bool
	scanDiffBase    string
	scanPR          int
	scanDiffScope   string
)

func init() {
	registerScanFlags(scanCmd)
}

// registerScanFlags wires the full scan-pipeline flag set onto cmd. Used by
// scanCmd and by the thin diffCmd wrapper so that both surfaces accept the
// same knobs.
func registerScanFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output directory (default: project scan dir or temp dir)")
	cmd.Flags().StringVarP(&scanLanguage, "language", "l", "", "Language: python, javascript, go, c, ruby, php, auto")
	cmd.Flags().StringVar(&scanLevel, "level", "reachable", "Processing level: all, reachable, codeql, exploitable")
	cmd.Flags().BoolVar(&scanVerify, "verify", false, "Enable Stage 2 attacker simulation")
	cmd.Flags().BoolVar(&scanNoContext, "no-context", false, "Skip application context generation")
	cmd.Flags().BoolVar(&scanNoEnhance, "no-enhance", false, "Skip context enhancement step")
	cmd.Flags().StringVar(&scanEnhanceMode, "enhance-mode", "agentic", "Enhancement mode: agentic (thorough) or single-shot (fast)")
	cmd.Flags().BoolVar(&scanNoReport, "no-report", false, "Skip report generation")
	cmd.Flags().BoolVar(&scanSkipDynamicTest, "skip-dynamic-test", false, "Skip Docker-isolated dynamic testing (default: run dynamic tests)")
	cmd.Flags().IntVar(&scanLimit, "limit", 0, "Max units to analyze (0 = no limit)")
	cmd.Flags().StringVar(&scanModel, "model", "opus", "Model: opus or sonnet")
	cmd.Flags().IntVar(&scanWorkers, "workers", 8, "Number of parallel workers for LLM steps (default: 8)")
	cmd.Flags().IntVar(&scanBackoff, "backoff", 30, "Seconds to wait when rate-limited (default: 30)")
	cmd.Flags().BoolVar(&scanFull, "full", false, "Force full scan (rejects --incremental/--diff-base/--pr)")
	cmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Incremental against the last successful scan on this project")
	cmd.Flags().StringVar(&scanDiffBase, "diff-base", "", "Incremental mode: filter pipeline to units overlapping diff vs this ref (e.g. origin/main, HEAD~5)")
	cmd.Flags().IntVar(&scanPR, "pr", 0, "Incremental mode against a GitHub PR number (requires gh; mutex with --diff-base)")
	cmd.Flags().StringVar(&scanDiffScope, "diff-scope", "changed_functions", "Diff scope: changed_files, changed_functions, callers")
}

func runScan(cmd *cobra.Command, args []string) {
	// Fail-fast on missing Docker when dynamic-test will run, before we
	// resolve the project, write meta.json, or shell to Python. Otherwise
	// the user burns the whole pipeline only to error at the last step.
	if !scanSkipDynamicTest {
		if err := checkDockerAvailable(); err != nil {
			output.PrintError(err.Error())
			os.Exit(2)
		}
	}

	repoPath, ctx, err := resolveRepoArg(args)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults if using project context
	if ctx != nil {
		if scanOutput == "" {
			scanOutput = ctx.ScanDir
		}
		if scanLanguage == "" {
			scanLanguage = ctx.Language
		}
	}
	if scanLanguage == "" {
		scanLanguage = "auto"
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Decide full vs incremental, honoring init's running meta.json if
	// present (init was just run for this commit and recorded the choice).
	decision, err := resolveScanMode(ctx, repoPath)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Build the diff manifest from the decision before checkpoint
	// detection so that any PR-mode checkout happens first and the scan
	// dir is up-to-date.
	manifestOpts := diffOpts{}
	if decision.Kind == config.ScanKindDiff {
		manifestOpts.base = decision.Base
		manifestOpts.scope = decision.Scope
	}
	manifestPath, err := prepareDiffManifest(repoPath, scanOutput, manifestOpts)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Check for interrupted runs in the scan directory
	if ctx != nil && scanOutput != "" {
		steps := []string{"enhance", "analyze", "verify"}
		for _, step := range steps {
			if cpInfo := checkpoint.DetectViaPython(rt.Path, scanOutput, step); cpInfo != nil {
				if !checkpoint.PromptResume(cpInfo, step, quiet) {
					_ = checkpoint.Clean(cpInfo.Dir)
				}
				// Note: Python side auto-detects and uses the checkpoint dir,
				// so we only need to clean if the user wants a fresh start.
			}
		}
	}

	// Build Python CLI args
	pyArgs := []string{"scan", repoPath}
	if scanOutput != "" {
		pyArgs = append(pyArgs, "--output", scanOutput)
	}
	if scanLanguage != "auto" {
		pyArgs = append(pyArgs, "--language", scanLanguage)
	}
	if scanLevel != "reachable" {
		pyArgs = append(pyArgs, "--level", scanLevel)
	}
	if scanVerify {
		pyArgs = append(pyArgs, "--verify")
	}
	if scanNoContext {
		pyArgs = append(pyArgs, "--no-context")
	}
	if scanNoEnhance {
		pyArgs = append(pyArgs, "--no-enhance")
	}
	if scanEnhanceMode != "agentic" {
		pyArgs = append(pyArgs, "--enhance-mode", scanEnhanceMode)
	}
	if scanNoReport {
		pyArgs = append(pyArgs, "--no-report")
	}
	if !scanSkipDynamicTest {
		pyArgs = append(pyArgs, "--dynamic-test")
	}
	if scanLimit > 0 {
		pyArgs = append(pyArgs, "--limit", fmt.Sprintf("%d", scanLimit))
	}
	if scanModel != "opus" {
		pyArgs = append(pyArgs, "--model", scanModel)
	}
	if scanWorkers != 8 {
		pyArgs = append(pyArgs, "--workers", fmt.Sprintf("%d", scanWorkers))
	}
	if scanBackoff != 30 {
		pyArgs = append(pyArgs, "--backoff", fmt.Sprintf("%d", scanBackoff))
	}
	if manifestPath != "" {
		pyArgs = append(pyArgs, "--diff-manifest", manifestPath)
	}

	// Pass repository metadata from project context so reports don't show
	// [NOT PROVIDED] placeholders.
	if ctx != nil && ctx.Project != nil {
		if ctx.Project.Name != "" {
			pyArgs = append(pyArgs, "--repo-name", ctx.Project.Name)
		}
		if ctx.Project.RepoURL != "" {
			pyArgs = append(pyArgs, "--repo-url", ctx.Project.RepoURL)
		}
		if ctx.Project.CommitSHA != "" {
			pyArgs = append(pyArgs, "--commit-sha", ctx.Project.CommitSHA)
		}
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, requireAPIKey())
	if err != nil {
		finalizeScanMetaIfProject(ctx, config.ScanStatusFailed)
		output.PrintError(err.Error())
		os.Exit(2)
	}

	switch result.Envelope.Status {
	case "interrupted":
		finalizeScanMetaIfProject(ctx, config.ScanStatusInterrupted)
	case "success":
		finalizeScanMetaIfProject(ctx, config.ScanStatusSuccess)
	default:
		finalizeScanMetaIfProject(ctx, config.ScanStatusFailed)
	}

	if result.Envelope.Status == "interrupted" {
		os.Exit(130)
	} else if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintScanSummaryV2(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}

// finalizeScanMetaIfProject updates the scan-run meta.json with a terminal
// status when the scan ran against a known project. Ad-hoc scans without
// project context have no meta.json and are silently skipped.
func finalizeScanMetaIfProject(ctx *projectContext, status string) {
	if ctx == nil || ctx.Project == nil {
		return
	}
	if err := config.FinalizeScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort, status); err != nil {
		output.PrintWarning(fmt.Sprintf("Failed to update scan meta: %s", err))
	}
}

// resolveScanMode produces the modeDecision for this scan run. Honors a
// running meta.json from a recent `openant init` (so the user is not
// re-prompted), otherwise calls selectMode with the scan flags.
//
// When running against a project, also writes meta.json status=running
// reflecting the decision so step verbs and finalizeScanMetaIfProject
// have something to read/update.
func resolveScanMode(ctx *projectContext, repoPath string) (modeDecision, error) {
	flagsPassed := scanFull || scanIncremental || scanDiffBase != "" || scanPR > 0

	// Reuse init's pending decision when no flags override it.
	if !flagsPassed && ctx != nil && ctx.Project != nil {
		existing, err := config.LoadScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort)
		if err == nil && existing.Status == config.ScanStatusRunning {
			return modeDecision{Kind: existing.Kind, Base: existing.Base, Scope: existing.Scope}, nil
		}
	}

	projectName := ""
	if ctx != nil && ctx.Project != nil {
		projectName = ctx.Project.Name
	}

	decision, err := selectMode(modeOpts{
		full:        scanFull,
		incremental: scanIncremental,
		diffBase:    scanDiffBase,
		pr:          scanPR,
		scope:       scanDiffScope,
		projectName: projectName,
		repoPath:    repoPath,
	})
	if err != nil {
		return modeDecision{}, err
	}

	// Record the decision in meta.json status=running if we have a project.
	// finalizeScanMetaIfProject will flip it terminal when the pipeline ends.
	if ctx != nil && ctx.Project != nil {
		meta := config.NewScanMeta(
			decision.Kind,
			ctx.Project.CommitSHA,
			git.CurrentBranch(repoPath),
			ctx.Project.Language,
		)
		meta.Base = decision.Base
		meta.Scope = decision.Scope
		if err := config.SaveScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort, meta); err != nil {
			output.PrintWarning(fmt.Sprintf("Failed to write scan meta: %s", err))
		}
	}

	return decision, nil
}
