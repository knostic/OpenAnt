package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/checkpoint"
	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
	"github.com/knostic/open-ant-cli/internal/languages"
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
	scanOutput                      string
	scanLanguage                    string
	scanLevel                       string
	scanVerify                      bool
	scanNoContext                   bool
	scanNoEnhance                   bool
	scanEnhanceMode                 string
	scanNoReport                    bool
	scanSkipDynamicTest             bool
	scanLimit                       int
	scanLLMConfig                   string
	scanWorkers                     int
	scanBackoff                     int
	scanFull                        bool
	scanIncremental                 bool
	scanDiffBase                    string
	scanPR                          int
	scanStaged                      bool
	scanDiffScope                   string
	scanLLMReachability             bool
	scanLLMReachabilityMaxCodeBytes int
	scanLibraryMode                 bool
	scanRepoName                    string
	scanRepoURL                     string
	scanCommitSHA                   string
)

func init() {
	registerScanFlags(scanCmd)
}

// registerScanFlags wires the full scan-pipeline flag set onto cmd. Used by
// scanCmd and by the thin diffCmd wrapper so that both surfaces accept the
// same knobs.

// resolveRepoMetadata merges the explicit CLI flags, the project context,
// and the git-detected working-tree HEAD (#539 + #557): the flag wins; the
// project context is the middle tier; a bare-path scan of a git checkout
// falls to detection (a nil context is the #539 primary usage; a non-git
// path detects empty and keeps whatever the earlier tiers supplied).
// The returned warn is non-empty when the winning SHA disagrees with the
// detected HEAD (an explicit flag in a CI synthetic-merge checkout is
// legitimate; a stale project SHA is the footgun — the caller prints it).
// The "nogit" sentinel (init records it for non-repo paths) is treated as
// empty so it never flows into permalinks or SARIF revisionIds.
func resolveRepoMetadata(name, url, sha string, ctx *projectContext, detectedSHA string) (string, string, string, string) {
	return resolveRepoMetadataFull(name, url, sha, ctx, detectedSHA, "")
}

// resolveRepoMetadataFull is resolveRepoMetadata with the #562 URL tier: a
// bare-path scan of a git checkout derives its --repo-url from the origin
// remote, NORMALIZED (scp→https, credentials stripped — a raw remote never
// persists). The detected URL is the LAST resort (an explicit flag or a
// project URL wins; the project tier also normalizes defensively — an init
// recorded scp-form or credential-bearing remote would otherwise reach the
// report permalinks and the SARIF repositoryUri verbatim).
func resolveRepoMetadataFull(name, url, sha string, ctx *projectContext, detectedSHA, detectedURL string) (string, string, string, string) {
	flaggedSHA := sha != ""
	if ctx != nil && ctx.Project != nil {
		if name == "" && ctx.Project.Name != "" {
			name = ctx.Project.Name
		}
		if url == "" && ctx.Project.RepoURL != "" {
			url = ctx.Project.RepoURL
		}
		if sha == "" && ctx.Project.CommitSHA != "" &&
			ctx.Project.CommitSHA != "nogit" {
			sha = ctx.Project.CommitSHA
		}
	}
	// #562: normalize whatever the earlier tiers supplied (the hazard
	// predates detection — init records the raw remote today). An EXPLICIT
	// FLAG that fails normalization (git://, a local path) keeps the honest
	// absence — never a silent fall-through to detection behind the user's
	// back (the #557 flag-wins invariant); detection only fills a never-set
	// flag or an empty project tier.
	flagURLSet := url != ""
	if url != "" {
		url = git.NormalizeRemote(url)
	}
	if url == "" && !flagURLSet && detectedURL != "" {
		url = detectedURL
	}
	if sha == "" && detectedSHA != "" {
		sha = detectedSHA
	}
	warn := ""
	if detectedSHA != "" && sha != detectedSHA {
		warn = fmt.Sprintf(
			"report will stamp commit %s but the working tree is at %s; "+
				"the scan runs on the working tree, not the stamped commit",
			sha, detectedSHA)
		if !flaggedSHA {
			// The project tier supplied a SHA init recorded — a moved tree,
			// not a deliberate CI override. The remedy: re-run init.
			warn += " (re-run `openant init` to refresh the project SHA)"
		}
	}
	return name, url, sha, warn
}

func registerScanFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output directory (default: project scan dir or temp dir)")
	cmd.Flags().StringVarP(&scanLanguage, "language", "l", "", languages.FlagHelp())
	cmd.Flags().StringVar(&scanLevel, "level", "reachable", "Processing level: all, reachable, codeql, exploitable")
	cmd.Flags().BoolVar(&scanVerify, "verify", false, "Enable Stage 2 attacker simulation")
	cmd.Flags().BoolVar(&scanNoContext, "no-context", false, "Skip application context generation")
	cmd.Flags().BoolVar(&scanNoEnhance, "no-enhance", false, "Skip context enhancement step")
	cmd.Flags().StringVar(&scanEnhanceMode, "enhance-mode", "agentic", "Enhancement mode: agentic (thorough) or single-shot (fast)")
	cmd.Flags().BoolVar(&scanNoReport, "no-report", false, "Skip report generation")
	cmd.Flags().BoolVar(&scanSkipDynamicTest, "skip-dynamic-test", false, "Skip Docker-isolated dynamic testing (default: run dynamic tests)")
	cmd.Flags().IntVar(&scanLimit, "limit", 0, "Max units to analyze and enhance, 0 = no limit (the LLM reachability pass still reviews the full codebase)")
	cmd.Flags().StringVar(&scanLLMConfig, "llm-config", "", "Name of the llm-config in ~/.config/openant/config.json (defaults to the file's default_llm, or the built-in 'openant-default' if no config file exists).")
	cmd.Flags().IntVar(&scanWorkers, "workers", 8, "Number of parallel workers for LLM steps (default: 8)")
	cmd.Flags().IntVar(&scanBackoff, "backoff", 30, "Seconds to wait when rate-limited (default: 30)")
	cmd.Flags().BoolVar(&scanFull, "full", false, "Force full scan (rejects --incremental/--diff-base/--pr)")
	cmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Incremental against the last successful scan on this project")
	cmd.Flags().StringVar(&scanDiffBase, "diff-base", "", "Incremental mode: filter pipeline to units overlapping diff vs this ref (e.g. origin/main, HEAD~5)")
	cmd.Flags().IntVar(&scanPR, "pr", 0, "Incremental mode against a GitHub PR number (requires gh; mutex with --diff-base)")
	cmd.Flags().BoolVar(&scanStaged, "staged", false, "Incremental mode against the staged index vs HEAD (pre-commit hook usage; mutex with --diff-base/--pr)")
	cmd.Flags().StringVar(&scanDiffScope, "diff-scope", "changed_functions", "Diff scope: changed_files, changed_functions, callers")
	// #539: the repository metadata the Python CLI already accepts — a
	// bare-path scan (the documented primary usage) resolves to a nil
	// project context, so the metadata block below never fired and every
	// report carried [NOT PROVIDED] with no CLI way to supply it.
	cmd.Flags().StringVar(&scanRepoName, "repo-name", "", "Repository name (org/repo) — stamped into reports")
	cmd.Flags().StringVar(&scanRepoURL, "repo-url", "", "Repository URL — stamped into reports")
	cmd.Flags().StringVar(&scanCommitSHA, "commit-sha", "", "Commit SHA — stamped into reports")
	cmd.Flags().BoolVar(&scanLLMReachability, "llm-reachability", false, "Enable the LLM reachability review stage (Opus). Surfaces entry points and external-input sites the structural pass would miss by reviewing the full codebase before the reachability filter is applied. Off by default — enabling this incurs cost proportional to total repo size, not the filtered unit count (~one Opus call per 25 units across the whole codebase).")
	cmd.Flags().IntVar(&scanLLMReachabilityMaxCodeBytes, "llm-reachability-max-code-bytes", 1500, "Max code bytes per unit sent to the LLM reachability stage (default: 1500). Higher values (e.g. 4096, 8192) catch entry-point indicators past byte 1500 in long handlers / generated code, at proportional Opus cost increase. Only meaningful with --llm-reachability.")
	cmd.Flags().BoolVar(&scanLibraryMode, "library-mode", false, "Seed the exported public API as reachability entry points, for a library whose public API is being dropped by the structural filter. Blunt: keeps most units — prefer letting fuzz/bin/route entry points seed reachability first.")
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
		manifestOpts.staged = decision.Staged
	}
	manifestPath, err := prepareDiffManifest(repoPath, scanOutput, manifestOpts)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Check for interrupted runs in the scan directory
	if ctx != nil && scanOutput != "" {
		// #532: llm_reach joins the probe list — its checkpoints are the most
		// expensive per-pass ($10+ on a 5K-unit corpus), so a silent auto-adopt
		// on an explicit fresh start would defeat the user's choice. Records
		// classify as completed (no error arms match) and a missing/unknown
		// _summary takes PromptResume's legacy arm — same lifecycle as the
		// other phases.
		steps := []string{"enhance", "analyze", "verify", "llm_reach"}
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
	if scanLLMConfig != "" {
		pyArgs = append(pyArgs, "--llm-config", scanLLMConfig)
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
	if scanLLMReachability {
		pyArgs = append(pyArgs, "--llm-reachability")
	}
	if scanLibraryMode {
		pyArgs = append(pyArgs, "--library-mode")
	}
	if scanLLMReachabilityMaxCodeBytes != 1500 {
		pyArgs = append(pyArgs, "--llm-reachability-max-code-bytes", fmt.Sprintf("%d", scanLLMReachabilityMaxCodeBytes))
	}

	// Pass repository metadata so reports don't show [NOT PROVIDED]
	// placeholders. #539: an explicit flag wins; the project context is the
	// fallback (a bare-path scan has no project context — the flags are the
	// only way in).
	// #557: detection runs AFTER resolveScanMode (the --pr path checks
	// out the PR head in mode.go's FetchPR — scan.go:178) — hoisting this
	// above would stamp the pre-checkout SHA (the review round's ordering
	// hazard).
	detectedSHA := git.HeadSHA(repoPath)
	// #562: the origin remote, normalized (scp→https, credentials never
	// persist). The detection is informational — a non-git path or a
	// remote-less repo yields "" and the tier is skipped.
	detectedURL := git.NormalizeRemote(git.RemoteURL(repoPath))
	repoName, repoURL, commitSHA, metadataWarn := resolveRepoMetadataFull(
		scanRepoName, scanRepoURL, scanCommitSHA, ctx, detectedSHA,
		detectedURL)
	if metadataWarn != "" {
		output.PrintWarning(metadataWarn)
	}
	if scanRepoURL != "" && detectedURL != "" &&
		git.NormalizeRemote(scanRepoURL) != detectedURL {
		// #562 (the review round): print the NORMALIZED forms only — the
		// raw flag may carry credentials that must never reach a log.
		output.PrintWarning(fmt.Sprintf(
			"report will stamp repo URL %s but the origin remote is %s",
			git.NormalizeRemote(scanRepoURL), detectedURL))
	}
	if repoName != "" {
		pyArgs = append(pyArgs, "--repo-name", repoName)
	}
	if repoURL != "" {
		pyArgs = append(pyArgs, "--repo-url", repoURL)
	}
	if commitSHA != "" {
		pyArgs = append(pyArgs, "--commit-sha", commitSHA)
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
	flagsPassed := scanFull || scanIncremental || scanDiffBase != "" || scanPR > 0 || scanStaged

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
		staged:      scanStaged,
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
