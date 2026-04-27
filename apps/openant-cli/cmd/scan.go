package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/checkpoint"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [repository-path]",
	Short: "Scan a repository for vulnerabilities (full pipeline)",
	Long: `Scan runs the full pipeline:
  parse → app context → enhance → detect → verify → report → dynamic test

This is the recommended command for most users. It produces a complete
vulnerability report with false positive elimination.

If no repository path is given, the active project is used (see: openant init).

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
	scanNoReport    bool
	scanDynamicTest bool
	scanLimit       int
	scanModel       string
	scanWorkers     int
	scanBackoff     int
)

func init() {
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output directory (default: project scan dir or temp dir)")
	scanCmd.Flags().StringVarP(&scanLanguage, "language", "l", "", "Language: python, javascript, go, c, ruby, php, auto")
	scanCmd.Flags().StringVar(&scanLevel, "level", "reachable", "Processing level: all, reachable, codeql, exploitable")
	scanCmd.Flags().BoolVar(&scanVerify, "verify", false, "Enable Stage 2 attacker simulation")
	scanCmd.Flags().BoolVar(&scanNoContext, "no-context", false, "Skip application context generation")
	scanCmd.Flags().BoolVar(&scanNoEnhance, "no-enhance", false, "Skip context enhancement step")
	scanCmd.Flags().StringVar(&scanEnhanceMode, "enhance-mode", "agentic", "Enhancement mode: agentic (thorough) or single-shot (fast)")
	scanCmd.Flags().BoolVar(&scanNoReport, "no-report", false, "Skip report generation")
	scanCmd.Flags().BoolVar(&scanDynamicTest, "dynamic-test", false, "Enable Docker-isolated dynamic testing (off by default)")
	scanCmd.Flags().IntVar(&scanLimit, "limit", 0, "Max units to analyze (0 = no limit)")
	scanCmd.Flags().StringVar(&scanModel, "model", "opus", "Model: opus or sonnet")
	scanCmd.Flags().IntVar(&scanWorkers, "workers", 8, "Number of parallel workers for LLM steps (default: 8)")
	scanCmd.Flags().IntVar(&scanBackoff, "backoff", 30, "Seconds to wait when rate-limited (default: 30)")
}

func runScan(cmd *cobra.Command, args []string) {
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
	if scanDynamicTest {
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
		output.PrintError(err.Error())
		os.Exit(2)
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
