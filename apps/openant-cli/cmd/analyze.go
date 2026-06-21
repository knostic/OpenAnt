package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/checkpoint"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [dataset-path]",
	Short: "Run vulnerability analysis on parsed data",
	Long: `Analyze runs Claude-powered Stage 1 vulnerability detection on a parsed dataset.

With --verify, it chains into Stage 2 attacker simulation automatically.
For standalone Stage 2, use the verify command instead.

If no dataset path is given, the active project's enhanced dataset is used.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runAnalyze,
}

var (
	analyzeOutput         string
	analyzeVerify         bool
	analyzeAnalyzerOutput string
	analyzeAppContext     string
	analyzeRepoPath       string
	analyzeExploitOnly    bool
	analyzeExploitAll     bool
	analyzeLimit          int
	analyzeLLMConfig      string
	analyzeWorkers        int
	analyzeCheckpoint     string
	analyzeBackoff        int
)

func init() {
	analyzeCmd.Flags().StringVarP(&analyzeOutput, "output", "o", "", "Output directory")
	analyzeCmd.Flags().BoolVar(&analyzeVerify, "verify", false, "Chain into Stage 2 attacker simulation after detection")
	analyzeCmd.Flags().StringVar(&analyzeAnalyzerOutput, "analyzer-output", "", "Path to analyzer_output.json (for Stage 2)")
	analyzeCmd.Flags().StringVar(&analyzeAppContext, "app-context", "", "Path to application_context.json")
	analyzeCmd.Flags().StringVar(&analyzeRepoPath, "repo-path", "", "Path to the repository (for context correction)")
	analyzeCmd.Flags().BoolVar(&analyzeExploitAll, "exploitable-all", false, "Analyze units classified as exploitable or vulnerable_internal (safer, compensates for parser gaps)")
	analyzeCmd.Flags().BoolVar(&analyzeExploitOnly, "exploitable-only", false, "Analyze only units classified as exploitable (strict, use after parser entry point fixes)")
	analyzeCmd.MarkFlagsMutuallyExclusive("exploitable-all", "exploitable-only")
	analyzeCmd.Flags().IntVar(&analyzeLimit, "limit", 0, "Max units to analyze (0 = no limit)")
	analyzeCmd.Flags().StringVar(&analyzeLLMConfig, "llm-config", "", "Name of the llm-config in ~/.config/openant/config.json (defaults to the file's default_llm, or the built-in 'openant-default' if no config file exists).")
	analyzeCmd.Flags().IntVar(&analyzeWorkers, "workers", 8, "Number of parallel workers for LLM steps (default: 8)")
	analyzeCmd.Flags().StringVar(&analyzeCheckpoint, "checkpoint", "", "Path to checkpoint directory for save/resume")
	analyzeCmd.Flags().IntVar(&analyzeBackoff, "backoff", 30, "Seconds to wait when rate-limited (default: 30)")
}

// buildAnalyzePyArgs assembles the argv passed to the Python `openant analyze`
// subprocess. Extracted as a pure function (mirrors buildParsePyArgs) so the
// flag-forwarding contract — including the exploitable filter parity with the
// Python backend — is unit-testable without spawning Python.
func buildAnalyzePyArgs(
	datasetPath, output string,
	verify bool,
	analyzerOutput, appContext, repoPath string,
	exploitOnly, exploitAll bool,
	limit int,
	llmConfig string,
	workers int,
	checkpoint string,
	backoff int,
) []string {
	pyArgs := []string{"analyze", datasetPath, "--output", output}
	if verify {
		pyArgs = append(pyArgs, "--verify")
	}
	if analyzerOutput != "" {
		pyArgs = append(pyArgs, "--analyzer-output", analyzerOutput)
	}
	if appContext != "" {
		pyArgs = append(pyArgs, "--app-context", appContext)
	}
	if repoPath != "" {
		pyArgs = append(pyArgs, "--repo-path", repoPath)
	}
	if exploitAll {
		pyArgs = append(pyArgs, "--exploitable-all")
	}
	if exploitOnly {
		pyArgs = append(pyArgs, "--exploitable-only")
	}
	if limit > 0 {
		pyArgs = append(pyArgs, "--limit", fmt.Sprintf("%d", limit))
	}
	if llmConfig != "" {
		pyArgs = append(pyArgs, "--llm-config", llmConfig)
	}
	if workers != 8 {
		pyArgs = append(pyArgs, "--workers", fmt.Sprintf("%d", workers))
	}
	if checkpoint != "" {
		pyArgs = append(pyArgs, "--checkpoint", checkpoint)
	}
	if backoff != 30 {
		pyArgs = append(pyArgs, "--backoff", fmt.Sprintf("%d", backoff))
	}
	return pyArgs
}

func runAnalyze(cmd *cobra.Command, args []string) {
	datasetPath, ctx, err := resolveFileArg(args, "dataset_enhanced.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if analyzeOutput == "" {
			analyzeOutput = ctx.ScanDir
		}
		if analyzeAnalyzerOutput == "" {
			analyzeAnalyzerOutput = ctx.scanFile("analyzer_output.json")
		}
		if analyzeRepoPath == "" {
			analyzeRepoPath = ctx.RepoPath
		}
	}
	if analyzeOutput == "" {
		output.PrintError("--output is required (or use openant init to set up a project)")
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Auto-detect checkpoints from a previous interrupted run
	if analyzeCheckpoint == "" && ctx != nil {
		if cpInfo := checkpoint.DetectViaPython(rt.Path, ctx.ScanDir, "analyze"); cpInfo != nil {
			if checkpoint.PromptResume(cpInfo, "analyze", quiet) {
				analyzeCheckpoint = cpInfo.Dir
			} else {
				_ = checkpoint.Clean(cpInfo.Dir)
			}
		}
	}

	pyArgs := buildAnalyzePyArgs(
		datasetPath, analyzeOutput, analyzeVerify,
		analyzeAnalyzerOutput, analyzeAppContext, analyzeRepoPath,
		analyzeExploitOnly, analyzeExploitAll, analyzeLimit,
		analyzeLLMConfig, analyzeWorkers, analyzeCheckpoint, analyzeBackoff,
	)

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
			output.PrintAnalyzeSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
