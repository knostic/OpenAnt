package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/checkpoint"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var enhanceCmd = &cobra.Command{
	Use:   "enhance [dataset-path]",
	Short: "Enhance a dataset with security context",
	Long: `Enhance adds security context to each code unit in a parsed dataset.

Agentic mode (default) uses tool-use to examine call paths and classify
each unit's security relevance. Single-shot mode is faster and cheaper
but less thorough.

If no dataset path is given, the active project's scan directory is used.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runEnhance,
}

var (
	enhanceOutput         string
	enhanceAnalyzerOutput string
	enhanceRepoPath       string
	enhanceMode           string
	enhanceCheckpoint     string
	enhanceWorkers        int
	enhanceBackoff        int
)

func init() {
	enhanceCmd.Flags().StringVarP(&enhanceOutput, "output", "o", "", "Output path for enhanced dataset")
	enhanceCmd.Flags().StringVar(&enhanceAnalyzerOutput, "analyzer-output", "", "Path to analyzer_output.json (required for agentic mode)")
	enhanceCmd.Flags().StringVar(&enhanceRepoPath, "repo-path", "", "Path to the repository (required for agentic mode)")
	enhanceCmd.Flags().StringVar(&enhanceMode, "mode", "agentic", "Enhancement mode: agentic (thorough) or single-shot (fast)")
	enhanceCmd.Flags().StringVar(&enhanceCheckpoint, "checkpoint", "", "Path to save/resume checkpoint (agentic mode)")
	enhanceCmd.Flags().IntVar(&enhanceWorkers, "workers", 8, "Number of parallel workers for LLM steps (default: 8)")
	enhanceCmd.Flags().IntVar(&enhanceBackoff, "backoff", 30, "Seconds to wait when rate-limited (default: 30)")
}

func runEnhance(cmd *cobra.Command, args []string) {
	datasetPath, ctx, err := resolveFileArg(args, "dataset.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if enhanceOutput == "" {
			enhanceOutput = ctx.scanFile("dataset_enhanced.json")
		}
		if enhanceAnalyzerOutput == "" {
			enhanceAnalyzerOutput = ctx.scanFile("analyzer_output.json")
		}
		if enhanceRepoPath == "" {
			enhanceRepoPath = ctx.RepoPath
		}
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Auto-detect checkpoints from a previous interrupted run
	if enhanceCheckpoint == "" && ctx != nil {
		if cpInfo := checkpoint.DetectViaPython(rt.Path, ctx.ScanDir, "enhance"); cpInfo != nil {
			if checkpoint.PromptResume(cpInfo, "enhance", quiet) {
				enhanceCheckpoint = cpInfo.Dir
			} else {
				// User chose fresh start — remove old checkpoints
				_ = checkpoint.Clean(cpInfo.Dir)
			}
		}
	}

	pyArgs := []string{"enhance", datasetPath}
	if enhanceOutput != "" {
		pyArgs = append(pyArgs, "--output", enhanceOutput)
	}
	if enhanceAnalyzerOutput != "" {
		pyArgs = append(pyArgs, "--analyzer-output", enhanceAnalyzerOutput)
	}
	if enhanceRepoPath != "" {
		pyArgs = append(pyArgs, "--repo-path", enhanceRepoPath)
	}
	if enhanceMode != "agentic" {
		pyArgs = append(pyArgs, "--mode", enhanceMode)
	}
	if enhanceCheckpoint != "" {
		pyArgs = append(pyArgs, "--checkpoint", enhanceCheckpoint)
	}
	if enhanceWorkers != 8 {
		pyArgs = append(pyArgs, "--workers", fmt.Sprintf("%d", enhanceWorkers))
	}
	if enhanceBackoff != 30 {
		pyArgs = append(pyArgs, "--backoff", fmt.Sprintf("%d", enhanceBackoff))
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
			output.PrintEnhanceSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
