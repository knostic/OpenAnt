package cmd

import (
	"os"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var patchCmd = &cobra.Command{
	Use:   "patch [pipeline-output-path]",
	Short: "Generate and evaluate a candidate remediation for a finding",
	Long: `Patch invokes the merged Auto Patcher engine to generate a candidate
remediation for a single Finding and produce a Trust Report judging whether
that candidate should be trusted.

The Trust Report is treated as an opaque artifact: it is written under the
active scan directory but never parsed, scored, or reinterpreted.

Requires LLM_PROVIDER to be set explicitly (e.g. LLM_PROVIDER=anthropic) so
a run never silently falls back to a mock LLM. Set LLM_PROVIDER=mock only
if you intentionally want a mock run.

If no path is given, the active project's pipeline_output.json is used.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runPatch,
}

var (
	patchFindingID string
	patchRepoRoot  string
	patchOutput    string
)

func init() {
	patchCmd.Flags().StringVar(&patchFindingID, "finding-id", "", "ID of the finding to remediate (required)")
	patchCmd.Flags().StringVar(&patchRepoRoot, "repo-root", "", "Path to the target repository root (defaults to the active project's repo path)")
	patchCmd.Flags().StringVarP(&patchOutput, "output", "o", "", "Output directory (default: active scan directory)")
}

func buildPatchPyArgs(pipelineOutputPath, findingID, repoRoot, outputDir string) []string {
	pyArgs := []string{"patch", pipelineOutputPath, "--finding-id", findingID}
	if repoRoot != "" {
		pyArgs = append(pyArgs, "--repo-root", repoRoot)
	}
	if outputDir != "" {
		pyArgs = append(pyArgs, "--output", outputDir)
	}
	return pyArgs
}

func runPatch(cmd *cobra.Command, args []string) {
	if patchFindingID == "" {
		output.PrintError("openant patch requires --finding-id <finding-id>")
		os.Exit(2)
	}

	pipelineOutputPath, ctx, err := resolveFileArg(args, "pipeline_output.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if _, err := os.Stat(pipelineOutputPath); err != nil {
		output.PrintError("pipeline_output.json not found. Run 'openant build-output' first.")
		os.Exit(2)
	}

	outputDir := patchOutput
	if outputDir == "" && ctx != nil {
		outputDir = ctx.ScanDir
	}

	repoRoot := patchRepoRoot
	if repoRoot == "" && ctx != nil {
		repoRoot = ctx.RepoPath
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pyArgs := buildPatchPyArgs(pipelineOutputPath, patchFindingID, repoRoot, outputDir)

	// Auto Patcher's LLM calls are independently configured via LLM_PROVIDER /
	// OPENAI_API_KEY / ANTHROPIC_API_KEY -- never OpenAnt's own --api-key or
	// llm_providers config, so no API key is forwarded here.
	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, "")
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
			output.PrintPatchSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
