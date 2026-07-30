package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var patchCmd = &cobra.Command{
	Use:   "patch [pipeline-output-path]",
	Short: "Generate and evaluate a candidate remediation for a finding or a known CVE",
	Long: `Patch invokes the merged Auto Patcher engine to generate a candidate
remediation and produce a Trust Report judging whether that candidate should
be trusted. Two entry points converge on the same pipeline and the same
Trust Report format:

  openant patch --finding-id <id>                       remediate an OpenAnt-detected Finding
  openant patch --cve CVE-YYYY-NNNN --repo-root <path>   remediate a known CVE advisory

The Trust Report is treated as an opaque artifact: it is written under the
active scan directory but never parsed, scored, or reinterpreted. A
CVE-sourced report additionally discloses that its input was a public
advisory, not an OpenAnt Finding, and that advisory claims are not
repository-verified facts.

Requires LLM_PROVIDER to be set explicitly (e.g. LLM_PROVIDER=anthropic) so
a run never silently falls back to a mock LLM. Set LLM_PROVIDER=mock only
if you intentionally want a mock run.

If no path is given for --finding-id, the active project's
pipeline_output.json is used. --cve requires --repo-root, which defaults to
the active project's repo path when not given explicitly.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runPatch,
}

var (
	patchFindingID string
	patchCVE       string
	patchRepoRoot  string
	patchOutput    string
)

func init() {
	patchCmd.Flags().StringVar(&patchFindingID, "finding-id", "", "ID of the finding to remediate (mutually exclusive with --cve)")
	patchCmd.Flags().StringVar(&patchCVE, "cve", "", "CVE identifier to fetch from NVD and remediate (mutually exclusive with --finding-id)")
	patchCmd.Flags().StringVar(&patchRepoRoot, "repo-root", "", "Path to the target repository root (defaults to the active project's repo path; required for --cve)")
	patchCmd.Flags().StringVarP(&patchOutput, "output", "o", "", "Output directory (default: active scan directory)")
}

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

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

func buildPatchCVEPyArgs(cve, repoRoot, outputDir string) []string {
	pyArgs := []string{"patch", "--cve", cve, "--repo-root", repoRoot}
	if outputDir != "" {
		pyArgs = append(pyArgs, "--output", outputDir)
	}
	return pyArgs
}

func runPatch(cmd *cobra.Command, args []string) {
	if patchFindingID == "" && patchCVE == "" {
		output.PrintError("openant patch requires either --finding-id <id> or --cve <CVE-ID>")
		os.Exit(2)
	}
	if patchFindingID != "" && patchCVE != "" {
		output.PrintError("--finding-id and --cve are mutually exclusive; pass exactly one")
		os.Exit(2)
	}

	if patchCVE != "" {
		runPatchCVE(args)
		return
	}
	runPatchFinding(args)
}

func runPatchFinding(args []string) {
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

	// Resolved before ensurePython() so a missing/declined provider fails
	// fast, without paying for a venv/dependency bootstrap first.
	llmEnv, err := resolvePatchLLMEnv()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pyArgs := buildPatchPyArgs(pipelineOutputPath, patchFindingID, repoRoot, outputDir)

	// Auto Patcher's LLM calls are independently configured via LLM_PROVIDER /
	// OPENAI_API_KEY / ANTHROPIC_API_KEY -- never OpenAnt's own --api-key or
	// llm_providers config, so no legacy API key is forwarded here. llmEnv
	// carries only what resolvePatchLLMEnv resolved (explicit env passthrough
	// needs nothing added; interactive selection adds LLM_PROVIDER + the
	// chosen provider's key) into the Python subprocess's environment only.
	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, "", llmEnv)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	printPatchResultAndExit(result)
}

func runPatchCVE(args []string) {
	if len(args) > 0 {
		output.PrintError("openant patch --cve does not take a pipeline-output-path argument")
		os.Exit(2)
	}
	if !cveIDPattern.MatchString(patchCVE) {
		output.PrintError(fmt.Sprintf("invalid CVE identifier %q: expected format CVE-YYYY-NNNN", patchCVE))
		os.Exit(2)
	}

	// resolveProject() is optional here (unlike Finding mode, where a
	// missing active project with no positional arg is a hard error) --
	// it's only ever used as a convenience default for --repo-root/--output,
	// never required on its own.
	ctx, ctxErr := resolveProject()

	repoRoot := patchRepoRoot
	if repoRoot == "" && ctxErr == nil {
		repoRoot = ctx.RepoPath
	}
	if repoRoot == "" {
		output.PrintError("--cve requires --repo-root <path> (no active project to default to)")
		os.Exit(2)
	}
	if _, err := os.Stat(repoRoot); err != nil {
		output.PrintError(fmt.Sprintf("--repo-root does not exist: %s", repoRoot))
		os.Exit(2)
	}

	outputDir := patchOutput
	if outputDir == "" && ctxErr == nil {
		outputDir = ctx.ScanDir
	}

	// Resolved before ensurePython() so a missing/declined provider fails
	// fast, without paying for a venv/dependency bootstrap first.
	llmEnv, err := resolvePatchLLMEnv()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pyArgs := buildPatchCVEPyArgs(patchCVE, repoRoot, outputDir)

	// Same deliberate omission as Finding mode: Auto Patcher's LLM calls are
	// configured independently via LLM_PROVIDER / OPENAI_API_KEY /
	// ANTHROPIC_API_KEY, never OpenAnt's own --api-key. llmEnv carries only
	// what resolvePatchLLMEnv resolved into the Python subprocess's
	// environment only.
	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, "", llmEnv)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	printPatchResultAndExit(result)
}

func printPatchResultAndExit(result *python.InvokeResult) {
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
