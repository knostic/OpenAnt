package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var generateContextCmd = &cobra.Command{
	Use:   "generate-context [repository-path]",
	Short: "Generate application security context for a repository",
	Long: `Generate analyzes a repository and produces an application_context.json
file that describes the application type, trust boundaries, intended
behaviors, and patterns that should not be flagged as vulnerabilities.

This context is automatically used by the analyze and verify commands
to reduce false positives.

If no repository path is given, the active project is used (see: openant init).

The command checks for a manual override file (OPENANT.md or OPENANT.json)
in the repository root before falling back to LLM-based generation.
Use --force to skip the manual override check.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runGenerateContext,
}

var (
	gcOutput    string
	gcForce     bool
	gcShowPrompt bool
)

func init() {
	generateContextCmd.Flags().StringVarP(&gcOutput, "output", "o", "", "Output path (default: <scan-dir>/application_context.json or <repo>/application_context.json)")
	generateContextCmd.Flags().BoolVar(&gcForce, "force", false, "Force regeneration, ignoring OPENANT.md override files")
	generateContextCmd.Flags().BoolVar(&gcShowPrompt, "show-prompt", false, "Include formatted prompt text in output")
}

func runGenerateContext(cmd *cobra.Command, args []string) {
	repoPath, ctx, err := resolveRepoArg(args)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if gcOutput == "" {
			gcOutput = ctx.scanFile("application_context.json")
		}
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Build Python CLI args
	pyArgs := []string{"generate-context", repoPath}
	if gcOutput != "" {
		pyArgs = append(pyArgs, "--output", gcOutput)
	}
	if gcForce {
		pyArgs = append(pyArgs, "--force")
	}
	if gcShowPrompt {
		pyArgs = append(pyArgs, "--show-prompt")
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, requireAPIKey())
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			printGenerateContextSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}

func printGenerateContextSummary(data map[string]any) {
	output.PrintHeader("Application Context Generated")
	if v, ok := data["application_type"].(string); ok {
		output.PrintKeyValue("Type", v)
	}
	if v, ok := data["purpose"].(string); ok {
		output.PrintKeyValue("Purpose", v)
	}
	if v, ok := data["confidence"].(float64); ok {
		output.PrintKeyValue("Confidence", fmt.Sprintf("%.0f%%", v*100))
	}
	if v, ok := data["source"].(string); ok {
		output.PrintKeyValue("Source", v)
	}
	if v, ok := data["app_context_path"].(string); ok {
		output.PrintKeyValue("Output", v)
	}
	fmt.Println()
}
