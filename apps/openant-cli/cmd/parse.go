package cmd

import (
	"os"
	"strings"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var parseCmd = &cobra.Command{
	Use:   "parse [repository-path]",
	Short: "Extract code units from a repository",
	Long: `Parse extracts analyzable code units from a repository.

The output is a JSON dataset that can be fed into the analyze command.
Supports Python, JavaScript/TypeScript, Go, C/C++, Ruby, and PHP repositories.

If no repository path is given, the active project is used (see: openant init).`,
	Args: cobra.MaximumNArgs(1),
	Run:  runParse,
}

var (
	parseOutput    string
	parseLanguage  string
	parseLevel     string
	parseDiffBase  string
	parsePR        int
	parseDiffScope string
)

func init() {
	parseCmd.Flags().StringVarP(&parseOutput, "output", "o", "", "Output directory (default: project scan dir)")
	parseCmd.Flags().StringVarP(&parseLanguage, "language", "l", "", "Language: python, javascript, go, c, ruby, php, auto")
	parseCmd.Flags().StringVar(&parseLevel, "level", "all", "Processing level: all, reachable, codeql, exploitable")
	parseCmd.Flags().StringVar(&parseDiffBase, "diff-base", "", "Incremental mode: tag units overlapping diff vs this ref")
	parseCmd.Flags().IntVar(&parsePR, "pr", 0, "Incremental mode against a GitHub PR number (mutex with --diff-base)")
	parseCmd.Flags().StringVar(&parseDiffScope, "diff-scope", "changed_functions", "Diff scope: changed_files, changed_functions, callers")
}

func runParse(cmd *cobra.Command, args []string) {
	repoPath, ctx, err := resolveRepoArg(args)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if parseOutput == "" {
			parseOutput = ctx.ScanDir
		}
		if parseLanguage == "" {
			parseLanguage = ctx.Language
		}
	}
	if parseLanguage == "" {
		parseLanguage = "auto"
	}
	if parseOutput == "" {
		output.PrintError("--output is required (or use openant init to set up a project)")
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	stepOpts, err := resolveStepDiffOpts(ctx, parseDiffBase, parsePR, parseDiffScope)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}
	manifestPath, err := prepareDiffManifest(repoPath, parseOutput, stepOpts)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Construct dataset name from project metadata: org-repo-shortSHA
	var datasetName string
	if ctx != nil && ctx.Project != nil {
		slug := strings.ReplaceAll(ctx.Project.Name, "/", "-")
		if ctx.Project.CommitSHAShort != "" {
			datasetName = slug + "-" + ctx.Project.CommitSHAShort
		} else {
			datasetName = slug
		}
	}

	pyArgs := []string{"parse", repoPath, "--output", parseOutput}
	if datasetName != "" {
		pyArgs = append(pyArgs, "--name", datasetName)
	}
	if parseLanguage != "auto" {
		pyArgs = append(pyArgs, "--language", parseLanguage)
	}
	if parseLevel != "all" {
		pyArgs = append(pyArgs, "--level", parseLevel)
	}
	if manifestPath != "" {
		pyArgs = append(pyArgs, "--diff-manifest", manifestPath)
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, resolvedAPIKey())
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintParseSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
