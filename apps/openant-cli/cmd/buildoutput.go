package cmd

import (
	"os"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var buildOutputCmd = &cobra.Command{
	Use:   "build-output [results-path]",
	Short: "Build pipeline_output.json from verified results",
	Long: `Build-output assembles findings from the verify step into the bridge
format (pipeline_output.json) consumed by the report and dynamic-test commands.

This step is typically run automatically inside the scan command. It is
only needed when running the pipeline step-by-step.

If no results path is given, the active project's results_verified.json is used.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runBuildOutput,
}

var (
	buildOutputPath            string
	buildOutputRepoName        string
	buildOutputRepoURL         string
	buildOutputLanguage        string
	buildOutputCommitSHA       string
	buildOutputAppType         string
	buildOutputProcessingLevel string
)

func init() {
	buildOutputCmd.Flags().StringVarP(&buildOutputPath, "output", "o", "", "Output path for pipeline_output.json")
	buildOutputCmd.Flags().StringVar(&buildOutputRepoName, "repo-name", "", "Repository name (e.g. owner/repo)")
	buildOutputCmd.Flags().StringVar(&buildOutputRepoURL, "repo-url", "", "Repository URL")
	buildOutputCmd.Flags().StringVar(&buildOutputLanguage, "language", "", "Primary language")
	buildOutputCmd.Flags().StringVar(&buildOutputCommitSHA, "commit-sha", "", "Commit SHA")
	buildOutputCmd.Flags().StringVar(&buildOutputAppType, "app-type", "", "Application type (default: web_app)")
	buildOutputCmd.Flags().StringVar(&buildOutputProcessingLevel, "processing-level", "", "Processing level used")
}

func runBuildOutput(cmd *cobra.Command, args []string) {
	resultsPath, ctx, err := resolveFileArg(args, "results_verified.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if buildOutputPath == "" {
			buildOutputPath = ctx.scanFile("pipeline_output.json")
		}
		if buildOutputRepoName == "" {
			buildOutputRepoName = ctx.Project.Name
		}
		if buildOutputRepoURL == "" && ctx.Project.RepoURL != "" {
			buildOutputRepoURL = ctx.Project.RepoURL
		}
		if buildOutputLanguage == "" {
			buildOutputLanguage = ctx.Language
		}
		if buildOutputCommitSHA == "" {
			buildOutputCommitSHA = ctx.Project.CommitSHA
		}
	}
	if buildOutputPath == "" {
		output.PrintError("--output is required (or use openant init to set up a project)")
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pyArgs := []string{"build-output", resultsPath, "--output", buildOutputPath}
	if buildOutputRepoName != "" {
		pyArgs = append(pyArgs, "--repo-name", buildOutputRepoName)
	}
	if buildOutputRepoURL != "" {
		pyArgs = append(pyArgs, "--repo-url", buildOutputRepoURL)
	}
	if buildOutputLanguage != "" {
		pyArgs = append(pyArgs, "--language", buildOutputLanguage)
	}
	if buildOutputCommitSHA != "" {
		pyArgs = append(pyArgs, "--commit-sha", buildOutputCommitSHA)
	}
	if buildOutputAppType != "" {
		pyArgs = append(pyArgs, "--app-type", buildOutputAppType)
	}
	if buildOutputProcessingLevel != "" {
		pyArgs = append(pyArgs, "--processing-level", buildOutputProcessingLevel)
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, resolvedAPIKey(), nil)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintBuildOutputSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
