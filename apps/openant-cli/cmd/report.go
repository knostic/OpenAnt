package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/knostic/open-ant-cli/internal/report"
	isatty "github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report [results-path]",
	Short: "Generate reports from analysis results",
	Long: `Report generates reports from analysis results or pipeline output.

Formats:
  disclosure   Per-vulnerability disclosure documents (default, uses LLM)
  summary      Narrative security overview (uses LLM)
  html         Interactive HTML report with charts and filters
  csv          Spreadsheet export of all findings

If no results path is given, the active project's results_verified.json is used.
Python owns default output paths — you only need -o to override.

Examples:
  openant report -p myproject
  openant report -p myproject -f summary
  openant report results.json -f html -o report.html --dataset dataset.json`,
	Args: cobra.MaximumNArgs(1),
	Run:  runReport,
}

var (
	reportOutput         string
	reportDataset        string
	reportFormat         string
	reportPipelineOutput string
	reportRepoName       string
	reportExtraDest      string
)

func init() {
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Output path (default: derived from format)")
	reportCmd.Flags().StringVar(&reportDataset, "dataset", "", "Path to dataset JSON (for html/csv)")
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "", "Report format: disclosure, summary, html, csv")
	reportCmd.Flags().StringVar(&reportPipelineOutput, "pipeline-output", "", "Path to pipeline_output.json (for summary/disclosure)")
	reportCmd.Flags().StringVar(&reportRepoName, "repo-name", "", "Repository name (used when auto-building pipeline_output)")
	reportCmd.Flags().StringVar(&reportExtraDest, "copy-to", "", "Copy reports to an additional location")
}

// isInteractive returns true if stdin is a terminal and we're not in quiet mode.
func isInteractive() bool {
	return !quiet && isatty.IsTerminal(os.Stdin.Fd())
}

func runReport(cmd *cobra.Command, args []string) {
	resultsPath, ctx, err := resolveFileArg(args, "results_verified.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults for pipeline-output, repo-name, dataset
	if ctx != nil {
		if reportPipelineOutput == "" {
			candidate := ctx.scanFile("pipeline_output.json")
			if _, err := os.Stat(candidate); err == nil {
				reportPipelineOutput = candidate
			}
		}
		if reportRepoName == "" {
			reportRepoName = ctx.Project.Name
		}
		if reportDataset == "" {
			reportDataset = ctx.scanFile("dataset_enhanced.json")
		}
	}

	// Check prerequisite steps before generating reports
	if ctx != nil {
		yellow := color.New(color.FgYellow, color.Bold)

		// Check if build-output has been run (needed for summary/disclosure and dynamic-test)
		poPath := ctx.scanFile("pipeline_output.json")
		if _, err := os.Stat(poPath); err != nil {
			if isInteractive() {
				yellow.Fprintln(os.Stderr, "pipeline_output.json not found — 'openant build-output' hasn't been run yet.")
				fmt.Fprint(os.Stderr, "Continue without it? [Y/n] ")
				var answer string
				fmt.Scanln(&answer)
				answer = strings.TrimSpace(strings.ToLower(answer))
				if answer == "n" || answer == "no" {
					fmt.Fprintln(os.Stderr, "Run 'openant build-output' first, then re-run report.")
					os.Exit(0)
				}
			} else {
				yellow.Fprintln(os.Stderr, "Warning: pipeline_output.json not found — summary/disclosure reports will not be available.")
			}
		}

		// Check if dynamic tests have been run
		dtPath := ctx.scanFile("dynamic_test_results.json")
		if _, err := os.Stat(dtPath); err != nil {
			if isInteractive() {
				yellow.Fprintln(os.Stderr, "Dynamic tests haven't been run yet.")
				fmt.Fprint(os.Stderr, "Continue without dynamic test results? [Y/n] ")
				var answer string
				fmt.Scanln(&answer)
				answer = strings.TrimSpace(strings.ToLower(answer))
				if answer == "n" || answer == "no" {
					fmt.Fprintln(os.Stderr, "Run 'openant dynamic-test' first, then re-run report.")
					os.Exit(0)
				}
			} else {
				yellow.Fprintln(os.Stderr, "Warning: dynamic tests haven't been run — reports will not include dynamic test results.")
			}
		}
	}

	// Determine formats to generate
	formatFlagSet := cmd.Flags().Changed("format")
	formats := []string{}

	if formatFlagSet {
		// User explicitly provided -f, use it directly
		formats = []string{reportFormat}
	} else if isInteractive() {
		// Interactive: show format picker
		selected, err := promptFormats()
		if err != nil {
			output.PrintError(err.Error())
			os.Exit(2)
		}
		if len(selected) == 0 {
			output.PrintError("No formats selected")
			os.Exit(2)
		}
		formats = selected
	} else {
		// Non-interactive, no flag: use default
		formats = []string{"disclosure"}
	}

	// Check if any selected format requires pipeline_output.json
	needsPipelineOutput := false
	for _, f := range formats {
		if f == "summary" || f == "disclosure" {
			needsPipelineOutput = true
			break
		}
	}
	if needsPipelineOutput && reportPipelineOutput == "" {
		output.PrintError("It seems like you haven't run 'openant build-output'. You must run it first.")
		os.Exit(2)
	}

	// Prompt for extra output location (interactive only, unless --copy-to given)
	scanDir := ""
	if ctx != nil {
		scanDir = ctx.ScanDir
	}
	extraDest := reportExtraDest
	if extraDest == "" && !formatFlagSet && isInteractive() {
		extraDest, err = promptExtraLocation(scanDir)
		if err != nil {
			output.PrintError(err.Error())
			os.Exit(2)
		}
	}

	// Ensure Python runtime
	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Run each selected format
	exitCode := 0
	var allResults []map[string]any

	for _, fmt := range formats {
		if fmt == "html" {
			// HTML reports use the Go renderer
			outputPath := reportOutput
			if outputPath == "" {
				// Derive default: same dir as results, in final-reports/
				resultsDir := filepath.Dir(resultsPath)
				outputPath = filepath.Join(resultsDir, "final-reports", "report.html")
			}

			reskinPath := filepath.Join(filepath.Dir(outputPath), "report-reskin.html")
			if err := runHTMLReport(rt, resultsPath, outputPath); err != nil {
				output.PrintError("html: " + err.Error())
				exitCode = 2
				continue
			}

			data := map[string]any{
				"output_path": outputPath,
				"reskin_path": reskinPath,
				"format":      "html",
			}
			if !jsonOutput {
				output.PrintReportSummary(data)
			}
			allResults = append(allResults, data)
		} else {
			// Other formats delegate to Python
			pyArgs := buildReportArgs(resultsPath, fmt)

			result, err := python.Invoke(rt.Path, pyArgs, "", quiet, resolvedAPIKey())
			if err != nil {
				output.PrintError(fmt + ": " + err.Error())
				exitCode = 2
				continue
			}

			if result.ExitCode != 0 {
				exitCode = result.ExitCode
			}

			if jsonOutput {
				output.PrintJSON(result.Envelope)
			} else if result.Envelope.Status == "success" {
				if data, ok := result.Envelope.Data.(map[string]any); ok {
					output.PrintReportSummary(data)
					allResults = append(allResults, data)
				}
			} else {
				output.PrintErrors(result.Envelope.Errors)
			}
		}
	}

	// Copy to extra location if requested
	if extraDest != "" && len(allResults) > 0 {
		copyReportsToExtra(allResults, extraDest)
	}

	os.Exit(exitCode)
}

// promptFormats shows an interactive multi-select with spacebar toggle.
func promptFormats() ([]string, error) {
	var selected []string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select report formats").
				Options(
					huh.NewOption("Disclosure docs — per-vulnerability reports for responsible disclosure ($)", "disclosure").Selected(true),
					huh.NewOption("Summary — narrative security overview written by AI ($)", "summary"),
					huh.NewOption("HTML — interactive report with charts and filters", "html"),
					huh.NewOption("CSV — spreadsheet export of all findings", "csv"),
				).
				Value(&selected),
		),
	)

	err := form.Run()
	if err != nil {
		return nil, err
	}

	return selected, nil
}

// promptExtraLocation asks the user for an optional extra output directory.
func promptExtraLocation(scanDir string) (string, error) {
	var dest string

	title := "Copy reports to additional location?"
	if scanDir != "" {
		title = fmt.Sprintf("Reports will be saved to %s/final-reports/\nCopy to additional location?", scanDir)
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(title).
				Prompt("> ").
				Placeholder("enter to skip").
				Value(&dest),
		),
	)

	err := form.Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(dest), nil
}

// runHTMLReport generates an HTML report using the Go renderer.
// It calls Python's report-data subcommand to get pre-computed data,
// then renders the HTML template.
func runHTMLReport(rt *python.RuntimeInfo, resultsPath string, outputPath string) error {
	// 1. Call Python report-data to get pre-computed JSON
	pyArgs := []string{"report-data", resultsPath}
	if reportDataset != "" {
		pyArgs = append(pyArgs, "--dataset", reportDataset)
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, resolvedAPIKey())
	if err != nil {
		return fmt.Errorf("report-data failed: %w", err)
	}
	if result.Envelope.Status != "success" {
		msg := "report-data returned error"
		if len(result.Envelope.Errors) > 0 {
			msg = result.Envelope.Errors[0]
		}
		return fmt.Errorf("%s", msg)
	}

	// 2. Marshal data back to JSON, then unmarshal into our struct
	dataBytes, err := json.Marshal(result.Envelope.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal report data: %w", err)
	}

	var reportData report.ReportData
	if err := json.Unmarshal(dataBytes, &reportData); err != nil {
		return fmt.Errorf("failed to parse report data: %w", err)
	}

	// 3. Render HTML (original dark theme)
	if err := report.GenerateOverview(reportData, outputPath); err != nil {
		return fmt.Errorf("failed to render HTML: %w", err)
	}

	// 4. Render reskin HTML (Knostic light theme) alongside the original
	reskinPath := filepath.Join(filepath.Dir(outputPath), "report-reskin.html")
	if err := report.GenerateReskin(reportData, reskinPath); err != nil {
		return fmt.Errorf("failed to render reskin HTML: %w", err)
	}

	return nil
}

// buildReportArgs constructs the Python CLI arguments for a single format.
func buildReportArgs(resultsPath string, format string) []string {
	pyArgs := []string{"report", resultsPath, "--format", format}

	// Only pass --output if user explicitly set it
	if reportOutput != "" {
		pyArgs = append(pyArgs, "--output", reportOutput)
	}
	if reportDataset != "" {
		pyArgs = append(pyArgs, "--dataset", reportDataset)
	}
	if reportPipelineOutput != "" {
		pyArgs = append(pyArgs, "--pipeline-output", reportPipelineOutput)
	}
	if reportRepoName != "" {
		pyArgs = append(pyArgs, "--repo-name", reportRepoName)
	}

	return pyArgs
}

// copyReportsToExtra copies generated report files/dirs to the extra destination.
func copyReportsToExtra(results []map[string]any, dest string) {
	cyan := color.New(color.FgCyan)

	// Ensure dest directory exists
	if err := os.MkdirAll(dest, 0o755); err != nil {
		output.PrintError("Failed to create " + dest + ": " + err.Error())
		return
	}

	for _, data := range results {
		srcPath, ok := data["output_path"].(string)
		if !ok || srcPath == "" {
			continue
		}

		info, err := os.Stat(srcPath)
		if err != nil {
			output.PrintError("Cannot access " + srcPath + ": " + err.Error())
			continue
		}

		if info.IsDir() {
			// Copy directory recursively
			destDir := filepath.Join(dest, filepath.Base(srcPath))
			if err := copyDir(srcPath, destDir); err != nil {
				output.PrintError("Failed to copy " + srcPath + ": " + err.Error())
				continue
			}
			cyan.Printf("  Copied: ")
			fmt.Println(destDir)
		} else {
			// Copy single file
			destFile := filepath.Join(dest, filepath.Base(srcPath))
			if err := copyFile(srcPath, destFile); err != nil {
				output.PrintError("Failed to copy " + srcPath + ": " + err.Error())
				continue
			}
			cyan.Printf("  Copied: ")
			fmt.Println(destFile)
		}
	}
}

// copyFile copies a single file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// copyDir recursively copies a directory.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(destPath, 0o755)
		}
		return copyFile(path, destPath)
	})
}
