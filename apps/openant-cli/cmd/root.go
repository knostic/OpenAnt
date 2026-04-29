// Package cmd implements the Cobra CLI commands for OpenAnt.
package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags.
var version = "dev"

// Persistent flags shared across commands.
var (
	jsonOutput  bool
	quiet       bool
	apiKeyFlag  string
	projectFlag string
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "openant",
	Short: "LLM-powered static analysis security testing",
	Long: `OpenAnt is a two-stage SAST tool that uses Claude to find real vulnerabilities
in Python, JavaScript, Go, and C/C++ codebases.

Stage 1: Detect potential vulnerabilities via code analysis
Stage 2: Simulate an attacker to eliminate false positives

Commands:
  scan          Full pipeline: parse → enhance → detect → verify → report
  diff          Scan only code changed vs a base ref or GitHub PR
  parse         Extract code units from a repository
  enhance       Add security context to a parsed dataset
  analyze       Run Stage 1 vulnerability detection
  verify        Run Stage 2 attacker simulation
  build-output  Assemble pipeline_output.json from verified results
  dynamic-test  Docker-isolated exploit testing
  report        Generate reports from analysis results
  config        Manage CLI configuration (API key, etc.)`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

// resolvedAPIKey returns the API key resolved from flag > config file.
func resolvedAPIKey() string {
	return config.ResolveAPIKey(apiKeyFlag)
}

// requireAPIKey returns the resolved API key or exits with a helpful error
// telling the user how to configure one. Use this in commands that make
// LLM calls (enhance, analyze, verify, scan, dynamic-test).
func requireAPIKey() string {
	key := resolvedAPIKey()
	if key != "" {
		return key
	}
	fmt.Fprintln(os.Stderr, "Error: No API key configured.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run:  openant set-api-key <your-anthropic-api-key>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "You can get an API key at https://console.anthropic.com/settings/keys")
	os.Exit(2)
	return "" // unreachable
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output raw JSON (machine-readable)")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	rootCmd.PersistentFlags().StringVar(&apiKeyFlag, "api-key", "", "Anthropic API key (overrides config)")
	rootCmd.PersistentFlags().StringVarP(&projectFlag, "project", "p", "", "Project to use (overrides active project, e.g. grafana/grafana)")

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(parseCmd)
	rootCmd.AddCommand(enhanceCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(buildOutputCmd)
	rootCmd.AddCommand(dynamicTestCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(setAPIKeyCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(versionCmd)
}
