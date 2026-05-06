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
	Long: `OpenAnt is a two-stage SAST tool that uses LLMs to find real vulnerabilities
in Python, JavaScript, Go, and C/C++ codebases.

Works with Anthropic's API or any compatible local AI server (llama-swap,
llama-server, vLLM, LM Studio, etc.).

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
  config        Manage CLI configuration (API key, endpoint, models)`,
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
	fmt.Fprintln(os.Stderr, "Run:  openant config set api-key")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "For local AI (llama-swap, llama-server, etc.), any value works:")
	fmt.Fprintln(os.Stderr, "  openant config set api-key       (enter 'not-needed')")
	fmt.Fprintln(os.Stderr, "  openant config set base-url      (enter your server URL)")
	os.Exit(2)
	return "" // unreachable
}

// llmEnv builds the environment variable map passed to the Python subprocess.
// It injects the API key, base URL, and model names from the config file
// so the Python core can connect to a local AI server or Anthropic's API.
func llmEnv() map[string]string {
	env := map[string]string{}

	key := resolvedAPIKey()
	if key != "" {
		env["ANTHROPIC_API_KEY"] = key
	}

	cfg, err := config.Load()
	if err != nil {
		return env
	}

	if cfg.BaseURL != "" {
		env["ANTHROPIC_BASE_URL"] = cfg.BaseURL
	}
	if cfg.OpusModel != "" {
		env["OPENANT_OPUS_MODEL"] = cfg.OpusModel
	}
	if cfg.SonnetModel != "" {
		env["OPENANT_SONNET_MODEL"] = cfg.SonnetModel
	}
	if cfg.VerifySSL != nil && !*cfg.VerifySSL {
		env["OPENANT_VERIFY_SSL"] = "false"
	}

	return env
}

// llmEnvRequired is like llmEnv but exits if no API key is configured.
func llmEnvRequired() map[string]string {
	requireAPIKey() // exits if missing
	return llmEnv()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output raw JSON (machine-readable)")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	rootCmd.PersistentFlags().StringVar(&apiKeyFlag, "api-key", "", "LLM API key (overrides config)")
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
