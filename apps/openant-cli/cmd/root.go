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

// resolveAPIKeyFor returns the API key the Python subprocess should
// receive as “ANTHROPIC_API_KEY“ env, with v2-aware gating.
//
// Takes a pre-loaded “*config.Config“ so a caller that already has
// one (“requireAPIKey“) doesn't pay for a second “Load()“.
//
// Precedence:
//
//  1. “--api-key“ flag — always wins.
//  2. If the config has an “llm_providers“ section, return “""“.
//     Python reads per-provider keys from the file itself; injecting
//     the legacy “api_key“ here would override an explicit
//     “llm_providers["anthropic"].api_key=null“ and potentially
//     leak an Anthropic key to an OpenRouter-pointed provider.
//  3. Otherwise (v1-only / fresh-install path), return the legacy
//     “api_key“ field so the Python migration finds it.
func resolveAPIKeyFor(cfg *config.Config) string {
	if apiKeyFlag != "" {
		return apiKeyFlag
	}
	if cfg == nil {
		return ""
	}
	if cfg.HasV2Providers() {
		return ""
	}
	return cfg.APIKey
}

// resolvedAPIKey is the public surface that callers use when they
// don't already have a loaded “Config“. It does one “Load()“
// and delegates to :func:`resolveAPIKeyFor`. Errors loading config
// fall through to an empty string — same as the previous behavior.
func resolvedAPIKey() string {
	cfg, err := config.Load()
	if err != nil {
		// Honor the flag even when config is unreadable so an
		// emergency one-off invocation still works.
		if apiKeyFlag != "" {
			return apiKeyFlag
		}
		return ""
	}
	return resolveAPIKeyFor(cfg)
}

// requireAPIKey returns the resolved API key or exits with a helpful error
// telling the user how to configure one. Use this in commands that make
// LLM calls (enhance, analyze, verify, scan, dynamic-test).
//
// When the user has authored a v2 “llm_providers“ section, we
// trust them to have configured keys per provider and don't fail
// here: Python will surface a clear error from
// “registry.validate()“ at scan start if any of those keys are
// missing or wrong.
func requireAPIKey() string {
	cfg, _ := config.Load()
	if cfg != nil && cfg.HasV2Providers() {
		// v2 path: Python reads keys from the providers entries.
		// Honor the --api-key flag override if present, otherwise
		// stay out of the way.
		return apiKeyFlag
	}
	// Reuse the loaded cfg — don't pay for a second config.Load().
	key := resolveAPIKeyFor(cfg)
	if key != "" {
		return key
	}
	fmt.Fprintln(os.Stderr, "Error: No API key configured.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run:  openant set-api-key <your-anthropic-api-key>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Or author an `llm_providers` section in ~/.config/openant/config.json")
	fmt.Fprintln(os.Stderr, "  (see docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "You can get an Anthropic API key at https://console.anthropic.com/settings/keys")
	os.Exit(2)
	return "" // unreachable
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output raw JSON (machine-readable)")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	rootCmd.PersistentFlags().StringVar(&apiKeyFlag, "api-key", "", "LLM API key (overrides config). On v1 configs this becomes ANTHROPIC_API_KEY in the Python subprocess; on v2 configs (llm_providers section present) Python reads per-provider keys from config.json and this flag is only used as the explicit-override path.")
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
