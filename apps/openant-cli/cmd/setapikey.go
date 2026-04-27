package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

var anthropicAPIURL = "https://api.anthropic.com/v1/messages"

func validateAPIKey(key string) error {
	body := strings.NewReader(`{"model":"claude-haiku-4-5-20251001","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequest("POST", anthropicAPIURL, body)
	if err != nil {
		return fmt.Errorf("failed to build validation request: %w", err)
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach Anthropic API: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("Anthropic rejected the key (HTTP 401). Double-check it at https://console.anthropic.com/settings/keys")
	}
	return nil
}

var setAPIKeyCmd = &cobra.Command{
	Use:   "set-api-key <key>",
	Short: "Save your Anthropic API key",
	Long: `Save your Anthropic API key to the OpenAnt config file.

The key is stored in ~/.config/openant/config.json with restricted
permissions (0600). This is required before running enhance, analyze,
verify, or scan.

Get an API key at https://console.anthropic.com/settings/keys

Examples:
  openant set-api-key sk-ant-api03-...`,
	Args: cobra.ExactArgs(1),
	Run:  runSetAPIKey,
}

func runSetAPIKey(cmd *cobra.Command, args []string) {
	key := strings.TrimSpace(args[0])
	if key == "" {
		output.PrintError("API key cannot be empty")
		os.Exit(1)
	}

	// Validate against Anthropic BEFORE saving — a bad key should never
	// be persisted, otherwise `openant scan` silently produces zero results
	// that look like a clean repo.
	fmt.Fprintf(os.Stderr, "Validating API key with Anthropic... ")
	if err := validateAPIKey(key); err != nil {
		fmt.Fprintf(os.Stderr, "\n")
		output.PrintError(err.Error())
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "OK\n")

	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	cfg.APIKey = key

	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n")
	output.PrintSuccess(fmt.Sprintf("API key saved (%s)", config.MaskKey(key)))
	fmt.Fprintf(os.Stderr, "\n")
}
