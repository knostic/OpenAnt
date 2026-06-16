package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

// validateAPIKey is the back-compat wrapper for “openant set-api-key“.
// Delegates to the shared “probeAnthropic“ helper which is also used by
// “openant setup llm“ so both code paths agree on what "the key works"
// means.
func validateAPIKey(key string) error {
	err := probeAnthropic(key, "", "claude-haiku-4-5-20251001")
	if err == nil {
		return nil
	}
	pe, ok := asProbeError(err)
	if !ok {
		return err
	}
	// A 404 (model_not_found) means the key AUTHENTICATED — auth is
	// checked before model resolution — but this account can't see the
	// probe model (e.g. enterprise/allow-listed orgs without Haiku
	// access). The key is valid, so don't reject it over the model.
	if pe.Kind == "model_not_found" {
		return nil
	}
	// Transient server-side failures (429 rate-limit, 5xx) are NOT a
	// verdict on the key — rejecting here would refuse a likely-valid
	// key just because Anthropic was busy. Soft-pass and save it; the
	// next real call will surface a genuinely bad key. Only a
	// conclusive auth failure (401/403, Kind=="auth") should reject.
	if pe.Status == http.StatusTooManyRequests || pe.Status >= http.StatusInternalServerError {
		return nil
	}
	return err
}

var setAPIKeyCmd = &cobra.Command{
	Use:   "set-api-key [key]",
	Short: "Save your Anthropic API key",
	Long: `Save your Anthropic API key to the OpenAnt config file.

Run without an argument to be prompted for the key interactively. The
prompt does NOT echo what you type/paste, so the key never lands in your
terminal scrollback:

  openant set-api-key

The key is stored in ~/.config/openant/config.json with restricted
permissions (0600). This is required before running enhance, analyze,
verify, or scan.

Get an API key at https://console.anthropic.com/settings/keys

You may also pass the key as an argument for back-compat:

  openant set-api-key sk-ant-api03-...

WARNING: passing the key as an argument exposes it to your shell history
and to other users via process listings (e.g. ` + "`ps`" + `). Prefer the
interactive no-echo prompt above.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runSetAPIKey,
}

func runSetAPIKey(cmd *cobra.Command, args []string) {
	var key string
	if len(args) == 1 {
		// Back-compat: key passed as an argv. Exposed to shell history /
		// `ps`; the command help warns against this.
		key = strings.TrimSpace(args[0])
	} else {
		// No argv: read the key interactively WITHOUT echo (falls back to
		// a plain line read when stdin is not a terminal — pipes, CI).
		reader := bufio.NewReader(os.Stdin)
		k, err := promptSecret(reader, "Anthropic API key")
		if err != nil {
			output.PrintError(err.Error())
			os.Exit(1)
		}
		key = strings.TrimSpace(k)
	}
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

	// SetAPIKey updates the v1 ``api_key`` AND the v2
	// ``llm_providers["anthropic"].api_key`` entry (if present) so
	// users who have authored an explicit anthropic provider see
	// the rotation applied to their actual provider, not just the
	// legacy field. See config.Config.SetAPIKey.
	cfg.SetAPIKey(key)

	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n")
	output.PrintSuccess(fmt.Sprintf("API key saved (%s)", config.MaskKey(key)))
	fmt.Fprintf(os.Stderr, "\n")
}
