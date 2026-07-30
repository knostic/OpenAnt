package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/x/term"
	"github.com/knostic/open-ant-cli/internal/config"
)

// isInteractiveTerminal reports whether stdin is a real interactive
// terminal. A package-level var (mirroring internal/python.defaultInvokeTimeout's
// test-override pattern) so tests can force either branch of
// resolvePatchLLMEnv without needing a real TTY -- setup_test.go's
// withScriptedStdin already replaces os.Stdin with a non-tty os.Pipe() for
// scripted input, so the interactive branch needs its own seam to be
// reachable in tests.
var isInteractiveTerminal = func() bool {
	return term.IsTerminal(os.Stdin.Fd())
}

// patchLLMOption is one entry in the provider menu `openant patch` offers
// when LLM_PROVIDER isn't already set. Deliberately NOT the same set as
// OpenAnt's own scan-pipeline providers: no Google, because
// utilities.autopatcher.llm_client.py's LLM_CONFIG has no google entry --
// Auto Patcher's Python engine has no code path that would ever use it.
var patchLLMMenu = []struct {
	key      string
	provider string
	envName  string
	label    string
}{
	{key: "1", provider: "anthropic", envName: "ANTHROPIC_API_KEY", label: "Anthropic"},
	{key: "2", provider: "openai", envName: "OPENAI_API_KEY", label: "OpenAI"},
	{key: "3", provider: "mock", envName: "", label: "Mock"},
}

// resolvePatchLLMEnv resolves the LLM_PROVIDER (+ matching API key) env vars
// to inject into the Auto Patcher Python subprocess ONLY. The returned map
// is meant for python.Invoke's extraEnv parameter -- callers must never
// os.Setenv() these into this process's own environment.
//
// Precedence:
//  1. LLM_PROVIDER already set in the environment -- honored as-is, no
//     prompting, no config lookup. Only validated enough to fail fast when a
//     named real provider's matching API key is missing; core/patch.py's
//     _require_llm_provider() remains the final Python-side backstop
//     regardless of what happens here.
//  2. Interactive terminal, no explicit provider -- offer the menu of
//     providers Auto Patcher actually supports, reusing this package's
//     existing prompt/secret/config helpers (from cmd/setup.go and
//     internal/config). Never silently reuses a stored credential --
//     always asks first.
//  3. Non-interactive, no explicit provider -- fail clearly. Never prompts,
//     never falls back to mock.
func resolvePatchLLMEnv() (map[string]string, error) {
	if provider := os.Getenv("LLM_PROVIDER"); provider != "" {
		return validateExplicitPatchProvider(provider)
	}

	if !isInteractiveTerminal() {
		return nil, fmt.Errorf(
			"LLM_PROVIDER is not set and this is not an interactive terminal.\n" +
				"Set LLM_PROVIDER=anthropic|openai|mock (and the matching API key,\n" +
				"e.g. ANTHROPIC_API_KEY) before running openant patch non-interactively.",
		)
	}

	reader := bufio.NewReader(os.Stdin)
	return promptForPatchLLMEnv(reader)
}

// validateExplicitPatchProvider fails fast when a real (non-mock) provider
// is explicitly named but its matching API key is missing from the
// environment. Returns nil, nil on success: the value is already present in
// os.Environ() and reaches the subprocess via the existing environment
// passthrough in python.Invoke -- nothing needs to be added to the
// subprocess-only extraEnv map for this case.
//
// An unrecognized provider name (e.g. a future provider, or a typo) is
// deliberately left unvalidated here: utilities.autopatcher.llm_client.py
// already has its own, unmodified fallback-to-mock-with-warning behavior for
// that case, and this function must not duplicate or override it.
func validateExplicitPatchProvider(provider string) (map[string]string, error) {
	switch provider {
	case "mock":
		return nil, nil
	case "anthropic":
		if os.Getenv("ANTHROPIC_API_KEY") == "" {
			return nil, fmt.Errorf(
				"LLM_PROVIDER=anthropic is set but ANTHROPIC_API_KEY is not.\n" +
					"Export it, or set LLM_PROVIDER=mock to use mock mode.",
			)
		}
		return nil, nil
	case "openai":
		if os.Getenv("OPENAI_API_KEY") == "" {
			return nil, fmt.Errorf(
				"LLM_PROVIDER=openai is set but OPENAI_API_KEY is not.\n" +
					"Export it, or set LLM_PROVIDER=mock to use mock mode.",
			)
		}
		return nil, nil
	default:
		return nil, nil
	}
}

// promptForPatchLLMEnv shows the interactive provider menu. Only offers
// providers Auto Patcher's Python engine actually supports -- never Google.
func promptForPatchLLMEnv(reader *bufio.Reader) (map[string]string, error) {
	fmt.Fprintln(os.Stderr, "No LLM provider configured for Auto Patcher.")
	for _, opt := range patchLLMMenu {
		fmt.Fprintf(os.Stderr, "%s) %s\n", opt.key, opt.label)
	}
	choice, err := promptString(reader, "Choose (1/2/3)", "")
	if err != nil {
		return nil, err
	}
	choice = strings.TrimSpace(choice)

	for _, opt := range patchLLMMenu {
		if opt.key != choice {
			continue
		}
		if opt.provider == "mock" {
			fmt.Fprintln(os.Stderr, "Using mock LLM for this run.")
			return map[string]string{"LLM_PROVIDER": "mock"}, nil
		}
		return promptOrReusePatchProviderKey(reader, opt.provider, opt.envName, opt.label)
	}
	return nil, fmt.Errorf("invalid choice %q; expected 1, 2, or 3", choice)
}

// promptOrReusePatchProviderKey offers reuse of an already-configured
// OpenAnt credential for the chosen provider -- visibly, via an explicit
// yes/no confirmation showing the masked key -- before falling back to a
// fresh no-echo prompt. Never reuses a stored credential silently.
func promptOrReusePatchProviderKey(reader *bufio.Reader, provider, envName, label string) (map[string]string, error) {
	cfg, _ := config.Load()
	if key, ok := existingPatchCredential(cfg, provider); ok {
		reuse, err := promptYesNo(
			reader,
			fmt.Sprintf("Reuse your configured %s key (%s) from OpenAnt setup for Auto Patcher too?", label, config.MaskKey(key)),
			true,
		)
		if err != nil {
			return nil, err
		}
		if reuse {
			return map[string]string{"LLM_PROVIDER": provider, envName: key}, nil
		}
	}

	key, err := promptSecret(reader, fmt.Sprintf("Enter %s", envName))
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, fmt.Errorf("%s is required to use %s", envName, label)
	}
	return map[string]string{"LLM_PROVIDER": provider, envName: key}, nil
}

// existingPatchCredential looks up a credential OpenAnt already has
// configured for the given provider -- the v2 llm_providers entry first,
// else the legacy v1 api_key field (which is always an Anthropic key).
func existingPatchCredential(cfg *config.Config, provider string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	if entry, ok := cfg.GetProvider(provider); ok && entry.APIKey != "" {
		return entry.APIKey, true
	}
	if provider == "anthropic" && cfg.APIKey != "" {
		return cfg.APIKey, true
	}
	return "", false
}
