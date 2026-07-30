package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forceInteractive overrides isInteractiveTerminal for the duration of the
// test, so scripted (non-tty) stdin from withScriptedStdin can still drive
// the interactive branch of resolvePatchLLMEnv -- mirrors how
// cmd/setup_test.go's withScriptedStdin already accepts that promptSecret
// falls back to its non-tty read path under the same circumstance.
func forceInteractive(t *testing.T, interactive bool) {
	t.Helper()
	orig := isInteractiveTerminal
	isInteractiveTerminal = func() bool { return interactive }
	t.Cleanup(func() { isInteractiveTerminal = orig })
}

// silenceStderr redirects os.Stderr to /dev/null for the duration of the
// test -- the resolver's menu/prompt text is expected output, not a signal
// worth asserting on here, so this just keeps `go test -v` output readable.
// Mirrors the inline pattern cmd/setup_test.go's TestSetupLLMWizard_HappyPath
// already uses.
func silenceStderr(t *testing.T) {
	t.Helper()
	orig := os.Stderr
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	os.Stderr = devnull
	t.Cleanup(func() {
		os.Stderr = orig
		devnull.Close()
	})
}

func clearPatchLLMEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"LLM_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
		orig, had := os.LookupEnv(k)
		os.Unsetenv(k)
		t.Cleanup(func() {
			if had {
				os.Setenv(k, orig)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Explicit LLM_PROVIDER already set.
// ---------------------------------------------------------------------------

func TestResolvePatchLLMEnv_ExplicitAnthropicWithKey(t *testing.T) {
	clearPatchLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "anthropic")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(env) != 0 {
		t.Fatalf("expected no extraEnv additions for an already-explicit provider, got %v", env)
	}
}

func TestResolvePatchLLMEnv_ExplicitOpenAIWithKey(t *testing.T) {
	clearPatchLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "openai")
	t.Setenv("OPENAI_API_KEY", "sk-openai-test")

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(env) != 0 {
		t.Fatalf("expected no extraEnv additions for an already-explicit provider, got %v", env)
	}
}

func TestResolvePatchLLMEnv_ExplicitMock(t *testing.T) {
	clearPatchLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "mock")

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(env) != 0 {
		t.Fatalf("expected no extraEnv additions for explicit mock, got %v", env)
	}
}

func TestResolvePatchLLMEnv_ExplicitRealProviderMissingKeyFailsClearly(t *testing.T) {
	clearPatchLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "anthropic")
	// ANTHROPIC_API_KEY intentionally left unset.

	_, err := resolvePatchLLMEnv()
	if err == nil {
		t.Fatal("expected an error when LLM_PROVIDER=anthropic has no matching API key")
	}
	if !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Errorf("error should name the missing env var, got: %v", err)
	}
}

func TestResolvePatchLLMEnv_ExplicitOpenAIMissingKeyFailsClearly(t *testing.T) {
	clearPatchLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "openai")

	_, err := resolvePatchLLMEnv()
	if err == nil {
		t.Fatal("expected an error when LLM_PROVIDER=openai has no matching API key")
	}
	if !strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Errorf("error should name the missing env var, got: %v", err)
	}
}

func TestResolvePatchLLMEnv_UnrecognizedExplicitProviderNotGatekept(t *testing.T) {
	// e.g. "google" or a typo -- Go must not reject or rewrite it; Python's
	// own llm_client.py already has an unmodified fallback for this case.
	clearPatchLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "google")

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("Go must not gatekeep an unrecognized explicit provider, got error: %v", err)
	}
	if len(env) != 0 {
		t.Fatalf("expected no extraEnv additions, got %v", env)
	}
}

// ---------------------------------------------------------------------------
// Non-interactive, no explicit provider.
// ---------------------------------------------------------------------------

func TestResolvePatchLLMEnv_NonInteractiveUnsetProviderFailsClearly(t *testing.T) {
	clearPatchLLMEnv(t)
	forceInteractive(t, false)

	_, err := resolvePatchLLMEnv()
	if err == nil {
		t.Fatal("expected an error for non-interactive execution with no LLM_PROVIDER")
	}
	if !strings.Contains(err.Error(), "LLM_PROVIDER") {
		t.Errorf("error should mention LLM_PROVIDER, got: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "interactive") {
		t.Errorf("error should explain why (not an interactive terminal), got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Interactive, no explicit provider.
// ---------------------------------------------------------------------------

func TestResolvePatchLLMEnv_InteractiveFreshProviderSelection(t *testing.T) {
	silenceStderr(t)
	clearPatchLLMEnv(t)
	withFakeConfigHome(t) // empty config -- nothing to offer reuse of
	forceInteractive(t, true)
	withScriptedStdin(t, "1\nsk-fresh-anthropic\n") // choose Anthropic, then enter a fresh key

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env["LLM_PROVIDER"] != "anthropic" {
		t.Errorf("LLM_PROVIDER = %q, want anthropic", env["LLM_PROVIDER"])
	}
	if env["ANTHROPIC_API_KEY"] != "sk-fresh-anthropic" {
		t.Errorf("ANTHROPIC_API_KEY = %q, want sk-fresh-anthropic", env["ANTHROPIC_API_KEY"])
	}
}

func TestResolvePatchLLMEnv_InteractiveMockSelection(t *testing.T) {
	silenceStderr(t)
	clearPatchLLMEnv(t)
	forceInteractive(t, true)
	withScriptedStdin(t, "3\n") // choose Mock

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env["LLM_PROVIDER"] != "mock" {
		t.Errorf("LLM_PROVIDER = %q, want mock", env["LLM_PROVIDER"])
	}
	if _, hasKey := env["ANTHROPIC_API_KEY"]; hasKey {
		t.Errorf("mock selection should not carry an API key, got %v", env)
	}
}

func TestResolvePatchLLMEnv_InteractiveInvalidChoiceFailsClearly(t *testing.T) {
	silenceStderr(t)
	clearPatchLLMEnv(t)
	forceInteractive(t, true)
	withScriptedStdin(t, "9\n")

	_, err := resolvePatchLLMEnv()
	if err == nil {
		t.Fatal("expected an error for an invalid menu choice")
	}
}

func TestResolvePatchLLMEnv_ReusesExistingCompatibleStoredCredential(t *testing.T) {
	silenceStderr(t)
	clearPatchLLMEnv(t)
	configPath := withFakeConfigHome(t)
	writeConfigJSON(t, configPath, map[string]any{"api_key": "sk-stored-anthropic"})
	forceInteractive(t, true)
	withScriptedStdin(t, "1\ny\n") // choose Anthropic, confirm reuse

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env["ANTHROPIC_API_KEY"] != "sk-stored-anthropic" {
		t.Errorf("ANTHROPIC_API_KEY = %q, want the stored credential to be reused", env["ANTHROPIC_API_KEY"])
	}
}

func TestResolvePatchLLMEnv_DeclinedReuseFallsBackToFreshPrompt(t *testing.T) {
	silenceStderr(t)
	clearPatchLLMEnv(t)
	configPath := withFakeConfigHome(t)
	writeConfigJSON(t, configPath, map[string]any{"api_key": "sk-stored-anthropic"})
	forceInteractive(t, true)
	withScriptedStdin(t, "1\nn\nsk-fresh-instead\n") // choose Anthropic, decline reuse, enter a fresh key

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env["ANTHROPIC_API_KEY"] != "sk-fresh-instead" {
		t.Errorf("ANTHROPIC_API_KEY = %q, want the freshly-entered key since reuse was declined", env["ANTHROPIC_API_KEY"])
	}
}

func TestResolvePatchLLMEnv_GoogleOnlyStoredConfigIsNeverOfferedOrReused(t *testing.T) {
	// Auto Patcher doesn't support Google at all -- a user whose only
	// configured OpenAnt credential is Google must land on a fresh-key
	// prompt for Anthropic, never see a reuse offer, and never have the
	// Google credential surface anywhere.
	silenceStderr(t)
	clearPatchLLMEnv(t)
	configPath := withFakeConfigHome(t)
	writeConfigJSON(t, configPath, map[string]any{
		"$schema_version": 2,
		"llm_providers": map[string]any{
			"google": map[string]any{"type": "google", "api_key": "sk-google-only"},
		},
	})
	forceInteractive(t, true)
	withScriptedStdin(t, "1\nsk-fresh-anthropic\n") // choose Anthropic; no reuse prompt should appear

	env, err := resolvePatchLLMEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env["LLM_PROVIDER"] != "anthropic" {
		t.Errorf("LLM_PROVIDER = %q, want anthropic", env["LLM_PROVIDER"])
	}
	if env["ANTHROPIC_API_KEY"] != "sk-fresh-anthropic" {
		t.Errorf("ANTHROPIC_API_KEY = %q, want the freshly-entered key", env["ANTHROPIC_API_KEY"])
	}
	for _, v := range env {
		if strings.Contains(v, "google") {
			t.Fatalf("the Google-only stored credential leaked into the resolved env: %v", env)
		}
	}
}

func TestResolvePatchLLMEnv_NeverMutatesProcessEnvironment(t *testing.T) {
	silenceStderr(t)
	clearPatchLLMEnv(t)
	withFakeConfigHome(t)
	forceInteractive(t, true)
	withScriptedStdin(t, "1\nsk-fresh-anthropic\n")

	if _, err := resolvePatchLLMEnv(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v := os.Getenv("LLM_PROVIDER"); v != "" {
		t.Fatalf("resolvePatchLLMEnv must never os.Setenv this process's own LLM_PROVIDER; got %q", v)
	}
	if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" {
		t.Fatalf("resolvePatchLLMEnv must never os.Setenv this process's own ANTHROPIC_API_KEY; got %q", v)
	}
}

// writeConfigJSON writes an arbitrary JSON document to path, creating parent
// directories as needed -- used to seed ~/.config/openant/config.json (as
// redirected by withFakeConfigHome) with a specific stored-credential shape.
func writeConfigJSON(t *testing.T, path string, doc map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal config fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
}
