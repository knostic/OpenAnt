package cmd

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// openaiAPIURL is the default chat-completions endpoint used when no
// per-provider base_url is configured. Exposed as a package variable
// so tests can point probes at an httptest.Server. Production code
// never mutates it.
var openaiAPIURL = "https://api.openai.com/v1/chat/completions"

// probeOpenAI sends a minimal 1-token chat-completions request to verify
// (a) the API key authenticates, (b) the model ID resolves, and
// (c) the endpoint is reachable. baseURL is optional — when empty,
// hits api.openai.com. When set, the wizard appends
// “/v1/chat/completions“ so a user-entered base URL of
// “https://my-proxy.example“ resolves correctly.
//
// Returns the same “AnthropicProbeError“ shape as “probeAnthropic“
// (despite the name) so the wizard renders a consistent failure
// message regardless of provider.
func probeOpenAI(apiKey, baseURL, model string) error {
	endpoint := openaiAPIURL
	if baseURL != "" {
		endpoint = strings.TrimRight(baseURL, "/") + "/v1/chat/completions"
	}
	return probeChatCompletionsAt(apiKey, endpoint, model)
}

// openrouterAPIBase is the default OpenRouter base URL — it already includes
// the ``/v1`` segment (matching the Python adapter's ``_DEFAULT_BASE_URL`` and
// the openai SDK's path handling). Package var so tests can point at httptest.
var openrouterAPIBase = "https://openrouter.ai/api/v1"

// probeOpenRouter verifies an OpenRouter key+model. OpenRouter speaks the
// OpenAI chat-completions wire API, but its base_url already carries ``/v1``,
// so we append only ``/chat/completions`` (NOT ``/v1/chat/completions`` like
// probeOpenAI) and default a BLANK base_url to OpenRouter — not api.openai.com,
// which probeOpenAI would hit, failing the probe with an OpenRouter key.
func probeOpenRouter(apiKey, baseURL, model string) error {
	base := strings.TrimRight(baseURL, "/")
	if base == "" {
		base = openrouterAPIBase
	}
	return probeChatCompletionsAt(apiKey, base+"/chat/completions", model)
}

// ollamaAPIBase is the default Ollama base URL — it already includes the
// ``/v1`` segment (matching the Python adapter's ``_DEFAULT_BASE_URL``).
// Package var so tests can point at httptest.
var ollamaAPIBase = "http://localhost:11434/v1"

// probeOllama verifies an Ollama model is pulled and serving. Ollama speaks
// the OpenAI chat-completions wire API on its own base (already carrying
// ``/v1``, like OpenRouter) and ignores Authorization headers — stock local
// Ollama needs no key, so a blank key probes with the same placeholder the
// Python adapter sends. A key-checking remote gateway still works: any
// non-blank key is forwarded verbatim.
func probeOllama(apiKey, baseURL, model string) error {
	base := strings.TrimRight(baseURL, "/")
	if base == "" {
		base = ollamaAPIBase
	}
	if apiKey == "" {
		apiKey = "ollama" // placeholder; matches utilities/llm/providers/ollama.py
	}
	err := probeChatCompletionsAt(apiKey, base+"/chat/completions", model)
	if err == nil {
		return nil
	}
	// Rewrite the generic 404 wording into the fixable `ollama pull` hint.
	if pe, ok := err.(*AnthropicProbeError); ok && pe.Kind == "model_not_found" {
		pe.Message = fmt.Sprintf("model %q not pulled into Ollama — run `ollama pull %s` (or `ollama list` to see what's installed)", model, model)
	}
	return err
}

// probeChatCompletionsAt POSTs a minimal 1-token request to a full
// chat-completions endpoint and maps the HTTP status to a probe error. Shared
// by the OpenAI and OpenRouter probes (both speak the OpenAI wire API).
func probeChatCompletionsAt(apiKey, endpoint, model string) error {
	// Reasoning models (o1/o3/o4) reject ``max_tokens`` and require
	// ``max_completion_tokens``; regular chat models keep ``max_tokens``.
	tokenKey := "max_tokens"
	if isOpenAIReasoningModel(model) {
		tokenKey = "max_completion_tokens"
	}
	payload := fmt.Sprintf(
		`{"model":%q,"messages":[{"role":"user","content":"hi"}],%q:1}`,
		model, tokenKey,
	)
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(payload))
	if err != nil {
		return &AnthropicProbeError{
			Kind:    "other",
			Message: fmt.Sprintf("failed to build probe request: %s", err),
		}
	}
	req.Header.Set("authorization", "Bearer "+apiKey)
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return &AnthropicProbeError{
			Kind:    "network",
			Message: fmt.Sprintf("could not reach %s: %s", endpoint, err),
		}
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return &AnthropicProbeError{
			Kind:    "auth",
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("authentication rejected (HTTP %d) — double-check the API key", resp.StatusCode),
		}
	case http.StatusNotFound:
		return &AnthropicProbeError{
			Kind:    "model_not_found",
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("model %q not found at %s (HTTP 404) — check the model ID at the provider", model, endpoint),
		}
	default:
		return &AnthropicProbeError{
			Kind:    "other",
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("probe returned unexpected HTTP %d from %s", resp.StatusCode, endpoint),
		}
	}
}

// isOpenAIReasoningModel reports whether model is an OpenAI reasoning
// model (o1/o3/o4 families), which reject “max_tokens“ and require
// “max_completion_tokens“ on Chat Completions. Strips any proxy
// prefix (“openai/o1“ → “o1“) and matches the bare “o<digit>“
// family — “gpt-4o“ / “gpt-4o-mini“ are NOT reasoning models.
func isOpenAIReasoningModel(model string) bool {
	m := strings.ToLower(model)
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	return len(m) >= 2 && m[0] == 'o' && m[1] >= '1' && m[1] <= '9'
}
