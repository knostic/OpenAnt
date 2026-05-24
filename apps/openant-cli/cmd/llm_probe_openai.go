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
// ``/v1/chat/completions`` so a user-entered base URL of
// ``https://my-proxy.example`` resolves correctly.
//
// Returns the same ``AnthropicProbeError`` shape as ``probeAnthropic``
// (despite the name) so the wizard renders a consistent failure
// message regardless of provider.
func probeOpenAI(apiKey, baseURL, model string) error {
	endpoint := openaiAPIURL
	if baseURL != "" {
		endpoint = strings.TrimRight(baseURL, "/") + "/v1/chat/completions"
	}

	payload := fmt.Sprintf(
		`{"model":%q,"messages":[{"role":"user","content":"hi"}],"max_tokens":1}`,
		model,
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
