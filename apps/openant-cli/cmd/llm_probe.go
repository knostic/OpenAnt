package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// anthropicAPIURL is the default messages endpoint used when no per-provider
// base_url is configured. Exposed as a package variable rather than a const
// so the existing test suite can point validateAPIKey / probeAnthropic at
// an httptest.Server. Production code never mutates it.
var anthropicAPIURL = "https://api.anthropic.com/v1/messages"

// AnthropicProbeError categorises probe failures so the setup wizard can
// show the user a tailored message ("bad key" vs "model not found" vs
// "couldn't reach the endpoint") without re-parsing the HTTP body.
type AnthropicProbeError struct {
	Kind    string // "auth", "model_not_found", "network", "other"
	Status  int    // HTTP status code (0 if no response)
	Message string // user-facing description
}

func (e *AnthropicProbeError) Error() string {
	return e.Message
}

// anthropicEndpoint resolves the messages URL for a given provider's
// base_url. An empty base_url resolves to “anthropicAPIURL“ (which
// production-defaults to api.anthropic.com but is test-overridable).
// Otherwise the base_url is treated as the provider root and
// “/v1/messages“ is appended — matching how the Anthropic SDK
// composes URLs against “base_url“.
func anthropicEndpoint(baseURL string) string {
	if baseURL == "" {
		return anthropicAPIURL
	}
	return strings.TrimRight(baseURL, "/") + "/v1/messages"
}

// probeAnthropic sends a minimal 1-token request to an Anthropic-compatible
// endpoint to verify (a) the API key authenticates, (b) the model ID
// resolves, and (c) the endpoint is reachable. baseURL is optional — when
// empty, hits the default Anthropic endpoint.
//
// This is the same probe shape used by “openant set-api-key“,
// generalised over base_url and model so the setup wizard can probe each
// phase's resolved (provider, model) pair against the user's chosen
// endpoint.
func probeAnthropic(apiKey, baseURL, model string) error {
	endpoint := anthropicEndpoint(baseURL)

	payload := fmt.Sprintf(
		`{"model":%q,"max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`,
		model,
	)
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(payload))
	if err != nil {
		return &AnthropicProbeError{
			Kind:    "other",
			Message: fmt.Sprintf("failed to build probe request: %s", err),
		}
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
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

// asProbeError unwraps an error into an AnthropicProbeError so callers
// can branch on the failure Kind — e.g. “set-api-key“ treats a
// “model_not_found“ as a soft pass because it only needs to confirm
// the key authenticated.
func asProbeError(err error) (*AnthropicProbeError, bool) {
	var pe *AnthropicProbeError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}
