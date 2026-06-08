package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// googleAPIBase is the default Gemini API base URL used when no
// per-provider base_url is configured. Exposed as a package variable
// so tests can override it.
var googleAPIBase = "https://generativelanguage.googleapis.com"

// keyParamPattern matches a “key=<value>“ query parameter so the value
// can be scrubbed before it reaches an error string. Gemini auth puts the
// API key in the URL, so a raw “*url.Error“ from the HTTP client echoes
// the whole URL — including the secret — which would otherwise land in
// stderr via output.PrintError.
var keyParamPattern = regexp.MustCompile(`(key=)[^&\s"]*`)

// redactKeyParam replaces the value of any “key=“ query parameter with
// “REDACTED“. Handles both “key=...&“ (mid-query) and “key=...“ at
// the end of the string. Used to sanitise transport errors that carry the
// Gemini URL (and thus the API key) before they are logged or printed.
func redactKeyParam(s string) string {
	return keyParamPattern.ReplaceAllString(s, "${1}REDACTED")
}

// probeGoogle sends a minimal 1-token generateContent request to verify
// (a) the API key authenticates, (b) the model ID resolves, and
// (c) the endpoint is reachable. baseURL is optional — when empty,
// hits “generativelanguage.googleapis.com“.
//
// Returns “AnthropicProbeError“ (the shared shape) so the wizard
// renders consistent messages across providers.
//
// Gemini's auth model differs from OpenAI/Anthropic: the API key is
// passed as a “?key=“ query parameter rather than a header, and the
// model name is in the URL path rather than the body.
func probeGoogle(apiKey, baseURL, model string) error {
	base := googleAPIBase
	if baseURL != "" {
		base = strings.TrimRight(baseURL, "/")
	}
	// generateContent expects the model in the path. Escape it
	// defensively even though valid model IDs don't contain unsafe
	// characters.
	endpoint := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s",
		base, url.PathEscape(model), url.QueryEscape(apiKey))

	payload := `{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":1}}`
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(payload))
	if err != nil {
		// err may echo the request URL (which carries the key) on a
		// malformed endpoint — redact defensively.
		return &AnthropicProbeError{
			Kind:    "other",
			Message: fmt.Sprintf("failed to build probe request: %s", redactKeyParam(err.Error())),
		}
	}
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// client.Do returns a *url.Error whose .Error() includes the full
		// request URL — and Gemini's URL carries ``?key=<apiKey>``. Redact
		// the key before this message can reach stderr.
		return &AnthropicProbeError{
			Kind:    "network",
			Message: fmt.Sprintf("could not reach %s: %s", base, redactKeyParam(err.Error())),
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
			Message: fmt.Sprintf("model %q not found at %s (HTTP 404) — check the model ID at the provider", model, base),
		}
	default:
		return &AnthropicProbeError{
			Kind:    "other",
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("probe returned unexpected HTTP %d from %s", resp.StatusCode, base),
		}
	}
}
