package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// probeOpenAI
// ---------------------------------------------------------------------------

func TestProbeOpenAI_AcceptsValid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request shape matches the OpenAI chat-completions API.
		if got := r.Header.Get("authorization"); got != "Bearer sk-test-openai" {
			t.Errorf("authorization header = %q, want 'Bearer sk-test-openai'", got)
		}
		if got := r.Header.Get("content-type"); got != "application/json" {
			t.Errorf("content-type = %q, want 'application/json'", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	orig := openaiAPIURL
	defer func() { openaiAPIURL = orig }()
	openaiAPIURL = server.URL

	if err := probeOpenAI("sk-test-openai", "", "gpt-5"); err != nil {
		t.Fatalf("expected nil error for 200 response, got: %v", err)
	}
}

func TestProbeOpenAI_Rejects401AsAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	orig := openaiAPIURL
	defer func() { openaiAPIURL = orig }()
	openaiAPIURL = server.URL

	err := probeOpenAI("sk-bad", "", "gpt-5")
	pe, ok := asProbeError(err)
	if !ok {
		t.Fatalf("expected AnthropicProbeError, got %T", err)
	}
	if pe.Kind != "auth" {
		t.Errorf("expected Kind 'auth', got %q", pe.Kind)
	}
}

func TestProbeOpenAI_Rejects404AsModelNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	orig := openaiAPIURL
	defer func() { openaiAPIURL = orig }()
	openaiAPIURL = server.URL

	err := probeOpenAI("sk-test", "", "gpt-future")
	pe, ok := asProbeError(err)
	if !ok {
		t.Fatalf("expected AnthropicProbeError, got %T", err)
	}
	if pe.Kind != "model_not_found" {
		t.Errorf("expected Kind 'model_not_found', got %q", pe.Kind)
	}
}

func TestProbeOpenAI_RespectsBaseURL(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Pass server.URL as the base — should hit ``{base}/v1/chat/completions``.
	if err := probeOpenAI("sk-test", server.URL, "gpt-5"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", gotPath)
	}
}

// ---------------------------------------------------------------------------
// probeGoogle
// ---------------------------------------------------------------------------

func TestProbeGoogle_AcceptsValid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Gemini uses ?key= query param, not a header.
		if got := r.URL.Query().Get("key"); got != "AIza-test" {
			t.Errorf("key query = %q, want 'AIza-test'", got)
		}
		// Model is in the path as ``models/{model}:generateContent``.
		if !strings.Contains(r.URL.Path, "models/gemini-test:generateContent") {
			t.Errorf("path = %q, expected to contain model + generateContent", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	orig := googleAPIBase
	defer func() { googleAPIBase = orig }()
	googleAPIBase = server.URL

	if err := probeGoogle("AIza-test", "", "gemini-test"); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestProbeGoogle_Rejects403AsAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	orig := googleAPIBase
	defer func() { googleAPIBase = orig }()
	googleAPIBase = server.URL

	err := probeGoogle("AIza-bad", "", "gemini-test")
	pe, ok := asProbeError(err)
	if !ok {
		t.Fatalf("expected AnthropicProbeError, got %T", err)
	}
	if pe.Kind != "auth" {
		t.Errorf("expected Kind 'auth', got %q", pe.Kind)
	}
}

func TestProbeGoogle_Rejects404AsModelNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	orig := googleAPIBase
	defer func() { googleAPIBase = orig }()
	googleAPIBase = server.URL

	err := probeGoogle("AIza-test", "", "gemini-future")
	pe, ok := asProbeError(err)
	if !ok {
		t.Fatalf("expected AnthropicProbeError, got %T", err)
	}
	if pe.Kind != "model_not_found" {
		t.Errorf("expected Kind 'model_not_found', got %q", pe.Kind)
	}
}

func TestProbeGoogle_HandlesSpecialCharsInModel(t *testing.T) {
	// Gemini model IDs can contain slashes (e.g. "tunedModels/foo/bar").
	// The probe URL-encodes them via url.PathEscape so the request URL
	// is valid; Go's HTTP server then decodes them back, so this test
	// inspects ``RawPath`` (the wire-format) rather than ``Path``
	// (the decoded form).
	var gotRawPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawPath = r.URL.RawPath
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	orig := googleAPIBase
	defer func() { googleAPIBase = orig }()
	googleAPIBase = server.URL

	if err := probeGoogle("AIza-test", "", "tunedModels/my-tuned"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	// URL-encoded forward slash is %2F. We don't care which exact
	// encoding (lowercase %2f also valid), only that the slash was
	// escaped on the wire so the API treats the whole thing as one
	// path segment.
	if !strings.Contains(strings.ToLower(gotRawPath), "tunedmodels%2fmy-tuned:generatecontent") {
		t.Errorf("model not properly URL-encoded in path: raw=%q", gotRawPath)
	}
}

// TestProbeGoogle_DoesNotLeakKeyOnNetworkError verifies that a transport
// failure (connection refused) does NOT surface the API key in the returned
// error. Gemini puts the key in the URL as “?key=...“, so a raw
// “*url.Error“ from client.Do() would otherwise echo the whole URL —
// including the secret — into stderr (setup.go -> output.PrintError).
func TestProbeGoogle_DoesNotLeakKeyOnNetworkError(t *testing.T) {
	// 127.0.0.1:1 forces a connection-refused transport error while the
	// key still rides in the request URL.
	err := probeGoogle("SECRETKEY123", "http://127.0.0.1:1", "gemini-2.5-pro")
	if err == nil {
		t.Fatal("expected a network error, got nil")
	}
	if strings.Contains(err.Error(), "SECRETKEY123") {
		t.Errorf("API key leaked into error string: %s", err.Error())
	}
}

// ---------------------------------------------------------------------------
// probeOpenAI reasoning models (o1/o3/o4 use max_completion_tokens)
// ---------------------------------------------------------------------------

func TestProbeOpenAI_ReasoningModelsUseMaxCompletionTokens(t *testing.T) {
	cases := []struct {
		model           string
		wantCompletion  bool // body should contain "max_completion_tokens"
		wantPlainMaxTok bool // body should contain "max_tokens"
	}{
		{"o1", true, false},
		{"o3-mini", true, false},
		{"o4-mini", true, false},
		{"gpt-4o", false, true},
		{"gpt-4o-mini", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.model, func(t *testing.T) {
			var gotBody string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			orig := openaiAPIURL
			defer func() { openaiAPIURL = orig }()
			openaiAPIURL = server.URL

			if err := probeOpenAI("sk-test", "", tc.model); err != nil {
				t.Fatalf("probe: %v", err)
			}
			hasCompletion := strings.Contains(gotBody, "max_completion_tokens")
			// "max_tokens" is a substring of "max_completion_tokens", so check
			// for the standalone JSON key form to disambiguate.
			hasPlainMaxTok := strings.Contains(gotBody, `"max_tokens"`)
			if hasCompletion != tc.wantCompletion {
				t.Errorf("model %q: max_completion_tokens present=%v, want %v (body=%s)", tc.model, hasCompletion, tc.wantCompletion, gotBody)
			}
			if hasPlainMaxTok != tc.wantPlainMaxTok {
				t.Errorf("model %q: max_tokens present=%v, want %v (body=%s)", tc.model, hasPlainMaxTok, tc.wantPlainMaxTok, gotBody)
			}
		})
	}
}
