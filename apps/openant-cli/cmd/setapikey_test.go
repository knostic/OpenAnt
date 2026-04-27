package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateAPIKey_Rejects401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Override the API URL for this test.
	orig := anthropicAPIURL
	defer func() { anthropicAPIURL = orig }()
	anthropicAPIURL = server.URL

	err := validateAPIKey("sk-bad-key")
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if got := err.Error(); !contains(got, "401") {
		t.Errorf("error should mention 401, got: %s", got)
	}
}

func TestValidateAPIKey_AcceptsValid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"h"}],"model":"claude-haiku-4-5-20251001","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	orig := anthropicAPIURL
	defer func() { anthropicAPIURL = orig }()
	anthropicAPIURL = server.URL

	if err := validateAPIKey("sk-good-key"); err != nil {
		t.Fatalf("expected nil error for 200 response, got: %v", err)
	}
}

func TestValidateAPIKey_SendsCorrectHeaders(t *testing.T) {
	var gotKey, gotVersion, gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotContentType = r.Header.Get("content-type")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	orig := anthropicAPIURL
	defer func() { anthropicAPIURL = orig }()
	anthropicAPIURL = server.URL

	_ = validateAPIKey("sk-test-123")

	if gotKey != "sk-test-123" {
		t.Errorf("x-api-key = %q, want %q", gotKey, "sk-test-123")
	}
	if gotVersion != "2023-06-01" {
		t.Errorf("anthropic-version = %q, want %q", gotVersion, "2023-06-01")
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q, want %q", gotContentType, "application/json")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
