package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
)

// ---------------------------------------------------------------------------
// H3-Go — wizard must not offer o1-mini (the Python adapter drops it because
// it rejects the `system` role and lacks tool support). o1 / o3-mini /
// gpt-4o / gpt-4o-mini stay.
// ---------------------------------------------------------------------------

func TestKnownModels_OpenAIDropsO1Mini(t *testing.T) {
	openai, ok := knownModels["openai"]
	if !ok {
		t.Fatal("knownModels missing openai entry")
	}
	for _, m := range openai {
		if m == "o1-mini" {
			t.Errorf("o1-mini is still offered by the wizard; it must be removed (rejects system role, no tools)")
		}
	}
	// The keepers must still be present.
	for _, want := range []string{"o1", "o3-mini", "gpt-4o", "gpt-4o-mini"} {
		if !stringSliceContains(openai, want) {
			t.Errorf("knownModels[openai] dropped %q; only o1-mini should be removed", want)
		}
	}
}

// ---------------------------------------------------------------------------
// M4-Go — runHTMLReport must forward the report command's --llm-config to the
// Python report-data subcommand (the summary path already does this). Tested
// via the buildReportDataArgs helper.
// ---------------------------------------------------------------------------

func TestBuildReportDataArgs_ForwardsLLMConfig(t *testing.T) {
	origLLM := reportLLMConfig
	origDataset := reportDataset
	t.Cleanup(func() {
		reportLLMConfig = origLLM
		reportDataset = origDataset
	})

	reportDataset = ""
	reportLLMConfig = "my-llm"

	args := buildReportDataArgs("/tmp/results.json")

	if args[0] != "report-data" {
		t.Fatalf("args[0] = %q, want report-data", args[0])
	}
	if args[1] != "/tmp/results.json" {
		t.Fatalf("args[1] = %q, want results path", args[1])
	}
	if !argsContainPair(args, "--llm-config", "my-llm") {
		t.Errorf("--llm-config my-llm not forwarded; got %v", args)
	}
}

func TestBuildReportDataArgs_OmitsLLMConfigWhenBlank(t *testing.T) {
	origLLM := reportLLMConfig
	origDataset := reportDataset
	t.Cleanup(func() {
		reportLLMConfig = origLLM
		reportDataset = origDataset
	})

	reportDataset = "/tmp/ds.json"
	reportLLMConfig = ""

	args := buildReportDataArgs("/tmp/results.json")

	for _, a := range args {
		if a == "--llm-config" {
			t.Errorf("--llm-config must be omitted when reportLLMConfig is blank; got %v", args)
		}
	}
	// --dataset should still ride along when set.
	if !argsContainPair(args, "--dataset", "/tmp/ds.json") {
		t.Errorf("--dataset not forwarded; got %v", args)
	}
}

// argsContainPair reports whether flag immediately followed by val appears in args.
func argsContainPair(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// L7 — probeAllPhases must RETURN AN ERROR when a provider's probe fails
// (only the happy / reserved-name / blank-key-skip paths were covered).
// ---------------------------------------------------------------------------

func TestProbeAllPhases_ReturnsErrorOnProbeFailure(t *testing.T) {
	// Point the anthropic endpoint at a server that always 401s.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	orig := anthropicAPIURL
	defer func() { anthropicAPIURL = orig }()
	anthropicAPIURL = server.URL

	providers := map[string]config.ProviderEntry{
		// Non-blank key so the probe actually fires (blank keys are skipped).
		"anthropic": {Type: "anthropic", APIKey: "sk-bad", BaseURL: ""},
	}
	phases := map[string]config.LLMPhaseRef{
		"analyze": {Provider: "anthropic", Model: "claude-x"},
	}

	err := probeAllPhases(providers, phases)
	if err == nil {
		t.Fatal("expected probeAllPhases to return an error when the probe 401s, got nil")
	}
}

// ---------------------------------------------------------------------------
// L8 — set-api-key must soft-pass a likely-valid key on transient 429 / 5xx
// (only a conclusive 401/403 auth failure should reject).
// ---------------------------------------------------------------------------

func TestValidateAPIKey_SoftPassesOn429(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	orig := anthropicAPIURL
	defer func() { anthropicAPIURL = orig }()
	anthropicAPIURL = server.URL

	if err := validateAPIKey("sk-maybe-good"); err != nil {
		t.Fatalf("429 is transient — key must be accepted (soft-pass), got: %v", err)
	}
}

func TestValidateAPIKey_SoftPassesOn500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	orig := anthropicAPIURL
	defer func() { anthropicAPIURL = orig }()
	anthropicAPIURL = server.URL

	if err := validateAPIKey("sk-maybe-good"); err != nil {
		t.Fatalf("5xx is transient — key must be accepted (soft-pass), got: %v", err)
	}
}

func TestValidateAPIKey_StillRejects401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	orig := anthropicAPIURL
	defer func() { anthropicAPIURL = orig }()
	anthropicAPIURL = server.URL

	if err := validateAPIKey("sk-bad"); err == nil {
		t.Fatal("401 is a conclusive auth failure — key must still be rejected")
	}
}
