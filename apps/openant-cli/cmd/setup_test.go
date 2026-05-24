package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withScriptedStdin redirects os.Stdin to the contents of ``script`` for
// the duration of the test. Each line of the script answers one prompt.
// Lines that are blank ("\n") accept the prompt's default.
//
// The wizard exits via os.Exit(1) on any error path (bad input, network
// failure, etc.) — these tests therefore script a fully-valid happy
// path and stub the probe endpoint to return 200, so no exit path
// fires.
func withScriptedStdin(t *testing.T, script string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(script); err != nil {
		t.Fatalf("write script: %v", err)
	}
	w.Close()
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		r.Close()
	})
}

// withFakeConfigHome points the config layer at a fresh temp dir and
// returns the resolved config.json path so the test can assert on it
// after the wizard runs.
func withFakeConfigHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", tmp)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tmp)
	}
	return filepath.Join(tmp, "openant", "config.json")
}

// withProbeServer points anthropicAPIURL at an httptest.Server that
// always returns 200 OK, so the wizard's probe succeeds. Same pattern
// the existing setapikey_test.go uses for validateAPIKey.
func withProbeServer(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	orig := anthropicAPIURL
	t.Cleanup(func() { anthropicAPIURL = orig })
	anthropicAPIURL = server.URL
}

func TestSetupLLMWizard_HappyPath(t *testing.T) {
	configPath := withFakeConfigHome(t)
	withProbeServer(t)

	// Script:
	//   1. llm-config name: "my-config"
	//   2. analyze:      provider=anthropic, type=anthropic, key=sk-test, base_url=(blank), model=(default)
	//   3-7. verify, llm_reach, enhance, report, dynamic_test, app_context: accept provider default + model default
	//   8. Set as default_llm: y
	script := strings.Join([]string{
		"my-config",          // llm-config name
		"",                   // analyze: provider (accept default "anthropic")
		"",                   // analyze: provider type (accept default "anthropic")
		"sk-test",            // analyze: API key
		"",                   // analyze: base URL (blank)
		"",                   // analyze: model (accept Opus default)
		"",                   // verify: provider (re-use anthropic from session)
		"",                   // verify: model (default Opus)
		"",                   // llm_reach: provider
		"",                   // llm_reach: model
		"",                   // enhance: provider
		"",                   // enhance: model (default Sonnet)
		"",                   // report: provider
		"",                   // report: model
		"",                   // dynamic_test: provider
		"",                   // dynamic_test: model
		"",                   // app_context: provider
		"",                   // app_context: model
		"y",                  // Set as default_llm?
	}, "\n") + "\n"

	withScriptedStdin(t, script)

	// The wizard prints to stderr — silence it for the test. (No need
	// to capture; the assertions are on the written config file.)
	origStderr := os.Stderr
	devnull, _ := os.Open(os.DevNull)
	os.Stderr = devnull
	t.Cleanup(func() {
		os.Stderr = origStderr
		devnull.Close()
	})

	runSetupLLM(nil, nil)

	// Assert config file exists and has the expected shape.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("config file is not valid JSON: %v", err)
	}

	if got["default_llm"] != "my-config" {
		t.Errorf("default_llm = %v, want my-config", got["default_llm"])
	}

	providers, ok := got["llm_providers"].(map[string]any)
	if !ok {
		t.Fatalf("llm_providers missing or wrong type: %v", got["llm_providers"])
	}
	anth, ok := providers["anthropic"].(map[string]any)
	if !ok {
		t.Fatalf("llm_providers.anthropic missing")
	}
	if anth["type"] != "anthropic" {
		t.Errorf("provider type = %v, want anthropic", anth["type"])
	}
	if anth["api_key"] != "sk-test" {
		t.Errorf("provider api_key = %v, want sk-test", anth["api_key"])
	}
	if _, hasBaseURL := anth["base_url"]; hasBaseURL {
		t.Error("blank base_url leaked into output — should be omitted")
	}

	configs, _ := got["llm_configs"].(map[string]any)
	myCfg, ok := configs["my-config"].(map[string]any)
	if !ok {
		t.Fatalf("llm_configs.my-config missing")
	}

	// Every phase must be populated. PHASES parity check.
	wantPhases := []string{"analyze", "verify", "llm_reach", "enhance", "report", "dynamic_test", "app_context"}
	for _, phase := range wantPhases {
		entry, ok := myCfg[phase].(map[string]any)
		if !ok {
			t.Errorf("phase %q missing from written llm-config", phase)
			continue
		}
		if entry["provider"] != "anthropic" {
			t.Errorf("phase %q provider = %v, want anthropic", phase, entry["provider"])
		}
		if entry["model"] == "" {
			t.Errorf("phase %q model is empty", phase)
		}
	}
}

func TestSetupLLMWizard_OpenAIProvider(t *testing.T) {
	// Verify the wizard accepts "openai" as a provider type, routes the
	// probe through probeOpenAI (not probeAnthropic), and writes a
	// well-formed config. This exercises the routing logic AND
	// implicitly verifies the heads-up warning path doesn't error
	// out the wizard.
	configPath := withFakeConfigHome(t)

	// Stub OpenAI's endpoint; assert the probe used it (not the
	// Anthropic one). If routing is broken, the wizard would either
	// hit the wrong URL or fail with a model-not-found from Anthropic.
	var probedOpenAI bool
	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probedOpenAI = true
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	origOpenAI := openaiAPIURL
	defer func() { openaiAPIURL = origOpenAI }()
	openaiAPIURL = openaiServer.URL

	// Also stub the Anthropic endpoint to a 401 — if the wizard
	// accidentally routes to it, the test fails loudly.
	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("wizard hit Anthropic endpoint despite picking openai provider")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer anthropicServer.Close()
	origAnthropic := anthropicAPIURL
	defer func() { anthropicAPIURL = origAnthropic }()
	anthropicAPIURL = anthropicServer.URL

	// Script: pick "openai" everywhere with the same model.
	script := strings.Join([]string{
		"openai-config",
		"openai",          // app_context: provider name
		"openai",          // provider type
		"sk-openai-test",  // API key
		"",                // base URL
		"gpt-4o-mini",       // model
		"", "gpt-4o-mini",   // llm_reach: provider (default openai) + model
		"", "gpt-4o-mini",   // enhance
		"", "gpt-4o",        // analyze (heavier model)
		"", "gpt-4o",        // verify
		"", "gpt-4o-mini",   // dynamic_test
		"", "gpt-4o-mini",   // report
		"y",               // default_llm
	}, "\n") + "\n"

	withScriptedStdin(t, script)
	devnull, _ := os.Open(os.DevNull)
	t.Cleanup(func() { devnull.Close() })
	origStderr := os.Stderr
	os.Stderr = devnull
	t.Cleanup(func() { os.Stderr = origStderr })

	runSetupLLM(nil, nil)

	if !probedOpenAI {
		t.Error("wizard never hit the OpenAI probe endpoint")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(data, &got)
	providers, _ := got["llm_providers"].(map[string]any)
	openai, _ := providers["openai"].(map[string]any)
	if openai["type"] != "openai" {
		t.Errorf("provider type = %v, want openai", openai["type"])
	}
	if openai["api_key"] != "sk-openai-test" {
		t.Errorf("api_key = %v, want sk-openai-test", openai["api_key"])
	}
}

func TestSetupLLMWizard_RefusesOpenantDefaultName(t *testing.T) {
	withFakeConfigHome(t)
	withProbeServer(t)

	// Script: try "openant-default", get rejected, then provide
	// a valid name. The rest of the flow is the minimum-input happy
	// path.
	script := strings.Join([]string{
		"openant-default",   // rejected — reserved
		"my-config",         // accepted
		"",                  // analyze: provider
		"",                  // analyze: provider type
		"sk-test",           // analyze: API key
		"",                  // analyze: base URL
		"",                  // analyze: model
		"", "",              // verify
		"", "",              // llm_reach
		"", "",              // enhance
		"", "",              // report
		"", "",              // dynamic_test
		"", "",              // app_context
		"",                  // default_llm (accept Y default)
	}, "\n") + "\n"

	withScriptedStdin(t, script)

	devnull, _ := os.Open(os.DevNull)
	t.Cleanup(func() { devnull.Close() })
	origStderr := os.Stderr
	os.Stderr = devnull
	t.Cleanup(func() { os.Stderr = origStderr })

	runSetupLLM(nil, nil)

	// If we got here without os.Exit firing, the reserved-name guard
	// looped back to ask again, and the second answer was accepted.
	// Verify the file ended up under my-config and NOT under
	// openant-default (which would be a contract violation).
	cfgPath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "openant", "config.json")
	if runtime.GOOS == "windows" {
		cfgPath = filepath.Join(os.Getenv("APPDATA"), "openant", "config.json")
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(data, &got)
	configs, _ := got["llm_configs"].(map[string]any)
	if _, banned := configs["openant-default"]; banned {
		t.Error("openant-default entry was written despite being reserved")
	}
	if _, ok := configs["my-config"]; !ok {
		t.Error("my-config not written")
	}
}
