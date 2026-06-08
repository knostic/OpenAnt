// Tests for v2 config preservation. The Go side knows about three
// typed fields; everything else (llm_providers, llm_configs,
// default_llm, $schema_version) belongs to the Python pipeline and
// must survive a Load → mutate → Save round-trip without loss.

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeConfigAt drops a config.json at a fake XDG_CONFIG_HOME / HOME
// and points the OS env at it for the duration of the test.
func withConfigJSON(t *testing.T, body string) {
	t.Helper()
	tmp := t.TempDir()
	subdir := filepath.Join(tmp, "openant")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// configDir() prefers XDG_CONFIG_HOME on non-Windows, %APPDATA% on
	// Windows. Set the right env so the test cuts to our temp dir.
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", tmp)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tmp)
	}
}

func TestSavePreservesV2Fields(t *testing.T) {
	// User has hand-authored a v2 config with llm_providers and
	// llm_configs. Loading and re-saving (which happens whenever
	// any Go command writes config — set-api-key, set-active-project,
	// init, etc.) must NOT strip those fields.
	original := `{
  "$schema_version": 2,
  "api_key": "sk-ant-legacy",
  "default_llm": "cheap-qwen",
  "active_project": "owner/repo",
  "llm_providers": {
    "anthropic": {
      "type": "anthropic",
      "api_key": "sk-or-v1-test",
      "base_url": "https://openrouter.ai/api/v1"
    }
  },
  "llm_configs": {
    "cheap-qwen": {
      "analyze": {"provider": "anthropic", "model": "qwen/qwen-3-coder-480b"}
    }
  }
}
`
	withConfigJSON(t, original)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "sk-ant-legacy" {
		t.Errorf("api_key not loaded: %q", cfg.APIKey)
	}

	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path, _ := Path()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	for _, key := range []string{
		"$schema_version", "default_llm",
		"llm_providers", "llm_configs",
	} {
		if _, ok := out[key]; !ok {
			t.Errorf("v2 field %q stripped by Save (regression)", key)
		}
	}
	providers, _ := out["llm_providers"].(map[string]any)
	anth, _ := providers["anthropic"].(map[string]any)
	if anth["base_url"] != "https://openrouter.ai/api/v1" {
		t.Errorf("llm_providers.anthropic.base_url stripped: %v", anth)
	}
}

func TestSetAPIKeyAlsoUpdatesV2Provider(t *testing.T) {
	original := `{
  "$schema_version": 2,
  "api_key": "sk-ant-old",
  "llm_providers": {
    "anthropic": {
      "type": "anthropic",
      "api_key": "sk-ant-old"
    }
  }
}
`
	withConfigJSON(t, original)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cfg.SetAPIKey("sk-ant-new")
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path, _ := Path()
	data, _ := os.ReadFile(path)
	var out map[string]any
	_ = json.Unmarshal(data, &out)

	if out["api_key"] != "sk-ant-new" {
		t.Errorf("legacy api_key not updated: %v", out["api_key"])
	}
	providers, _ := out["llm_providers"].(map[string]any)
	anth, _ := providers["anthropic"].(map[string]any)
	if anth["api_key"] != "sk-ant-new" {
		t.Errorf("llm_providers.anthropic.api_key not updated (stale-key bug): %v", anth["api_key"])
	}
}

func TestHasV2ProvidersReportsCorrectly(t *testing.T) {
	t.Run("absent on v1 config", func(t *testing.T) {
		withConfigJSON(t, `{"api_key": "sk-x"}`)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.HasV2Providers() {
			t.Error("v1 config falsely reported v2 providers")
		}
	})

	t.Run("present when llm_providers set", func(t *testing.T) {
		withConfigJSON(t, `{
  "llm_providers": {"anthropic": {"type": "anthropic", "api_key": "sk"}}
}`)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.HasV2Providers() {
			t.Error("v2 config not detected")
		}
	})

	t.Run("absent when llm_providers is empty", func(t *testing.T) {
		// An explicitly-empty providers dict is treated as v1 — the
		// Go side has nothing to defer to, the user just made an
		// editing mistake. Better to fall through to legacy
		// behavior than reject.
		withConfigJSON(t, `{"llm_providers": {}}`)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.HasV2Providers() {
			t.Error("empty llm_providers dict should not count as v2")
		}
	})
}

func TestSaveEmptyConfigDoesNotEmitNullFields(t *testing.T) {
	// A fresh install round-trips cleanly; in particular Save on a
	// brand-new Config{} produces an empty object, not a dict full
	// of "key": "" entries.
	tmp := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", tmp)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tmp)
	}
	cfg := &Config{}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path, _ := Path()
	data, _ := os.ReadFile(path)
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty Config should serialise to {}, got %v", out)
	}
}

// ---------------------------------------------------------------------------
// LLM setup helpers — used by ``openant setup llm``.
// ---------------------------------------------------------------------------

func TestGetProviderReturnsTypedEntry(t *testing.T) {
	withConfigJSON(t, `{
  "$schema_version": 2,
  "llm_providers": {
    "anthropic": {
      "type": "anthropic",
      "api_key": "sk-existing",
      "base_url": "https://proxy.example/v1"
    }
  }
}`)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, ok := cfg.GetProvider("anthropic")
	if !ok {
		t.Fatal("GetProvider returned ok=false for existing provider")
	}
	if got.Type != "anthropic" || got.APIKey != "sk-existing" || got.BaseURL != "https://proxy.example/v1" {
		t.Errorf("unexpected entry: %+v", got)
	}

	if _, ok := cfg.GetProvider("never-set"); ok {
		t.Error("GetProvider returned ok=true for unknown provider")
	}
}

func TestLLMConfigExistsAndNames(t *testing.T) {
	withConfigJSON(t, `{
  "$schema_version": 2,
  "llm_configs": {
    "alpha": {"analyze": {"provider": "anthropic", "model": "claude-opus-4-6"}},
    "beta":  {"analyze": {"provider": "anthropic", "model": "claude-sonnet-4-20250514"}}
  }
}`)
	cfg, _ := Load()

	if !cfg.LLMConfigExists("alpha") {
		t.Error("LLMConfigExists missed 'alpha'")
	}
	if cfg.LLMConfigExists("gamma") {
		t.Error("LLMConfigExists falsely reported 'gamma'")
	}
	// Built-in must not show up as "exists" even though every user has it
	// available — overwriting it would be confusing.
	if cfg.LLMConfigExists("openant-default") {
		t.Error("openant-default leaked into LLMConfigExists; the built-in should be invisible to this check")
	}

	names := cfg.LLMConfigNames()
	if len(names) != 2 {
		t.Errorf("LLMConfigNames returned %v, want 2 entries", names)
	}
}

func TestWriteLLMConfigOnFreshInstall(t *testing.T) {
	// No config.json on disk. Save → re-load must produce a complete
	// v2 file with all the wizard's input intact.
	tmp := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", tmp)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tmp)
	}

	cfg := &Config{}
	phases := map[string]LLMPhaseRef{
		"analyze": {Provider: "anthropic", Model: "claude-opus-4-6"},
		"verify":  {Provider: "anthropic", Model: "claude-opus-4-6"},
	}
	providers := map[string]ProviderEntry{
		"anthropic": {Type: "anthropic", APIKey: "sk-test", BaseURL: ""},
	}
	cfg.WriteLLMConfig("my-config", phases, providers, true)

	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Read raw to assert exact schema shape.
	path, _ := Path()
	data, _ := os.ReadFile(path)
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	if v, _ := out["$schema_version"].(float64); v != 2 {
		t.Errorf("$schema_version=%v, want 2", out["$schema_version"])
	}
	if out["default_llm"] != "my-config" {
		t.Errorf("default_llm=%v, want my-config", out["default_llm"])
	}
	provs, _ := out["llm_providers"].(map[string]any)
	anth, _ := provs["anthropic"].(map[string]any)
	if anth["type"] != "anthropic" || anth["api_key"] != "sk-test" {
		t.Errorf("provider entry malformed: %v", anth)
	}
	if _, hasBaseURL := anth["base_url"]; hasBaseURL {
		t.Error("empty base_url leaked into output — should be omitted")
	}
	configs, _ := out["llm_configs"].(map[string]any)
	myConfig, _ := configs["my-config"].(map[string]any)
	analyze, _ := myConfig["analyze"].(map[string]any)
	if analyze["provider"] != "anthropic" || analyze["model"] != "claude-opus-4-6" {
		t.Errorf("analyze phase malformed: %v", analyze)
	}
}

func TestWriteLLMConfigPreservesExistingSiblings(t *testing.T) {
	// User already has a 'beta' llm-config and an 'openrouter' provider.
	// Writing a new 'alpha' config that doesn't touch them must leave
	// both intact.
	withConfigJSON(t, `{
  "$schema_version": 2,
  "default_llm": "beta",
  "llm_providers": {
    "openrouter": {"type": "anthropic", "api_key": "sk-or", "base_url": "https://openrouter.ai/api/v1"}
  },
  "llm_configs": {
    "beta": {"analyze": {"provider": "openrouter", "model": "qwen/qwen-3-coder-480b"}}
  }
}`)
	cfg, _ := Load()

	cfg.WriteLLMConfig(
		"alpha",
		map[string]LLMPhaseRef{
			"analyze": {Provider: "anthropic", Model: "claude-opus-4-6"},
		},
		map[string]ProviderEntry{
			"anthropic": {Type: "anthropic", APIKey: "sk-ant"},
		},
		false, // not making default
	)
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path, _ := Path()
	data, _ := os.ReadFile(path)
	var out map[string]any
	_ = json.Unmarshal(data, &out)

	provs, _ := out["llm_providers"].(map[string]any)
	if _, ok := provs["openrouter"]; !ok {
		t.Error("pre-existing 'openrouter' provider stripped by WriteLLMConfig")
	}
	if _, ok := provs["anthropic"]; !ok {
		t.Error("new 'anthropic' provider not added")
	}

	configs, _ := out["llm_configs"].(map[string]any)
	if _, ok := configs["beta"]; !ok {
		t.Error("pre-existing 'beta' llm-config stripped")
	}
	if _, ok := configs["alpha"]; !ok {
		t.Error("new 'alpha' llm-config not added")
	}

	if out["default_llm"] != "beta" {
		t.Errorf("default_llm overwritten despite makeDefault=false: got %v, want 'beta'", out["default_llm"])
	}
}

func TestSaveIsAtomicAndLeavesNoTempFile(t *testing.T) {
	// Save must write via a temp file + rename so a crash mid-write can't
	// truncate config.json (which now holds multiple provider keys). After
	// a successful Save, no leftover *.tmp file should remain in the dir,
	// and a reload must round-trip the data.
	withConfigJSON(t, `{
  "$schema_version": 2,
  "api_key": "sk-ant-legacy",
  "default_llm": "cheap",
  "llm_providers": {
    "anthropic": {"type": "anthropic", "api_key": "sk-ant", "base_url": "https://openrouter.ai/api/v1"}
  },
  "llm_configs": {
    "cheap": {"analyze": {"provider": "anthropic", "model": "qwen/qwen-3-coder-480b"}}
  }
}`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload and assert round-trip equality on the fields we care about.
	cfg2, err := Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg2.APIKey != "sk-ant-legacy" {
		t.Errorf("api_key not round-tripped: %q", cfg2.APIKey)
	}
	if !cfg2.HasV2Providers() {
		t.Error("v2 providers lost across atomic Save")
	}

	// No leftover temp files.
	path, _ := Path()
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file after Save: %s", e.Name())
		}
	}
}

func TestWriteLLMConfigPreservesUnknownProviderFields(t *testing.T) {
	// A user hand-authored a provider entry with an extra field
	// (organization_id) the Go typed surface doesn't know about. Updating
	// that provider via WriteLLMConfig must merge — preserving the unknown
	// sibling key — not rebuild the entry from scratch and drop it.
	withConfigJSON(t, `{
  "$schema_version": 2,
  "llm_providers": {
    "myprov": {
      "type": "openai",
      "api_key": "sk-old",
      "base_url": "https://proxy.example/v1",
      "organization_id": "keep-me"
    }
  }
}`)
	cfg, _ := Load()

	cfg.WriteLLMConfig(
		"my-config",
		map[string]LLMPhaseRef{
			"analyze": {Provider: "myprov", Model: "gpt-4o"},
		},
		map[string]ProviderEntry{
			"myprov": {Type: "openai", APIKey: "sk-new", BaseURL: "https://proxy.example/v1"},
		},
		false,
	)
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path, _ := Path()
	data, _ := os.ReadFile(path)
	var out map[string]any
	_ = json.Unmarshal(data, &out)

	provs, _ := out["llm_providers"].(map[string]any)
	myprov, ok := provs["myprov"].(map[string]any)
	if !ok {
		t.Fatalf("myprov entry missing")
	}
	if myprov["organization_id"] != "keep-me" {
		t.Errorf("unknown sibling field organization_id dropped: %v", myprov["organization_id"])
	}
	if myprov["api_key"] != "sk-new" {
		t.Errorf("typed field api_key not updated: %v", myprov["api_key"])
	}
	if myprov["type"] != "openai" {
		t.Errorf("type field = %v, want openai", myprov["type"])
	}
}

func TestWriteLLMConfigOverwritesExistingProvider(t *testing.T) {
	// Re-running the wizard with the same provider name + a fresh API
	// key should update the stored credential (key rotation flow).
	withConfigJSON(t, `{
  "$schema_version": 2,
  "llm_providers": {
    "anthropic": {"type": "anthropic", "api_key": "sk-old"}
  }
}`)
	cfg, _ := Load()

	cfg.WriteLLMConfig(
		"my-config",
		map[string]LLMPhaseRef{
			"analyze": {Provider: "anthropic", Model: "claude-opus-4-6"},
		},
		map[string]ProviderEntry{
			"anthropic": {Type: "anthropic", APIKey: "sk-new"},
		},
		false,
	)
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	cfg2, _ := Load()
	got, _ := cfg2.GetProvider("anthropic")
	if got.APIKey != "sk-new" {
		t.Errorf("provider key not rotated: got %q, want sk-new", got.APIKey)
	}
}
