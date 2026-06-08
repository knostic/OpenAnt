// Package config handles persistent configuration for the OpenAnt CLI.
//
// Configuration is stored in ~/.config/openant/config.json (or
// $XDG_CONFIG_HOME/openant/config.json on Linux). The file is created
// with 0600 permissions since it may contain API keys.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds the persistent CLI configuration.
//
// The typed fields below are the ones the Go CLI reads and writes
// directly. v2 fields (“llm_providers“, “llm_configs“,
// “default_llm“, “$schema_version“) are interpreted by the
// Python pipeline; the Go side preserves them through a private
// “raw“ map so a round-trip “Load“ → “Save“ (triggered by
// e.g. “openant set-api-key“) doesn't silently wipe whatever the
// user authored.
type Config struct {
	APIKey        string `json:"api_key,omitempty"`
	DefaultModel  string `json:"default_model,omitempty"`
	ActiveProject string `json:"active_project,omitempty"`

	// raw holds the originally-loaded JSON dict, so Save can write
	// back v2 fields the typed surface doesn't know about. Not
	// exported — callers manipulate v2 entries through methods
	// (SetAPIKey, HasV2Providers, etc.) so the Go side never needs
	// the full v2 schema typed out.
	raw map[string]any
}

// configDir returns the base directory for openant config files.
// On macOS/Linux: $XDG_CONFIG_HOME/openant or ~/.config/openant
// On Windows: %APPDATA%\openant
func configDir() (string, error) {
	// Use Go's built-in UserConfigDir which handles platform differences:
	//   macOS:   ~/Library/Application Support
	//   Linux:   $XDG_CONFIG_HOME or ~/.config
	//   Windows: %APPDATA%
	//
	// However, on macOS we prefer ~/.config for CLI tools (standard for
	// developer tools like gh, docker, aws). UserConfigDir returns
	// ~/Library/Application Support which is more for GUI apps.
	if runtime.GOOS != "windows" {
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "openant"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, ".config", "openant"), nil
	}

	// Windows: use %APPDATA%
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine config directory: %w", err)
	}
	return filepath.Join(dir, "openant"), nil
}

// Path returns the full path to the config file.
func Path() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads the config file. Returns an empty Config if the file
// does not exist (not an error — first run).
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Parse once into the typed fields and once into a generic map
	// so v2 keys (llm_providers / llm_configs / default_llm /
	// $schema_version) survive a Load → Save round-trip.
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err == nil {
		cfg.raw = raw
	}

	return &cfg, nil
}

// Save writes the config to disk with restricted permissions.
//
// Preserves unknown (v2) fields by merging the typed view into the
// raw map loaded earlier. A fresh “Config{}“ (e.g. a brand-new
// install) round-trips cleanly because the raw map is nil and the
// merge produces a typed-only dict.
func Save(cfg *Config) error {
	path, err := Path()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Merge typed fields into the preserved raw map. Empty values
	// are removed to keep ``omitempty`` semantics consistent with
	// the previous behavior.
	out := cfg.raw
	if out == nil {
		out = map[string]any{}
	}
	setOrDelete(out, "api_key", cfg.APIKey)
	setOrDelete(out, "default_model", cfg.DefaultModel)
	setOrDelete(out, "active_project", cfg.ActiveProject)

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	data = append(data, '\n')

	// Atomic write: stage to a temp file in the same directory, then
	// rename over the target. A crash mid-write can no longer truncate
	// the live config (which may hold multiple provider keys) — the
	// rename either fully succeeds or leaves the old file intact.
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set config permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to flush config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		if runtime.GOOS != "windows" {
			return fmt.Errorf("failed to replace config: %w", err)
		}
		// Windows can't rename onto an existing file. Move the live
		// config aside first, then swap the new one in — so a failed
		// replace never destroys the original (which may hold multiple
		// provider keys). On failure, roll the original back.
		backup := path + ".bak"
		_ = os.Remove(backup)
		if err := os.Rename(path, backup); err != nil {
			return fmt.Errorf("failed to stage config replace: %w", err)
		}
		if err := os.Rename(tmpName, path); err != nil {
			_ = os.Rename(backup, path) // restore the original
			return fmt.Errorf("failed to replace config: %w", err)
		}
		_ = os.Remove(backup)
	}

	return nil
}

func setOrDelete(m map[string]any, key, value string) {
	if value == "" {
		delete(m, key)
		return
	}
	m[key] = value
}

// SetAPIKey writes “key“ to both the legacy top-level “api_key“
// field and (if present) the v2 “llm_providers["anthropic"].api_key“
// entry. The two must stay in sync: the Python pipeline reads the
// v2 entry when present, the v1 migration projects the legacy field
// into the v2 entry when it isn't. Set both so a user who has
// hand-authored an “llm_providers["anthropic"]“ doesn't see a
// stale provider key after running “openant set-api-key“.
func (c *Config) SetAPIKey(key string) {
	c.APIKey = key
	if c.raw == nil {
		return
	}
	providers, ok := c.raw["llm_providers"].(map[string]any)
	if !ok {
		return
	}
	anth, ok := providers["anthropic"].(map[string]any)
	if !ok {
		return
	}
	anth["api_key"] = key
}

// HasV2Providers reports whether the user has explicitly authored an
// “llm_providers“ section. The Python subprocess invoker uses this
// to decide whether to inject the legacy “api_key“ as an
// “ANTHROPIC_API_KEY“ env var — for v2 users that injection would
// override the explicit per-provider keys, so the Go side stays
// out of the way once a v2 config is on disk.
func (c *Config) HasV2Providers() bool {
	if c.raw == nil {
		return false
	}
	providers, ok := c.raw["llm_providers"].(map[string]any)
	if !ok {
		return false
	}
	return len(providers) > 0
}

// ProviderEntry is the typed view of one “llm_providers[<name>]“
// entry that the setup wizard consumes. The Go side never types out
// the full v2 schema — only the fields the wizard needs to read or
// reuse when the user names an existing provider.
type ProviderEntry struct {
	Type    string
	APIKey  string
	BaseURL string
}

// LLMPhaseRef is one “{provider, model}“ pair inside an llm-config.
// Mirrors “utilities.llm.PhaseRef“ on the Python side; kept here to
// avoid threading the v2 schema through every Go caller.
type LLMPhaseRef struct {
	Provider string
	Model    string
}

// GetProvider returns the provider entry currently authored under
// “llm_providers[name]“. The second return value reports presence
// so the setup wizard can skip re-prompting for credentials when a
// phase names a provider already on disk.
func (c *Config) GetProvider(name string) (ProviderEntry, bool) {
	if c.raw == nil {
		return ProviderEntry{}, false
	}
	providers, ok := c.raw["llm_providers"].(map[string]any)
	if !ok {
		return ProviderEntry{}, false
	}
	entry, ok := providers[name].(map[string]any)
	if !ok {
		return ProviderEntry{}, false
	}
	out := ProviderEntry{}
	if v, ok := entry["type"].(string); ok {
		out.Type = v
	}
	if v, ok := entry["api_key"].(string); ok {
		out.APIKey = v
	}
	if v, ok := entry["base_url"].(string); ok {
		out.BaseURL = v
	}
	return out, true
}

// LLMConfigExists reports whether a user-authored llm-config with this
// name is present. The built-in “openant-default“ is NOT considered
// an existing entry — it always resolves regardless of file contents,
// so trying to overwrite it via the wizard would be confusing.
func (c *Config) LLMConfigExists(name string) bool {
	if c.raw == nil {
		return false
	}
	llmConfigs, ok := c.raw["llm_configs"].(map[string]any)
	if !ok {
		return false
	}
	_, exists := llmConfigs[name]
	return exists
}

// LLMConfigNames returns the names of user-authored llm-configs.
// Used by the setup wizard's intro to show the user what they already
// have. Does NOT include the built-in “openant-default“.
func (c *Config) LLMConfigNames() []string {
	if c.raw == nil {
		return nil
	}
	llmConfigs, ok := c.raw["llm_configs"].(map[string]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(llmConfigs))
	for name := range llmConfigs {
		out = append(out, name)
	}
	return out
}

// ProviderNames returns the names of user-authored providers.
// Same intro-display purpose as LLMConfigNames.
func (c *Config) ProviderNames() []string {
	if c.raw == nil {
		return nil
	}
	providers, ok := c.raw["llm_providers"].(map[string]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(providers))
	for name := range providers {
		out = append(out, name)
	}
	return out
}

// WriteLLMConfig persists a complete llm-config entry plus any new
// providers it depends on. The wizard collects user input into typed
// structures; this method handles the v2 schema gymnastics
// (initialising the raw map on fresh installs, pinning
// “$schema_version“, merging into existing “llm_providers“ /
// “llm_configs“ sections without clobbering siblings).
//
// “providers“ MAY include entries already present in the config —
// the wizard re-passes them when the user named an existing provider
// for a new phase. Overwrites are intentional: a key rotation
// (re-running “setup llm“ with a fresh key) should update the
// stored credential.
//
// “makeDefault“ flips “default_llm“ to “name“. The previous
// value is silently overwritten; the wizard is expected to confirm
// with the user first.
func (c *Config) WriteLLMConfig(
	name string,
	phases map[string]LLMPhaseRef,
	providers map[string]ProviderEntry,
	makeDefault bool,
) {
	if c.raw == nil {
		c.raw = map[string]any{}
	}

	// Pin the schema marker so a downgraded reader knows what to do.
	c.raw["$schema_version"] = 2

	// Providers section.
	provSection, _ := c.raw["llm_providers"].(map[string]any)
	if provSection == nil {
		provSection = map[string]any{}
		c.raw["llm_providers"] = provSection
	}
	for pname, p := range providers {
		// Merge into any existing entry so hand-authored sibling keys
		// (e.g. a future ``organization_id``) survive a wizard re-run,
		// instead of rebuilding the entry from the typed view and
		// dropping them.
		entry, _ := provSection[pname].(map[string]any)
		if entry == nil {
			entry = map[string]any{}
		}
		entry["type"] = p.Type
		if p.APIKey != "" {
			entry["api_key"] = p.APIKey
		} else {
			delete(entry, "api_key")
		}
		if p.BaseURL != "" {
			entry["base_url"] = p.BaseURL
		} else {
			delete(entry, "base_url")
		}
		provSection[pname] = entry
	}

	// LLM configs section.
	cfgSection, _ := c.raw["llm_configs"].(map[string]any)
	if cfgSection == nil {
		cfgSection = map[string]any{}
		c.raw["llm_configs"] = cfgSection
	}
	phaseMap := map[string]any{}
	for phase, ref := range phases {
		phaseMap[phase] = map[string]any{
			"provider": ref.Provider,
			"model":    ref.Model,
		}
	}
	cfgSection[name] = phaseMap

	if makeDefault {
		c.raw["default_llm"] = name
	}
}

// DataDir returns the root data directory: ~/.openant/
func DataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".openant"), nil
}

// ProjectsDir returns ~/.openant/projects/
func ProjectsDir() (string, error) {
	dataDir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "projects"), nil
}

// ProjectDir returns the directory for a specific project.
// Name is "org/repo", so the path is ~/.openant/projects/org/repo/
func ProjectDir(name string) (string, error) {
	projDir, err := ProjectsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(projDir, name), nil
}

// ScanDir returns the scan directory for a specific project, commit SHA, and language.
// ~/.openant/projects/org/repo/scans/{shortSHA}/{language}/
func ScanDir(projectName, shortSHA, language string) (string, error) {
	projDir, err := ProjectDir(projectName)
	if err != nil {
		return "", err
	}
	return filepath.Join(projDir, "scans", shortSHA, language), nil
}

// MaskKey returns a masked version of an API key for display. Long keys
// show the first 7 and last 4 characters; short keys (which shouldn't
// occur for real provider keys) are fully masked so we never slice out
// of range or reveal a whole key.
func MaskKey(key string) string {
	if key == "" {
		return "(not set)"
	}
	if len(key) < 8 {
		return "****"
	}
	if len(key) <= 12 {
		return key[:3] + "..." + key[len(key)-2:]
	}
	return key[:7] + "..." + key[len(key)-4:]
}
