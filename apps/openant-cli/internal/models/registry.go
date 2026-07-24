// Package models is the Go-side reader for config/models.json, the shared
// provider-model registry (the same file core/model_registry.py reads on the
// Python side). It exists so the setup wizard's model prefills and hint lists
// are DERIVED from and VALIDATED against that registry rather than hardcoded —
// cmd/setup.go previously baked literal defaults that named retired model IDs
// (claude-opus-4-6, claude-sonnet-4-20250514), so a fresh user's config 404'd on
// every phase.
//
// Unlike the Python side this package reads NO pricing — the wizard only needs
// model IDs and their current/retired status. Pricing (and its null-is-never-$0
// invariant) stays entirely in core/model_registry.py.
//
// Missing config is a LOUD failure here (like internal/languages), not a silent
// degrade: prefilling a default and validating it is real work, and a wizard
// that can't read the registry should say so rather than suggest nothing.
package models

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// modelRecord mirrors one entry of the "models" array in config/models.json.
// Only the fields the wizard needs are decoded; price/source/retrieved are
// ignored (Go drops unknown JSON keys).
type modelRecord struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Status   string `json:"status"`
}

// Config is the parsed form of config/models.json.
type Config struct {
	Models []modelRecord `json:"models"`
}

// phaseTier maps each pipeline phase to the capability tier its wizard-prefill
// model should come from. This is the wizard's UX intent — which is NOT
// expressed in config/models.json — and it reproduces exactly the per-phase tier
// split cmd/setup.go shipped before this reader existed (stronger reasoning for
// detection / verification / reachability review; lighter/faster models for the
// generation phases enhance / report / dynamic_test / app_context).
var phaseTier = map[string]string{
	"app_context":  "light",
	"llm_reach":    "strong",
	"enhance":      "light",
	"analyze":      "strong",
	"verify":       "strong",
	"dynamic_test": "light",
	"report":       "light",
}

// tierModel maps (provider, tier) to the model id the wizard pre-fills. These
// are CURRENT ids; DefaultModel VALIDATES each against config/models.json and
// refuses to return one that is missing or retired, so a future retirement in
// the registry surfaces as a failing prefill (and unit test) rather than a
// silently-404'ing default. The non-anthropic values are unchanged from the
// pre-registry setup.go; only the anthropic ids moved off the retired
// claude-opus-4-6 / claude-sonnet-4-20250514 onto the current equivalents.
var tierModel = map[string]map[string]string{
	"anthropic": {"strong": "claude-opus-4-8", "light": "claude-sonnet-4-6"},
	"openai":    {"strong": "gpt-4o", "light": "gpt-4o-mini"},
	"google":    {"strong": "gemini-1.5-pro", "light": "gemini-2.0-flash"},
}

// FindConfig locates config/models.json by walking up from the executable path
// and then the current working directory — the same strategy (and 6-level
// bound) internal/languages.FindConfig uses for languages.json.
func FindConfig() (string, error) {
	rel := filepath.Join("config", "models.json")

	if exePath, err := os.Executable(); err == nil {
		exePath, _ = filepath.EvalSymlinks(exePath)
		dir := filepath.Dir(exePath)
		for range 6 {
			candidate := filepath.Join(dir, rel)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for range 6 {
			candidate := filepath.Join(dir, rel)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return "", fmt.Errorf("could not find config/models.json from executable or working directory")
}

// Load reads and parses the shared model registry. Fails loud (returns an error)
// when the config is missing or malformed.
func Load() (*Config, error) {
	path, err := FindConfig()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return &cfg, nil
}

// find returns the record for a model id, or nil.
func (c *Config) find(id string) *modelRecord {
	for i := range c.Models {
		if c.Models[i].ID == id {
			return &c.Models[i]
		}
	}
	return nil
}

// DefaultModel returns the wizard's pre-fill model id for (provider, phase),
// validated to be a CURRENT registry entry. It errors when (provider, phase) has
// no mapping, or when the mapped id is absent from the registry or not
// "current" — so a retired/unknown default can never be handed to the wizard.
func (c *Config) DefaultModel(provider, phase string) (string, error) {
	tier, ok := phaseTier[phase]
	if !ok {
		return "", fmt.Errorf("no default-model tier for phase %q", phase)
	}
	byTier, ok := tierModel[provider]
	if !ok {
		return "", fmt.Errorf("no default models for provider type %q", provider)
	}
	id, ok := byTier[tier]
	if !ok {
		return "", fmt.Errorf("no %q-tier default model for provider type %q", tier, provider)
	}
	rec := c.find(id)
	if rec == nil {
		return "", fmt.Errorf("default model %q (provider %q, phase %q) is not in the registry", id, provider, phase)
	}
	if rec.Status != "current" {
		return "", fmt.Errorf("default model %q (provider %q, phase %q) has status %q, not current", id, provider, phase, rec.Status)
	}
	return id, nil
}

// KnownModels returns the CURRENT model ids for a provider type, sorted. Sourced
// entirely from the registry, so the wizard's hint list can never show a retired
// id (unlike the old hardcoded knownModels map, which listed claude-opus-4-6).
func (c *Config) KnownModels(provider string) []string {
	var ids []string
	for _, rec := range c.Models {
		if rec.Provider == provider && rec.Status == "current" {
			ids = append(ids, rec.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// DefaultModel is the package-level convenience: load the registry (fail loud on
// a missing config), then resolve+validate the (provider, phase) prefill.
func DefaultModel(provider, phase string) (string, error) {
	cfg, err := Load()
	if err != nil {
		return "", err
	}
	return cfg.DefaultModel(provider, phase)
}

// KnownModels is the package-level convenience mirror of DefaultModel.
func KnownModels(provider string) ([]string, error) {
	cfg, err := Load()
	if err != nil {
		return nil, err
	}
	return cfg.KnownModels(provider), nil
}
