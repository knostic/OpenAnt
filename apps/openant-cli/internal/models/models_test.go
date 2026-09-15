package models

import "testing"

// These tests are the network-free proof that the setup wizard's prefills and
// hints resolve to LIVE models — the structural replacement for eyeballing the
// old hardcoded maps. They never touch a provider API (the interactive wizard's
// probeAnthropic/etc. issue real billed requests; none of that runs here).

// Review blocker (#346): ollama was missing — every (provider, phase) the
// wizard can prefill must resolve, including the local provider.
var testProviderTypes = []string{"anthropic", "openai", "google", "ollama"}

// Every (provider, phase) the wizard can prefill must resolve to a NON-EMPTY id
// whose registry record is "current" — never retired/unknown, which is exactly
// the 404-on-fresh-install bug this replaces (setup.go used to prefill the
// retired claude-opus-4-6 / claude-sonnet-4-20250514).
func TestDefaultModelResolvesCurrentForEveryPhaseAndProvider(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	for phase := range phaseTier {
		for _, prov := range testProviderTypes {
			id, err := cfg.DefaultModel(prov, phase)
			if err != nil {
				t.Errorf("DefaultModel(%q, %q): unexpected error: %v", prov, phase, err)
				continue
			}
			if id == "" {
				t.Errorf("DefaultModel(%q, %q): empty id", prov, phase)
				continue
			}
			rec := cfg.find(id)
			if rec == nil {
				t.Errorf("DefaultModel(%q, %q)=%q: not in registry", prov, phase, id)
				continue
			}
			if rec.Status != "current" {
				t.Errorf("DefaultModel(%q, %q)=%q: status %q, want current", prov, phase, id, rec.Status)
			}
		}
	}
}

// The exact call the plan names, exercised through the package-level entry point
// (which Load()s the registry itself).
func TestDefaultModelAnthropicAnalyze(t *testing.T) {
	id, err := DefaultModel("anthropic", "analyze")
	if err != nil {
		t.Fatalf("DefaultModel(anthropic, analyze): %v", err)
	}
	if id == "" {
		t.Fatal("DefaultModel(anthropic, analyze): empty id")
	}
}

// The hint list must be non-empty per provider and contain ONLY current ids —
// the old hardcoded knownModels listed retired ids (claude-opus-4-6).
func TestKnownModelsAreCurrentOnly(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	for _, prov := range testProviderTypes {
		ids := cfg.KnownModels(prov)
		if len(ids) == 0 {
			t.Errorf("KnownModels(%q): empty", prov)
			continue
		}
		for _, id := range ids {
			rec := cfg.find(id)
			if rec == nil || rec.Status != "current" {
				t.Errorf("KnownModels(%q) returned %q with record %v, want a current model", prov, id, rec)
			}
		}
	}
}

// A provider type or phase with no mapping must error rather than hand back an
// empty (or wrong) default — the wizard treats that error as "no prefill".
func TestDefaultModelRejectsUnknownPhaseAndProvider(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if _, err := cfg.DefaultModel("anthropic", "no_such_phase"); err == nil {
		t.Error("DefaultModel with unknown phase: want error, got nil")
	}
	if _, err := cfg.DefaultModel("no_such_provider", "analyze"); err == nil {
		t.Error("DefaultModel with unknown provider: want error, got nil")
	}
}
