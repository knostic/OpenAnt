// #664 behavioral tests: the per-language dimension preserves records.
package config

import (
	"testing"
	"time"
)

// TestTwoLanguagesSameSHA: a python scan followed by a go scan at the
// same SHA preserves BOTH records (the issue's core case).
func TestTwoLanguagesSameSHA(t *testing.T) {
	withTempHome(t)
	py := &ScanMeta{Kind: ScanKindFull, Commit: "x", StartedAt: "2026-04-28T00:00:00Z", Status: ScanStatusSuccess, Language: "python"}
	goMeta := &ScanMeta{Kind: ScanKindFull, Commit: "x", StartedAt: "2026-04-29T00:00:00Z", Status: ScanStatusRunning, Language: "go"}
	if err := SaveScanMeta("p", "sha1", "python", py); err != nil {
		t.Fatal(err)
	}
	if err := SaveScanMeta("p", "sha1", "go", goMeta); err != nil {
		t.Fatal(err)
	}
	gotPy, err := LoadScanMeta("p", "sha1", "python")
	if err != nil {
		t.Fatalf("python record lost: %v", err)
	}
	if gotPy.Status != ScanStatusSuccess {
		t.Fatalf("python status: %s", gotPy.Status)
	}
	gotGo, err := LoadScanMeta("p", "sha1", "go")
	if err != nil {
		t.Fatalf("go record lost: %v", err)
	}
	if gotGo.Status != ScanStatusRunning {
		t.Fatalf("go status: %s", gotGo.Status)
	}
}

// TestInitToScanRoundTrip: the init→scan handoff works when both use
// the same language key (the read/write contract fable executed).
func TestInitToScanRoundTrip(t *testing.T) {
	withTempHome(t)
	m := &ScanMeta{Kind: ScanKindDiff, Commit: "abc", Base: "origin/main", Scope: "callers", StartedAt: time.Now().UTC().Format(time.RFC3339), Status: ScanStatusRunning, Language: "auto"}
	if err := SaveScanMeta("p", "abc12345", "auto", m); err != nil {
		t.Fatal(err)
	}
	got, err := LoadScanMeta("p", "abc12345", "auto")
	if err != nil {
		t.Fatalf("init→scan handoff broken: %v", err)
	}
	if got.Base != "origin/main" {
		t.Fatalf("wrong base: %s", got.Base)
	}
}

// TestFinalizeFlipsRunningToSuccess: FinalizeScanMeta with the same key
// the writer used actually flips the status.
func TestFinalizeFlipsRunningToSuccess(t *testing.T) {
	withTempHome(t)
	m := &ScanMeta{Kind: ScanKindFull, Commit: "abc", StartedAt: time.Now().UTC().Format(time.RFC3339), Status: ScanStatusRunning, Language: "auto"}
	if err := SaveScanMeta("p", "abc12345", "auto", m); err != nil {
		t.Fatal(err)
	}
	if err := FinalizeScanMeta("p", "abc12345", "auto", ScanStatusSuccess); err != nil {
		t.Fatal(err)
	}
	got, err := LoadScanMeta("p", "abc12345", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ScanStatusSuccess {
		t.Fatalf("finalize did not flip: %s", got.Status)
	}
}

// TestLegacyFallback: a pre-#664 sha-level meta is still readable
// (the upgrade story).
func TestLegacyFallback(t *testing.T) {
	withTempHome(t)
	m := &ScanMeta{Kind: ScanKindFull, Commit: "abc", StartedAt: time.Now().UTC().Format(time.RFC3339), Status: ScanStatusSuccess, Language: "go"}
	// write to the LEGACY path (language="")
	if err := SaveScanMeta("p", "legacy123", "", m); err != nil {
		t.Fatal(err)
	}
	// read from the legacy path
	got, err := LoadScanMeta("p", "legacy123", "")
	if err != nil {
		t.Fatalf("legacy read failed: %v", err)
	}
	if got.Status != ScanStatusSuccess {
		t.Fatalf("legacy status: %s", got.Status)
	}
}

// Guard (b): the mixed-layout walk. A legacy sha-level SUCCESS plus a
// per-language running/failed record at the same sha — LatestScanMeta
// must still resolve the legacy success (the upgrader's last known-good
// scan). Fails when foundPerLang-style shadowing is present (astra-1).
func TestLatestScanMetaLegacyNotShadowedByPerLang(t *testing.T) {
	withTempHome(t)
	legacy := &ScanMeta{Kind: ScanKindFull, Commit: "x", StartedAt: "2026-04-28T00:00:00Z", Status: ScanStatusSuccess, Language: "python"}
	if err := SaveScanMeta("p", "sha1", "", legacy); err != nil {
		t.Fatal(err)
	}
	// a post-upgrade failed go scan at the same sha
	failed := &ScanMeta{Kind: ScanKindFull, Commit: "x", StartedAt: "2026-04-29T00:00:00Z", Status: ScanStatusFailed, Language: "go"}
	if err := SaveScanMeta("p", "sha1", "go", failed); err != nil {
		t.Fatal(err)
	}
	m, sha, err := LatestScanMeta("p")
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || sha == "" {
		t.Fatal("the legacy success was shadowed by a failed per-language record — the #664 complaint, recreated across the upgrade boundary")
	}
	if m.Status != ScanStatusSuccess {
		t.Fatalf("resolved a non-success: %+v", m)
	}
}

// Guard (d): the migrated legacy record does not double-resolve. When the
// legacy success WAS migrated to a per-language record of the same
// language, the legacy copy is dropped from the walk (identity dedup, not
// shadowing).
func TestLatestScanMetaMigratedLegacyDeduped(t *testing.T) {
	withTempHome(t)
	legacy := &ScanMeta{Kind: ScanKindFull, Commit: "x", StartedAt: "2026-04-28T00:00:00Z", Status: ScanStatusSuccess, Language: "python"}
	if err := SaveScanMeta("p", "sha1", "", legacy); err != nil {
		t.Fatal(err)
	}
	migrated := &ScanMeta{Kind: ScanKindFull, Commit: "x", StartedAt: "2026-04-28T00:00:00Z", Status: ScanStatusSuccess, Language: "python"}
	if err := SaveScanMeta("p", "sha1", "python", migrated); err != nil {
		t.Fatal(err)
	}
	m, _, err := LatestScanMeta("p")
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("the migrated record should still resolve")
	}
}

// Guard (e): the path-component validation (D4) — a language flag of
// "../.." must be rejected, not escape the project tree.
func TestScanMetaPathRejectsTraversal(t *testing.T) {
	withTempHome(t)
	if _, err := scanMetaPath("p", "sha1", "../.."); err == nil {
		t.Fatal("a traversal language key was accepted")
	}
	if err := SaveScanMeta("p", "sha1", "a/b", &ScanMeta{}); err == nil {
		t.Fatal("a multi-element language key was accepted")
	}
}
