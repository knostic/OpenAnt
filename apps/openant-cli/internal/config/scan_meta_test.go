package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withTempHome points HOME at a temp dir for the duration of the test so
// ProjectDir / ScanRunDir resolve under there. Restores HOME on cleanup.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func TestSaveLoadScanMetaRoundTrip(t *testing.T) {
	withTempHome(t)

	want := &ScanMeta{
		Kind:            ScanKindFull,
		Commit:          "abc123def456",
		Branch:          "master",
		StartedAt:       "2026-04-28T11:53:30Z",
		FinishedAt:      "2026-04-28T11:55:12Z",
		Status:          ScanStatusSuccess,
		Language:        "python",
		AnalyzerVersion: "0.1.0",
		Model:           "opus",
	}
	if err := SaveScanMeta("test/proj", "abc123de", want); err != nil {
		t.Fatalf("SaveScanMeta: %v", err)
	}
	got, err := LoadScanMeta("test/proj", "abc123de")
	if err != nil {
		t.Fatalf("LoadScanMeta: %v", err)
	}
	if *got != *want {
		t.Errorf("round-trip mismatch:\n want=%+v\n  got=%+v", want, got)
	}
}

func TestSaveScanMetaWritesAtPredictablePath(t *testing.T) {
	home := withTempHome(t)
	m := &ScanMeta{Kind: ScanKindFull, Commit: "x", StartedAt: "2026-04-28T00:00:00Z", Status: ScanStatusRunning, Language: "python"}
	if err := SaveScanMeta("p", "shortsha", m); err != nil {
		t.Fatalf("SaveScanMeta: %v", err)
	}
	expected := filepath.Join(home, ".openant", "projects", "p", "scans", "shortsha", "meta.json")
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("meta.json not at expected path %s: %v", expected, err)
	}
}

func TestLoadScanMetaMissing(t *testing.T) {
	withTempHome(t)
	_, err := LoadScanMeta("never/initialized", "deadbeef")
	if err == nil {
		t.Fatal("expected error loading missing meta, got nil")
	}
}

func TestLatestScanMetaReturnsNewestSuccess(t *testing.T) {
	withTempHome(t)
	older := &ScanMeta{
		Kind:      ScanKindFull,
		Commit:    "older",
		StartedAt: time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		Status:    ScanStatusSuccess,
		Language:  "python",
	}
	newer := &ScanMeta{
		Kind:      ScanKindDiff,
		Commit:    "newer",
		Base:      "older",
		Scope:     "changed_functions",
		StartedAt: time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
		Status:    ScanStatusSuccess,
		Language:  "python",
	}
	if err := SaveScanMeta("p", "older0000", older); err != nil {
		t.Fatal(err)
	}
	if err := SaveScanMeta("p", "newer1111", newer); err != nil {
		t.Fatal(err)
	}

	got, sha, err := LatestScanMeta("p")
	if err != nil {
		t.Fatalf("LatestScanMeta: %v", err)
	}
	if got == nil {
		t.Fatal("expected a meta, got nil")
	}
	if sha != "newer1111" {
		t.Errorf("expected newer1111, got %s", sha)
	}
	if got.Commit != "newer" {
		t.Errorf("expected commit=newer, got %s", got.Commit)
	}
}

func TestLatestScanMetaSkipsFailedAndLegacyDirs(t *testing.T) {
	home := withTempHome(t)

	// Successful run.
	good := &ScanMeta{
		Kind: ScanKindFull, Commit: "good",
		StartedAt: time.Now().UTC().Add(-3 * time.Hour).Format(time.RFC3339),
		Status:    ScanStatusSuccess, Language: "python",
	}
	if err := SaveScanMeta("p", "goodshort", good); err != nil {
		t.Fatal(err)
	}

	// Failed run, more recent — should be skipped.
	failed := &ScanMeta{
		Kind: ScanKindFull, Commit: "failed",
		StartedAt: time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
		Status:    ScanStatusFailed, Language: "python",
	}
	if err := SaveScanMeta("p", "failedshrt", failed); err != nil {
		t.Fatal(err)
	}

	// Legacy run: a scans/<sha>/ dir with no meta.json. Should be skipped.
	legacyDir := filepath.Join(home, ".openant", "projects", "p", "scans", "legacysha")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}

	got, sha, err := LatestScanMeta("p")
	if err != nil {
		t.Fatalf("LatestScanMeta: %v", err)
	}
	if got == nil {
		t.Fatal("expected the successful meta, got nil")
	}
	if sha != "goodshort" {
		t.Errorf("expected goodshort, got %s", sha)
	}
}

func TestLatestScanMetaNoProject(t *testing.T) {
	withTempHome(t)
	got, sha, err := LatestScanMeta("does/not/exist")
	if err != nil {
		t.Fatalf("expected no error for missing project, got %v", err)
	}
	if got != nil || sha != "" {
		t.Errorf("expected nil/empty for missing project, got meta=%+v sha=%q", got, sha)
	}
}

func TestFinalizeScanMetaSetsTerminalStatus(t *testing.T) {
	withTempHome(t)
	m := NewScanMeta(ScanKindFull, "abc", "master", "python")
	if err := SaveScanMeta("p", "abcshort", m); err != nil {
		t.Fatal(err)
	}

	if err := FinalizeScanMeta("p", "abcshort", ScanStatusSuccess); err != nil {
		t.Fatalf("FinalizeScanMeta: %v", err)
	}

	got, err := LoadScanMeta("p", "abcshort")
	if err != nil {
		t.Fatalf("LoadScanMeta: %v", err)
	}
	if got.Status != ScanStatusSuccess {
		t.Errorf("expected status=success, got %s", got.Status)
	}
	if got.FinishedAt == "" {
		t.Error("expected FinishedAt to be set")
	}
	if _, err := time.Parse(time.RFC3339, got.FinishedAt); err != nil {
		t.Errorf("FinishedAt is not RFC3339: %v", err)
	}
}

func TestFinalizeScanMetaIsNoOpWhenMissing(t *testing.T) {
	withTempHome(t)
	if err := FinalizeScanMeta("never/seen", "deadbeef", ScanStatusSuccess); err != nil {
		t.Errorf("expected no error finalizing missing meta, got %v", err)
	}
}

func TestNewScanMetaSetsRunningAndTimestamp(t *testing.T) {
	m := NewScanMeta(ScanKindFull, "sha123", "master", "python")
	if m.Status != ScanStatusRunning {
		t.Errorf("expected status=running, got %s", m.Status)
	}
	if m.StartedAt == "" {
		t.Error("expected StartedAt to be set")
	}
	if _, err := time.Parse(time.RFC3339, m.StartedAt); err != nil {
		t.Errorf("StartedAt is not RFC3339: %v", err)
	}
	if m.Kind != ScanKindFull || m.Commit != "sha123" || m.Branch != "master" || m.Language != "python" {
		t.Errorf("fields not set correctly: %+v", m)
	}
}
