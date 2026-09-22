// #664 review guards (M5): the four shapes the adversarial panel derived.
// Each one FAILS when its target defect is present — the fix-linkage the
// previous attempt lacked (reverting the fix hunk fails a named test).
package cmd

import (
	"testing"

	config "github.com/knostic/open-ant-cli/internal/config"
)

// Guard (a): the cmd-layer init-write → scan-adopt round trip. A config-
// package test with literal args CANNOT detect a key mismatch between two
// CALLERS; only a cmd-layer round trip can (init writes at its language,
// resolveScanMode adopts what init wrote). Fails when the adoption key
// diverges from the init key (the F1 class).
func TestInitWriteScanAdoptRoundTrip(t *testing.T) {
	withTempHome(t)
	// init's write: pending diff decision under the pin "python"
	meta := config.NewScanMeta(config.ScanKindDiff, "current", "main", "python")
	meta.Base = "from-init"
	meta.Scope = "callers"
	if err := config.SaveScanMeta("p", "currshort", "python", meta); err != nil {
		t.Fatal(err)
	}
	// the scan (no mode flags, same language) adopts the pending decision
	savedFull, savedIncremental, savedDiffBase, savedPR, savedStaged := scanFull, scanIncremental, scanDiffBase, scanPR, scanStaged
	savedLang := scanLanguage
	defer func() {
		scanFull, scanIncremental, scanDiffBase, scanPR, scanStaged = savedFull, savedIncremental, savedDiffBase, savedPR, savedStaged
		scanLanguage = savedLang
	}()
	scanFull, scanIncremental, scanDiffBase, scanPR, scanStaged = false, false, "", 0, false
	scanLanguage = "python"
	ctx := &projectContext{Project: &config.Project{Name: "p", CommitSHAShort: "currshort", Language: "python"}}
	got, err := resolveScanMode(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.Base != "from-init" || got.Scope != "callers" || got.Kind != config.ScanKindDiff {
		t.Fatalf("adoption lost init's decision: %+v", got)
	}
}

// Guard (c): `scan -l go` on a python-pinned project writes AND finalizes
// the GO record; python's pending record is untouched. Fails when the
// writer or finalizer keys on the pin (astra-2 / F1's mirror).
func TestScanLanguageOverrideWritesOwnRecord(t *testing.T) {
	withTempHome(t)
	// python's pending init record
	pyMeta := config.NewScanMeta(config.ScanKindDiff, "current", "main", "python")
	pyMeta.Base = "from-init"
	if err := config.SaveScanMeta("p", "currshort", "python", pyMeta); err != nil {
		t.Fatal(err)
	}
	savedFull, savedIncremental, savedDiffBase, savedPR, savedStaged := scanFull, scanIncremental, scanDiffBase, scanPR, scanStaged
	savedLang := scanLanguage
	defer func() {
		scanFull, scanIncremental, scanDiffBase, scanPR, scanStaged = savedFull, savedIncremental, savedDiffBase, savedPR, savedStaged
		scanLanguage = savedLang
	}()
	scanFull, scanIncremental, scanDiffBase, scanPR, scanStaged = true, false, "", 0, false // --full: no adoption
	scanLanguage = "go"
	ctx := &projectContext{Project: &config.Project{Name: "p", CommitSHAShort: "currshort", Language: "python"}}
	if _, err := resolveScanMode(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// the scan's own record: go/meta.json, Language "go"
	got, err := config.LoadScanMeta("p", "currshort", "go")
	if err != nil {
		t.Fatalf("the go run has no record (the F1 class): %v", err)
	}
	if got.Language != "go" {
		t.Fatalf("go record stamped %q — the record must stamp the run's language", got.Language)
	}
	// finalize hits the record the scan wrote
	finalizeScanMetaIfProject(ctx, config.ScanStatusSuccess)
	got, err = config.LoadScanMeta("p", "currshort", "go")
	if err != nil || got.Status != config.ScanStatusSuccess {
		t.Fatalf("finalize did not flip the go record: %v %+v", err, got)
	}
	// python's pending record untouched
	py, err := config.LoadScanMeta("p", "currshort", "python")
	if err != nil {
		t.Fatalf("python's record destroyed: %v", err)
	}
	if py.Status != config.ScanStatusRunning || py.Base != "from-init" {
		t.Fatalf("python's record was modified by the go run: %+v", py)
	}
}
