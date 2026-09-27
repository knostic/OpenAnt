package cmd

import (
	"strings"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
)

// #667 (the maintainer's REJECT-now ruling): an explicit `scan -l <other>`
// on a language-pinned project wrote another language's scan into the
// PINNED language's directory — replacing dataset.json/results.json in
// place while meta.json still recorded the pin and `status: success`.
// The guard REJECTS the explicit off-pin request at the CLI boundary
// (before any artifact write); the multi-language artifact routing is the
// later work (route-later). This is the regression guard on the guard.
func TestRejectOffPinLanguage(t *testing.T) {
	pinnedPy := &projectContext{Project: &config.Project{
		Name: "org/repo", Language: "python",
	}, ScanDir: "/fake/home/.openant/projects/org/repo/scans/deadbeef/python"}
	pinnedGo := &projectContext{Project: &config.Project{
		Name: "org/repo", Language: "go",
	}}
	pinnedAuto := &projectContext{Project: &config.Project{
		Name: "org/repo", Language: "auto",
	}}

	// THE #667 SHAPE: the explicit off-pin request on a concrete pin.
	err := rejectOffPinLanguage(pinnedPy, true, "go", pinnedPy.ScanDir)
	if err == nil {
		t.Fatal("explicit `scan -l go` on a python-pinned project must REJECT " +
			"(the off-pin scan would overwrite the pin's artifacts in place)")
	}
	for _, want := range []string{"#667", "python-pinned", "go"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection must name %q (got: %v)", want, err)
		}
	}

	// The symmetric shape: the other pin direction.
	if err := rejectOffPinLanguage(pinnedGo, true, "python", pinnedGo.ScanDir); err == nil {
		t.Error("explicit `scan -l python` on a go-pinned project must REJECT")
	}

	// An explicit request EQUAL to the pin is the honest same-language scan.
	if err := rejectOffPinLanguage(pinnedPy, true, "python", pinnedPy.ScanDir); err != nil {
		t.Errorf("an explicit same-language scan must pass (got: %v)", err)
	}

	// No explicit -l: the default adopts the pin (the existing behavior).
	if err := rejectOffPinLanguage(pinnedPy, false, "python", pinnedPy.ScanDir); err != nil {
		t.Errorf("a defaulted scan must pass (got: %v)", err)
	}

	// An auto-pinned project is multi-language by design: the explicit
	// request routes later, it does not overwrite a concrete pin.
	if err := rejectOffPinLanguage(pinnedAuto, true, "python", pinnedAuto.ScanDir); err != nil {
		t.Errorf("an auto-pinned project takes any language (route-later) (got: %v)", err)
	}

	// A bare-path scan (no project context) has no pin to overwrite.
	if err := rejectOffPinLanguage(nil, true, "go", ""); err != nil {
		t.Errorf("a projectless scan has no pin (got: %v)", err)
	}
	if err := rejectOffPinLanguage(&projectContext{}, true, "go", ""); err != nil {
		t.Errorf("a context without a project has no pin (got: %v)", err)
	}

	// The T1 round's F4: `-l auto` on a CONCRETE pin is rejected (the
	// multi merge replaces the pin's merged dataset with a single
	// language's) — a pinned choice now, not an accident.
	if err := rejectOffPinLanguage(pinnedPy, true, "auto", pinnedPy.ScanDir); err == nil {
		t.Error("`scan -l auto` on a python-pinned project must REJECT " +
			"(the multi merge overwrites the pin's merged dataset)")
	}

	// The T1 round's F2: an unsupported language names the real problem
	// (the supported set), never the init remedy that pins garbage.
	err = rejectOffPinLanguage(pinnedPy, true, "cobol", pinnedPy.ScanDir)
	if err == nil || !strings.Contains(err.Error(), "not a supported language") {
		t.Errorf("an unsupported -l must name the supported set (got: %v)", err)
	}

	// The delta round's D1: `-o ""` re-defaults to the pin (the effective
	// output IS the pin) — the exemption must NOT fire; the overwrite is
	// the same shape as no -o at all.
	if err := rejectOffPinLanguage(pinnedPy, true, "go", pinnedPy.ScanDir); err == nil {
		t.Error("an effective output EQUAL to the pin must reject (the -o-empty shape)")
	}
	// ...and an -o ELSEWHERE exempts (the claim would be false there) —
	// the delta round's D4: the exemption is TESTED now (the deletion
	// mutant passed before).
	if err := rejectOffPinLanguage(pinnedPy, true, "go", "/tmp/elsewhere"); err != nil {
		t.Errorf("an -o elsewhere must exempt (got: %v)", err)
	}
	// The round-4 F-1: the Clean/Abs compare is TESTED — the non-canonical
	// spellings of the pin path (the tab-completion form) must reject, not
	// exempt (the raw-compare mutant survived before).
	for _, spelling := range []string{pinnedPy.ScanDir + "/", pinnedPy.ScanDir + "/./", pinnedPy.ScanDir + "/../python"} {
		if err := rejectOffPinLanguage(pinnedPy, true, "go", spelling); err == nil {
			t.Errorf("the non-canonical pin spelling %q must REJECT (the F-A bypass)", spelling)
		}
	}
	// An empty effective output (a projectless form) behaves as the pin.
	if err := rejectOffPinLanguage(pinnedPy, true, "go", ""); err == nil {
		t.Error("an empty effective output (the pin default) must reject")
	}

	// An empty pin (a legacy project.json without the language field)
	// behaves as auto: no concrete pin to protect.
	empty := &projectContext{Project: &config.Project{Name: "org/repo"}}
	if err := rejectOffPinLanguage(empty, true, "go", ""); err != nil {
		t.Errorf("an empty pin is not a concrete pin (got: %v)", err)
	}
}
