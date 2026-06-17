package main

// Guard test for the duplicate-unit-id store hazard (substrate defense-in-depth).
//
// The extractor stores units as `output.Functions[funcID] = info`. If two distinct declarations
// resolve to the same funcID — the failure mode behind the generic-receiver class-key collapse,
// where many methods became "m.go:unknown.Name" — the second write silently overwrites the first
// and a real unit vanishes with no signal. duplicateIDWarning makes that collision observable
// (the caller logs it to stderr) so a future unhandled shape fails loudly instead of silently.

import (
	"strings"
	"testing"
)

func TestDuplicateIDWarning_NoCollision(t *testing.T) {
	fns := map[string]FunctionInfo{}
	if w := duplicateIDWarning(fns, "m.go:Stack.Len", FunctionInfo{FilePath: "m.go", StartLine: 10}); w != "" {
		t.Errorf("expected no warning for a fresh id, got %q", w)
	}
	// A different id sharing the map must also not warn.
	fns["m.go:Stack.Len"] = FunctionInfo{FilePath: "m.go", StartLine: 10}
	if w := duplicateIDWarning(fns, "m.go:Queue.Len", FunctionInfo{FilePath: "m.go", StartLine: 20}); w != "" {
		t.Errorf("expected no warning for a distinct id, got %q", w)
	}
}

func TestDuplicateIDWarning_Collision(t *testing.T) {
	fns := map[string]FunctionInfo{
		"m.go:unknown.Len": {FilePath: "m.go", StartLine: 10},
	}
	w := duplicateIDWarning(fns, "m.go:unknown.Len", FunctionInfo{FilePath: "m.go", StartLine: 20})
	if w == "" {
		t.Fatal("expected a warning when funcID already present (silent overwrite), got none")
	}
	if !strings.Contains(w, "m.go:unknown.Len") {
		t.Errorf("warning should name the colliding id; got %q", w)
	}
}
