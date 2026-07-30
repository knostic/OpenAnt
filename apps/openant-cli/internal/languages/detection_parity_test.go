package languages

// A7: Go<->Python language-DETECTION parity (Go half).
//
// Consumes the SAME shared golden as the Python twin
// (libs/openant-core/tests/test_detection_parity.py) so the expected outcomes
// are single-sourced and cannot drift. Reuses writeTree from registry_test.go.
//
// Non-error fixtures: compare Ranked(DetectLanguages(tree)) to the golden list.
// Error fixtures: DetectLanguages (plural) returns empty+nil here, so the
// "no supported files" outcome surfaces at DetectLanguage (singular) / empty
// Ranked -- assert that, matching Python detect_languages raising ValueError.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func goldenPath(t *testing.T) string {
	t.Helper()
	// package dir is apps/openant-cli/internal/languages; repo root is 4 up.
	p := filepath.Join("..", "..", "..", "..", "config", "testdata", "detection_parity.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("shared golden not found at %s: %v", p, err)
	}
	return p
}

type parityFixture struct {
	Name   string          `json:"name"`
	Tree   []string        `json:"tree"`
	Expect json.RawMessage `json:"expect"`
}

func loadParityFixtures(t *testing.T) []parityFixture {
	t.Helper()
	raw, err := os.ReadFile(goldenPath(t))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var doc struct {
		Fixtures []parityFixture `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(doc.Fixtures) < 7 {
		t.Fatalf("golden has %d fixtures, want >= 7", len(doc.Fixtures))
	}
	return doc.Fixtures
}

func TestDetectionParityAgainstSharedGolden(t *testing.T) {
	for _, fx := range loadParityFixtures(t) {
		fx := fx
		t.Run(fx.Name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, fx.Tree)

			// Is this an error fixture? expect == {"error": true}
			var errObj struct {
				Error bool `json:"error"`
			}
			if json.Unmarshal(fx.Expect, &errObj) == nil && errObj.Error {
				if _, err := DetectLanguage(dir); err == nil {
					t.Fatalf("%s: expected an error outcome, got none", fx.Name)
				}
				return
			}

			var want []string
			if err := json.Unmarshal(fx.Expect, &want); err != nil {
				t.Fatalf("%s: bad golden expect: %v", fx.Name, err)
			}
			counts, err := DetectLanguages(dir)
			if err != nil {
				t.Fatalf("%s: DetectLanguages error: %v", fx.Name, err)
			}
			got := Ranked(counts)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: detected %v, golden expects %v", fx.Name, got, want)
			}
		})
	}
}
