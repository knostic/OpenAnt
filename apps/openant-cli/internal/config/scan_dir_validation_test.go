package config

import "testing"

// #691 (the persisted-value defense): ScanDir joins the language into the
// artifacts path for EVERY caller (init, resolve, project) — a stale or
// migrated project.json carrying a traversal value must not escape here.
// #676's validLanguageKey guards only the meta path; this is the same
// single-element rule on the artifacts path.
func TestScanDirRejectsNonElementLanguage(t *testing.T) {
	// THE #691 TRAVERSAL: the persisted escape value refuses.
	if _, err := ScanDir("org/repo", "deadbeef", "../../../../../../ESCAPED"); err == nil {
		t.Fatal("the traversal language must REJECT (the persisted escape shape)")
	}
	// A nested path element refuses.
	if _, err := ScanDir("org/repo", "deadbeef", "a/b"); err == nil {
		t.Fatal("a multi-element language must REJECT")
	}
	// "." and ".." refuse.
	if _, err := ScanDir("org/repo", "deadbeef", ".."); err == nil {
		t.Fatal(".. must REJECT")
	}
	// The honest forms pass: a concrete language, the auto pin, and the
	// legacy empty form (no language subdir — the parent scans dir).
	for _, lang := range []string{"python", "auto", ""} {
		if _, err := ScanDir("org/repo", "deadbeef", lang); err != nil {
			t.Errorf("the honest form %q must pass: %v", lang, err)
		}
	}
}
