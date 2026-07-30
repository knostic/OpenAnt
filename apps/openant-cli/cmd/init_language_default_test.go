package cmd

import (
	"strings"
	"testing"
)

// The `-l` flag used to be REQUIRED with an empty default, which meant `openant
// init <repo>` errored and every user had to name one language up front. Since
// `scan` passes the stored value as an explicit -l, and explicit beats auto, that
// pinned a project to a single language permanently — so "scan all languages, not
// just the main one" could never be true through the product's primary flow.
//
// This is a regression guard on the fix and on the shape of the mistake: the first
// attempt added a `if initLanguage == "" { initLanguage = "auto" }` branch, which
// was DEAD CODE because the required flag meant empty was unreachable. The bug was
// only visible by running the binary, which is why this test exists at the flag
// level rather than asserting on the resolution logic.
func TestInitLanguageDefaultsToAutoAndIsNotRequired(t *testing.T) {
	flag := initCmd.Flags().Lookup("language")
	if flag == nil {
		t.Fatal("init has no --language flag")
	}
	if flag.DefValue != "auto" {
		t.Errorf("--language default = %q, want \"auto\"; without it `openant init <repo>` "+
			"pins the project to one language", flag.DefValue)
	}

	// cobra records required-ness in the flag's annotations.
	if ann := flag.Annotations["cobra_annotation_bash_completion_one_required_flag"]; len(ann) > 0 {
		t.Error("--language is marked required; that removes the default and forces " +
			"every project into a single language")
	}
}

func TestInitLanguageHelpDescribesAutoAsScanAll(t *testing.T) {
	// The help text is what tells a user what `auto` means. It described a
	// "dominance heuristic" — the old single-language behaviour — for a flag whose
	// semantics had changed, which is worse than no help.
	usage := initCmd.Flags().Lookup("language").Usage
	if usage == "" {
		t.Fatal("no usage text for --language")
	}
	for _, stale := range []string{"dominance", "experimental"} {
		if strings.Contains(usage, stale) {
			t.Errorf("--language help still describes the old behaviour (%q): %s", stale, usage)
		}
	}
}
