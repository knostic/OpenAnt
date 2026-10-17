package main

// #747 regression tests for resolvePackageCall.
//
// Two coupled defects in one loop at the base (callgraph.go:874-883):
//
//  1. the match key was the import path's LAST COMPONENT
//     (`pkgDir := filepath.Base(pkgPath)`), so every sibling directory named
//     `config` was a candidate for an import of `command/agent/config`;
//  2. the loop returned the FIRST match over `c.functionsByName[funcName]`, a
//     slice appended under Go MAP ITERATION in buildIndexes (:138-140), so the
//     winner was a different wrong package per process.
//
// The adjacent resolveMethodCall was repaired for exactly this class by PR
// #178 (its comment at :820-824 names "map-iteration order in buildIndexes ->
// nondeterministic/unstable edges"); the package-call path was not. These
// tests pin the port.
//
// Every test drives resolvePackageCall at its stable signature and seeds
// c.functionsByName DIRECTLY with the wrong candidate FIRST — so the RED is
// STRUCTURAL, not a sampled map-order coin flip (the same technique the
// pre-existing TestResolvePackageCall_MatchesPackageDirNotAlias uses).

import "testing"

// The reported defect: the import names a package the tree does not define,
// and two same-basename siblings do. The base emits an edge to a sibling;
// the only correct answer is no edge at all.
func TestResolvePackageCall_SameBasenameSiblingIsNotTheImportedPackage(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["cmd/main.go"] = map[string]string{"config": "fx747/z/config"}
	c.functionsByName["LoadConfig"] = []string{
		"a/config/config.go:LoadConfig",
		"b/config/config.go:LoadConfig",
	}

	got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
	if got != "" {
		t.Errorf("import is fx747/z/config, which this tree does not define; "+
			"resolution must be empty, got %q — a same-basename sibling is a "+
			"WRONG-PACKAGE edge, not an over-seed", got)
	}
}

// The imported package IS present alongside two same-basename siblings. The
// wrong candidates are listed FIRST, which is what the base's first-wins loop
// returns; the repair must reach past them to the imported package.
func TestResolvePackageCall_PrefersTheImportedPackageOverSameBasenameSiblings(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["cmd/main.go"] = map[string]string{"config": "fx747/z/config"}
	c.functionsByName["LoadConfig"] = []string{
		"a/config/config.go:LoadConfig",
		"b/config/config.go:LoadConfig",
		"z/config/config.go:LoadConfig",
	}

	got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
	if got != "z/config/config.go:LoadConfig" {
		t.Errorf("expected the IMPORTED package z/config, got %q", got)
	}
}

// Order-independence, stated as a property rather than sampled: the answer
// must be identical for every permutation of the candidate slice. A loop that
// returns the first match fails this for 5 of the 6 permutations; a fix that
// merely SORTS the index would pass only because the sort hides the order
// dependence, so the assertion is made on the unsorted permutations directly.
func TestResolvePackageCall_IsIndependentOfCandidateOrder(t *testing.T) {
	perms := [][]string{
		{"a/config/config.go:LoadConfig", "b/config/config.go:LoadConfig", "z/config/config.go:LoadConfig"},
		{"a/config/config.go:LoadConfig", "z/config/config.go:LoadConfig", "b/config/config.go:LoadConfig"},
		{"b/config/config.go:LoadConfig", "a/config/config.go:LoadConfig", "z/config/config.go:LoadConfig"},
		{"b/config/config.go:LoadConfig", "z/config/config.go:LoadConfig", "a/config/config.go:LoadConfig"},
		{"z/config/config.go:LoadConfig", "a/config/config.go:LoadConfig", "b/config/config.go:LoadConfig"},
		{"z/config/config.go:LoadConfig", "b/config/config.go:LoadConfig", "a/config/config.go:LoadConfig"},
	}
	for i, p := range perms {
		c := NewCallGraphBuilder("/repo")
		c.importsByFile["cmd/main.go"] = map[string]string{"config": "fx747/z/config"}
		c.functionsByName["LoadConfig"] = p
		got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
		if got != "z/config/config.go:LoadConfig" {
			t.Errorf("permutation %d %v resolved to %q, want z/config/config.go:LoadConfig "+
				"(the resolution must not depend on the candidate order)", i, p, got)
		}
	}
}

// The deepest matching package wins: a repo-root `config/` package and a
// nested `z/config/` package are both component-suffixes of the import
// `fx747/z/config`, and only the nested one is the real target.
func TestResolvePackageCall_DeepestImportPathSuffixWins(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["cmd/main.go"] = map[string]string{"config": "fx747/z/config"}
	c.functionsByName["LoadConfig"] = []string{
		"config/config.go:LoadConfig",
		"z/config/config.go:LoadConfig",
	}

	got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
	if got != "z/config/config.go:LoadConfig" {
		t.Errorf("the deepest import-path suffix (z/config) must win over the "+
			"shallower repo-root config/, got %q", got)
	}
}

// A genuinely ambiguous tie inside ONE package -- two build-tagged files in
// the same directory defining the same name -- must break stably, by the
// lexicographically smallest funcID, exactly as resolveMethodCall does. The
// issue body names this case: "14 of the 21 campaign flips are same-package
// method/function or build-tag ties the plain full-path match would not
// resolve".
func TestResolvePackageCall_BuildTagTieBreaksLexicographically(t *testing.T) {
	for _, order := range [][]string{
		{"z/config/unix.go:LoadConfig", "z/config/darwin.go:LoadConfig"},
		{"z/config/darwin.go:LoadConfig", "z/config/unix.go:LoadConfig"},
	} {
		c := NewCallGraphBuilder("/repo")
		c.importsByFile["cmd/main.go"] = map[string]string{"config": "fx747/z/config"}
		c.functionsByName["LoadConfig"] = order
		got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
		if got != "z/config/darwin.go:LoadConfig" {
			t.Errorf("candidates %v: a same-package tie must break to the "+
				"lexicographically smallest funcID, got %q", order, got)
		}
	}
}

// LOCK -- green at the base BY DESIGN, and it must stay green. PR #78 moved
// this site OFF the alias (`strings.Contains(funcID, pkgAlias)`) so that an
// aliased import resolves and a mere substring match does not fabricate.
// Those two gains must survive the #747 repair: the import path is
// `exp007/user`, the alias is `u`, and `unrelated/stuff.go` contains `u` as a
// substring and is listed FIRST.
func TestResolvePackageCall_AliasedImportStillResolvesByPath(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["main/main.go"] = map[string]string{"u": "exp007/user"}
	c.functionsByName["Helper"] = []string{
		"unrelated/stuff.go:Helper",
		"user/user.go:Helper",
	}

	got := c.resolvePackageCall("Helper", "u", "main/main.go")
	if got != "user/user.go:Helper" {
		t.Errorf("PR #78's gain must survive: an aliased import resolves by "+
			"package path and a substring of the alias does not match; got %q", got)
	}
}

// The FALLBACK's declared limitation, pinned so it is visible rather than
// silent: when NO go.mod in the scanned tree covers the import path -- an import
// of a module outside the tree, or a tree scanned from BELOW its go.mod, which
// the parser cannot read past -- an import path that shares no component tail
// with the tree resolves to NO edge, where the basename test produced one. It
// produced one by guessing: with a single same-basename candidate the guess was
// deterministic, with several it flipped per process. Both are fabricated edges,
// and WORKFLOW C5-graph's rule is that a fabricated edge is not a
// reachability-safe over-seed -- over-seeding real API is safe, a wrong edge
// misleads reachability -- so neither is kept.
//
// This test seeds no module map, which is what puts resolution on the fallback
// path; the shapes where a go.mod DOES cover the import path -- a module root in
// a subdirectory, a nested module with a /vN suffix, a module whose last
// component is also a directory name -- are resolved EXACTLY and are pinned in
// callgraph_modulepath_test.go. If this trade is ever reversed for the fallback,
// reverse it HERE: the alternative is "exactly one candidate whose
// filepath.Base(dir) equals path.Base(pkgPath)", and this test is the one that
// flips.
func TestResolvePackageCall_UnmirroredModulePathEmitsNoEdge(t *testing.T) {
	for _, candidates := range [][]string{
		{"sub/pkg/do.go:Do"},
		{"sub1/pkg/do.go:Do", "sub2/pkg/do.go:Do"},
	} {
		c := NewCallGraphBuilder("/repo")
		c.importsByFile["cmd/main.go"] = map[string]string{"pkg": "other.example/m/pkg"}
		c.functionsByName["Do"] = candidates

		got := c.resolvePackageCall("Do", "pkg", "cmd/main.go")
		if got != "" {
			t.Errorf("candidates %v share no component tail with the import "+
				"other.example/m/pkg, so any edge is a guess; got %q",
				candidates, got)
		}
	}
}

// A non-method candidate is preferred over a method of the same name in the
// same package: a package-qualified call cannot reach a method. The method is
// NOT excluded outright, because analyzeCallExpr (:762-770) classifies a
// selector as a package call on import-alias membership alone, so a local
// variable shadowing an import alias arrives here as a package call and its
// real method edge must still be reachable.
func TestResolvePackageCall_PrefersFunctionOverSameNamedMethod(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["cmd/main.go"] = map[string]string{"config": "fx747/z/config"}
	c.functionsByName["LoadConfig"] = []string{
		"z/config/a.go:Loader.LoadConfig",
		"z/config/b.go:LoadConfig",
	}

	got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
	if got != "z/config/b.go:LoadConfig" {
		t.Errorf("a package-qualified call reaches a function, not a method of "+
			"the same name in that package; got %q", got)
	}
}

// ...and when the ONLY candidate is a method, the edge is kept (the shadowed
// import-alias case above): dropping it would be a new false-negative class.
func TestResolvePackageCall_MethodOnlyCandidateKeepsItsEdge(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["cmd/main.go"] = map[string]string{"config": "fx747/z/config"}
	c.functionsByName["LoadConfig"] = []string{"z/config/a.go:Loader.LoadConfig"}

	got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
	if got != "z/config/a.go:Loader.LoadConfig" {
		t.Errorf("the only candidate in the imported package must keep its edge "+
			"(analyzeCallExpr routes a shadowed import alias here); got %q", got)
	}
}

// A PARTIAL component is not a match -- the property that actually distinguishes
// this repair from the basename test it replaces. "xz/config" and "z/configs"
// both contain a component that merely SHARES a prefix/suffix with one of the
// import path's components, and neither is the imported package. Asserted at the
// production boundary (resolvePackageCall) rather than against the scoring helper,
// so that this whole file still COMPILES against the pristine base and its RED is
// assertion-red, not absence-red: a test file referencing a post-fix symbol breaks
// the package build and masks every other witness's failure.
//
// NOTE on Windows, deliberately NOT asserted anywhere in this file: funcID file
// parts come from filepath.Rel (extractor.go:61), so on windows-latest they are
// backslash-separated while an import path never is. resolvePackageCall normalises
// with filepath.Dir + filepath.ToSlash, both separator-aware on Windows and no-ops
// on Unix -- so a backslash funcID is unreachable on a Unix runner and a test
// feeding one would assert an impossible state instead of the production path.
func TestResolvePackageCall_PartialComponentIsNotAMatch(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["cmd/main.go"] = map[string]string{"config": "fx747/z/config"}
	c.functionsByName["LoadConfig"] = []string{
		"xz/config/config.go:LoadConfig",
		"z/configs/config.go:LoadConfig",
	}

	got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
	if got != "" {
		t.Errorf("neither xz/config nor z/configs is the imported package "+
			"fx747/z/config -- a shared prefix or suffix inside one path "+
			"component is not a component match; got %q", got)
	}
}

// ...and the same import with a candidate directory DEEPER than the import path
// cannot be a component suffix of it, so it is not the imported package either.
func TestResolvePackageCall_CandidateDeeperThanImportPathIsNotAMatch(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["cmd/main.go"] = map[string]string{"config": "z/config"}
	c.functionsByName["LoadConfig"] = []string{
		"deeper/than/the/import/z/config/config.go:LoadConfig",
		"other/z/config/config.go:LoadConfig",
	}

	got := c.resolvePackageCall("LoadConfig", "config", "cmd/main.go")
	if got != "" {
		t.Errorf("both candidates are deeper than the import path z/config, so "+
			"neither is a component suffix of it and the pair is ambiguous on "+
			"basename alone; got %q", got)
	}
}
