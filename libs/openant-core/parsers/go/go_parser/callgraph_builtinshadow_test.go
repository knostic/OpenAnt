package main

// Regression tests for the builtin-shadow filter.
//
// The builtins skip-set is meant to drop calls to the LANGUAGE builtin (len,
// make, min, ...). But when the repo defines its OWN function of that name a
// bare call resolves to the user function and the edge is real, so the builtin
// filter must be bypassed. Go builtin shadowing is PACKAGE/BLOCK-scoped, NOT
// repo-global: a user `min` in one package does not disable the builtin `min`
// in another. So the bypass is scoped to the caller's own file / package
// (mirroring resolveSimpleCall's priorities 1 & 2 and the Python/C parsers'
// same-file scoping) and must NOT consult the repo-global name index —
// otherwise a genuine builtin call in an unrelated package survives the filter
// and is then mis-resolved to a cross-package user func via
// resolveSimpleCall's len(candidates)==1 uniqueness gate (a false edge that
// poisons reachability). Sites covered: the plain call-expr filter
// (callgraph.go) and the range-over-func filter.

import "testing"

func hasCall(calls []CallInfo, name string) bool {
	for _, ci := range calls {
		if ci.Name == name {
			return true
		}
	}
	return false
}

// plain call: `len()` where the SAME FILE defines its own func named `len`.
func TestExtractCalls_UserFuncShadowingBuiltinNotDropped(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.functionsByName["len"] = []string{"a/a.go:len"}
	c.functionsByFile["a/a.go"] = []string{"a/a.go:len"} // same-file shadow
	fi := FunctionInfo{Name: "F", FilePath: "a/a.go", Code: "func F(){ len() }"}

	if !hasCall(c.extractCalls(fi), "len") {
		t.Errorf("call to same-file user func 'len' (shadowing the builtin) was dropped by the builtins filter")
	}
}

// range-over-func sibling site: `for range gen` where the same file shadows a
// builtin name (`new`) with its own iterator func.
func TestExtractCalls_RangeOverUserFuncShadowingBuiltinNotDropped(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.functionsByName["new"] = []string{"a/a.go:new"}
	c.functionsByFile["a/a.go"] = []string{"a/a.go:new"} // same-file shadow
	fi := FunctionInfo{Name: "F", FilePath: "a/a.go", Code: "func F(){ for range new {} }"}

	if !hasCall(c.extractCalls(fi), "new") {
		t.Errorf("range-over same-file user func 'new' (shadowing the builtin) was dropped by the builtins filter")
	}
}

// same-PACKAGE (different file) shadow is also kept: Go shadowing is
// package-scoped, so a user `len` in another file of the same dir shadows the
// builtin for this caller too.
func TestExtractCalls_SamePackageShadowNotDropped(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.functionsByName["len"] = []string{"pkg/other.go:len"}
	c.functionsByFile["pkg/other.go"] = []string{"pkg/other.go:len"} // same dir as caller
	fi := FunctionInfo{Name: "F", FilePath: "pkg/main.go", Code: "func F(){ len() }"}

	if !hasCall(c.extractCalls(fi), "len") {
		t.Errorf("call to same-package user func 'len' (shadowing the builtin) was dropped by the builtins filter")
	}
}

// negative control: a genuine builtin call with NO user func of that name stays filtered.
func TestExtractCalls_GenuineBuiltinStillFiltered(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	fi := FunctionInfo{Name: "F", FilePath: "a/a.go", Code: "func F(){ len([]int{}) }"}

	if hasCall(c.extractCalls(fi), "len") {
		t.Errorf("genuine builtin len() should stay filtered when no user func shadows it")
	}
}

// CROSS-PACKAGE negative regression (the FA3 gap): a genuine builtin `min()` in
// package a, plus an UNRELATED user func `min` in package b. Repo-global
// shadowing (functionsByName) would KEEP this builtin call (because a `min`
// exists SOMEWHERE), after which resolveSimpleCall's unique-name gate
// (len(candidates)==1) mis-resolves it to b.min — a false cross-package edge.
// Package-scoped shadowing must still FILTER the builtin here: package a defines
// no `min`, so the call is the language builtin and must be dropped.
func TestExtractCalls_CrossPackageBuiltinNotShadowed(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.functionsByName["min"] = []string{"b/b.go:min"}    // user min ONLY in pkg b
	c.functionsByFile["b/b.go"] = []string{"b/b.go:min"} // unrelated package
	// caller lives in pkg a and calls the genuine builtin min()
	fi := FunctionInfo{Name: "F", FilePath: "a/a.go", Code: "func F(){ min(1, 2) }"}

	if hasCall(c.extractCalls(fi), "min") {
		t.Errorf("genuine builtin min() in pkg a must NOT be kept just because an unrelated user 'min' exists in pkg b (repo-global bypass would emit a false cross-package edge)")
	}
}
