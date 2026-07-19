package main

// Regression tests for cross-package method-collision resolution (callgraph.go:resolveMethodCall).
//
// methodsByType is keyed by the BARE receiver type name (funcInfo.ClassName), so two packages that
// each define a type "Store" with a method "Get" land in the same slice. buildIndexes appends in
// map-iteration order (`for _, funcInfo := range analyzer.Functions`), and the old resolveMethodCall
// returned the FIRST slice element whose id ends in ".<method>" -- ignoring the currentFile param
// entirely. The winning edge therefore depended on Go map-iteration order: nondeterministic and, on a
// collision, frequently the wrong (other-package) method.
//
// These tests pin the deterministic behavior: prefer the caller's own package, and break any
// remaining tie lexicographically. Both fail against the pre-fix source (which returns whichever
// candidate is first in the slice).

import "testing"

// A collision must resolve to the method defined in the CALLER's package, not whichever candidate
// happened to be indexed first.
func TestResolveMethodCall_CrossPkgCollisionPrefersCallerPackage(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	// The wrong (other-package) candidate is deliberately FIRST, mimicking an unlucky map order.
	c.methodsByType["Store"] = []string{"pkgb/b.go:Store.Get", "pkga/a.go:Store.Get"}

	got := c.resolveMethodCall("Get", "Store", "pkga/a.go")
	if got != "pkga/a.go:Store.Get" {
		t.Errorf("cross-package method collision must resolve to the caller's own package, got %q "+
			"(picking the first slice element depends on map-iteration order -> nondeterministic)", got)
	}
}

// With no same-package candidate, the choice must still be deterministic (lexicographically smallest
// funcID) rather than map-iteration-order dependent.
func TestResolveMethodCall_CrossPkgCollisionDeterministicTieBreak(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.methodsByType["Store"] = []string{"z/z.go:Store.Get", "a/a.go:Store.Get"}

	got := c.resolveMethodCall("Get", "Store", "other/o.go")
	if got != "a/a.go:Store.Get" {
		t.Errorf("cross-package collision with no same-package match must resolve deterministically "+
			"(lexicographically smallest funcID), got %q", got)
	}
}
