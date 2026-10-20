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
// These tests pin the deterministic behavior: prefer the caller's own package, break a remaining
// same-package tie lexicographically, and — when NO same-package candidate exists — resolve to
// NO edge at all (#781: a cross-package winner through the bare-name registry is a fabrication,
// never the real target). Both fail against the pre-#746 source (which returns whichever
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

// With no same-package candidate, the resolution must be NO EDGE (#781): methodsByType and
// varTypes hold BARE type names, so a bare-written type is the caller's own package's type by
// construction and a cross-package winner is a bare-name collision — a fabricated reachability
// path, never the real target. The pre-#781 behavior (the lexicographically smallest
// cross-package candidate) was deterministic but still fabricated the edge; #781 rejects it.
// Declared residuals (the same trade #746's composite-literal gate ships): a dot-import
// (import . "m/f") and a type alias (type B = otherpkg.B) are the shapes where the other
// package's type IS written bare — those rare real edges are traded for the fabrication kill.
func TestResolveMethodCall_CrossPkgCollisionNoSamePackageIsNoEdge(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.methodsByType["Store"] = []string{"z/z.go:Store.Get", "a/a.go:Store.Get"}

	got := c.resolveMethodCall("Get", "Store", "other/o.go")
	if got != "" {
		t.Errorf("cross-package collision with no same-package candidate must resolve to NO edge "+
			"(#781: a bare-name collision fabricates a reachability path), got %q", got)
	}
}
