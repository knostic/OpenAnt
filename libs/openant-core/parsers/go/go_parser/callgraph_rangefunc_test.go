package main

// Go 1.23 range-over-func: `for v := range seqFunc { ... }` invokes seqFunc as an
// iterator, so it is a call edge. extractCalls walked only *ast.CallExpr and missed
// the RangeStmt form, so a function reachable only as a range iterator was dropped.
// A non-function range expression (slice/map/channel/int) is either not a bare
// identifier or simply does not resolve later, so no false edge is introduced.

import "testing"

func TestExtractCalls_RangeOverFunc(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	fi := FunctionInfo{
		Name:     "run2",
		FilePath: "a/a.go",
		Code:     "func run2(){ for v := range seqFunc { _ = v } }",
	}
	calls := c.extractCalls(fi)
	found := false
	for _, ci := range calls {
		if ci.Name == "seqFunc" {
			found = true
		}
	}
	if !found {
		t.Fatalf("range-over-func `range seqFunc` must record a call to seqFunc; got %+v", calls)
	}
}

func TestExtractCalls_RangeOverSliceNotACall(t *testing.T) {
	// Precision: ranging over a plain slice ident is recorded as a candidate name but
	// is not a builtin; it simply will not resolve to a function later. It must at
	// least not be mistaken for a *method* or *package* call here.
	c := NewCallGraphBuilder("/repo")
	fi := FunctionInfo{
		Name:     "loop",
		FilePath: "a/a.go",
		Code:     "func loop(items []int){ for _, x := range items { _ = x } }",
	}
	for _, ci := range c.extractCalls(fi) {
		if ci.Name == "items" && (ci.IsMethod || ci.Package != "") {
			t.Fatalf("range over slice `items` must not be a method/package call; got %+v", ci)
		}
	}
}
