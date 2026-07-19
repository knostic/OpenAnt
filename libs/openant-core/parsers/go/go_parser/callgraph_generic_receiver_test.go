package main

// Regression for go-self-deref-generic-receiver: a method whose receiver is a
// generic type — func (s *Stack[T]) Push(){ s.grow() } (*ast.IndexExpr) or
// func (p *Pair[K,V]) Set(){ p.norm() } (*ast.IndexListExpr) — must resolve the
// self-call edge (Push -> grow). Pre-fix, exprTypeName handled *ast.Ident and
// *ast.StarExpr (the deref) but had NO case for the type-parameter nodes, so the
// receiver variable's static type collapsed to "", ReceiverTypes was empty, and
// resolveCalls emitted no edge — the self-edge was silently dropped.

import "testing"

// Single type parameter: receiver *Stack[T] parses as *ast.StarExpr -> *ast.IndexExpr.
func TestGenericReceiverSelfCallEdge_IndexExpr(t *testing.T) {
	funcs := map[string]FunctionInfo{
		"m.go:Stack.Push": {Name: "Push", FilePath: "m.go", Package: "main", ClassName: "Stack",
			Receiver: "*Stack[T]",
			Code:     "func (s *Stack[T]) Push(x int) {\n\ts.grow()\n}"},
		"m.go:Stack.grow": {Name: "grow", FilePath: "m.go", Package: "main", ClassName: "Stack",
			Receiver: "*Stack[T]",
			Code:     "func (s *Stack[T]) grow() {}"},
	}
	cg := buildGraphForFuncs(t, funcs)
	if !hasEdge(cg, "m.go:Stack.Push", "m.go:Stack.grow") {
		t.Fatalf("expected self-edge m.go:Stack.Push -> m.go:Stack.grow, got %v", cg)
	}
}

// Multiple type parameters: receiver *Pair[K,V] parses as *ast.StarExpr -> *ast.IndexListExpr.
func TestGenericReceiverSelfCallEdge_IndexListExpr(t *testing.T) {
	funcs := map[string]FunctionInfo{
		"m.go:Pair.Set": {Name: "Set", FilePath: "m.go", Package: "main", ClassName: "Pair",
			Receiver: "*Pair[K, V]",
			Code:     "func (p *Pair[K, V]) Set(k int, v int) {\n\tp.norm()\n}"},
		"m.go:Pair.norm": {Name: "norm", FilePath: "m.go", Package: "main", ClassName: "Pair",
			Receiver: "*Pair[K, V]",
			Code:     "func (p *Pair[K, V]) norm() {}"},
	}
	cg := buildGraphForFuncs(t, funcs)
	if !hasEdge(cg, "m.go:Pair.Set", "m.go:Pair.norm") {
		t.Fatalf("expected self-edge m.go:Pair.Set -> m.go:Pair.norm, got %v", cg)
	}
}
