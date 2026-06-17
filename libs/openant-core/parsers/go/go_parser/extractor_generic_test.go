package main

// Regression tests for the generic-type key-collapse bug family in the Go parser.
//
// Bug 1 (extractor.go typeToString): a method on a generic type — `func (s *Stack[T]) Push()` —
//   parses with an *ast.IndexExpr (one type param) or *ast.IndexListExpr (multiple) inside the
//   receiver. typeToString had no case for either, so it fell to `default: return "unknown"`,
//   making className "unknown". Every generic-type method across a repo then collapsed onto the
//   fake class `unknown`, and DISTINCT types' same-named methods collided onto one unit id —
//   silent data loss via map overwrite (output.Functions[id] = info).
//
// Bug 2 (callgraph.go analyzeCallExpr): generic CALL sites were dropped — `Gen[K,V]()`
//   (*ast.IndexListExpr) had no case, and `obj.M[T]()` (*ast.IndexExpr whose .X is a
//   *ast.SelectorExpr) was rejected by the `fun.X.(*ast.Ident)` guard — losing call edges.
//
// These tests exercise the stable public boundaries (Extract / extractCalls) so they compile
// against both pre-fix and post-fix sources; RED is demonstrated by running pre-fix.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempGo writes src to <dir>/m.go and returns the path; the relPath from the repo root
// (dir) is therefore "m.go", so unit ids are "m.go:<Class>.<Method>".
func writeTempGo(t *testing.T, src string) (repo, file string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "m.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write temp go: %v", err)
	}
	return dir, path
}

func extractIDs(t *testing.T, src string) map[string]FunctionInfo {
	t.Helper()
	repo, file := writeTempGo(t, src)
	out, err := NewExtractor(repo).Extract([]string{file})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return out.Functions
}

// Bug 1: generic receivers must key under the bare base type, never "unknown".
func TestGenericReceiver_ClassNameIsBaseType(t *testing.T) {
	src := `package main

type Stack[T any] struct{ items []T }
type Pair[K any, V any] struct{ k K; v V }
type Plain struct{}

func (s *Stack[T]) Push(x T)      {}        // *ast.StarExpr -> *ast.IndexExpr
func (s Stack[T]) PeekVal() (z T) { return }// value receiver: *ast.IndexExpr directly
func (p *Pair[K, V]) Key() (k K)  { return }// *ast.StarExpr -> *ast.IndexListExpr
func (p *Plain) Do()              {}        // control: *ast.Ident
`
	fns := extractIDs(t, src)
	want := []string{
		"m.go:Stack.Push",
		"m.go:Stack.PeekVal",
		"m.go:Pair.Key",
		"m.go:Plain.Do",
	}
	for _, id := range want {
		if _, ok := fns[id]; !ok {
			t.Errorf("missing unit id %q; got ids %v", id, keys(fns))
		}
	}
	for id := range fns {
		if strings.Contains(id, "unknown") {
			t.Errorf("unit id %q contains the bogus class key 'unknown'", id)
		}
	}
}

// Bug 1 (deeper, the data-loss regression): two DISTINCT generic types with a same-named method
// must produce two distinct units — pre-fix both collapsed to "m.go:unknown.Len" and the map
// overwrite silently dropped one.
func TestGenericTypes_NoUnitCollision(t *testing.T) {
	src := `package main

type Stack[T any] struct{}
type Queue[T any] struct{}

func (s *Stack[T]) Len() int { return 0 }
func (q *Queue[T]) Len() int { return 1 }
`
	fns := extractIDs(t, src)
	if _, ok := fns["m.go:Stack.Len"]; !ok {
		t.Errorf("missing m.go:Stack.Len; got %v", keys(fns))
	}
	if _, ok := fns["m.go:Queue.Len"]; !ok {
		t.Errorf("missing m.go:Queue.Len (silent collision/data-loss); got %v", keys(fns))
	}
	if len(fns) != 2 {
		t.Errorf("expected exactly 2 distinct method units, got %d: %v", len(fns), keys(fns))
	}
}

// Bug 2: generic call sites must recover the called name (and receiver for generic methods).
func TestCallgraph_GenericCalls(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	fi := FunctionInfo{
		Name:     "Run",
		FilePath: "a/a.go",
		Code: "func Run(){ " +
			"Gen[int](); " + // *ast.IndexExpr{Ident} — already worked (control)
			"Gen2[int,string](); " + // *ast.IndexListExpr — was dropped
			"o.M[int](); " + // *ast.IndexExpr{SelectorExpr} — was dropped
			"o.N[int,bool]() " + // *ast.IndexListExpr{SelectorExpr} — was dropped
			"}",
	}
	calls := c.extractCalls(fi)
	got := map[string]CallInfo{}
	for _, ci := range calls {
		got[ci.Name] = ci
	}
	for _, name := range []string{"Gen", "Gen2", "M", "N"} {
		if _, ok := got[name]; !ok {
			t.Errorf("generic call %q not recovered; got calls %+v", name, calls)
		}
	}
	// generic METHOD calls must also recover the receiver
	if ci, ok := got["M"]; ok && ci.Receiver != "o" {
		t.Errorf("o.M[int](): expected receiver 'o', got %q", ci.Receiver)
	}
	if ci, ok := got["N"]; ok && ci.Receiver != "o" {
		t.Errorf("o.N[int,bool](): expected receiver 'o', got %q", ci.Receiver)
	}
}

func keys(m map[string]FunctionInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
