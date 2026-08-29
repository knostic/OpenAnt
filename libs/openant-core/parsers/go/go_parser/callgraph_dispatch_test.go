package main

// Regression test for issue #299 (Go member — 1 of 7): container-literal
// dispatch loses call edges, and the generic-instantiation IndexExpr unwrap
// misreads map/slice indexing, producing a FALSE edge to a same-named
// function while the real dispatch target gets nothing.
//
// Contract:
//   - a package-scope container of function references (map[string]func(){...}
//     / []func(){...}) plus a subscript call handlers[k]() records edges to
//     every function the container references — over-seed, the safe direction;
//   - NO edge to a function that merely shares the container's name (the
//     shadow/false-edge case — the issue's highest-severity finding);
//   - generic instantiation fn[T]() keeps resolving (the unwrap's purpose);
//   - a method value (f := v.Method; f()) survives when the receiver's type
//     is locally known;
//   - a subscript over an UNKNOWN name records nothing (abstain over guess).

import (
	"os"
	"path/filepath"
	"testing"
)

// buildGraphForFiles writes real files and runs the full builder the way the
// pipeline does (file-scope containers are only visible when the file is
// parsed, not from synthetic function bodies).
func buildGraphForFiles(t *testing.T, files0 map[string]string) map[string][]string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files0 {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	builder := NewCallGraphBuilder(dir)
	analyzer := &AnalyzerOutput{RepoRoot: dir, Functions: map[string]FunctionInfo{}}
	for funcID, funcInfo := range analyzer.Functions {
		_ = funcID
		_ = funcInfo
	}
	// Extract functions from the real files through the standard extractor
	// path so Code/FilePath are populated exactly as production does.
	ex := NewExtractor(dir)
	files := make([]string, 0, len(files0))
	for name := range files0 {
		files = append(files, filepath.Join(dir, name))
	}
	if out, err := ex.Extract(files); err == nil && out != nil {
		for k, v := range out.Functions {
			analyzer.Functions[k] = v
		}
	}
	for funcID, funcInfo := range analyzer.Functions {
		builder.functionsByName[funcInfo.Name] = append(builder.functionsByName[funcInfo.Name], funcID)
		builder.functionsByFile[funcInfo.FilePath] = append(builder.functionsByFile[funcInfo.FilePath], funcID)
		if funcInfo.ClassName != "" {
			builder.methodsByType[funcInfo.ClassName] = append(builder.methodsByType[funcInfo.ClassName], funcID)
		}
		// #299: the harness bypasses buildIndexes, so collect file containers
		// the way buildIndexes does (imports are not needed by these fixtures).
		if builder.containersByFile[funcInfo.FilePath] == nil {
			builder.collectFileContainers(filepath.Join(dir, funcInfo.FilePath), funcInfo.FilePath)
		}
	}
	cg := make(map[string][]string)
	for funcID, funcInfo := range analyzer.Functions {
		calls := builder.extractCalls(funcInfo)
		resolved := builder.resolveCalls(funcID, funcInfo, calls, analyzer)
		if len(resolved) > 0 {
			cg[funcID] = resolved
		}
	}
	return cg
}

const dispatchSrc = `package main

func handlerA() int { return 1 }
func handlerB() int { return 2 }
func directTarget() int { return 3 }
func handlers() int { return 4 } // SHADOW: shares the container's name

var handlers = map[string]func() int{"a": handlerA, "b": handlerB}
var fnSlice = []func() int{handlerB}

func dispatch(k string, i int) int {
	handlers[k]()
	return fnSlice[i]()
}

func control() int { return directTarget() }
`

func TestContainerDispatchEdges(t *testing.T) {
	cg := buildGraphForFiles(t, map[string]string{"main.go": dispatchSrc})
	if !hasEdge(cg, "main.go:dispatch", "main.go:handlerA") {
		t.Errorf("dispatch must edge to handlerA via the map container; got %v", cg)
	}
	if !hasEdge(cg, "main.go:dispatch", "main.go:handlerB") {
		t.Errorf("dispatch must edge to handlerB via the map container; got %v", cg)
	}
	if !hasEdge(cg, "main.go:control", "main.go:directTarget") {
		t.Errorf("control edge must survive; got %v", cg)
	}
}

func TestNoFalseEdgeToSameNamedFunction(t *testing.T) {
	// The shadow case: the OLD unwrap collapsed dispatchTable[k] to the bare
	// identifier, which could resolve to a same-named function. It must not.
	cg := buildGraphForFiles(t, map[string]string{"main.go": dispatchSrc})
	if hasEdge(cg, "main.go:dispatch", "main.go:handlers") {
		t.Errorf("FALSE EDGE: dispatch -> handlers recorded (the container's own name resolved to a function); got %v", cg)
	}
	// and the shadow function itself is not the dispatch target: handlerA/B are
	if !hasEdge(cg, "main.go:dispatch", "main.go:handlerA") {
		t.Errorf("the REAL dispatch target handlerA must get the edge; got %v", cg)
	}
}

func TestContainerTargetsHaveDispatcherAsCaller(t *testing.T) {
	cg := buildGraphForFiles(t, map[string]string{"main.go": dispatchSrc})
	for _, h := range []string{"main.go:handlerA", "main.go:handlerB"} {
		callers := cg // forward graph only in this harness; check via edges from dispatch
		_ = callers
		if !hasEdge(cg, "main.go:dispatch", h) {
			t.Errorf("caller set of %s must contain the DISPATCHER specifically; got %v", h, cg)
		}
	}
}

const genericSrc = `package main

type Num interface{ int | float64 }

func genericFn[T Num](v T) T { return v }

func useGeneric() int {
	return genericFn[int](3)
}
`

func TestGenericInstantiationStillResolves(t *testing.T) {
	// The unwrap exists for fn[T](); the discrimination must preserve it.
	cg := buildGraphForFiles(t, map[string]string{"gen.go": genericSrc})
	if !hasEdge(cg, "gen.go:useGeneric", "gen.go:genericFn") {
		t.Errorf("generic instantiation fn[T]() must keep its edge; got %v", cg)
	}
}

const unknownSubscriptSrc = `package main

func sink() int { return 1 }

func useUnknown(k string) int {
	data := map[string]int{"a": 1}
	return data[k] + sink()
}
`

func TestUnknownSubscriptRecordsNothing(t *testing.T) {
	cg := buildGraphForFiles(t, map[string]string{"u.go": unknownSubscriptSrc})
	if hasEdge(cg, "u.go:useUnknown", "u.go:useUnknown") {
		t.Errorf("no self edge expected")
	}
	// data[k] is an int map: no function edge; sink() still resolves.
	if !hasEdge(cg, "u.go:useUnknown", "u.go:sink") {
		t.Errorf("direct call must resolve; got %v", cg)
	}
}

const methodValueSrc = `package main

type Widget struct{}

func (w Widget) Compute() int { return 1 }

func useMethodValue() int {
	v := Widget{}
	f := v.Compute
	return f()
}
`

func TestMethodValueSurvives(t *testing.T) {
	cg := buildGraphForFiles(t, map[string]string{"m.go": methodValueSrc})
	if !hasEdge(cg, "m.go:useMethodValue", "m.go:Widget.Compute") {
		t.Errorf("method value f := v.Compute; f() must edge to Widget.Compute; got %v", cg)
	}
}
