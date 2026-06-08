package main

// Regression test for BUG-NEW-2026-06-04-go-dataflow_loss: a call through a
// function-value alias (f := helper; f()) must emit an edge caller -> helper,
// mirroring the direct call helper().

import "testing"

// buildGraphForFuncs runs the full call-graph build over a synthetic
// AnalyzerOutput (same shape the extractor emits) and returns the call graph.
func buildGraphForFuncs(t *testing.T, funcs map[string]FunctionInfo) map[string][]string {
	t.Helper()
	builder := NewCallGraphBuilder(".")
	analyzer := &AnalyzerOutput{RepoRoot: ".", Functions: funcs}
	// Index directly (parseImports reads real files; none of these synthetic
	// funcs use package-qualified calls, so an empty import table is fine).
	for funcID, funcInfo := range analyzer.Functions {
		builder.functionsByName[funcInfo.Name] = append(builder.functionsByName[funcInfo.Name], funcID)
		builder.functionsByFile[funcInfo.FilePath] = append(builder.functionsByFile[funcInfo.FilePath], funcID)
		if funcInfo.ClassName != "" {
			builder.methodsByType[funcInfo.ClassName] = append(builder.methodsByType[funcInfo.ClassName], funcID)
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

func hasEdge(cg map[string][]string, from, to string) bool {
	for _, t := range cg[from] {
		if t == to {
			return true
		}
	}
	return false
}

// Baseline control: a direct call helper() resolves to an edge.
func TestDirectCallEdge(t *testing.T) {
	funcs := map[string]FunctionInfo{
		"main.go:helper": {Name: "helper", FilePath: "main.go", Package: "main",
			Code: "func helper() int {\n\treturn 42\n}"},
		"main.go:caller": {Name: "caller", FilePath: "main.go", Package: "main",
			Code: "func caller() int {\n\treturn helper()\n}"},
	}
	cg := buildGraphForFuncs(t, funcs)
	if !hasEdge(cg, "main.go:caller", "main.go:helper") {
		t.Fatalf("baseline: expected edge main.go:caller -> main.go:helper, got %v", cg)
	}
}

// BUG-19: a func-value alias f := helper; f() must resolve to the same edge.
func TestFuncValueAliasEdge(t *testing.T) {
	funcs := map[string]FunctionInfo{
		"main.go:helper": {Name: "helper", FilePath: "main.go", Package: "main",
			Code: "func helper() int {\n\treturn 42\n}"},
		"main.go:caller": {Name: "caller", FilePath: "main.go", Package: "main",
			Code: "func caller() int {\n\tf := helper\n\treturn f()\n}"},
	}
	cg := buildGraphForFuncs(t, funcs)
	if !hasEdge(cg, "main.go:caller", "main.go:helper") {
		t.Fatalf("alias: expected edge main.go:caller -> main.go:helper, got %v", cg)
	}
}

// Precision guard: a reassigned/conditional alias must NOT produce a false edge.
func TestFuncValueAliasReassignedNoEdge(t *testing.T) {
	funcs := map[string]FunctionInfo{
		"main.go:helper": {Name: "helper", FilePath: "main.go", Package: "main",
			Code: "func helper() int {\n\treturn 42\n}"},
		"main.go:other": {Name: "other", FilePath: "main.go", Package: "main",
			Code: "func other() int {\n\treturn 7\n}"},
		"main.go:caller": {Name: "caller", FilePath: "main.go", Package: "main",
			Code: "func caller() int {\n\tf := helper\n\tf = other\n\treturn f()\n}"},
	}
	cg := buildGraphForFuncs(t, funcs)
	if hasEdge(cg, "main.go:caller", "main.go:helper") {
		t.Fatalf("reassigned: must NOT resolve f() to helper after f=other, got %v", cg)
	}
}
