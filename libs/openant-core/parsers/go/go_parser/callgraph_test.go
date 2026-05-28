package main

// Regression tests for four coupled defects in the Go call-graph resolver (callgraph.go).
//
// Receiver classification: isLikelyPackage classified ANY short
//   lowercase identifier (db, tx, ctx, w) as a package using a name-shape heuristic with no import
//   context, so local-variable method calls were misrouted to package resolution. Fix: classify a
//   selector receiver as a package iff its name is an import alias of the file.
// Package-call resolution: resolvePackageCall
//   resolved the import path correctly but matched candidates with strings.Contains(funcID, pkgAlias)
//   -- the alias, not the package directory -- so aliased imports failed and edges were emitted to
//   unrelated packages. Fix: match the package's directory (last path component of the import path).
// Dispatch: resolveCalls routed a plain function's simple call to resolveMethodCall
//   because `call.Receiver == callerInfo.ClassName` is ""=="" for a non-method caller. Fix: guard the
//   self/method branch on callerInfo.ClassName != "".
// os filtering: the entire "os" package was in the builtins skip-set, so os.StartProcess and
//   other OS sinks were dropped by the call-extraction filter. Fix: do not blanket-skip "os".
//
// Tests exercise stable-signature boundaries (extractCalls / resolvePackageCall / resolveCalls) so they
// compile against both the pre-fix and post-fix sources (RED demonstrated via `git stash` of the fix).

import "testing"

// receiver classification: local var must not be treated as a package
func TestExtractCalls_LocalVarNotClassifiedAsPackage(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["a/a.go"] = map[string]string{"fmt": "fmt"} // fmt imported; db is a local var
	fi := FunctionInfo{Name: "Run", FilePath: "a/a.go", Code: "func Run(){ db.Query() }"}

	calls := c.extractCalls(fi)
	if len(calls) != 1 || calls[0].Name != "Query" {
		t.Fatalf("expected one db.Query call, got %+v", calls)
	}
	ci := calls[0]
	if ci.Package != "" {
		t.Errorf("local var 'db' misclassified as package (Package=%q)", ci.Package)
	}
	if !ci.IsMethod || ci.Receiver != "db" {
		t.Errorf("db.Query() should be a method call on receiver 'db', got %+v", ci)
	}
}

// package resolution must match the package directory, not the alias
func TestResolvePackageCall_MatchesPackageDirNotAlias(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	// `import u "exp007/user"` -- alias 'u', package dir 'user'. The real target lives in user/.
	c.importsByFile["main/main.go"] = map[string]string{"u": "exp007/user"}
	// The unrelated candidate is FIRST and its path contains the alias 'u' as a substring (the old bug).
	c.functionsByName["Helper"] = []string{"unrelated/stuff.go:Helper", "user/user.go:Helper"}

	got := c.resolvePackageCall("Helper", "u", "main/main.go")
	if got != "user/user.go:Helper" {
		t.Errorf("expected resolution to the user/ package by directory, got %q "+
			"(alias-substring match would wrongly pick 'unrelated/stuff.go:Helper')", got)
	}
}

// a plain function's simple call must not be misrouted to method resolution
func TestResolveCalls_PlainFuncSimpleCallNotMisroutedToMethod(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.functionsByFile["a/a.go"] = []string{"a/a.go:main", "a/a.go:greet"}
	c.functionsByName["greet"] = []string{"a/a.go:greet"}

	caller := FunctionInfo{Name: "main", ClassName: "", FilePath: "a/a.go"}
	calls := []CallInfo{{Name: "greet", IsMethod: false, Receiver: "", IsSelf: false}}

	resolved := c.resolveCalls("a/a.go:main", caller, calls, nil)
	if len(resolved) != 1 || resolved[0] != "a/a.go:greet" {
		t.Errorf("plain func calling greet() should resolve to a/a.go:greet via simple-call, got %v "+
			"(\"\"==\"\" misroute to resolveMethodCall loses the edge)", resolved)
	}
}

// an os sink must not be filtered out as a builtin
func TestExtractCalls_OsSinkNotFilteredAsBuiltin(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	c.importsByFile["a/a.go"] = map[string]string{"os": "os", "fmt": "fmt"}
	fi := FunctionInfo{Name: "F", FilePath: "a/a.go", Code: "func F(){ os.StartProcess(); fmt.Println() }"}

	calls := c.extractCalls(fi)
	var sawOs, sawFmt bool
	for _, ci := range calls {
		if ci.Name == "StartProcess" {
			sawOs = true
		}
		if ci.Name == "Println" {
			sawFmt = true
		}
	}
	if !sawOs {
		t.Error("os.StartProcess() was wrongly filtered out as a builtin (os is a security sink, not noise)")
	}
	if sawFmt {
		t.Error("fmt.Println() should stay filtered as builtin noise")
	}
}
