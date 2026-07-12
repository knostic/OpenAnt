package main

// A package-level `var h = func(){ ... }` is a GenDecl with a FuncLit initializer.
// extractFromFile walked only *ast.FuncDecl, so such a var was never emitted as a unit
// and its body was never scanned -> a function reachable only through it was orphaned.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtract_PackageLevelVarFuncLit(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n" +
		"var pkgHandler = func(){ named() }\n" +
		"func named(){ _ = 1 }\n" +
		"func main(){ pkgHandler() }\n"
	path := filepath.Join(dir, "m.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := NewExtractor(dir).Extract([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	var handler *FunctionInfo
	ids := make([]string, 0, len(out.Functions))
	for id, fi := range out.Functions {
		ids = append(ids, id)
		if fi.Name == "pkgHandler" {
			f := fi
			handler = &f
		}
	}
	if handler == nil {
		t.Fatalf("package-level var func literal `pkgHandler` must be extracted as a unit; got %v", ids)
	}
	// Its body must be scannable so the call graph can reach `named` through it.
	c := NewCallGraphBuilder(dir)
	calls := c.extractCalls(*handler)
	reachesNamed := false
	for _, ci := range calls {
		if ci.Name == "named" {
			reachesNamed = true
		}
	}
	if !reachesNamed {
		t.Fatalf("pkgHandler's body call to named() must be captured; got %+v", calls)
	}
}
