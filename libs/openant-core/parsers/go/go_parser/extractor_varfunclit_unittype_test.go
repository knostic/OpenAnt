package main

// A package-level `var Handler = func(w http.ResponseWriter, r *http.Request){...}`
// is a func-valued var whose unit_type must be classified like any other function
// (here: http_handler). extractVarFuncLit hardcoded UnitTypeFunction, bypassing
// classifyUnitType, so such a var was mis-tagged "function" and never seeded as an
// HTTP entry point downstream.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtract_VarFuncLit_ClassifiedAsHTTPHandler(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n" +
		"import \"net/http\"\n" +
		"var Handler = func(w http.ResponseWriter, r *http.Request){ w.Write([]byte(\"ok\")) }\n" +
		"func main(){ _ = Handler }\n"
	path := filepath.Join(dir, "m.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := NewExtractor(dir).Extract([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	var handler *FunctionInfo
	for _, fi := range out.Functions {
		if fi.Name == "Handler" {
			f := fi
			handler = &f
		}
	}
	if handler == nil {
		t.Fatalf("var func literal `Handler` must be extracted as a unit")
	}
	if handler.UnitType != UnitTypeHTTPHandler {
		t.Fatalf("var func literal HTTP handler misclassified: got unit_type %q, want %q",
			handler.UnitType, UnitTypeHTTPHandler)
	}
}
