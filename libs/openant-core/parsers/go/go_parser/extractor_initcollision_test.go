package main

// Go permits several `init()` functions in a single file/package. makeFunctionID
// keyed a top-level func solely on `filePath:Name`, so every `init` in one file
// collapsed to the same unit id and all but the last were overwritten in
// output.Functions (data loss -> their bodies were never scanned for the call graph).

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtract_MultipleInitFuncsNotDropped(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n" +
		"func a(){ _ = 1 }\n" +
		"func b(){ _ = 1 }\n" +
		"func init(){ a() }\n" +
		"func init(){ b() }\n" +
		"func main(){}\n"
	path := filepath.Join(dir, "m.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := NewExtractor(dir).Extract([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	initCount := 0
	ids := make([]string, 0, len(out.Functions))
	for id, fi := range out.Functions {
		ids = append(ids, id)
		if fi.Name == "init" {
			initCount++
		}
	}
	if initCount != 2 {
		t.Fatalf("both init() functions must be extracted as distinct units; got %d init units, all ids: %v", initCount, ids)
	}
}
