package main

// #747, second round: a cross-package call resolves through the MODULE PATH
// declared by the tree's go.mod files, not through a trailing-component guess.
//
// The first round scored a candidate by how many whole path components of its
// directory matched the TAIL of the import path. That is sound only when the
// module path mirrors the directory layout, and three ordinary layouts break it
// because the module path itself is never read:
//
//   1. the module root is a SUBDIRECTORY of the scanned root (a polyglot repo
//      with one `backend/go.mod`, scanned from the repo root, which is what the
//      pipeline passes): `backend/` appears in no import path, so EVERY
//      cross-package edge in the module is lost;
//   2. a nested module carries a major-version suffix (`sdk/go.mod` declaring
//      `.../sdk/v2`): no directory is ever named `v2`, so every import of that
//      module is lost -- measured at -2,680 correct edges on the issue's own
//      corpus (openbao);
//   3. the module path's last component is ALSO a directory name (module
//      `example.com/x/app`, directories `config/` and `app/config/`): the
//      deeper candidate wins, which is the WRONG package -- `go list` resolves
//      `example.com/x/app/config` to `config/`.
//
// Reading each go.mod's module path makes all three exact. These tests drive the
// whole production pipeline -- Scanner, Extractor, CallGraphBuilder -- over real
// temporary trees, and reference no post-fix symbol, so this file compiles
// against the pre-repair tree and its RED is an ASSERTION failure rather than a
// build break that would mask every other witness in the package.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeTree materialises files (repo-relative path -> content) under a fresh
// temporary directory and returns its path.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// calleesOf runs the real pipeline over root and returns the sorted callees
// recorded for callerID, cross-checked against the reverse graph (the
// reachability consumer reads the transpose, so a forward edge without its
// transpose is silently lost downstream).
func calleesOf(t *testing.T, root, callerID string) []string {
	t.Helper()
	scanner := NewScanner(root, false)
	scanResult, err := scanner.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	analyzer, err := NewExtractor(root).Extract(scanner.GetFilePaths(scanResult))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, ok := analyzer.Functions[callerID]; !ok {
		ids := make([]string, 0, len(analyzer.Functions))
		for id := range analyzer.Functions {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Fatalf("the FIXTURE is broken, not the parser: caller %q was not "+
			"extracted; extracted %v", callerID, ids)
	}
	graph, err := NewCallGraphBuilder(root).BuildCallGraph(analyzer)
	if err != nil {
		t.Fatalf("callgraph: %v", err)
	}
	forward := append([]string{}, graph.CallGraph[callerID]...)
	sort.Strings(forward)
	var reverse []string
	for callee, callers := range graph.ReverseCallGraph {
		for _, caller := range callers {
			if caller == callerID {
				reverse = append(reverse, callee)
			}
		}
	}
	sort.Strings(reverse)
	if strings.Join(forward, ",") != strings.Join(reverse, ",") {
		t.Fatalf("forward/reverse asymmetry for %s: %v vs %v", callerID, forward, reverse)
	}
	return forward
}

func wantCallees(t *testing.T, root, callerID string, want []string, why string) {
	t.Helper()
	got := calleesOf(t, root, callerID)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s\n  caller %s\n  want  %v\n  got   %v", why, callerID, want, got)
	}
}

// F1: ONE go.mod in a subdirectory -- the ordinary polyglot layout -- scanned
// from the repo root, which is the path the pipeline passes. `backend/` occurs
// in no import path, so a component-suffix score is 0 for every candidate and
// every cross-package edge inside the module disappears. There is only ONE
// candidate here, so not even ambiguity excuses the loss.
func TestModulePath_ModuleRootInASubdirectoryStillResolves(t *testing.T) {
	root := writeTree(t, map[string]string{
		"frontend/app.js":                 "console.log('not Go');\n",
		"backend/go.mod":                  "module example.com/svc\n\ngo 1.21\n",
		"backend/cmd/main.go":             "package main\n\nimport \"example.com/svc/internal/store\"\n\nfunc main() { _ = store.Open() }\n",
		"backend/internal/store/store.go": "package store\n\nfunc Open() string { return \"store\" }\n",
	})
	wantCallees(t, root, "backend/cmd/main.go:main",
		[]string{"backend/internal/store/store.go:Open"},
		"the module root is backend/, so example.com/svc/internal/store IS "+
			"backend/internal/store -- dropping the only candidate loses a "+
			"correct edge")
}

// F3: a nested module with a major-version suffix -- `sdk/go.mod` declaring
// `fx747mod/sdk/v2`, the exact shape of openbao's own sdk and api modules. No
// directory is named `v2`, so the component-suffix score is 0 for the real
// target; the same-basename decoy in `internal/jsonutil` is what a basename
// match would have emitted instead. Both go.mod files cover the import path
// here, so this also pins that the LONGEST (most specific) module path wins:
// resolving against the root module would give `sdk/v2/helper/jsonutil`.
func TestModulePath_NestedModuleWithMajorVersionSuffixResolves(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                     "module fx747mod\n\ngo 1.21\n",
		"sdk/go.mod":                 "module fx747mod/sdk/v2\n\ngo 1.21\n",
		"cmd/main.go":                "package main\n\nimport \"fx747mod/sdk/v2/helper/jsonutil\"\n\nfunc main() { _ = jsonutil.Decode() }\n",
		"sdk/helper/jsonutil/j.go":   "package jsonutil\n\nfunc Decode() string { return \"sdk\" }\n",
		"internal/jsonutil/decoy.go": "package jsonutil\n\nfunc Decode() string { return \"decoy\" }\n",
	})
	wantCallees(t, root, "cmd/main.go:main",
		[]string{"sdk/helper/jsonutil/j.go:Decode"},
		"fx747mod/sdk/v2/helper/jsonutil is sdk/helper/jsonutil: the /v2 belongs "+
			"to the MODULE PATH, not to any directory, and internal/jsonutil is "+
			"a different package entirely")
}

// F2: the module path's last component is also a directory name. `go list` is
// the ground truth and says `example.com/x/app/config` is `config/`:
//
//	$ go list -f '{{.ImportPath}} -> {{.Dir}}' example.com/x/app/config
//	example.com/x/app/config -> <tree>/config
//
// A trailing-component score prefers the DEEPER `app/config/`, turning a
// coin-flip into a guaranteed wrong edge. Real shapes: a repo whose inner
// directory repeats the module name (hashicorp/vault has vault/).
func TestModulePath_ModuleLastComponentIsAlsoADirectoryName(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":               "module example.com/x/app\n\ngo 1.21\n",
		"cmd/main.go":          "package main\n\nimport \"example.com/x/app/config\"\n\nfunc main() { _ = config.Load() }\n",
		"config/config.go":     "package config\n\nfunc Load() string { return \"root config\" }\n",
		"app/config/config.go": "package config\n\nfunc Load() string { return \"app config\" }\n",
	})
	wantCallees(t, root, "cmd/main.go:main",
		[]string{"config/config.go:Load"},
		"the module is example.com/x/app at the root, so .../app/config is "+
			"config/, never the deeper app/config/ (go list, above, is the "+
			"ground truth)")
}

// The go.mod grammar permits a quoted path and permits the directive in
// factored form, and gofmt leaves both alone. Asserted through the SAME layout
// as the test above, so a module directive this parser cannot read is not a
// silent degradation to the guess -- it would resolve to app/config/ and fail
// here.
func TestModulePath_FactoredAndQuotedModuleDirectiveIsRead(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":               "// a leading comment\nmodule (\n\t\"example.com/x/app\" // the path\n)\n\ngo 1.21\n\nrequire (\n\texample.com/dep v1.2.3\n)\n",
		"cmd/main.go":          "package main\n\nimport \"example.com/x/app/config\"\n\nfunc main() { _ = config.Load() }\n",
		"config/config.go":     "package config\n\nfunc Load() string { return \"root config\" }\n",
		"app/config/config.go": "package config\n\nfunc Load() string { return \"app config\" }\n",
	})
	wantCallees(t, root, "cmd/main.go:main",
		[]string{"config/config.go:Load"},
		"a factored, quoted, comment-trailed module directive is still the "+
			"module path")
}

// The exactness has to cut both ways, or it is just another guess: when a
// go.mod DOES cover the import path, the only answer is the directory that path
// names, and a miss is NO edge rather than a fall-through to the heuristic.
// `b/store/` here is a genuine component suffix of the import path, so it is
// exactly what the fallback would have offered -- and it is still the wrong
// package.
func TestModulePath_InModuleImportOfAMissingPackageEmitsNoEdge(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":       "module example.com/m\n\ngo 1.21\n",
		"cmd/main.go":  "package main\n\nimport \"example.com/m/a/b/store\"\n\nfunc main() { _ = store.Open() }\n",
		"b/store/s.go": "package store\n\nfunc Open() string { return \"not the imported package\" }\n",
	})
	wantCallees(t, root, "cmd/main.go:main", nil,
		"example.com/m/a/b/store is a/b/store, which this tree does not "+
			"define; b/store is a component suffix of the import path and "+
			"still the wrong package, so the exact step must NOT fall through "+
			"to the heuristic")
}

// A module path covers an import path only on WHOLE components. Module
// `example.com/m` is a string prefix of `example.com/mother/pkg`, which belongs
// to a different module altogether, so it must not be rewritten into this
// tree's `other/pkg`.
func TestModulePath_ModulePathCoversOnlyWholeComponents(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":         "module example.com/m\n\ngo 1.21\n",
		"cmd/main.go":    "package main\n\nimport \"example.com/mother/pkg\"\n\nfunc main() { _ = pkg.Open() }\n",
		"other/pkg/p.go": "package pkg\n\nfunc Open() string { return \"not in example.com/m\" }\n",
	})
	wantCallees(t, root, "cmd/main.go:main", nil,
		"example.com/mother is not example.com/m plus a path component, so "+
			"no directory in this module is the imported package")
}

// Two go.mod files declaring the SAME module path -- a copied module in one
// tree -- must still resolve to one canonical answer on every process, not to
// whichever the map happened to visit first. The documented tie-break is the
// lexicographically smallest directory.
func TestModulePath_DuplicateModulePathResolvesCanonically(t *testing.T) {
	files := map[string]string{
		"one/go.mod":   "module example.com/dup\n\ngo 1.21\n",
		"two/go.mod":   "module example.com/dup\n\ngo 1.21\n",
		"one/pkg/a.go": "package pkg\n\nfunc Open() string { return \"one\" }\n",
		"two/pkg/b.go": "package pkg\n\nfunc Open() string { return \"two\" }\n",
		"cmd/go.mod":   "module example.com/caller\n\ngo 1.21\n",
		"cmd/main.go":  "package main\n\nimport \"example.com/dup/pkg\"\n\nfunc main() { _ = pkg.Open() }\n",
	}
	for i := 0; i < 8; i++ {
		root := writeTree(t, files)
		wantCallees(t, root, "cmd/main.go:main",
			[]string{"one/pkg/a.go:Open"},
			"a module path declared twice must resolve to the lexicographically "+
				"smallest directory on EVERY process, not to Go map order")
	}
}

// LOCK, green before and after: when NO go.mod in the tree covers the import
// path -- a tree scanned from BELOW its module root, which the parser cannot
// read past, or a module genuinely outside the tree -- the component-suffix
// heuristic is still the best available evidence and must keep resolving. If
// this ever goes red, the fallback was dropped, not improved.
func TestModulePath_SuffixFallbackSurvivesWithoutAnyGoMod(t *testing.T) {
	root := writeTree(t, map[string]string{
		"cmd/main.go":        "package main\n\nimport \"example.com/m/z/config\"\n\nfunc main() { _ = config.Load() }\n",
		"z/config/config.go": "package config\n\nfunc Load() string { return \"z\" }\n",
		"a/config/config.go": "package config\n\nfunc Load() string { return \"a\" }\n",
	})
	wantCallees(t, root, "cmd/main.go:main",
		[]string{"z/config/config.go:Load"},
		"no go.mod covers example.com/m/z/config, so the deepest component "+
			"suffix (z/config, which a/config is not) must still resolve")
}

// R2-1 (fable T1 r2): a symlinked go.mod (git mode 120000 survives clone) must
// be REFUSED, not followed — a hostile `go.mod -> /dev/zero` or a FIFO hangs or
// OOMs the parser otherwise (measured 40 GB RSS at the refuted head). The
// scanner already refuses symlinked .go files; the module walk inherits the
// same gate via Lstat.
func TestReadModulePathRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	// a regular go.mod the control shape can resolve
	regular := filepath.Join(dir, "regular", "go.mod")
	if err := os.MkdirAll(filepath.Dir(regular), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte("module example.com/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readModulePath(regular); got != "example.com/x" {
		t.Fatalf("the regular go.mod must parse: got %q", got)
	}
	// the symlink shapes: to a file, to a directory, and a broken link
	for _, shape := range []string{"link-to-file", "link-to-dir", "broken"} {
		linkDir := filepath.Join(dir, shape)
		if err := os.MkdirAll(linkDir, 0o755); err != nil {
			t.Fatal(err)
		}
		target := regular
		if shape == "link-to-dir" {
			target = filepath.Dir(regular)
		} else if shape == "broken" {
			target = filepath.Join(dir, "does-not-exist")
		}
		link := filepath.Join(linkDir, "go.mod")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if got := readModulePath(link); got != "" {
			t.Fatalf("a symlinked go.mod (%s) must be REFUSED, got %q", shape, got)
		}
	}
}
