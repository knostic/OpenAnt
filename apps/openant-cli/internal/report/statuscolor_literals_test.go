package report

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// statusColorLiterals harvests every string literal returned by
// StatusColor (the method on StepReport/ReportData) from the package's
// own source via go/ast — a future `case "skipped": return "text-yellow-400"`
// cannot escape the coverage test (the the design review plan ruling: hand-enumeration
// drifts; the AST harvest is complete by construction).
func statusColorLiterals() ([]string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	// The package source dir (tests run in-package: cwd IS the dir).
	srcDir := dir
	if _, err := os.Stat(filepath.Join(srcDir, "types.go")); err != nil {
		srcDir = filepath.Dir(os.Args[0])
	}
	fset := token.NewFileSet()
	var lits []string
	entries, rerr := os.ReadDir(srcDir)
	if rerr != nil {
		return nil, rerr
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(srcDir, e.Name())
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			if !strings.Contains(strings.ToLower(name), "color") {
				continue
			}
			// Collect every string literal in a return statement.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ret, ok := n.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, res := range ret.Results {
					if bl, ok := res.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						// F7 (round 1): a class-returning method that
						// returns multi-class strings or a bg-* token is
						// still collected — but HEX colors (the
						// SeverityColor/DynamicTestColor channel, used in
						// style="background-color:" not class="") are NOT
						// class tokens; filter the # shape.
						s := strings.Trim(bl.Value, "\"`")
						for _, tok := range strings.Fields(s) {
							if tok != "" && !strings.HasPrefix(tok, "#") {
								lits = append(lits, tok)
							}
						}
					}
				}
				return true
			})
		}
	}
	sort.Strings(lits)
	return lits, nil
}
