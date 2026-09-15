package report

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
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
//
// The content-list contract (#540 review): tailwind.config.js's `content`
// names types.go as the ONLY Go source of class literals — the harvester
// reads the SAME file. A class-returning method moved elsewhere escapes
// BOTH the compiler and this checker through the literal side (its
// template usage still REDs the coverage side — the fail-loud property
// runs through the template token).
type colorMethod struct {
	walked       bool
	hasClassLits bool // false = hex-only (SeverityColor-style) or empty
}

func statusColorLiterals() ([]string, map[string]colorMethod, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, nil, err
	}
	// The package source dir (tests run in-package: cwd IS the dir).
	srcDir := dir
	if _, err := os.Stat(filepath.Join(srcDir, "types.go")); err != nil {
		srcDir = filepath.Dir(os.Args[0])
	}
	fset := token.NewFileSet()
	var lits []string
	methods := map[string]colorMethod{}
	path := filepath.Join(srcDir, "types.go")
	f, perr := parser.ParseFile(fset, path, nil, 0)
	if perr != nil {
		return nil, nil, fmt.Errorf("parse types.go: %w", perr)
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
		// The return-TYPE gate: only string-first-return methods are class
		// or hex channels. A color-NAMED method returning bool/int (a
		// predicate like HasColor) is legitimate code the fail-closed
		// check below would false-RED on.
		if fn.Type == nil || fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
			continue
		}
		if id, ok := fn.Type.Results.List[0].Type.(*ast.Ident); !ok || id.Name != "string" {
			continue
		}
		info := colorMethod{walked: true}
		// Collect every string literal in a return statement.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			if len(ret.Results) == 0 {
				return true
			}
			// The FIRST result is the class channel (extra results — the
			// error channel of a (string, error) signature — are not).
			// Fail-closed on anything but a string literal there: a
			// concatenation like return "text-" + "blue-400" yields a class
			// this contract cannot verify — the compiler would not emit it
			// and the checker would never see it.
			bl, isLit := ret.Results[0].(*ast.BasicLit)
			if !isLit || bl.Kind != token.STRING {
				perr = fmt.Errorf("%s returns a non-literal first result (%s) — the class coverage contract can only verify string literals; refactor to literals", name, types.ExprString(ret.Results[0]))
				return false
			}
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
					info.hasClassLits = true
				}
			}
			return true
		})
		methods[name] = info
	}
	if perr != nil {
		return nil, nil, perr
	}
	sort.Strings(lits)
	return lits, methods, nil
}
