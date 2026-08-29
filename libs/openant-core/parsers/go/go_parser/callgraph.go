package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"unicode"
)

// CallGraphBuilder builds call graphs from function information
type CallGraphBuilder struct {
	repoPath string
	fset     *token.FileSet

	// Indexes for resolution
	functionsByName map[string][]string // simple name -> [func_ids]
	functionsByFile map[string][]string // file_path -> [func_ids]
	methodsByType   map[string][]string // receiver_type -> [func_ids]

	// Import tracking per file
	importsByFile map[string]map[string]string // file -> alias -> package_path

	// #299: file -> container name -> function names referenced by the
	// container's composite literal (var handlers = map[string]func(){...} /
	// var tbl = []func(){...}). Dispatch through a known container
	// (handlers[k]()) records edges to every referenced function —
	// over-seed, the safe direction for reachability.
	containersByFile map[string]map[string][]string

	// Built-in functions to skip
	builtins map[string]bool
}

// NewCallGraphBuilder creates a new call graph builder
func NewCallGraphBuilder(repoPath string) *CallGraphBuilder {
	builtins := map[string]bool{
		// Built-in functions
		"append": true, "cap": true, "clear": true, "close": true, "complex": true,
		"copy": true, "delete": true, "imag": true, "len": true, "make": true,
		"max": true, "min": true, "new": true, "panic": true, "print": true,
		"println": true, "real": true, "recover": true,
		// Common stdlib that we don't want to trace
		"fmt":     true,
		"log":     true,
		"errors":  true,
		"strings": true,
		"strconv": true,
		"bytes":   true,
		"time":    true,
		"context": true,
		"sync":    true,
		"atomic":  true,
		"sort":    true,
		"math":    true,
		"io":      true,
		// "os" is intentionally NOT skipped: it carries security-relevant sinks (os.StartProcess,
		// etc.) that downstream analysis must be able to see; blanket-skipping dropped them.
		"path":    true,
		"regexp":  true,
		"json":    true,
		"xml":     true,
		"http":    true,
		"net":     true,
		"reflect": true,
		"runtime": true,
		"testing": true,
		"unsafe":  true,
	}

	return &CallGraphBuilder{
		repoPath:         repoPath,
		fset:             token.NewFileSet(),
		functionsByName:  make(map[string][]string),
		functionsByFile:  make(map[string][]string),
		methodsByType:    make(map[string][]string),
		importsByFile:    make(map[string]map[string]string),
		containersByFile: make(map[string]map[string][]string),
		builtins:         builtins,
	}
}

// BuildCallGraph builds the call graph from extracted functions
func (c *CallGraphBuilder) BuildCallGraph(analyzer *AnalyzerOutput) (*CallGraph, error) {
	// Build indexes
	c.buildIndexes(analyzer)

	// Build the call graph
	callGraph := make(map[string][]string)
	reverseGraph := make(map[string][]string)

	totalEdges := 0
	maxOutDegree := 0

	for funcID, funcInfo := range analyzer.Functions {
		// Parse the function code to find calls
		calls := c.extractCalls(funcInfo)

		// Resolve calls to function IDs
		resolvedCalls := c.resolveCalls(funcID, funcInfo, calls, analyzer)

		// Add to call graph
		if len(resolvedCalls) > 0 {
			callGraph[funcID] = resolvedCalls
			totalEdges += len(resolvedCalls)

			if len(resolvedCalls) > maxOutDegree {
				maxOutDegree = len(resolvedCalls)
			}

			// Build reverse graph
			for _, calledID := range resolvedCalls {
				reverseGraph[calledID] = append(reverseGraph[calledID], funcID)
			}
		}
	}

	// Calculate statistics
	avgOutDegree := 0.0
	if len(analyzer.Functions) > 0 {
		avgOutDegree = float64(totalEdges) / float64(len(analyzer.Functions))
	}

	return &CallGraph{
		CallGraph:        callGraph,
		ReverseCallGraph: reverseGraph,
		Statistics: CallGraphStats{
			TotalEdges:   totalEdges,
			AvgOutDegree: avgOutDegree,
			MaxOutDegree: maxOutDegree,
			TotalNodes:   len(analyzer.Functions),
		},
	}, nil
}

func (c *CallGraphBuilder) buildIndexes(analyzer *AnalyzerOutput) {
	for funcID, funcInfo := range analyzer.Functions {
		// Index by simple name
		c.functionsByName[funcInfo.Name] = append(c.functionsByName[funcInfo.Name], funcID)

		// Index by file
		c.functionsByFile[funcInfo.FilePath] = append(c.functionsByFile[funcInfo.FilePath], funcID)

		// Index methods by receiver type
		if funcInfo.ClassName != "" {
			c.methodsByType[funcInfo.ClassName] = append(c.methodsByType[funcInfo.ClassName], funcID)
		}
	}

	// Parse imports for each unique file
	seenFiles := make(map[string]bool)
	for _, funcInfo := range analyzer.Functions {
		if seenFiles[funcInfo.FilePath] {
			continue
		}
		seenFiles[funcInfo.FilePath] = true

		fullPath := filepath.Join(c.repoPath, funcInfo.FilePath)
		c.parseImports(fullPath, funcInfo.FilePath)
		// #299: collect file-scope dispatch containers from the same parse
		c.collectFileContainers(fullPath, funcInfo.FilePath)
	}
}

// collectFileContainers parses a file (full mode, once, cached) and records
// every package-scope `var name = <composite literal>` whose elements are
// function identifiers: the dispatch-table idiom. Target NAMES are stored and
// resolved through the normal name-resolution path at the dispatch site.
func (c *CallGraphBuilder) collectFileContainers(fullPath, relPath string) {
	if c.containersByFile[relPath] != nil {
		return
	}
	c.containersByFile[relPath] = map[string][]string{}
	file, err := parser.ParseFile(token.NewFileSet(), fullPath, nil, 0)
	if err != nil {
		return
	}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			targets := compositeFuncTargets(lit)
			if len(targets) > 0 {
				c.containersByFile[relPath][vs.Names[0].Name] = targets
			}
		}
	}
}

// compositeFuncTargets returns the bare identifiers inside a composite
// literal (map values via KeyValueExpr, or direct elements) — the function
// references a dispatch table holds. TYPE-SHAPE GUARD (#299 review finding):
// only composite literals whose element type is function-valued
// (map[K]func..., []func..., [N]func...) are treated as dispatch tables —
// map[string]int{...} or []MyStruct{...} literals must not have their
// bare identifiers read as call targets (fabrication on name collision).
func compositeFuncTargets(lit *ast.CompositeLit) []string {
	if !funcValuedElementType(lit.Type) {
		return nil
	}
	var targets []string
	for _, elt := range lit.Elts {
		var id *ast.Ident
		switch e := elt.(type) {
		case *ast.Ident:
			id = e
		case *ast.KeyValueExpr:
			if v, ok := e.Value.(*ast.Ident); ok {
				id = v
			}
		}
		if id != nil && id.Name != "" {
			targets = append(targets, id.Name)
		}
	}
	return targets
}

// funcValuedElementType reports whether the composite literal's type has
// function-valued elements: a MapType with FuncType values, an ArrayType
// (incl. slice) of FuncType, or an IndexExpr/IndexListExpr of a generic
// container whose ultimate element resolves to FuncType by name-shape
// (conservative: only the syntactic shapes above; anything else abstains).
func funcValuedElementType(t ast.Expr) bool {
	switch typ := t.(type) {
	case *ast.MapType:
		_, ok := typ.Value.(*ast.FuncType)
		return ok
	case *ast.ArrayType:
		_, ok := typ.Elt.(*ast.FuncType)
		return ok
	case *ast.IndexExpr:
		return funcValuedElementType(typ.X) && isFuncValuedIndexArg(typ.Index)
	case *ast.IndexListExpr:
		return funcValuedElementType(typ.X)
	}
	return false
}

// isFuncValuedIndexArg reports whether a generic instantiation's LAST type
// argument is func-shaped (map[K, V] with V=func..., or []T with T=func...).
// Without go/types this is heuristic on the syntactic shape: a *ast.FuncType
// argument is unambiguous; anything else abstains (safe direction).
func isFuncValuedIndexArg(idx ast.Expr) bool {
	switch a := idx.(type) {
	case *ast.FuncType:
		return true
	case *ast.IndexListExpr:
		if n := len(a.Indices); n > 0 {
			return isFuncValuedIndexArg(a.Indices[n-1])
		}
	}
	return false
}

func (c *CallGraphBuilder) parseImports(fullPath, relPath string) {
	file, err := parser.ParseFile(c.fset, fullPath, nil, parser.ImportsOnly)
	if err != nil {
		return
	}

	imports := make(map[string]string)
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// Default alias is the last component of the path
			parts := strings.Split(path, "/")
			alias = parts[len(parts)-1]
		}
		imports[alias] = path
	}
	c.importsByFile[relPath] = imports
}

// CallInfo represents a function call found in code
type CallInfo struct {
	Name     string // Simple function name
	Receiver string // Receiver for method calls (e.g., "obj" in obj.Method())
	Package  string // Package alias for package.Func() calls
	IsMethod bool   // True if this is a method call
	IsSelf   bool   // True if receiver is "self" or matches current receiver
	// ReceiverTypes is the STATIC type(s) the receiver variable holds, inferred
	// from the enclosing function's signature and body (var-decl / composite
	// literal / receiver / params). Method dispatch keys on the TYPE, not the
	// receiver's variable name. A receiver whose type is unknown yields an empty
	// slice (no edge); a reassigned receiver yields several types (UNION).
	ReceiverTypes []string
}

func (c *CallGraphBuilder) extractCalls(funcInfo FunctionInfo) []CallInfo {
	var calls []CallInfo

	// Parse the function code as a statement
	// We wrap it to make it parseable
	wrappedCode := "package p\n" + funcInfo.Code
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", wrappedCode, 0)
	if err != nil {
		return calls
	}

	// A selector receiver (pkg.Func vs obj.Method) is a package iff its name is one of THIS file's
	// import aliases. Pass the file's import set down so analyzeCallExpr classifies using the real
	// import table instead of a name-shape heuristic.
	imports := c.importsByFile[funcInfo.FilePath]

	// Track simple func-value aliases (f := helper) so a later call f()
	// resolves to the aliased function. Only single, unconditional bindings
	// of the form `name := <ident>` / `name = <ident>` are tracked; any
	// reassignment (or a non-ident RHS) marks the name ambiguous so we emit
	// no false edge — precision over recall.
	aliases := c.collectFuncValueAliases(file)
	// #299: method-value bindings (f := v.Method) — resolved against the
	// receiver variable's locally-known type at the call site.
	methodAliases := c.collectMethodValueAliases(file)
	// #299: local dispatch containers (t := []func(){h1, h2}) merged over
	// the file-scope containers.
	containers := c.collectLocalContainers(file)
	for name, targets := range c.containersByFile[funcInfo.FilePath] {
		containers[name] = targets
	}

	// Per-body receiver-variable -> static-type model. Method calls are resolved
	// against the receiver's TYPE (walking below), never its variable name, so a
	// local `w := Widget{}` / a `var w Widget` / a parameter / the method's own
	// receiver all dispatch to the right type's method.
	varTypes := c.collectVarTypes(file)

	// A name is filtered as a builtin only when no user function of that name is
	// visible from THIS caller's scope. A user func shadowing a builtin (e.g. a
	// local `len`) is a real call target, so its edge must be kept. Go builtin
	// shadowing is PACKAGE/BLOCK-scoped, NOT repo-global: a user `min` in one
	// package does not disable the builtin `min` in another. So the bypass is
	// scoped to the same file / same package (mirroring resolveSimpleCall's
	// priorities 1 & 2, and the Python/C parsers' same-file scoping) and
	// deliberately EXCLUDES the repo-global name index — using functionsByName
	// here would let a genuine builtin call in an unrelated package survive the
	// filter and then be mis-resolved to a cross-package user func via
	// resolveSimpleCall's len(candidates)==1 uniqueness gate (a false edge).
	isBuiltin := func(name string) bool {
		return c.builtins[name] && !c.userFuncInScope(name, funcInfo.FilePath)
	}

	// Walk the AST looking for call expressions
	ast.Inspect(file, func(n ast.Node) bool {
		// Go 1.23 range-over-func: `for v := range seqFunc` invokes seqFunc as an
		// iterator, so a bare function identifier as the range expression is a call
		// edge. A slice/map/channel/int range expression is either not a bare ident
		// or simply will not resolve to a function later, so no false edge is added.
		if rng, ok := n.(*ast.RangeStmt); ok {
			if ident, ok := rng.X.(*ast.Ident); ok {
				name := ident.Name
				if target, ok := aliases[name]; ok {
					name = target
				}
				if name != "" && !isBuiltin(name) {
					calls = append(calls, CallInfo{Name: name})
				}
			}
			return true
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// #299: dispatch through a known container — a subscript call
		// handlers[k]() / tbl[i]() whose base names a tracked container of
		// function references records an edge to EVERY referenced function
		// (over-seed, the safe direction; nothing invented — only names the
		// container's literal actually referenced).
		if idx, ok := call.Fun.(*ast.IndexExpr); ok {
			if base, ok := idx.X.(*ast.Ident); ok {
				if targets, ok := containers[base.Name]; ok {
					for _, target := range targets {
						if !isBuiltin(target) {
							calls = append(calls, CallInfo{Name: target})
						}
					}
					return true
				}
			}
		}

		// #299: bare-ident call through a method-value binding
		// (f := v.Method; f()) — resolve against the receiver's type.
		if ident, ok := call.Fun.(*ast.Ident); ok {
			if ma, ok := methodAliases[ident.Name]; ok {
				mi := CallInfo{Name: ma.method, IsMethod: true, Receiver: ma.recvVar}
				mi.ReceiverTypes = varTypes[ma.recvVar]
				if mi.Name != "" && !isBuiltin(mi.Name) {
					calls = append(calls, mi)
				}
				return true
			}
		}

		callInfo := c.analyzeCallExpr(call, imports)
		// Rewrite an unambiguous func-value alias call (f()) to its target
		// (helper()) so it resolves like a direct call.
		if callInfo.Name != "" && callInfo.Receiver == "" && callInfo.Package == "" {
			if target, ok := aliases[callInfo.Name]; ok {
				callInfo.Name = target
			}
		}
		// Attach the receiver's static type(s) for method-call dispatch. Package
		// calls (Package != "") and non-method calls keep no receiver type.
		if callInfo.IsMethod && callInfo.Package == "" && callInfo.Receiver != "" {
			callInfo.ReceiverTypes = varTypes[callInfo.Receiver]
		}
		if callInfo.Name != "" && !isBuiltin(callInfo.Name) && !c.builtins[callInfo.Package] {
			calls = append(calls, callInfo)
		}
		return true
	})

	return calls
}

// exprTypeName returns the simple type name of a type expression: the identifier
// for `T`, the pointee's name for `*T`, and the bare base type for a generic
// instantiation `T[A]` / `T[A, B]`. The base type is the key methodsByType uses
// (extractor.go's typeToString collapses generics the same way), so a generic
// receiver `*Stack[T]` must resolve to "Stack" — otherwise the receiver var gets
// no static type and the self-call edge is dropped. Anything more complex
// (qualified, slice, map, ...) is not a receiver type we can key on, so "".
func exprTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprTypeName(t.X)
	case *ast.IndexExpr:
		// Generic type with one type parameter, e.g. Stack[T]: drop the arg, key on the base.
		return exprTypeName(t.X)
	case *ast.IndexListExpr:
		// Generic type with multiple type parameters, e.g. Pair[K, V]: same, key on the base.
		return exprTypeName(t.X)
	}
	return ""
}

// compositeTypeName returns the type constructed by an RHS expression when it is
// a composite literal `T{...}` or `&T{...}`, else "". This is the sound, local,
// unambiguous ctor case; a plain call `NewT()` is deliberately NOT inferred (its
// return type is not available here), so we never emit a wrong-type edge.
func compositeTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return exprTypeName(e.Type)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return compositeTypeName(e.X)
		}
	}
	return ""
}

// collectVarTypes builds a receiver-variable -> static-type-set model for a
// parsed function body. Sources (all sound, static): the method's own receiver,
// the function's parameters, `var x T` declarations, and `x := T{}` / `x := &T{}`
// composite-literal assignments. A variable bound to several distinct types
// keeps ALL of them (UNION) so a reassigned receiver never hides a reachable
// method. Unknown / non-nameable types contribute nothing (no edge).
func (c *CallGraphBuilder) collectVarTypes(file *ast.File) map[string][]string {
	varTypes := make(map[string][]string)
	add := func(name, typ string) {
		if name == "" || name == "_" || typ == "" {
			return
		}
		for _, existing := range varTypes[name] {
			if existing == typ {
				return
			}
		}
		varTypes[name] = append(varTypes[name], typ)
	}

	// Method receiver + parameters, from each function signature.
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Recv != nil {
			for _, field := range fd.Recv.List {
				typ := exprTypeName(field.Type)
				for _, n := range field.Names {
					add(n.Name, typ)
				}
			}
		}
		if fd.Type != nil && fd.Type.Params != nil {
			for _, field := range fd.Type.Params.List {
				typ := exprTypeName(field.Type)
				for _, n := range field.Names {
					add(n.Name, typ)
				}
			}
		}
	}

	// Local `var x T` declarations and `x := T{}` / `x := &T{}` bindings.
	ast.Inspect(file, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			if len(stmt.Lhs) == len(stmt.Rhs) {
				for i, lhs := range stmt.Lhs {
					if lid, ok := lhs.(*ast.Ident); ok {
						add(lid.Name, compositeTypeName(stmt.Rhs[i]))
					}
				}
			}
		case *ast.DeclStmt:
			gd, ok := stmt.Decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				declType := exprTypeName(vs.Type)
				for i, name := range vs.Names {
					typ := declType
					if typ == "" && i < len(vs.Values) {
						typ = compositeTypeName(vs.Values[i])
					}
					add(name.Name, typ)
				}
			}
		}
		return true
	})
	return varTypes
}

// methodValueAlias is a `f := v.Method` binding: calling f() resolves to the
// method on the receiver variable's locally-known type (#299).
type methodValueAlias struct {
	method  string
	recvVar string
}

// collectMethodValueAliases scans a parsed function body for single,
// unconditional method-value bindings (`f := v.Method`) and returns the bound
// name -> (method, receiver var). Abstains on anything ambiguous, matching
// collectFuncValueAliases' precision-over-recall contract.
func (c *CallGraphBuilder) collectMethodValueAliases(file *ast.File) map[string]methodValueAlias {
	out := make(map[string]methodValueAlias)
	ambiguous := make(map[string]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		lid, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		if ambiguous[lid.Name] {
			return true
		}
		if _, seen := out[lid.Name]; seen {
			delete(out, lid.Name)
			ambiguous[lid.Name] = true
			return true
		}
		sel, ok := assign.Rhs[0].(*ast.SelectorExpr)
		if !ok {
			return true // non-selector RHS is not a method value; the plain
			// alias tracker owns that case
		}
		if recv, ok := sel.X.(*ast.Ident); ok {
			out[lid.Name] = methodValueAlias{method: sel.Sel.Name, recvVar: recv.Name}
		}
		return true
	})
	return out
}

// collectLocalContainers scans a parsed function body for single-binding
// local dispatch containers (`t := []func(){h1, h2}`) and returns
// name -> referenced function names (#299).
func (c *CallGraphBuilder) collectLocalContainers(file *ast.File) map[string][]string {
	out := make(map[string][]string)
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		lid, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		if _, seen := out[lid.Name]; seen {
			delete(out, lid.Name) // rebound -> ambiguous, drop
			return true
		}
		lit, ok := assign.Rhs[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		if targets := compositeFuncTargets(lit); len(targets) > 0 {
			out[lid.Name] = targets
		}
		return true
	})
	return out
}

// collectFuncValueAliases scans a parsed function body for single, unconditional
// func-value bindings (`f := helper`) and returns name -> target-function-name.
// A name bound more than once, or bound to anything other than a bare identifier,
// is dropped (left out of the map) so a reassigned/conditional alias never
// produces a false edge.
func (c *CallGraphBuilder) collectFuncValueAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string)
	ambiguous := make(map[string]bool)

	record := func(lhs, rhs ast.Expr) {
		lid, ok := lhs.(*ast.Ident)
		if !ok {
			return
		}
		if ambiguous[lid.Name] {
			return
		}
		rid, ok := rhs.(*ast.Ident)
		if !ok {
			// Bound to a non-ident (call, selector, literal, ...) -> ambiguous.
			delete(aliases, lid.Name)
			ambiguous[lid.Name] = true
			return
		}
		if _, seen := aliases[lid.Name]; seen {
			// Second binding of the same name -> ambiguous, drop it.
			delete(aliases, lid.Name)
			ambiguous[lid.Name] = true
			return
		}
		aliases[lid.Name] = rid.Name
	}

	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// Only handle 1:1 bindings (f := helper); skip tuple assignments.
		if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			// Mark any ident LHS ambiguous so a multi-value rebind can't alias.
			for _, lhs := range assign.Lhs {
				if lid, ok := lhs.(*ast.Ident); ok {
					delete(aliases, lid.Name)
					ambiguous[lid.Name] = true
				}
			}
			return true
		}
		record(assign.Lhs[0], assign.Rhs[0])
		return true
	})

	return aliases
}

// isTypeIndexExpr reports whether an IndexExpr's argument is TYPE-shaped —
// the generic-instantiation form fn[T]() — as opposed to a VALUE index
// m[k](). Without go/types the test is syntactic: type parameters are
// conventionally exported identifiers (T, K, V, SomeType), qualified type
// names (pkg.T), nested instantiations (fn[A[B]]), or type literals
// (*T, []T, map[K]V, chan T, interface{...}, struct{...}, func(...)...).
// A lowercase identifier, literal, call, or binary expression is a value
// index and must NOT be unwrapped to the container's bare name (#299's
// false-edge fix). Accepted residual: a generic call whose type parameter
// is lowercase (non-idiomatic) is treated as value indexing and abstains.
// predeclaredTypeNames are Go's universe-block type names: lowercase, but
// type-shaped when they appear as a single index argument (genericFn[int](3)).
var predeclaredTypeNames = map[string]bool{
	"bool": true, "byte": true, "rune": true, "string": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"uintptr": true, "float32": true, "float64": true,
	"complex64": true, "complex128": true, "error": true, "any": true, "comparable": true,
}

func isTypeIndexExpr(idx ast.Expr) bool {
	switch e := idx.(type) {
	case *ast.Ident:
		if predeclaredTypeNames[e.Name] {
			return true // int/string/any/... — lowercase but TYPE names
		}
		r := []rune(e.Name)
		return len(r) > 0 && unicode.IsUpper(r[0])
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.IndexListExpr,
		*ast.StarExpr, *ast.ArrayType, *ast.MapType, *ast.ChanType,
		*ast.InterfaceType, *ast.StructType, *ast.FuncType, *ast.Ellipsis:
		return true
	default:
		return false // BasicLit, CallExpr, BinaryExpr, UnaryExpr: value index
	}
}

func (c *CallGraphBuilder) analyzeCallExpr(call *ast.CallExpr, imports map[string]string) CallInfo {
	info := CallInfo{}

	// Unwrap a generic instantiation so fn[T](), fn[K,V](), obj.M[T]() and obj.M[K,V]() are
	// analyzed identically to their non-generic forms. A single type argument parses as
	// *ast.IndexExpr, multiple as *ast.IndexListExpr; both wrap the underlying function
	// expression (an Ident or a SelectorExpr) in .X.
	//
	// #299: the unwrap historically fired for ANY IndexExpr, so a map/slice
	// VALUE index handlers[k]() collapsed to the bare identifier `handlers`
	// — producing a FALSE edge to any same-named function while the real
	// dispatch target got nothing. Now a single-argument IndexExpr is only
	// unwrapped when the index is TYPE-SHAPED (the generic-instantiation
	// form); a value index is left alone (the walk's container-dispatch
	// path handles tracked containers; unknown bases record nothing).
	// IndexListExpr is always generic (multiple type arguments).
	fun := call.Fun
	switch idx := fun.(type) {
	case *ast.IndexExpr:
		if isTypeIndexExpr(idx.Index) {
			fun = idx.X
		} else {
			return info // value indexing: no bare-name resolution
		}
	case *ast.IndexListExpr:
		fun = idx.X
	}

	switch f := fun.(type) {
	case *ast.Ident:
		// Simple call: funcName() (or generic Gen[..]())
		info.Name = f.Name

	case *ast.SelectorExpr:
		// Method or package call: obj.Method() or pkg.Func() (or generic obj.M[..]())
		info.Name = f.Sel.Name
		info.IsMethod = true

		switch x := f.X.(type) {
		case *ast.Ident:
			info.Receiver = x.Name
			// It is a package call iff the receiver name is an import alias of this file.
			// A short lowercase local (db, tx, ctx, w, r) is NOT a package.
			if _, isImport := imports[x.Name]; isImport {
				info.Package = x.Name
				info.IsMethod = false
			}

		case *ast.SelectorExpr:
			// Chained call: a.b.Method()
			info.Receiver = x.Sel.Name

		case *ast.CallExpr:
			// Result of another call: getObj().Method()
			info.Receiver = "~call_result~"
		}
	}

	return info
}

func (c *CallGraphBuilder) resolveCalls(callerID string, callerInfo FunctionInfo, calls []CallInfo, analyzer *AnalyzerOutput) []string {
	var resolved []string
	seen := make(map[string]bool)

	appendTarget := func(targetID string) {
		if targetID != "" && targetID != callerID && !seen[targetID] {
			resolved = append(resolved, targetID)
			seen[targetID] = true
		}
	}

	for _, call := range calls {
		switch {
		case call.IsMethod && call.Package == "":
			// Method call: dispatch on the receiver's static TYPE(S), never its
			// variable name. An unknown/ambiguous receiver type resolves to
			// nothing (no edge) rather than to an unrelated same-named method;
			// several candidate types (a reassigned receiver) UNION their
			// methods so no reachable method is hidden.
			for _, rt := range call.ReceiverTypes {
				appendTarget(c.resolveMethodCall(call.Name, rt, callerInfo.FilePath))
			}
		case call.Package != "":
			// Package-qualified call
			appendTarget(c.resolvePackageCall(call.Name, call.Package, callerInfo.FilePath))
		default:
			// Simple function call
			appendTarget(c.resolveSimpleCall(call.Name, callerInfo.FilePath, callerInfo.Package))
		}
	}

	return resolved
}

func (c *CallGraphBuilder) resolveMethodCall(methodName, receiverType, currentFile string) string {
	// methodsByType is keyed by the BARE receiver type, so two packages that each define a type
	// with the same name and method collide in one slice. Returning the first matching element made
	// the winner depend on map-iteration order in buildIndexes -> nondeterministic/unstable edges.
	// Instead pick deterministically: prefer a method in the caller's own package, then break ties
	// by the lexicographically smallest funcID.
	callerPkg := filepath.Dir(currentFile)
	suffix := "." + methodName
	best := ""
	pick := func(funcID string) {
		if !strings.HasSuffix(funcID, suffix) {
			return
		}
		if best == "" {
			best = funcID
			return
		}
		candSame := filepath.Dir(funcID) == callerPkg
		bestSame := filepath.Dir(best) == callerPkg
		if (candSame && !bestSame) || (candSame == bestSame && funcID < best) {
			best = funcID
		}
	}

	// Try the exact receiver type first; only fall back to the pointer-stripped type if it yields
	// no match (preserving the original exact-before-pointer preference).
	for _, funcID := range c.methodsByType[receiverType] {
		pick(funcID)
	}
	if best == "" {
		for _, funcID := range c.methodsByType[strings.TrimPrefix(receiverType, "*")] {
			pick(funcID)
		}
	}

	return best
}

func (c *CallGraphBuilder) resolvePackageCall(funcName, pkgAlias, currentFile string) string {
	// Get the import path for this alias
	imports := c.importsByFile[currentFile]
	if imports == nil {
		return ""
	}

	pkgPath := imports[pkgAlias]
	if pkgPath == "" {
		return ""
	}

	// Match by the package's directory (the last component of the resolved import path), NOT the
	// user-chosen alias. funcID is "<relPath>:<Name>", so a function's package is the directory its
	// file lives in. The old code tested strings.Contains(funcID, pkgAlias): it used the alias (so
	// aliased imports failed to resolve) and matched any funcID merely CONTAINING the alias as a
	// substring (so it emitted edges to unrelated packages).
	pkgDir := filepath.Base(pkgPath)
	for _, funcID := range c.functionsByName[funcName] {
		filePart := funcID
		if ci := strings.LastIndex(funcID, ":"); ci >= 0 {
			filePart = funcID[:ci]
		}
		if filepath.Base(filepath.Dir(filePart)) == pkgDir {
			return funcID
		}
	}

	return ""
}

// userFuncInScope reports whether the repo defines its own function of the given
// simple name that is visible from currentFile's scope — the same file or the
// same package (same directory). It intentionally mirrors resolveSimpleCall's
// same-file + same-package priorities and EXCLUDES the repo-global unique-name
// fallback: a user func in an unrelated package must not shadow a builtin call
// here, otherwise a genuine builtin call would be kept and then mis-resolved to
// that cross-package func. This is the Go analogue of the Python
// (_resolve_local_function) and C (_resolve_same_file) parsers' same-file scoping.
func (c *CallGraphBuilder) userFuncInScope(funcName, currentFile string) bool {
	suffix := ":" + funcName
	// Priority 1: same file.
	for _, funcID := range c.functionsByFile[currentFile] {
		if strings.HasSuffix(funcID, suffix) {
			return true
		}
	}
	// Priority 2: same package (a different file in the same directory).
	currentDir := filepath.Dir(currentFile)
	for file, funcs := range c.functionsByFile {
		if filepath.Dir(file) != currentDir {
			continue
		}
		for _, funcID := range funcs {
			if strings.HasSuffix(funcID, suffix) {
				return true
			}
		}
	}
	return false
}

func (c *CallGraphBuilder) resolveSimpleCall(funcName, currentFile, currentPkg string) string {
	// Priority 1: Same file
	if funcs, ok := c.functionsByFile[currentFile]; ok {
		for _, funcID := range funcs {
			if strings.HasSuffix(funcID, ":"+funcName) {
				return funcID
			}
		}
	}

	// Priority 2: Same package (different file)
	for file, funcs := range c.functionsByFile {
		if filepath.Dir(file) == filepath.Dir(currentFile) {
			for _, funcID := range funcs {
				if strings.HasSuffix(funcID, ":"+funcName) {
					return funcID
				}
			}
		}
	}

	// Priority 3: Unique name match
	candidates := c.functionsByName[funcName]
	if len(candidates) == 1 {
		return candidates[0]
	}

	return ""
}
