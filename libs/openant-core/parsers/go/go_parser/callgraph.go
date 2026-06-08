package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
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
		"os":      true,
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
		repoPath:        repoPath,
		fset:            token.NewFileSet(),
		functionsByName: make(map[string][]string),
		functionsByFile: make(map[string][]string),
		methodsByType:   make(map[string][]string),
		importsByFile:   make(map[string]map[string]string),
		builtins:        builtins,
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
	}
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

	// Track simple func-value aliases (f := helper) so a later call f()
	// resolves to the aliased function. Only single, unconditional bindings
	// of the form `name := <ident>` / `name = <ident>` are tracked; any
	// reassignment (or a non-ident RHS) marks the name ambiguous so we emit
	// no false edge — precision over recall.
	aliases := c.collectFuncValueAliases(file)

	// Walk the AST looking for call expressions
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		callInfo := c.analyzeCallExpr(call)
		// Rewrite an unambiguous func-value alias call (f()) to its target
		// (helper()) so it resolves like a direct call.
		if callInfo.Name != "" && callInfo.Receiver == "" && callInfo.Package == "" {
			if target, ok := aliases[callInfo.Name]; ok {
				callInfo.Name = target
			}
		}
		if callInfo.Name != "" && !c.builtins[callInfo.Name] && !c.builtins[callInfo.Package] {
			calls = append(calls, callInfo)
		}
		return true
	})

	return calls
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

func (c *CallGraphBuilder) analyzeCallExpr(call *ast.CallExpr) CallInfo {
	info := CallInfo{}

	switch fun := call.Fun.(type) {
	case *ast.Ident:
		// Simple call: funcName()
		info.Name = fun.Name

	case *ast.SelectorExpr:
		// Method or package call: obj.Method() or pkg.Func()
		info.Name = fun.Sel.Name
		info.IsMethod = true

		switch x := fun.X.(type) {
		case *ast.Ident:
			info.Receiver = x.Name
			// Check if it looks like a package (lowercase) or object
			if isLikelyPackage(x.Name) {
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

	case *ast.IndexExpr:
		// Generic function call: fn[T]()
		if ident, ok := fun.X.(*ast.Ident); ok {
			info.Name = ident.Name
		}
	}

	return info
}

func isLikelyPackage(name string) bool {
	// Packages are typically lowercase
	if len(name) == 0 {
		return false
	}

	// Common patterns that are definitely packages
	packagePatterns := []string{
		"fmt", "log", "os", "io", "net", "http", "json", "xml",
		"strings", "strconv", "bytes", "time", "context", "sync",
		"errors", "filepath", "regexp", "math", "sort", "reflect",
	}
	for _, p := range packagePatterns {
		if name == p {
			return true
		}
	}

	// If all lowercase and short, likely a package
	first := rune(name[0])
	return first >= 'a' && first <= 'z' && len(name) <= 10
}

func (c *CallGraphBuilder) resolveCalls(callerID string, callerInfo FunctionInfo, calls []CallInfo, analyzer *AnalyzerOutput) []string {
	var resolved []string
	seen := make(map[string]bool)

	for _, call := range calls {
		var targetID string

		// Try different resolution strategies.
		// Guard: a self/receiver match requires a *non-empty* class — otherwise
		// a plain function call (Receiver == "" from a top-level func whose
		// ClassName is also "") spuriously matches `Receiver == ClassName` and
		// gets misrouted into resolveMethodCall(name, "", ...), which can never
		// resolve. Such calls must fall through to the simple-call path.
		if call.IsSelf || (callerInfo.ClassName != "" && call.Receiver == callerInfo.ClassName) {
			// Self/receiver call - look in same type's methods
			targetID = c.resolveMethodCall(call.Name, callerInfo.ClassName, callerInfo.FilePath)
		} else if call.IsMethod && call.Receiver != "" {
			// Method call on some object
			targetID = c.resolveMethodCall(call.Name, call.Receiver, callerInfo.FilePath)
		} else if call.Package != "" {
			// Package-qualified call
			targetID = c.resolvePackageCall(call.Name, call.Package, callerInfo.FilePath)
		} else {
			// Simple function call
			targetID = c.resolveSimpleCall(call.Name, callerInfo.FilePath, callerInfo.Package)
		}

		if targetID != "" && targetID != callerID && !seen[targetID] {
			resolved = append(resolved, targetID)
			seen[targetID] = true
		}
	}

	return resolved
}

func (c *CallGraphBuilder) resolveMethodCall(methodName, receiverType, currentFile string) string {
	// Try to find method on the receiver type
	if methods, ok := c.methodsByType[receiverType]; ok {
		for _, funcID := range methods {
			if strings.HasSuffix(funcID, "."+methodName) {
				return funcID
			}
		}
	}

	// Also try without pointer
	receiverType = strings.TrimPrefix(receiverType, "*")
	if methods, ok := c.methodsByType[receiverType]; ok {
		for _, funcID := range methods {
			if strings.HasSuffix(funcID, "."+methodName) {
				return funcID
			}
		}
	}

	return ""
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

	// Try to find the function in files from that package
	// This is a simplified approach - we look for functions by name
	// that are in files whose directory matches the package
	for _, funcID := range c.functionsByName[funcName] {
		// Check if the function is likely from the right package
		if strings.Contains(funcID, pkgAlias) {
			return funcID
		}
	}

	return ""
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
