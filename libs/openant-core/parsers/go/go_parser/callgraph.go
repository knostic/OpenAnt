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

	// A selector receiver (pkg.Func vs obj.Method) is a package iff its name is one of THIS file's
	// import aliases. Pass the file's import set down so analyzeCallExpr classifies using the real
	// import table instead of a name-shape heuristic.
	imports := c.importsByFile[funcInfo.FilePath]

	// Walk the AST looking for call expressions
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		callInfo := c.analyzeCallExpr(call, imports)
		if callInfo.Name != "" && !c.builtins[callInfo.Name] && !c.builtins[callInfo.Package] {
			calls = append(calls, callInfo)
		}
		return true
	})

	return calls
}

func (c *CallGraphBuilder) analyzeCallExpr(call *ast.CallExpr, imports map[string]string) CallInfo {
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

	case *ast.IndexExpr:
		// Generic function call: fn[T]()
		if ident, ok := fun.X.(*ast.Ident); ok {
			info.Name = ident.Name
		}
	}

	return info
}

func (c *CallGraphBuilder) resolveCalls(callerID string, callerInfo FunctionInfo, calls []CallInfo, analyzer *AnalyzerOutput) []string {
	var resolved []string
	seen := make(map[string]bool)

	for _, call := range calls {
		var targetID string

		// Try different resolution strategies
		if callerInfo.ClassName != "" && (call.IsSelf || call.Receiver == callerInfo.ClassName) {
			// Self/receiver call - look in same type's methods. Guarded on ClassName != "" so a
			// plain function (ClassName=="") making a simple call (Receiver=="") is NOT misrouted
			// here via ""=="" and lost; it falls through to resolveSimpleCall below.
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
