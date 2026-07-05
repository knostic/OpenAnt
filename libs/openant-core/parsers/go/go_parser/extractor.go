package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Extractor extracts functions and methods from Go source files
type Extractor struct {
	repoPath string
	fset     *token.FileSet
}

// NewExtractor creates a new function extractor
func NewExtractor(repoPath string) *Extractor {
	return &Extractor{
		repoPath: repoPath,
		fset:     token.NewFileSet(),
	}
}

// Extract processes all Go files and extracts function information
func (e *Extractor) Extract(files []string) (*AnalyzerOutput, error) {
	output := &AnalyzerOutput{
		RepoRoot:  e.repoPath,
		Functions: make(map[string]FunctionInfo),
	}

	for _, filePath := range files {
		if err := e.extractFromFile(filePath, output); err != nil {
			// Log error but continue processing other files
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", filePath, err)
			continue
		}
	}

	return output, nil
}

func (e *Extractor) extractFromFile(filePath string, output *AnalyzerOutput) error {
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Parse the file
	file, err := parser.ParseFile(e.fset, filePath, content, parser.ParseComments)
	if err != nil {
		return err
	}

	// Get relative path from repo root
	relPath, err := filepath.Rel(e.repoPath, filePath)
	if err != nil {
		relPath = filePath
	}

	// Get package name
	pkgName := file.Name.Name

	// Process all declarations
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			funcInfo := e.extractFunctionDecl(d, relPath, pkgName, content)
			funcID := e.makeFunctionID(relPath, funcInfo)
			if w := duplicateIDWarning(output.Functions, funcID, funcInfo); w != "" {
				fmt.Fprintln(os.Stderr, "Warning: "+w)
			}
			output.Functions[funcID] = funcInfo
		}
	}

	return nil
}

func (e *Extractor) extractFunctionDecl(decl *ast.FuncDecl, filePath, pkgName string, content []byte) FunctionInfo {
	// Get position info
	startPos := e.fset.Position(decl.Pos())
	endPos := e.fset.Position(decl.End())

	// Extract function name
	funcName := decl.Name.Name

	// Check if it's a method (has receiver)
	var receiver string
	var className string
	if decl.Recv != nil && len(decl.Recv.List) > 0 {
		recv := decl.Recv.List[0]
		receiver = e.typeToString(recv.Type)
		// Remove pointer prefix for className
		className = strings.TrimPrefix(receiver, "*")
	}

	// Extract parameters
	var params []string
	if decl.Type.Params != nil {
		for _, field := range decl.Type.Params.List {
			paramType := e.typeToString(field.Type)
			if len(field.Names) > 0 {
				for _, name := range field.Names {
					params = append(params, fmt.Sprintf("%s %s", name.Name, paramType))
				}
			} else {
				params = append(params, paramType)
			}
		}
	}

	// Extract return types
	var returns []string
	if decl.Type.Results != nil {
		for _, field := range decl.Type.Results.List {
			returnType := e.typeToString(field.Type)
			if len(field.Names) > 0 {
				for _, name := range field.Names {
					returns = append(returns, fmt.Sprintf("%s %s", name.Name, returnType))
				}
			} else {
				returns = append(returns, returnType)
			}
		}
	}

	// Extract code using correct byte offsets
	startOffset := e.fset.Position(decl.Pos()).Offset
	endOffset := e.fset.Position(decl.End()).Offset

	// Bounds check
	if startOffset < 0 || endOffset > len(content) || startOffset >= endOffset {
		// Fallback: return empty code
		return FunctionInfo{
			Name:       funcName,
			Code:       "",
			StartLine:  startPos.Line,
			EndLine:    endPos.Line,
			UnitType:   UnitTypeFunction,
			ClassName:  className,
			IsExported: len(funcName) > 0 && unicode.IsUpper(rune(funcName[0])),
			Package:    pkgName,
			FilePath:   filePath,
			Receiver:   receiver,
			Parameters: params,
			Returns:    returns,
		}
	}

	code := string(content[startOffset:endOffset])

	// Determine unit type
	unitType := e.classifyUnitType(funcName, receiver, params, returns, code, filePath)

	// Check if exported (starts with uppercase)
	isExported := len(funcName) > 0 && unicode.IsUpper(rune(funcName[0]))

	// Check for goroutine usage (async-like)
	isAsync := strings.Contains(code, "go ") || strings.Contains(code, "go\t")

	return FunctionInfo{
		Name:       funcName,
		Code:       code,
		StartLine:  startPos.Line,
		EndLine:    endPos.Line,
		UnitType:   unitType,
		ClassName:  className,
		IsExported: isExported,
		Package:    pkgName,
		FilePath:   filePath,
		Receiver:   receiver,
		Parameters: params,
		Returns:    returns,
		IsAsync:    isAsync,
	}
}

func (e *Extractor) typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + e.typeToString(t.X)
	case *ast.SelectorExpr:
		return e.typeToString(t.X) + "." + t.Sel.Name
	case *ast.IndexExpr:
		// Generic type with one type parameter, e.g. Stack[T]. The class key is the
		// base type, so drop the type argument and recurse into the base (t.X).
		return e.typeToString(t.X)
	case *ast.IndexListExpr:
		// Generic type with multiple type parameters, e.g. Pair[K, V]. Same as above:
		// the class key is the bare base type, so recurse into t.X and drop the args.
		return e.typeToString(t.X)
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + e.typeToString(t.Elt)
		}
		return fmt.Sprintf("[%v]%s", t.Len, e.typeToString(t.Elt))
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", e.typeToString(t.Key), e.typeToString(t.Value))
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.ChanType:
		return "chan " + e.typeToString(t.Value)
	case *ast.FuncType:
		return "func(...)"
	case *ast.Ellipsis:
		return "..." + e.typeToString(t.Elt)
	default:
		return "unknown"
	}
}

func (e *Extractor) classifyUnitType(name, receiver string, params, returns []string, code, filePath string) string {
	// Check for main function
	if name == "main" && receiver == "" {
		return UnitTypeMain
	}

	// Check for init function
	if name == "init" && receiver == "" {
		return UnitTypeInit
	}

	// Check for test function
	if strings.HasPrefix(name, "Test") && len(params) > 0 {
		for _, p := range params {
			if strings.Contains(p, "*testing.T") || strings.Contains(p, "testing.T") {
				return UnitTypeTest
			}
		}
	}

	// Check for benchmark function
	if strings.HasPrefix(name, "Benchmark") && len(params) > 0 {
		for _, p := range params {
			if strings.Contains(p, "*testing.B") || strings.Contains(p, "testing.B") {
				return UnitTypeTest
			}
		}
	}

	// Check for HTTP handler patterns
	if e.isHTTPHandler(params, returns, code) {
		return UnitTypeHTTPHandler
	}

	// Check for CLI handler patterns
	if e.isCLIHandler(params, returns, code) {
		return UnitTypeCLIHandler
	}

	// Check for middleware pattern
	if e.isMiddleware(params, returns, code) {
		return UnitTypeMiddleware
	}

	// Default: method or function
	if receiver != "" {
		return UnitTypeMethod
	}

	return UnitTypeFunction
}

// HTTP handler detection patterns
var httpHandlerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`http\.ResponseWriter`),
	regexp.MustCompile(`\*http\.Request`),
	regexp.MustCompile(`gin\.Context`),
	regexp.MustCompile(`echo\.Context`),
	regexp.MustCompile(`fiber\.Ctx`),
	regexp.MustCompile(`chi\.Router`),
	regexp.MustCompile(`mux\.Router`),
	regexp.MustCompile(`middleware\.Responder`), // go-swagger
	regexp.MustCompile(`HandlerFunc`),
}

func (e *Extractor) isHTTPHandler(params, returns []string, code string) bool {
	paramsStr := strings.Join(params, " ")

	// Check parameters for HTTP patterns. A handler is identified by what it
	// RECEIVES (request/context types in params), not by what it returns —
	// matching these patterns against the return type mis-tagged factories
	// such as `func Logger() gin.HandlerFunc` as http_handler entry points (F10).
	for _, pattern := range httpHandlerPatterns {
		if pattern.MatchString(paramsStr) {
			return true
		}
	}

	// Check for common handler patterns in code
	if strings.Contains(code, "http.HandleFunc") ||
		strings.Contains(code, ".HandleFunc(") ||
		strings.Contains(code, "Handler =") ||
		strings.Contains(code, "w.Write(") ||
		strings.Contains(code, "w.WriteHeader(") {
		return true
	}

	return false
}

// CLI handler detection patterns
var cliHandlerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`cli\.Context`),
	regexp.MustCompile(`cobra\.Command`),
	regexp.MustCompile(`\*flag\.FlagSet`),
	regexp.MustCompile(`urfave/cli`),
}

func (e *Extractor) isCLIHandler(params, returns []string, code string) bool {
	paramsStr := strings.Join(params, " ")

	for _, pattern := range cliHandlerPatterns {
		if pattern.MatchString(paramsStr) || pattern.MatchString(code) {
			return true
		}
	}

	// Check for CLI patterns
	if strings.Contains(code, "cli.Command") ||
		strings.Contains(code, "cobra.Command") ||
		strings.Contains(code, "flag.Parse()") ||
		strings.Contains(code, "os.Args") {
		return true
	}

	return false
}

func (e *Extractor) isMiddleware(params, returns []string, code string) bool {
	// Middleware often takes and returns http.Handler or similar
	returnsStr := strings.Join(returns, " ")
	paramsStr := strings.Join(params, " ")

	// A bare `next(` substring previously matched any body with a next() call
	// (Go 1.23 iterators, lexers, cursors), mislabelling them middleware (F7).
	// Only treat a `next(` call as middleware when the function has an HTTP
	// request signature, i.e. it is actually wrapping a handler.
	hasHTTPSignature := strings.Contains(paramsStr, "http.ResponseWriter") ||
		strings.Contains(paramsStr, "http.Request") ||
		strings.Contains(paramsStr, "http.Handler")

	if strings.Contains(returnsStr, "http.Handler") ||
		strings.Contains(returnsStr, "http.HandlerFunc") ||
		strings.Contains(code, "next.ServeHTTP") ||
		(hasHTTPSignature && strings.Contains(code, "next(")) {
		return true
	}

	return false
}

// duplicateIDWarning returns a non-empty diagnostic when funcID already maps to a unit in fns.
// A collision means two distinct declarations resolved to the same unit id — typically a
// class-key collapse (e.g. an unhandled receiver shape falling back to "unknown") — and the
// subsequent `fns[funcID] = ...` write would silently overwrite the earlier unit (data loss).
// The caller logs the returned string so the collapse is observable instead of silent. An empty
// string means no collision (the common case).
func duplicateIDWarning(fns map[string]FunctionInfo, funcID string, incoming FunctionInfo) string {
	existing, ok := fns[funcID]
	if !ok {
		return ""
	}
	return fmt.Sprintf("duplicate unit id %q: %s:%d would overwrite %s:%d (class-key collapse?)",
		funcID, incoming.FilePath, incoming.StartLine, existing.FilePath, existing.StartLine)
}

func (e *Extractor) makeFunctionID(filePath string, info FunctionInfo) string {
	if info.ClassName != "" {
		return fmt.Sprintf("%s:%s.%s", filePath, info.ClassName, info.Name)
	}
	return fmt.Sprintf("%s:%s", filePath, info.Name)
}
