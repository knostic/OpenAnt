#!/usr/bin/env node
/**
 * TypeScript/JavaScript Function Analyzer
 *
 * Uses TypeScript Compiler API (via ts-morph) to extract function code from JavaScript/TypeScript files.
 * Provides accurate AST-based function extraction with no RegEx.
 *
 * Usage:
 *   node typescript_analyzer.js <repo_path> <file1> <file2> ...
 *
 * Output (JSON):
 *   {
 *     "functions": {
 *       "file.ts:functionName": {
 *         "name": "functionName",
 *         "code": "function code here",
 *         "isExported": true
 *       }
 *     },
 *     "callGraph": {
 *       "file.ts:callerName": [
 *         {"resolved": true, "functionId": "file.ts:calleeName"}
 *       ]
 *     }
 *   }
 */

const { Project } = require("ts-morph");
const { ts } = require("@ts-morph/common");
const path = require("path");
const { toPosixPath } = require("./path_utils");

/**
 * Maximally permissive compiler options for AST extraction.
 * We use ESNext target/module to accept ALL valid JS/TS syntax
 * regardless of what the project actually targets.
 * The analyzer only needs to parse and check exports, not compile.
 */
const PERMISSIVE_COMPILER_OPTIONS = {
  allowJs: true,
  checkJs: false,
  noEmit: true,
  skipLibCheck: true,
  target: ts.ScriptTarget.ESNext,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  jsx: ts.JsxEmit.ReactJSX,
  esModuleInterop: true,
  allowSyntheticDefaultImports: true,
};

class TypeScriptAnalyzer {
  constructor(repoPath) {
    // Normalise immediately so all later path operations (path.relative,
    // path.join) work with a consistent forward-slash base on Windows.
    this.repoPath = toPosixPath(path.resolve(repoPath));
    this.project = new Project({
      compilerOptions: PERMISSIVE_COMPILER_OPTIONS,
    });
    this.functions = {}; // functionId -> function metadata
    this.callGraph = {}; // callerId -> array of call info
  }

  /**
   * Classify function type based on heuristics
   * @returns {string} One of: route_handler, middleware, model, utility, class_method, function
   */
  classifyFunction(name, code, isClassMethod = false, className = null) {
    const codeLower = code.toLowerCase();
    const nameLower = name.toLowerCase();

    // Check for route handler patterns
    if (this._hasRouteHandlerSignature(code)) {
      return "route_handler";
    }

    // Check for middleware patterns (has next parameter)
    if (this._hasMiddlewareSignature(code)) {
      return "middleware";
    }

    // Check for model patterns
    if (className && /model|schema|entity/i.test(className)) {
      return "model";
    }
    if (/\.(find|create|update|delete|save|query)\s*\(/i.test(code)) {
      if (/sequelize|mongoose|prisma|typeorm/i.test(codeLower)) {
        return "model";
      }
    }

    // Class methods
    if (isClassMethod) {
      return "class_method";
    }

    // Default to utility for standalone functions
    return "function";
  }

  /**
   * Check if function has route handler signature (req, res) or (request, response)
   */
  _hasRouteHandlerSignature(code) {
    // Match common Express handler patterns
    const handlerPatterns = [
      /\(\s*req\s*,\s*res\s*[,\)]/, // (req, res) or (req, res, next)
      /\(\s*request\s*,\s*response\s*[,\)]/, // (request, response)
      /\(\s*ctx\s*[,\)]/, // Koa style (ctx)
      /:\s*Request\s*,/, // TypeScript: Request type
      /:\s*Response\s*[,\)]/, // TypeScript: Response type
    ];
    return handlerPatterns.some((pattern) => pattern.test(code));
  }

  /**
   * Check if function has middleware signature (req, res, next) or (err, req, res, next)
   */
  _hasMiddlewareSignature(code) {
    const middlewarePatterns = [
      /\(\s*req\s*,\s*res\s*,\s*next\s*\)/, // (req, res, next)
      /\(\s*err\s*,\s*req\s*,\s*res\s*,\s*next\s*\)/, // Error middleware
      /\(\s*request\s*,\s*response\s*,\s*next\s*\)/, // Full names
      /next\s*\(\s*\)/, // Calls next()
    ];
    // Must have next() call to be considered middleware
    const hasNextCall = /next\s*\(/.test(code);
    const hasNextParam = /,\s*next\s*[:\)]/.test(code);
    return hasNextParam && hasNextCall;
  }

  /**
   * Analyze a list of files and extract functions + call graph
   */
  analyzeFiles(filePaths) {
    // Step 1: Add all files to project
    for (const filePath of filePaths) {
      const fullPath = path.isAbsolute(filePath)
        ? filePath
        : path.join(this.repoPath, filePath);

      // ts-morph treats backslashes as escape characters when matching
      // paths it has already added. Normalise to forward slashes so
      // Windows-native paths (with `\`) resolve consistently.
      const normalised = toPosixPath(fullPath);

      try {
        this.project.addSourceFileAtPath(normalised);
      } catch (error) {
        console.error(`Failed to add file ${normalised}: ${error.message}`);
      }
    }

    // Step 2: Extract functions from each file
    for (const sourceFile of this.project.getSourceFiles()) {
      this.extractFunctionsFromFile(sourceFile);
    }

    // Step 3: Build call graph
    for (const sourceFile of this.project.getSourceFiles()) {
      this.buildCallGraphForFile(sourceFile);
    }

    return {
      functions: this.functions,
      callGraph: this.callGraph,
    };
  }

  /**
   * Extract all functions/methods from a source file
   */
  extractFunctionsFromFile(sourceFile) {
    // Always emit POSIX-style relative paths so functionId values are
    // stable across platforms (Python downstream consumers and dataset
    // diffs key off these strings).
    const relativePath = toPosixPath(
      path.relative(this.repoPath, sourceFile.getFilePath()),
    );

    // Extract function declarations
    for (const func of sourceFile.getFunctions()) {
      const name = func.getName();
      if (!name) continue;

      const code = func.getFullText();
      const functionId = `${relativePath}:${name}`;
      this.functions[functionId] = {
        name: name,
        code: code,
        isExported: func.isExported(),
        unitType: this.classifyFunction(name, code, false, null),
        startLine: func.getStartLineNumber(),
        endLine: func.getEndLineNumber(),
      };
    }

    // Extract arrow functions assigned to variables/constants
    for (const statement of sourceFile.getVariableStatements()) {
      for (const declaration of statement.getDeclarations()) {
        const initializer = declaration.getInitializer();
        if (
          initializer &&
          (initializer.getKindName() === "ArrowFunction" ||
            initializer.getKindName() === "FunctionExpression")
        ) {
          const name = declaration.getName();
          const code = statement.getFullText();
          const functionId = `${relativePath}:${name}`;

          // Include the full variable declaration (const name = ...) for context
          this.functions[functionId] = {
            name: name,
            code: code,
            isExported: statement.isExported(),
            unitType: this.classifyFunction(name, code, false, null),
            startLine: statement.getStartLineNumber(),
            endLine: statement.getEndLineNumber(),
          };
        }
      }
    }

    // Extract methods from classes
    for (const classDecl of sourceFile.getClasses()) {
      const className = classDecl.getName() || "AnonymousClass";

      for (const method of classDecl.getMethods()) {
        const methodName = method.getName();
        const code = method.getFullText();
        const functionId = `${relativePath}:${className}.${methodName}`;

        this.functions[functionId] = {
          name: `${className}.${methodName}`,
          code: code,
          isExported: classDecl.isExported(),
          unitType: this.classifyFunction(methodName, code, true, className),
          startLine: method.getStartLineNumber(),
          endLine: method.getEndLineNumber(),
          className: className,
        };
      }
    }

    // Extract methods from object literals in export default
    // Pattern: export default { method1, method2 }
    // Pattern: export default { method1() {...}, method2: () => {...} }
    this._extractExportDefaultMethods(sourceFile, relativePath);

    // Extract methods from module.exports = { ... }
    this._extractModuleExportsMethods(sourceFile, relativePath);

    // Extract functions from module.exports.propertyName = function() {...}
    // Pattern used by DVNA and similar CommonJS codebases
    this._extractModuleExportsPropertyFunctions(sourceFile, relativePath);
  }

  /**
   * Extract methods from export default object literals
   * Pattern: export default { method1, method2 }
   */
  _extractExportDefaultMethods(sourceFile, relativePath) {
    for (const exportDecl of sourceFile.getExportAssignments()) {
      const expression = exportDecl.getExpression();
      if (
        expression &&
        expression.getKindName() === "ObjectLiteralExpression"
      ) {
        this._extractFromObjectLiteral(expression, relativePath, "default");
      }
    }
  }

  /**
   * Extract methods from module.exports = { ... }
   */
  _extractModuleExportsMethods(sourceFile, relativePath) {
    for (const statement of sourceFile.getStatements()) {
      if (statement.getKindName() === "ExpressionStatement") {
        const expr = statement.getExpression();
        if (expr && expr.getKindName() === "BinaryExpression") {
          const left = expr.getLeft();
          const right = expr.getRight();

          // Check if it's module.exports = { ... }
          if (left && left.getText() === "module.exports") {
            if (right && right.getKindName() === "ObjectLiteralExpression") {
              this._extractFromObjectLiteral(right, relativePath, "exports");
            }
          }
        }
      }
    }
  }

  /**
   * Extract functions from module.exports.propertyName = function() {...} pattern
   * This handles CommonJS exports used by DVNA and similar codebases:
   *   module.exports.userSearch = function (req, res) {...}
   *   exports.ping = function (req, res) {...}
   */
  _extractModuleExportsPropertyFunctions(sourceFile, relativePath) {
    for (const statement of sourceFile.getStatements()) {
      if (statement.getKindName() === "ExpressionStatement") {
        const expr = statement.getExpression();
        if (expr && expr.getKindName() === "BinaryExpression") {
          const left = expr.getLeft();
          const right = expr.getRight();

          // Check if left side is module.exports.X or exports.X
          if (left && left.getKindName() === "PropertyAccessExpression") {
            const leftText = left.getText();

            // Match module.exports.functionName or exports.functionName
            let functionName = null;
            if (leftText.startsWith("module.exports.")) {
              functionName = leftText.substring("module.exports.".length);
            } else if (
              leftText.startsWith("exports.") &&
              !leftText.startsWith("exports.default")
            ) {
              functionName = leftText.substring("exports.".length);
            }

            // If we found a property assignment with a function value
            if (
              functionName &&
              right &&
              (right.getKindName() === "ArrowFunction" ||
                right.getKindName() === "FunctionExpression")
            ) {
              const functionId = `${relativePath}:${functionName}`;

              // Don't overwrite if already extracted
              if (!this.functions[functionId]) {
                const code = statement.getFullText();
                this.functions[functionId] = {
                  name: functionName,
                  code: code,
                  isExported: true,
                  unitType: this.classifyFunction(
                    functionName,
                    code,
                    false,
                    null,
                  ),
                  startLine: statement.getStartLineNumber(),
                  endLine: statement.getEndLineNumber(),
                  exportType: "commonjs",
                };
              }
            }
          }
        }
      }
    }
  }

  /**
   * Extract methods from an object literal expression
   */
  _extractFromObjectLiteral(objectLiteral, relativePath, exportType) {
    for (const property of objectLiteral.getProperties()) {
      const kindName = property.getKindName();

      if (
        kindName === "MethodDeclaration" ||
        kindName === "ShorthandPropertyAssignment" ||
        kindName === "PropertyAssignment"
      ) {
        let name, code;

        if (kindName === "MethodDeclaration") {
          // Pattern: { methodName() { ... } }
          name = property.getName();
          code = property.getFullText();
        } else if (kindName === "ShorthandPropertyAssignment") {
          // Pattern: { methodName } - references a variable defined elsewhere
          name = property.getName();
          // For shorthand, the code is minimal, we'd need to find the actual definition
          // Skip for now as these reference functions already extracted above
          continue;
        } else if (kindName === "PropertyAssignment") {
          // Pattern: { methodName: () => { ... } } or { methodName: function() { ... } }
          name = property.getName();
          const initializer = property.getInitializer();
          if (
            initializer &&
            (initializer.getKindName() === "ArrowFunction" ||
              initializer.getKindName() === "FunctionExpression")
          ) {
            code = property.getFullText();
          } else {
            continue; // Not a function
          }
        }

        if (name && code) {
          const functionId = `${relativePath}:${exportType}.${name}`;
          // Don't overwrite if we already have this function from variable extraction
          if (!this.functions[functionId]) {
            this.functions[functionId] = {
              name: `${exportType}.${name}`,
              code: code,
              isExported: true,
              unitType: this.classifyFunction(name, code, false, null),
              startLine: property.getStartLineNumber(),
              endLine: property.getEndLineNumber(),
              exportType: exportType,
            };
          }
        }
      }
    }
  }

  /**
   * Build call graph for a source file
   *
   * For each function, find what other functions it calls
   */
  buildCallGraphForFile(sourceFile) {
    const relativePath = toPosixPath(
      path.relative(this.repoPath, sourceFile.getFilePath()),
    );

    // Analyze function declarations
    for (const func of sourceFile.getFunctions()) {
      const name = func.getName();
      if (!name) continue;

      const callerId = `${relativePath}:${name}`;
      this.callGraph[callerId] = this.extractCallsFromFunction(
        func,
        relativePath,
      );
    }

    // Analyze arrow functions
    for (const statement of sourceFile.getVariableStatements()) {
      for (const declaration of statement.getDeclarations()) {
        const initializer = declaration.getInitializer();
        if (
          initializer &&
          (initializer.getKindName() === "ArrowFunction" ||
            initializer.getKindName() === "FunctionExpression")
        ) {
          const name = declaration.getName();
          const callerId = `${relativePath}:${name}`;
          this.callGraph[callerId] = this.extractCallsFromFunction(
            initializer,
            relativePath,
          );
        }
      }
    }

    // Analyze class methods
    for (const classDecl of sourceFile.getClasses()) {
      const className = classDecl.getName() || "AnonymousClass";

      for (const method of classDecl.getMethods()) {
        const methodName = method.getName();
        const callerId = `${relativePath}:${className}.${methodName}`;
        this.callGraph[callerId] = this.extractCallsFromFunction(
          method,
          relativePath,
        );
      }
    }
  }

  /**
   * Extract function calls from within a function body
   */
  extractCallsFromFunction(funcNode, currentFile) {
    const calls = [];
    const callExpressions = funcNode
      .getDescendantsOfKind(funcNode.getKind())
      .filter((n) => n.getKindName() === "CallExpression");

    // This is simplified - a full implementation would:
    // 1. Resolve import/require statements
    // 2. Track variable assignments
    // 3. Resolve member expressions (obj.method())
    // 4. Handle dynamic calls

    // For now, just track that calls exist without full resolution
    for (const callExpr of callExpressions) {
      calls.push({
        resolved: false,
        name: callExpr.getExpression().getText(),
      });
    }

    return calls;
  }
}

/**
 * Extract a single function from a file
 */
function extractSingleFunction(filePath, functionRef) {
  const fs = require("fs");

  // Normalise to forward slashes so ts-morph can match the path it stores
  // internally. On Windows, filePath may arrive with backslashes.
  const normalisedFilePath = toPosixPath(path.resolve(filePath));

  // Check if file exists using the normalised path for consistent error messages.
  if (!fs.existsSync(normalisedFilePath)) {
    console.error(`File not found: ${normalisedFilePath}`);
    process.exit(1);
  }

  const project = new Project({
    compilerOptions: PERMISSIVE_COMPILER_OPTIONS,
  });

  try {
    const sourceFile = project.addSourceFileAtPath(normalisedFilePath);

    // Parse function reference (e.g., "sessionHandler.handleLogin" or just "handleLogin")
    let className = null;
    let functionName = functionRef;

    if (functionRef.includes(".")) {
      const parts = functionRef.split(".");
      className = parts[0];
      functionName = parts[parts.length - 1];
    }

    // Search for the function
    let foundFunction = null;

    // 1. Try class methods first if className specified
    if (className) {
      for (const classDecl of sourceFile.getClasses()) {
        const classNameMatch = classDecl.getName();
        if (classNameMatch === className) {
          for (const method of classDecl.getMethods()) {
            if (method.getName() === functionName) {
              foundFunction = {
                node: method,
                code: method.getFullText(),
                name: functionName,
                class_name: className,
                start_line: method.getStartLineNumber(),
                end_line: method.getEndLineNumber(),
              };
              break;
            }
          }
        }
      }
    }

    // 2. Try standalone function declarations
    if (!foundFunction) {
      for (const func of sourceFile.getFunctions()) {
        if (func.getName() === functionName) {
          foundFunction = {
            node: func,
            code: func.getFullText(),
            name: functionName,
            class_name: null,
            start_line: func.getStartLineNumber(),
            end_line: func.getEndLineNumber(),
          };
          break;
        }
      }
    }

    // 3. Try arrow functions / function expressions assigned to variables
    if (!foundFunction) {
      for (const statement of sourceFile.getVariableStatements()) {
        for (const declaration of statement.getDeclarations()) {
          if (declaration.getName() === functionName) {
            const initializer = declaration.getInitializer();
            if (
              initializer &&
              (initializer.getKindName() === "ArrowFunction" ||
                initializer.getKindName() === "FunctionExpression")
            ) {
              foundFunction = {
                node: initializer,
                code: statement.getFullText(),
                name: functionName,
                class_name: null,
                start_line: statement.getStartLineNumber(),
                end_line: statement.getEndLineNumber(),
              };
              break;
            }
          }
        }
        if (foundFunction) break;
      }
    }

    // 4. Try constructor function pattern (this.methodName = function/arrow)
    // Pattern: function ClassName(db) { this.methodName = (req, res) => {...}; }
    if (!foundFunction) {
      for (const func of sourceFile.getFunctions()) {
        // Look for assignments inside the function body
        const body = func.getBody();
        if (!body) continue;

        // Find expression statements like: this.methodName = ...
        for (const statement of body.getStatements
          ? body.getStatements()
          : []) {
          if (statement.getKindName() === "ExpressionStatement") {
            const expr = statement.getExpression();
            if (expr && expr.getKindName() === "BinaryExpression") {
              const left = expr.getLeft();
              const right = expr.getRight();

              // Check if it's this.functionName = ...
              if (left && left.getKindName() === "PropertyAccessExpression") {
                const leftText = left.getText();
                if (leftText === `this.${functionName}`) {
                  // Found it! Extract the right-hand side (the function)
                  if (
                    right &&
                    (right.getKindName() === "ArrowFunction" ||
                      right.getKindName() === "FunctionExpression")
                  ) {
                    foundFunction = {
                      node: right,
                      code: right.getFullText(),
                      name: functionName,
                      class_name: func.getName() || className,
                      start_line: right.getStartLineNumber(),
                      end_line: right.getEndLineNumber(),
                    };
                    break;
                  }
                }
              }
            }
          }
        }
        if (foundFunction) break;
      }
    }

    // 5. Try module.exports.functionName pattern (used by DVNA)
    // Pattern: module.exports.userSearch = function (req, res) {...}
    if (!foundFunction) {
      for (const statement of sourceFile.getStatements()) {
        if (statement.getKindName() === "ExpressionStatement") {
          const expr = statement.getExpression();
          if (expr && expr.getKindName() === "BinaryExpression") {
            const left = expr.getLeft();
            const right = expr.getRight();

            // Check if it's module.exports.functionName = ...
            if (left && left.getKindName() === "PropertyAccessExpression") {
              const leftText = left.getText();
              // Match both module.exports.functionName and exports.functionName
              if (
                leftText === `module.exports.${functionName}` ||
                leftText === `exports.${functionName}`
              ) {
                if (
                  right &&
                  (right.getKindName() === "ArrowFunction" ||
                    right.getKindName() === "FunctionExpression")
                ) {
                  foundFunction = {
                    node: right,
                    code: right.getFullText(),
                    name: functionName,
                    class_name: className,
                    start_line: right.getStartLineNumber(),
                    end_line: right.getEndLineNumber(),
                  };
                  break;
                }
              }
            }
          }
        }
      }
    }

    // 6. Try to follow require/import to find the actual handler file
    // Pattern: const ClassName = require('./module'); ... new ClassName().methodName
    // Note: className might be lowercase instance (sessionHandler) but require uses PascalCase (SessionHandler)
    if (!foundFunction && className) {
      // Convert instance name to class name (sessionHandler -> SessionHandler)
      const classNamePascal =
        className.charAt(0).toUpperCase() + className.slice(1);

      // Look for require statement that matches the className (try both cases)
      for (const statement of sourceFile.getVariableStatements()) {
        for (const declaration of statement.getDeclarations()) {
          const declName = declaration.getName();
          if (declName === className || declName === classNamePascal) {
            const initializer = declaration.getInitializer();
            if (initializer && initializer.getKindName() === "CallExpression") {
              const callText = initializer.getText();
              // Check if it's a require call
              const requireMatch = callText.match(
                /require\s*\(\s*['"]([^'"]+)['"]\s*\)/,
              );
              if (requireMatch) {
                const requiredPath = requireMatch[1];
                // Resolve the path relative to current file; use the
                // already-normalised path to avoid mixed separators.
                const currentDir = path.dirname(normalisedFilePath);
                let resolvedPath = toPosixPath(
                  path.resolve(currentDir, requiredPath),
                );

                // Try with .js extension if not present
                if (!fs.existsSync(resolvedPath)) {
                  resolvedPath = resolvedPath + ".js";
                }
                if (!fs.existsSync(resolvedPath)) {
                  resolvedPath = toPosixPath(
                    path.resolve(currentDir, requiredPath + ".ts"),
                  );
                }

                if (fs.existsSync(resolvedPath)) {
                  // Recursively extract from the required file
                  // Create a new project for the required file
                  const requiredProject = new Project({
                    compilerOptions: PERMISSIVE_COMPILER_OPTIONS,
                  });

                  try {
                    const requiredSourceFile =
                      requiredProject.addSourceFileAtPath(resolvedPath);

                    // Pattern A: Look for module.exports.functionName = function(...) {...}
                    // This is used by DVNA's appHandler.js
                    for (const stmt of requiredSourceFile.getStatements()) {
                      if (stmt.getKindName() === "ExpressionStatement") {
                        const expr = stmt.getExpression();
                        if (expr && expr.getKindName() === "BinaryExpression") {
                          const left = expr.getLeft();
                          const right = expr.getRight();

                          if (
                            left &&
                            left.getKindName() === "PropertyAccessExpression"
                          ) {
                            const leftText = left.getText();
                            if (
                              leftText === `module.exports.${functionName}` ||
                              leftText === `exports.${functionName}`
                            ) {
                              if (
                                right &&
                                (right.getKindName() === "ArrowFunction" ||
                                  right.getKindName() === "FunctionExpression")
                              ) {
                                foundFunction = {
                                  node: right,
                                  code: right.getFullText(),
                                  name: functionName,
                                  class_name: className,
                                  start_line: right.getStartLineNumber(),
                                  end_line: right.getEndLineNumber(),
                                  source_file: resolvedPath,
                                };
                                break;
                              }
                            }
                          }
                        }
                      }
                      if (foundFunction) break;
                    }

                    // Pattern B: Look for constructor function pattern in the required file
                    // This is used by NodeGoat's sessionHandler, etc.
                    if (!foundFunction) {
                      for (const func of requiredSourceFile.getFunctions()) {
                        const funcName = func.getName();
                        // Match against both original className and PascalCase version
                        if (
                          funcName === className ||
                          funcName === classNamePascal ||
                          funcName === declName
                        ) {
                          const body = func.getBody();
                          if (!body) continue;

                          for (const stmt of body.getStatements
                            ? body.getStatements()
                            : []) {
                            if (stmt.getKindName() === "ExpressionStatement") {
                              const expr = stmt.getExpression();
                              if (
                                expr &&
                                expr.getKindName() === "BinaryExpression"
                              ) {
                                const left = expr.getLeft();
                                const right = expr.getRight();

                                if (
                                  left &&
                                  left.getText() === `this.${functionName}`
                                ) {
                                  if (
                                    right &&
                                    (right.getKindName() === "ArrowFunction" ||
                                      right.getKindName() ===
                                        "FunctionExpression")
                                  ) {
                                    foundFunction = {
                                      node: right,
                                      code: right.getFullText(),
                                      name: functionName,
                                      class_name: className,
                                      start_line: right.getStartLineNumber(),
                                      end_line: right.getEndLineNumber(),
                                      source_file: resolvedPath,
                                    };
                                    break;
                                  }
                                }
                              }
                            }
                          }
                          if (foundFunction) break;
                        }
                      }
                    }
                  } catch (e) {
                    // Failed to parse required file, continue
                  }
                }
              }
            }
          }
        }
        if (foundFunction) break;
      }
    }

    if (foundFunction) {
      // Output just the function data
      console.log(
        JSON.stringify(
          {
            code: foundFunction.code,
            start_line: foundFunction.start_line,
            end_line: foundFunction.end_line,
            name: foundFunction.name,
            class_name: foundFunction.class_name,
          },
          null,
          2,
        ),
      );
      process.exit(0);
    } else {
      console.error(`Function not found: ${functionRef} in ${filePath}`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`Failed to extract function: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  }
}

// Main execution
if (require.main === module) {
  const args = process.argv.slice(2);
  const fs = require("fs");

  if (args.length < 2) {
    console.error("Usage:");
    console.error(
      "  Batch mode:  node typescript_analyzer.js <repo_path> <file1> <file2> ...",
    );
    console.error(
      "  Batch mode:  node typescript_analyzer.js <repo_path> --files-from <list.txt> [--output <output.json>]",
    );
    console.error(
      "  Single mode: node typescript_analyzer.js <file_path> <function_ref>",
    );
    process.exit(1);
  }

  // Detect mode based on first argument
  const firstArg = args[0];
  const isDirectory =
    fs.existsSync(firstArg) && fs.statSync(firstArg).isDirectory();
  const isFile = fs.existsSync(firstArg) && fs.statSync(firstArg).isFile();

  try {
    if (isDirectory && args.length >= 2) {
      // Batch mode: analyze multiple files
      const repoPath = args[0];
      let filePaths;
      let outputFile = null;

      // Parse options
      let i = 1;
      while (i < args.length) {
        if (args[i] === "--files-from" && i + 1 < args.length) {
          const listFile = args[i + 1];
          if (!fs.existsSync(listFile)) {
            console.error(`File list not found: ${listFile}`);
            process.exit(1);
          }
          const content = fs.readFileSync(listFile, "utf-8");
          // Split on either CRLF or LF and trim residual whitespace so
          // file lists written on Windows (with \r\n line endings) don't
          // leave a trailing \r on each path, which would make
          // addSourceFileAtPath fail.
          filePaths = content
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter((line) => line.length > 0);
          console.error(`Loaded ${filePaths.length} files from ${listFile}`);
          i += 2;
        } else if (args[i] === "--output" && i + 1 < args.length) {
          outputFile = args[i + 1];
          i += 2;
        } else {
          // Assume it's a file path
          if (!filePaths) filePaths = [];
          filePaths.push(args[i]);
          i++;
        }
      }

      if (!filePaths || filePaths.length === 0) {
        console.error("No files to analyze");
        process.exit(1);
      }

      const analyzer = new TypeScriptAnalyzer(repoPath);
      const result = analyzer.analyzeFiles(filePaths);

      // Output JSON
      const jsonOutput = JSON.stringify(result, null, 2);
      if (outputFile) {
        fs.writeFileSync(outputFile, jsonOutput);
        console.error(`Output written to ${outputFile}`);
      } else {
        console.log(jsonOutput);
      }
      process.exit(0);
    } else if ((isFile || !fs.existsSync(firstArg)) && args.length === 2) {
      // Single function mode: extract one function
      const filePath = args[0];
      const functionRef = args[1];

      extractSingleFunction(filePath, functionRef);
    } else {
      console.error("Invalid arguments. Could not determine mode.");
      console.error(
        `First argument: ${firstArg} (exists: ${fs.existsSync(firstArg)}, isDir: ${isDirectory}, isFile: ${isFile})`,
      );
      console.error(`Argument count: ${args.length}`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`Analysis failed: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  }
}

module.exports = { TypeScriptAnalyzer };
