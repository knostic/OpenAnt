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
    this.classes = {};   // "filePath:className" -> { constructorDeps, fieldDeps, baseTypes }
    this.callGraph = {}; // callerId -> array of call info { resolved, name }
    // Resolved bidirectional graph (snake_case, list-of-resolved-ids) matching
    // the C/Python/Ruby sibling contract consumed by the Python pipeline.
    this.resolvedCallGraph = {};  // callerId -> [resolvedCalleeId]
    this.reverseCallGraph = {};   // calleeId -> [callerId]
    this.indirectCalls = {};      // callerId -> [unresolved/dynamic call names]
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
   * Check if a function's parameter shape matches a known web-framework route
   * handler (Express / Koa / Fastify).
   *
   * The bare `(request, response)` pattern was removed: it is ambiguous and
   * misfires on React components (`function MyComponent(request, response)`)
   * which share those parameter names. Fastify's distinctive
   * `(request, reply)` shape is added. The
   * remaining patterns (`(req, res)`, Koa `(ctx)`, TS `: Request`/`: Response`
   * type annotations) are framework-specific enough to be reliable.
   */
  _hasRouteHandlerSignature(code) {
    const handlerPatterns = [
      /\(\s*req\s*,\s*res\s*[,\)]/, // Express (req, res) / (req, res, next)
      /\(\s*request\s*,\s*reply\s*[,\)]/, // Fastify (request, reply)
      /\(\s*ctx\s*[,\)]/, // Koa style (ctx)
      /:\s*Request\s*,/, // TypeScript: Request type
      /:\s*Response\s*[,\)]/, // TypeScript: Response type
      /:\s*FastifyRequest\b/, // TypeScript Fastify: FastifyRequest type
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

    // Step 4: Backstop the Pattern-A companion invariant — every function in
    // the inventory must have a callGraph key.
    // The emit-time companions above cover the AST-walked paths; this fills any
    // remaining function (e.g. re-export references) with an empty edge list so
    // `len(callGraph) === len(functions)` always holds.
    for (const functionId of Object.keys(this.functions)) {
      if (!(functionId in this.callGraph)) {
        this.callGraph[functionId] = [];
      }
    }

    // Step 4.5: Stamp the snake_case schema-contract fields downstream Python
    // consumers expect. EntryPointDetector keys off `unit_type`;
    // without it no Express route is ever seen as an entry point and every
    // reachable callee is filtered out. We keep the camelCase `unitType` too so
    // the JS unit_generator continues to work.
    for (const funcData of Object.values(this.functions)) {
      if (funcData.unit_type === undefined) {
        funcData.unit_type = funcData.unitType || "function";
      }
      if (funcData.parameters === undefined) {
        funcData.parameters = [];
      }
    }

    // Step 5: Build the resolved bidirectional graph + per-function metadata
    // expected by downstream Python consumers (snake_case call_graph /
    // reverse_call_graph of resolved ids, repository, per-fn parameters).
    this._buildResolvedGraphs();

    return {
      repository: this.repoPath,
      functions: this.functions,
      classes: this.classes,
      callGraph: this.callGraph,
      call_graph: this.resolvedCallGraph,
      reverse_call_graph: this.reverseCallGraph,
      indirect_calls: this.indirectCalls,
    };
  }

  /**
   * Extract all functions/methods from a source file
   */
  // Module-level FunctionDeclarations: top-level OR nested only inside blocks /
  // control-flow statements (if/else, try/catch, for/while, switch, bare {}) —
  // NOT inside another function/method/accessor (their text already rides inside
  // the parent unit) and NOT inside a class `static {}` block (block-scoped to
  // the initializer, callable nowhere). `getFunctions()` returned only top-level
  // declarations, so block-scoped functions were silently dropped from both the
  // inventory and the call graph. Returns [{node, id}] with COLLISION-ONLY
  // `#L<line>` disambiguation (sibling-block same-name functions are both
  // runtime-reachable, so keep both; unique names keep the plain `path:name`
  // id). Both the inventory and call-graph builders iterate this same list so
  // their keys match exactly (the `len(callGraph) === len(functions)` lockstep).
  // The named FunctionDeclaration nodes that are module-level (top-level OR only
  // block-nested), excluding function-nested and static-block-scoped ones. Used
  // by the inventory builder, the call-graph builder, AND the resolver — all
  // three must see the same set so a block function is a unit, has its own
  // edges, and is resolvable as a call target.
  _moduleLevelFunctionNodes(sourceFile) {
    const STOP = new Set([
      ts.SyntaxKind.FunctionDeclaration,
      ts.SyntaxKind.FunctionExpression,
      ts.SyntaxKind.ArrowFunction,
      ts.SyntaxKind.MethodDeclaration,
      ts.SyntaxKind.Constructor,
      ts.SyntaxKind.GetAccessor,
      ts.SyntaxKind.SetAccessor,
      ts.SyntaxKind.ClassStaticBlockDeclaration,
    ]);
    const isModuleLevel = (fn) => {
      for (let p = fn.getParent(); p; p = p.getParent()) {
        if (STOP.has(p.getKind())) return false;
      }
      return true;
    };
    return sourceFile
      .getDescendantsOfKind(ts.SyntaxKind.FunctionDeclaration)
      .filter((fn) => fn.getName() && isModuleLevel(fn));
  }

  _moduleLevelFunctionEntries(sourceFile, relativePath) {
    const fns = this._moduleLevelFunctionNodes(sourceFile);
    const countByName = {};
    for (const fn of fns) {
      const n = fn.getName();
      countByName[n] = (countByName[n] || 0) + 1;
    }
    const seen = new Set();
    return fns.map((fn) => {
      const name = fn.getName();
      let id = `${relativePath}:${name}`;
      if (countByName[name] > 1) {
        // collision-only: keep both, deterministic by source line (never by
        // emit order). Colon-free `#L` suffix survives the downstream
        // `split(':')[0]` (file) / `rsplit(':',1)[-1]` (name) id contracts.
        let uid = `${id}#L${fn.getStartLineNumber()}`;
        while (seen.has(uid)) uid = `${uid}.x`;
        seen.add(uid);
        id = uid;
      }
      return { node: fn, id };
    });
  }

  extractFunctionsFromFile(sourceFile) {
    // Always emit POSIX-style relative paths so functionId values are
    // stable across platforms (Python downstream consumers and dataset
    // diffs key off these strings).
    const relativePath = toPosixPath(
      path.relative(this.repoPath, sourceFile.getFilePath()),
    );

    // Extract function declarations (top-level + module-level block-scoped).
    for (const { node: func, id: functionId } of this._moduleLevelFunctionEntries(
      sourceFile,
      relativePath,
    )) {
      const name = func.getName();
      const code = func.getFullText();
      this.functions[functionId] = {
        name: name,
        code: code,
        isExported: func.isExported(),
        unitType: this.classifyFunction(name, code, false, null),
        startLine: func.getStartLineNumber(),
        endLine: func.getEndLineNumber(),
        parameters: this._extractParameters(func),
      };
    }

    // Extract arrow functions assigned to variables/constants.
    // Also covers Higher-Order-Component wrappers whose initializer is a call
    // expression containing an inline function — `const X = memo(() => {})`,
    // `forwardRef((p, r) => {})`, `styled.div\`...\``.
    for (const statement of sourceFile.getVariableStatements()) {
      for (const declaration of statement.getDeclarations()) {
        const initializer = declaration.getInitializer();
        if (!initializer) continue;
        const initKind = initializer.getKindName();
        const isDirectFunction =
          initKind === "ArrowFunction" || initKind === "FunctionExpression";
        const isHocWrapper =
          !isDirectFunction && this._isFunctionProducingInitializer(initializer);
        if (isDirectFunction || isHocWrapper) {
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
            parameters: isDirectFunction
              ? this._extractParameters(initializer)
              : [],
          };
        }
      }
    }

    // Extract methods from classes
    for (const classDecl of sourceFile.getClasses()) {
      const className = classDecl.getName() || "AnonymousClass";

      // getMethods() excludes get/set accessors, so iterate the
      // accessor lists too. They share the member-naming contract (Class.name).
      const classMembers = [
        ...classDecl.getMethods(),
        ...classDecl.getGetAccessors(),
        ...classDecl.getSetAccessors(),
      ];
      for (const method of classMembers) {
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
          parameters: this._extractParameters(method),
        };
      }

      // Build class-level metadata: constructorDeps and baseTypes
      const classEntry = {};

      // Extract base types (implements + extends) for nominal DI resolution.
      // Strips generics: implements Repository<User> -> Repository
      const baseTypes = [];
      const extendsExpr = classDecl.getExtends();
      if (extendsExpr) {
        const name = extendsExpr.getExpression().getText().replace(/<.*$/, '');
        if (/^[A-Z][a-zA-Z0-9_$]*$/.test(name)) baseTypes.push(name);
      }
      for (const impl of classDecl.getImplements()) {
        const name = impl.getExpression().getText().replace(/<.*$/, '');
        if (/^[A-Z][a-zA-Z0-9_$]*$/.test(name)) baseTypes.push(name);
      }
      if (baseTypes.length > 0) classEntry.baseTypes = baseTypes;

      // Extract constructor DI metadata.
      // DI classes have a single primary constructor; overloads are unusual in NestJS/Angular.
      const constructors = classDecl.getConstructors();
      if (constructors.length > 0) {
        const ctor = constructors[0];
        const injections = {};  // paramName -> typeName

        for (const param of ctor.getParameters()) {
          const paramName = param.getName();
          const typeNode = param.getTypeNode();
          if (typeNode) {
            // Strip generic parameters so Repository<User> resolves as Repository
            const typeName = typeNode.getText().replace(/<.*$/, '');
            // Only store simple PascalCase type names (skip union types, primitives)
            if (/^[A-Z][a-zA-Z0-9_$]*$/.test(typeName)) {
              injections[paramName] = typeName;
            }
          }
        }

        if (Object.keys(injections).length > 0) classEntry.constructorDeps = injections;
      }

      // Extract field/property injection metadata.
      // Covers decorator-based (@Inject, @InjectRepository, etc.) and Angular's inject() function.
      const fieldDeps = {};
      for (const prop of classDecl.getProperties()) {
        const propName = prop.getName();
        let typeName = null;

        // Decorator-based: any @Inject* decorator signals an injection point;
        // the injected type comes from the TypeScript type annotation.
        const hasInjectDecorator = prop.getDecorators().some(d => /^Inject/.test(d.getName()));
        if (hasInjectDecorator) {
          const typeNode = prop.getTypeNode();
          if (typeNode) {
            const t = typeNode.getText().replace(/<.*$/, '');
            if (/^[A-Z][a-zA-Z0-9_$]*$/.test(t)) typeName = t;
          }
        }

        // Functional: private svc = inject(SvcType)  (Angular inject() API)
        if (!typeName) {
          const init = prop.getInitializer();
          if (init && init.getKindName() === 'CallExpression') {
            const expr = init.getExpression();
            if (expr && expr.getText() === 'inject') {
              const args = init.getArguments();
              if (args.length > 0) {
                const t = args[0].getText().replace(/<.*$/, '');
                if (/^[A-Z][a-zA-Z0-9_$]*$/.test(t)) typeName = t;
              }
            }
          }
        }

        if (typeName) fieldDeps[propName] = typeName;
      }
      if (Object.keys(fieldDeps).length > 0) classEntry.fieldDeps = fieldDeps;

      if (Object.keys(classEntry).length > 0) {
        this.classes[`${relativePath}:${className}`] = classEntry;
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

    // Extract anonymous callbacks used as Express route handlers / middleware
    // Pattern: app.get('/x', auth, async (req, res) => {...})
    this._extractExpressRouteCallbacks(sourceFile, relativePath);

    // Extract methods from class *expressions* (module.exports = class {...},
    // const X = class {...}) which getClasses() does not return.
    this._extractClassExpressionMethods(sourceFile, relativePath);

    // Extract anonymous `export default function(){...}`.
    this._extractAnonymousDefaultExport(sourceFile, relativePath);

    // Extract prototype / this-assignment / Object.assign / defineProperty
    // method shapes that aren't class members or top-level functions.
    this._extractAssignedMethods(sourceFile, relativePath);

    // Extract a synthetic unit for files whose only meaningful content is a
    // bare top-level side-effect call, e.g. preload scripts calling
    // contextBridge.exposeInMainWorld({...}).
    this._extractTopLevelSideEffects(sourceFile, relativePath);
  }

  /**
   * True if `node` is a call/tagged-template whose argument list contains an
   * inline function — the Higher-Order-Component pattern. Examples:
   *   memo(() => {})            forwardRef((p, r) => {})
   *   React.memo(function(){})  styled.div`...`
   */
  _isFunctionProducingInitializer(node) {
    if (!node) return false;
    const kind = node.getKindName();
    if (kind === "CallExpression") {
      const args = node.getArguments ? node.getArguments() : [];
      return args.some((a) => {
        const k = a.getKindName();
        return k === "ArrowFunction" || k === "FunctionExpression";
      });
    }
    if (kind === "TaggedTemplateExpression") {
      // styled.div`...` / css`...` — component-producing template tags.
      return true;
    }
    return false;
  }

  /**
   * True if `node` is a re-export reference value, e.g. `require('./x').foo`
   * or a bare identifier/property-access that names an exported symbol.
   */
  _isReexportInitializer(node) {
    if (!node) return false;
    const kind = node.getKindName();
    if (kind === "PropertyAccessExpression") {
      // require('./x').foo  or  mod.foo
      return /require\s*\(|\./.test(node.getText());
    }
    return false;
  }

  /**
   * Extract methods declared inside class *expressions* (not ClassDeclarations,
   * which getClasses() already covers). Names the class from the binding it is
   * assigned to where possible, else "AnonymousClass".
   */
  _extractClassExpressionMethods(sourceFile, relativePath) {
    const classExprs = sourceFile.getDescendantsOfKind(
      ts.SyntaxKind.ClassExpression,
    );
    for (const classExpr of classExprs) {
      const className =
        (classExpr.getName && classExpr.getName()) ||
        this._inferAssignedName(classExpr) ||
        "AnonymousClass";

      const methods = classExpr.getMethods ? classExpr.getMethods() : [];
      for (const method of methods) {
        const methodName = method.getName();
        const functionId = `${relativePath}:${className}.${methodName}`;
        if (this.functions[functionId]) continue;
        const code = method.getFullText();
        this.functions[functionId] = {
          name: `${className}.${methodName}`,
          code: code,
          isExported: false,
          unitType: this.classifyFunction(methodName, code, true, className),
          startLine: method.getStartLineNumber(),
          endLine: method.getEndLineNumber(),
          className: className,
        };
        this.callGraph[functionId] = this.extractCallsFromFunction(
          method,
          relativePath,
        );
      }
    }
  }

  /**
   * Infer the binding name a node is assigned to:
   *   const X = <node>            -> "X"
   *   module.exports = <node>     -> "exports"
   */
  _inferAssignedName(node) {
    const parent = node.getParent && node.getParent();
    if (!parent) return null;
    const pk = parent.getKindName();
    if (pk === "VariableDeclaration" && parent.getName) {
      return parent.getName();
    }
    if (pk === "BinaryExpression" && parent.getLeft) {
      const leftText = parent.getLeft().getText();
      if (leftText === "module.exports" || leftText === "exports") {
        return "exports";
      }
      return leftText;
    }
    return null;
  }

  /**
   * Extract anonymous `export default function(){...}`.
   *
   * ts-morph parses `export default function(){}` as a *nameless* exported
   * FunctionDeclaration (the named-declaration loop skips it via
   * `if (!name) continue`), and parses `export default () => {}` as an
   * ExportAssignment. Handle both.
   */
  _extractAnonymousDefaultExport(sourceFile, relativePath) {
    const emit = (node, code, bodyNode) => {
      const functionId = `${relativePath}:default`;
      if (this.functions[functionId]) return;
      this.functions[functionId] = {
        name: "default",
        code: code,
        isExported: true,
        unitType: this.classifyFunction("default", code, false, null),
        startLine: node.getStartLineNumber(),
        endLine: node.getEndLineNumber(),
        exportType: "default",
      };
      this.callGraph[functionId] = this.extractCallsFromFunction(
        bodyNode,
        relativePath,
      );
    };

    // Nameless default-exported function declaration.
    for (const func of sourceFile.getFunctions()) {
      if (func.getName()) continue;
      if (func.isDefaultExport && func.isDefaultExport()) {
        emit(func, func.getFullText(), func);
      }
    }

    // `export default () => {}` / `export default function(){}` expressions.
    for (const exportDecl of sourceFile.getExportAssignments()) {
      if (exportDecl.isExportEquals && exportDecl.isExportEquals()) continue;
      const expr = exportDecl.getExpression();
      if (!expr) continue;
      const k = expr.getKindName();
      if (k === "ArrowFunction" || k === "FunctionExpression") {
        emit(exportDecl, exportDecl.getFullText(), expr);
      }
    }
  }

  /**
   * Extract function-valued assignments that aren't class members or named
   * declarations:
   *   Foo.prototype.bar = function(){}
   *   function Ctor(){ this.method = fn; }
   *   Object.assign(Foo.prototype, { m(){}, n: fn })
   *   Object.defineProperty(X.prototype, "n", { value: fn })
   *
   * We walk every CallExpression / BinaryExpression descendant so the shape is
   * found regardless of whether it lives at top level or inside a constructor
   * function body.
   */
  _extractAssignedMethods(sourceFile, relativePath) {
    // 1. Assignment expressions: X.prototype.m = fn  /  this.m = fn
    for (const bin of sourceFile.getDescendantsOfKind(
      ts.SyntaxKind.BinaryExpression,
    )) {
      if (bin.getOperatorToken().getText() !== "=") continue;
      const left = bin.getLeft();
      const right = bin.getRight();
      if (!left || left.getKindName() !== "PropertyAccessExpression") continue;
      const rk = right && right.getKindName();
      if (rk !== "ArrowFunction" && rk !== "FunctionExpression") continue;

      const qualified = this._qualifiedNameForAssignmentTarget(
        left,
        bin,
        relativePath,
      );
      if (!qualified) continue;
      this._emitAssignedFunction(qualified, right, relativePath);
    }

    // 2. Object.assign(<ClassOrProto>, { ... })  and
    //    Object.defineProperty(<ClassOrProto>, "name", { value: fn })
    for (const call of sourceFile.getDescendantsOfKind(
      ts.SyntaxKind.CallExpression,
    )) {
      const callee = call.getExpression();
      if (!callee || callee.getKindName() !== "PropertyAccessExpression") {
        continue;
      }
      const objText =
        callee.getExpression && callee.getExpression()
          ? callee.getExpression().getText()
          : null;
      const member = callee.getName ? callee.getName() : null;
      if (objText !== "Object") continue;
      const args = call.getArguments();

      if (member === "assign" && args.length >= 2) {
        const target = this._receiverClassName(args[0]);
        if (!target) continue;
        const objLit = args[1];
        if (objLit.getKindName() !== "ObjectLiteralExpression") continue;
        for (const prop of objLit.getProperties()) {
          const pk = prop.getKindName();
          let propName = null;
          let fnNode = null;
          if (pk === "MethodDeclaration") {
            propName = prop.getName();
            fnNode = prop;
          } else if (pk === "PropertyAssignment") {
            propName = prop.getName();
            const init = prop.getInitializer();
            const ik = init && init.getKindName();
            if (ik === "ArrowFunction" || ik === "FunctionExpression") {
              fnNode = init;
            }
          }
          if (propName && fnNode) {
            this._emitAssignedFunction(
              `${target}.${propName}`,
              fnNode,
              relativePath,
            );
          }
        }
      } else if (member === "defineProperty" && args.length >= 3) {
        const target = this._receiverClassName(args[0]);
        const nameArg = args[1];
        const descriptor = args[2];
        if (!target) continue;
        if (
          nameArg.getKindName() !== "StringLiteral" ||
          descriptor.getKindName() !== "ObjectLiteralExpression"
        ) {
          continue;
        }
        const propName = nameArg.getLiteralValue
          ? nameArg.getLiteralValue()
          : nameArg.getText().slice(1, -1);
        for (const prop of descriptor.getProperties()) {
          if (prop.getKindName() !== "PropertyAssignment") continue;
          const dName = prop.getName();
          if (dName !== "value" && dName !== "get" && dName !== "set") continue;
          const init = prop.getInitializer();
          const ik = init && init.getKindName();
          if (ik === "ArrowFunction" || ik === "FunctionExpression") {
            this._emitAssignedFunction(
              `${target}.${propName}`,
              init,
              relativePath,
            );
          }
        }
      }
    }
  }

  /**
   * Map an assignment target PropertyAccessExpression to a qualified
   * "Class.member" name.
   *   Foo.prototype.bar  -> "Foo.bar"
   *   this.bar (in fn F)  -> "F.bar"
   */
  _qualifiedNameForAssignmentTarget(left, binExpr, relativePath) {
    const member = left.getName ? left.getName() : null;
    if (!member) return null;
    const obj = left.getExpression ? left.getExpression() : null;
    if (!obj) return null;
    const objKind = obj.getKindName();

    if (objKind === "PropertyAccessExpression") {
      // Foo.prototype.bar  ->  obj is `Foo.prototype`
      if (obj.getName && obj.getName() === "prototype") {
        const cls = obj.getExpression ? obj.getExpression().getText() : null;
        if (cls) return `${cls}.${member}`;
      }
      return null;
    }

    if (objKind === "ThisKeyword") {
      // this.bar — name the enclosing function as the class.
      const cls = this._enclosingFunctionName(binExpr);
      if (cls) return `${cls}.${member}`;
    }
    return null;
  }

  /**
   * The name of the nearest enclosing named function declaration (used to
   * label `this.method = fn` assignments inside constructor functions).
   */
  _enclosingFunctionName(node) {
    let cur = node.getParent && node.getParent();
    while (cur) {
      const k = cur.getKindName();
      if (k === "FunctionDeclaration" && cur.getName && cur.getName()) {
        return cur.getName();
      }
      cur = cur.getParent && cur.getParent();
    }
    return null;
  }

  /**
   * Resolve a `Object.assign`/`Object.defineProperty` first argument to a class
   * name. Accepts `Foo.prototype` -> "Foo" and bare `Foo` -> "Foo".
   */
  _receiverClassName(arg) {
    if (!arg) return null;
    const k = arg.getKindName();
    if (k === "PropertyAccessExpression") {
      if (arg.getName && arg.getName() === "prototype") {
        return arg.getExpression ? arg.getExpression().getText() : null;
      }
      return null;
    }
    if (k === "Identifier") {
      return arg.getText();
    }
    return null;
  }

  /**
   * Emit a function entry for an assigned method shape, keyed
   * "<relativePath>:<qualifiedName>".
   */
  _emitAssignedFunction(qualifiedName, fnNode, relativePath) {
    const functionId = `${relativePath}:${qualifiedName}`;
    if (this.functions[functionId]) return;
    const code = fnNode.getFullText();
    const methodName = qualifiedName.includes(".")
      ? qualifiedName.split(".").pop()
      : qualifiedName;
    const className = qualifiedName.includes(".")
      ? qualifiedName.slice(0, qualifiedName.lastIndexOf("."))
      : null;
    this.functions[functionId] = {
      name: qualifiedName,
      code: code,
      isExported: false,
      unitType: this.classifyFunction(methodName, code, className !== null, className),
      startLine: fnNode.getStartLineNumber(),
      endLine: fnNode.getEndLineNumber(),
      className: className,
    };
    // Pattern-A companion: emit the callGraph entry alongside the function so
    // `len(callGraph) === len(functions)` holds.
    this.callGraph[functionId] = this.extractCallsFromFunction(
      fnNode,
      relativePath,
    );
  }

  /**
   * Emit a synthetic unit when a file's top-level statements are dominated by
   * a bare side-effect call (e.g. an Electron preload script that only calls
   * contextBridge.exposeInMainWorld({...})). Without this, such files yield
   * zero units even though they carry analysable behaviour.
   */
  _extractTopLevelSideEffects(sourceFile, relativePath) {
    // Only synthesise when the regular extractors produced nothing for this
    // file — otherwise we'd duplicate real functions/methods.
    const filePrefix = `${relativePath}:`;
    const hasAny = Object.keys(this.functions).some((id) =>
      id.startsWith(filePrefix),
    );
    if (hasAny) return;

    for (const statement of sourceFile.getStatements()) {
      if (statement.getKindName() !== "ExpressionStatement") continue;
      const expr = statement.getExpression();
      if (!expr || expr.getKindName() !== "CallExpression") continue;

      const callee = expr.getExpression();
      let label = "module";
      if (callee && callee.getKindName() === "PropertyAccessExpression") {
        const obj = callee.getExpression
          ? callee.getExpression().getText()
          : "";
        const member = callee.getName ? callee.getName() : "";
        label = member ? `${obj}.${member}` : obj || "module";
      } else if (callee && callee.getKindName() === "Identifier") {
        label = callee.getText();
      }

      const functionId = `${relativePath}:${label}`;
      if (this.functions[functionId]) continue;
      const code = statement.getFullText();
      this.functions[functionId] = {
        name: label,
        code: code,
        isExported: false,
        unitType: "module_level",
        startLine: statement.getStartLineNumber(),
        endLine: statement.getEndLineNumber(),
      };
      // One synthetic unit per file is enough to make the file analysable.
      return;
    }
  }

  /**
   * HTTP verbs we recognise on a router/app/server object. Shared by Express,
   * Fastify and Koa router DSLs. `use` is included to pick
   * up middleware-mount callbacks; `route` covers `app.route('/x', handler)`
   * style registrations.
   */
  static EXPRESS_VERBS = new Set([
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "all",
    "route",
    "use",
  ]);

  /**
   * Walk a source file looking for Express-style route registrations and
   * emit a synthetic function entry for each anonymous arrow / function
   * expression used as a callback.
   *
   * Recognises patterns of the form:
   *   <obj>.<verb>(<path>, ...callbacks)
   *   <obj>.<verb>(...callbacks)         // only for `use`
   * where `<verb>` is one of the Express HTTP verbs (or `use`) and the
   * first argument (when present) is a string-literal path.
   *
   * For each anonymous callback at index >= 1 we synthesise a function
   * entry. The last anonymous-or-named callback is treated as the route
   * handler; earlier callbacks are middleware. Named identifiers in
   * callback positions are recorded as explicit call edges from the
   * synthesised callbacks (e.g. `authenticateToken` becomes an upstream
   * dependency of the handler so call-graph based analyses see the
   * relationship).
   */
  /**
   * Heuristic: does `receiver` look like an Express app / router?
   *
   * We accept identifiers whose name ends with or contains one of the common
   * Express app/router stems (case-insensitive), and chained calls like
   * `app.route(...)` or `router.route(...)`. We deliberately reject other
   * receivers so generic `.get(...)` calls on caches / clients / query-builders
   * aren't misread as routes.
   *
   * Accepted stems: app, router, routes, server, web, api, endpoints,
   * controller, plus framework names fastify and koa so
   * `fastify.get(...)` / `koa.get(...)` registrations are recognised alongside
   * Express. Codebases using single-word identifiers outside this list (e.g.
   * `http`) will not be extracted; add the stem here if needed.
   */
  // Stems that strongly suggest an Express/Fastify/Koa app/router/server object.
  static EXPRESS_RECEIVER_STEMS =
    "app|router|routes|server|web|api|endpoints|controller|fastify|koa";

  _isPlausibleExpressReceiver(receiver) {
    if (!receiver) return false;
    const kind = receiver.getKindName();
    const stems = TypeScriptAnalyzer.EXPRESS_RECEIVER_STEMS;

    if (kind === "Identifier") {
      const name = receiver.getText().toLowerCase();
      // Accept exact stems, suffix matches (myApp), and underscore-prefixed
      // variants (app_server) while rejecting generic short names.
      return new RegExp(`(^|_)(${stems})(\\d|$|_)`).test(name)
        || new RegExp(`(${stems})$`).test(name);
    }
    if (kind === "CallExpression") {
      // e.g. app.route('/x').get(...) — receiver is the .route() call
      const inner = receiver.getExpression && receiver.getExpression();
      if (inner && inner.getKindName && inner.getKindName() === "PropertyAccessExpression") {
        const innerName = inner.getName && inner.getName();
        if (innerName === "route" || innerName === "Router") return true;
      }
      return false;
    }
    if (kind === "PropertyAccessExpression") {
      // e.g. this.app.get(...) or express.Router().get(...) — accept when
      // the trailing identifier matches our identifier pattern.
      const trailing = receiver.getName && receiver.getName();
      if (!trailing) return false;
      const lower = trailing.toLowerCase();
      return new RegExp(`(${stems})$`).test(lower);
    }
    return false;
  }

  _extractExpressRouteCallbacks(sourceFile, relativePath) {
    const callExpressions = sourceFile
      .getDescendantsOfKind(ts.SyntaxKind.CallExpression);

    for (const callExpr of callExpressions) {
      const expression = callExpr.getExpression();
      if (!expression || expression.getKindName() !== "PropertyAccessExpression") {
        continue;
      }

      const methodName = expression.getName ? expression.getName() : null;
      if (!methodName || !TypeScriptAnalyzer.EXPRESS_VERBS.has(methodName)) {
        continue;
      }

      // Filter to plausibly-Express receivers. Without this we'd match any
      // `foo.get('x', () => {})` style call (e.g. cache lookups, query
      // builders) and synthesise bogus route units.
      const receiver = expression.getExpression
        ? expression.getExpression()
        : null;
      if (!this._isPlausibleExpressReceiver(receiver)) {
        continue;
      }

      const args = callExpr.getArguments();
      if (args.length === 0) continue;

      // Determine whether the first argument is a path string literal.
      const firstArg = args[0];
      const firstKind = firstArg.getKindName();
      let httpPath = null;
      let callbackStartIndex = 0;
      if (firstKind === "StringLiteral" || firstKind === "NoSubstitutionTemplateLiteral") {
        httpPath = firstArg.getLiteralValue
          ? firstArg.getLiteralValue()
          : firstArg.getText().slice(1, -1);
        callbackStartIndex = 1;
      } else if (methodName === "use") {
        // `app.use(middleware)` — no path, all args are callbacks.
        httpPath = null;
        callbackStartIndex = 0;
      } else {
        // Not an Express-shaped call (no string path and not `use`).
        continue;
      }

      // Gather the callback arguments (functions + named identifiers).
      const callbacks = args.slice(callbackStartIndex);
      if (callbacks.length === 0) continue;

      // We only emit units when at least one callback is an inline
      // anonymous function. Otherwise the existing extraction logic
      // already handles named handlers.
      const hasInline = callbacks.some((a) => {
        const k = a.getKindName();
        return k === "ArrowFunction" || k === "FunctionExpression";
      });
      if (!hasInline) continue;

      const httpMethod = methodName.toUpperCase();
      const lastCallbackIndex = callbacks.length - 1;

      // Collect named middleware identifiers (Identifier / PropertyAccess)
      // that appear as siblings in the args list. They become explicit
      // call-graph edges from each synthesised callback.
      const namedMiddleware = [];
      for (let i = 0; i < callbacks.length; i++) {
        const arg = callbacks[i];
        const k = arg.getKindName();
        if (k === "Identifier") {
          namedMiddleware.push(arg.getText());
        } else if (k === "PropertyAccessExpression") {
          // Stores only the trailing name (e.g. "auth" from "middleware.auth").
          // dependency_resolver._resolveCall looks up by simple name, so if
          // another unrelated function shares the same name the edge may
          // resolve to the wrong target (silent false-positive). This is a
          // known limitation of the current simple-name resolution model.
          const name = arg.getName ? arg.getName() : arg.getText();
          namedMiddleware.push(name);
        }
      }

      for (let i = 0; i < callbacks.length; i++) {
        const arg = callbacks[i];
        const k = arg.getKindName();
        if (k !== "ArrowFunction" && k !== "FunctionExpression") continue;

        // Only emit for *anonymous* function expressions. A function
        // expression with a name like `function named(req,res){}` is
        // already extracted elsewhere.
        if (k === "FunctionExpression" && arg.getName && arg.getName()) {
          continue;
        }

        const isHandler = i === lastCallbackIndex;
        const role = isHandler ? "handler" : `middleware:${i}`;
        const pathLabel = httpPath !== null ? httpPath : "";
        const baseName = pathLabel
          ? `${httpMethod} ${pathLabel} [${role}]`
          : `${httpMethod} [${role}]`;
        const synthName = baseName;

        const code = arg.getFullText();
        const startLine = arg.getStartLineNumber();
        const endLine = arg.getEndLineNumber();
        // Synthesise an ID that's stable per file/line so two routes on
        // the same line+path don't collide.
        const idSuffix = `${httpMethod}:${pathLabel}:${startLine}:${i}`;
        const functionId = `${relativePath}:express(${idSuffix})`;

        if (this.functions[functionId]) continue;

        const unitType = isHandler ? "route_handler" : "route_middleware";
        const explicitCalls = namedMiddleware.filter((n) => n && n !== synthName);

        this.functions[functionId] = {
          name: synthName,
          code: code,
          isExported: false,
          unitType: unitType,
          startLine: startLine,
          endLine: endLine,
          isEntryPoint: isHandler,
          routeMetadata: {
            http_method: httpMethod,
            http_path: httpPath,
            callback_index: i,
            total_callbacks: callbacks.length,
            named_middleware: explicitCalls,
          },
          explicitCalls: explicitCalls,
        };

        // Emit a callGraph entry for the synthesised callback so the
        // invariant `callGraph keys ≡ functions keys` holds. The named
        // middleware identifiers are recorded as upstream dependencies via
        // explicitCalls (merged downstream by dependency_resolver.js); here
        // we capture any inline call expressions from the callback body so
        // call-graph based analyses can see them too.
        this.callGraph[functionId] = this.extractCallsFromFunction(
          arg,
          relativePath,
        );
      }
    }
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
                // Pattern-A companion.
                this.callGraph[functionId] = this.extractCallsFromFunction(
                  right,
                  relativePath,
                );
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
        // The AST node whose body holds the function's call expressions, used
        // to emit the Pattern-A callGraph companion. null for re-exports.
        let bodyNode = null;

        if (kindName === "MethodDeclaration") {
          // Pattern: { methodName() { ... } }
          name = property.getName();
          code = property.getFullText();
          bodyNode = property;
        } else if (kindName === "ShorthandPropertyAssignment") {
          // Pattern: { methodName } - references a variable defined elsewhere
          name = property.getName();
          // For shorthand, the code is minimal, we'd need to find the actual definition
          // Skip for now as these reference functions already extracted above
          continue;
        } else if (kindName === "PropertyAssignment") {
          // Pattern: { methodName: () => { ... } } or { methodName: function() { ... } }
          // Also re-export barrels: { foo: require('./x').foo } — the value is
          // a function reference, not an inline function. We surface
          // the property so the re-exported symbol is visible downstream.
          name = property.getName();
          const initializer = property.getInitializer();
          if (
            initializer &&
            (initializer.getKindName() === "ArrowFunction" ||
              initializer.getKindName() === "FunctionExpression")
          ) {
            code = property.getFullText();
            bodyNode = initializer;
          } else if (initializer && this._isReexportInitializer(initializer)) {
            code = property.getFullText();
          } else {
            continue; // Not a function or re-export
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
            // Pattern-A companion. Re-export references have no
            // inline body; the Step-4 backstop fills them with [].
            if (bodyNode) {
              this.callGraph[functionId] = this.extractCallsFromFunction(
                bodyNode,
                relativePath,
              );
            }
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

    // Analyze function declarations (same enumeration + id scheme as the
    // inventory builder, so callGraph keys match functions keys exactly —
    // a block function must get its REAL outgoing edges, not a backstop []).
    for (const { node: func, id: callerId } of this._moduleLevelFunctionEntries(
      sourceFile,
      relativePath,
    )) {
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

      // Mirror the inventory builder: include get/set accessors so
      // every emitted function gets a callGraph companion (Pattern-A).
      const classMembers = [
        ...classDecl.getMethods(),
        ...classDecl.getGetAccessors(),
        ...classDecl.getSetAccessors(),
      ];
      for (const method of classMembers) {
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
   * Parameter names for a function-like node, used to populate the per-function
   * `parameters` schema field. Returns [] when the node has no
   * getParameters() accessor.
   */
  _extractParameters(node) {
    if (!node || !node.getParameters) return [];
    try {
      return node.getParameters().map((p) => p.getName());
    } catch {
      return [];
    }
  }

  /**
   * Normalise a call-expression callee to a simple identifier name, matching
   * the C parser's `_extract_call_name` contract:
   *   plain(...)                 -> "plain"
   *   obj.method(...)            -> "method"   (trailing member)
   *   foo.bar().baz(...)         -> "baz"      (trailing member of the chain)
   *   obj['m'](...)              -> null       (dynamic / element access)
   *   (expr)(...)                -> null
   * Returns null when no stable identifier name can be derived (the call is
   * then treated as dynamic/indirect).
   */
  _normalizeCallName(calleeExpr) {
    if (!calleeExpr) return null;
    const kind = calleeExpr.getKindName();
    if (kind === "Identifier") {
      return calleeExpr.getText();
    }
    if (kind === "PropertyAccessExpression") {
      // Trailing member name (e.g. `baz` from `foo.bar().baz`).
      return calleeExpr.getName ? calleeExpr.getName() : null;
    }
    // ElementAccessExpression (obj['m']), ParenthesizedExpression, etc. have no
    // stable identifier name — treat as dynamic.
    return null;
  }

  /**
   * Extract function calls from within a function body.
   *
   * Each entry is { resolved, name, dynamic }:
   *  - `name` is the normalised callee identifier or null.
   *  - `dynamic` is true when the callee has no stable identifier name
   *    (element access, IIFE, etc.) — bucketed into indirect_calls.
   * Identifier arguments passed to a call (callback arguments) are also
   * recorded as edges so `addEventListener('click', handler)` / `setTimeout(cb)`
   * / `arr.forEach(cb)` relationships are visible.
   */
  extractCallsFromFunction(funcNode, currentFile) {
    const calls = [];
    const seen = new Set();
    const pushName = (name, dynamic) => {
      const key = `${name} ${dynamic ? 1 : 0}`;
      if (seen.has(key)) return;
      seen.add(key);
      calls.push({ resolved: false, name: name, dynamic: dynamic });
    };

    const callExpressions = funcNode.getDescendantsOfKind(
      ts.SyntaxKind.CallExpression,
    );

    for (const callExpr of callExpressions) {
      const callee = callExpr.getExpression();
      const normalized = this._normalizeCallName(callee);
      if (normalized) {
        pushName(normalized, false);
      } else {
        // Dynamic / element-access callee — record the raw span trimmed to a
        // single line so node names never become multiline blobs.
        const raw = callee ? callee.getText().replace(/\s+/g, " ").trim() : "";
        pushName(raw, true);
      }

      // Callback arguments: bare identifiers handed to the call become edges.
      for (const arg of callExpr.getArguments()) {
        if (arg.getKindName() === "Identifier") {
          pushName(arg.getText(), false);
        }
      }
    }

    return calls;
  }

  /**
   * Build the resolved bidirectional call graph and indirect-call buckets in
   * the snake_case shape the Python pipeline consumes. Resolution is JS-native
   * and conservative:
   * same-file name match, else unique-name match across the repo — mirroring
   * the contract the C/Ruby siblings satisfy, without lifting their code.
   *
   * Also stamps per-function `parameters` metadata so the schema contract is
   * complete.
   */
  _buildResolvedGraphs() {
    // Index functions by file and by simple name for resolution.
    const byFile = Object.create(null);
    const byName = Object.create(null);
    for (const funcId of Object.keys(this.functions)) {
      const file = funcId.slice(0, funcId.lastIndexOf(":"));
      (byFile[file] = byFile[file] || []).push(funcId);
      const simple = (this.functions[funcId].name || "").split(".").pop();
      (byName[simple] = byName[simple] || []).push(funcId);
    }

    const resolveName = (name, callerFile) => {
      // 1. Same-file simple-name match.
      for (const funcId of byFile[callerFile] || []) {
        const fname = this.functions[funcId].name || "";
        if (fname === name || fname.endsWith("." + name)) return funcId;
      }
      // 2. Unique-name match across the repo.
      const candidates = byName[name];
      if (candidates && candidates.length === 1) return candidates[0];
      return null;
    };

    for (const [callerId, edges] of Object.entries(this.callGraph)) {
      const callerFile = callerId.slice(0, callerId.lastIndexOf(":"));
      const resolvedTargets = [];
      const indirect = [];

      for (const edge of edges) {
        const name = edge && edge.name;
        if (!name) continue;
        if (edge.dynamic) {
          if (!indirect.includes(name)) indirect.push(name);
          continue;
        }
        const target = resolveName(name, callerFile);
        if (target && target !== callerId) {
          if (!resolvedTargets.includes(target)) resolvedTargets.push(target);
        } else if (!target) {
          // Unresolvable static name — bucket as indirect so it isn't lost.
          if (!indirect.includes(name)) indirect.push(name);
        }
      }

      this.resolvedCallGraph[callerId] = resolvedTargets;
      if (indirect.length > 0) this.indirectCalls[callerId] = indirect;

      for (const target of resolvedTargets) {
        (this.reverseCallGraph[target] = this.reverseCallGraph[target] || []);
        if (!this.reverseCallGraph[target].includes(callerId)) {
          this.reverseCallGraph[target].push(callerId);
        }
      }
    }

    // Ensure every function has a (possibly empty) resolved entry.
    for (const funcId of Object.keys(this.functions)) {
      if (!(funcId in this.resolvedCallGraph)) {
        this.resolvedCallGraph[funcId] = [];
      }
    }
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
          // getMethods() excludes get/set accessors, so search the
          // accessor lists too when resolving a single member by name.
          const classMembers = [
            ...classDecl.getMethods(),
            ...classDecl.getGetAccessors(),
            ...classDecl.getSetAccessors(),
          ];
          for (const method of classMembers) {
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

    // 2. Try standalone function declarations (incl. module-level block-scoped,
    // so a call TO a function defined inside an if/try/for block resolves).
    if (!foundFunction) {
      for (const func of this._moduleLevelFunctionNodes(sourceFile)) {
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
