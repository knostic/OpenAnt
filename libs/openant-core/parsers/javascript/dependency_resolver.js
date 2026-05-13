#!/usr/bin/env node
/**
 * DependencyResolver - Resolves function dependencies for self-contained analysis units
 *
 * This component takes the analyzer output and:
 * 1. Builds a call graph by analyzing function bodies for call expressions
 * 2. Resolves function references to their definitions
 * 3. Collects transitive dependencies up to a configurable depth
 *
 * Usage:
 *   node dependency_resolver.js <analyzer_output.json> [--output <output.json>] [--depth <N>]
 *
 * Input: analyzer_output.json from typescript_analyzer.js
 * Output: Enhanced analyzer output with resolved call graph and dependency bundles
 */

const fs = require('fs');
const path = require('path');

class DependencyResolver {
  constructor(analyzerOutput, options = {}) {
    this.functions = analyzerOutput.functions || {};
    this.classes = analyzerOutput.classes || {};  // "filePath:className" -> { constructorDeps, fieldDeps, baseTypes }
    this.callGraph = {};  // functionId -> [calledFunctionIds]
    this.reverseCallGraph = {};  // functionId -> [callerFunctionIds]
    this.maxDepth = options.maxDepth || 3;
    this.repoRoot = analyzerOutput.repoRoot || '';

    // Build indexes for faster lookup
    this.functionsByName = Object.create(null);  // simpleName -> [functionIds]
    this.functionsByFile = Object.create(null);  // filePath -> [functionIds]
    this.imports = Object.create(null);  // filePath -> { importedName -> { source, originalName } }
    this.classesByBaseType = Object.create(null);  // baseTypeName -> ["filePath:className", ...]

    this._buildIndexes();
  }

  /**
   * Build lookup indexes from function inventory
   */
  _buildIndexes() {
    for (const [funcId, funcData] of Object.entries(this.functions)) {
      // Index by simple name (last part of qualified name)
      const simpleName = funcData.name.split('.').pop();
      if (!this.functionsByName[simpleName]) {
        this.functionsByName[simpleName] = [];
      }
      this.functionsByName[simpleName].push(funcId);

      // Index by file path
      const filePath = funcId.split(':')[0];
      if (!this.functionsByFile[filePath]) {
        this.functionsByFile[filePath] = [];
      }
      this.functionsByFile[filePath].push(funcId);
    }

    for (const [classKey, classData] of Object.entries(this.classes)) {
      for (const baseType of (classData.baseTypes || [])) {
        if (!this.classesByBaseType[baseType]) this.classesByBaseType[baseType] = [];
        this.classesByBaseType[baseType].push(classKey);
      }
    }
  }

  /**
   * Build call graph by analyzing function bodies
   */
  buildCallGraph() {
    for (const [funcId, funcData] of Object.entries(this.functions)) {
      const calls = this._extractCalls(funcData.code, funcId);
      this.callGraph[funcId] = calls;

      // Build reverse graph
      for (const calledId of calls) {
        if (!this.reverseCallGraph[calledId]) {
          this.reverseCallGraph[calledId] = [];
        }
        if (!this.reverseCallGraph[calledId].includes(funcId)) {
          this.reverseCallGraph[calledId].push(funcId);
        }
      }
    }

    return this.callGraph;
  }

  /**
   * Extract function calls from code and resolve to function IDs
   */
  _extractCalls(code, callerFuncId) {
    const calls = [];
    const callerFile = callerFuncId.split(':')[0];

    // Match function call patterns
    // 1. Simple calls: functionName(...)
    // 2. Method calls: object.method(...)
    // 3. Chained calls: object.method1().method2(...)
    // 4. Async/await calls: await functionName(...)

    const patterns = [
      // await asyncFunction(args)
      /await\s+([a-zA-Z_$][\w$]*)\s*\(/g,
      // this.method(args)
      /this\.([a-zA-Z_$][\w$]*)\s*\(/g,
      // object.method(args) - captures both object and method
      /([a-zA-Z_$][\w$]*)\.([a-zA-Z_$][\w$]*)\s*\(/g,
      // standalone function(args)
      /(?<![.\w$])([a-zA-Z_$][\w$]*)\s*\(/g,
    ];

    const seenCalls = new Set();

    // Pattern 1: await calls
    let match;
    const awaitPattern = /await\s+([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = awaitPattern.exec(code)) !== null) {
      const funcName = match[1];
      const resolved = this._resolveCall(funcName, callerFile, callerFuncId);
      if (resolved && !seenCalls.has(resolved)) {
        seenCalls.add(resolved);
        calls.push(resolved);
      }
    }

    // Pattern 2: this.method calls (within the same class)
    const thisPattern = /this\.([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = thisPattern.exec(code)) !== null) {
      const methodName = match[1];
      const resolved = this._resolveThisCall(methodName, callerFuncId);
      if (resolved && !seenCalls.has(resolved)) {
        seenCalls.add(resolved);
        calls.push(resolved);
      }
    }

    // Pattern 3: object.method calls
    const methodPattern = /([a-zA-Z_$][\w$]*)\.([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = methodPattern.exec(code)) !== null) {
      const objectName = match[1];
      const methodName = match[2];

      // Skip 'this' (handled above) and common built-ins
      if (objectName === 'this' || this._isBuiltIn(objectName)) continue;

      const resolved = this._resolveMethodCall(objectName, methodName, callerFile, callerFuncId);
      if (resolved && !seenCalls.has(resolved)) {
        seenCalls.add(resolved);
        calls.push(resolved);
      }
    }

    // Pattern 4: standalone function calls
    const standalonePattern = /(?<![.\w$])([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = standalonePattern.exec(code)) !== null) {
      const funcName = match[1];

      // Skip keywords and common built-ins
      if (this._isKeywordOrBuiltIn(funcName)) continue;

      const resolved = this._resolveCall(funcName, callerFile, callerFuncId);
      if (resolved && !seenCalls.has(resolved)) {
        seenCalls.add(resolved);
        calls.push(resolved);
      }
    }

    return calls;
  }

  /**
   * Check if name is a JavaScript built-in object
   */
  _isBuiltIn(name) {
    const builtIns = new Set([
      'console', 'Math', 'JSON', 'Object', 'Array', 'String', 'Number',
      'Boolean', 'Date', 'RegExp', 'Error', 'Promise', 'Map', 'Set',
      'WeakMap', 'WeakSet', 'Symbol', 'Proxy', 'Reflect', 'Buffer',
      'process', 'global', 'window', 'document', 'localStorage',
      'sessionStorage', 'fetch', 'XMLHttpRequest', 'WebSocket',
      'URL', 'URLSearchParams', 'FormData', 'Headers', 'Request', 'Response'
    ]);
    return builtIns.has(name);
  }

  /**
   * Check if name is a keyword or built-in function
   */
  _isKeywordOrBuiltIn(name) {
    const keywords = new Set([
      'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break',
      'continue', 'return', 'throw', 'try', 'catch', 'finally',
      'function', 'class', 'const', 'let', 'var', 'new', 'delete',
      'typeof', 'instanceof', 'in', 'of', 'await', 'async', 'yield',
      'import', 'export', 'default', 'from', 'as', 'super', 'extends',
      // Built-in functions
      'require', 'parseInt', 'parseFloat', 'isNaN', 'isFinite',
      'encodeURI', 'decodeURI', 'encodeURIComponent', 'decodeURIComponent',
      'eval', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
      'setImmediate', 'clearImmediate', 'queueMicrotask'
    ]);
    return keywords.has(name);
  }

  /**
   * Resolve a simple function call to a function ID
   */
  _resolveCall(funcName, callerFile, callerFuncId) {
    // 1. First check same file
    const sameFileFuncs = this.functionsByFile[callerFile];
    if (sameFileFuncs && Array.isArray(sameFileFuncs)) {
      for (const funcId of sameFileFuncs) {
        const funcData = this.functions[funcId];
        if (funcData && (funcData.name === funcName || funcData.name.endsWith('.' + funcName))) {
          return funcId;
        }
      }
    }

    // 2. Check by simple name across all files
    const candidates = this.functionsByName[funcName];
    if (candidates && Array.isArray(candidates) && candidates.length === 1) {
      return candidates[0];
    }

    // 3. Multiple candidates - return null (ambiguous)
    // A more sophisticated implementation would parse imports to disambiguate
    return null;
  }

  /**
   * Resolve a this.method call within a class
   */
  _resolveThisCall(methodName, callerFuncId) {
    // Extract class name from caller (e.g., "file.ts:ClassName.method" -> "ClassName")
    const callerFile = callerFuncId.split(':')[0];
    const callerFunc = this.functions[callerFuncId];

    if (callerFunc && callerFunc.className) {
      // Look for ClassName.methodName in same file
      const targetId = `${callerFile}:${callerFunc.className}.${methodName}`;
      if (this.functions[targetId]) {
        return targetId;
      }
    }

    return null;
  }

  /**
   * Resolve an object.method call
   *
   * Supports two resolution strategies:
   * 1. Direct class name match: objectName === className
   * 2. DI-aware resolution: objectName is a constructor-injected parameter,
   *    use its type annotation to find the target class
   */
  _resolveMethodCall(objectName, methodName, callerFile, callerFuncId = null) {
    const candidates = this.functionsByName[methodName];

    if (!candidates || !Array.isArray(candidates)) {
      return null;
    }

    // 1. Exact class name match (existing behavior)
    for (const funcId of candidates) {
      const funcData = this.functions[funcId];
      if (funcData && funcData.className === objectName) {
        return funcId;
      }
    }

    // 2. DI-aware resolution: look up objectName in caller's constructorDeps
    //    e.g., this.callService.getById() -> constructorDeps says callService: CallService
    //    -> resolve to CallService.getById
    if (callerFuncId) {
      const callerFunc = this.functions[callerFuncId];
      const classEntry = callerFunc && callerFunc.className &&
          this.classes[callerFile + ':' + callerFunc.className];
      if (classEntry && (classEntry.constructorDeps || classEntry.fieldDeps)) {
        const typeName = (classEntry.constructorDeps || {})[objectName]
            ?? (classEntry.fieldDeps || {})[objectName];
        if (typeName) {
          // 2a. Exact type match
          for (const funcId of candidates) {
            const funcData = this.functions[funcId];
            if (funcData && funcData.className === typeName) {
              return funcId;
            }
          }

          // 2b. Nominal type match: prefer candidates whose class implements or extends typeName.
          //     If exactly one such candidate exists, the resolution is unambiguous.
          const nominalClassKeys = this.classesByBaseType[typeName] || [];
          const nominalMatches = candidates.filter(funcId => {
            const funcData = this.functions[funcId];
            if (!funcData || !funcData.className) return false;
            const funcClassKey = funcId.split(':')[0] + ':' + funcData.className;
            return nominalClassKeys.includes(funcClassKey);
          });
          if (nominalMatches.length === 1) return nominalMatches[0];

          // 2c. Prefix match: last resort for versioned names (e.g., CallService -> CallServiceV1).
          //     Skip if multiple candidates match to preserve no-false-positive property.
          const prefixMatches = candidates.filter(funcId => {
            const funcData = this.functions[funcId];
            return funcData && funcData.className && funcData.className.startsWith(typeName);
          });
          if (prefixMatches.length === 1) return prefixMatches[0];
        }
      }
    }

    return null;
  }

  /**
   * Get all dependencies for a function up to maxDepth
   */
  getDependencies(funcId, depth = null) {
    const maxD = depth !== null ? depth : this.maxDepth;
    const dependencies = new Set();
    const queue = [{ id: funcId, depth: 0 }];
    const visited = new Set([funcId]);

    while (queue.length > 0) {
      const { id, depth: currentDepth } = queue.shift();

      if (currentDepth >= maxD) continue;

      const calls = this.callGraph[id] || [];
      for (const calledId of calls) {
        if (!visited.has(calledId)) {
          visited.add(calledId);
          dependencies.add(calledId);
          queue.push({ id: calledId, depth: currentDepth + 1 });
        }
      }
    }

    return Array.from(dependencies);
  }

  /**
   * Get all callers (reverse dependencies) for a function
   */
  getCallers(funcId, depth = null) {
    const maxD = depth !== null ? depth : this.maxDepth;
    const callers = new Set();
    const queue = [{ id: funcId, depth: 0 }];
    const visited = new Set([funcId]);

    while (queue.length > 0) {
      const { id, depth: currentDepth } = queue.shift();

      if (currentDepth >= maxD) continue;

      const callerIds = this.reverseCallGraph[id] || [];
      for (const callerId of callerIds) {
        if (!visited.has(callerId)) {
          visited.add(callerId);
          callers.add(callerId);
          queue.push({ id: callerId, depth: currentDepth + 1 });
        }
      }
    }

    return Array.from(callers);
  }

  /**
   * Bundle dependencies for a function (for self-contained analysis)
   */
  bundleDependencies(funcId) {
    const deps = this.getDependencies(funcId);
    const bundle = {
      primary: {
        id: funcId,
        ...this.functions[funcId]
      },
      dependencies: []
    };

    for (const depId of deps) {
      const depFunc = this.functions[depId];
      if (depFunc) {
        bundle.dependencies.push({
          id: depId,
          name: depFunc.name,
          code: depFunc.code,
          unitType: depFunc.unitType,
          className: depFunc.className
        });
      }
    }

    return bundle;
  }

  /**
   * Get statistics about the call graph
   */
  getStatistics() {
    const stats = {
      totalFunctions: Object.keys(this.functions).length,
      totalEdges: 0,
      avgOutDegree: 0,
      avgInDegree: 0,
      maxOutDegree: 0,
      maxInDegree: 0,
      isolatedFunctions: 0,
      byUnitType: Object.create(null)
    };

    for (const [funcId, calls] of Object.entries(this.callGraph)) {
      const outDegree = calls.length;
      stats.totalEdges += outDegree;
      stats.maxOutDegree = Math.max(stats.maxOutDegree, outDegree);

      const inDegree = (this.reverseCallGraph[funcId] || []).length;
      stats.maxInDegree = Math.max(stats.maxInDegree, inDegree);

      if (outDegree === 0 && inDegree === 0) {
        stats.isolatedFunctions++;
      }

      // Count by unit type
      const unitType = this.functions[funcId]?.unitType || 'unknown';
      stats.byUnitType[unitType] = (stats.byUnitType[unitType] || 0) + 1;
    }

    const numFuncs = Object.keys(this.functions).length;
    stats.avgOutDegree = numFuncs > 0 ? (stats.totalEdges / numFuncs).toFixed(2) : 0;
    stats.avgInDegree = stats.avgOutDegree;  // Same for directed graphs

    return stats;
  }

  /**
   * Export enhanced output with resolved call graph
   */
  export() {
    return {
      functions: this.functions,
      callGraph: this.callGraph,
      reverseCallGraph: this.reverseCallGraph,
      statistics: this.getStatistics(),
      repoRoot: this.repoRoot
    };
  }
}

// CLI execution
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: node dependency_resolver.js <analyzer_output.json> [--output <file>] [--depth <N>]');
    process.exit(1);
  }

  const inputFile = args[0];
  let outputFile = null;
  let maxDepth = 3;

  // Parse options
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--output' && i + 1 < args.length) {
      outputFile = args[++i];
    } else if (args[i] === '--depth' && i + 1 < args.length) {
      maxDepth = parseInt(args[++i], 10);
    }
  }

  // Load input
  if (!fs.existsSync(inputFile)) {
    console.error(`Input file not found: ${inputFile}`);
    process.exit(1);
  }

  const analyzerOutput = JSON.parse(fs.readFileSync(inputFile, 'utf-8'));

  // Build call graph
  console.error(`Processing ${Object.keys(analyzerOutput.functions || {}).length} functions...`);

  const resolver = new DependencyResolver(analyzerOutput, { maxDepth });
  resolver.buildCallGraph();

  const result = resolver.export();
  const stats = result.statistics;

  console.error(`Call graph built:`);
  console.error(`  Total functions: ${stats.totalFunctions}`);
  console.error(`  Total edges: ${stats.totalEdges}`);
  console.error(`  Avg out-degree: ${stats.avgOutDegree}`);
  console.error(`  Max out-degree: ${stats.maxOutDegree}`);
  console.error(`  Isolated functions: ${stats.isolatedFunctions}`);
  console.error(`  By unit type:`);
  for (const [type, count] of Object.entries(stats.byUnitType)) {
    console.error(`    - ${type}: ${count}`);
  }

  // Output
  const jsonOutput = JSON.stringify(result, null, 2);
  if (outputFile) {
    fs.writeFileSync(outputFile, jsonOutput);
    console.error(`Output written to ${outputFile}`);
  } else {
    console.log(jsonOutput);
  }
}

module.exports = { DependencyResolver };
