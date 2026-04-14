#!/usr/bin/env node
/**
 * Unit Generator
 *
 * Creates analysis units for ALL functions extracted from a repository.
 * Supports both static and LLM-enhanced dependency resolution.
 *
 * Usage:
 *   node unit_generator.js <typescript_analyzer_output.json> [--output <file>] [--depth <N>] [--llm]
 *
 * Input:
 *   - typescript_analyzer_output.json: Output from typescript_analyzer.js (batch mode)
 *
 * Output (JSON):
 *   {
 *     "name": "dataset_name",
 *     "repository": "/path/to/repo",
 *     "units": [
 *       {
 *         "id": "file.ts:functionName",
 *         "unit_type": "route_handler" | "middleware" | "model" | "utility" | "class_method" | "function",
 *         "code": {
 *           "primary_code": "...",
 *           "primary_origin": {...},
 *           "upstream_dependencies": [{ "id": "...", "code": "...", ... }],  // Functions this calls
 *           "downstream_callers": [{ "id": "...", "code": "...", ... }],     // Functions that call this
 *           "dependency_metadata": { "depth": 3, "total_upstream": 5, "total_downstream": 2 }
 *         },
 *         "data_flow": {                    // Optional: from LLM analysis
 *           "inputs": [...],
 *           "outputs": [...],
 *           "tainted_variables": [...],
 *           "security_relevant_flows": [...]
 *         },
 *         "route": null,  // Populated for route_handlers if route info available
 *         "ground_truth": { "status": "UNKNOWN" },
 *         "metadata": {...}
 *       }
 *     ],
 *     "statistics": {
 *       "total_units": 150,
 *       "by_type": { "route_handler": 20, "function": 100, ... },
 *       "call_graph": { "total_edges": 500, "avg_out_degree": 2.5, ... }
 *     }
 *   }
 */

const fs = require('fs');
const path = require('path');
const { DependencyResolver } = require('./dependency_resolver');

class UnitGenerator {
    constructor(repoPath, datasetName = null, options = {}) {
        this.repoPath = repoPath;
        this.datasetName = datasetName || path.basename(repoPath);
        this.maxDepth = options.maxDepth || 3;
        this.units = [];
        this.resolver = null;  // Initialized in generateUnits
        this.statistics = {
            totalUnits: 0,
            byType: Object.create(null),
            callGraph: {}
        };
    }

    /**
     * Generate analysis units from TypeScript analyzer output
     * @param {Object} analyzerOutput - Output from TypeScriptAnalyzer.analyzeFiles()
     * @param {Object} routeInfo - Optional route information to tag route handlers
     */
    generateUnits(analyzerOutput, routeInfo = null) {
        const { functions } = analyzerOutput;

        // Initialize DependencyResolver and build call graph
        this.resolver = new DependencyResolver(analyzerOutput, { maxDepth: this.maxDepth });
        this.resolver.buildCallGraph();

        // Store call graph statistics
        const resolverStats = this.resolver.getStatistics();
        this.statistics.callGraph = {
            totalEdges: resolverStats.totalEdges,
            avgOutDegree: resolverStats.avgOutDegree,
            avgInDegree: resolverStats.avgInDegree,
            maxOutDegree: resolverStats.maxOutDegree,
            maxInDegree: resolverStats.maxInDegree,
            isolatedFunctions: resolverStats.isolatedFunctions
        };

        // Track units with dependencies
        this.statistics.unitsWithUpstream = 0;
        this.statistics.unitsWithDownstream = 0;

        // Build a map of route handlers if route info is provided
        const routeHandlerMap = this._buildRouteHandlerMap(routeInfo);

        // Process all functions
        const functionIds = Object.keys(functions);
        for (const functionId of functionIds) {
            const funcData = functions[functionId];
            const unit = this._createUnit(functionId, funcData, routeHandlerMap);
            this.units.push(unit);
            this._updateStatistics(unit);
        }

        return {
            name: this.datasetName,
            repository: this.repoPath,
            units: this.units,
            statistics: this.statistics,
            metadata: {
                generator: 'unit_generator.js',
                generated_at: new Date().toISOString(),
                dependency_depth: this.maxDepth
            }
        };
    }

    /**
     * Update statistics for a unit
     */
    _updateStatistics(unit) {
        this.statistics.totalUnits++;
        const unitType = unit.unit_type;
        this.statistics.byType[unitType] = (this.statistics.byType[unitType] || 0) + 1;

        const depMeta = unit.code.dependency_metadata || {};
        if (depMeta.total_upstream > 0) {
            this.statistics.unitsWithUpstream++;
        }
        if (depMeta.total_downstream > 0) {
            this.statistics.unitsWithDownstream++;
        }
    }

    /**
     * Build a map of route handlers from route information
     */
    _buildRouteHandlerMap(routeInfo) {
        const map = new Map();
        if (!routeInfo || !routeInfo.routes) return map;

        for (const route of routeInfo.routes) {
            const handler = route.handler;
            const file = route.file;

            // Create keys for matching
            // Pattern: "file.ts:handlerName" or "file.ts:ClassName.methodName"
            if (handler && file) {
                const key = `${file}:${handler}`;
                map.set(key, route);

                // Also store just by handler name for simpler matching
                map.set(handler, route);
            }
        }

        return map;
    }

    /**
     * Assemble enhanced code with all dependencies using file boundary markers
     * Matches DVNA enhanced dataset format expected by experiment.py
     */
    _assembleEnhancedCode(funcData, upstreamDependencies, downstreamCallers) {
        const FILE_BOUNDARY = '\n\n// ========== File Boundary ==========\n\n';
        const parts = [];
        const includedCode = new Set();

        // Add primary code first
        parts.push(funcData.code);
        includedCode.add(funcData.code);

        // Add upstream dependencies (functions this calls)
        for (const dep of upstreamDependencies) {
            if (dep.code && !includedCode.has(dep.code)) {
                parts.push(dep.code);
                includedCode.add(dep.code);
            }
        }

        // Add downstream callers (functions that call this)
        for (const caller of downstreamCallers) {
            if (caller.code && !includedCode.has(caller.code)) {
                parts.push(caller.code);
                includedCode.add(caller.code);
            }
        }

        return parts.join(FILE_BOUNDARY);
    }

    /**
     * Collect unique file paths from primary and all dependencies
     */
    _collectFilesIncluded(primaryFilePath, upstreamDependencies, downstreamCallers) {
        const files = new Set();
        files.add(primaryFilePath);

        for (const dep of upstreamDependencies) {
            if (dep.id) {
                const colonIndex = dep.id.lastIndexOf(':');
                if (colonIndex > 0) {
                    files.add(dep.id.substring(0, colonIndex));
                }
            }
        }

        for (const caller of downstreamCallers) {
            if (caller.id) {
                const colonIndex = caller.id.lastIndexOf(':');
                if (colonIndex > 0) {
                    files.add(caller.id.substring(0, colonIndex));
                }
            }
        }

        return Array.from(files);
    }

    /**
     * Create a single analysis unit
     */
    _createUnit(functionId, funcData, routeHandlerMap) {
        // Parse function ID: "relative/path/file.ts:functionName"
        const colonIndex = functionId.lastIndexOf(':');
        const filePath = functionId.substring(0, colonIndex);
        const functionName = functionId.substring(colonIndex + 1);

        // Check if this is a route handler
        let routeData = null;
        let unitType = funcData.unitType || 'function';

        // Try to match against route info
        if (routeHandlerMap.has(functionId)) {
            routeData = routeHandlerMap.get(functionId);
            unitType = 'route_handler';
        } else if (routeHandlerMap.has(functionName)) {
            routeData = routeHandlerMap.get(functionName);
            unitType = 'route_handler';
        }

        // Get upstream dependencies (functions this calls)
        const upstreamIds = this.resolver.getDependencies(functionId);
        const upstreamDependencies = [];

        for (const depId of upstreamIds) {
            const depFunc = this.resolver.functions[depId];
            if (depFunc) {
                upstreamDependencies.push({
                    id: depId,
                    name: depFunc.name,
                    code: depFunc.code,
                    unit_type: depFunc.unitType || 'function',
                    class_name: depFunc.className || null
                });
            }
        }

        // Get downstream callers (functions that call this)
        const callerIds = this.resolver.getCallers(functionId);
        const downstreamCallers = [];

        for (const callerId of callerIds) {
            const callerFunc = this.resolver.functions[callerId];
            if (callerFunc) {
                downstreamCallers.push({
                    id: callerId,
                    name: callerFunc.name,
                    code: callerFunc.code,
                    unit_type: callerFunc.unitType || 'function',
                    class_name: callerFunc.className || null
                });
            }
        }

        // Get direct calls from call graph
        const directCalls = this.resolver.callGraph[functionId] || [];
        const directCallers = this.resolver.reverseCallGraph[functionId] || [];

        // Assemble enhanced code with dependencies (OpenAnt standard format)
        const filesIncluded = this._collectFilesIncluded(filePath, upstreamDependencies, downstreamCallers);
        const hasDepsInlined = upstreamDependencies.length > 0 || downstreamCallers.length > 0;
        const assembledCode = this._assembleEnhancedCode(funcData, upstreamDependencies, downstreamCallers);

        // Build the unit
        const unit = {
            id: functionId,
            unit_type: unitType,
            code: {
                primary_code: assembledCode,
                primary_origin: {
                    file_path: filePath,
                    start_line: funcData.startLine || null,
                    end_line: funcData.endLine || null,
                    function_name: funcData.name,
                    class_name: funcData.className || null,
                    deps_inlined: hasDepsInlined,
                    files_included: filesIncluded,
                    original_length: funcData.code.length,
                    enhanced_length: assembledCode.length
                },
                dependencies: [],
                dependency_metadata: {
                    depth: this.maxDepth,
                    total_upstream: upstreamDependencies.length,
                    total_downstream: downstreamCallers.length,
                    direct_calls: directCalls.length,
                    direct_callers: directCallers.length
                }
            },
            route: routeData ? {
                method: routeData.method,
                path: routeData.path,
                handler: routeData.handler,
                middleware: routeData.middleware || []
            } : null,
            ground_truth: {
                status: 'UNKNOWN',
                vulnerability_types: [],
                issues: [],
                annotation_source: null,
                annotation_key: null,
                notes: null
            },
            metadata: {
                is_exported: funcData.isExported || false,
                export_type: funcData.exportType || null,
                generator: 'unit_generator.js',
                direct_calls: directCalls,
                direct_callers: directCallers
            }
        };

        return unit;
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);

    if (args.length < 1) {
        console.error('Usage: node unit_generator.js <typescript_analyzer_output.json> [options]');
        console.error('');
        console.error('Options:');
        console.error('  --output <file>       Write results to file instead of stdout');
        console.error('  --depth <N>           Max dependency resolution depth (default: 3)');
        console.error('  --routes <routes.json> Route information from ast_parser.js');
        console.error('  --name <name>         Dataset name (default: derived from repo path)');
        console.error('');
        console.error('Examples:');
        console.error('  node unit_generator.js analyzer_output.json --output dataset.json --depth 2');
        process.exit(1);
    }

    const analyzerFile = args[0];
    let outputFile = null;
    let routesFile = null;
    let datasetName = null;
    let maxDepth = 3;

    // Parse arguments
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--output' && args[i + 1]) {
            outputFile = args[i + 1];
            i++;
        } else if (args[i] === '--depth' && args[i + 1]) {
            maxDepth = parseInt(args[i + 1], 10);
            i++;
        } else if (args[i] === '--routes' && args[i + 1]) {
            routesFile = args[i + 1];
            i++;
        } else if (args[i] === '--name' && args[i + 1]) {
            datasetName = args[i + 1];
            i++;
        }
    }

    try {
        // Load analyzer output
        if (!fs.existsSync(analyzerFile)) {
            console.error(`Analyzer output file not found: ${analyzerFile}`);
            process.exit(1);
        }
        const analyzerOutput = JSON.parse(fs.readFileSync(analyzerFile, 'utf-8'));

        // Load routes if provided
        let routeInfo = null;
        if (routesFile && fs.existsSync(routesFile)) {
            routeInfo = JSON.parse(fs.readFileSync(routesFile, 'utf-8'));
        }

        // Determine repo path from analyzer output or use current directory
        const repoPath = analyzerOutput.repoRoot || analyzerOutput.repository || process.cwd();

        // Generate units with dependency resolution
        console.error(`Processing ${Object.keys(analyzerOutput.functions || {}).length} functions...`);
        console.error(`Dependency resolution depth: ${maxDepth}`);

        const generator = new UnitGenerator(repoPath, datasetName, { maxDepth });
        const result = generator.generateUnits(analyzerOutput, routeInfo);

        // Merge with existing dataset if present
        let finalResult = result;
        if (outputFile && fs.existsSync(outputFile)) {
            try {
                const existing = JSON.parse(fs.readFileSync(outputFile, 'utf-8'));
                const existingUnits = existing.units || [];
                const existingIds = new Set(existingUnits.map(u => u.id));

                // Find new units not already in existing dataset
                const newUnits = result.units.filter(u => !existingIds.has(u.id));
                const duplicateCount = result.units.length - newUnits.length;

                console.error(`Existing dataset found:`);
                console.error(`  Existing units: ${existingUnits.length}`);
                console.error(`  New units to add: ${newUnits.length}`);
                console.error(`  Duplicates skipped: ${duplicateCount}`);

                // Append new units to existing
                finalResult = {
                    ...existing,
                    units: [...existingUnits, ...newUnits],
                    statistics: {
                        totalUnits: existingUnits.length + newUnits.length,
                        byType: Object.create(null),
                        callGraph: existing.statistics?.callGraph || {}
                    },
                    metadata: {
                        ...existing.metadata,
                        lastMerged: new Date().toISOString(),
                        lastAddedUnits: newUnits.length
                    }
                };

                // Recalculate byType statistics
                for (const unit of finalResult.units) {
                    const t = unit.unit_type || 'function';
                    finalResult.statistics.byType[t] = (finalResult.statistics.byType[t] || 0) + 1;
                }
            } catch (e) {
                console.error(`Could not parse existing file, will overwrite: ${e.message}`);
            }
        }

        const output = JSON.stringify(finalResult, null, 2);

        if (outputFile) {
            fs.writeFileSync(outputFile, output);
            console.error(`Dataset generated. Results written to: ${outputFile}`);
            console.error(`Total units: ${result.statistics.totalUnits}`);
            console.error(`By type:`, result.statistics.byType);
            console.error(`Call graph: ${result.statistics.callGraph.totalEdges} edges, avg degree: ${result.statistics.callGraph.avgOutDegree}`);
        } else {
            console.log(output);
        }

        process.exit(0);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

module.exports = { UnitGenerator };
