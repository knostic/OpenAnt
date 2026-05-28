/**
 * Context Assembler for Vulnerability Analysis
 *
 * Uses TypeScript compiler API to:
 * 1. Parse JavaScript/TypeScript files
 * 2. Resolve symbols across files (LSP-like "go to definition")
 * 3. Recursively gather all code context for a route handler
 */

const ts = require('typescript');
const fs = require('fs');
const path = require('path');

class ContextAssembler {
    constructor(projectRoot, options = {}) {
        this.projectRoot = projectRoot;
        this.maxDepth = options.maxDepth || 5;
        this.maxFiles = options.maxFiles || 20;
        this.visitedFiles = new Set();
        this.visitedSymbols = new Set();
        this.collectedCode = [];
        this.collectedTemplates = [];  // Track template files separately
        this.program = null;
        this.checker = null;

        // Track statistics
        this.stats = {
            filesVisited: 0,
            symbolsResolved: 0,
            unresolvedImports: [],
            externalModules: [],
            templatesResolved: 0,
            unresolvedTemplates: []
        };
    }

    /**
     * Initialize TypeScript program for the project
     */
    initializeProgram() {
        // Find all JS/TS files in the project
        const files = this.findSourceFiles(this.projectRoot);

        if (files.length === 0) {
            throw new Error(`No source files found in ${this.projectRoot}`);
        }

        // Create TypeScript program with JavaScript support
        const compilerOptions = {
            allowJs: true,
            checkJs: false,
            noEmit: true,
            target: ts.ScriptTarget.ES2020,
            module: ts.ModuleKind.CommonJS,
            moduleResolution: ts.ModuleResolutionKind.NodeJs,
            resolveJsonModule: true,
            esModuleInterop: true,
            skipLibCheck: true,
            baseUrl: this.projectRoot,
            paths: {
                '*': ['node_modules/*']
            }
        };

        this.program = ts.createProgram(files, compilerOptions);
        this.checker = this.program.getTypeChecker();

        return files.length;
    }

    /**
     * Find all JavaScript and TypeScript source files
     */
    findSourceFiles(dir, files = []) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });

        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);

            // Skip node_modules and hidden directories
            if (entry.name === 'node_modules' || entry.name.startsWith('.')) {
                continue;
            }

            if (entry.isDirectory()) {
                this.findSourceFiles(fullPath, files);
            } else if (/\.(js|ts|jsx|tsx|mjs|cjs)$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
                files.push(fullPath);
            }
        }

        return files;
    }

    /**
     * Assemble complete context for a route handler
     *
     * @param {string} entryFile - File containing the route definition
     * @param {string} handlerName - Name of the handler function (e.g., 'appHandler.userSearch')
     * @param {string} routePath - Optional route path to filter relevant templates (e.g., '/app/products')
     * @returns {Object} - Assembled context with code and metadata
     */
    assembleContext(entryFile, handlerName, routePath = null) {
        if (!this.program) {
            this.initializeProgram();
        }

        // Reset state for new assembly
        this.visitedFiles.clear();
        this.visitedSymbols.clear();
        this.collectedCode = [];
        this.collectedTemplates = [];
        this.routePath = routePath;  // Store for template filtering
        this.stats = {
            filesVisited: 0,
            symbolsResolved: 0,
            unresolvedImports: [],
            externalModules: [],
            templatesResolved: 0,
            unresolvedTemplates: []
        };

        // Resolve entry file path
        const entryFilePath = path.isAbsolute(entryFile)
            ? entryFile
            : path.join(this.projectRoot, entryFile);

        // Get the source file
        const sourceFile = this.program.getSourceFile(entryFilePath);
        if (!sourceFile) {
            return {
                success: false,
                error: `Could not find source file: ${entryFilePath}`,
                code: '',
                files: [],
                stats: this.stats
            };
        }

        // Add the entry file
        this.addFileContext(sourceFile, 0);

        // Parse the handler name to find what we need to resolve
        const [moduleName, functionName] = handlerName.includes('.')
            ? handlerName.split('.')
            : [null, handlerName];

        // Find and resolve the handler
        if (moduleName) {
            this.resolveModuleHandler(sourceFile, moduleName, functionName);
        } else {
            this.resolveFunctionInFile(sourceFile, functionName);
        }

        // Combine code files and templates
        const allCode = [
            ...this.collectedCode.map(c => c.code),
            ...this.collectedTemplates.map(t => `// ========== Template: ${t.relativePath} ==========\n${t.code}`)
        ].join('\n\n// ========== File Boundary ==========\n\n');

        const allFiles = [
            ...this.collectedCode.map(c => ({
                path: c.path,
                relativePath: path.relative(this.projectRoot, c.path),
                functions: c.functions || [],
                type: 'source'
            })),
            ...this.collectedTemplates.map(t => ({
                path: t.path,
                relativePath: t.relativePath,
                type: 'template'
            }))
        ];

        return {
            success: true,
            code: allCode,
            files: allFiles,
            stats: this.stats
        };
    }

    /**
     * Add a file's context to the collection
     */
    addFileContext(sourceFile, depth) {
        const filePath = sourceFile.fileName;

        if (this.visitedFiles.has(filePath) || depth > this.maxDepth) {
            return;
        }

        if (this.visitedFiles.size >= this.maxFiles) {
            return;
        }

        this.visitedFiles.add(filePath);
        this.stats.filesVisited++;

        // Extract function definitions from the file
        const functions = this.extractFunctions(sourceFile);

        this.collectedCode.push({
            path: filePath,
            code: sourceFile.getFullText(),
            functions: functions
        });

        // Recursively process imports
        this.processImports(sourceFile, depth + 1);

        // Process template references only at depth 0 or 1 (entry file and direct handlers)
        // This prevents including all templates from all transitively imported files
        if (depth <= 1) {
            this.processTemplateReferences(sourceFile);
        }
    }

    /**
     * Extract function definitions from a source file
     */
    extractFunctions(sourceFile) {
        const functions = [];

        const visit = (node) => {
            if (ts.isFunctionDeclaration(node) && node.name) {
                functions.push({
                    name: node.name.text,
                    line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1
                });
            } else if (ts.isMethodDeclaration(node) && node.name) {
                functions.push({
                    name: node.name.getText(),
                    line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1
                });
            } else if (ts.isVariableStatement(node)) {
                // Handle exports.functionName = function() {} pattern
                node.declarationList.declarations.forEach(decl => {
                    if (decl.name && ts.isIdentifier(decl.name)) {
                        if (decl.initializer &&
                            (ts.isFunctionExpression(decl.initializer) ||
                             ts.isArrowFunction(decl.initializer))) {
                            functions.push({
                                name: decl.name.text,
                                line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1
                            });
                        }
                    }
                });
            } else if (ts.isExpressionStatement(node)) {
                // Handle module.exports.functionName = function() {} pattern
                const expr = node.expression;
                if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
                    const left = expr.left;
                    if (ts.isPropertyAccessExpression(left)) {
                        const name = left.name.getText();
                        if (expr.right &&
                            (ts.isFunctionExpression(expr.right) ||
                             ts.isArrowFunction(expr.right))) {
                            functions.push({
                                name: name,
                                line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1
                            });
                        }
                    }
                }
            }

            ts.forEachChild(node, visit);
        };

        visit(sourceFile);
        return functions;
    }

    /**
     * Process imports/requires in a file and resolve them
     */
    processImports(sourceFile, depth) {
        const visit = (node) => {
            // Handle require() calls
            if (ts.isCallExpression(node) &&
                ts.isIdentifier(node.expression) &&
                node.expression.text === 'require' &&
                node.arguments.length > 0 &&
                ts.isStringLiteral(node.arguments[0])) {

                const importPath = node.arguments[0].text;
                this.resolveImport(importPath, sourceFile, depth);
            }

            // Handle ES6 imports
            if (ts.isImportDeclaration(node) && node.moduleSpecifier) {
                if (ts.isStringLiteral(node.moduleSpecifier)) {
                    const importPath = node.moduleSpecifier.text;
                    this.resolveImport(importPath, sourceFile, depth);
                }
            }

            ts.forEachChild(node, visit);
        };

        visit(sourceFile);
    }

    /**
     * Resolve an import path to a source file
     */
    resolveImport(importPath, fromSourceFile, depth) {
        // Skip external modules
        if (!importPath.startsWith('.') && !importPath.startsWith('/')) {
            if (!this.stats.externalModules.includes(importPath)) {
                this.stats.externalModules.push(importPath);
            }
            return;
        }

        const fromDir = path.dirname(fromSourceFile.fileName);
        let resolvedPath = path.resolve(fromDir, importPath);

        // Try to find the actual file
        const extensions = ['', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '/index.js', '/index.ts', '/index.mjs', '/index.cjs'];
        let found = false;

        for (const ext of extensions) {
            const tryPath = resolvedPath + ext;
            const sourceFile = this.program.getSourceFile(tryPath);
            if (sourceFile) {
                this.addFileContext(sourceFile, depth);
                found = true;
                break;
            }
        }

        if (!found) {
            if (!this.stats.unresolvedImports.includes(importPath)) {
                this.stats.unresolvedImports.push(importPath);
            }
        }
    }

    /**
     * Process template references (res.render calls) in a source file
     */
    processTemplateReferences(sourceFile) {
        const visit = (node) => {
            // Look for res.render('templatePath', ...) calls
            if (ts.isCallExpression(node)) {
                const expr = node.expression;
                // Check for property access like res.render or response.render
                if (ts.isPropertyAccessExpression(expr) &&
                    expr.name.text === 'render' &&
                    node.arguments.length > 0 &&
                    ts.isStringLiteral(node.arguments[0])) {

                    const templatePath = node.arguments[0].text;
                    this.resolveTemplate(templatePath);
                }
            }

            ts.forEachChild(node, visit);
        };

        visit(sourceFile);
    }

    /**
     * Resolve a template path to the actual template file
     */
    resolveTemplate(templatePath) {
        // Skip if already resolved
        if (this.collectedTemplates.some(t => t.templatePath === templatePath)) {
            return;
        }

        // If we have a route path, only include templates that match
        // e.g., route '/app/products' should match template 'app/products'
        if (this.routePath) {
            // Normalize paths for comparison
            const normalizedRoute = this.routePath.replace(/^\//, '');  // Remove leading slash
            const normalizedTemplate = templatePath.replace(/^\//, '');

            // Check if template matches the route exactly
            // e.g., route 'app/products' matches template 'app/products'
            if (normalizedTemplate !== normalizedRoute) {
                // Don't add to unresolved - it's just filtered out
                return;
            }
        }

        // Common view directories for Express apps
        const viewDirs = ['views', 'src/views', 'app/views'];
        // Common template extensions
        const templateExtensions = ['.ejs', '.pug', '.jade', '.hbs', '.handlebars', '.html', '.njk'];

        for (const viewDir of viewDirs) {
            for (const ext of templateExtensions) {
                const fullPath = path.join(this.projectRoot, viewDir, templatePath + ext);
                if (fs.existsSync(fullPath)) {
                    try {
                        const content = fs.readFileSync(fullPath, 'utf-8');
                        const relativePath = path.relative(this.projectRoot, fullPath);

                        this.collectedTemplates.push({
                            templatePath: templatePath,
                            path: fullPath,
                            relativePath: relativePath,
                            code: content
                        });

                        this.stats.templatesResolved++;
                        return;
                    } catch (err) {
                        // Continue trying other paths
                    }
                }
            }
        }

        // Template not found
        if (!this.stats.unresolvedTemplates.includes(templatePath)) {
            this.stats.unresolvedTemplates.push(templatePath);
        }
    }

    /**
     * Resolve a module handler (e.g., appHandler.userSearch)
     */
    resolveModuleHandler(sourceFile, moduleName, functionName) {
        // Find the require/import for this module
        const visit = (node) => {
            // Handle: var appHandler = require('../core/appHandler')
            if (ts.isVariableStatement(node)) {
                for (const decl of node.declarationList.declarations) {
                    if (ts.isIdentifier(decl.name) && decl.name.text === moduleName) {
                        if (decl.initializer && ts.isCallExpression(decl.initializer)) {
                            const call = decl.initializer;
                            if (ts.isIdentifier(call.expression) &&
                                call.expression.text === 'require' &&
                                call.arguments.length > 0 &&
                                ts.isStringLiteral(call.arguments[0])) {

                                const importPath = call.arguments[0].text;
                                this.resolveModuleFunctionDefinition(importPath, sourceFile, functionName);
                                this.stats.symbolsResolved++;
                            }
                        }
                    }
                }
            }

            ts.forEachChild(node, visit);
        };

        visit(sourceFile);
    }

    /**
     * Resolve a function definition within a module
     */
    resolveModuleFunctionDefinition(importPath, fromSourceFile, functionName) {
        const fromDir = path.dirname(fromSourceFile.fileName);
        let resolvedPath = path.resolve(fromDir, importPath);

        const extensions = ['', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'];

        for (const ext of extensions) {
            const tryPath = resolvedPath + ext;
            const sourceFile = this.program.getSourceFile(tryPath);
            if (sourceFile) {
                // Add the full module file
                this.addFileContext(sourceFile, 1);

                // Note: The full file is already included, but we could
                // extract just the specific function if needed
                break;
            }
        }
    }

    /**
     * Resolve a function within the current file
     */
    resolveFunctionInFile(sourceFile, functionName) {
        // The entry file is already added, just note the function
        this.stats.symbolsResolved++;
    }
}

/**
 * CLI interface for testing
 */
async function main() {
    const args = process.argv.slice(2);

    if (args.length < 2) {
        console.log('Usage: node context_assembler.js <project_root> <entry_file> [handler_name] [route_path]');
        console.log('');
        console.log('Examples:');
        console.log('  node context_assembler.js /path/to/dvna routes/app.js appHandler.userSearch');
        console.log('  node context_assembler.js /path/to/dvna routes/app.js appHandler.productSearch /app/products');
        console.log('  node context_assembler.js /path/to/juice-shop routes/search.ts');
        process.exit(1);
    }

    const [projectRoot, entryFile, handlerName = 'main', routePath = null] = args;

    console.log(`Assembling context for ${projectRoot}...`);
    console.log(`Entry file: ${entryFile}`);
    console.log(`Handler: ${handlerName}`);
    if (routePath) console.log(`Route path: ${routePath}`);
    console.log('');

    const assembler = new ContextAssembler(projectRoot, { maxDepth: 5, maxFiles: 20 });

    try {
        const fileCount = assembler.initializeProgram();
        console.log(`Found ${fileCount} source files in project`);
        console.log('');

        const result = assembler.assembleContext(entryFile, handlerName, routePath);

        if (!result.success) {
            console.error(`Error: ${result.error}`);
            process.exit(1);
        }

        console.log('=== Assembly Results ===');
        console.log(`Files visited: ${result.stats.filesVisited}`);
        console.log(`Symbols resolved: ${result.stats.symbolsResolved}`);
        console.log(`Templates resolved: ${result.stats.templatesResolved}`);
        console.log(`External modules: ${result.stats.externalModules.join(', ') || 'none'}`);
        console.log(`Unresolved imports: ${result.stats.unresolvedImports.join(', ') || 'none'}`);
        console.log(`Unresolved templates: ${result.stats.unresolvedTemplates.join(', ') || 'none'}`);
        console.log('');
        console.log('Files collected:');
        result.files.forEach((f, i) => {
            const typeLabel = f.type === 'template' ? ' [TEMPLATE]' : '';
            console.log(`  ${i + 1}. ${f.relativePath}${typeLabel}`);
            if (f.functions && f.functions.length > 0) {
                console.log(`     Functions: ${f.functions.map(fn => fn.name).join(', ')}`);
            }
        });
        console.log('');
        console.log(`Total code length: ${result.code.length} characters`);

        // Optionally output the full code
        if (process.env.OUTPUT_CODE === '1') {
            console.log('\n=== Assembled Code ===\n');
            console.log(result.code);
        }

    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

// Export for use as module
module.exports = { ContextAssembler };

// Run CLI if executed directly
if (require.main === module) {
    main();
}
