#!/usr/bin/env node
/**
 * Repository Scanner
 *
 * Enumerates ALL source files in a repository for complete coverage.
 * This is Phase 1 of the parser upgrade to achieve full repository coverage.
 *
 * Usage:
 *   node repository_scanner.js <repo_path> [--output <file>] [--exclude <patterns>]
 *
 * Output (JSON):
 *   {
 *     "repository": "/path/to/repo",
 *     "scan_time": "2025-12-23T...",
 *     "files": [
 *       { "path": "relative/path/to/file.ts", "size": 1234, "extension": ".ts" }
 *     ],
 *     "statistics": {
 *       "total_files": 150,
 *       "by_extension": { ".ts": 100, ".js": 50 },
 *       "total_size_bytes": 500000,
 *       "directories_scanned": 25,
 *       "directories_excluded": 10
 *     }
 *   }
 */

const fs = require('fs');
const path = require('path');

class RepositoryScanner {
    constructor(repoPath, options = {}) {
        this.repoPath = path.resolve(repoPath);
        this.skipTests = options.skipTests || false;

        // Default exclude patterns
        this.excludePatterns = options.excludePatterns || [
            'node_modules',
            'dist',
            'build',
            'coverage',
            '.git',
            '.svn',
            '.hg',
            '__pycache__',
            '.next',
            '.nuxt',
            'out',
            '.cache',
            'tmp',
            'temp',
            '.turbo',
            '.vercel',
            '.netlify'
        ];

        // Source file extensions to include
        this.sourceExtensions = options.sourceExtensions || [
            '.js',
            '.ts',
            '.jsx',
            '.tsx',
            '.mjs',
            '.cjs'
        ];

        // Statistics
        this.stats = {
            totalFiles: 0,
            byExtension: {},
            totalSizeBytes: 0,
            directoriesScanned: 0,
            directoriesExcluded: 0,
            testFilesSkipped: 0,
            // snake_case coverage keys, matching the Python-family parsers so the
            // aggregator's presence probe (core/scanner.py) reads them. Present
            // at 0 marks this parser as coverage-instrumented (vs. a parser that
            // reports no coverage at all, where the key is absent).
            symlinks_skipped: 0,
            symlink_examples: [],
            directories_unreadable: 0,
            unreadable_examples: []
        };

        // Results
        this.files = [];
    }

    /**
     * Check if a file is a test file
     */
    isTestFile(relativePath) {
        const base = path.basename(relativePath);
        const dir = relativePath.replace(/\\/g, '/');

        // Directory-based patterns
        if (dir.includes('__tests__/') || dir.includes('__mocks__/') ||
            /(?:^|\/)tests?\//.test(dir)) {
            return true;
        }

        // File name patterns: .test.*, .spec.*, _test.*, test_*
        if (/\.(test|spec)\.[jt]sx?$/.test(base)) return true;
        if (/_(test)\.[jt]sx?$/.test(base)) return true;
        if (/^test_/.test(base)) return true;

        return false;
    }

    /**
     * Check if a directory should be excluded
     */
    shouldExcludeDirectory(dirName) {
        return this.excludePatterns.some(pattern => {
            // Exact match
            if (dirName === pattern) return true;
            // Glob-like match (e.g., pattern ends with *)
            if (pattern.endsWith('*') && dirName.startsWith(pattern.slice(0, -1))) return true;
            return false;
        });
    }

    /**
     * Check if a file is a source file we want to include
     */
    isSourceFile(fileName) {
        const ext = path.extname(fileName).toLowerCase();
        return this.sourceExtensions.includes(ext);
    }

    /**
     * Recursively scan a directory
     */
    scanDirectory(dirPath, relativePath = '') {
        this.stats.directoriesScanned++;

        let entries;
        try {
            entries = fs.readdirSync(dirPath, { withFileTypes: true });
        } catch (error) {
            // Unreadable directory: record it as a counted coverage gap rather
            // than a silent skip (a silent skip is a false negative, the worst
            // direction for a SAST tool), then stop descending this one.
            this.stats.directories_unreadable++;
            if (this.stats.unreadable_examples.length < 5) {
                this.stats.unreadable_examples.push(`${relativePath || '.'}: ${error.message}`);
            }
            console.error(`Warning: Cannot read directory ${dirPath}: ${error.message}`);
            return;
        }

        for (const entry of entries) {
            const fullPath = path.join(dirPath, entry.name);
            const entryRelativePath = relativePath ? path.join(relativePath, entry.name) : entry.name;

            // Refuse symlinked directories. The scanned repository is untrusted:
            // `vendor -> /` would walk the host filesystem into the dataset (and
            // from there to the model provider), and `loop -> ..` never terminates.
            //
            // This check is currently redundant — readdirSync({withFileTypes:true})
            // returns Dirents with lstat semantics, so a symlink reports
            // isSymbolicLink() and isDirectory() is already false. It is written out
            // anyway because that safety is an undocumented property of the API
            // choice, not of this code: switching to statSync, or to a readdir
            // without withFileTypes, would silently restore the vulnerability with
            // no visible diff at this line. The sibling Python scanners had exactly
            // this bug.
            if (entry.isSymbolicLink()) {
                // Count as a symlink skip, NOT directoriesExcluded — that field
                // is for excluded real directories, and folding refusals into it
                // both mislabels the gap and hides it from the coverage probe,
                // which reads snake_case symlinks_skipped.
                this.stats.symlinks_skipped++;
                if (this.stats.symlink_examples.length < 5) {
                    this.stats.symlink_examples.push(entryRelativePath);
                }
                continue;
            }

            if (entry.isDirectory()) {
                if (this.shouldExcludeDirectory(entry.name)) {
                    this.stats.directoriesExcluded++;
                    continue;
                }
                // Recurse into subdirectory
                this.scanDirectory(fullPath, entryRelativePath);
            } else if (entry.isFile()) {
                if (this.isSourceFile(entry.name)) {
                    // Skip test files if requested
                    if (this.skipTests && this.isTestFile(entryRelativePath)) {
                        this.stats.testFilesSkipped++;
                        continue;
                    }

                    let fileStats;
                    try {
                        fileStats = fs.statSync(fullPath);
                    } catch (error) {
                        console.error(`Warning: Cannot stat file ${fullPath}: ${error.message}`);
                        continue;
                    }

                    const ext = path.extname(entry.name).toLowerCase();

                    this.files.push({
                        path: entryRelativePath,
                        size: fileStats.size,
                        extension: ext
                    });

                    // Update statistics
                    this.stats.totalFiles++;
                    this.stats.totalSizeBytes += fileStats.size;
                    this.stats.byExtension[ext] = (this.stats.byExtension[ext] || 0) + 1;
                }
            }
        }
    }

    /**
     * Run the scan and return results
     */
    scan() {
        if (!fs.existsSync(this.repoPath)) {
            throw new Error(`Repository path does not exist: ${this.repoPath}`);
        }

        if (!fs.statSync(this.repoPath).isDirectory()) {
            throw new Error(`Repository path is not a directory: ${this.repoPath}`);
        }

        this.files = [];
        this.stats = {
            totalFiles: 0,
            byExtension: {},
            totalSizeBytes: 0,
            directoriesScanned: 0,
            directoriesExcluded: 0,
            testFilesSkipped: 0,
            // snake_case coverage keys, matching the Python-family parsers so the
            // aggregator's presence probe (core/scanner.py) reads them. Present
            // at 0 marks this parser as coverage-instrumented (vs. a parser that
            // reports no coverage at all, where the key is absent).
            symlinks_skipped: 0,
            symlink_examples: [],
            directories_unreadable: 0,
            unreadable_examples: []
        };

        this.scanDirectory(this.repoPath);

        // Sort files by path for consistent output
        this.files.sort((a, b) => a.path.localeCompare(b.path));

        return {
            repository: this.repoPath,
            scan_time: new Date().toISOString(),
            files: this.files,
            statistics: this.stats
        };
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);

    if (args.length < 1) {
        console.error('Usage: node repository_scanner.js <repo_path> [--output <file>] [--exclude <pattern1,pattern2,...>]');
        console.error('');
        console.error('Options:');
        console.error('  --output <file>     Write results to file instead of stdout');
        console.error('  --exclude <patterns> Additional comma-separated exclude patterns');
        console.error('');
        console.error('Example:');
        console.error('  node repository_scanner.js /path/to/repo --output scan_results.json');
        process.exit(1);
    }

    const repoPath = args[0];
    let outputFile = null;
    let additionalExcludes = [];
    let skipTests = false;

    // Parse arguments
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--output' && args[i + 1]) {
            outputFile = args[i + 1];
            i++;
        } else if (args[i] === '--exclude' && args[i + 1]) {
            additionalExcludes = args[i + 1].split(',').map(s => s.trim());
            i++;
        } else if (args[i] === '--skip-tests') {
            skipTests = true;
        }
    }

    try {
        const options = {};
        if (skipTests) {
            options.skipTests = true;
        }
        if (additionalExcludes.length > 0) {
            // Merge with default excludes
            const defaultExcludes = [
                'node_modules', 'dist', 'build', 'coverage', '.git', '.svn', '.hg',
                '__pycache__', '.next', '.nuxt', 'out', '.cache', 'tmp', 'temp',
                '.turbo', '.vercel', '.netlify'
            ];
            options.excludePatterns = [...defaultExcludes, ...additionalExcludes];
        }

        const scanner = new RepositoryScanner(repoPath, options);
        const result = scanner.scan();

        const output = JSON.stringify(result, null, 2);

        if (outputFile) {
            fs.writeFileSync(outputFile, output);
            console.error(`Scan complete. Results written to: ${outputFile}`);
            console.error(`Total files found: ${result.statistics.totalFiles}`);
            console.error(`By extension:`, result.statistics.byExtension);
        } else {
            console.log(output);
        }

        process.exit(0);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

module.exports = { RepositoryScanner };
