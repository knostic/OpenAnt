# JavaScript/TypeScript Parser Pipeline

**Last Updated**: 2026-01-11 (Processing Levels + CodeQL Integration)

---

## Overview

The OpenAnt parser pipeline transforms JavaScript/TypeScript repositories into structured datasets for security analysis. It supports four processing levels with progressive cost optimization through filtering.

---

## Processing Levels

The pipeline supports four processing levels with cumulative filtering:

| Level | Name | Filter | Stages | Cost |
|-------|------|--------|--------|------|
| 1 | `all` | None | 1-3 | Highest |
| 2 | `reachable` | Entry point reachability | 1-3 + 3.5 | Moderate |
| 3 | `codeql` | Reachable + CodeQL-flagged | 1-3 + 3.5 + 3.6-3.7 | Low |
| 4 | `exploitable` | Reachable + CodeQL + Exploitable | 1-3 + 3.5 + 3.6-3.7 + 4 + 4.5 | Lowest |

**Example cost savings (Flowise `packages/components`):**

| Level | Units | Reduction |
|-------|-------|-----------|
| All | 1,417 | - |
| Reachable | 78 | 94.5% |
| CodeQL | 2 | 99.9% |
| Exploitable | 2 | 99.9% |

**What each level excludes:**

| Level | Code NOT Processed |
|-------|-------------------|
| 1: all | None - complete coverage |
| 2: reachable | Internal utilities, dead code, non-entry-point reachable functions |
| 3: codeql | Reachable code without known vulnerability patterns (SQLi, XSS, etc.) |
| 4: exploitable | CodeQL-flagged code classified as security_control, neutral, or vulnerable_internal |

---

## Core Objectives

1. **Full repository coverage** — Process every source file, not just route handlers
2. **Dataset completeness** — Include all functions in the generated dataset
3. **Self-contained analysis units** — Each unit contains all code needed for security analysis
4. **Include all dependencies** — Capture both upstream (callees) and downstream (callers) dependencies
5. **Security intent detection** — Distinguish security controls from vulnerable code

---

## Pipeline Stages

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        JAVASCRIPT STAGES (1-3)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Stage 1: RepositoryScanner                                              │
│  ─────────────────────────                                               │
│  Input:  Repository path                                                 │
│  Output: scan_results.json (list of all source files)                    │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 2: TypeScriptAnalyzer                                             │
│  ──────────────────────────                                              │
│  Input:  File list from Stage 1                                          │
│  Output: analyzer_output.json (all functions with metadata)              │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 3: UnitGenerator (includes DependencyResolver)                    │
│  ────────────────────────────────────────────────────                    │
│  Input:  analyzer_output.json                                            │
│  Output: dataset.json (OpenAnt dataset format)                          │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                     FILTERING STAGES (3.5-3.7) - Optional                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Stage 3.5: ReachabilityFilter (if --processing-level >= reachable)      │
│  ─────────────────────────────                                           │
│  Input:  dataset.json + analyzer_output.json                             │
│  Output: dataset.json (filtered to reachable units)                      │
│  Method: BFS from entry points via reverse call graph                    │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 3.6: CodeQL Analysis (if --processing-level >= codeql)            │
│  ───────────────────────────                                             │
│  Input:  Repository path                                                 │
│  Output: codeql-results.sarif (vulnerability findings)                   │
│  Method: CodeQL database + security queries                              │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 3.7: CodeQL Filter (if --processing-level >= codeql)              │
│  ─────────────────────────                                               │
│  Input:  dataset.json + SARIF results                                    │
│  Output: dataset.json (filtered to CodeQL-flagged units)                 │
│  Method: Map SARIF file:line to function units                           │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                     LLM ENHANCEMENT STAGES (4-4.5) - Optional            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Stage 4: ContextEnhancer                                                │
│  ────────────────────────                                                │
│  Input:  dataset.json + analyzer_output.json                             │
│  Output: dataset.json (enhanced with LLM context)                        │
│  Modes:  Single-shot (fast) or Agentic (accurate)                        │
│  Model:  Claude Sonnet                                                   │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 4.5: ExploitableFilter (if --processing-level == exploitable)     │
│  ────────────────────────────                                            │
│  Input:  dataset.json (with agent_context.security_classification)       │
│  Output: dataset.json (filtered to exploitable units only)               │
│  Method: Keep only units classified as "exploitable"                     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Processing Levels

```bash
# Level 1: All units (no filtering)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --processing-level all

# Level 2: Reachable units only (94% cost reduction)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --processing-level reachable

# Level 3: Reachable + CodeQL-flagged (99% cost reduction)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --processing-level codeql

# Level 4: Exploitable only (maximum cost savings)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --processing-level exploitable \
    --llm --agentic
```

### With LLM Enhancement

```bash
# Single-shot LLM enhancement (fast, less accurate)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --llm

# Agentic LLM enhancement (recommended for Level 4)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --llm --agentic
```

### Run Individual Stages

```bash
# Stage 1: Scan repository
node repository_scanner.js /path/to/repo --output scan_results.json

# Stage 2: Analyze functions (requires file list)
node /path/to/typescript_analyzer.js \
    /path/to/repo --files-from file_list.txt --output analyzer_output.json

# Stage 3: Generate dataset
node unit_generator.js analyzer_output.json --output dataset.json --depth 3

# Stage 4a (single-shot): LLM enhancement
python -m utilities.context_enhancer dataset.json --output enhanced_dataset.json

# Stage 4b (agentic): LLM enhancement with tool use
python -m utilities.context_enhancer dataset.json \
    --agentic \
    --analyzer-output analyzer_output.json \
    --repo-path /path/to/repo \
    --output enhanced_dataset.json
```

---

## Stage 1: RepositoryScanner

**File**: `repository_scanner.js`

**Purpose**: Enumerate all source files in a repository for complete coverage.

**Input**:
- `repo_path`: Path to repository root

**Output** (`scan_results.json`):
```json
{
  "repository": "/path/to/repo",
  "scan_time": "2024-12-24T10:00:00Z",
  "files": [
    { "path": "src/index.ts", "size": 1234, "extension": ".ts" },
    { "path": "src/utils/helper.js", "size": 567, "extension": ".js" }
  ],
  "statistics": {
    "totalFiles": 150,
    "byExtension": { ".ts": 100, ".js": 50 },
    "totalSizeBytes": 500000,
    "directoriesScanned": 25,
    "directoriesExcluded": 10
  }
}
```

**Behavior**:
- Recursively scans all directories
- Includes: `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`
- Excludes: `node_modules`, `dist`, `build`, `.git`, `coverage`, etc.

**CLI**:
```bash
node repository_scanner.js <repo_path> [--output <file>] [--exclude <patterns>]
```

---

## Stage 2: TypeScriptAnalyzer

**File**: External (path provided via `--analyzer-path`)

**Purpose**: Extract all functions from source files with metadata and unit type classification.

**Input**:
- Repository path
- File list (from `--files-from` or inline)

**Output** (`analyzer_output.json`):
```json
{
  "repoRoot": "/path/to/repo",
  "functions": {
    "src/auth/login.ts:handleLogin": {
      "name": "handleLogin",
      "code": "async function handleLogin(req, res) { ... }",
      "startLine": 15,
      "endLine": 45,
      "unitType": "route_handler",
      "className": null,
      "isExported": true,
      "exportType": "named"
    }
  }
}
```

**Unit Types**:
| Type | Detection |
|------|-----------|
| `route_handler` | Has `(req, res)` or `(request, response)` parameters |
| `middleware` | Has `(req, res, next)` parameters or calls `next()` |
| `class_method` | Method inside a class |
| `function` | Default for standalone functions |

**CLI**:
```bash
node typescript_analyzer.js <repo_path> --files-from <file_list.txt> --output <output.json>
```

---

## Stage 3: UnitGenerator

**File**: `unit_generator.js`

**Purpose**: Create OpenAnt dataset from analyzer output. Includes DependencyResolver for call graph building. Outputs standard OpenAnt format with assembled dependency code.

**Input**:
- `analyzer_output.json` from Stage 2
- Optional: `routes.json` for route handler tagging

**Output** (`dataset.json`) — Standard OpenAnt Format:
```json
{
  "name": "repository-name",
  "repository": "/path/to/repo",
  "units": [
    {
      "id": "src/auth/login.ts:handleLogin",
      "unit_type": "route_handler",
      "code": {
        "primary_code": "async function handleLogin(req, res) { ... }\n\n// ========== File Boundary ==========\n\nfunction sanitizeInput(input) { ... }",
        "primary_origin": {
          "file_path": "src/auth/login.ts",
          "start_line": 15,
          "end_line": 45,
          "function_name": "handleLogin",
          "class_name": null,
          "enhanced": true,
          "files_included": ["src/auth/login.ts", "src/utils/validate.ts"],
          "original_length": 500,
          "enhanced_length": 1200
        },
        "dependencies": [],
        "dependency_metadata": {
          "depth": 3,
          "total_upstream": 5,
          "total_downstream": 0,
          "direct_calls": 3,
          "direct_callers": 0
        }
      }
    }
  ],
  "statistics": {
    "totalUnits": 150,
    "byType": { "route_handler": 20, "function": 100, "middleware": 10 },
    "callGraph": {
      "totalEdges": 500,
      "avgOutDegree": 2.5,
      "maxOutDegree": 15
    }
  }
}
```

**Key Format Requirements** (for OpenAnt compatibility):
| Field | Required | Description |
|-------|----------|-------------|
| `code.primary_code` | Yes | All code assembled with `// ========== File Boundary ==========` separators |
| `code.primary_origin.enhanced` | Yes | `true` if dependencies included, `false` otherwise |
| `code.primary_origin.files_included` | Yes | List of all files whose code is in `primary_code` |
| `code.primary_origin.original_length` | Yes | Length of primary function code only |
| `code.primary_origin.enhanced_length` | Yes | Length of assembled code with dependencies |

**Validation**: Use `validate_dataset_schema.py` to verify output before LLM operations:
```bash
python validate_dataset_schema.py dataset.json
```

**DependencyResolver** (embedded in UnitGenerator):
- Builds call graph by analyzing function bodies
- Resolves `this.method()`, `object.method()`, standalone function calls
- Builds reverse call graph (who calls this function)
- Collects transitive dependencies up to configurable depth

**CLI**:
```bash
node unit_generator.js <analyzer_output.json> [options]

Options:
  --output <file>       Write results to file instead of stdout
  --depth <N>           Max dependency resolution depth (default: 3)
  --routes <routes.json> Route information from ast_parser.js
  --name <name>         Dataset name (default: derived from repo path)
```

---

## Stage 4: ContextEnhancer (Optional)

**File**: `utilities/context_enhancer.py`

**Purpose**: Enhance static analysis with LLM-identified context using Claude Sonnet.

**Model**: `claude-sonnet-4-20250514`

### Two Enhancement Modes

| Mode | Flag | Description | Accuracy | Cost |
|------|------|-------------|----------|------|
| **Single-shot** | `--llm` | One prompt per unit, fast | ~31% | ~$0.02/unit |
| **Agentic** | `--llm --agentic` | Iterative tool use, traces call paths | **100%** | ~$0.21/unit |

### Single-Shot Mode (Default)

Fast, single-prompt analysis. Good for initial exploration but has high false positive rate for security controls.

**Output** (added to each unit):
```json
{
  "llm_context": {
    "missing_dependencies": [...],
    "additional_callers": [...],
    "data_flow": {...},
    "imports": [...],
    "reasoning": "...",
    "confidence": 0.85
  }
}
```

### Agentic Mode (Recommended)

Iterative analysis with tool use. The agent searches for function usages, reads code, and traces call paths to understand intent.

**Agent Tools**:
| Tool | Purpose |
|------|---------|
| `search_usages` | Find where a function is called |
| `search_definitions` | Find where a function is defined |
| `read_function` | Get full function code by ID |
| `list_functions` | List functions in a file |
| `read_file_section` | Read specific lines from a file |
| `finish` | Complete analysis with result |

**Output** (added to each unit):
```json
{
  "agent_context": {
    "include_functions": [
      {"id": "src/validator.ts:isUnsafeFilePath", "reason": "Called to validate paths"}
    ],
    "usage_context": "This function is called by readFile/writeFile to validate paths before I/O",
    "security_classification": "security_control",
    "classification_reasoning": "Function throws errors when unsafe conditions detected, callers respect these errors to block operations",
    "confidence": 0.95,
    "agent_metadata": {
      "iterations": 12,
      "total_tokens": 61000
    },
    "reachability": {
      "is_entry_point": false,
      "reachable_from_entry": true,
      "entry_point_path": ["src/routes/files.ts:handleUpload", "src/validator.ts:validatePath", "src/validator.ts:isUnsafeFilePath"]
    }
  }
}
```

**Security Classifications** (Reachability-Aware):
| Classification | Meaning |
|----------------|---------|
| `exploitable` | Vulnerable AND reachable from user input (HTTP, CLI, stdin, etc.) |
| `vulnerable_internal` | Vulnerable but NOT reachable from user input (internal APIs, tests) |
| `security_control` | Prevents or blocks vulnerabilities |
| `neutral` | Neither vulnerable nor a security control |

**Reachability Analysis**:
The agentic enhancer now includes reachability analysis to distinguish exploitable vulnerabilities from internal-only ones:
- **Entry Point Detection**: Identifies route handlers, CLI parsers, stdin readers, WebSocket handlers
- **Call Path Tracing**: Uses reverse call graph to trace paths from entry points to each function
- **Cost Optimization**: Units not reachable from entry points can be deprioritized or skipped

**CLI**:
```bash
# Single-shot mode
python -m utilities.context_enhancer <dataset.json> [-o <output.json>] [--batch-size 10]

# Agentic mode (recommended)
python -m utilities.context_enhancer <dataset.json> \
    --agentic \
    --analyzer-output <analyzer_output.json> \
    --repo-path <repo_path> \
    [-o <output.json>] \
    [--verbose]
```

**Environment**:
- Requires `ANTHROPIC_API_KEY` environment variable

---

## File Locations

| File | Location | Purpose |
|------|----------|---------|
| `repository_scanner.js` | `parsers/javascript/` | Stage 1: File enumeration |
| `typescript_analyzer.js` | External | Stage 2: Function extraction |
| `dependency_resolver.js` | `parsers/javascript/` | Call graph building (used by Stage 3) |
| `unit_generator.js` | `parsers/javascript/` | Stage 3: Dataset generation (OpenAnt format) |
| `context_enhancer.py` | `utilities/` | Stage 4: LLM enhancement |
| `agentic_enhancer/` | `utilities/` | Agentic enhancement module |
| `agentic_enhancer/entry_point_detector.py` | `utilities/` | Entry point detection (route handlers, CLI, etc.) |
| `agentic_enhancer/reachability_analyzer.py` | `utilities/` | User input reachability analysis |
| `test_pipeline.py` | `parsers/javascript/` | Pipeline orchestration |
| `validate_dataset_schema.py` | `openant/` | Validate dataset matches OpenAnt schema |

---

## Model Strategy

| Task | Model | Rationale |
|------|-------|-----------|
| Context enhancement (single-shot) | Sonnet | Auxiliary task, cost-effective |
| Context enhancement (agentic) | Sonnet | Tool use for exploration |
| Vulnerability detection | Opus | Core analysis, requires deep reasoning |

All LLM calls are in Python (`utilities/`). JavaScript components perform static analysis only.

---

## Test Pipeline Usage

The `test_pipeline.py` script orchestrates all stages:

```bash
# Static analysis only (Stages 1-3)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output

# With single-shot LLM enhancement (Stages 1-4)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --llm

# With agentic LLM enhancement (Stages 1-4, recommended)
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --llm --agentic
```

**IDE Mode**: Edit the hardcoded values at the top of `test_pipeline.py`:
```python
IDE_MODE = True
HARDCODED_REPO_PATH = '/path/to/repo'
HARDCODED_OUTPUT_DIR = '/path/to/output'
HARDCODED_ANALYZER_PATH = '/path/to/typescript_analyzer.js'
HARDCODED_ENABLE_LLM = True
HARDCODED_AGENTIC = True
```

**Output Files**:
- `scan_results.json` - Stage 1 output
- `analyzer_output.json` - Stage 2 output
- `dataset.json` - Final dataset (Stage 3 or 4)
- `pipeline_results.json` - Summary of all stages

---

## Dependencies

### Node.js
```bash
cd /path/to/openant/parsers/javascript
npm ci  # Installs dependencies for scanner and generator (from the committed lock, #795)
```

### Python
```bash
pip install anthropic python-dotenv
```

---

## Troubleshooting

### "No files found" (Stage 1)
- Check repository path exists
- Verify source files have supported extensions
- Check exclude patterns aren't too aggressive

### "0 functions extracted" (Stage 2)
- Verify file list is correct
- Check for TypeScript compilation errors
- Try running on individual files to isolate issue

### "Empty call graph" (Stage 3)
- Functions may be isolated (no calls between them)
- Check if function names match call patterns
- Increase `--depth` parameter

### "LLM errors" (Stage 4)
- Verify `ANTHROPIC_API_KEY` is set
- Check API rate limits
- Review error messages in output

### High false positive rate (Single-shot mode)
- Use `--agentic` flag for accurate security classification
- Agentic mode traces call paths to understand intent

---

## Version History

- **2026-01-11**: Added 4-level processing system with CodeQL integration:
  - Level 1 (all): No filtering
  - Level 2 (reachable): Entry point reachability filter (94% cost reduction)
  - Level 3 (codeql): CodeQL security analysis filter (99% cost reduction)
  - Level 4 (exploitable): Agentic classification filter (maximum savings)
  - Added `--processing-level` CLI argument
  - Added CodeQL database creation, security query execution, SARIF parsing
  - Added `_detect_codeql_language()` for Python/JavaScript auto-detection
- **2026-01-11**: Added reachability-aware classification. New categories: `exploitable` (vulnerable + user-reachable) and `vulnerable_internal` (vulnerable but internal). Added `EntryPointDetector` and `ReachabilityAnalyzer` modules.
- **2025-12-26**: Added agentic context enhancement with tool use. 100% accuracy on security control detection. Added `--agentic` flag to pipeline.
- **2025-12-25**: Fixed unit_generator.js to output standard OpenAnt format (`enhanced`, `files_included`, assembled `primary_code` with file boundaries). Added `validate_dataset_schema.py`.
- **2024-12-24**: Major refactoring - moved LLM calls from JavaScript to Python
- **2024-12-23**: Added RepositoryScanner, DependencyResolver, UnitGenerator
- **2024-12-23**: Initial documentation
