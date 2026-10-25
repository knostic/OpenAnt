# Parser Upgrade Plan - Implementation Status

**Purpose**: This document tracks the parser upgrade from route-only extraction to full repository coverage with call graph analysis, LLM enhancement, and cost-optimized processing levels.

**Created**: 2024-12-23
**Last Updated**: 2026-01-11 (Processing Levels + CodeQL Integration)

---

## Implementation Status

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1: Full Coverage | **COMPLETE** | RepositoryScanner, TypeScriptAnalyzer, UnitGenerator |
| Phase 2: Call Graph | **COMPLETE** | DependencyResolver integrated into UnitGenerator |
| Phase 3: LLM Enhancement | **COMPLETE** | ContextEnhancer (Python) using Claude Sonnet |
| Phase 4: OpenAnt Format | **COMPLETE** | Standard output format with assembled dependencies |
| Phase 5: Agentic Enhancement | **COMPLETE** | Iterative tool use for security intent detection |
| Phase 6: Reachability Classification | **COMPLETE** | Entry point detection + user input reachability analysis |
| Phase 7: Processing Levels + CodeQL | **COMPLETE** | 4-level cost optimization with CodeQL pre-filter |

---

## Core Objectives

The parser pipeline **must** adhere to these requirements:

1. **Achieve full repository coverage** — Process every line of code in the target repository without exception.
2. **Ensure dataset completeness** — Include the entire repository's codebase in the generated dataset.
3. **Produce self-contained analysis units** — Each item in the dataset must contain all code necessary for complete security assessment by an LLM.
4. **Include all dependencies** — Capture both upstream dependencies (code that the target calls) and downstream dependencies (code that calls or consumes the target).
5. **Output standard OpenAnt format** — The parser output must be directly consumable by OpenAnt's `experiment.py` without transformation.
6. **Detect security intent** — Distinguish security controls from vulnerable code by tracing call paths and understanding usage patterns.

---

## Standard OpenAnt Input Format

**CRITICAL**: The parser must output this exact schema for OpenAnt compatibility.

### Dataset Structure

```json
{
  "name": "repository-name",
  "repository": "/path/to/repo",
  "units": [ ... ],
  "statistics": {
    "totalUnits": 1417,
    "byType": {
      "function": 322,
      "class_method": 1040,
      "model": 55
    },
    "callGraph": {
      "totalEdges": 2823,
      "avgOutDegree": "1.99",
      "avgInDegree": "1.99",
      "maxOutDegree": 15,
      "maxInDegree": 164,
      "isolatedFunctions": 19
    },
    "unitsWithUpstream": 833,
    "unitsWithDownstream": 548
  },
  "metadata": {
    "generator": "unit_generator.js",
    "generated_at": "2025-12-25T14:21:49.149Z",
    "dependency_depth": 3
  }
}
```

### Unit Structure (Standard OpenAnt Format)

```json
{
  "id": "evaluation/EvaluationRunner.ts:EvaluationRunner.addMetrics",
  "unit_type": "class_method",
  "code": {
    "primary_code": "static addMetrics(id: string, metric: string) { ... }\n\n// ========== File Boundary ==========\n\nonLLMEnd(output: LLMResult) { ... }",
    "primary_origin": {
      "file_path": "evaluation/EvaluationRunner.ts",
      "start_line": 71,
      "end_line": 77,
      "function_name": "EvaluationRunner.addMetrics",
      "class_name": "EvaluationRunner",
      "enhanced": true,
      "files_included": [
        "evaluation/EvaluationRunner.ts",
        "evaluation/EvaluationRunTracer.ts",
        "evaluation/EvaluationRunTracerLlama.ts"
      ],
      "original_length": 248,
      "enhanced_length": 7822
    },
    "dependencies": [],
    "dependency_metadata": {
      "depth": 3,
      "total_upstream": 0,
      "total_downstream": 3,
      "direct_calls": 1,
      "direct_callers": 4
    }
  },
  "route": null,
  "ground_truth": {
    "status": "UNKNOWN",
    "vulnerability_types": [],
    "issues": [],
    "annotation_source": null,
    "annotation_key": null,
    "notes": null
  },
  "metadata": {
    "is_exported": true,
    "export_type": null,
    "generator": "unit_generator.js",
    "direct_calls": ["evaluation/EvaluationRunner.ts:EvaluationRunner.addMetrics"],
    "direct_callers": [
      "evaluation/EvaluationRunTracer.ts:EvaluationRunTracer.onLLMEnd",
      "evaluation/EvaluationRunTracer.ts:EvaluationRunTracer.onRunUpdate"
    ]
  },
  "agent_context": {
    "include_functions": [...],
    "usage_context": "...",
    "security_classification": "security_control",
    "classification_reasoning": "...",
    "confidence": 0.95
  }
}
```

### Required Fields for OpenAnt Compatibility

| Field | Required | Description |
|-------|----------|-------------|
| `code.primary_code` | **YES** | All code assembled with `// ========== File Boundary ==========` separators |
| `code.primary_origin.enhanced` | **YES** | `true` if dependencies included in primary_code, `false` otherwise |
| `code.primary_origin.files_included` | **YES** | List of all files whose code appears in primary_code |
| `code.primary_origin.original_length` | **YES** | Character count of primary function code only |
| `code.primary_origin.enhanced_length` | **YES** | Character count of assembled code with all dependencies |

**Why these fields matter**:
- `experiment.py` checks `primary_origin.enhanced` (line 191) to decide whether to use multifile analysis
- `experiment.py` uses `primary_origin.files_included` (line 192) for language detection and context
- Without these fields, OpenAnt analyzes each unit in isolation without dependency context

### Validation

Always validate output before LLM operations:

```bash
python validate_dataset_schema.py dataset.json
```

---

## Phase 1: Full Coverage — COMPLETE

### 1.1 RepositoryScanner — DONE

**File**: `parsers/javascript/repository_scanner.js`

**Implementation**:
- Recursively enumerates all source files in repository
- Supports `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs` extensions
- Excludes `node_modules`, `dist`, `build`, `.git`, `coverage`, etc.
- Outputs file list with metadata (size, extension)

**Usage**:
```bash
node repository_scanner.js /path/to/repo --output scan_results.json
```

### 1.2 TypeScriptAnalyzer Modifications — DONE

**File**: External (path provided via `--analyzer-path`)

**Modifications**:
- Added batch mode to extract ALL functions from files
- Added unit type classification (`route_handler`, `middleware`, `function`, `class_method`)
- Added export detection (`isExported`, `exportType`)
- Added call extraction for call graph building

**Output Format**:
```json
{
  "functions": {
    "file.ts:functionName": {
      "name": "functionName",
      "code": "function functionName() { ... }",
      "startLine": 10,
      "endLine": 25,
      "unitType": "route_handler",
      "className": null,
      "isExported": true,
      "exportType": "named"
    }
  }
}
```

### 1.3 UnitGenerator — DONE

**File**: `parsers/javascript/unit_generator.js`

**Implementation**:
- Creates analysis units for ALL functions (not just routes)
- Classifies units by type
- Integrates with DependencyResolver for call graph
- **Outputs standard OpenAnt dataset format** with assembled dependencies

**Usage**:
```bash
node unit_generator.js analyzer_output.json --output dataset.json --depth 3
```

---

## Phase 2: Call Graph — COMPLETE

### 2.1 DependencyResolver — DONE

**File**: `parsers/javascript/dependency_resolver.js`

**Implementation**:
- Builds call graph by analyzing function bodies with regex patterns
- Resolves `this.method()`, `object.method()`, standalone function calls
- Builds reverse call graph (who calls this function)
- Provides transitive dependency resolution up to configurable depth
- Integrated into UnitGenerator (not standalone)

**Features**:
- `buildCallGraph()` - Analyzes all functions and builds caller/callee relationships
- `getDependencies(functionId)` - Returns transitive callees (upstream)
- `getCallers(functionId)` - Returns transitive callers (downstream)
- `getStatistics()` - Returns call graph metrics (edges, degrees, isolated functions)

### 2.2 Code Assembly — DONE (2025-12-25)

Dependencies are assembled directly into `primary_code` with file boundary markers:

```
primary function code

// ========== File Boundary ==========

dependency 1 code

// ========== File Boundary ==========

dependency 2 code
```

This format matches DVNA/NodeGoat enhanced datasets and is recognized by OpenAnt.

---

## Phase 3: LLM Enhancement — COMPLETE

### 3.1 Architecture Decision: Python Only

**Decision**: All LLM calls are in Python. JavaScript components perform static analysis only.

**Rationale**:
- Centralizes LLM logic in `utilities/` alongside existing LLM components
- Reuses existing error handling (JSON correction, retries)
- Allows model strategy (Sonnet vs Opus) to be managed in one place
- Eliminates code duplication between languages

### 3.2 ContextEnhancer (Single-Shot) — DONE

**File**: `utilities/context_enhancer.py`

**Implementation**:
- Uses Claude Sonnet (`claude-sonnet-4-6`) for cost-effective enhancement
- Identifies missing dependencies that static analysis missed
- Identifies additional callers based on naming patterns
- Extracts data flow information (inputs, outputs, tainted variables, security flows)
- Batch processing with progress reporting

**Usage**:
```bash
python -m utilities.context_enhancer dataset.json --output enhanced.json
```

**Limitation**: Single-shot analysis has ~31% accuracy for security control detection due to lack of context about how functions are used.

### 3.3 Model Strategy — DONE

| Task | Model | Location |
|------|-------|----------|
| Context enhancement (single-shot) | Sonnet | `utilities/context_enhancer.py` |
| Context enhancement (agentic) | Sonnet | `utilities/agentic_enhancer/` |
| JSON repair | Sonnet | `utilities/json_corrector.py` |
| Context review | Sonnet | `utilities/context_reviewer.py` |
| Vulnerability detection | Opus | `utilities/llm_client.py` |

### 3.4 Removed JavaScript LLM Code

The following were removed during refactoring (2024-12-24):
- `llm_context_analyzer.js` — Deleted entirely
- `unit_generator.js` — Removed `--llm`, `--model`, `--batch` flags and all LLM methods

---

## Phase 4: OpenAnt Format Compliance — COMPLETE (2025-12-25)

### 4.1 Problem Identified

The original `unit_generator.js` output was incompatible with OpenAnt:
- Missing `primary_origin.enhanced` field
- Missing `primary_origin.files_included` field
- Dependency code stored in separate arrays instead of assembled into `primary_code`

This caused `experiment.py` to set `is_enhanced=false` for all units, resulting in analysis without dependency context.

### 4.2 Solution Implemented

Modified `unit_generator.js` to:
1. Assemble all dependency code into `primary_code` with file boundary markers
2. Set `primary_origin.enhanced = true` when dependencies are included
3. Populate `primary_origin.files_included` with all contributing files
4. Track `original_length` and `enhanced_length` for statistics

### 4.3 Validation Script

Created `validate_dataset_schema.py` to verify datasets before expensive LLM operations:

```bash
python validate_dataset_schema.py dataset.json
```

Checks:
- `code.primary_origin.enhanced` exists and is boolean
- `code.primary_origin.files_included` exists and is array
- File boundary markers present when multiple files included
- `primary_code` is non-empty

---

## Phase 5: Agentic Enhancement — COMPLETE (2025-12-26)

### 5.1 Problem Identified

Single-shot LLM analysis produced high false positive rates (7/10 findings) because:
1. **Task Framing**: "Find vulnerabilities" primes model to flag anything security-related
2. **Context Depth**: Cannot trace how functions are used
3. **Pattern vs Intent**: Cannot distinguish security controls from vulnerable code

Example: `isUnsafeFilePath` was flagged as vulnerable because it "handles path traversal patterns", when it's actually a security control that BLOCKS path traversal.

### 5.2 Solution: Agentic Analysis

Implemented iterative tool-use analysis that mimics how a security expert would analyze code:

1. **Work Plan**: Agent states analysis approach before using tools
2. **Trace Call Paths**: Search for usages, read callers, understand data flow
3. **Determine Intent**: "Is this code BLOCKING or EXECUTING something dangerous?"
4. **Complete Analysis**: Return classification with reasoning

### 5.3 Implementation

**New Files**:
| File | Purpose |
|------|---------|
| `utilities/agentic_enhancer/__init__.py` | Package exports |
| `utilities/agentic_enhancer/repository_index.py` | Searchable function index |
| `utilities/agentic_enhancer/tools.py` | Tool definitions for Anthropic API |
| `utilities/agentic_enhancer/prompts.py` | System and user prompts |
| `utilities/agentic_enhancer/agent.py` | Main agent loop with tool dispatch |

**Agent Tools**:
| Tool | Purpose |
|------|---------|
| `search_usages` | Find where a function is called |
| `search_definitions` | Find where a function is defined |
| `read_function` | Get full function code by ID |
| `list_functions` | List functions in a file |
| `read_file_section` | Read specific lines from a file |
| `finish` | Complete analysis with result |

**Security Classifications** (Updated in Phase 6):
| Classification | Meaning |
|----------------|---------|
| `exploitable` | Vulnerable AND reachable from user input |
| `vulnerable_internal` | Vulnerable but NOT reachable from user input |
| `security_control` | Prevents or blocks vulnerabilities |
| `neutral` | Neither vulnerable nor a security control |

### 5.4 Usage

```bash
# Via context_enhancer
python -m utilities.context_enhancer dataset.json \
    --agentic \
    --analyzer-output analyzer_output.json \
    --repo-path /path/to/repo \
    --output enhanced_dataset.json

# Via test_pipeline
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output \
    --llm --agentic
```

### 5.5 Test Results — VERIFIED

Tested on 13 units from 4 Flowise files with known vulnerabilities:

| Metric | Single-Shot | Agentic |
|--------|------------|---------|
| True Positives | 1 | 3 |
| False Positives | 7 | 0 |
| True Negatives | 3 | 10 |
| False Negatives | 2 | 0 |
| **Accuracy** | **31%** | **100%** |

**Correctly classified as VULNERABLE (3)**:
- `SecureFileStore.createUnsecure` — Disables security controls
- `Puppeteer_DocumentLoaders.init` — SSRF vulnerability
- `Playwright_DocumentLoaders.init` — SSRF vulnerability

**Correctly classified as SECURITY_CONTROL (10)**:
- `SecureFileStore.validateFilePath`
- `SecureFileStore.validateFileSize`
- `SecureFileStore.readFile`
- `SecureFileStore.writeFile`
- `SecureFileStore.getConfig`
- `validator.isValidUUID`
- `validator.isValidURL`
- `validator.isPathTraversal`
- `validator.isUnsafeFilePath`
- `validator.isWithinWorkspace`

### 5.6 Cost Analysis

| Mode | Cost per Unit | Accuracy |
|------|---------------|----------|
| Single-shot | ~$0.02 | ~31% |
| Agentic | ~$0.21 | 100% |

Agentic mode is ~10x more expensive but eliminates false positives.

---

## Phase 6: Reachability Classification — COMPLETE (2026-01-11)

### 6.1 Problem Identified

With datasets like DVNA and NodeGoat showing 83-89% of units classified as `vulnerable`, simply filtering on vulnerability status provides minimal cost savings. The key insight: **not all vulnerabilities are exploitable** — only those reachable from user input pose actual risk.

### 6.2 Solution: User Input Reachability Analysis

Added two new components to distinguish exploitable vulnerabilities from internal-only ones:

1. **Entry Point Detection**: Identifies functions that directly receive user input
2. **Reachability Analysis**: Uses reverse call graph to trace paths from entry points

### 6.3 Implementation

**New Files**:
| File | Purpose |
|------|---------|
| `utilities/agentic_enhancer/entry_point_detector.py` | Identifies entry points (route handlers, CLI, stdin, etc.) |
| `utilities/agentic_enhancer/reachability_analyzer.py` | BFS reachability from entry points via reverse call graph |

**Entry Point Detection Patterns**:
- Route handlers: `@app.route`, `@router.post`, `req.body`, `request.args`
- CLI: `sys.argv`, `argparse`, `click.command`
- Stdin: `input()`, `sys.stdin`
- WebSocket: `on_message`, `websocket.receive`
- Streamlit: `st.text_input`, `st.file_uploader`

**Updated Classification Enum**:
| Classification | Meaning |
|----------------|---------|
| `exploitable` | Vulnerable + reachable from user input (highest priority) |
| `vulnerable_internal` | Vulnerable but no user input path (lower priority) |
| `security_control` | Defensive code |
| `neutral` | No security relevance |

### 6.4 Output Format

Each unit now includes reachability information:

```json
{
  "agent_context": {
    "security_classification": "exploitable",
    "reachability": {
      "is_entry_point": false,
      "reachable_from_entry": true,
      "entry_point_path": ["routes/api.js:handleRequest", "utils/process.js:processData", "utils/eval.js:unsafeEval"]
    }
  }
}
```

### 6.5 Usage

```python
from utilities.agentic_enhancer import (
    create_reachability_context,
    enhance_unit_with_agent,
    RepositoryIndex
)

# Create reachability context from call graph
entry_points, reachability = create_reachability_context(
    functions=call_graph_data['functions'],
    call_graph=call_graph_data['call_graph'],
    reverse_call_graph=call_graph_data['reverse_call_graph']
)

# Enhance unit with reachability-aware classification
enhanced = enhance_unit_with_agent(
    unit, index,
    entry_points=entry_points,
    reachability=reachability
)
```

### 6.6 Expected Cost Savings

For a codebase with:
- 1000 total units
- 100 entry points
- 300 units reachable from entry points (30%)

Cost optimization:
- **Before**: Analyze all 1000 units
- **After**: Analyze only 300 reachable units (70% cost reduction)

Units classified as `vulnerable_internal` can be:
- Skipped entirely (aggressive optimization)
- Processed with lower priority
- Flagged for manual review

---

## Phase 7: Processing Levels + CodeQL — COMPLETE (2026-01-11)

### 7.1 Problem Identified

Reachability filtering (Phase 6) achieved significant cost savings (70-94%), but many reachable units are still security-neutral. Using CodeQL as a pre-filter can identify only units with known vulnerability patterns.

### 7.2 Solution: 4-Level Processing System

Implemented cumulative filtering with four processing levels:

| Level | Name | Filter | Cost Reduction |
|-------|------|--------|----------------|
| 1 | `all` | None | - |
| 2 | `reachable` | Entry point reachability | ~94% |
| 3 | `codeql` | Reachable + CodeQL-flagged | ~99% |
| 4 | `exploitable` | Reachable + CodeQL + Agentic classification | ~99.9% |

### 7.3 Implementation

**New CLI Argument:**
```bash
python test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/analyzer.js \
    --processing-level {all,reachable,codeql,exploitable}
```

**New Pipeline Stages:**
| Stage | Purpose |
|-------|---------|
| 3.5 | ReachabilityFilter - BFS from entry points |
| 3.6 | CodeQL Analysis - Create database, run security queries |
| 3.7 | CodeQL Filter - Map SARIF findings to function units |
| 4.5 | ExploitableFilter - Keep only "exploitable" classified units |

**CodeQL Integration:**
- Auto-detects language (JavaScript or Python) from scan results
- Creates CodeQL database for repository
- Runs security-extended query suite
- Outputs SARIF format results
- Maps file:line findings to function units by line range overlap

**New Methods in `test_pipeline.py`:**
| Method | Purpose |
|--------|---------|
| `_detect_codeql_language()` | Detect JS/Python from file extensions |
| `run_codeql_analysis()` | Create database, run queries, parse SARIF |
| `apply_codeql_filter()` | Filter dataset to CodeQL-flagged units |
| `apply_reachability_filter()` | Filter to reachable units |
| `apply_exploitable_filter()` | Filter to exploitable units only |

### 7.4 Test Results — VERIFIED

Tested on Flowise `packages/components` (1,417 units):

| Level | Units | Reduction | Agentic Cost |
|-------|-------|-----------|--------------|
| All | 1,417 | - | ~$300 |
| Reachable | 78 | 94.5% | ~$16 |
| CodeQL | 2 | 99.9% | **$0.69** |
| Exploitable | 2 | 99.9% | $0.69 |

**CodeQL Findings:**
- 11 security findings detected
- Mapped to 10 function units
- Only 2 of those in reachable set
- Both classified as "exploitable" by agentic analysis

### 7.5 What Each Level Excludes

| Level | Code NOT Processed | Risk |
|-------|-------------------|------|
| 1: all | None | None |
| 2: reachable | Internal utilities, dead code, non-entry-point functions | Low - misses unreachable vulnerabilities |
| 3: codeql | Reachable code without known vulnerability patterns | Medium - misses novel/logic flaws |
| 4: exploitable | security_control, neutral, vulnerable_internal | Low - depends on LLM accuracy |

### 7.6 CodeQL Requirements

**Installation:**
```bash
# macOS
brew install codeql

# Download query packs
codeql pack download codeql/javascript-queries
codeql pack download codeql/python-queries
```

**Supported Languages:**
- JavaScript/TypeScript (via `codeql/javascript-queries`)
- Python (via `codeql/python-queries`)

---

## Reference Files

| File | Location | Purpose |
|------|----------|---------|
| repository_scanner.js | `parsers/javascript/` | Stage 1: File enumeration |
| typescript_analyzer.js | External | Stage 2: Function extraction |
| dependency_resolver.js | `parsers/javascript/` | Call graph building |
| unit_generator.js | `parsers/javascript/` | Stage 3: Dataset generation (OpenAnt format) |
| context_enhancer.py | `utilities/` | Stage 4: LLM enhancement (both modes) |
| agentic_enhancer/ | `utilities/` | Agentic enhancement module |
| entry_point_detector.py | `utilities/agentic_enhancer/` | Entry point detection |
| reachability_analyzer.py | `utilities/agentic_enhancer/` | User input reachability analysis |
| test_pipeline.py | `parsers/javascript/` | Pipeline orchestration |
| validate_dataset_schema.py | `openant/` | Validate OpenAnt schema compliance |
| PARSER_PIPELINE.md | `parsers/javascript/` | Complete pipeline documentation |

---

## Success Criteria — VERIFIED

| Criterion | Status | Notes |
|-----------|--------|-------|
| Coverage Test | PASS | RepositoryScanner processes all source files |
| Completeness Test | PASS | UnitGenerator creates units for all functions |
| Self-Containment Test | PASS | Dependencies assembled into primary_code |
| Dependency Test | PASS | Upstream/downstream included with file boundaries |
| LLM Enhancement | PASS | ContextEnhancer adds missing context |
| OpenAnt Format | PASS | Output validated with validate_dataset_schema.py |
| Experiment.py Integration | PASS | `is_enhanced=true` recognized, multifile prompts used |
| Security Intent Detection | PASS | Agentic mode achieves 100% accuracy on test set |
| Reachability Classification | PASS | Entry points detected, reachability paths traced |

---

## Future Improvements (Not Planned)

The following items from the original plan were not implemented but could be added later:

1. **Dependency Relevance Filtering** — LLM to determine which dependencies are security-relevant (currently all are included up to depth limit)

2. **Cross-File Data Flow Inference** — LLM to trace taint propagation across function boundaries (currently basic data flow extraction only)

3. **Dependency Summarization** — LLM to summarize large dependencies that exceed token limits (currently dependencies are included in full)

4. **Cost Optimization** — Reduce agentic iterations through better initial prompts or hybrid single-shot + agentic approach

These would require additional prompts and integration work but are not critical for the current use case.

---

## Version History

- **2026-01-11**: Phase 7 complete. Added 4-level processing system with CodeQL integration. Levels: all, reachable, codeql, exploitable. Added `--processing-level` CLI argument. CodeQL auto-detects language, creates database, runs security queries, maps SARIF to function units. Achieved 99.9% cost reduction on Flowise test.
- **2026-01-11**: Phase 6 complete. Added reachability-aware classification. New categories: `exploitable` (vulnerable + user-reachable) and `vulnerable_internal` (vulnerable but internal). Added `EntryPointDetector` and `ReachabilityAnalyzer` modules.
- **2025-12-26**: Phase 5 complete. Added agentic context enhancement with tool use. Achieved 100% accuracy on security control detection. Added `--agentic` flag to pipeline.
- **2025-12-25**: Phase 4 complete. Fixed unit_generator.js to output standard OpenAnt format. Added `enhanced`, `files_included`, assembled `primary_code` with file boundaries. Created validate_dataset_schema.py.
- **2024-12-24**: Phase 3 complete. LLM code moved from JavaScript to Python.
- **2024-12-23**: Phase 1 and 2 complete. RepositoryScanner, DependencyResolver, UnitGenerator implemented.
- **2024-12-23**: Initial plan created.
