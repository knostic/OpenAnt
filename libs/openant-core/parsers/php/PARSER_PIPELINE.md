# PHP Code Parser Pipeline

A comprehensive PHP code parser that deconstructs codebases into self-contained analysis units for vulnerability detection.

## Overview

The parser transforms a PHP repository into a dataset of analysis units, where each unit contains:
- The primary code (function or method)
- All upstream dependencies (functions it calls)
- All downstream callers (functions that call it)
- Metadata for security analysis

## Pipeline Stages

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Repository     │     │   Function      │     │   Call Graph    │     │     Unit        │
│   Scanner       │ ──▶ │   Extractor     │ ──▶ │    Builder      │ ──▶ │   Generator     │
│                 │     │                 │     │                 │     │                 │
│ Find .php files │     │  Extract funcs  │     │  Build call     │     │  Create self-   │
│                 │     │  via tree-sitter│     │  relationships  │     │  contained units│
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Stage 1: Repository Scanner (`repository_scanner.py`)

Scans the repository to find all PHP source files.

**Input:** Repository path
**Output:** List of `.php` files with metadata

**Features:**
- Excludes common non-source directories (`vendor`, `node_modules`, `.git`, `build`, `dist`, `storage`, `bootstrap/cache`, etc.)
- Optional test file skipping (`test_*`, `*_test.php`, `*Test.php`, `test/`, `tests/`, `spec/`, `phpunit`)
- File size statistics

**Example:**
```bash
python repository_scanner.py /path/to/repo --output scan.json
```

### Stage 2: Function Extractor (`function_extractor.py`)

Extracts ALL functions and methods from PHP files using tree-sitter.

**Input:** Scan results or repository path
**Output:** Complete function inventory

**Extracts:**
- Top-level functions (`function_definition`)
- Class methods (`method_declaration`)
- Class, interface, and trait definitions
- Namespace definitions
- Imports (`use`, `require`, `include`, `require_once`, `include_once`)

**Example:**
```bash
python function_extractor.py /path/to/repo --output functions.json
```

### Stage 3: Call Graph Builder (`call_graph_builder.py`)

Builds bidirectional call graphs by analyzing function bodies via tree-sitter.

**Input:** Extractor output
**Output:** Call graph + reverse call graph

**Resolves:**
- Simple function calls: `func_name(...)`
- Member calls: `$this->method(...)`, `$obj->method(...)`
- Scoped calls: `ClassName::method(...)`, `self::method(...)`, `static::method(...)`

**Call Graphs:**
- **Forward (call_graph):** function -> functions it calls
- **Reverse (reverse_call_graph):** function -> functions that call it

**Filters:** ~120 PHP builtins (`echo`, `print`, `array_*`, `str*`, `preg_*`, etc.)

**Example:**
```bash
python call_graph_builder.py functions.json --output call_graph.json
```

### Stage 4: Unit Generator (`unit_generator.py`)

Creates self-contained analysis units with full context.

**Input:** Call graph data
**Output:** OpenAnt dataset format

**Each unit contains:**
```json
{
  "id": "file.php:ClassName.method_name",
  "unit_type": "method",
  "code": {
    "primary_code": "... enhanced code with dependencies ...",
    "primary_origin": {
      "file_path": "file.php",
      "start_line": 10,
      "end_line": 25,
      "function_name": "method_name",
      "enhanced": true,
      "files_included": ["file.php", "utils.php"]
    },
    "dependency_metadata": {
      "total_upstream": 5,
      "total_downstream": 2
    }
  }
}
```

**Example:**
```bash
python unit_generator.py call_graph.json --output dataset.json
```

## Quick Start

### Standard CLI (recommended)

Use `test_pipeline.py` for the standard CLI interface (identical to Python/C/Go/JavaScript/Ruby parsers):

```bash
# Static analysis only (all units)
python test_pipeline.py /path/to/repo --output /tmp/output

# With reachability filtering
python test_pipeline.py /path/to/repo --output /tmp/output --processing-level reachable

# With CodeQL pre-filter + agentic classification
python test_pipeline.py /path/to/repo --output /tmp/output --llm --agentic --processing-level codeql

# Maximum cost savings: only exploitable units
python test_pipeline.py /path/to/repo --output /tmp/output --llm --agentic --processing-level exploitable

# With all options
python test_pipeline.py /path/to/repo \
    --output /tmp/output \
    --skip-tests \
    --depth 3 \
    --name my_dataset \
    --processing-level reachable
```

Output files (in `--output` directory):
- `scan_results.json` - File list
- `analyzer_output.json` - Stage 2 verification index
- `dataset.json` - Final units
- `pipeline_results.json` - Summary of all stages

### LLM Enhancement and Filtering Stages

When using `test_pipeline.py` with `--llm` and/or `--processing-level`, the pipeline adds:

- **Stage 3.5: Reachability Filter** (`--processing-level reachable|codeql|exploitable`) - Filter to units reachable from entry points
- **Stage 3.6-3.7: CodeQL Analysis + Filter** (`--processing-level codeql|exploitable`) - Run CodeQL security queries
- **Stage 4: Context Enhancer** (`--llm`) - LLM-based context enhancement (single-shot or `--agentic`)
- **Stage 4.5: Exploitable Filter** (`--processing-level exploitable --llm --agentic`) - Keep only exploitable units

## Unit Types

| Type | Description |
|------|-------------|
| `function` | Top-level standalone function |
| `method` | Class instance method |
| `static_method` | Static class method |
| `constructor` | `__construct` method |
| `magic_method` | `__call`, `__get`, `__set`, `__toString`, etc. |
| `route_handler` | Controller actions |
| `private_function` | Top-level functions starting with `_` |
| `private_method` | Class methods starting with `_` |
| `test` | Test functions |

## Enhanced Code Assembly

Units include not just the primary code, but also relevant dependencies:

```php
// Primary method
public function processInput($data) {
    $validated = $this->validate($data);
    return $this->transform($validated);
}

// ========== File Boundary ==========

// Upstream dependency
public function validate($data) {
    ...
}

// ========== File Boundary ==========

// Another upstream dependency
public function transform($data) {
    ...
}
```

## Test Results

The parser has been validated against the WordPress/WordPress repository:

| Metric | Value |
|--------|-------|
| PHP files scanned | 1,842 |
| Total functions extracted | 12,185 |
| Total units generated | 12,177 |
| Enhanced units | 678 |
| Standalone functions | 4,304 |
| Methods | 4,665 |
| Static methods | 1,502 |
| Constructors | 385 |
| Route handlers | 617 |
| Call graph edges | 1,397 |
| Schema validation | PASSED |

## Files

```
parsers/php/
├── test_pipeline.py         # Standard CLI (use this - identical to Python/C/Go/JS/Ruby)
├── repository_scanner.py    # Stage 1: Find files
├── function_extractor.py    # Stage 2: Extract code
├── call_graph_builder.py    # Stage 3: Build relationships
├── unit_generator.py        # Stage 4: Create units
├── PARSER_PIPELINE.md       # This file (human documentation)
└── PARSER_UPGRADE_PLAN.md   # Technical reference for Claude
```

## Related Documentation

- `datasets/DATASET_FORMAT.md` - Complete dataset schema
- `datasets/php/` - Baseline PHP dataset (WordPress)
- `CURRENT_IMPLEMENTATION.md` - Project overview
