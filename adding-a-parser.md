# Adding a Parser to OpenAnt

This guide explains how to add support for a new programming language to OpenAnt's parsing pipeline.

## Overview

OpenAnt parsers transform source code repositories into **analysis units** — self-contained code snippets with dependency context that can be analyzed for vulnerabilities. Every parser follows the same 4-stage pipeline:

```
Repository → [1. Scanner] → [2. Extractor] → [3. Call Graph] → [4. Unit Generator] → Dataset
```

The output is a standardized `dataset.json` that downstream stages (analyzer, verifier, enhancer) consume. As long as your parser produces the correct output schema, you can implement it however you like.

## Quick Start Checklist

Adding a new language requires:

1. **Create parser directory**: `libs/openant-core/parsers/<language>/`
2. **Implement 4 stage modules** (see [Pipeline Stages](#the-4-stage-pipeline))
3. **Create pipeline orchestrator**: `test_pipeline.py`
4. **Register in adapter**: `libs/openant-core/core/parser_adapter.py`
5. **Update language detection**: Add file extensions to `detect_language()`
6. **Add to CLI whitelist**: `libs/openant-core/openant/cli.py` (required for `--language` flag)
7. **Add dependencies**: `requirements.txt` and `pyproject.toml` (for venv auto-install)
8. **Update CLI help**: `apps/openant-cli/cmd/parse.go` (optional, help text only)
9. **Update README**: Add language to "Supported languages" list

## The 4-Stage Pipeline

### Stage 1: Repository Scanner

**Purpose**: Enumerate all source files in the repository.

**Class**: `RepositoryScanner`

**Input**: Repository path + options (skip_tests, exclude_patterns)

**Output**: `scan_results.json`

```json
{
  "repository": "/path/to/repo",
  "scan_time": "2025-01-15T10:30:00",
  "files": [
    { "path": "src/main.rs", "size": 1234 },
    { "path": "src/lib.rs", "size": 5678 }
  ],
  "statistics": {
    "total_files": 150,
    "total_size_bytes": 500000,
    "directories_scanned": 25,
    "directories_excluded": 10
  }
}
```

**Key responsibilities**:
- Walk directory tree, respecting exclude patterns (`.git`, `vendor`, `node_modules`, etc.)
- Filter by file extension for your language
- Optionally skip test files when `skip_tests=True`

### Stage 2: Function Extractor

**Purpose**: Extract all functions, methods, and classes from source files using AST parsing.

**Class**: `FunctionExtractor`

**Input**: Repository path + scan results

**Output**: `functions.json` (intermediate, not written to disk in most implementations)

```json
{
  "repository": "/path/to/repo",
  "extraction_time": "2025-01-15T10:30:05",
  "functions": {
    "src/main.rs:main": {
      "name": "main",
      "qualified_name": "main",
      "file_path": "src/main.rs",
      "start_line": 10,
      "end_line": 25,
      "code": "fn main() {\n    ...\n}",
      "class_name": null,
      "module_name": null,
      "parameters": [],
      "unit_type": "function"
    },
    "src/lib.rs:Config.new": {
      "name": "new",
      "qualified_name": "Config.new",
      "file_path": "src/lib.rs",
      "start_line": 15,
      "end_line": 20,
      "code": "pub fn new() -> Self { ... }",
      "class_name": "Config",
      "module_name": null,
      "parameters": [],
      "unit_type": "constructor"
    }
  },
  "classes": { ... },
  "imports": { ... },
  "statistics": {
    "total_functions": 150,
    "total_classes": 20,
    "files_processed": 50,
    "files_with_errors": 2
  }
}
```

**Function ID format**: `<relative_file_path>:<qualified_name>`

Examples:
- `src/main.rs:main`
- `src/lib.rs:Config.new`
- `app/controllers/users_controller.rb:UsersController.create`

**Required fields per function**:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Simple function name |
| `qualified_name` | string | Class.method or just name if top-level |
| `file_path` | string | Relative path from repo root |
| `start_line` | int | 1-indexed line number |
| `end_line` | int | 1-indexed line number |
| `code` | string | Full source code of the function |
| `class_name` | string \| null | Containing class/struct name |
| `module_name` | string \| null | Containing module/namespace |
| `parameters` | string[] | Parameter names |
| `unit_type` | string | See unit types below |

**Unit types** (used for classification and filtering):
- `function` — standalone function
- `method` — instance method in a class
- `constructor` — `__init__`, `new`, `initialize`, etc.
- `route_handler` — HTTP endpoint handler
- `callback` — lifecycle hooks, event handlers
- `test` — test functions (filtered out when `skip_tests=True`)
- `singleton_method` — class/static methods

### Stage 3: Call Graph Builder

**Purpose**: Build bidirectional call graphs showing function dependencies.

**Class**: `CallGraphBuilder`

**Input**: Function extractor output

**Output**: `call_graph.json`

```json
{
  "repository": "/path/to/repo",
  "functions": { ... },
  "classes": { ... },
  "imports": { ... },
  "call_graph": {
    "src/main.rs:main": ["src/lib.rs:Config.new", "src/lib.rs:run"],
    "src/lib.rs:run": ["src/lib.rs:process"]
  },
  "reverse_call_graph": {
    "src/lib.rs:Config.new": ["src/main.rs:main"],
    "src/lib.rs:run": ["src/main.rs:main"],
    "src/lib.rs:process": ["src/lib.rs:run"]
  },
  "statistics": {
    "total_functions": 150,
    "total_edges": 500,
    "avg_out_degree": 3.33,
    "max_out_degree": 15,
    "isolated_functions": 20
  }
}
```

**Key responsibilities**:
- Parse function bodies to find call sites
- Resolve calls to function IDs (same file → imported files → unique name match)
- Filter out language builtins and standard library calls
- Build both forward (`call_graph`) and reverse (`reverse_call_graph`) mappings

### Stage 4: Unit Generator

**Purpose**: Create self-contained analysis units with dependency context.

**Class**: `UnitGenerator`

**Input**: Call graph output

**Output**: `dataset.json` + `analyzer_output.json`

This is the **critical output** — downstream stages depend on this exact schema.

#### `dataset.json` Schema

```json
{
  "name": "my-project",
  "repository": "/path/to/repo",
  "units": [
    {
      "id": "src/lib.rs:process",
      "unit_type": "function",
      "code": {
        "primary_code": "fn process() { ... }\n\n# ========== File Boundary ==========\n\nfn helper() { ... }",
        "primary_origin": {
          "file_path": "src/lib.rs",
          "start_line": 30,
          "end_line": 45,
          "function_name": "process",
          "class_name": null,
          "enhanced": true,
          "files_included": ["src/lib.rs", "src/helpers.rs"],
          "original_length": 250,
          "enhanced_length": 800
        },
        "dependencies": [],
        "dependency_metadata": {
          "depth": 3,
          "total_upstream": 2,
          "total_downstream": 1,
          "direct_calls": 2,
          "direct_callers": 1
        }
      },
      "ground_truth": {
        "status": "UNKNOWN",
        "vulnerability_types": [],
        "issues": [],
        "annotation_source": null,
        "annotation_key": null,
        "notes": null
      },
      "metadata": {
        "parameters": ["input"],
        "generator": "rust_unit_generator.py",
        "direct_calls": ["src/helpers.rs:validate", "src/helpers.rs:transform"],
        "direct_callers": ["src/lib.rs:run"]
      }
    }
  ],
  "statistics": {
    "total_units": 150,
    "by_type": { "function": 100, "method": 40, "constructor": 10 },
    "units_with_upstream": 120,
    "units_with_downstream": 80,
    "units_enhanced": 130,
    "avg_upstream": 2.5,
    "avg_downstream": 1.8
  },
  "metadata": {
    "generator": "rust_unit_generator.py",
    "generated_at": "2025-01-15T10:30:15",
    "dependency_depth": 3
  }
}
```

**Enhanced code assembly**: The `primary_code` field contains the function's code plus its dependencies, separated by file boundary markers:

```
fn main() {
    process();
}

# ========== File Boundary ==========

fn process() {
    // dependency code
}
```

Use your language's comment syntax for the boundary marker.

#### `analyzer_output.json` Schema

This file provides a function index used by the verifier for cross-referencing:

```json
{
  "repository": "/path/to/repo",
  "functions": {
    "src/lib.rs:process": {
      "name": "process",
      "unitType": "function",
      "code": "fn process() { ... }",
      "filePath": "src/lib.rs",
      "startLine": 30,
      "endLine": 45,
      "isExported": true,
      "parameters": ["input"],
      "className": null
    }
  },
  "call_graph": { ... },
  "reverse_call_graph": { ... }
}
```

Note: `analyzer_output.json` uses **camelCase** field names for historical reasons.

## Pipeline Orchestrator (`test_pipeline.py`)

Each parser has a `test_pipeline.py` that wires the 4 stages together and handles CLI arguments. This is the entry point called by `parser_adapter.py`.

**Required CLI interface**:

```bash
python test_pipeline.py <repo_path> \
    --output <dir> \
    --processing-level <all|reachable|codeql|exploitable> \
    --skip-tests \
    --name <dataset_name>
```

**Processing levels** (filtering modes):
- `all` — Include all functions
- `reachable` — Filter to functions reachable from entry points
- `codeql` — Filter to reachable + CodeQL-flagged functions
- `exploitable` — Filter to reachable + CodeQL + LLM-classified exploitable

The `reachable` filter uses `utilities/agentic_enhancer/entry_point_detector.py` and `reachability_analyzer.py`. See the Ruby parser's `apply_reachability_filter()` method for an example.

**Exit code**: Return 0 on success, non-zero on failure.

## Registering Your Parser

### 1. Update `parser_adapter.py`

Location: `libs/openant-core/core/parser_adapter.py`

Add your language to three places:

**a) `detect_language()` — file extension mapping**:

```python
def detect_language(repo_path: str) -> str:
    counts = {"python": 0, "javascript": 0, "go": 0, "c": 0, "ruby": 0, "php": 0, "rust": 0}  # Add here
    # ...
    elif suffix == ".rs":  # Add extension check
        counts["rust"] += 1
```

**b) `parse_repository()` — dispatch branch**:

```python
def parse_repository(...) -> ParseResult:
    # ...
    elif language == "rust":
        return _parse_rust(repo_path, output_dir, processing_level, skip_tests, name)
```

**c) Add `_parse_<language>()` function**:

```python
def _parse_rust(repo_path: str, output_dir: str, processing_level: str, 
                skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the Rust parser."""
    print("[Parser] Running Rust parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "rust" / "test_pipeline.py"

    cmd = [
        sys.executable, str(parser_script),
        repo_path,
        "--output", output_dir,
        "--processing-level", processing_level,
    ]

    if name:
        cmd.extend(["--name", name])
    if skip_tests:
        cmd.append("--skip-tests")

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,  # 30 min timeout
    )

    if result.returncode != 0:
        raise RuntimeError(f"Rust parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    units_count = 0
    if os.path.exists(dataset_path):
        with open(dataset_path) as f:
            data = json.load(f)
        units_count = len(data.get("units", []))

    print(f"  Rust parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="rust",
        processing_level=processing_level,
    )
```

### 2. Add to CLI Whitelist (required)

Location: `libs/openant-core/openant/cli.py`

The CLI validates the `--language` flag against a whitelist. Without this, users get:
```
error: argument --language/-l: invalid choice: 'rust'
```

Update the `choices` list in **two places** (for `scan` and `parse` commands):

```python
# Around line 465 (scan command)
scan_p.add_argument(
    "--language", "-l",
    choices=["auto", "python", "javascript", "go", "c", "ruby", "php", "rust"],  # Add here
    ...
)

# Around line 500 (parse command)  
parse_p.add_argument(
    "--language", "-l",
    choices=["auto", "python", "javascript", "go", "c", "ruby", "php", "rust"],  # Add here
    ...
)
```

### 3. Add Dependencies (required for venv)

When users run `openant init` or any command for the first time, OpenAnt creates a managed venv at `~/.openant/venv/` and installs dependencies from `pyproject.toml`. For your parser's dependencies to be included, add them to **both** files:

**a) `libs/openant-core/requirements.txt`**:

```
tree-sitter-rust>=0.21.0
```

**b) `libs/openant-core/pyproject.toml`**:

```toml
dependencies = [
    # ... existing deps ...
    "tree-sitter-rust>=0.21.0",
]
```

Without this, users will see `ModuleNotFoundError` when running the parser.

### 4. Update CLI help (optional)

Location: `apps/openant-cli/cmd/parse.go`

Update the `--language` flag description:

```go
parseCmd.Flags().StringVarP(&parseLanguage, "language", "l", "", 
    "Language: python, javascript, go, c, ruby, php, rust, auto")
```

### 5. Update README.md

Add your language to the "Supported languages" list.

## Recommended Approach: tree-sitter

For most languages, [tree-sitter](https://tree-sitter.github.io/tree-sitter/) is the easiest path. It provides fast, incremental parsing with pre-built grammars for 100+ languages.

**Why tree-sitter**:
- No external runtime needed (pure Python bindings)
- Consistent API across languages
- Handles syntax errors gracefully
- Pre-built grammars for most languages

**Dependencies**:

Add to both `libs/openant-core/requirements.txt` and `libs/openant-core/pyproject.toml`:

```
tree-sitter>=0.21.0
tree-sitter-<language>>=0.21.0  # e.g., tree-sitter-rust
```

See [Add Dependencies](#3-add-dependencies-required-for-venv) for details.

**Basic usage**:

```python
import tree_sitter_rust as ts_rust
from tree_sitter import Language, Parser

RUST_LANGUAGE = Language(ts_rust.language())
parser = Parser(RUST_LANGUAGE)

source = b"fn main() { println!(\"Hello\"); }"
tree = parser.parse(source)

# Walk the AST
def walk(node, depth=0):
    print("  " * depth + f"{node.type}: {source[node.start_byte:node.end_byte]}")
    for child in node.children:
        walk(child, depth + 1)

walk(tree.root_node)
```

**Alternative approaches**:

If tree-sitter doesn't have a grammar for your language, you can:
- Use the language's native AST parser (like Python's `ast` module)
- Use a subprocess to call an external parser (like the Go and JS parsers do)
- Write a regex-based fallback (less accurate, but works)

## Reference Implementation

The **Ruby parser** (`libs/openant-core/parsers/ruby/`) is the cleanest tree-sitter implementation to use as a template:

| File | Purpose |
|------|---------|
| `repository_scanner.py` | Stage 1: File enumeration |
| `function_extractor.py` | Stage 2: AST parsing with tree-sitter |
| `call_graph_builder.py` | Stage 3: Call resolution |
| `unit_generator.py` | Stage 4: Dataset generation |
| `test_pipeline.py` | Pipeline orchestrator |
| `__init__.py` | Empty (required for Python imports) |

Copy this directory, rename it, and adapt:
1. Change file extensions in `RepositoryScanner`
2. Update tree-sitter import and language in `FunctionExtractor`
3. Adjust call resolution patterns in `CallGraphBuilder` for your language's semantics
4. Update builtins list in `CallGraphBuilder.RUBY_BUILTINS`
5. Adjust unit type classification logic

## Testing Your Parser

### 1. Run on a test repository

```bash
cd libs/openant-core
python parsers/<language>/test_pipeline.py /path/to/test/repo --output /tmp/test-output
```

### 2. Verify outputs

Check that these files exist and have valid JSON:
- `/tmp/test-output/dataset.json`
- `/tmp/test-output/analyzer_output.json`
- `/tmp/test-output/scan_results.json`
- `/tmp/test-output/call_graph.json` (if your pipeline writes it)

### 3. Validate dataset schema

```python
import json

with open("/tmp/test-output/dataset.json") as f:
    dataset = json.load(f)

# Check required fields
assert "name" in dataset
assert "units" in dataset
assert len(dataset["units"]) > 0

for unit in dataset["units"]:
    assert "id" in unit
    assert "unit_type" in unit
    assert "code" in unit
    assert "primary_code" in unit["code"]
    assert "primary_origin" in unit["code"]
```

### 4. Test through the full pipeline

```bash
# From repo root
openant init /path/to/test/repo -l <language> --name test/repo
openant parse
openant analyze  # Requires ANTHROPIC_API_KEY
```

### 5. Compare with existing parsers

Parse the same polyglot repo with your parser and an existing one. The output structure should be identical — only the content differs.

## Dispatch resolution — the highest-leverage call-graph work

Once bare calls and typed-receiver methods resolve, the biggest remaining source of *missed edges* (silent false negatives — the dangerous direction, since the reachability filter prunes what the graph can't reach) is **dynamic/interface dispatch**: a call on a receiver whose concrete type isn't statically pinned. Treat this as ONE substrate, not a pile of per-call fixes:

1. **Build a conformer map** in your extractor: `interface/trait/protocol → [implementing types]`. This is per-language and unavoidable:
   - **Nominal** (Rust `impl Trait for T`, Swift `: Protocol`, PHP `implements`) → read the declared clause. Easiest.
   - **Structural** (Go interfaces) → no declaration; you must method-set-match (all types × all interfaces). This is most of the work and 0% shared — do not skip it.
   - **Duck-typed** (Ruby/Python) → "conformers" is barely definable; resolve by name + MRO, not a declared map.
2. **Consult it uniformly** at every member-call site whose receiver types to an interface/trait — for BOTH trait-object receivers (`&dyn T` / `any T`) AND generic trait-bounded receivers (`fn f<B: T>(x: &B)`). A generic-bound receiver types as the param letter; feed its *bound trait* into the same closure. (The Swift parser's `_conformer_closure` and the Rust parser's `trait_impls` + `_resolve_generic_bound_member` are the reference.)
3. **Reachability-safe over-approximation:** union to the conformer set (any is a real runtime target), but keep it BOUNDED by the declared interface — never fan out to every same-named method (that is the phantom-explosion failure mode).

**Traps a reviewer will catch (bake these into tests from day one):**
- **Multi-bound** `B: A + C` → dispatch to the conformer **intersection** (types implementing *all* bounds), not a union — else you fabricate edges to a single-bound type with a coincidentally same-named method.
- **Blanket impls** `impl<T: Foo> Bar for T` target the impl's OWN generic param — do NOT register the letter `T` as a concrete conformer, or it fabricates cross-file edges between every `T`-named blanket. And resolve a *bounded generic-param receiver via its bounds BEFORE any concrete-type lookup on the letter*, or such a pseudo-type hijacks every generic receiver named `T`/`B`.
- **Scope:** collect a function's generic bounds from its OWN signature only — a nested `fn inner<B: Other>` must not bleed its bound into the outer `B`.
- **Popular interface** with N implementors → N edges per call. Real dispatch, but watch graph size; the same cap you use for `dyn` applies.

A shared cross-parser *resolver* is tempting but leaky — it no-ops on a language whose conformer map is empty (structural/duck), giving a false sense of coverage. Share at most a dumb `transitive_closure(map)` helper and a cross-parser test contract; keep the map-building and dispatch policy local to each parser.

## Questions?

Open an issue on GitHub or check existing parser implementations for examples.
