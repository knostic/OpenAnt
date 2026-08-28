# C/C++ Parser Pipeline

A tree-sitter-based parser for extracting functions, building call graphs, and generating OpenAnt dataset format from C/C++ codebases.

## Architecture

The parser follows the same 4-stage pipeline as the Python parser:

```
Stage 1: RepositoryScanner  →  Find .c/.h/.cpp/.hpp files
Stage 2: FunctionExtractor  →  Extract functions via tree-sitter
Stage 3: CallGraphBuilder   →  Build bidirectional call graph
Stage 4: UnitGenerator      →  Generate dataset.json + analyzer_output.json
```

## Dependencies

```bash
pip install tree-sitter tree-sitter-c tree-sitter-cpp
```

## Quick Start

```bash
# Basic run (all units)
python parsers/c/test_pipeline.py /path/to/repo --output datasets/myrepo

# With reachability filtering (recommended)
python parsers/c/test_pipeline.py /path/to/repo --output datasets/myrepo --processing-level reachable --skip-tests

# With CodeQL pre-filter
python parsers/c/test_pipeline.py /path/to/repo --output datasets/myrepo --processing-level codeql --skip-tests

# With LLM enhancement
python parsers/c/test_pipeline.py /path/to/repo --output datasets/myrepo --processing-level reachable --llm --agentic
```

## Processing Levels

| Level | Filter | Description |
|-------|--------|-------------|
| `all` | None | Process all units (no filtering) |
| `reachable` | Entry point reachability | Filter to units reachable from entry points |
| `codeql` | Reachable + CodeQL | Add CodeQL static analysis pre-filter |
| `exploitable` | Reachable + CodeQL + LLM | Maximum cost savings with LLM classification |

## Stage Details

### Stage 1: Repository Scanner (`repository_scanner.py`)

Scans for source files with extensions: `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.cxx`, `.hxx`, `.hh`

**Excluded directories:** `.git`, `build`, `CMakeFiles`, `third_party`, `external`, `vendor`, `test`, `tests`, `fuzz`, `doc`, `docs`, `demos`, `examples`, hidden directories (`.`), underscore directories (`_`)

**`--skip-tests` flag:** Filters files in `test/`, `tests/`, `fuzz/`, or matching `*_test.c`, `*_test.cpp`, `test_*.c`

### Stage 2: Function Extractor (`function_extractor.py`)

Uses tree-sitter to parse C/C++ source and extract:
- Function definitions (name, parameters, return type, body)
- Static/exported status
- Include directives (for call resolution)
- Macro definitions (for alias tracking)
- Function prototypes in headers (for call resolution)

**Function ID format:** `relative/path.c:function_name` (e.g., `ssl/ssl_lib.c:SSL_new`)

**Unit type classification:**

| Type | Detection |
|------|-----------|
| `main` | name == `main` |
| `callback` | registered via `_set_*_callback` / `_set_*_func` |
| `cli_handler` | in `apps/` directory, processes `argc`/`argv` |
| `constructor` | C++ constructor or `__attribute__((constructor))` |
| `destructor` | C++ destructor or `__attribute__((destructor))` |
| `method` | C++ class method |
| `static_function` | has `static` keyword |
| `function` | default |

### Stage 3: Call Graph Builder (`call_graph_builder.py`)

Walks function bodies for `call_expression` nodes and resolves calls:

1. **Same-file functions** - exact name match in same `.c` file
2. **Header-declared functions** - match against included `.h` files
3. **Macro-aliased calls** - e.g., `OPENSSL_malloc` -> `CRYPTO_malloc`
4. **Unique name match** - single function with that name in repo
5. **Unresolved** - left unresolved (stdlib, external)

Standard C library functions are filtered out (malloc, printf, memcpy, etc.).

### Stage 4: Unit Generator (`unit_generator.py`)

Generates `dataset.json` and `analyzer_output.json` with identical schema to Python/Go parsers.

**File boundary marker:** `// ========== File Boundary ==========` (C-style comment)

## Output Files

| File | Description |
|------|-------------|
| `scan_results.json` | File listing from scanner |
| `dataset.json` | OpenAnt dataset format (input to experiment.py) |
| `analyzer_output.json` | Function metadata with camelCase fields |
| `pipeline_results.json` | Pipeline execution summary |

## Design Decisions

### Why tree-sitter over libclang?

- **No build environment needed** - libclang requires `compile_commands.json` (running `./Configure` + build)
- **Sees both `#ifdef` branches** - better for security analysis
- **Error-tolerant** - produces a tree even for files with unresolved includes
- **Fast** - tree-sitter is written in C internally
- **No compiled binary needed** - just `pip install`

### Limitations

- Function-pointer dispatch through STATIC containers resolves as of #298 (a
  braced initialiser of function references — ops struct designated
  initialisers, function-pointer arrays, struct-array command tables — plus a
  subscript or member call through the container name records edges to every
  function the initialisers reference; over-seed is the safe direction).
  REMAINING unmitigated on a default scan: dispatch through pointers assigned
  at RUNTIME (indirect calls via variables holding function addresses with no
  static initialiser table), which the opt-in `--llm-reachability` stage
  (off by default; reads the first 1,500 bytes per unit) only partially
  compensates for.
- Cannot resolve complex macro expansions (tree-sitter sees the macro call, not the expansion)
- Does not track struct field access patterns
- C++ template instantiation is not tracked
