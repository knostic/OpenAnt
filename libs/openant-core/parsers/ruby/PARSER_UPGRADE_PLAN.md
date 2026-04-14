# Ruby Parser Technical Reference

**Purpose:** This document is for Claude to read after context compaction to understand the Ruby parser implementation.

## Quick Context

This is the Ruby code parser for OpenAnt (a SAST tool). It mirrors the C parser's tree-sitter approach and the Python parser's pipeline structure.

**Goal:** Parse Ruby repositories into self-contained analysis units for vulnerability detection.

## Architecture

```
test_pipeline.py (orchestrator)
    ├── repository_scanner.py   → Finds all .rb/.rake files
    ├── function_extractor.py   → Extracts functions via tree-sitter
    ├── call_graph_builder.py   → Builds call relationships via tree-sitter
    └── unit_generator.py       → Creates final dataset
```

## Key Implementation Details

### 1. Repository Scanner (`repository_scanner.py`)

**Class:** `RepositoryScanner`

**Key method:** `scan()` → Returns dict with `files` list

**Extensions:** `.rb`, `.rake`

**Excludes:** `.git`, `vendor`, `.bundle`, `tmp`, `log`, `coverage`, `build`, `dist`, `pkg`, `node_modules`, `.cache`, `doc`, `docs`

### 2. Function Extractor (`function_extractor.py`)

**Class:** `FunctionExtractor`

**Tree-sitter setup:**
```python
import tree_sitter_ruby as ts_ruby
from tree_sitter import Language, Parser
RUBY_LANGUAGE = Language(ts_ruby.language())
```

**Node types handled:**
- `method` → instance methods
- `singleton_method` → `def self.method_name`
- `class` → class definitions
- `module` → module definitions
- `call` → for import extraction (`require`, `include`, etc.)

**Stack-based traversal:** `(node, class_name, module_name)` tuple tracking

**Function ID format:** `relative/path/file.rb:ClassName.method_name` or `file.rb:method_name`

**Unit types assigned:**
- `initialize` → `constructor`
- `def self.foo` → `singleton_method`
- Inside class → `method` (or `route_handler` if controller, `callback` if `before_/after_/around_`)
- Inside module only → `module_method`
- Top-level → `function`

### 3. Call Graph Builder (`call_graph_builder.py`)

**Class:** `CallGraphBuilder`

**Key data structures:**
```python
self.call_graph = {}           # func_id → [called_func_ids]
self.reverse_call_graph = {}   # func_id → [caller_func_ids]
self.functions_by_name = {}    # simple_name → [func_ids]
self.functions_by_file = {}    # file_path → [func_ids]
self.methods_by_class = {}     # "file:ClassName" → [method_ids]
```

**Call resolution order:**
1. Same-class methods (implicit self)
2. Same-file functions
3. Require-resolved files
4. Unique name match across files

**Skips:** ~80 Ruby builtins (`puts`, `print`, `each`, `map`, `raise`, `require`, `attr_accessor`, `freeze`, `dup`, `to_s`, `nil?`, etc.)

### 4. Unit Generator (`unit_generator.py`)

**Class:** `UnitGenerator`

**Key method:** `assemble_enhanced_code()` - Combines primary code with dependencies

**File boundary marker:**
```python
FILE_BOUNDARY = '\n\n# ========== File Boundary ==========\n\n'
```

**`generate_analyzer_output()`** produces camelCase fields for compatibility:
```python
{
    'name': ..., 'unitType': ..., 'code': ..., 'filePath': ...,
    'startLine': ..., 'endLine': ..., 'isSingleton': ...,
    'isExported': True, 'moduleName': ..., 'parameters': ..., 'className': ...
}
```

## Test Repository

**Location:** `../test_repos/rails`

**Commit:** `f5255a4089cff69af0ce3b63fda751bdc6dd93cb`

**Test command (from project root):**
```bash
python parsers/ruby/test_pipeline.py ../test_repos/rails \
    --output /tmp/ruby_output --skip-tests --depth 3 --name rails
```

## Statistics from Baseline Run

**Parsing Results (rails/rails):**
```
- 1,491 Ruby files
- 13,914 total functions extracted
- 13,818 units generated
- 8,402 call graph edges
- 7,613 enhanced units
- Avg 1.25 upstream deps per unit
```

**Type breakdown:**
```
callback=70, constructor=866, function=67, method=8683,
module_method=3509, private_method=50, route_handler=103, singleton_method=566
```

## Common Issues & Solutions

### Issue: Methods inside modules without classes
**Solution:** Track `module_name` in the stack traversal and classify as `module_method`

### Issue: Implicit self calls not resolved
**Solution:** `_resolve_simple_call` checks same-class methods first when `caller_class` is set

### Issue: Tree-sitter parse fails
**Solution:** Falls back to regex-based call extraction

## Key Files to Read

When resuming work on the parser:

1. **This file** - Technical overview
2. `function_extractor.py` - Tree-sitter AST traversal
3. `call_graph_builder.py` - Call resolution logic
4. `unit_generator.py` - Unit assembly and analyzer output

## Future Improvements

1. **Block/proc tracking** - Track blocks passed to methods
2. **Mixin resolution** - Resolve `include`/`extend` module methods
3. **Metaprogramming detection** - `define_method`, `method_missing`
4. **Class inheritance** - Resolve parent class methods
