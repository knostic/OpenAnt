# PHP Parser Technical Reference

**Purpose:** This document is for Claude to read after context compaction to understand the PHP parser implementation.

## Quick Context

This is the PHP code parser for OpenAnt (a SAST tool). It mirrors the Ruby/C parser's tree-sitter approach and the Python parser's pipeline structure.

**Goal:** Parse PHP repositories into self-contained analysis units for vulnerability detection.

## Architecture

```
test_pipeline.py (orchestrator)
    ├── repository_scanner.py   → Finds all .php files
    ├── function_extractor.py   → Extracts functions via tree-sitter
    ├── call_graph_builder.py   → Builds call relationships via tree-sitter
    └── unit_generator.py       → Creates final dataset
```

## Key Implementation Details

### 1. Repository Scanner (`repository_scanner.py`)

**Class:** `RepositoryScanner`

**Key method:** `scan()` → Returns dict with `files` list

**Extensions:** `.php`

**Excludes:** `.git`, `vendor`, `node_modules`, `build`, `dist`, `tmp`, `cache`, `storage`, `bootstrap/cache`, `public/build`

### 2. Function Extractor (`function_extractor.py`)

**Class:** `FunctionExtractor`

**Tree-sitter setup:**
```python
import tree_sitter_php as ts_php
from tree_sitter import Language, Parser
PHP_LANGUAGE = Language(ts_php.language_php())
```

**IMPORTANT:** PHP uses `language_php()` NOT `language()` — this is a tree-sitter-php API difference.

**Node types handled:**
- `function_definition` → top-level functions
- `method_declaration` → class methods (with `visibility_modifier`, `static_modifier`)
- `class_declaration` → class definitions (with `base_clause`, `class_interface_clause`)
- `interface_declaration` → interface definitions
- `trait_declaration` → trait definitions
- `namespace_definition` → namespace scoping
- `use_declaration` → imports

**Stack-based traversal:** `(node, class_name, namespace_name)` tuple tracking

**Function ID format:** `relative/path/file.php:ClassName.method_name` or `file.php:function_name`

**Unit types assigned:**
- `__construct` → `constructor`
- Magic methods (`__call`, `__get`, etc.) → `magic_method`
- Static methods → `static_method`
- Controller classes/paths → `route_handler`
- Inside class → `method` (or `private_method` if starts with `_`)
- Top-level → `function` (or `private_function` if starts with `_`)

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

**Call node types resolved:**
- `function_call_expression` → simple calls like `func()`
- `member_call_expression` → `$this->method()`, `$obj->method()`
- `scoped_call_expression` → `ClassName::method()`, `self::method()`, `static::method()`

**Call resolution order:**
1. Same-class methods (`$this->`, `self::`)
2. Same-file functions
3. Import-resolved files (`use`, `require`)
4. Unique name match across files

**Skips:** ~120 PHP builtins (`echo`, `print`, `array_*`, `str*`, `json_*`, `preg_*`, etc.)

### 4. Unit Generator (`unit_generator.py`)

**Class:** `UnitGenerator`

**Key method:** `assemble_enhanced_code()` - Combines primary code with dependencies

**File boundary marker:**
```python
FILE_BOUNDARY = '\n\n// ========== File Boundary ==========\n\n'
```

**`generate_analyzer_output()`** produces camelCase fields for compatibility:
```python
{
    'name': ..., 'unitType': ..., 'code': ..., 'filePath': ...,
    'startLine': ..., 'endLine': ..., 'visibility': ...,
    'isExported': True, 'namespace': ..., 'parameters': ..., 'className': ...
}
```

## Test Repository

**Location:** `../test_repos/WordPress`

**Commit:** `3f84a08d7ce1a59f22f9ddb151b3f4a06d7e5d1d`

**Test command (from project root):**
```bash
python parsers/php/test_pipeline.py ../test_repos/WordPress \
    --output /tmp/php_output --skip-tests --depth 3 --name WordPress
```

## Statistics from Baseline Run

**Parsing Results (WordPress/WordPress):**
```
- 1,842 PHP files
- 12,185 total functions extracted
- 12,177 units generated
- 1,397 call graph edges
- 678 enhanced units
- Avg 0.12 upstream deps per unit
```

**Type breakdown:**
```
constructor=385, function=4304, magic_method=152, method=4665,
private_function=388, private_method=162, route_handler=617,
static_method=1502, test=10
```

## Common Issues & Solutions

### Issue: tree-sitter-php uses `language_php()` not `language()`
**Solution:** Always use `Language(ts_php.language_php())` instead of `Language(ts_php.language())`

### Issue: Namespace-scoped functions
**Solution:** Track `namespace_name` in the stack traversal; use `\` separator for qualified names

### Issue: Tree-sitter parse fails
**Solution:** Falls back to regex-based call extraction

### Issue: Magic methods classified incorrectly
**Solution:** Explicit `PHP_MAGIC_METHODS` set checked before other classification rules

## Key Files to Read

When resuming work on the parser:

1. **This file** - Technical overview
2. `function_extractor.py` - Tree-sitter AST traversal
3. `call_graph_builder.py` - Call resolution logic
4. `unit_generator.py` - Unit assembly and analyzer output

## Future Improvements

1. **Trait method resolution** - Resolve `use TraitName` inside classes
2. **Type-hinted call resolution** - Use type hints to resolve `$obj->method()` calls
3. **Anonymous function tracking** - Track closures and arrow functions
4. **Autoloader detection** - Resolve class-to-file mappings via PSR-4/composer.json
