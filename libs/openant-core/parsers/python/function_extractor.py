#!/usr/bin/env python3
"""
Function Extractor for Python Codebases

Extracts ALL functions and class methods from Python source files using AST.
This is Phase 2 of the Python parser - function inventory.

Usage:
    python function_extractor.py <repo_path> [--output <file>] [--scan-file <scan.json>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "extraction_time": "2025-12-30T...",
        "functions": {
            "file.py:function_name": {
                "name": "function_name",
                "qualified_name": "module.function_name",
                "file_path": "file.py",
                "start_line": 10,
                "end_line": 25,
                "code": "def function_name(...):\\n    ...",
                "class_name": null,
                "decorators": ["@decorator"],
                "is_async": false,
                "parameters": ["param1", "param2"],
                "docstring": "Function docstring...",
                "unit_type": "function"
            }
        },
        "classes": {
            "file.py:ClassName": {
                "name": "ClassName",
                "file_path": "file.py",
                "start_line": 5,
                "end_line": 50,
                "methods": ["method1", "method2"],
                "bases": ["BaseClass"],
                "decorators": []
            }
        },
        "imports": {
            "file.py": {
                "os": "os",
                "Path": "pathlib.Path",
                "json": "json"
            }
        },
        "statistics": {
            "total_functions": 150,
            "total_classes": 25,
            "total_methods": 100,
            "by_type": {...},
            "files_processed": 50,
            "files_with_errors": 2
        }
    }
"""

import ast
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from utilities.file_io import read_json, write_json, open_utf8


class FunctionExtractor:
    """
    Extract all functions and classes from Python source files using AST.

    This is Stage 2 of the Python parser pipeline. It parses each Python file
    and extracts:
    - Standalone functions (top-level def statements)
    - Class definitions and their methods
    - Module-level code (executable code outside functions/classes)

    The module-level extraction is CRITICAL for detecting vulnerabilities in:
    - Streamlit apps (code runs at module level)
    - Scripts with global initialization
    - Configuration files with dynamic evaluation

    Key features:
    - Uses Python's AST for reliable parsing
    - Extracts decorators, parameters, docstrings
    - Classifies functions by type (route_handler, constructor, etc.)
    - Creates synthetic __module__ units for module-level code

    Usage:
        extractor = FunctionExtractor('/path/to/repo')
        result = extractor.extract_all()  # Process all .py files
        # OR
        result = extractor.extract_from_scan(scan_result)  # Use scanner output

    Attributes:
        repo_path: Absolute path to the repository root
        functions: Dict mapping func_id to function metadata
        classes: Dict mapping class_id to class metadata
        imports: Dict mapping file_path to import statements
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.functions: Dict[str, Dict] = {}
        self.classes: Dict[str, Dict] = {}
        self.imports: Dict[str, Dict[str, str]] = {}

        # File cache
        self.file_cache: Dict[str, str] = {}

        # Statistics
        self.stats = {
            'total_functions': 0,
            'total_classes': 0,
            'total_methods': 0,
            'standalone_functions': 0,
            'module_level_units': 0,
            'async_functions': 0,
            'files_processed': 0,
            'files_with_errors': 0,
            'by_type': {},
        }

    def read_file(self, file_path: Path) -> str:
        """Read and cache file contents."""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                self.file_cache[path_str] = file_path.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                print(f"Warning: Cannot read {file_path}: {e}", file=sys.stderr)
                self.file_cache[path_str] = ""
        return self.file_cache[path_str]

    def get_source_segment(self, content: str, node: ast.AST) -> str:
        """Extract source code for an AST node."""
        lines = content.split('\n')

        # Get line range
        start_line = node.lineno - 1  # 0-indexed
        end_line = getattr(node, 'end_lineno', start_line + 1)

        # Include decorators if present
        if hasattr(node, 'decorator_list') and node.decorator_list:
            first_decorator_line = min(d.lineno for d in node.decorator_list) - 1
            start_line = min(start_line, first_decorator_line)

        # Extract lines
        source_lines = lines[start_line:end_line]
        return '\n'.join(source_lines)

    def extract_decorators(self, node: ast.AST) -> List[str]:
        """Extract decorator names from a function or class."""
        decorators = []
        if hasattr(node, 'decorator_list'):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name):
                    decorators.append(f"@{dec.id}")
                elif isinstance(dec, ast.Attribute):
                    decorators.append(f"@{self._get_attribute_string(dec)}")
                elif isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Name):
                        decorators.append(f"@{dec.func.id}(...)")
                    elif isinstance(dec.func, ast.Attribute):
                        decorators.append(f"@{self._get_attribute_string(dec.func)}(...)")
        return decorators

    def extract_parameters(self, node: ast.FunctionDef) -> List[str]:
        """Extract parameter names from a function definition."""
        params = []
        args = node.args

        # Positional args
        for arg in args.args:
            params.append(arg.arg)

        # *args
        if args.vararg:
            params.append(f"*{args.vararg.arg}")

        # Keyword-only args
        for arg in args.kwonlyargs:
            params.append(arg.arg)

        # **kwargs
        if args.kwarg:
            params.append(f"**{args.kwarg.arg}")

        return params

    def get_docstring(self, node: ast.AST) -> Optional[str]:
        """Extract docstring from a function or class."""
        return ast.get_docstring(node)

    def _path_has_segment(self, file_path: str, token: str) -> bool:
        """True if `token` equals a whole path segment (a directory name or the filename stem),
        case-insensitively -- used instead of a bare ``token in path`` substring test so that, for
        example, 'views' classifies ``app/views.py`` and ``app/views/x.py`` but NOT ``interviews/a.py``
        or ``app/previews/b.py``."""
        p = Path(file_path)
        try:
            p = p.relative_to(self.repo_path)
        except ValueError:
            pass
        segments = {s.lower() for s in p.with_suffix('').parts}
        return token.lower() in segments

    def classify_function(self, func_name: str, decorators: List[str],
                          class_name: Optional[str], file_path: str) -> str:
        """Classify a function by its type/purpose."""
        dec_str = ' '.join(decorators).lower()
        path_lower = file_path.lower()

        # Route handlers
        if '@app.route' in dec_str or '@router.' in dec_str or '@blueprint.' in dec_str:
            return 'route_handler'
        if '@get' in dec_str or '@post' in dec_str or '@put' in dec_str or '@delete' in dec_str:
            return 'route_handler'

        # Django views
        if self._path_has_segment(file_path, 'views') and class_name is None:
            return 'view_function'

        # Class methods
        if class_name:
            if func_name == '__init__':
                return 'constructor'
            if func_name.startswith('__') and func_name.endswith('__'):
                return 'dunder_method'
            # @property getter, @<name>.setter/.deleter, and @cached_property/
            # @functools.cached_property are all property accessors. Reuse the
            # single _property_role predicate so classification can't drift from
            # the qualified_name role-suffix logic (a literal '@property' match
            # silently mislabels @cached_property as a plain method).
            if self._property_role(decorators) is not None:
                return 'property'
            if '@staticmethod' in dec_str:
                return 'static_method'
            if '@classmethod' in dec_str:
                return 'class_method'
            return 'method'

        # Middleware/decorators
        if 'middleware' in func_name.lower() or self._path_has_segment(file_path, 'middleware'):
            return 'middleware'

        # Test functions. Match the file by PATH COMPONENT, not bare substring:
        # 'test' in path_lower wrongly flags e.g. latest.py / contest.py / fastest.py.
        # A real test file is one whose directory or filename is/starts-with 'test'
        # (pytest's discovery convention: test_*.py / *_test.py / a tests/ dir).
        path_parts = path_lower.replace('\\', '/').split('/')
        filename = path_parts[-1] if path_parts else ''
        is_test_path = (
            any(part == 'test' or part == 'tests' for part in path_parts[:-1])
            or filename.startswith('test_')
            or filename.endswith('_test.py')
            or filename == 'test.py'
        )
        if func_name.startswith('test_') or is_test_path:
            return 'test'

        # Utility functions
        if func_name.startswith('_') and not func_name.startswith('__'):
            return 'private_function'

        return 'function'

    def _get_attribute_string(self, node: ast.Attribute) -> str:
        """Get full attribute string (e.g., 'module.submodule.attr')."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return '.'.join(parts)

    def extract_imports(self, tree: ast.AST, file_path: str) -> Dict[str, str]:
        """Extract all imports from a file."""
        imports = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imports[name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                level = node.level or 0
                if level > 0:
                    # Relative import: reconstruct the absolute package anchor from the importing
                    # file's location so the dotted path resolves to a real module. file_path is
                    # repo-relative (e.g. 'pkg/sub/mod.py'); its package is the directory parts.
                    # level=1 -> the file's own package, level=2 -> the parent package, etc.
                    pkg_parts = list(Path(file_path).parts[:-1])
                    keep = max(0, len(pkg_parts) - (level - 1))
                    anchor = pkg_parts[:keep]
                    base_parts = anchor + ([module] if module else [])
                else:
                    base_parts = [module] if module else []
                for alias in node.names:
                    name = alias.asname or alias.name
                    full_path = '.'.join(base_parts + [alias.name]) if base_parts else alias.name
                    imports[name] = full_path

        return imports

    def _property_role(self, decorators: List[str]) -> Optional[str]:
        """Classify a property accessor from its decorators: getter | setter |
        deleter | None. Match on the decorator's final dotted segment (TOKEN),
        not a bare substring, so `@property`/`@cached_property`/
        `@functools.cached_property`/`@x.setter`/`@x.deleter` are recognized but
        a method whose decorator merely CONTAINS the text (e.g.
        `@some_property_validator`, `@app.property_route`) is NOT misclassified."""
        for d in decorators:
            leaf = d.lstrip('@').split('(')[0].rsplit('.', 1)[-1]
            if leaf == 'setter':
                return 'setter'
            if leaf == 'deleter':
                return 'deleter'
        for d in decorators:
            leaf = d.lstrip('@').split('(')[0].rsplit('.', 1)[-1]
            if leaf in ('property', 'cached_property'):
                return 'getter'
        return None

    def _store_function(self, func_id: str, func_data: Dict) -> str:
        """Insert a function unit, disambiguating any residual func_id collision.

        Property accessors are already disambiguated by ROLE upstream (in
        process_function, via the qualified_name), so they never collide here.
        The residual cases are TRUE same-qualified-name duplicates -- two nested
        defs of the same name in one scope, or a lambda sharing a name with a
        def. Keying solely on qualified_name would let the second overwrite the
        first (a recall loss), so disambiguate DETERMINISTICALLY by source line
        (`#L<line>`), never by emission order -- the canonical-unit choice must
        be stable across edits. The earlier-in-source unit (parsed first) keeps
        the clean id.
        """
        if func_id not in self.functions:
            self.functions[func_id] = func_data
            return func_id
        line = func_data.get('start_line', 0)
        unique_id = f"{func_id}#L{line}"
        n = 2
        while unique_id in self.functions:
            unique_id = f"{func_id}#L{line}.{n}"
            n += 1
        self.functions[unique_id] = func_data
        return unique_id

    def _count_function(self, func_data: Dict, *, is_method: bool) -> None:
        """Update statistics for a single emitted function/method unit."""
        self.stats['total_functions'] += 1
        if is_method:
            self.stats['total_methods'] += 1
        else:
            self.stats['standalone_functions'] += 1
        if func_data['is_async']:
            self.stats['async_functions'] += 1
        unit_type = func_data['unit_type']
        self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

    # Block-statement containers whose bodies may hold def/class nodes the
    # def/class-only recursion never reaches. Built defensively so Python
    # versions lacking TryStar (<3.11) / Match (<3.10) don't raise.
    _BLOCK_CONTAINERS = tuple(filter(None, (
        getattr(ast, _n, None) for _n in (
            'If', 'For', 'AsyncFor', 'While', 'With', 'AsyncWith',
            'Try', 'TryStar', 'Match',
        )
    )))

    @staticmethod
    def _block_bodies(stmt: ast.AST) -> List[list]:
        """Every statement-list body of a block container (if/try/for/.../match)."""
        bodies: List[list] = []
        for field in ('body', 'orelse', 'finalbody'):
            v = getattr(stmt, field, None)
            if isinstance(v, list):
                bodies.append(v)
        for handler in getattr(stmt, 'handlers', None) or []:      # except arms
            b = getattr(handler, 'body', None)
            if isinstance(b, list):
                bodies.append(b)
        for case in getattr(stmt, 'cases', None) or []:            # match arms
            b = getattr(case, 'body', None)
            if isinstance(b, list):
                bodies.append(b)
        return bodies

    def _descend_into_blocks(self, stmts: list, file_path: Path, content: str) -> None:
        """Find def/class nodes inside block statements at ANY depth and emit them.

        A `def`/`class` inside an `if`/`try`/`for`/`while`/`with`/`match` block is
        runtime-reachable (version guards, `try/except ImportError` fallbacks,
        CBV `if/else` dispatchers) but the def/class-only recursion never entered
        a block body, so it was dropped from both the inventory and the call
        graph. This descends ONLY into block-container nodes — direct
        `FunctionDef`/`ClassDef` children of a body are emitted by the caller, so
        there is no double-processing (the two node sets are disjoint). Surfaced
        defs reuse the existing keep-both (`#L<line>`) machinery.
        """
        for stmt in stmts:
            if not isinstance(stmt, self._BLOCK_CONTAINERS):
                continue
            for body in self._block_bodies(stmt):
                for child in body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._process_function_tree(child, file_path, content, class_name=None)
                    elif isinstance(child, ast.ClassDef):
                        self._process_class_tree(child, file_path, content, outer_qualifier=None)
                self._descend_into_blocks(body, file_path, content)

    def _process_function_tree(self, node: ast.AST, file_path: Path, content: str,
                               class_name: Optional[str] = None) -> None:
        """Register a function and recurse into its body.

        Handles defs nested inside a function body (which the top-level child
        iteration never reaches) and classes nested inside a function. Each
        nested def is emitted as its own unit; nested classes are delegated to
        process_class so their methods are extracted too.
        """
        func_id, func_data = self.process_function(node, str(file_path), content, class_name)
        self._store_function(func_id, func_data)
        self._count_function(func_data, is_method=class_name is not None)

        # Recurse into the body: a def nested inside this function's body is
        # never reached by the top-level / direct-method walks.
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # A def nested inside a function is a standalone (non-method)
                # function in its own right; do not attribute it to a class.
                self._process_function_tree(child, file_path, content, class_name=None)
            elif isinstance(child, ast.ClassDef):
                self._process_class_tree(child, file_path, content, outer_qualifier=None)
        # defs/classes wrapped in a block inside this function's body
        self._descend_into_blocks(node.body, file_path, content)

    def _process_class_tree(self, node: ast.ClassDef, file_path: Path, content: str,
                            outer_qualifier: Optional[str] = None) -> None:
        """Register a class, its methods, and any classes nested within it.

        `outer_qualifier` is the dotted prefix of any enclosing class
        (e.g. 'Outer' so an inner class method is keyed 'Outer.Inner.deep').
        """
        class_id, class_data, method_nodes = self.process_class(
            node, str(file_path), content, outer_qualifier=outer_qualifier
        )
        self.classes[class_id] = class_data
        self.stats['total_classes'] += 1

        qualified_class = f"{outer_qualifier}.{node.name}" if outer_qualifier else node.name

        for method_node, method_class_name in method_nodes:
            # Methods may themselves contain nested defs -- recurse.
            self._process_function_tree(method_node, file_path, content, class_name=method_class_name)

        # Recurse into nested classes so their methods are extracted.
        for item in node.body:
            if isinstance(item, ast.ClassDef):
                self._process_class_tree(item, file_path, content, outer_qualifier=qualified_class)
        # defs/classes wrapped in a block inside the class body (e.g. an
        # `if TYPE_CHECKING:` block declaring conditional members).
        self._descend_into_blocks(node.body, file_path, content)

    def extract_assigned_lambdas(self, tree: ast.AST, file_path: Path, content: str) -> None:
        """Emit a function unit for each module-level `name = lambda ...`.

        Only FunctionDef/AsyncFunctionDef/ClassDef are recognised as units, so a
        named lambda (a common handler / dispatch idiom) is invisible and calls
        to it cannot resolve. Capture module-level single-target name bindings to
        a lambda as functions.
        """
        relative_path = file_path.relative_to(self.repo_path).as_posix()
        for node in ast.iter_child_nodes(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Lambda):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id
                func_id = f"{relative_path}:{name}"
                params = [a.arg for a in node.value.args.args]
                if node.value.args.vararg:
                    params.append(f"*{node.value.args.vararg.arg}")
                for a in node.value.args.kwonlyargs:
                    params.append(a.arg)
                if node.value.args.kwarg:
                    params.append(f"**{node.value.args.kwarg.arg}")
                func_data = {
                    'name': name,
                    'qualified_name': name,
                    'file_path': relative_path,
                    'start_line': node.lineno,
                    'end_line': getattr(node, 'end_lineno', node.lineno),
                    'code': self.get_source_segment(content, node),
                    'class_name': None,
                    'decorators': [],
                    'is_async': False,
                    'parameters': params,
                    'docstring': None,
                    'unit_type': self.classify_function(name, [], None, relative_path),
                    'is_lambda': True,
                }
                self._store_function(func_id, func_data)
                self._count_function(func_data, is_method=False)

    def process_function(self, node: ast.FunctionDef, file_path: str,
                         content: str, class_name: Optional[str] = None) -> Dict:
        """Process a function definition and extract metadata."""
        func_name = node.name
        relative_path = Path(file_path).relative_to(self.repo_path).as_posix()

        # Extract metadata
        decorators = self.extract_decorators(node)

        # @property getter, @x.setter and @x.deleter accessors all share the
        # qualified name `Class.x`, which would collide into one func_id and let
        # the setter overwrite the getter. Disambiguate by ROLE in the
        # qualified_name (getter stays canonical `C.x`; setter -> `C.x.setter`,
        # deleter -> `C.x.deleter`). This keeps func_id == path:qualified_name --
        # the invariant call_graph_builder relies on to reconstruct call targets
        # -- and is order-independent (role is intrinsic, not emission position).
        property_role = self._property_role(decorators)
        qualified_name = f"{class_name}.{func_name}" if class_name else func_name
        if property_role in ('setter', 'deleter'):
            qualified_name = f"{qualified_name}.{property_role}"

        # Generate unique ID (after any role suffix)
        func_id = f"{relative_path}:{qualified_name}"
        parameters = self.extract_parameters(node)
        docstring = self.get_docstring(node)
        code = self.get_source_segment(content, node)
        is_async = isinstance(node, ast.AsyncFunctionDef)
        unit_type = self.classify_function(func_name, decorators, class_name, relative_path)

        # The captured `code` (get_source_segment) includes any decorator lines,
        # so start_line must point at the first decorator, not the `def` line.
        # Off-by-one for one decorator; off-by-N for stacked decorators.
        start_line = node.lineno
        if getattr(node, 'decorator_list', None):
            start_line = min(start_line, min(d.lineno for d in node.decorator_list))

        func_data = {
            'name': func_name,
            'qualified_name': qualified_name,
            'file_path': relative_path,
            'start_line': start_line,
            'end_line': getattr(node, 'end_lineno', node.lineno),
            'code': code,
            'class_name': class_name,
            'decorators': decorators,
            'is_async': is_async,
            'parameters': parameters,
            'docstring': docstring[:500] if docstring else None,  # Truncate long docstrings
            'unit_type': unit_type,
            'property_role': property_role,
        }

        return func_id, func_data

    def process_class(self, node: ast.ClassDef, file_path: str, content: str,
                      outer_qualifier: Optional[str] = None) -> Tuple[str, Dict, List[Tuple]]:
        """Process a class definition and extract metadata.

        `outer_qualifier` is the dotted name of any enclosing class, so a class
        nested inside another is keyed by its full path (e.g. 'Outer.Inner') and
        its methods become 'Outer.Inner.method'.
        """
        class_name = f"{outer_qualifier}.{node.name}" if outer_qualifier else node.name
        relative_path = Path(file_path).relative_to(self.repo_path).as_posix()
        class_id = f"{relative_path}:{class_name}"

        # Extract base classes
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(self._get_attribute_string(base))

        decorators = self.extract_decorators(node)

        # Collect methods
        methods = []
        method_funcs = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(item.name)
                method_funcs.append(item)

        class_data = {
            'name': class_name,
            'file_path': relative_path,
            'start_line': node.lineno,
            'end_line': getattr(node, 'end_lineno', node.lineno),
            'methods': methods,
            'bases': bases,
            'decorators': decorators,
            'docstring': self.get_docstring(node),
        }

        return class_id, class_data, [(m, class_name) for m in method_funcs]

    def extract_module_level_code(self, tree: ast.AST, content: str,
                                    file_path: Path) -> Optional[Tuple[str, Dict]]:
        """
        Extract module-level code that is not inside functions or classes.

        This is a CRITICAL function for vulnerability detection. Many Python
        applications (especially Streamlit, scripts, and CLI tools) have
        significant executable code at module level that would otherwise
        be missed by function-only extraction.

        Example of vulnerable module-level code this captures:
            # In a Streamlit app:
            user_input = st.text_input("Enter expression")
            result = eval(user_input)  # RCE vulnerability at module level!

        The function works by:
        1. Identifying which lines are covered by functions/classes
        2. Collecting all uncovered lines (module-level code)
        3. Filtering to only executable code (not just imports/comments)
        4. Creating a synthetic __module__ unit

        Args:
            tree: Parsed AST of the file
            content: Raw file content as string
            file_path: Path to the source file

        Returns:
            tuple: (func_id, func_data) where func_id is "file.py:__module__"
                   and func_data contains the extracted code and metadata.
                   Returns None if no significant module-level code found.

        Note:
            The unit_type for module-level code is 'module_level' and the
            function name is '__module__' (synthetic identifier).
        """
        lines = content.split('\n')
        total_lines = len(lines)

        # Track which lines are covered by functions/classes. Walk the WHOLE
        # tree (not just top-level children) so a def/class wrapped in a block
        # (if/try/for/with/match) is covered too — otherwise its body, now its
        # own unit, would also leak verbatim into this synthetic :__module__ text.
        covered_lines: Set[int] = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start_line = node.lineno
                end_line = getattr(node, 'end_lineno', start_line)

                # Include decorators
                if hasattr(node, 'decorator_list') and node.decorator_list:
                    first_decorator = min(d.lineno for d in node.decorator_list)
                    start_line = min(start_line, first_decorator)

                for line_num in range(start_line, end_line + 1):
                    covered_lines.add(line_num)

        # Collect uncovered lines (module-level code)
        module_level_lines = []
        for line_num in range(1, total_lines + 1):  # 1-indexed like AST
            if line_num not in covered_lines:
                module_level_lines.append((line_num, lines[line_num - 1]))

        # Filter out empty lines and pure comments at the start
        # but keep all code including imports
        significant_lines = []
        for line_num, line in module_level_lines:
            stripped = line.strip()
            # Keep all non-empty lines (imports, assignments, calls, etc.)
            if stripped and not stripped.startswith('#'):
                significant_lines.append((line_num, line))
            elif stripped.startswith('#') and significant_lines:
                # Keep comments that appear after code (inline documentation)
                significant_lines.append((line_num, line))

        # Skip if no significant module-level code
        if not significant_lines:
            return None

        # Check if there's actual executable code (not just imports)
        has_executable_code = False
        for _, line in significant_lines:
            stripped = line.strip()
            # Skip pure import lines
            if stripped.startswith('import ') or stripped.startswith('from '):
                continue
            # Skip docstrings
            if stripped.startswith('"""') or stripped.startswith("'''"):
                continue
            # Found executable code
            if stripped:
                has_executable_code = True
                break

        if not has_executable_code:
            return None

        # Build module-level code string
        # Include ALL module-level code for complete context
        module_code_lines = []
        for line_num, line in module_level_lines:
            module_code_lines.append(line)

        module_code = '\n'.join(module_code_lines)

        # Remove leading/trailing empty lines but preserve internal structure
        module_code = module_code.strip()

        if not module_code:
            return None

        relative_path = file_path.relative_to(self.repo_path).as_posix()
        func_id = f"{relative_path}:__module__"

        # Determine start and end lines
        start_line = significant_lines[0][0] if significant_lines else 1
        end_line = significant_lines[-1][0] if significant_lines else total_lines

        func_data = {
            'name': '__module__',
            'qualified_name': '__module__',
            'file_path': relative_path,
            'start_line': start_line,
            'end_line': end_line,
            'code': module_code,
            'class_name': None,
            'decorators': [],
            'is_async': False,
            'parameters': [],
            'docstring': None,
            'unit_type': 'module_level',
            'is_module_level': True,
        }

        return func_id, func_data

    def process_file(self, file_path: Path) -> None:
        """Process a single Python file."""
        content = self.read_file(file_path)
        if not content:
            self.stats['files_with_errors'] += 1
            return

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}", file=sys.stderr)
            self.stats['files_with_errors'] += 1
            return

        self.stats['files_processed'] += 1
        relative_path = file_path.relative_to(self.repo_path).as_posix()

        # Extract imports
        self.imports[relative_path] = self.extract_imports(tree, relative_path)

        # Process top-level functions and classes. The tree helpers recurse so
        # defs nested in function bodies and classes nested in classes/functions
        # are also extracted (not just the direct children).
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._process_function_tree(node, file_path, content, class_name=None)
            elif isinstance(node, ast.ClassDef):
                self._process_class_tree(node, file_path, content, outer_qualifier=None)

        # defs/classes wrapped in a top-level block (version guard, try/except
        # ImportError fallback, with-guarded handler, etc.).
        self._descend_into_blocks(tree.body, file_path, content)

        # Module-level lambdas bound to a name (handler = lambda ...).
        self.extract_assigned_lambdas(tree, file_path, content)

        # Extract module-level code
        module_result = self.extract_module_level_code(tree, content, file_path)
        if module_result:
            func_id, func_data = module_result
            self.functions[func_id] = func_data
            self.stats['total_functions'] += 1
            self.stats['module_level_units'] += 1
            self.stats['by_type']['module_level'] = self.stats['by_type'].get('module_level', 0) + 1

    def extract_from_scan(self, scan_result: Dict) -> Dict:
        """Extract functions from files listed in a scan result."""
        for file_info in scan_result.get('files', []):
            file_path = self.repo_path / file_info['path']
            self.process_file(file_path)

        return self.export()

    def extract_all(self, files: Optional[List[str]] = None) -> Dict:
        """Extract functions from all Python files or a specific list."""
        if files:
            for file_rel_path in files:
                file_path = self.repo_path / file_rel_path
                if file_path.exists():
                    self.process_file(file_path)
        else:
            # Scan all .py files
            for file_path in self.repo_path.rglob('*.py'):
                # Skip common excluded directories. Match whole path SEGMENTS (not a substring of the
                # full path) so e.g. 'venv' excludes a real venv/ dir but not 'myvenv/keep.py', and an
                # ancestor dir whose name contains a token cannot poison the whole scan. rglob yields
                # paths under repo_path, so relative_to never raises.
                excluded = {'__pycache__', '.git', 'venv', '.venv', 'node_modules'}
                if excluded & set(file_path.relative_to(self.repo_path).parts):
                    continue
                self.process_file(file_path)

        return self.export()

    def export(self) -> Dict:
        """Export extraction results."""
        return {
            'repository': str(self.repo_path),
            'extraction_time': datetime.now().isoformat(),
            'functions': self.functions,
            'classes': self.classes,
            'imports': self.imports,
            'statistics': self.stats,
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Extract all functions and classes from a Python repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python function_extractor.py /path/to/repo
  python function_extractor.py /path/to/repo --output functions.json
  python function_extractor.py /path/to/repo --scan-file scan_results.json
        '''
    )

    parser.add_argument('repo_path', help='Path to the repository')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--scan-file', help='Use file list from repository scanner output')

    args = parser.parse_args()

    try:
        extractor = FunctionExtractor(args.repo_path)

        if args.scan_file:
            scan_result = read_json(args.scan_file)
            result = extractor.extract_from_scan(scan_result)
        else:
            result = extractor.extract_all()

        output = json.dumps(result, indent=2)

        if args.output:
            with open_utf8(args.output, 'w') as f:
                f.write(output)
            print(f"Extraction complete. Results written to: {args.output}", file=sys.stderr)
            print(f"Total functions: {result['statistics']['total_functions']}", file=sys.stderr)
            print(f"  Standalone: {result['statistics']['standalone_functions']}", file=sys.stderr)
            print(f"  Methods: {result['statistics']['total_methods']}", file=sys.stderr)
            print(f"  Module-level: {result['statistics']['module_level_units']}", file=sys.stderr)
            print(f"  Async: {result['statistics']['async_functions']}", file=sys.stderr)
            print(f"Total classes: {result['statistics']['total_classes']}", file=sys.stderr)
            print(f"Files processed: {result['statistics']['files_processed']}", file=sys.stderr)
            if result['statistics']['files_with_errors'] > 0:
                print(f"Files with errors: {result['statistics']['files_with_errors']}", file=sys.stderr)
            print(f"By type:", file=sys.stderr)
            for unit_type, count in sorted(result['statistics']['by_type'].items()):
                print(f"  {unit_type}: {count}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
