#!/usr/bin/env python3
"""
Call Graph Builder for PHP Codebases

Builds bidirectional call graphs from extracted function data:
- Forward graph: function -> functions it calls
- Reverse graph: function -> functions that call it

This is Phase 3 of the PHP parser - dependency resolution.

Usage:
    python call_graph_builder.py <extractor_output.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "functions": {...},
        "call_graph": {
            "file.php:func1": ["file.php:func2", "other.php:func3"],
            ...
        },
        "reverse_call_graph": {
            "file.php:func2": ["file.php:func1"],
            ...
        },
        "statistics": {
            "total_edges": 500,
            "avg_out_degree": 2.5,
            "max_out_degree": 15,
            "isolated_functions": 20
        }
    }
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import tree_sitter_php as ts_php
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


# Use the tagless grammar variant: function bodies are re-parsed WITHOUT their <?php tag (func_data
# ['code'] is tag-stripped), and language_php() treats tagless input as inert 'text' (0 call nodes).
PHP_LANGUAGE = Language(ts_php.language_php_only())

# PHP builtins and common functions to filter out
PHP_BUILTINS = {
    'echo', 'print', 'print_r', 'var_dump', 'var_export',
    'die', 'exit', 'isset', 'unset', 'empty',
    'array', 'list', 'count', 'sizeof', 'strlen', 'substr',
    'strpos', 'str_replace', 'trim', 'ltrim', 'rtrim',
    'strtolower', 'strtoupper', 'ucfirst', 'lcfirst', 'ucwords',
    'explode', 'implode', 'join',
    'array_push', 'array_pop', 'array_shift', 'array_unshift',
    'array_merge', 'array_keys', 'array_values', 'array_map',
    'array_filter', 'array_reduce', 'array_unique', 'array_reverse',
    'array_slice', 'array_splice', 'in_array', 'array_search',
    'array_key_exists', 'sort', 'asort', 'ksort', 'usort',
    'rsort', 'arsort', 'krsort',
    'is_array', 'is_string', 'is_int', 'is_integer', 'is_numeric',
    'is_bool', 'is_null', 'is_object', 'is_callable',
    'intval', 'floatval', 'strval', 'boolval', 'settype', 'gettype',
    'class_exists', 'method_exists', 'property_exists', 'function_exists',
    'get_class', 'get_parent_class', 'is_a', 'instanceof',
    'json_encode', 'json_decode', 'serialize', 'unserialize',
    'date', 'time', 'strtotime', 'mktime',
    'sprintf', 'printf', 'number_format',
    'abs', 'ceil', 'floor', 'round', 'min', 'max',
    'rand', 'mt_rand', 'array_rand',
    'file_get_contents', 'file_put_contents', 'file_exists',
    'is_file', 'is_dir', 'mkdir', 'rmdir', 'unlink', 'rename',
    'copy', 'move_uploaded_file', 'pathinfo', 'basename', 'dirname',
    'realpath', 'glob',
    'header', 'setcookie', 'session_start', 'session_destroy',
    'htmlspecialchars', 'htmlentities', 'strip_tags',
    'addslashes', 'stripslashes', 'nl2br',
    'urlencode', 'urldecode', 'rawurlencode', 'rawurldecode',
    'base64_encode', 'base64_decode',
    'md5', 'sha1', 'hash', 'password_hash', 'password_verify',
    'preg_match', 'preg_match_all', 'preg_replace', 'preg_split',
    'trigger_error', 'throw',
    'compact', 'extract', 'defined', 'define', 'constant',
    'array_walk', 'array_combine', 'array_flip', 'array_fill',
    'array_chunk', 'array_column', 'array_pad',
    'array_intersect', 'array_diff', 'range',
    'call_user_func', 'call_user_func_array',
}

# Higher-order builtins whose callback argument is a real call edge. Maps builtin name -> the 0-based
# position of the callback argument. The outer builtin call is still filtered (it is in PHP_BUILTINS);
# we additionally resolve the callback it dispatches to.
CALLBACK_BUILTINS = {
    'call_user_func': 0, 'call_user_func_array': 0,
    'array_map': 0, 'array_filter': 1, 'array_walk': 1, 'array_reduce': 1,
    'usort': 1, 'uasort': 1, 'uksort': 1, 'preg_replace_callback': 1,
}

# PHP keywords to skip in regex fallback
PHP_KEYWORDS = {
    'if', 'else', 'elseif', 'while', 'for', 'foreach',
    'switch', 'case', 'break', 'continue', 'return',
    'try', 'catch', 'finally', 'throw', 'new',
    'class', 'function', 'interface', 'trait',
    'namespace', 'use', 'require', 'require_once',
    'include', 'include_once', 'echo', 'print',
}


class CallGraphBuilder:
    """
    Build bidirectional call graphs from extracted PHP function data.

    This is Stage 3 of the PHP parser pipeline.
    """

    def __init__(self, extractor_output: Dict, options: Optional[Dict] = None):
        options = options or {}

        self.functions = extractor_output.get('functions', {})
        self.classes = extractor_output.get('classes', {})
        self.imports = extractor_output.get('imports', {})
        self.repo_path = extractor_output.get('repository', '')

        self.max_depth = options.get('max_depth', 3)

        # Call graphs
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}

        # Indexes for faster lookup
        self.functions_by_name: Dict[str, List[str]] = {}
        self.functions_by_file: Dict[str, List[str]] = {}
        self.methods_by_class: Dict[str, List[str]] = {}
        # class_key -> list of trait names the class composes via in-class `use`.
        self.traits_by_class: Dict[str, List[str]] = {}

        self._build_indexes()

        # Parser for re-parsing function bodies
        self.php_parser = Parser(PHP_LANGUAGE)

    def _build_indexes(self) -> None:
        """Build lookup indexes for faster resolution."""
        for func_id, func_data in self.functions.items():
            name = func_data.get('name', '')
            if name:
                if name not in self.functions_by_name:
                    self.functions_by_name[name] = []
                self.functions_by_name[name].append(func_id)

            file_path = func_data.get('file_path', '')
            if file_path:
                if file_path not in self.functions_by_file:
                    self.functions_by_file[file_path] = []
                self.functions_by_file[file_path].append(func_id)

            class_name = func_data.get('class_name')
            if class_name:
                class_key = f"{file_path}:{class_name}"
                if class_key not in self.methods_by_class:
                    self.methods_by_class[class_key] = []
                self.methods_by_class[class_key].append(func_id)

        # Index each class's composed traits (in-class `use TraitName;`) so a
        # $this->/self:: call can fall back to a method pulled in from a trait.
        for class_key, class_data in self.classes.items():
            traits = class_data.get('traits')
            if traits:
                self.traits_by_class[class_key] = list(traits)

    def _is_builtin(self, name: str) -> bool:
        """Check if name is a PHP builtin or common function."""
        return name.lower() in PHP_BUILTINS  # PHP function names are case-insensitive

    def _extract_calls_from_code(self, code: str, caller_id: str) -> Set[str]:
        """Extract function call references from code using tree-sitter."""
        calls = set()
        caller_file = caller_id.split(':')[0]
        caller_func = self.functions.get(caller_id, {})
        caller_class = caller_func.get('class_name')
        caller_namespace = caller_func.get('namespace_name')

        # The extractor stores each function/method body as a raw PHP fragment
        # WITHOUT a leading "<?php" open tag. tree-sitter-php treats untagged
        # input as inline HTML 'text' and yields no call nodes, so prepend an
        # open tag before re-parsing. All node byte offsets used below are
        # relative to this tagged buffer, so resolution stays consistent.
        if not code.lstrip().startswith('<?'):
            code = '<?php ' + code
        code_bytes = code.encode('utf-8', errors='replace')
        try:
            tree = self.php_parser.parse(code_bytes)
        except Exception:
            return self._extract_calls_regex(code, caller_id)

        root = tree.root_node
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type in ('function_call_expression', 'member_call_expression',
                             'scoped_call_expression', 'object_creation_expression'):
                resolved = self._resolve_call_node(node, code_bytes, caller_file,
                                                   caller_class, caller_namespace, root)
                if resolved:
                    calls.add(resolved)
            stack.extend(reversed(node.children))

        return calls

    def _resolve_call_node(self, node, source: bytes, caller_file: str,
                           caller_class: Optional[str],
                           caller_namespace: Optional[str] = None,
                           root=None) -> Optional[str]:
        """Resolve a tree-sitter call node to a function ID."""
        if node.type == 'function_call_expression':
            return self._resolve_function_call(node, source, caller_file, caller_class,
                                               caller_namespace, root)
        elif node.type == 'member_call_expression':
            return self._resolve_member_call(node, source, caller_file, caller_class)
        elif node.type == 'scoped_call_expression':
            return self._resolve_scoped_call(node, source, caller_file, caller_class)
        elif node.type == 'object_creation_expression':
            return self._resolve_new(node, source, caller_file, caller_class)
        return None

    def _resolve_function_call(self, node, source: bytes, caller_file: str,
                                caller_class: Optional[str],
                                caller_namespace: Optional[str] = None,
                                root=None) -> Optional[str]:
        """Resolve a simple function call like func()."""
        func_name = None

        for child in node.children:
            if child.type in ('name', 'identifier'):
                func_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                break
            elif child.type == 'qualified_name':
                func_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                # Use just the last segment for resolution
                if '\\' in func_name:
                    func_name = func_name.rsplit('\\', 1)[-1]
                break
            elif child.type == 'variable_name':
                # Variable-function call like $f(). Follow a single
                # string-literal binding ($f = 'helper';) to recover the name.
                var_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                func_name = self._resolve_variable_function(var_name, root, source)
                break

        if not func_name:
            return None

        if self._is_builtin(func_name):
            # Higher-order builtins (call_user_func, array_map, ...) drop the OUTER call, but the
            # callback they dispatch to is a real edge -- resolve it instead of returning None.
            cb_idx = CALLBACK_BUILTINS.get(func_name.lower())
            if cb_idx is not None:
                return self._resolve_callback_arg(node, source, caller_file, caller_class, cb_idx)
            return None

        return self._resolve_simple_call(func_name, caller_file, caller_class, caller_namespace)

    def _resolve_callback_arg(self, node, source: bytes, caller_file: str,
                              caller_class: Optional[str], idx: int) -> Optional[str]:
        """Resolve the callback argument at position `idx` of a higher-order builtin call.

        Only string-literal callbacks have a static target: 'fn', 'Class::method', or the array form
        ['Class', 'method']. Variable/closure callbacks ($cb, fn() => ...) have no resolvable target.
        """
        args_node = next((c for c in node.children if c.type == 'arguments'), None)
        if args_node is None:
            return None
        arg_nodes = [c for c in args_node.children if c.type == 'argument']
        if idx >= len(arg_nodes) or not arg_nodes[idx].children:
            return None
        value = arg_nodes[idx].children[0]
        if value.type == 'string':
            name = source[value.start_byte:value.end_byte].decode('utf-8', errors='replace').strip('\'"')
            return self._resolve_callback_name(name, caller_file, caller_class)
        if value.type == 'array_creation_expression':
            # ['ClassName', 'method'] static callback (instance [$obj,'m'] needs a type we don't track).
            strings = []
            stack = [value]
            while stack:
                n = stack.pop()
                if n.type == 'string':
                    strings.append(source[n.start_byte:n.end_byte].decode('utf-8', errors='replace').strip('\'"'))
                stack.extend(reversed(n.children))
            if len(strings) >= 2:
                return self._resolve_class_call(strings[0], strings[1], caller_file)
        return None

    def _resolve_callback_name(self, name: str, caller_file: str,
                               caller_class: Optional[str]) -> Optional[str]:
        """Resolve a string callback: 'Class::method' (static) or a plain function name."""
        if '::' in name:
            cls, _, method = name.partition('::')
            return self._resolve_class_call(cls, method, caller_file)
        if self._is_builtin(name):
            return None
        return self._resolve_simple_call(name, caller_file, caller_class)

    def _resolve_new(self, node, source: bytes, caller_file: str,
                     caller_class: Optional[str]) -> Optional[str]:
        """Resolve `new ClassName(...)` to the class's __construct method, if one is defined."""
        class_name = None
        for child in node.children:
            if child.type in ('name', 'qualified_name'):
                class_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                if '\\' in class_name:
                    class_name = class_name.rsplit('\\', 1)[-1]
                break
        if not class_name:
            return None
        return self._resolve_class_call(class_name, '__construct', caller_file)

    def _resolve_variable_function(self, var_name: str, root,
                                   source: bytes) -> Optional[str]:
        """Follow a single string-literal binding for a $var() callee.

        Scans the enclosing function body for assignments to ``var_name``.
        Only a single, unambiguous string-literal binding
        (``$f = 'helper';``) is followed; if the variable is assigned more
        than once, or from a non-literal, resolution is declined for
        precision (no guessing).
        """
        if root is None:
            return None
        literal_names: Set[str] = set()
        non_literal = False

        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == 'assignment_expression':
                children = [c for c in n.children if c.type not in ('=',)]
                # Shape: <variable_name> = <rhs>
                if len(children) >= 2 and children[0].type == 'variable_name':
                    lhs = source[children[0].start_byte:children[0].end_byte].decode(
                        'utf-8', errors='replace')
                    if lhs == var_name:
                        rhs = children[1]
                        literal = self._string_literal_value(rhs, source)
                        if literal is not None:
                            literal_names.add(literal)
                        else:
                            non_literal = True
            stack.extend(n.children)

        # Single unambiguous string binding only.
        if non_literal or len(literal_names) != 1:
            return None
        return next(iter(literal_names))

    @staticmethod
    def _string_literal_value(node, source: bytes) -> Optional[str]:
        """Return the content of a string-literal node, else None."""
        if node.type != 'string':
            return None
        for child in node.children:
            if child.type == 'string_content':
                return source[child.start_byte:child.end_byte].decode(
                    'utf-8', errors='replace')
        # Empty string literal ('') has no string_content child.
        return ''

    def _resolve_member_call(self, node, source: bytes, caller_file: str,
                              caller_class: Optional[str]) -> Optional[str]:
        """Resolve a member call like $obj->method()."""
        method_name = None
        receiver = None

        for child in node.children:
            if child.type == 'name':
                method_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
            elif child.type in ('->', 'arguments'):
                continue
            elif child.type == 'variable_name':
                receiver = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')

        if not method_name:
            return None

        if self._is_builtin(method_name):
            return None

        # $this->method() - same class
        if receiver == '$this' and caller_class:
            return self._resolve_self_call(method_name, caller_file, caller_class)

        return None

    def _resolve_scoped_call(self, node, source: bytes, caller_file: str,
                              caller_class: Optional[str]) -> Optional[str]:
        """Resolve a scoped call like ClassName::method()."""
        method_name = None
        scope = None

        for child in node.children:
            if child.type == 'name' and scope is not None:
                method_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
            elif child.type == 'relative_scope' and scope is None:
                # self / static / parent are `relative_scope` nodes, not `name` -- without this branch
                # the scope was never captured and self::/static::/parent:: calls were silently dropped.
                scope = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
            elif child.type in ('name', 'qualified_name') and scope is None:
                scope = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                if '\\' in scope:
                    scope = scope.rsplit('\\', 1)[-1]
            elif child.type == '::':
                continue

        if not method_name or not scope:
            return None

        if self._is_builtin(method_name):
            return None

        # self::method() or static::method() - same class
        if scope in ('self', 'static') and caller_class:
            return self._resolve_self_call(method_name, caller_file, caller_class)

        # parent::method() - the method is inherited from the parent class,
        # which may be defined in a different file. Resolve via the
        # class->parent index, then a cross-file class-method lookup.
        if scope == 'parent' and caller_class:
            parent_class = self._resolve_parent_class(caller_file, caller_class)
            if parent_class:
                return self._resolve_class_call(parent_class, method_name, caller_file)
            return None

        # ClassName::method()
        return self._resolve_class_call(scope, method_name, caller_file)

    def _resolve_simple_call(self, func_name: str, caller_file: str,
                             caller_class: Optional[str],
                             caller_namespace: Optional[str] = None) -> Optional[str]:
        """Resolve a simple (unqualified) function call to a function ID."""
        # 1. Check same class first (implicit $this)
        if caller_class:
            result = self._resolve_self_call(func_name, caller_file, caller_class)
            if result:
                return result

        # 2. Check same file
        same_file_funcs = self.functions_by_file.get(caller_file, [])
        for func_id in same_file_funcs:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == func_name and not func_data.get('class_name'):
                return func_id

        # 3. Check use/require-resolved files
        file_imports = self.imports.get(caller_file, {})
        for import_name, import_type in file_imports.items():
            if import_type in ('require', 'require_once', 'include', 'include_once', 'use'):
                # Match the import by file name (anchored), not an unanchored `in` substring which
                # over-matched any path merely containing the import string.
                imp_base = import_name.replace('\\', '/').rsplit('/', 1)[-1]
                for file_path in self.functions_by_file:
                    if (file_path.endswith(f"{import_name}.php")
                            or file_path.endswith(f"/{imp_base}.php")
                            or file_path == f"{imp_base}.php"):
                        file_funcs = self.functions_by_file[file_path]
                        for func_id in file_funcs:
                            func_data = self.functions.get(func_id, {})
                            if func_data.get('name') == func_name:
                                return func_id

        # 4. Unique name match across files. An unqualified call resolves within
        #    the caller's own namespace; a function in a different namespace is not
        #    reachable this way, so a same-named function elsewhere must not leak an
        #    edge across the namespace boundary.
        candidates = self.functions_by_name.get(func_name, [])
        candidates = [c for c in candidates
                      if not self.functions.get(c, {}).get('class_name')
                      and self._namespace_compatible(
                          self.functions.get(c, {}).get('namespace_name'), caller_namespace)]
        if len(candidates) == 1:
            return candidates[0]

        return None

    @staticmethod
    def _namespace_compatible(candidate_ns: Optional[str],
                              caller_ns: Optional[str]) -> bool:
        """Whether an unqualified call from caller_ns may bind a function in
        candidate_ns. They must be the same namespace (treating None / '' / '\\'
        as the global namespace)."""
        def norm(ns):
            return (ns or '').strip('\\')
        return norm(candidate_ns) == norm(caller_ns)

    def _resolve_self_call(self, method_name: str, caller_file: str,
                           caller_class: str) -> Optional[str]:
        """Resolve a $this->method() or self::method() call within a class."""
        class_key = f"{caller_file}:{caller_class}"
        class_methods = self.methods_by_class.get(class_key, [])

        for func_id in class_methods:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == method_name:
                return func_id

        # Fall back to methods composed in via traits (`use TraitName;`). A trait
        # method is invoked exactly like an own method ($this->m()/self::m()), but
        # it lives under the trait's own class_key, so resolve it there. The trait
        # may be declared in a different file, hence the cross-file lookup.
        for trait_name in self.traits_by_class.get(class_key, []):
            resolved = self._resolve_class_call(trait_name, method_name, caller_file)
            if resolved:
                return resolved

        return None

    def _resolve_class_call(self, class_name: str, method_name: str,
                            caller_file: str) -> Optional[str]:
        """Resolve a ClassName::method() call."""
        # Check same file first
        class_key = f"{caller_file}:{class_name}"
        if class_key in self.methods_by_class:
            for func_id in self.methods_by_class[class_key]:
                func_data = self.functions.get(func_id, {})
                if func_data.get('name') == method_name:
                    return func_id

        # Check all files for the class
        for key, func_ids in self.methods_by_class.items():
            if key.endswith(f":{class_name}"):
                for func_id in func_ids:
                    func_data = self.functions.get(func_id, {})
                    if func_data.get('name') == method_name:
                        return func_id

        return None

    def _resolve_parent_class(self, caller_file: str,
                              caller_class: str) -> Optional[str]:
        """Return the parent (superclass) name of caller_class, if known.

        The class index records each class's ``superclass`` (the ``extends``
        target). The parent class may be defined in a different file, so a
        same-file lookup is tried first, then any file declaring the class.
        """
        # Same-file class declaration first (most precise).
        class_data = self.classes.get(f"{caller_file}:{caller_class}")
        if class_data and class_data.get('superclass'):
            return self._strip_namespace(class_data['superclass'])

        # Fall back to any class with this name across files.
        for key, data in self.classes.items():
            if key.endswith(f":{caller_class}") and data.get('superclass'):
                return self._strip_namespace(data['superclass'])

        return None

    @staticmethod
    def _strip_namespace(name: str) -> str:
        """Reduce a possibly namespace-qualified class name to its last segment."""
        if '\\' in name:
            return name.rsplit('\\', 1)[-1]
        return name

    def _extract_calls_regex(self, code: str, caller_id: str) -> Set[str]:
        """Fallback regex-based call extraction for unparseable code."""
        calls = set()
        caller_file = caller_id.split(':')[0]

        # Match function calls: name(
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[\(]'
        for match in re.finditer(pattern, code):
            func_name = match.group(1)
            # Skip PHP keywords
            if func_name in PHP_KEYWORDS:
                continue
            if not self._is_builtin(func_name):
                resolved = self._resolve_simple_call(func_name, caller_file, None)
                if resolved:
                    calls.add(resolved)

        return calls

    def build_call_graph(self) -> None:
        """Build the complete call graph for all functions."""
        for func_id, func_data in self.functions.items():
            code = func_data.get('code', '')
            if not code:
                self.call_graph[func_id] = []
                continue

            calls = self._extract_calls_from_code(code, func_id)

            # Filter to valid function IDs (must exist, not self-calls)
            valid_calls = [c for c in calls if c in self.functions and c != func_id]
            self.call_graph[func_id] = valid_calls

            # Build reverse graph
            for called_id in valid_calls:
                if called_id not in self.reverse_call_graph:
                    self.reverse_call_graph[called_id] = []
                if func_id not in self.reverse_call_graph[called_id]:
                    self.reverse_call_graph[called_id].append(func_id)

    def get_dependencies(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get all dependencies (callees) for a function up to max depth."""
        max_d = depth if depth is not None else self.max_depth
        dependencies = []
        visited = {func_id}
        queue = [(func_id, 0)]

        while queue:
            current_id, current_depth = queue.pop(0)

            if current_depth >= max_d:
                continue

            calls = self.call_graph.get(current_id, [])
            for called_id in calls:
                if called_id not in visited:
                    visited.add(called_id)
                    dependencies.append(called_id)
                    queue.append((called_id, current_depth + 1))

        return dependencies

    def get_callers(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get all callers for a function up to max depth."""
        max_d = depth if depth is not None else self.max_depth
        callers = []
        visited = {func_id}
        queue = [(func_id, 0)]

        while queue:
            current_id, current_depth = queue.pop(0)

            if current_depth >= max_d:
                continue

            caller_ids = self.reverse_call_graph.get(current_id, [])
            for caller_id in caller_ids:
                if caller_id not in visited:
                    visited.add(caller_id)
                    callers.append(caller_id)
                    queue.append((caller_id, current_depth + 1))

        return callers

    def get_statistics(self) -> Dict:
        """Calculate call graph statistics."""
        total_edges = sum(len(calls) for calls in self.call_graph.values())
        num_funcs = len(self.functions)

        out_degrees = [len(self.call_graph.get(f, [])) for f in self.functions]
        in_degrees = [len(self.reverse_call_graph.get(f, [])) for f in self.functions]

        isolated = sum(1 for f in self.functions
                       if len(self.call_graph.get(f, [])) == 0
                       and len(self.reverse_call_graph.get(f, [])) == 0)

        return {
            'total_functions': num_funcs,
            'total_edges': total_edges,
            'avg_out_degree': round(total_edges / num_funcs, 2) if num_funcs > 0 else 0,
            'avg_in_degree': round(total_edges / num_funcs, 2) if num_funcs > 0 else 0,
            'max_out_degree': max(out_degrees) if out_degrees else 0,
            'max_in_degree': max(in_degrees) if in_degrees else 0,
            'isolated_functions': isolated,
        }

    def export(self) -> Dict:
        """Export the call graph data."""
        return {
            'repository': self.repo_path,
            'functions': self.functions,
            'classes': self.classes,
            'imports': self.imports,
            'call_graph': self.call_graph,
            'reverse_call_graph': self.reverse_call_graph,
            'statistics': self.get_statistics(),
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Build call graphs from extracted PHP function data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python call_graph_builder.py functions.json
  python call_graph_builder.py functions.json --output call_graph.json
  python call_graph_builder.py functions.json --depth 5
        '''
    )

    parser.add_argument('input_file', help='Function extractor output JSON file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--depth', '-d', type=int, default=3,
                        help='Max dependency resolution depth (default: 3)')

    args = parser.parse_args()

    try:
        extractor_output = read_json(args.input_file)
        print(f"Processing {len(extractor_output.get('functions', {}))} functions...", file=sys.stderr)

        builder = CallGraphBuilder(extractor_output, {'max_depth': args.depth})
        builder.build_call_graph()

        result = builder.export()
        stats = result['statistics']

        print(f"Call graph built:", file=sys.stderr)
        print(f"  Total functions: {stats['total_functions']}", file=sys.stderr)
        print(f"  Total edges: {stats['total_edges']}", file=sys.stderr)
        print(f"  Avg out-degree: {stats['avg_out_degree']}", file=sys.stderr)
        print(f"  Max out-degree: {stats['max_out_degree']}", file=sys.stderr)
        print(f"  Isolated functions: {stats['isolated_functions']}", file=sys.stderr)

        output = json.dumps(result, indent=2)

        if args.output:
            with open_utf8(args.output, 'w') as f:
                f.write(output)
            print(f"Output written to: {args.output}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
