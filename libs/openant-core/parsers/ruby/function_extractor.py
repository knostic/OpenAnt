#!/usr/bin/env python3
"""
Function Extractor for Ruby Codebases

Extracts ALL functions and class methods from Ruby source files using tree-sitter.
This is Phase 2 of the Ruby parser - function inventory.

Usage:
    python function_extractor.py <repo_path> [--output <file>] [--scan-file <scan.json>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "extraction_time": "2025-12-30T...",
        "functions": {
            "file.rb:ClassName.method_name": {
                "name": "method_name",
                "qualified_name": "ClassName.method_name",
                "file_path": "file.rb",
                "start_line": 10,
                "end_line": 25,
                "code": "def method_name(...)\\n  ...\\nend",
                "class_name": "ClassName",
                "module_name": "ModuleName",
                "parameters": ["param1", "param2"],
                "is_singleton": false,
                "unit_type": "method"
            }
        },
        "classes": { ... },
        "imports": { ... },
        "statistics": { ... }
    }
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter_ruby as ts_ruby
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


RUBY_LANGUAGE = Language(ts_ruby.language())


class FunctionExtractor:
    """
    Extract all functions and classes from Ruby source files using tree-sitter.

    This is Stage 2 of the Ruby parser pipeline.
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.functions: Dict[str, Dict] = {}
        self.classes: Dict[str, Dict] = {}
        self.imports: Dict[str, Dict[str, str]] = {}

        self.parser = Parser(RUBY_LANGUAGE)

        self.file_cache: Dict[str, bytes] = {}

        self.stats = {
            'total_functions': 0,
            'total_classes': 0,
            'total_methods': 0,
            'standalone_functions': 0,
            'singleton_methods': 0,
            'files_processed': 0,
            'files_with_errors': 0,
            'by_type': {},
        }

    def read_file(self, file_path: Path) -> bytes:
        """Read and cache file contents as bytes (tree-sitter needs bytes)."""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                self.file_cache[path_str] = file_path.read_bytes()
            except Exception as e:
                print(f"Warning: Cannot read {file_path}: {e}", file=sys.stderr)
                self.file_cache[path_str] = b""
        return self.file_cache[path_str]

    def _node_text(self, node, source: bytes) -> str:
        """Extract text from a tree-sitter node."""
        return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def _get_method_name(self, node, source: bytes) -> Optional[str]:
        """Extract method name from a method or singleton_method node."""
        name_node = node.child_by_field_name('name')
        if name_node:
            return self._node_text(name_node, source)
        # Fallback: search for identifier child
        for child in node.children:
            if child.type == 'identifier':
                return self._node_text(child, source)
        return None

    def _get_parameters(self, node, source: bytes) -> List[str]:
        """Extract parameters from a method node."""
        params = []
        params_node = node.child_by_field_name('parameters')
        if params_node is None:
            # Look for method_parameters child
            for child in node.children:
                if child.type == 'method_parameters':
                    params_node = child
                    break

        if params_node is None:
            return params

        for child in params_node.children:
            if child.type in ('identifier', 'optional_parameter', 'splat_parameter',
                              'hash_splat_parameter', 'block_parameter',
                              'keyword_parameter', 'destructured_parameter'):
                param_text = self._node_text(child, source)
                params.append(param_text)

        return params

    def _classify_function(self, func_name: str, class_name: Optional[str],
                           module_name: Optional[str], is_singleton: bool,
                           file_path: str, visibility: str = 'public') -> str:
        """Classify a function by its type/purpose.

        ``visibility`` ('public' | 'private' | 'protected') is the declared
        Ruby method visibility threaded from the class body. Only PUBLIC
        controller methods are real route handlers; private/protected methods
        in a controller are filter callbacks / params helpers and must not be
        seeded as entry points.
        """
        path_lower = file_path.lower()

        # is_singleton must be checked BEFORE the initialize/constructor branch:
        # `def self.initialize` is a class-level singleton method, not the
        # instance constructor (Ruby's constructor is the instance `initialize`).
        if is_singleton:
            return 'singleton_method'

        if func_name == 'initialize':
            return 'constructor'

        # Non-public methods inside a class are helpers/callbacks, never
        # route handlers or callbacks-by-name, regardless of the enclosing
        # class. This must precede the controller branch so private params
        # helpers (user_params) and before_action target methods (set_user)
        # in *Controller classes are not mislabeled as route_handler.
        if class_name and visibility in ('private', 'protected'):
            return 'private_method' if visibility == 'private' else 'protected_method'

        # Callbacks
        if func_name.startswith(('before_', 'after_', 'around_')):
            return 'callback'

        # Controller actions (route handlers) — public methods only.
        if class_name and 'controller' in (class_name.lower() if class_name else ''):
            return 'route_handler'
        if 'controllers' in path_lower:
            if class_name:
                return 'route_handler'

        # Inside a class
        if class_name:
            if func_name.startswith('_'):
                return 'private_method'
            return 'method'

        # Inside a module only (no class)
        if module_name and not class_name:
            return 'module_method'

        # Test functions
        if func_name.startswith('test_') or 'test' in path_lower or 'spec' in path_lower:
            return 'test'

        # Top-level
        return 'function'

    # Sinatra / Padrino top-level route DSL verbs.
    _SINATRA_VERBS = frozenset({
        'get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'link', 'unlink',
    })

    @staticmethod
    def _literal_arg_text(arg_node, source: bytes) -> Optional[str]:
        """Return the literal value of a symbol or string argument node.

        Handles ``:foo`` (simple_symbol), ``:"foo"`` (delimited symbol),
        and ``"foo"``/``'foo'`` (string). Returns None for non-literals.
        """
        t = arg_node.type
        if t == 'simple_symbol':
            text = source[arg_node.start_byte:arg_node.end_byte].decode('utf-8', errors='replace')
            return text[1:] if text.startswith(':') else text
        if t in ('symbol', 'delimited_symbol'):
            for sc in arg_node.children:
                if sc.type in ('string_content', 'identifier', 'constant'):
                    return source[sc.start_byte:sc.end_byte].decode('utf-8', errors='replace')
            text = source[arg_node.start_byte:arg_node.end_byte].decode('utf-8', errors='replace')
            return text.lstrip(':').strip('"\'')
        if t == 'string':
            for sc in arg_node.children:
                if sc.type == 'string_content':
                    return source[sc.start_byte:sc.end_byte].decode('utf-8', errors='replace')
            return ''
        return None

    def _call_receiver_and_method(self, node, source: bytes):
        """For a 'call' node, return (method_name, [literal positional args]).

        method_name is the identifier of the call (e.g. 'define_method',
        'alias_method', 'get'); args are the literal symbol/string values in
        the argument_list, in order. Returns (None, []) if not a simple call.
        """
        method_name = None
        for child in node.children:
            if child.type == 'identifier':
                method_name = self._node_text(child, source)
                break
        if method_name is None:
            return None, []
        args = []
        for child in node.children:
            if child.type == 'argument_list':
                for arg in child.children:
                    if arg.type in ('simple_symbol', 'symbol', 'delimited_symbol', 'string'):
                        val = self._literal_arg_text(arg, source)
                        if val is not None:
                            args.append(val)
        return method_name, args

    def _has_block(self, node) -> bool:
        """True if the call node carries a do..end or { } block."""
        return any(c.type in ('do_block', 'block') for c in node.children)

    def _extract_imports(self, tree, source: bytes) -> Dict[str, str]:
        """Extract require/require_relative/include/extend/prepend from a file."""
        imports = {}
        stack = [tree.root_node]

        while stack:
            node = stack.pop()

            if node.type == 'call':
                # Check for require, require_relative, include, extend, prepend
                method_node = None
                for child in node.children:
                    if child.type == 'identifier':
                        method_node = child
                        break

                if method_node:
                    method_name = self._node_text(method_node, source)
                    if method_name in ('require', 'require_relative', 'include',
                                       'extend', 'prepend'):
                        # Extract the argument
                        arg_list = None
                        for child in node.children:
                            if child.type == 'argument_list':
                                arg_list = child
                                break

                        if arg_list:
                            for arg_child in arg_list.children:
                                if arg_child.type == 'string':
                                    # Extract string content
                                    for sc in arg_child.children:
                                        if sc.type == 'string_content':
                                            val = self._node_text(sc, source)
                                            imports[val] = method_name
                                            break
                                elif arg_child.type in ('constant', 'scope_resolution'):
                                    val = self._node_text(arg_child, source)
                                    imports[val] = method_name

            stack.extend(reversed(node.children))

        return imports

    def _body_node(self, node):
        """Return a node's body (`body` field, else a `body_statement` child)."""
        body_node = node.child_by_field_name('body')
        if body_node is None:
            for child in node.children:
                if child.type == 'body_statement':
                    body_node = child
                    break
        return body_node

    def _extract_functions_from_tree(self, tree, source: bytes, file_path: Path,
                                     relative_path: str) -> None:
        """Extract all method definitions from a parsed tree.

        Stack frame: ``(node, class_name, module_name, vis_state)`` where
        ``vis_state`` is a 1-element mutable list holding the current method
        visibility ('public'/'private'/'protected'). All direct children of a
        single class/module body SHARE one vis_state list, so a bare
        ``private``/``protected``/``public`` marker mutates the visibility seen
        by subsequent siblings popped from the same body (children are pushed in
        reverse so they pop in source order).
        """
        stack = [(tree.root_node, None, None, ['public'])]

        while stack:
            node, class_name, module_name, vis_state = stack.pop()

            if node.type == 'method':
                self._process_method_node(
                    node, source, relative_path, class_name, module_name,
                    is_singleton=False, visibility=vis_state[0],
                )
                # A nested `def` lives in the method's body -- keep traversing so
                # methods defined inside another method are not lost. Nested defs
                # inherit the enclosing class but default to public visibility.
                body_node = self._body_node(node)
                if body_node:
                    nested_vis = ['public']
                    for child in reversed(body_node.children):
                        stack.append((child, class_name, module_name, nested_vis))
                continue

            elif node.type == 'singleton_method':
                self._process_method_node(
                    node, source, relative_path, class_name, module_name,
                    is_singleton=True, visibility=vis_state[0],
                )
                body_node = self._body_node(node)
                if body_node:
                    nested_vis = ['public']
                    for child in reversed(body_node.children):
                        stack.append((child, class_name, module_name, nested_vis))
                continue

            elif node.type == 'alias':
                # `alias new old` keyword form.
                self._process_alias_node(
                    node, source, relative_path, class_name, module_name, vis_state[0],
                )

            elif node.type == 'call':
                # Metaprogramming / DSL calls: define_method, alias_method
                # inside a class, and top-level Sinatra route DSL. Non-matching
                # calls fall through to a normal child descent so nested defs are
                # still found.
                method_name, args = self._call_receiver_and_method(node, source)
                handled = False
                if method_name == 'define_method' and class_name and args:
                    self._emit_synthetic_method(
                        node, source, relative_path, class_name, module_name,
                        name=args[0], unit_type=None, visibility=vis_state[0],
                    )
                    handled = True
                elif method_name == 'alias_method' and class_name and args:
                    self._emit_synthetic_method(
                        node, source, relative_path, class_name, module_name,
                        name=args[0], unit_type=None, visibility=vis_state[0],
                    )
                    handled = True
                elif (class_name is None and module_name is None
                      and method_name in self._SINATRA_VERBS
                      and self._has_block(node) and args):
                    # Top-level `get '/path' do..end` Sinatra route.
                    self._emit_synthetic_method(
                        node, source, relative_path, class_name=None,
                        module_name=None, name=args[0], unit_type='route_handler',
                        visibility='public',
                    )
                    handled = True
                elif method_name in ('private', 'protected', 'public'):
                    # Arg-form visibility, e.g. `private :foo` — privatizes only
                    # the named symbol(s), NOT subsequent defs. Consume it here
                    # (without descending) so its inner `private` identifier does
                    # not leak into the bare-marker toggle below.
                    handled = True
                if not handled:
                    for child in reversed(node.children):
                        stack.append((child, class_name, module_name, vis_state))

            elif node.type == 'identifier' and class_name is not None and \
                    self._node_text(node, source) in ('private', 'protected', 'public'):
                # Bare visibility marker toggles subsequent-sibling visibility
                # within the current class body.
                vis_state[0] = self._node_text(node, source)

            elif node.type == 'class':
                # Extract class name
                name_node = node.child_by_field_name('name')
                local_class_name = self._node_text(name_node, source) if name_node else None
                # Compose with the enclosing class so a nested class keeps its
                # outer qualifier, e.g. `Outer::Inner`.
                if local_class_name and class_name:
                    new_class_name = f"{class_name}::{local_class_name}"
                else:
                    new_class_name = local_class_name

                # Extract superclass
                superclass = None
                sup_node = node.child_by_field_name('superclass')
                if sup_node:
                    # Skip the '<' token
                    for child in sup_node.children:
                        if child.type != '<':
                            superclass = self._node_text(child, source)
                            break

                if new_class_name:
                    class_id = f"{relative_path}:{new_class_name}"
                    body_node = node.child_by_field_name('body')
                    methods = self._collect_class_method_names(body_node, source)

                    self.classes[class_id] = {
                        'name': new_class_name,
                        'file_path': relative_path,
                        'start_line': node.start_point[0] + 1,
                        'end_line': node.end_point[0] + 1,
                        'methods': methods,
                        'superclass': superclass,
                        'module_name': module_name,
                    }
                    self.stats['total_classes'] += 1

                # Recurse into class body with updated class_name and a FRESH
                # per-body visibility state (defaults to public).
                body_node = node.child_by_field_name('body')
                if body_node:
                    class_vis = ['public']
                    for child in reversed(body_node.children):
                        stack.append((child, new_class_name, module_name, class_vis))
                continue  # Don't walk children again

            elif node.type == 'module':
                # Module name: the `name` field is a `constant` (plain module)
                # or a `scope_resolution` (compact `module A::B`). Concatenate
                # with any enclosing module so nested + compact forms both keep
                # the full namespace.
                name_node = node.child_by_field_name('name')
                if name_node is None:
                    for child in node.children:
                        if child.type in ('constant', 'scope_resolution'):
                            name_node = child
                            break
                this_name = self._node_text(name_node, source) if name_node else None
                if this_name and module_name:
                    new_module_name = f"{module_name}::{this_name}"
                elif this_name:
                    new_module_name = this_name
                else:
                    new_module_name = module_name

                # Recurse into module body
                body_node = node.child_by_field_name('body')
                if body_node is None:
                    # Try finding body_statement child
                    for child in node.children:
                        if child.type == 'body_statement':
                            body_node = child
                            break

                if body_node:
                    mod_vis = ['public']
                    for child in reversed(body_node.children):
                        stack.append((child, class_name, new_module_name, mod_vis))
                continue  # Don't walk children again

            else:
                for child in reversed(node.children):
                    stack.append((child, class_name, module_name, vis_state))

    def _collect_class_method_names(self, body_node, source: bytes) -> List[str]:
        """Names of methods declared in a class body, including alias/metaprog forms."""
        methods: List[str] = []
        if body_node is None:
            return methods
        for child in body_node.children:
            if child.type == 'method':
                mname = self._get_method_name(child, source)
                if mname:
                    methods.append(mname)
            elif child.type == 'singleton_method':
                mname = self._get_method_name(child, source)
                if mname:
                    methods.append(f"self.{mname}")
            elif child.type == 'alias':
                mname = self._alias_new_name(child, source)
                if mname:
                    methods.append(mname)
            elif child.type == 'call':
                method_name, args = self._call_receiver_and_method(child, source)
                if method_name in ('define_method', 'alias_method') and args:
                    methods.append(args[0])
        return methods

    @staticmethod
    def _alias_new_name(node, source: bytes) -> Optional[str]:
        """Return the NEW (created) name from an `alias new old` node."""
        idents = [c for c in node.children if c.type in ('identifier', 'constant', 'simple_symbol')]
        if idents:
            text = source[idents[0].start_byte:idents[0].end_byte].decode('utf-8', errors='replace')
            return text[1:] if text.startswith(':') else text
        return None

    def _process_alias_node(self, node, source: bytes, relative_path: str,
                            class_name: Optional[str], module_name: Optional[str],
                            visibility: str) -> None:
        """Emit a method unit for an `alias new old` keyword statement."""
        name = self._alias_new_name(node, source)
        if name:
            self._emit_synthetic_method(
                node, source, relative_path, class_name, module_name,
                name=name, unit_type=None, visibility=visibility,
            )

    def _emit_synthetic_method(self, node, source: bytes, relative_path: str,
                               class_name: Optional[str], module_name: Optional[str],
                               name: str, unit_type: Optional[str],
                               visibility: str) -> None:
        """Register a function unit for a metaprogramming / DSL / alias definition.

        Used for define_method, alias_method, alias, and Sinatra route DSL,
        where the defining node is not a tree-sitter `method` node. When
        ``unit_type`` is None the normal classifier is applied.
        """
        if not name:
            return
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        code = self._node_text(node, source)

        if unit_type is None:
            unit_type = self._classify_function(
                name, class_name, module_name, False, relative_path, visibility,
            )

        if class_name:
            qualified_name = f"{class_name}.{name}"
        elif module_name:
            qualified_name = f"{module_name}.{name}"
        else:
            qualified_name = name

        func_id = f"{relative_path}:{qualified_name}"
        self._store_function(func_id, {
            'name': name,
            'qualified_name': qualified_name,
            'file_path': relative_path,
            'start_line': start_line,
            'end_line': end_line,
            'code': code,
            'class_name': class_name,
            'module_name': module_name,
            'parameters': [],
            'is_singleton': False,
            'visibility': visibility,
            'unit_type': unit_type,
        })
        self.stats['total_functions'] += 1
        if class_name:
            self.stats['total_methods'] += 1
        else:
            self.stats['standalone_functions'] += 1
        self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1


    def _store_function(self, func_id: str, func_data: dict) -> str:
        """Insert a function unit, keeping BOTH on a same-(file,name) collision.

        Ruby `def` executes when reached, so same-name defs in mutually-exclusive
        conditional branches (`if/else`) are both runtime-reachable depending on
        the condition, and the EARLIER branch may be the live one. A plain
        keep-last store let the later (possibly dead) branch overwrite the
        earlier (possibly live) one — a silent false negative, confirmed against
        the real `ruby` interpreter. Keep BOTH via a deterministic `#L<line>`
        suffix (earlier-in-source keeps the clean id), mirroring the Python
        extractor's `_store_function`. Unconditional reopening is last-wins at
        runtime; keeping both there is the same benign tradeoff Python accepts.
        Collision-only: a unique name keeps its byte-identical `path:name` id.
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

    def _process_method_node(self, node, source: bytes, relative_path: str,
                              class_name: Optional[str], module_name: Optional[str],
                              is_singleton: bool, visibility: str = 'public') -> None:
        """Process a single method or singleton_method node."""
        name = self._get_method_name(node, source)
        if not name:
            return

        code = self._node_text(node, source)
        start_line = node.start_point[0] + 1  # tree-sitter is 0-indexed
        end_line = node.end_point[0] + 1
        parameters = self._get_parameters(node, source)

        unit_type = self._classify_function(
            name, class_name, module_name, is_singleton, relative_path, visibility
        )

        # Build qualified name and function ID
        if class_name:
            qualified_name = f"{class_name}.{name}"
        elif module_name:
            qualified_name = f"{module_name}.{name}"
        else:
            qualified_name = name

        func_id = f"{relative_path}:{qualified_name}"

        func_data = {
            'name': name,
            'qualified_name': qualified_name,
            'file_path': relative_path,
            'start_line': start_line,
            'end_line': end_line,
            'code': code,
            'class_name': class_name,
            'module_name': module_name,
            'parameters': parameters,
            'is_singleton': is_singleton,
            'visibility': visibility,
            'unit_type': unit_type,
        }

        self._store_function(func_id, func_data)
        self.stats['total_functions'] += 1

        if class_name:
            self.stats['total_methods'] += 1
        else:
            self.stats['standalone_functions'] += 1

        if is_singleton:
            self.stats['singleton_methods'] += 1

        self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

    def process_file(self, file_path: Path) -> None:
        """Process a single Ruby file."""
        source = self.read_file(file_path)
        if not source:
            self.stats['files_with_errors'] += 1
            return

        relative_path = file_path.relative_to(self.repo_path).as_posix()  # posix-normalize keys for cross-platform call-graph resolution

        try:
            tree = self.parser.parse(source)
        except Exception as e:
            print(f"Parse error in {file_path}: {e}", file=sys.stderr)
            self.stats['files_with_errors'] += 1
            return

        self.stats['files_processed'] += 1

        # Extract imports
        self.imports[relative_path] = self._extract_imports(tree, source)

        # Extract functions
        self._extract_functions_from_tree(tree, source, file_path, relative_path)

    def extract_from_scan(self, scan_result: Dict) -> Dict:
        """Extract functions from files listed in a scan result."""
        for file_info in scan_result.get('files', []):
            file_path = self.repo_path / file_info['path']
            self.process_file(file_path)

        return self.export()

    def extract_all(self, files: Optional[List[str]] = None) -> Dict:
        """Extract functions from all Ruby files or a specific list."""
        if files:
            for file_rel_path in files:
                file_path = self.repo_path / file_rel_path
                if file_path.exists():
                    self.process_file(file_path)
        else:
            for ext in ('.rb', '.rake'):
                for file_path in self.repo_path.rglob(f'*{ext}'):
                    path_str = str(file_path)
                    if any(excl in path_str for excl in ['.git', 'vendor', '.bundle', 'tmp', 'node_modules']):
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
        description='Extract all functions and classes from a Ruby repository',
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
            print(f"  Singleton methods: {result['statistics']['singleton_methods']}", file=sys.stderr)
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
