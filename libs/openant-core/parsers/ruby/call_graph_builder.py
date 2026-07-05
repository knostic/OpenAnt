#!/usr/bin/env python3
"""
Call Graph Builder for Ruby Codebases

Builds bidirectional call graphs from extracted function data:
- Forward graph: function -> functions it calls
- Reverse graph: function -> functions that call it

This is Phase 3 of the Ruby parser - dependency resolution.

Usage:
    python call_graph_builder.py <extractor_output.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "functions": {...},
        "call_graph": {
            "file.rb:func1": ["file.rb:func2", "other.rb:func3"],
            ...
        },
        "reverse_call_graph": {
            "file.rb:func2": ["file.rb:func1"],
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
import posixpath
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import tree_sitter_ruby as ts_ruby
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


RUBY_LANGUAGE = Language(ts_ruby.language())

# Ruby builtins and common methods to filter out
RUBY_BUILTINS = {
    # Kernel methods
    'puts', 'print', 'p', 'pp', 'warn', 'raise', 'fail',
    'require', 'require_relative', 'load', 'autoload',
    'lambda', 'proc', 'block_given?', 'caller', 'sleep',
    'exit', 'abort', 'at_exit', 'trap', 'fork', 'exec', 'system',
    'open', 'sprintf', 'format', 'rand', 'srand',
    'gets', 'readline', 'readlines',
    'loop', 'catch', 'throw',
    # Object methods
    'freeze', 'frozen?', 'dup', 'clone', 'nil?', 'is_a?', 'kind_of?',
    'instance_of?', 'respond_to?', 'send', 'public_send', 'method',
    'object_id', 'equal?', 'hash', 'class', 'inspect', 'tap',
    'then', 'yield_self',
    # Conversion
    'to_s', 'to_i', 'to_f', 'to_a', 'to_h', 'to_r', 'to_c',
    'to_sym', 'to_proc', 'to_json', 'to_yaml',
    'Integer', 'Float', 'String', 'Array', 'Hash',
    # Enumerable / Array / Hash common
    'each', 'map', 'collect', 'select', 'filter', 'reject', 'find',
    'detect', 'reduce', 'inject', 'flat_map', 'collect_concat',
    'each_with_object', 'each_with_index', 'each_slice', 'each_cons',
    'any?', 'all?', 'none?', 'count', 'size', 'length', 'empty?',
    'include?', 'member?', 'first', 'last', 'min', 'max',
    'min_by', 'max_by', 'sort', 'sort_by', 'reverse',
    'flatten', 'compact', 'uniq', 'zip', 'take', 'drop',
    'group_by', 'chunk', 'partition', 'tally',
    'push', 'pop', 'shift', 'unshift', 'append', 'prepend',
    'delete', 'delete_at', 'delete_if', 'keep_if',
    'keys', 'values', 'merge', 'merge!', 'update', 'fetch',
    'dig', 'slice', 'except', 'transform_keys', 'transform_values',
    # String methods
    'strip', 'chomp', 'chop', 'gsub', 'sub', 'match', 'match?',
    'split', 'join', 'concat', 'replace', 'encode', 'decode',
    'start_with?', 'end_with?', 'upcase', 'downcase', 'capitalize',
    'tr', 'squeeze', 'center', 'ljust', 'rjust', 'scan',
    # Class / Module macros
    'attr_accessor', 'attr_reader', 'attr_writer',
    'include', 'extend', 'prepend',
    'public', 'private', 'protected',
    'module_function', 'alias_method',
    'define_method', 'method_missing', 'respond_to_missing?',
    # Rails common
    'before_action', 'after_action', 'around_action',
    'before_filter', 'after_filter',
    'belongs_to', 'has_many', 'has_one', 'has_and_belongs_to_many',
    'validates', 'validate', 'validates_presence_of',
    'scope', 'default_scope',
    'delegate', 'class_attribute', 'mattr_accessor', 'cattr_accessor',
    'render', 'redirect_to', 'head', 'respond_to',
    'params', 'session', 'cookies', 'flash', 'request', 'response',
    # Type checks
    'is_a?', 'kind_of?', 'instance_of?', 'respond_to?',
    'nil?', 'blank?', 'present?', 'presence',
    # Logging
    'logger', 'log', 'debug', 'info', 'error',
    # New / initialize
    'new', 'allocate', 'initialize', 'super',
}


class CallGraphBuilder:
    """
    Build bidirectional call graphs from extracted Ruby function data.

    This is Stage 3 of the Ruby parser pipeline.
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
        # Module-level functions, keyed by module_name. Ruby module functions
        # carry module_name (class_name is None), so methods_by_class never
        # indexed them and their Module.method / same-module sibling calls were
        # unresolvable while a bare call to one could leak into an unrelated file.
        self.methods_by_module: Dict[str, List[str]] = {}

        self._build_indexes()

        # Parser for re-parsing function bodies
        self.ruby_parser = Parser(RUBY_LANGUAGE)

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

            module_name = func_data.get('module_name')
            if module_name and not class_name:
                if module_name not in self.methods_by_module:
                    self.methods_by_module[module_name] = []
                self.methods_by_module[module_name].append(func_id)

    def _is_builtin(self, name: str) -> bool:
        """Check if name is a Ruby builtin or common method."""
        return name in RUBY_BUILTINS

    def _extract_calls_from_code(self, code: str, caller_id: str) -> Set[str]:
        """Extract function call references from code using tree-sitter."""
        calls = set()
        caller_file = caller_id.split(':')[0]
        caller_func = self.functions.get(caller_id, {})
        caller_class = caller_func.get('class_name')
        caller_module = caller_func.get('module_name')
        caller_method = caller_func.get('name')

        code_bytes = code.encode('utf-8', errors='replace')
        try:
            tree = self.ruby_parser.parse(code_bytes)
        except Exception:
            return self._extract_calls_regex(code, caller_id)

        # First pass: collect local-variable names (assignment LHS) and
        # method-object bindings (`m = method(:sym)` / proc / lambda). These
        # inform parenless-call precision [BUG 1] and `.call` resolution [BUG 31].
        #
        # SINGLE-UNCONDITIONAL-ASSIGNMENT GUARD for method-object bindings: a
        # binding is kept ONLY when the variable is assigned exactly once AND at
        # the method/program top level (a direct statement of the body, not
        # nested inside an `if`/`unless`/`while`/`case`/`begin`/block). A var
        # assigned 2+ times (last-write-wins) or bound conditionally is a
        # "maybe" binding; resolving its `.call` would assert a maybe as
        # definite, so we drop it and let `m.call` go unresolved (no edge).
        # `local_vars` (for parenless precision) is NOT narrowed -- any
        # assignment target is still a local variable for the bare-identifier
        # guard, regardless of how many times / where it is bound.
        local_vars: Set[str] = set()
        assign_counts: Dict[str, int] = {}
        top_level_binding: Dict[str, str] = {}
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == 'assignment':
                lhs = node.children[0] if node.children else None
                if lhs is not None and lhs.type == 'identifier':
                    var_name = self._node_str(lhs, code_bytes)
                    local_vars.add(var_name)
                    assign_counts[var_name] = assign_counts.get(var_name, 0) + 1
                    if self._is_top_level_statement(node):
                        bound = self._method_object_target(node, code_bytes)
                        if bound:
                            top_level_binding[var_name] = bound
            stack.extend(reversed(node.children))

        # Keep a method-object binding only if it is single + unconditional:
        # exactly one assignment to that name, and that binding is top-level.
        method_object_bindings: Dict[str, str] = {
            name: bound
            for name, bound in top_level_binding.items()
            if assign_counts.get(name, 0) == 1
        }

        # Second pass: resolve calls and bare (parenless) identifier calls.
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == 'call':
                resolved = self._resolve_call_node(node, code_bytes, caller_file,
                                                   caller_class, caller_module, caller_method,
                                                   method_object_bindings)
                if resolved:
                    calls.add(resolved)
            elif node.type == 'identifier':
                resolved = self._resolve_bare_identifier(
                    node, code_bytes, caller_file, caller_class, local_vars
                )
                if resolved:
                    calls.add(resolved)
            elif node.type == 'super':
                # A bare `super` is its own node (not a `call`); `super(args)` is a
                # `call` whose first child is a `super` node, handled below.
                if node.parent is None or node.parent.type != 'call':
                    resolved = self._resolve_super_call(caller_file, caller_class, caller_method)
                    if resolved:
                        calls.add(resolved)
            stack.extend(reversed(node.children))

        return calls

    def _node_str(self, node, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    @staticmethod
    def _is_top_level_statement(node) -> bool:
        """True if `node` is a direct statement of a method/program body.

        Top-level means the parent is the method body (`body_statement`) or the
        file program node. Anything nested in an `if`/`then`/`else`/`while`/
        `case`/`begin`/block has some other parent, so it is conditional/looped
        and not a single-unconditional binding.
        """
        parent = node.parent
        return parent is not None and parent.type in ('body_statement', 'program')

    def _method_object_target(self, assignment_node, source: bytes) -> Optional[str]:
        """If RHS is method(:sym)/proc/lambda binding a named method, return the name.

        Tracks `m = method(:helper)` so a later `m.call` resolves to `helper`.
        """
        rhs = assignment_node.children[-1] if assignment_node.children else None
        if rhs is None or rhs.type != 'call':
            return None
        callee = None
        arg_list = None
        for child in rhs.children:
            if child.type == 'identifier' and callee is None:
                callee = self._node_str(child, source)
            elif child.type == 'argument_list':
                arg_list = child
        if callee != 'method' or arg_list is None:
            return None
        for arg in arg_list.children:
            if arg.type in ('simple_symbol', 'symbol'):
                sym = self._node_str(arg, source)
                return sym.lstrip(':')
        return None

    def _resolve_bare_identifier(self, node, source: bytes, caller_file: str,
                                 caller_class: Optional[str],
                                 local_vars: Set[str]) -> Optional[str]:
        """Resolve a bare (parenless) identifier used as a call.

        Precision guard: only treat a bare identifier as a call when its name
        is a KNOWN user function, it is NOT a Ruby builtin, and it is NOT a
        local variable / assignment target in this method body. We also skip
        identifiers that are a structural part of a call/method/assignment
        (their own handlers cover those) to avoid double-counting.
        """
        parent = node.parent
        if parent is not None and parent.type in (
            'call', 'method', 'singleton_method', 'assignment', 'method_call',
        ):
            return None
        name = self._node_str(node, source)
        if name in local_vars:
            return None
        if self._is_builtin(name):
            return None
        if name not in self.functions_by_name:
            return None
        return self._resolve_simple_call(name, caller_file, caller_class)

    def _resolve_call_node(self, node, source: bytes, caller_file: str,
                           caller_class: Optional[str],
                           caller_module: Optional[str] = None,
                           caller_method: Optional[str] = None,
                           method_object_bindings: Optional[Dict[str, str]] = None
                           ) -> Optional[str]:
        """Resolve a tree-sitter call node to a function ID."""
        # `super(args)` is a call node whose head is a `super` node, not an
        # identifier method name -- resolve it against the superclass.
        if any(c.type == 'super' for c in node.children):
            return self._resolve_super_call(caller_file, caller_class, caller_method)

        method_object_bindings = method_object_bindings or {}

        # Method-object call: `m = method(:helper)` then `m.call` resolves to the
        # bound target [BUG 31]. The positional heuristic below mis-parses a
        # lowercase-variable receiver (it captures the var as the method name),
        # so detect this precisely via tree-sitter's named receiver/method fields.
        recv_field = node.child_by_field_name('receiver')
        meth_field = node.child_by_field_name('method')
        if recv_field is not None and meth_field is not None:
            recv_text = source[recv_field.start_byte:recv_field.end_byte].decode(
                'utf-8', errors='replace')
            meth_text = source[meth_field.start_byte:meth_field.end_byte].decode(
                'utf-8', errors='replace')
            if meth_text == 'call' and recv_text in method_object_bindings:
                target_name = method_object_bindings[recv_text]
                return self._resolve_simple_call(target_name, caller_file, caller_class)

        # Extract method name
        method_name = None
        receiver = None
        args_node = None

        for child in node.children:
            if child.type == 'identifier' and method_name is None:
                method_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
            elif child.type == '.':
                continue
            elif child.type in ('argument_list', 'block', 'do_block'):
                if child.type == 'argument_list' and args_node is None:
                    args_node = child
                continue
            elif method_name is None and child.type not in ('identifier',):
                # This might be the receiver
                receiver_text = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                # The next identifier after '.' will be the method name
                receiver = receiver_text

        if not method_name:
            return None

        # ClassName.new(...) -> the class's initialize. `new` is in RUBY_BUILTINS,
        # so this must precede the builtin filter below or the edge is dropped.
        if method_name == 'new' and receiver and receiver[0:1].isupper():
            return self._resolve_class_call(receiver, 'initialize', caller_file)

        # send/public_send/__send__ with a literal symbol/string argument: the
        # dispatched method is the first literal arg. Runtime-string targets are
        # not statically recoverable. These verbs are filtered as builtins below,
        # so resolve the literal-symbol case before that filter.
        if method_name in ('send', 'public_send', '__send__'):
            target = self._literal_symbol_arg(args_node, source)
            if target is None:
                return None
            if receiver == 'self' or receiver is None:
                if caller_class:
                    return self._resolve_self_call(target, caller_file, caller_class)
                return self._resolve_simple_call(target, caller_file, caller_class, caller_module)
            if receiver[0:1].isupper():
                return self._resolve_class_call(receiver, target, caller_file)
            return None

        # A user method may share a name with a Ruby builtin (e.g. render, log,
        # open). Don't let the builtin filter drop a call that resolves to a
        # user-defined function visible in scope. Scope = same class or same
        # file ONLY (no global cross-file single-match) so a genuine builtin
        # call isn't wired to an unrelated same-named user method elsewhere.
        if self._is_builtin(method_name):
            if receiver is None and self._has_scoped_user_function(
                method_name, caller_file, caller_class
            ):
                return self._resolve_simple_call(method_name, caller_file, caller_class)
            return None

        # self.method(...) - same class
        if receiver == 'self' and caller_class:
            return self._resolve_self_call(method_name, caller_file, caller_class)
        # self.method(...) inside a module function (module_name, no class)
        if receiver == 'self' and caller_module:
            return self._resolve_module_call(caller_module, method_name, caller_file)

        # No receiver - simple function call
        if receiver is None:
            return self._resolve_simple_call(method_name, caller_file, caller_class, caller_module)

        # Receiver is a constant (ClassName.method or ModuleName.method)
        if receiver and receiver[0:1].isupper():
            return self._resolve_class_call(receiver, method_name, caller_file)

        return None

    @staticmethod
    def _literal_symbol_arg(args_node, source: bytes) -> Optional[str]:
        """Return the first literal symbol/string argument value, or None.

        Handles ``:foo`` (simple_symbol) and ``"foo"``/``'foo'`` (string). A
        non-literal first argument (variable, interpolation) has no static target.
        """
        if args_node is None:
            return None
        for child in args_node.children:
            if child.type == 'simple_symbol':
                text = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                return text[1:] if text.startswith(':') else text
            if child.type == 'string':
                for sc in child.children:
                    if sc.type == 'string_content':
                        return source[sc.start_byte:sc.end_byte].decode('utf-8', errors='replace')
                return None
            if child.type in ('(', ')', ','):
                continue
            # First non-literal positional argument: no static target.
            return None
        return None

    def _resolve_super_call(self, caller_file: str, caller_class: Optional[str],
                            caller_method: Optional[str]) -> Optional[str]:
        """Resolve a `super` call to the same-named method in the superclass.

        `super` re-dispatches the CURRENT method name (caller_method) up the
        ancestor chain, so the target is the superclass's method of the same name.
        """
        if not caller_class or not caller_method:
            return None
        superclass = self._superclass_of(caller_file, caller_class)
        if not superclass:
            return None
        if '::' in superclass:
            superclass = superclass.rsplit('::', 1)[-1]
        return self._resolve_class_call(superclass, caller_method, caller_file)

    def _superclass_of(self, caller_file: str, caller_class: str) -> Optional[str]:
        """Return the superclass of caller_class defined in caller_file, or None."""
        class_data = self.classes.get(f"{caller_file}:{caller_class}")
        if class_data:
            return class_data.get('superclass')
        for data in self.classes.values():
            if data.get('name') == caller_class and data.get('file_path') == caller_file:
                return data.get('superclass')
        return None

    def _resolve_simple_call(self, func_name: str, caller_file: str,
                             caller_class: Optional[str],
                             caller_module: Optional[str] = None) -> Optional[str]:
        """Resolve a simple (no-receiver) function call to a function ID."""
        # 1. Check same class first (implicit self)
        if caller_class:
            result = self._resolve_self_call(func_name, caller_file, caller_class)
            if result:
                return result

        # 1b. Inside a module function, a bare call resolves to a sibling of the
        #     SAME module first (any file), before falling through to file/global
        #     lookups. This is the same-module-sibling path.
        if caller_module:
            result = self._resolve_module_call(caller_module, func_name, caller_file)
            if result:
                return result

        # 2. Check same file. A module function is only a valid same-file target
        #    when the caller is in the same module (handled in 1b); a bare call
        #    from outside any module must not bind to a same-file module fn, so
        #    require both class_name and module_name to be unset here.
        same_file_funcs = self.functions_by_file.get(caller_file, [])
        for func_id in same_file_funcs:
            func_data = self.functions.get(func_id, {})
            if (func_data.get('name') == func_name
                    and not func_data.get('class_name')
                    and not func_data.get('module_name')):
                return func_id

        # 3. Check require-resolved files (anchored).
        file_imports = self.imports.get(caller_file, {})
        for import_name, import_type in file_imports.items():
            if import_type not in ('require', 'require_relative'):
                continue
            target_file = self._resolve_import_file(import_name, import_type, caller_file)
            if target_file is None:
                continue
            for func_id in self.functions_by_file.get(target_file, []):
                func_data = self.functions.get(func_id, {})
                if (func_data.get('name') == func_name
                        and not func_data.get('class_name')
                        and not func_data.get('module_name')):
                    return func_id

        # 4. Unique name match across files. Restrict to genuine top-level
        #    functions (neither class- nor module-bound) so a module function
        #    never leaks an edge to an unrelated bare call.
        candidates = self.functions_by_name.get(func_name, [])
        candidates = [c for c in candidates
                      if not self.functions.get(c, {}).get('class_name')
                      and not self.functions.get(c, {}).get('module_name')]
        if len(candidates) == 1:
            return candidates[0]

        return None

    def _resolve_import_file(self, import_name: str, import_type: str,
                             caller_file: str) -> Optional[str]:
        """Resolve a require / require_relative target to a known file path.

        `require_relative` is anchored to the caller file's directory and
        normalized (so `./helper` and `../lib/util` resolve correctly even when
        the basename collides). `require` matches by anchored file name, never an
        unanchored substring (which over-matched any path containing the string).
        """
        if import_type == 'require_relative':
            base_dir = posixpath.dirname(caller_file)
            anchored = posixpath.normpath(posixpath.join(base_dir, import_name))
            target = anchored if anchored.endswith('.rb') else f"{anchored}.rb"
            return target if target in self.functions_by_file else None

        # `require 'name'` / `require 'path/name'`: match the file by its name
        # component, anchored -- not a bare substring.
        candidate = import_name if import_name.endswith('.rb') else f"{import_name}.rb"
        if candidate in self.functions_by_file:
            return candidate
        base = candidate.rsplit('/', 1)[-1]
        matches = [fp for fp in self.functions_by_file
                   if fp == base or fp.endswith(f"/{base}")]
        return matches[0] if len(matches) == 1 else None

    def _resolve_module_call(self, module_name: str, method_name: str,
                             caller_file: str) -> Optional[str]:
        """Resolve a ModuleName.method() / same-module sibling call.

        Prefers a same-file definition, then any file defining the module.
        """
        fallback = None
        for func_id in self.methods_by_module.get(module_name, []):
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') != method_name:
                continue
            if func_data.get('file_path') == caller_file:
                return func_id
            if fallback is None:
                fallback = func_id
        return fallback

    def _has_scoped_user_function(self, name: str, caller_file: str,
                                  caller_class: Optional[str]) -> bool:
        """True if `name` is a user function visible in the caller's scope.

        Scope is deliberately narrow (same class or same file). This lets a
        user method that shadows a builtin name resolve, without globally
        rescuing a genuine builtin call into an unrelated same-named method.
        """
        if caller_class:
            class_key = f"{caller_file}:{caller_class}"
            for func_id in self.methods_by_class.get(class_key, []):
                if self.functions.get(func_id, {}).get('name') == name:
                    return True
        for func_id in self.functions_by_file.get(caller_file, []):
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == name and not func_data.get('class_name'):
                return True
        return False

    def _resolve_self_call(self, method_name: str, caller_file: str,
                           caller_class: str) -> Optional[str]:
        """Resolve a self.method() call within a class."""
        class_key = f"{caller_file}:{caller_class}"
        class_methods = self.methods_by_class.get(class_key, [])

        for func_id in class_methods:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == method_name:
                return func_id

        return None

    def _resolve_class_call(self, class_name: str, method_name: str,
                            caller_file: str) -> Optional[str]:
        """Resolve a ClassName.method() or ModuleName.method() call.

        A constant receiver may name a class or a module; module functions are not
        in methods_by_class, so fall back to the module index.
        """
        # Check same file first
        class_key = f"{caller_file}:{class_name}"
        if class_key in self.methods_by_class:
            for func_id in self.methods_by_class[class_key]:
                func_data = self.functions.get(func_id, {})
                if func_data.get('name') == method_name:
                    return func_id

        # Cross-file fallback. The previous behaviour linked the FIRST same-named
        # class found ANYWHERE, which is unsound: it wired callers to unrelated
        # files (and is wrong under same-name class collisions). Scope it: only
        # accept a cross-file class when the caller's file require/require_relative
        # resolves to the file that defines the class.
        for key, func_ids in self.methods_by_class.items():
            if not key.endswith(f":{class_name}"):
                continue
            key_file = key.rsplit(':', 1)[0]
            if not self._file_is_required_by(key_file, caller_file):
                continue
            for func_id in func_ids:
                func_data = self.functions.get(func_id, {})
                if func_data.get('name') == method_name:
                    return func_id

        # The receiver may be a module (e.g. Utils.helper for a module_function).
        return self._resolve_module_call(class_name, method_name, caller_file)

    def _file_is_required_by(self, target_file: str, caller_file: str) -> bool:
        """True if caller_file has a require/require_relative resolving to target_file."""
        target_stem = target_file.replace('\\', '/').rsplit('/', 1)[-1]
        if target_stem.endswith('.rb'):
            target_stem = target_stem[:-len('.rb')]
        file_imports = self.imports.get(caller_file, {})
        for import_name, import_type in file_imports.items():
            if import_type not in ('require', 'require_relative'):
                continue
            import_basename = import_name.replace('\\', '/').rsplit('/', 1)[-1]
            if import_basename == target_stem:
                return True
        return False

    def _extract_calls_regex(self, code: str, caller_id: str) -> Set[str]:
        """Fallback regex-based call extraction for unparseable code."""
        calls = set()
        caller_file = caller_id.split(':')[0]

        # Match method calls: name(
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_!?]*)\s*[\(]'
        for match in re.finditer(pattern, code):
            func_name = match.group(1)
            # Skip Ruby keywords
            if func_name in ('if', 'unless', 'while', 'until', 'for', 'case',
                             'when', 'begin', 'rescue', 'ensure', 'end',
                             'def', 'class', 'module', 'do', 'return', 'yield'):
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
        description='Build call graphs from extracted Ruby function data',
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
