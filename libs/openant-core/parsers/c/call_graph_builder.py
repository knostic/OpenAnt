#!/usr/bin/env python3
"""
Call Graph Builder for C/C++ Codebases

Builds bidirectional call graphs from extracted function data:
- Forward graph: function -> functions it calls
- Reverse graph: function -> functions that call it

This is Phase 3 of the C/C++ parser - dependency resolution.

Usage:
    python call_graph_builder.py <extractor_output.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "functions": {...},
        "call_graph": {
            "file.c:func1": ["file.c:func2", "other.c:func3"],
            ...
        },
        "reverse_call_graph": {
            "file.c:func2": ["file.c:func1"],
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

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())

C_EXTENSIONS = {'.c', '.h'}
CPP_EXTENSIONS = {'.cpp', '.hpp', '.cc', '.cxx', '.hxx', '.hh'}

# Standard C library functions to filter out
STDLIB_FUNCTIONS = {
    # Memory
    'malloc', 'calloc', 'realloc', 'free',
    # I/O
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
    'vsprintf', 'vsnprintf', 'scanf', 'fscanf', 'sscanf',
    'fopen', 'fclose', 'fread', 'fwrite', 'fgets', 'fputs',
    'fseek', 'ftell', 'rewind', 'fflush', 'feof', 'ferror',
    'puts', 'getchar', 'putchar', 'getc', 'putc', 'ungetc',
    'perror',
    # String
    'memcpy', 'memset', 'memmove', 'memcmp', 'memchr',
    'strlen', 'strcmp', 'strncmp', 'strcpy', 'strncpy',
    'strcat', 'strncat', 'strstr', 'strchr', 'strrchr',
    'strtok', 'strerror', 'strdup', 'strndup',
    # Conversion
    'atoi', 'atol', 'atof', 'strtol', 'strtoul', 'strtoll',
    'strtoull', 'strtod', 'strtof',
    # General
    'exit', 'abort', '_exit', 'atexit',
    'qsort', 'bsearch', 'abs', 'labs',
    'getenv', 'setenv', 'system',
    # Assert
    'assert',
    # Operators / keywords that look like calls
    'sizeof', 'offsetof', 'typeof', 'alignof',
    '__builtin_expect', '__builtin_unreachable',
    # va_args
    'va_start', 'va_end', 'va_arg', 'va_copy',
    # POSIX
    'close', 'read', 'write', 'open', 'lseek',
    'mmap', 'munmap', 'mprotect',
    'socket', 'bind', 'listen', 'accept', 'connect',
    'send', 'recv', 'sendto', 'recvfrom',
    'select', 'poll', 'epoll_create', 'epoll_ctl', 'epoll_wait',
    'fork', 'exec', 'execve', 'execvp', 'waitpid',
    'pthread_create', 'pthread_join', 'pthread_mutex_lock', 'pthread_mutex_unlock',
    'signal', 'sigaction',
    # C++ standard
    'std', 'move', 'forward', 'make_shared', 'make_unique',
    'static_cast', 'dynamic_cast', 'reinterpret_cast', 'const_cast',
    'new', 'delete',
}


class CallGraphBuilder:
    """
    Build bidirectional call graphs from extracted C/C++ function data.

    This is Stage 3 of the C/C++ parser pipeline.
    """

    def __init__(self, extractor_output: Dict, options: Optional[Dict] = None):
        options = options or {}

        self.functions = extractor_output.get('functions', {})
        self.includes = extractor_output.get('includes', {})
        self.macros = extractor_output.get('macros', {})
        self.macro_aliases = extractor_output.get('macro_aliases', {})
        self.prototypes = extractor_output.get('prototypes', {})
        # class_name -> [direct base-class name, ...] for the inheritance walk in
        # member dispatch (bug [30]). Defaults to {} when the extractor output
        # predates base-class extraction, so resolution degrades to the [51]
        # same-type behavior rather than erroring.
        self.class_bases: Dict[str, List[str]] = extractor_output.get('class_bases', {})
        self.repo_path = extractor_output.get('repository', '')

        self.max_depth = options.get('max_depth', 3)

        # Call graphs
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}

        # Indexes for faster lookup
        self.functions_by_name: Dict[str, List[str]] = {}
        self.functions_by_file: Dict[str, List[str]] = {}
        # class_name -> {base_method_name -> [func_id, ...]} for member dispatch.
        # Scoped per (class, method) so a receiver-typed call resolves only to a
        # method actually declared on that class, never a sibling/free function.
        self.methods_by_class: Dict[str, Dict[str, List[str]]] = {}

        # Include map: file -> set of included header files
        self.include_map: Dict[str, Set[str]] = {}

        self._build_indexes()

        # Parsers for re-parsing function bodies
        self.c_parser = Parser(C_LANGUAGE)
        self.cpp_parser = Parser(CPP_LANGUAGE)

    def _build_indexes(self) -> None:
        """Build lookup indexes for faster resolution."""
        for func_id, func_data in self.functions.items():
            name = func_data.get('name', '')
            if name:
                # Use the base name (without namespace/class prefix)
                base_name = name.split('::')[-1] if '::' in name else name
                if base_name not in self.functions_by_name:
                    self.functions_by_name[base_name] = []
                self.functions_by_name[base_name].append(func_id)
                # Also index by full name if different
                if name != base_name:
                    if name not in self.functions_by_name:
                        self.functions_by_name[name] = []
                    self.functions_by_name[name].append(func_id)

            file_path = func_data.get('file_path', '')
            if file_path:
                if file_path not in self.functions_by_file:
                    self.functions_by_file[file_path] = []
                self.functions_by_file[file_path].append(func_id)

            # Index methods by their declaring class for receiver-type dispatch.
            class_name = func_data.get('class_name')
            if class_name and name:
                method_base = name.split('::')[-1] if '::' in name else name
                self.methods_by_class.setdefault(class_name, {}) \
                    .setdefault(method_base, []).append(func_id)

        # Build include map
        for file_path, inc_list in self.includes.items():
            self.include_map[file_path] = set()
            for inc in inc_list:
                # Match included header to files in repo
                for other_file in self.functions_by_file:
                    # Require a path-component boundary. A bare `endswith(inc)`
                    # matched any tail (include "x.h" -> "src/prefix-x.h"), so only
                    # an exact match or a '/'-delimited basename match is valid.
                    if other_file == inc or other_file.endswith('/' + inc):
                        self.include_map[file_path].add(other_file)

    def _is_stdlib(self, name: str) -> bool:
        """Check if name is a standard library function."""
        return name in STDLIB_FUNCTIONS

    def _get_parser_for_file(self, file_path: str) -> Parser:
        ext = Path(file_path).suffix.lower()
        if ext in CPP_EXTENSIONS:
            return self.cpp_parser
        return self.c_parser

    def _extract_calls_from_code(self, code: str, caller_id: str) -> Set[str]:
        """Extract function call references from code using tree-sitter."""
        calls = set()
        caller_file = caller_id.split(':')[0]
        func_data = self.functions.get(caller_id, {})
        file_path = func_data.get('file_path', caller_file)

        parser = self._get_parser_for_file(file_path)

        # Wrap in a dummy function if needed for parsing
        code_bytes = code.encode('utf-8', errors='replace')
        try:
            tree = parser.parse(code_bytes)
        except Exception:
            return self._extract_calls_regex(code, caller_id)

        # Receiver static types inferred from local declarations in this body,
        # used to resolve member calls (w.compute() / w->compute()) to the
        # method on the receiver's known type.
        local_var_types = self._extract_local_var_types(tree.root_node, code_bytes)

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == 'call_expression':
                func_node = node.child_by_field_name('function')
                if func_node:
                    call_name, receiver = self._extract_call_name_and_receiver(
                        func_node, code_bytes
                    )
                    if call_name:
                        receiver_type = local_var_types.get(receiver) if receiver else None
                        resolved = self._resolve_call(call_name, caller_file,
                                                      receiver_type=receiver_type,
                                                      is_member=func_node.type == 'field_expression')
                        if resolved:
                            calls.add(resolved)
                # A function passed by name as an argument (e.g.
                # qsort(..., my_cmp), pthread_create(..., worker, ...)) is invoked
                # indirectly by the callee. Resolve bare-identifier arguments that
                # name a known function; non-function identifiers (variables) do not
                # resolve and so do not create edges.
                calls.update(self._extract_callback_args(node, code_bytes, caller_file))
            stack.extend(reversed(node.children))
        return calls

    def _extract_callback_args(self, call_node, source: bytes, caller_file: str) -> Set[str]:
        """Resolve function-name arguments passed to a call (higher-order/callback)."""
        found: Set[str] = set()
        arg_list = call_node.child_by_field_name('arguments')
        if arg_list is None:
            return found
        for arg in arg_list.children:
            name: Optional[str] = None
            if arg.type == 'identifier':
                name = source[arg.start_byte:arg.end_byte].decode('utf-8', errors='replace')
            elif arg.type in ('pointer_expression', 'unary_expression'):
                # &handler -> handler
                operand = arg.child_by_field_name('argument')
                if operand is not None and operand.type == 'identifier':
                    name = source[operand.start_byte:operand.end_byte].decode('utf-8', errors='replace')
            if name and not self._is_stdlib(name):
                resolved = self._resolve_call(name, caller_file)
                if resolved:
                    found.add(resolved)
        return found

    def _extract_call_name_and_receiver(self, node, source: bytes):
        """Return (call_name, receiver_identifier) for a call's function child.

        receiver_identifier is the bare identifier text of a member-call receiver
        (the `w` in `w.compute()` / `w->compute()`) when it is a simple
        identifier, else None. The call_name is identical to what
        _extract_call_name returns, so non-member calls are unaffected.
        """
        if node.type == 'field_expression':
            receiver = None
            arg = node.child_by_field_name('argument')
            if arg is not None and arg.type == 'identifier':
                receiver = source[arg.start_byte:arg.end_byte].decode(
                    'utf-8', errors='replace')
            # _extract_call_name declines field_expression (no false free-function
            # edges); the member name is recovered here from the `field` child and
            # resolved ONLY through typed/same-file member dispatch in _resolve_call.
            field = node.child_by_field_name('field')
            name = None
            if field is not None:
                name = source[field.start_byte:field.end_byte].decode(
                    'utf-8', errors='replace')
                if not name.isidentifier():
                    name = None
            return name, receiver
        return self._extract_call_name(node, source), None

    def _extract_local_var_types(self, root, source: bytes) -> Dict[str, str]:
        """Map local variable name -> declared type name within a function body.

        Walks `declaration` nodes and records the (type_identifier, variable)
        pairs for both plain declarations (`Widget w;`) and pointer declarations
        (`Widget* w = ...;`). Only simple type_identifier types are recorded;
        anything else (templates, qualified types, multiple declarators we can't
        cleanly attribute) is skipped so callers fall back to base-name
        resolution rather than risk a wrong-type edge.
        """
        var_types: Dict[str, str] = {}
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == 'declaration':
                type_node = node.child_by_field_name('type')
                if type_node is not None and type_node.type == 'type_identifier':
                    type_name = source[type_node.start_byte:type_node.end_byte] \
                        .decode('utf-8', errors='replace')
                    # A declaration can hold several declarators (Widget a, b;);
                    # attribute the type to every variable name we extract.
                    for child in node.children:
                        var_name = self._declared_var_name(child, source)
                        if var_name:
                            var_types[var_name] = type_name
            stack.extend(reversed(node.children))
        return var_types

    def _declared_var_name(self, node, source: bytes) -> Optional[str]:
        """Extract the declared variable identifier from a declarator subtree.

        Handles the plain identifier (`w`), pointer_declarator (`* w`) and
        init_declarator (`* w = ...` / `w = ...`) shapes. Returns None for nodes
        that are not a variable declarator (e.g. the type node, `;`).
        """
        if node.type == 'identifier':
            return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
        if node.type in ('pointer_declarator', 'init_declarator', 'reference_declarator'):
            inner = node.child_by_field_name('declarator')
            if inner is not None:
                return self._declared_var_name(inner, source)
            # init_declarator with no declarator field: scan children.
            for child in node.children:
                name = self._declared_var_name(child, source)
                if name:
                    return name
        return None

    def _extract_call_name(self, node, source: bytes) -> Optional[str]:
        """Extract the function name from a call_expression's function child."""
        text = source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

        if node.type == 'identifier':
            return text

        if node.type == 'field_expression':
            # obj->method() / obj.method() is a member or function-pointer
            # call, not a free-function call. The resolver only does name-only lookup
            # (no struct-member / receiver-type model), so binding the bare field name
            # wired the call to any unrelated free function of the same name. Decline
            # here instead of emitting that false edge.
            return None

        if node.type == 'qualified_identifier':
            return text

        if node.type == 'template_function':
            name_node = node.child_by_field_name('name')
            if name_node:
                return source[name_node.start_byte:name_node.end_byte].decode('utf-8', errors='replace')

        if node.type == 'parenthesized_expression':
            # Function pointer call: (*func_ptr)(args)
            return None

        return text if text.isidentifier() else None

    def _is_visible_from(self, func_id: str, caller_file: str) -> bool:
        """Whether a candidate definition is linkable from caller_file.

        A `static` function has internal linkage and is only callable
        within its own translation unit, so a static definition in another file
        must not resolve a call made elsewhere. Same-file definitions are always
        visible; cross-file resolution requires external (non-static) linkage.
        """
        func_data = self.functions.get(func_id, {})
        if func_data.get('file_path', '') == caller_file:
            return True
        return not func_data.get('is_static', False)

    def _resolve_same_file(self, call_name: str, caller_file: str) -> Optional[str]:
        """Resolve a call to a user-defined function in the same file, if any."""
        same_file_funcs = self.functions_by_file.get(caller_file, [])
        for func_id in same_file_funcs:
            func_data = self.functions.get(func_id, {})
            fname = func_data.get('name', '')
            base_name = fname.split('::')[-1] if '::' in fname else fname
            if base_name == call_name:
                return func_id
        return None

    def _resolve_method_on_class(self, class_name: str, call_name: str,
                                 caller_file: str) -> Optional[str]:
        """Resolve call_name to a method DIRECTLY declared on class_name (same file).

        Returns the func_id of a method named call_name declared on class_name and
        defined in caller_file, else None. No inheritance — this is the single-hop
        lookup the walk in _resolve_member_call composes over the base chain.
        """
        by_method = self.methods_by_class.get(class_name)
        if not by_method:
            return None
        for func_id in by_method.get(call_name, []):
            func_data = self.functions.get(func_id, {})
            if func_data.get('file_path', '') == caller_file:
                return func_id
        return None

    def _resolve_member_call(self, call_name: str, caller_file: str,
                             receiver_type: str) -> Optional[str]:
        """Resolve a member call to the method on the receiver's STATIC type,
        walking UP the base-class chain to the first ancestor that defines it.

        Sound static-type floor (bug [30]): start at the receiver's declared type
        and return its own method if it defines call_name; otherwise walk up its
        direct base classes (BFS, cycle-guarded) and resolve to the FIRST ancestor
        that declares call_name in the same file. The walk STOPS at the first
        definer, so a derived override resolves to itself, never an ancestor.

        Deliberately does NOT link derived overrides of an ancestor's virtual
        method (a documented non-goal that would create false edges): a call via a
        Base* receiver resolves to Base's method only — the static-type floor.

        Same-file only: if no class on the chain defines call_name in this
        translation unit, returns None so the caller falls back to base-name
        resolution (never a wrong-type / unrelated-free-function edge).
        """
        visited: Set[str] = set()
        queue: List[str] = [receiver_type]
        while queue:
            cls = queue.pop(0)
            if cls in visited:
                continue
            visited.add(cls)
            # First definer on the chain wins (own type before ancestors).
            match = self._resolve_method_on_class(cls, call_name, caller_file)
            if match:
                return match
            for base in self.class_bases.get(cls, []):
                if base not in visited:
                    queue.append(base)
        return None

    def _resolve_call(self, call_name: str, caller_file: str,
                      receiver_type: Optional[str] = None,
                      is_member: bool = False,
                      _alias_chain: Optional[Set[str]] = None) -> Optional[str]:
        """Resolve a function call name to a function ID.

        When receiver_type is given (a member call like w.compute() whose receiver
        w has a known same-file type), resolve to that type's method FIRST. If
        that fails, fall through to the unchanged base-name resolution below.
        """
        if receiver_type:
            member_match = self._resolve_member_call(call_name, caller_file,
                                                     receiver_type)
            if member_match:
                return member_match

        # A user-defined function in the SAME FILE shadows any stdlib/builtin
        # of the same name, so it must be checked BEFORE the stdlib filter.
        # Scope is deliberately same-file only: a genuine stdlib call (no
        # same-file definition) still falls through to _is_stdlib below, so we
        # never wrongly link a real stdlib call (e.g. printf/open) to an
        # unrelated same-named user function in another file.
        same_file_user_func = self._resolve_same_file(call_name, caller_file)
        if same_file_user_func:
            return same_file_user_func

        # A member call (obj->m() / obj.m()) whose receiver type is unknown or
        # whose chain defines no such method resolves same-file only: declining
        # here keeps the field-expression precision guarantee (never an edge to
        # an unrelated cross-file free function of the same name).
        if is_member:
            return None

        if self._is_stdlib(call_name):
            return None

        # Check for macro aliases
        resolved_name = self.macro_aliases.get(call_name, call_name)
        if resolved_name != call_name:
            # Guard against cyclic macro aliases (e.g. ``#define A B`` /
            # ``#define B A`` -> {"A": "B", "B": "A"}). Without a visited-set
            # the recursion below would loop A->B->A->... until RecursionError
            # aborted the whole repo's call-graph build.
            if _alias_chain is None:
                _alias_chain = {call_name}
            if resolved_name not in _alias_chain:
                _alias_chain.add(resolved_name)
                # Try resolving the aliased name instead
                result = self._resolve_call(resolved_name, caller_file,
                                            _alias_chain=_alias_chain)
                if result:
                    return result

        # 1. Same-file functions
        same_file_match = self._resolve_same_file(call_name, caller_file)
        if same_file_match:
            return same_file_match

        # 2. Functions in included headers
        included_files = self.include_map.get(caller_file, set())
        # Iterate in sorted order so resolution is deterministic regardless of
        # set-iteration order (PYTHONHASHSEED); stable lexicographic tiebreak on file path
        # when same-basename headers in different dirs define the same function name.
        for inc_file in sorted(included_files):
            file_funcs = self.functions_by_file.get(inc_file, [])
            for func_id in file_funcs:
                func_data = self.functions.get(func_id, {})
                fname = func_data.get('name', '')
                base_name = fname.split('::')[-1] if '::' in fname else fname
                # A function in an INCLUDED header is callable from the including
                # TU regardless of `static`: a `static inline` header helper (the
                # C header-inline idiom) is copied into every includer. The
                # cross-file static-linkage rejection in _is_visible_from is
                # correct only for a .c TU, so it must not gate an included-header
                # candidate. (Repo-wide and prototype fallbacks below stay strict.)
                header_candidate = func_data.get('file_path', '').endswith(
                    ('.h', '.hpp', '.hxx', '.hh')
                )
                if base_name == call_name and (
                    header_candidate or self._is_visible_from(func_id, caller_file)
                ):
                    return func_id

        # 3. Unique name match across entire repo
        candidates = self.functions_by_name.get(call_name, [])
        # Do not resolve a call to a file-local (static) definition in a
        # different translation unit; the repo-wide fallback previously ignored linkage.
        if len(candidates) == 1 and self._is_visible_from(candidates[0], caller_file):
            return candidates[0]

        # 4. If prototype exists, try to find the definition
        if call_name in self.prototypes:
            proto = self.prototypes[call_name]
            # Look for a definition (non-header)
            for func_id in candidates:
                func_data = self.functions.get(func_id, {})
                fp = func_data.get('file_path', '')
                ext = Path(fp).suffix.lower()
                if ext in {'.c', '.cpp', '.cc', '.cxx'} and self._is_visible_from(func_id, caller_file):
                    return func_id

        return None

    @staticmethod
    def _strip_comments_and_literals(code: str) -> str:
        """Blank out C comments and string/char literals, preserving length and
        newlines.

        The regex fallback scanned raw code, so a call-shaped token inside
        a // or /* */ comment or a "..." / '...' literal produced a phantom edge.
        Replacing those regions with spaces (newlines kept) removes the false matches
        without disturbing offsets.
        """
        out = []
        i, n = 0, len(code)
        while i < n:
            c = code[i]
            nxt = code[i + 1] if i + 1 < n else ''
            if c == '/' and nxt == '/':
                while i < n and code[i] != '\n':
                    out.append(' ')
                    i += 1
            elif c == '/' and nxt == '*':
                out.append('  ')
                i += 2
                while i < n and not (code[i] == '*' and i + 1 < n and code[i + 1] == '/'):
                    out.append('\n' if code[i] == '\n' else ' ')
                    i += 1
                if i < n:
                    out.append('  ')
                    i += 2
            elif c in ('"', "'"):
                quote = c
                out.append(' ')
                i += 1
                while i < n and code[i] != quote:
                    if code[i] == '\\' and i + 1 < n:
                        out.append('  ')
                        i += 2
                        continue
                    out.append('\n' if code[i] == '\n' else ' ')
                    i += 1
                if i < n:
                    out.append(' ')
                    i += 1
            else:
                out.append(c)
                i += 1
        return ''.join(out)

    def _extract_calls_regex(self, code: str, caller_id: str) -> Set[str]:
        """Fallback regex-based call extraction."""
        calls = set()
        caller_file = caller_id.split(':')[0]

        code = self._strip_comments_and_literals(code)
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        for match in re.finditer(pattern, code):
            func_name = match.group(1)
            # Skip C keywords that look like function calls
            if func_name in ('if', 'while', 'for', 'switch', 'return', 'sizeof',
                             'typeof', 'alignof', 'offsetof', 'case', 'else'):
                continue
            # No _is_stdlib gate here: _resolve_call applies the same-file-first
            # rule and the stdlib filter internally, so a user function whose
            # name collides with a builtin still resolves (same leak as the
            # tree-sitter path otherwise).
            resolved = self._resolve_call(func_name, caller_file)
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
            'includes': self.includes,
            'macros': self.macros,
            'macro_aliases': self.macro_aliases,
            'prototypes': self.prototypes,
            'call_graph': self.call_graph,
            'reverse_call_graph': self.reverse_call_graph,
            'statistics': self.get_statistics(),
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Build call graphs from extracted C/C++ function data',
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
