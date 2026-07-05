#!/usr/bin/env python3
"""
Function Extractor for C/C++ Codebases

Extracts ALL functions from C/C++ source files using tree-sitter.
This is Phase 2 of the C/C++ parser - function inventory.

Usage:
    python function_extractor.py <repo_path> [--output <file>] [--scan-file <scan.json>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "extraction_time": "2025-12-30T...",
        "functions": {
            "file.c:function_name": {
                "name": "function_name",
                "file_path": "file.c",
                "start_line": 10,
                "end_line": 25,
                "code": "int function_name(...) { ... }",
                "parameters": ["int x", "char *y"],
                "return_type": "int",
                "is_static": false,
                "is_exported": true,
                "unit_type": "function"
            }
        },
        "includes": { "file.c": ["openssl/ssl.h", "stdio.h"] },
        "macros": { "file.c": [{"name": "MACRO", "body": "..."}] },
        "statistics": { ... }
    }
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())

C_EXTENSIONS = {'.c', '.h'}
CPP_EXTENSIONS = {'.cpp', '.hpp', '.cc', '.cxx', '.hxx', '.hh'}


class FunctionExtractor:
    """
    Extract all functions from C/C++ source files using tree-sitter.

    This is Stage 2 of the C/C++ parser pipeline.
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.functions: Dict[str, Dict] = {}
        self.includes: Dict[str, List[str]] = {}
        self.macros: Dict[str, List[Dict]] = {}
        self.macro_aliases: Dict[str, str] = {}  # e.g. OPENSSL_malloc -> CRYPTO_malloc
        self.prototypes: Dict[str, Dict] = {}  # function name -> declaration info
        # class/struct name -> list of direct base-class names, for inheritance
        # walks in member dispatch (bug [30]). Populated from the
        # base_class_clause of each class_specifier/struct_specifier.
        self.class_bases: Dict[str, List[str]] = {}

        self.c_parser = Parser(C_LANGUAGE)
        self.cpp_parser = Parser(CPP_LANGUAGE)

        self.file_cache: Dict[str, bytes] = {}

        self.stats = {
            'total_functions': 0,
            'total_prototypes': 0,
            'inline_functions': 0,
            'static_functions': 0,
            'files_processed': 0,
            'files_with_errors': 0,
            'by_type': {},
        }

    def _get_parser(self, file_path: str) -> Parser:
        """Get the appropriate parser for a file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in CPP_EXTENSIONS:
            return self.cpp_parser
        return self.c_parser

    def _is_cpp_file(self, file_path: str) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        return ext in CPP_EXTENSIONS

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

    def _get_function_name(self, node, source: bytes) -> Optional[str]:
        """Extract function name from a function_definition node."""
        # Look for the declarator
        declarator = node.child_by_field_name('declarator')
        if declarator is None:
            return None
        return self._extract_identifier_from_declarator(declarator, source)

    def _extract_identifier_from_declarator(self, node, source: bytes) -> Optional[str]:
        """Recursively find the identifier in a declarator."""
        if node.type == 'identifier':
            return self._node_text(node, source)
        if node.type == 'field_identifier':
            return self._node_text(node, source)
        if node.type == 'destructor_name':
            return '~' + self._node_text(node, source).lstrip('~')

        # function_declarator -> declarator child
        if node.type == 'function_declarator':
            inner = node.child_by_field_name('declarator')
            if inner:
                return self._extract_identifier_from_declarator(inner, source)

        # pointer_declarator -> declarator child
        if node.type == 'pointer_declarator':
            inner = node.child_by_field_name('declarator')
            if inner:
                return self._extract_identifier_from_declarator(inner, source)

        # parenthesized_declarator
        if node.type == 'parenthesized_declarator':
            for child in node.children:
                result = self._extract_identifier_from_declarator(child, source)
                if result:
                    return result

        # qualified_identifier (C++ namespace::name)
        if node.type == 'qualified_identifier':
            return self._node_text(node, source)

        # operator overload (operator+, operator==, operator[], ...)
        if node.type == 'operator_name':
            return self._node_text(node, source)

        # conversion operator (operator int, operator MyType)
        if node.type == 'operator_cast':
            return self._node_text(node, source)

        # template_function: g<int> — keep the template arguments so an
        # explicit specialization does not collide with the primary template.
        if node.type == 'template_function':
            return self._node_text(node, source)

        # reference_declarator (C++ int& func())
        if node.type == 'reference_declarator':
            for child in node.children:
                result = self._extract_identifier_from_declarator(child, source)
                if result:
                    return result

        # structured_binding_declarator
        if node.type == 'structured_binding_declarator':
            return None

        # Fallback: search children
        for child in node.children:
            if child.type in ('identifier', 'field_identifier', 'qualified_identifier',
                              'function_declarator', 'pointer_declarator',
                              'parenthesized_declarator', 'destructor_name',
                              'template_function', 'reference_declarator',
                              'operator_name', 'operator_cast'):
                result = self._extract_identifier_from_declarator(child, source)
                if result:
                    return result

        return None

    def _get_return_type(self, node, source: bytes) -> str:
        """Extract return type from a function_definition node."""
        type_node = node.child_by_field_name('type')
        if type_node:
            return self._node_text(type_node, source)
        # Check for type specifiers before the declarator
        parts = []
        for child in node.children:
            if child == node.child_by_field_name('declarator'):
                break
            if child.type == 'body' or child.type == 'compound_statement':
                break
            if child.type in ('storage_class_specifier', 'type_qualifier'):
                continue  # skip static, const etc. for return type
            if child.type not in ('comment', '{', '}', ';'):
                parts.append(self._node_text(child, source))
        return ' '.join(parts) if parts else 'void'

    def _get_parameters(self, node, source: bytes) -> List[str]:
        """Extract parameters from a function_definition node."""
        declarator = node.child_by_field_name('declarator')
        if declarator is None:
            return []

        # Find the function_declarator
        func_decl = self._find_function_declarator(declarator)
        if func_decl is None:
            return []

        params_node = func_decl.child_by_field_name('parameters')
        if params_node is None:
            return []

        params = []
        for child in params_node.children:
            if child.type == 'parameter_declaration':
                params.append(self._node_text(child, source))
            elif child.type == 'variadic_parameter':
                params.append('...')
        return params

    @staticmethod
    def _signature_discriminator(parameters: List[str]) -> str:
        """A deterministic, COLON-FREE signature string for the parameter list.

        Colon-free is mandatory: the func_id is split on ':' downstream
        (`core/diff_filter.py`, `utilities/agentic_enhancer/repository_index.py`
        rsplit on ':' to recover the file), so any colon a C++ type carries
        (`std::string`, a ternary default arg) is mapped to '.' here.
        """
        joined = ','.join(p.strip() for p in parameters)
        joined = ' '.join(joined.split())  # collapse newlines/runs of whitespace
        return joined.replace(':', '.')

    @staticmethod
    def _same_signature(a: dict, b: dict) -> bool:
        """Two definitions share a signature iff their parameter lists match.

        Identical params => a redefinition of the SAME function under a different
        preprocessor branch (#ifdef/#else) or an ODR-duplicate. Different params
        => a genuine C++ overload.
        """
        return a.get('parameters', []) == b.get('parameters', [])

    def _store_function(self, func_id: str, func_data: dict) -> None:
        """Store a function, disambiguating same-(file,name) collisions instead
        of silently overwriting (Bug 1: #ifdef/#else stubs and C++ overloads
        collapsed onto one node — see reachability-bugs.md / bug-3482.md).

        Collision-only: when func_id is free, store byte-identically (the
        hardcoded `path:name` id literals across the suite depend on unique names
        keeping the plain `path:name` id). On a collision:
          - SAME signature -> keep ONE node, prefer the larger body. The #else
            stub is shorter than the real implementation regardless of which
            preprocessor arm tree-sitter emits first, so this is order- and
            direction-independent.
          - DIFFERENT signature -> a genuine overload; both are real. Mint a
            distinct key by folding the colon-free signature into the func_id.
            The `name` field is left bare (`area`, not `area(int,int)`) because
            the call-graph builder resolves calls by `name` (functions_by_name),
            so both overloads stay findable. (Contrast bug [39], which folds the
            template-arg discriminator into the NAME — correct there because a
            template call is written `g<int>`; an overload call is written bare.)
        """
        existing = self.functions.get(func_id)
        if existing is None:
            self.functions[func_id] = func_data
            return
        if self._same_signature(existing, func_data):
            if len(func_data.get('code', '')) > len(existing.get('code', '')):
                self.functions[func_id] = func_data
            return
        overload_id = f"{func_id}({self._signature_discriminator(func_data.get('parameters', []))})"
        prior = self.functions.get(overload_id)
        if prior is None or len(func_data.get('code', '')) > len(prior.get('code', '')):
            self.functions[overload_id] = func_data

    def _find_function_declarator(self, node):
        """Find the function_declarator within a declarator tree."""
        if node.type == 'function_declarator':
            return node
        for child in node.children:
            result = self._find_function_declarator(child)
            if result:
                return result
        return None

    def _is_static(self, node, source: bytes) -> bool:
        """Check if a function has the static storage class specifier."""
        for child in node.children:
            if child == node.child_by_field_name('declarator'):
                break
            if child.type == 'storage_class_specifier' and self._node_text(child, source) == 'static':
                return True
        return False

    def _has_inline(self, node, source: bytes) -> bool:
        """Check if a function has the inline specifier."""
        for child in node.children:
            if child == node.child_by_field_name('declarator'):
                break
            if child.type == 'storage_class_specifier' and self._node_text(child, source) == 'inline':
                return True
            # GCC attribute
            text = self._node_text(child, source)
            if '__inline' in text:
                return True
        return False

    def _classify_function(self, name: str, file_path: str, is_static: bool,
                           code: str, is_cpp: bool, class_name: Optional[str]) -> str:
        """Classify a function by its type/purpose."""
        if name == 'main':
            return 'main'

        if is_cpp and class_name:
            # Compare the UNqualified leaves: an out-of-line definition arrives
            # as a qualified name (e.g. 'Foo::Foo', 'Foo::~Foo') whose whole
            # string never equals the bare class_name.
            unqualified = name.rsplit('::', 1)[-1]
            class_leaf = class_name.rsplit('::', 1)[-1]
            if unqualified.startswith('~'):
                return 'destructor'
            if unqualified == class_leaf:
                return 'constructor'
            return 'method'

        if '__attribute__((constructor))' in code:
            return 'constructor'
        if '__attribute__((destructor))' in code:
            return 'destructor'

        path_lower = file_path.lower()
        if path_lower.startswith('apps/') or path_lower.startswith('apps\\'):
            if 'argc' in code and 'argv' in code:
                return 'cli_handler'

        if '_set_' in name and ('_callback' in name or '_func' in name):
            return 'callback'

        if is_static:
            return 'static_function'

        return 'function'

    def _get_class_name_from_qualified(self, name: str) -> Optional[str]:
        """Extract class name from C++ qualified name like ClassName::method."""
        if '::' in name:
            parts = name.split('::')
            if len(parts) >= 2:
                return '::'.join(parts[:-1])
        return None

    def _extract_base_classes(self, record_node, source: bytes) -> List[str]:
        """Return the direct base-class names of a class/struct specifier.

        tree-sitter represents inheritance as a `base_class_clause` child of the
        class_specifier/struct_specifier (sibling of name and body). The clause
        holds one `type_identifier` per base, interleaved with optional
        access_specifier / `virtual` / `,` tokens; we collect only the simple
        `type_identifier` bases. Qualified or templated bases (ns::Base,
        Base<T>) are NOT recorded — matching the same-name keying used for
        class_name elsewhere, so the inheritance walk stays sound (an unknown
        base simply yields no edge rather than a wrong one).
        """
        bases: List[str] = []
        for child in record_node.children:
            if child.type != 'base_class_clause':
                continue
            for sub in child.children:
                if sub.type == 'type_identifier':
                    bases.append(self._node_text(sub, source))
        return bases

    def _extract_includes(self, tree, source: bytes) -> List[str]:
        """Extract #include directives from a file."""
        includes = []
        stack = [tree.root_node]

        while stack:
            node = stack.pop()
            if node.type == 'preproc_include':
                path_node = node.child_by_field_name('path')
                if path_node:
                    inc_text = self._node_text(path_node, source)
                    # Strip quotes or angle brackets
                    inc_text = inc_text.strip('"<> ')
                    includes.append(inc_text)
            stack.extend(reversed(node.children))

        return includes

    def _extract_macros(self, tree, source: bytes) -> List[Dict]:
        """Extract #define macros from a file."""
        macros_list = []
        stack = [tree.root_node]

        while stack:
            node = stack.pop()
            if node.type == 'preproc_def':
                name_node = node.child_by_field_name('name')
                value_node = node.child_by_field_name('value')
                if name_node:
                    macro_name = self._node_text(name_node, source)
                    macro_body = self._node_text(value_node, source) if value_node else ''
                    macros_list.append({
                        'name': macro_name,
                        'body': macro_body.strip(),
                    })
            elif node.type == 'preproc_function_def':
                name_node = node.child_by_field_name('name')
                value_node = node.child_by_field_name('value')
                params_node = node.child_by_field_name('parameters')
                if name_node:
                    macro_name = self._node_text(name_node, source)
                    macro_body = self._node_text(value_node, source) if value_node else ''
                    params_text = self._node_text(params_node, source) if params_node else ''
                    macros_list.append({
                        'name': macro_name,
                        'body': macro_body.strip(),
                        'parameters': params_text,
                    })
                    # Track function-like macro aliases
                    # e.g. #define OPENSSL_malloc(size) CRYPTO_malloc(size, ...)
                    body_stripped = macro_body.strip()
                    if body_stripped and '(' in body_stripped:
                        # Extract the called function name
                        called = body_stripped.split('(')[0].strip()
                        if called.isidentifier():
                            self.macro_aliases[macro_name] = called

            stack.extend(reversed(node.children))

        return macros_list

    def _extract_functions_from_tree(self, tree, source: bytes, file_path: str,
                                      relative_path: str, is_cpp: bool) -> None:
        """Extract all function definitions from a parsed tree."""
        is_header = os.path.splitext(file_path)[1].lower() in ('.h', '.hpp', '.hxx', '.hh')

        # Iterative traversal with explicit stack carrying
        # (node, namespace_prefix, class_context). namespace_prefix is the
        # qualified prefix used to build the func_id; class_context is the
        # enclosing class/struct/union name (or None) used for metadata so a
        # namespace qualifier is never mistaken for a class qualifier.
        stack = [(tree.root_node, '', None)]

        # struct/union member functions are C++ methods exactly like class
        # members; only `class_specifier` was special-cased originally.
        record_specifiers = ('class_specifier', 'struct_specifier', 'union_specifier')

        while stack:
            node, namespace_prefix, class_context = stack.pop()

            if node.type == 'function_definition':
                self._process_function_node(node, source, relative_path,
                                            is_cpp, is_header, namespace_prefix,
                                            class_context)

            elif node.type == 'declaration' and not is_header:
                # Standalone declarations in .c/.cpp files are prototypes, EXCEPT
                # a declaration whose initializer is a lambda — a named callable.
                if is_cpp:
                    self._process_lambda_declaration(node, source, relative_path,
                                                     namespace_prefix)

            elif node.type == 'declaration' and is_header:
                # In headers, track prototypes for call resolution
                self._process_declaration_node(node, source, relative_path)
                if is_cpp:
                    self._process_lambda_declaration(node, source, relative_path,
                                                     namespace_prefix)

            elif node.type == 'namespace_definition' and is_cpp:
                ns_name_node = node.child_by_field_name('name')
                ns_name = self._node_text(ns_name_node, source) if ns_name_node else ''
                new_prefix = f"{namespace_prefix}{ns_name}::" if ns_name else namespace_prefix
                body_node = node.child_by_field_name('body')
                if body_node:
                    for child in reversed(body_node.children):
                        # class_context unchanged: a namespace is NOT a class.
                        stack.append((child, new_prefix, class_context))
                continue  # Don't walk children again

            elif node.type in record_specifiers and is_cpp:
                class_name_node = node.child_by_field_name('name')
                if class_name_node:
                    class_name = self._node_text(class_name_node, source)
                    new_prefix = f"{namespace_prefix}{class_name}::"
                    # Record direct base classes for the inheritance walk in
                    # member dispatch (bug [30]). Keyed by the bare class name
                    # (matching the class_name stored on each method).
                    bases = self._extract_base_classes(node, source)
                    if bases:
                        existing = self.class_bases.setdefault(class_name, [])
                        for base in bases:
                            if base not in existing:
                                existing.append(base)
                    body_node = node.child_by_field_name('body')
                    if body_node:
                        for child in reversed(body_node.children):
                            if child.type == 'function_definition':
                                self._process_function_node(
                                    child, source, relative_path,
                                    is_cpp, is_header, new_prefix, class_name
                                )
                            elif child.type == 'access_specifier':
                                pass
                            else:
                                stack.append((child, new_prefix, class_name))
                continue

            else:
                for child in reversed(node.children):
                    stack.append((child, namespace_prefix, class_context))

    def _process_function_node(self, node, source: bytes, relative_path: str,
                                is_cpp: bool, is_header: bool,
                                namespace_prefix: str = '',
                                class_context: Optional[str] = None) -> None:
        """Process a single function_definition node."""
        name = self._get_function_name(node, source)
        if not name:
            return

        full_name = namespace_prefix + name if namespace_prefix and '::' not in name else name
        # class_name comes from the lexical enclosing class/struct/union
        # (class_context) OR from a qualifier written in the source name
        # (out-of-line def: Foo::method). A namespace qualifier in
        # namespace_prefix must NOT become a class_name.
        if class_context is not None:
            class_name = class_context
        elif '::' in name:
            class_name = self._get_class_name_from_qualified(name)
        else:
            class_name = None

        code = self._node_text(node, source)
        start_line = node.start_point[0] + 1  # tree-sitter is 0-indexed
        end_line = node.end_point[0] + 1
        return_type = self._get_return_type(node, source)
        parameters = self._get_parameters(node, source)
        is_static = self._is_static(node, source)
        is_inline = self._has_inline(node, source)
        is_exported = not is_static

        unit_type = self._classify_function(
            name, relative_path, is_static, code, is_cpp, class_name
        )

        func_id = f"{relative_path}:{full_name}"

        func_data = {
            'name': full_name,
            'file_path': relative_path,
            'start_line': start_line,
            'end_line': end_line,
            'code': code,
            'parameters': parameters,
            'return_type': return_type,
            'is_static': is_static,
            'is_exported': is_exported,
            'is_inline': is_inline,
            'unit_type': unit_type,
            'class_name': class_name,
        }

        self._store_function(func_id, func_data)
        self.stats['total_functions'] += 1

        if is_static:
            self.stats['static_functions'] += 1
        if is_inline:
            self.stats['inline_functions'] += 1

        self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

    def _process_lambda_declaration(self, node, source: bytes, relative_path: str,
                                    namespace_prefix: str = '') -> None:
        """Extract a named lambda from a declaration (auto f = [](){...};).

        A lambda is a `lambda_expression` initializer inside an
        `init_declarator`; the declaration node is otherwise skipped by the
        traversal, so the callable would never be recorded as a unit.
        """
        # A declaration may declare several init_declarators.
        stack = list(node.children)
        while stack:
            child = stack.pop()
            if child.type != 'init_declarator':
                stack.extend(child.children)
                continue

            value_node = child.child_by_field_name('value')
            if value_node is None or value_node.type != 'lambda_expression':
                continue

            decl_node = child.child_by_field_name('declarator')
            name = (self._extract_identifier_from_declarator(decl_node, source)
                    if decl_node is not None else None)
            if not name:
                continue

            full_name = (namespace_prefix + name
                         if namespace_prefix and '::' not in name else name)
            func_id = f"{relative_path}:{full_name}"
            self._store_function(func_id, {
                'name': full_name,
                'file_path': relative_path,
                'start_line': node.start_point[0] + 1,
                'end_line': node.end_point[0] + 1,
                'code': self._node_text(node, source),
                'parameters': self._get_parameters(value_node, source),
                'return_type': 'auto',
                'is_static': False,
                'is_exported': False,
                'is_inline': False,
                'unit_type': 'lambda',
                'class_name': None,
            })
            self.stats['total_functions'] += 1
            self.stats['by_type']['lambda'] = self.stats['by_type'].get('lambda', 0) + 1

    def _process_declaration_node(self, node, source: bytes, relative_path: str) -> None:
        """Process a declaration node in a header to track prototypes."""
        # Look for function declarations (prototypes)
        declarator = node.child_by_field_name('declarator')
        if declarator is None:
            return

        func_decl = self._find_function_declarator(declarator)
        if func_decl is None:
            return

        name = self._extract_identifier_from_declarator(declarator, source)
        if not name:
            return

        self.prototypes[name] = {
            'name': name,
            'file_path': relative_path,
            'start_line': node.start_point[0] + 1,
        }
        self.stats['total_prototypes'] += 1

    def process_file(self, file_path: Path) -> None:
        """Process a single C/C++ file."""
        source = self.read_file(file_path)
        if not source:
            self.stats['files_with_errors'] += 1
            return

        relative_path = file_path.relative_to(self.repo_path).as_posix()
        is_cpp = self._is_cpp_file(str(file_path))
        parser = self._get_parser(str(file_path))

        try:
            tree = parser.parse(source)
        except Exception as e:
            print(f"Parse error in {file_path}: {e}", file=sys.stderr)
            self.stats['files_with_errors'] += 1
            return

        self.stats['files_processed'] += 1

        # Extract includes
        self.includes[relative_path] = self._extract_includes(tree, source)

        # Extract macros
        file_macros = self._extract_macros(tree, source)
        if file_macros:
            self.macros[relative_path] = file_macros

        # Extract functions
        self._extract_functions_from_tree(tree, source, str(file_path),
                                           relative_path, is_cpp)

    def extract_from_scan(self, scan_result: Dict) -> Dict:
        """Extract functions from files listed in a scan result."""
        for file_info in scan_result.get('files', []):
            file_path = self.repo_path / file_info['path']
            self.process_file(file_path)

        return self.export()

    def extract_all(self, files: Optional[List[str]] = None) -> Dict:
        """Extract functions from all C/C++ files or a specific list."""
        if files:
            for file_rel_path in files:
                file_path = self.repo_path / file_rel_path
                if file_path.exists():
                    self.process_file(file_path)
        else:
            all_extensions = C_EXTENSIONS | CPP_EXTENSIONS
            for ext in all_extensions:
                for file_path in self.repo_path.rglob(f'*{ext}'):
                    # Exclude on path COMPONENTS relative to repo_path, not a substring of the absolute
                    # path. A substring test wrongly skips files whose path merely contains a token
                    # ('src/latest/main.c', 'contest/sol.c' contain 'test') and is poisoned when an
                    # ancestor of repo_path contains one (a checkout under '/home/tester/' excludes all).
                    if {'.git', 'build', 'test', 'node_modules'} & set(file_path.relative_to(self.repo_path).parts):
                        continue
                    self.process_file(file_path)

        return self.export()

    def export(self) -> Dict:
        """Export extraction results."""
        return {
            'repository': str(self.repo_path),
            'extraction_time': datetime.now().isoformat(),
            'functions': self.functions,
            'includes': self.includes,
            'macros': self.macros,
            'macro_aliases': self.macro_aliases,
            'prototypes': self.prototypes,
            'class_bases': self.class_bases,
            'statistics': self.stats,
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Extract all functions from a C/C++ repository',
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
            print(f"  Static: {result['statistics']['static_functions']}", file=sys.stderr)
            print(f"  Inline: {result['statistics']['inline_functions']}", file=sys.stderr)
            print(f"  Prototypes tracked: {result['statistics']['total_prototypes']}", file=sys.stderr)
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
