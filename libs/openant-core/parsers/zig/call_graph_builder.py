"""
Stage 3: Call Graph Builder for Zig

Builds bidirectional call graphs showing function dependencies.
"""

import re
from collections import defaultdict
from typing import Dict, Any, List, Set

from utilities.file_io import write_json

import tree_sitter_zig as ts_zig
from tree_sitter import Language, Parser, Node


class CallGraphBuilder:
    """Builds call graphs from extracted Zig functions."""

    ZIG_LANGUAGE = Language(ts_zig.language())

    # Zig standard library and builtin functions to filter out
    ZIG_BUILTINS = {
        # Builtin functions
        "@import",
        "@as",
        "@intCast",
        "@floatCast",
        "@ptrCast",
        "@alignCast",
        "@enumFromInt",
        "@intFromEnum",
        "@intFromPtr",
        "@ptrFromInt",
        "@errorName",
        "@tagName",
        "@typeName",
        "@typeInfo",
        "@Type",
        "@sizeOf",
        "@alignOf",
        "@bitSizeOf",
        "@offsetOf",
        "@fieldParentPtr",
        "@hasField",
        "@hasDecl",
        "@field",
        "@call",
        "@src",
        "@This",
        "@min",
        "@max",
        "@add",
        "@sub",
        "@mul",
        "@div",
        "@rem",
        "@mod",
        "@shl",
        "@shr",
        "@bitReverse",
        "@byteSwap",
        "@truncate",
        "@reduce",
        "@shuffle",
        "@select",
        "@splat",
        "@memcpy",
        "@memset",
        "@ctz",
        "@clz",
        "@popCount",
        "@abs",
        "@sqrt",
        "@sin",
        "@cos",
        "@tan",
        "@exp",
        "@exp2",
        "@log",
        "@log2",
        "@log10",
        "@floor",
        "@ceil",
        "@round",
        "@mulAdd",
        "@panic",
        "@compileError",
        "@compileLog",
        "@breakpoint",
        "@returnAddress",
        "@frameAddress",
        "@cmpxchgStrong",
        "@cmpxchgWeak",
        "@atomicLoad",
        "@atomicStore",
        "@atomicRmw",
        "@fence",
        "@prefetch",
        "@setCold",
        "@setRuntimeSafety",
        "@setEvalBranchQuota",
        "@setFloatMode",
        "@setAlignStack",
        "@errorReturnTrace",
        "@asyncCall",
        "@cDefine",
        "@cInclude",
        "@cUndef",
        "@embedFile",
        "@export",
        "@extern",
        "@unionInit",
        "@wasmMemorySize",
        "@wasmMemoryGrow",
        # Common std functions
        "print",
        "println",
        "debug",
        "assert",
        "expect",
        "expectEqual",
        "expectError",
        "expectFmt",
        "expectEqualSlices",
        "expectEqualStrings",
        "allocPrint",
        "allocPrintZ",
        "bufPrint",
        "bufPrintZ",
        "comptimePrint",
    }

    def __init__(self, extractor_output: Dict[str, Any]):
        self.functions = extractor_output.get("functions", {})
        self.classes = extractor_output.get("classes", {})
        self.imports = extractor_output.get("imports", {})
        self.repository = extractor_output.get("repository", "")
        self.parser = Parser(self.ZIG_LANGUAGE)

    def build(self) -> Dict[str, Any]:
        """
        Build the call graph.

        Returns call_graph.json structure with:
        - functions (copied from extractor)
        - classes (copied from extractor)
        - imports (copied from extractor)
        - call_graph: {caller_id: [callee_ids]}
        - reverse_call_graph: {callee_id: [caller_ids]}
        """
        call_graph: Dict[str, List[str]] = defaultdict(list)
        reverse_call_graph: Dict[str, List[str]] = defaultdict(list)

        # Build an index of function names to IDs for resolution
        name_to_ids = self._build_name_index()

        # Build per-file simple const fn-alias bindings (`const f = handler;`)
        # so that a later `f()` resolves to `handler`.
        alias_to_target = self._build_alias_index(name_to_ids)

        # For each function, find calls in its body
        for func_id, func_info in self.functions.items():
            code = func_info.get("code", "")
            file_path = func_info.get("file_path", "")

            # Parse the function code to find call sites
            calls = self._find_calls_in_code(code, file_path)

            # Resolve each call to a function ID
            for call_name in calls:
                resolved_ids = self._resolve_call(
                    call_name, file_path, name_to_ids, alias_to_target
                )
                for resolved_id in resolved_ids:
                    if resolved_id != func_id:  # No self-calls
                        if resolved_id not in call_graph[func_id]:
                            call_graph[func_id].append(resolved_id)
                        if func_id not in reverse_call_graph[resolved_id]:
                            reverse_call_graph[resolved_id].append(func_id)

        # Calculate statistics
        total_edges = sum(len(callees) for callees in call_graph.values())
        out_degrees = [len(callees) for callees in call_graph.values()]
        avg_out_degree = total_edges / len(self.functions) if self.functions else 0
        max_out_degree = max(out_degrees) if out_degrees else 0
        isolated = len(
            [
                f
                for f in self.functions
                if f not in call_graph and f not in reverse_call_graph
            ]
        )

        return {
            "repository": self.repository,
            "functions": self.functions,
            "classes": self.classes,
            "imports": self.imports,
            "call_graph": dict(call_graph),
            "reverse_call_graph": dict(reverse_call_graph),
            "statistics": {
                "total_functions": len(self.functions),
                "total_edges": total_edges,
                "avg_out_degree": round(avg_out_degree, 2),
                "max_out_degree": max_out_degree,
                "isolated_functions": isolated,
            },
        }

    def _build_name_index(self) -> Dict[str, List[str]]:
        """Build index from function names to function IDs."""
        name_to_ids: Dict[str, List[str]] = defaultdict(list)

        for func_id, func_info in self.functions.items():
            name = func_info.get("name", "")
            qualified_name = func_info.get("qualified_name", "")

            if name:
                name_to_ids[name].append(func_id)
            if qualified_name and qualified_name != name:
                name_to_ids[qualified_name].append(func_id)

        return name_to_ids

    def _build_alias_index(
        self, name_to_ids: Dict[str, List[str]]
    ) -> Dict[str, Dict[str, str]]:
        """Index simple const fn-aliases per file: `const f = handler;` -> {f: handler}.

        Only bindings whose right-hand side is a bare identifier naming a known
        function are tracked (a genuine fn alias), so arbitrary const dataflow
        (`const x = 1;`) is ignored. Scoped per file to avoid cross-file leaks.
        """
        alias_to_target: Dict[str, Dict[str, str]] = defaultdict(dict)

        for func_info in self.functions.values():
            file_path = func_info.get("file_path", "")
            code = func_info.get("code", "")
            if not code:
                continue
            try:
                tree = self.parser.parse(code.encode("utf-8"))
            except Exception:
                continue
            self._collect_aliases_from_node(
                tree.root_node,
                code.encode("utf-8"),
                name_to_ids,
                alias_to_target[file_path],
            )

        return alias_to_target

    def _collect_aliases_from_node(
        self,
        node: Node,
        source: bytes,
        name_to_ids: Dict[str, List[str]],
        aliases: Dict[str, str],
    ) -> None:
        """Collect `const <alias> = <known-fn>;` bindings from a parse tree."""
        if node.type in ("variable_declaration", "VarDecl"):
            ident_children = [
                c for c in node.children if c.type in ("identifier", "IDENTIFIER")
            ]
            # A simple alias is exactly: const <alias> = <target-identifier>;
            if len(ident_children) == 2:
                alias_name = self._get_node_text(ident_children[0], source)
                target_name = self._get_node_text(ident_children[1], source)
                # Only record when the target is a known function name.
                if alias_name and target_name in name_to_ids:
                    aliases[alias_name] = target_name

        for child in node.children:
            self._collect_aliases_from_node(child, source, name_to_ids, aliases)

    def _find_calls_in_code(self, code: str, caller_file: str = "") -> Set[str]:
        """Find all function calls in a code snippet."""
        calls = set()

        try:
            tree = self.parser.parse(code.encode("utf-8"))
            self._extract_calls_from_node(tree.root_node, code.encode("utf-8"), calls)
        except Exception:
            # Fallback to regex-based extraction
            calls = self._find_calls_with_regex(code)

        # Filter out builtins, but NEVER filter a name that a same-file user
        # function actually defines. A user fn whose name collides with a
        # ZIG_BUILTINS entry (e.g. `expect`) must keep its edge. Scope the
        # shadow check to the caller's own file so a builtin call is not
        # spuriously linked to an unrelated same-named user fn elsewhere.
        shadowing = self._same_file_function_names(caller_file)
        calls = {
            c
            for c in calls
            if c in shadowing or (c not in self.ZIG_BUILTINS and not c.startswith("@"))
        }

        return calls

    def _same_file_function_names(self, caller_file: str) -> Set[str]:
        """Names of user functions defined in `caller_file` (same-file scope)."""
        if not caller_file:
            return set()
        names: Set[str] = set()
        for func_info in self.functions.values():
            if func_info.get("file_path") == caller_file:
                name = func_info.get("name", "")
                if name:
                    names.add(name)
        return names

    def _extract_calls_from_node(
        self, node: Node, source: bytes, calls: Set[str]
    ) -> None:
        """Recursively extract call sites from AST nodes."""
        # Look for function call expressions
        if node.type in ("call_expr", "call_expression", "CallExpr"):
            # Get the function being called
            for child in node.children:
                if child.type in (
                    "identifier",
                    "IDENTIFIER",
                    "field_access",
                    "field_expression",
                ):
                    # For a field access / expression (e.g. `o.m` or `C{}.m`),
                    # the method name is the trailing identifier child. Prefer
                    # that over text-splitting, which is brittle when the
                    # receiver itself contains punctuation (e.g. `C{}.m`).
                    if child.type in ("field_access", "field_expression"):
                        method_name = None
                        for sub in child.children:
                            if sub.type in ("identifier", "IDENTIFIER"):
                                method_name = self._get_node_text(sub, source)
                        if method_name:
                            calls.add(method_name)  # the method name
                        calls.add(self._get_node_text(child, source))  # full path
                        break
                    call_name = self._get_node_text(child, source)
                    # Handle method calls (obj.method)
                    if "." in call_name:
                        parts = call_name.split(".")
                        calls.add(parts[-1])  # Add just the method name
                        calls.add(call_name)  # Also add the full qualified name
                    else:
                        calls.add(call_name)
                    break

        # Recurse into children
        for child in node.children:
            self._extract_calls_from_node(child, source, calls)

    def _find_calls_with_regex(self, code: str) -> Set[str]:
        """Fallback regex-based call detection."""
        calls = set()

        # Pattern for function calls: name(...)
        # Matches: foo(), bar.baz(), self.method()
        pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*\("

        for match in re.finditer(pattern, code):
            call_name = match.group(1)
            if "." in call_name:
                parts = call_name.split(".")
                calls.add(parts[-1])
                calls.add(call_name)
            else:
                calls.add(call_name)

        return calls

    def _get_node_text(self, node: Node, source: bytes) -> str:
        """Get the source text for a node."""
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _resolve_call(
        self,
        call_name: str,
        caller_file: str,
        name_to_ids: Dict[str, List[str]],
        alias_to_target: Dict[str, Dict[str, str]] | None = None,
    ) -> List[str]:
        """
        Resolve a call name to function ID(s).

        Resolution order:
        1. Same file
        2. Imported files
        3. Unique name match
        """
        # Resolve a same-file const fn-alias (`const f = handler; f()`) to its
        # target function name before looking up candidates.
        if alias_to_target is not None:
            target = alias_to_target.get(caller_file, {}).get(call_name)
            if target is not None:
                call_name = target

        candidates = name_to_ids.get(call_name, [])

        if not candidates:
            return []

        # 1. Prefer same file
        same_file = [c for c in candidates if c.startswith(f"{caller_file}:")]
        if same_file:
            return same_file

        # 2. Check imported files
        file_imports = self.imports.get(caller_file, [])
        for candidate in candidates:
            candidate_file = candidate.split(":")[0]
            for imp in file_imports:
                if imp in candidate_file or candidate_file.endswith(imp):
                    return [candidate]

        # 3. If unique match, use it
        if len(candidates) == 1:
            return candidates

        # Multiple matches, return all (conservative)
        return candidates

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        """Save call graph to a JSON file."""
        write_json(output_path, results)
