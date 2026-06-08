"""
Stage 3: Call Graph Builder for Zig

Builds bidirectional call graphs showing function dependencies.
"""

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

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
        # Populated by build_call_graph(); read via the canonical API (export/get_statistics/...).
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}

    def build_call_graph(self) -> None:
        """Build the bidirectional call graph, populating self.call_graph / self.reverse_call_graph.

        Canonical API (parity with the c/php/python/ruby CallGraphBuilder): mutates state and returns
        None. Read results via export() / get_statistics() / get_dependencies() / get_callers().
        """
        call_graph: Dict[str, List[str]] = defaultdict(list)
        reverse_call_graph: Dict[str, List[str]] = defaultdict(list)

        name_to_ids = self._build_name_index()

        # Build per-file simple const fn-alias bindings (`const f = handler;`)
        # so that a later `f()` resolves to `handler`.
        alias_to_target = self._build_alias_index(name_to_ids)

        for func_id, func_info in self.functions.items():
            code = func_info.get("code", "")
            file_path = func_info.get("file_path", "")

            calls = self._find_calls_in_code(code, file_path)

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

        self.call_graph = dict(call_graph)
        self.reverse_call_graph = dict(reverse_call_graph)

    def build(self) -> Dict[str, Any]:
        """Back-compat wrapper: build the graph and return the exported dict.

        Retained because the pipeline (zig/test_pipeline.py) calls build() and consumes its return
        value; new code should use build_call_graph() + export() to match the canonical API.
        """
        self.build_call_graph()
        return self.export()

    def export(self) -> Dict[str, Any]:
        """Export the call graph in the canonical schema."""
        return {
            "repository": self.repository,
            "functions": self.functions,
            "classes": self.classes,
            "imports": self.imports,
            "call_graph": self.call_graph,
            "reverse_call_graph": self.reverse_call_graph,
            "statistics": self.get_statistics(),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Compute call-graph statistics (parity with the canonical builders, incl. in-degree)."""
        total_edges = sum(len(callees) for callees in self.call_graph.values())
        num_funcs = len(self.functions)
        out_degrees = [len(self.call_graph.get(f, [])) for f in self.functions]
        in_degrees = [len(self.reverse_call_graph.get(f, [])) for f in self.functions]
        isolated = sum(
            1
            for f in self.functions
            if not self.call_graph.get(f) and not self.reverse_call_graph.get(f)
        )
        return {
            "total_functions": num_funcs,
            "total_edges": total_edges,
            "avg_out_degree": round(total_edges / num_funcs, 2) if num_funcs else 0,
            "avg_in_degree": round(total_edges / num_funcs, 2) if num_funcs else 0,
            "max_out_degree": max(out_degrees) if out_degrees else 0,
            "max_in_degree": max(in_degrees) if in_degrees else 0,
            "isolated_functions": isolated,
        }

    def get_dependencies(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get transitive callees of func_id up to depth (BFS); parity with canonical."""
        max_d = depth if depth is not None else 3
        deps: List[str] = []
        visited = {func_id}
        queue = [(func_id, 0)]
        while queue:
            current, d = queue.pop(0)
            if d >= max_d:
                continue
            for callee in self.call_graph.get(current, []):
                if callee not in visited:
                    visited.add(callee)
                    deps.append(callee)
                    queue.append((callee, d + 1))
        return deps

    def get_callers(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get transitive callers of func_id up to depth (BFS); parity with canonical."""
        max_d = depth if depth is not None else 3
        callers: List[str] = []
        visited = {func_id}
        queue = [(func_id, 0)]
        while queue:
            current, d = queue.pop(0)
            if d >= max_d:
                continue
            for caller in self.reverse_call_graph.get(current, []):
                if caller not in visited:
                    visited.add(caller)
                    callers.append(caller)
                    queue.append((caller, d + 1))
        return callers

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
        if node.type in ("call_expression", "call_expr", "CallExpr"):
            # The callee is the first child: an `identifier` for a plain call foo(), or a
            # `field_expression` for a method/namespaced call obj.method() / mod.func().
            callee = node.children[0] if node.children else None
            if callee is not None and callee.type in ("identifier", "IDENTIFIER"):
                calls.add(self._get_node_text(callee, source))
            elif callee is not None and callee.type in ("field_expression", "field_access"):
                # The method name is the trailing identifier child. Prefer that
                # over text-splitting, which is brittle when the receiver itself
                # contains punctuation (e.g. `C{}.m`).
                method_name = None
                for sub in callee.children:
                    if sub.type in ("identifier", "IDENTIFIER"):
                        method_name = self._get_node_text(sub, source)
                text = self._get_node_text(callee, source)
                calls.add(method_name if method_name else text.split(".")[-1])
                calls.add(text)  # also the full dotted form
        elif node.type == "builtin_function":
            # @call(.modifier, realFn, argsTuple): the wrapped function is the real call target;
            # other @builtins are filtered out downstream.
            self._extract_builtin_call_target(node, source, calls)

        # Recurse into children
        for child in node.children:
            self._extract_calls_from_node(child, source, calls)

    def _extract_builtin_call_target(
        self, node: Node, source: bytes, calls: Set[str]
    ) -> None:
        """For Zig `@call(.modifier, fn, args)`, add `fn` as a call target (other @builtins: no-op)."""
        builtin = ""
        args = None
        for child in node.children:
            if child.type == "builtin_identifier":
                builtin = self._get_node_text(child, source)
            elif child.type == "arguments":
                args = child
        if builtin != "@call" or args is None:
            return
        # arguments: '(' , <.modifier field_expression> , ',' , <fn identifier/field_expression> , ...
        for child in args.children:
            if child.type not in ("identifier", "field_expression"):
                continue
            text = self._get_node_text(child, source)
            if text.startswith("."):
                continue  # the leading `.auto`/`.always_inline` call modifier, not the function
            calls.add(text.split(".")[-1])
            calls.add(text)
            return

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

        # 2. Check imported files. Match by the imported FILE name (not an unanchored substring),
        # and skip non-file stdlib imports (@import("std")/("builtin")/("root")) which would
        # otherwise substring-match unrelated candidate paths.
        file_imports = self.imports.get(caller_file, [])
        for candidate in candidates:
            candidate_file = candidate.split(":")[0]
            for imp in file_imports:
                if not imp.endswith(".zig"):
                    continue  # std / builtin / root are not file imports
                if candidate_file == imp or candidate_file.endswith("/" + imp):
                    return [candidate]

        # 3. If unique match, use it
        if len(candidates) == 1:
            return candidates

        # 4. Ambiguous across multiple files with no import resolving it. Do NOT emit edges to every
        # same-named symbol -- that over-connection is a namespace leak (a.deinit() would link to
        # every struct's deinit). Resolving the receiver's type needs info the extractor does not
        # carry, so the precise target is unknown; return nothing rather than over-connect.
        # Trade-off: lowers recall for genuinely-ambiguous bare-name calls to raise precision.
        return []

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        """Save call graph to a JSON file."""
        write_json(output_path, results)
