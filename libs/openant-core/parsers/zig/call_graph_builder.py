"""
Stage 3: Call Graph Builder for Zig

Builds bidirectional call graphs showing function dependencies.
"""

import posixpath
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
        # Contexts whose fallback call-scan input was truncated by the ReDoS budget
        # (scan_budget.py) — the call graph there is KNOWN-INCOMPLETE. See issue #288.
        self.scan_truncated: List[str] = []

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
        # Belt-and-suspenders: the alias index is an over-approximation AID, not
        # essential to producing a call graph. The tree walks it drives are now
        # iterative (no RecursionError), but any residual failure here must
        # degrade GRACEFULLY to an empty alias map rather than abort the whole
        # zig build -- `_resolve_call` reads it via `.get(caller_id, {})`, so an
        # empty dict simply means no alias-based resolution (edges still form via
        # every other path).
        try:
            alias_to_target = self._build_alias_index(name_to_ids)
        except Exception:
            alias_to_target = {}

        for func_id, func_info in self.functions.items():
            code = func_info.get("code", "")
            file_path = func_info.get("file_path", "")

            # Per-body receiver-variable -> static-type model, so `var a = A{}; a.foo()`
            # dispatches to A's foo, not to every same-named foo.
            var_types = self._collect_var_types(code)

            calls = self._find_calls_in_code(code, file_path)

            for call_name in calls:
                resolved_ids = self._resolve_call(
                    call_name, file_path, name_to_ids, alias_to_target, func_id, var_types
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
            "scan_truncated": self.scan_truncated,
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
    ) -> Dict[str, Dict[str, Set[str]]]:
        """Index simple const fn-aliases per function: `const f = handler;` -> {f: {handler}}.

        Only bindings whose right-hand side is a bare identifier naming a known
        function are tracked (a genuine fn alias), so arbitrary const dataflow
        (`const x = 1;`) is ignored. Scoped per FUNCTION (keyed by func_id), not
        per file: two functions in the same file may bind the same alias name to
        different targets (`const doit = foo` vs `const doit = bar`), and each
        caller must resolve to its own target rather than clobbering the other.

        Each alias maps to a SET of targets, not a single one: within one
        function the same alias name may bind to different targets on different
        control-flow paths (`const doit = foo` in one branch, `= bar` in
        another). We over-approximate by keeping every target so a later
        `doit()` resolves to edges for all of them rather than last-wins losing
        one.
        """
        alias_to_target: Dict[str, Dict[str, Set[str]]] = defaultdict(dict)

        for func_id, func_info in self.functions.items():
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
                alias_to_target[func_id],
            )

        return alias_to_target

    def _collect_aliases_from_node(
        self,
        node: Node,
        source: bytes,
        name_to_ids: Dict[str, List[str]],
        aliases: Dict[str, Set[str]],
    ) -> None:
        """Collect `const <alias> = <known-fn>;` bindings from a parse tree.

        ITERATIVE walk over an explicit worklist stack -- deliberately NOT
        self-recursive. A pathologically deep parse tree (deeply nested source)
        would drive a recursive walker past Python's recursion limit and raise
        RecursionError; because _build_alias_index invokes this walk OUTSIDE the
        try/except that guards parsing, that error would propagate up and abort
        the ENTIRE zig call-graph build. It is also ambient-stack-dependent (the
        overflow point shifts with however many frames are already on the stack
        at entry). The worklist form grows zero Python frames regardless of tree
        depth or ambient stack, so it is robust for any AST and NEVER truncates.

        This is a strict robustness improvement: it visits exactly the same
        nodes and records exactly the same aliases as the prior recursive
        version on real (shallow) Zig ASTs -- no behaviour change. (PR#87 marked
        the sibling `_walk_node` recursion 'by-design'; this rewrite alters no
        observable behaviour on real shallow ASTs, so it is safe to land
        regardless of that annotation.)
        """
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in ("variable_declaration", "VarDecl"):
                ident_children = [
                    c for c in current.children if c.type in ("identifier", "IDENTIFIER")
                ]
                # A simple alias is exactly: const <alias> = <target-identifier>;
                if len(ident_children) == 2:
                    alias_name = self._get_node_text(ident_children[0], source)
                    target_name = self._get_node_text(ident_children[1], source)
                    # Only record when the target is a known function name. A Zig
                    # `const` binding is immutable, but the SAME alias name can be
                    # declared on distinct control-flow paths within one function
                    # (`const doit = foo` in one branch, `= bar` in another).
                    # Accumulate every target in a set instead of last-wins
                    # overwriting, so a later `doit()` over-approximates to both.
                    if alias_name and target_name in name_to_ids:
                        aliases.setdefault(alias_name, set()).add(target_name)
                # Struct field-init fn pointers: `const h = T{ .cb = knownFn };` binds
                # `h.cb` -> knownFn so a later `h.cb()` resolves. The first identifier
                # child is the bound variable; the struct type name is nested inside the
                # struct_initializer and is ignored.
                if ident_children:
                    var_name = self._get_node_text(ident_children[0], source)
                    struct_init = next(
                        (c for c in current.children
                         if c.type in ("struct_initializer", "StructInit")),
                        None,
                    )
                    if var_name and struct_init is not None:
                        self._collect_field_fn_bindings(
                            struct_init, source, name_to_ids, aliases, var_name
                        )

            stack.extend(current.children)

    def _collect_field_fn_bindings(
        self, struct_init, source, name_to_ids, aliases, var_name
    ):
        """Record `.field = knownFn` struct-init bindings as `<var>.<field>` aliases.

        For `const h = T{ .cb = fn };` bind `h.cb` -> `fn` so a later `h.cb()`
        resolves via the dotted-alias dereference. Only DETERMINATE bindings are
        kept: the field value must be a bare identifier naming a KNOWN function. A
        runtime/param funcptr (RHS not a known function) or an indeterminate
        expression (e.g. a call `make()`) is skipped, so an unknown callback never
        over-connects.
        """
        init_list = next(
            (c for c in struct_init.children
             if c.type in ("initializer_list", "InitList")),
            None,
        )
        if init_list is None:
            return
        for child in init_list.children:
            if child.type not in ("assignment_expression", "AssignExpr"):
                continue
            field_name = None
            target_name = None
            seen_eq = False
            for sub in child.children:
                if sub.type == "=":
                    seen_eq = True
                    continue
                if not seen_eq and sub.type in ("field_expression", "field_access"):
                    # Leading-dot `.field` has exactly one identifier (the field);
                    # a qualified `a.b` has two and is not a field-init target.
                    idents = [
                        g for g in sub.children
                        if g.type in ("identifier", "IDENTIFIER")
                    ]
                    if len(idents) == 1:
                        field_name = self._get_node_text(idents[0], source)
                elif seen_eq and sub.type in ("identifier", "IDENTIFIER"):
                    target_name = self._get_node_text(sub, source)
            if field_name and target_name and target_name in name_to_ids:
                # Same over-approximation as the plain-alias case: a dotted
                # `<var>.<field>` alias can bind to different targets across
                # control-flow paths, so accumulate targets in a set rather
                # than last-wins overwriting.
                aliases.setdefault(f"{var_name}.{field_name}", set()).add(target_name)

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
        """Extract call sites from AST nodes.

        ITERATIVE walk over an explicit worklist stack -- see
        _collect_aliases_from_node for the full rationale. This is the DIRECT
        TWIN of that walk and had the identical unbounded self-recursion; a
        pathologically deep parse tree could overflow the Python stack here too.
        The worklist form grows zero Python frames and is a strict robustness
        improvement: same nodes visited, same calls recorded on real ASTs, no
        behaviour change.
        """
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in ("call_expression", "call_expr", "CallExpr"):
                # The callee is the first child: an `identifier` for a plain call foo(), or a
                # `field_expression` for a method/namespaced call obj.method() / mod.func().
                callee = current.children[0] if current.children else None
                if callee is not None and callee.type in ("identifier", "IDENTIFIER"):
                    calls.add(self._get_node_text(callee, source))
                elif callee is not None and callee.type in ("field_expression", "field_access"):
                    # Carry the RECEIVER by keeping only the full dotted form
                    # (`recv.method`); the resolver splits it and dispatches on the
                    # receiver's static TYPE. Adding the bare method name here would
                    # independently over-connect to EVERY same-named method (the
                    # namespace-leak FP), defeating type-based dispatch. An un-typed
                    # receiver still resolves by unique/same-file bare-name fallback
                    # inside _resolve_call, so recall is preserved.
                    text = self._get_node_text(callee, source)
                    calls.add(text)  # full dotted `receiver.method`
            elif current.type == "builtin_function":
                # @call(.modifier, realFn, argsTuple): the wrapped function is the real call target;
                # other @builtins are filtered out downstream.
                self._extract_builtin_call_target(current, source, calls)

            stack.extend(current.children)

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

        # Bound the input to this O(n^2)-on-adversarial-input finditer scan (ReDoS guard);
        # the pattern is unchanged, so the extracted call set is identical.
        from utilities.scan_budget import bound_macro_scan_text
        code, _truncated = bound_macro_scan_text(code, context="zig regex fallback")
        if _truncated:
            self.scan_truncated.append("zig regex fallback")
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

    def _collect_var_types(self, code: str) -> Dict[str, str]:
        """Map local variable name -> its declared struct type within one body.

        Captures the two sound, static forms: `var a = A{};` / `const a = A{}`
        (struct-initializer) and `var a: A = ...;` (type annotation). A variable
        redeclared with a different type is dropped (ambiguous) so a typed member
        dispatch never binds to a wrong type.
        """
        var_types: Dict[str, str] = {}
        ambiguous: Set[str] = set()
        if not code:
            return var_types
        try:
            tree = self.parser.parse(code.encode("utf-8"))
        except Exception:
            return var_types
        src = code.encode("utf-8")
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in ("variable_declaration", "VarDecl"):
                name, typ = self._var_decl_name_type(node, src)
                if name and typ:
                    if name in ambiguous:
                        pass
                    elif name in var_types and var_types[name] != typ:
                        ambiguous.add(name)
                        var_types.pop(name, None)
                    else:
                        var_types[name] = typ
            stack.extend(node.children)
        return var_types

    def _var_decl_name_type(self, node: Node, src: bytes):
        """Return (var_name, type_name) for a variable_declaration, or (name, None).

        Recognizes `<name> = T{...}` (struct-initializer type) and `<name>: T = ...`
        (type annotation). The bound variable is the first identifier child.
        """
        ident_children = [
            c for c in node.children if c.type in ("identifier", "IDENTIFIER")
        ]
        if not ident_children:
            return None, None
        var_name = self._get_node_text(ident_children[0], src)
        # struct-initializer form: `var a = A{};`
        struct_init = next(
            (c for c in node.children if c.type in ("struct_initializer", "StructInit")),
            None,
        )
        if struct_init is not None:
            for g in struct_init.children:
                if g.type in ("identifier", "IDENTIFIER"):
                    return var_name, self._get_node_text(g, src)
        # type-annotation form: `var a: A = ...;`
        seen_colon = False
        for c in node.children:
            if c.type == ":":
                seen_colon = True
                continue
            if seen_colon and c.type == "=":
                break
            if seen_colon and c.type in ("identifier", "IDENTIFIER"):
                return var_name, self._get_node_text(c, src)
        return var_name, None

    def _resolve_typed_member(
        self,
        recv_type: str,
        method: str,
        caller_file: str,
        name_to_ids: Dict[str, List[str]],
    ) -> List[str]:
        """Resolve `method` to the method declared on `recv_type` only.

        Filters the same-named candidates to those whose declaring struct is
        recv_type; prefers same-file matches. Returns [] when the type declares
        no such method (never over-connects to an unrelated type's method).
        """
        matches: List[str] = []
        for cand in name_to_ids.get(method, []):
            info = self.functions.get(cand, {})
            if (
                info.get("class_name") == recv_type
                or info.get("qualified_name") == f"{recv_type}.{method}"
            ):
                if cand not in matches:
                    matches.append(cand)
        same_file = [c for c in matches if c.startswith(f"{caller_file}:")]
        return same_file if same_file else matches

    def _resolve_call(
        self,
        call_name: str,
        caller_file: str,
        name_to_ids: Dict[str, List[str]],
        alias_to_target: Dict[str, Dict[str, Set[str]]] | None = None,
        caller_id: Optional[str] = None,
        var_types: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """
        Resolve a call name to function ID(s), unioning over all alias targets.

        A const fn-alias (`const f = handler; f()`) is expanded to its target
        function name(s) before candidate lookup. Aliases are keyed by the
        CALLER function (not the file) so a same-named alias in another function
        in the same file cannot clobber this one. An alias may bind to MULTIPLE
        targets across control-flow paths (`const doit = foo` in one branch,
        `= bar` in another); over-approximate by resolving every target name and
        unioning the resulting ids, so `doit()` yields caller->{foo, bar}.
        """
        names: List[str] = [call_name]
        if alias_to_target is not None and caller_id is not None:
            targets = alias_to_target.get(caller_id, {}).get(call_name)
            if targets:
                # Alias shadows the bare name (matching prior single-target
                # behavior): resolve only the alias targets, deterministically
                # ordered.
                names = sorted(targets)

        resolved: List[str] = []
        for name in names:
            for rid in self._resolve_name(name, caller_file, name_to_ids, var_types):
                if rid not in resolved:
                    resolved.append(rid)
        return resolved

    def _resolve_name(
        self,
        call_name: str,
        caller_file: str,
        name_to_ids: Dict[str, List[str]],
        var_types: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """
        Resolve a single (already alias-expanded) name to function ID(s).

        Resolution order:
        1. Same file
        2. Imported files
        3. Unique name match
        """
        # Member call `receiver.method`: dispatch on the receiver's static TYPE.
        # (Alias expansion already happened in _resolve_call; a directly-qualified
        # `Type.method` whose full name is itself indexed -- e.g. a struct method's
        # qualified_name -- is handled by the normal lookup below, so only names
        # NOT in the index are treated as member calls.)
        if "." in call_name and call_name not in name_to_ids:
            receiver, _, method = call_name.rpartition(".")
            recv_type = (var_types or {}).get(receiver)
            if recv_type is not None:
                # Known receiver type: resolve STRICTLY on that type -- return only
                # its own method(s), never a same-named method on an unrelated
                # type. Nothing if the type does not declare the method.
                return self._resolve_typed_member(recv_type, method, caller_file, name_to_ids)
            # Unknown receiver type: fall back to bare-name resolution of the
            # method (unique/same-file/import), preserving recall for un-typed
            # receivers (e.g. `obj.method()` with a single global `method`).
            call_name = method

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
        caller_dir = posixpath.dirname(caller_file)
        for candidate in candidates:
            candidate_file = candidate.split(":")[0]
            for imp in file_imports:
                if not imp.endswith(".zig"):
                    continue  # std / builtin / root are not file imports
                # The @import path is relative to the importing file's directory and
                # may contain ./ or ../; normalize it against caller_dir to the same
                # repo-relative form as the stored candidate key, or the cross-file
                # edge is dropped whenever the import crosses a directory boundary.
                resolved_imp = posixpath.normpath(posixpath.join(caller_dir, imp))
                if (
                    candidate_file == resolved_imp
                    or candidate_file == imp
                    or candidate_file.endswith("/" + imp)
                ):
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
