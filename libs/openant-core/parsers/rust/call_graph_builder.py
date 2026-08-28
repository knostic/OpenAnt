"""
Stage 3: Call Graph Builder for Rust

Builds bidirectional call graphs showing function dependencies.

Rust call forms this resolver was designed against (grammar verified with
tree-sitter-rust before writing any resolution logic; see the parser's
design notes for the actual node-type dump this was built from):

- Free function: ``foo()`` -> `call_expression` whose callee is `identifier`.
- Method call: ``self.method()`` / ``x.method()`` / ``a.b().c()`` -> callee is
  `field_expression` (`receiver`, `.`, `field_identifier`). The receiver is
  the keyword node `self`, an `identifier`, or another call/field expression
  (chained call — receiver type not tracked, see limitations).
- Associated function: ``Type::method()`` / ``Self::method()`` /
  ``Type::<Generic>::method()`` -> callee is `scoped_identifier` (or
  `generic_type` wrapping one, for the turbofish-qualified-type form).
- Turbofish: ``expr.parse::<i32>()`` / ``std::cmp::max::<i32>(a, b)`` -> callee
  is `generic_function`, which wraps the *real* callee (a `field_expression`
  or `scoped_identifier`) plus `type_arguments` — unwrapped before dispatch.
- Macros (`println!`, `format!`, `assert_eq!`, ...): tree-sitter-rust does
  NOT parse macro arguments as expressions — they are an opaque `token_tree`.
  A best-effort regex scan recovers call-shaped identifiers from the token
  stream of well-known formatting/assertion macros (see `_scan_macro_body`).
"""

import posixpath
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from utilities.file_io import write_json

from tree_sitter import Language, Parser, Node

import tree_sitter_rust as ts_rust


# Macros whose arguments commonly contain real call expressions worth
# recovering, even though the grammar treats their body as an opaque token
# tree rather than parsed Rust. Anything not in this set is assumed to be a
# user/derive macro whose body is not source-level Rust calls (or is simply
# not worth the false-positive risk of a blind regex scan).
_SCANNABLE_MACROS = {
    "format", "print", "println", "eprint", "eprintln", "write", "writeln",
    "panic", "assert", "assert_eq", "assert_ne", "debug_assert",
    "debug_assert_eq", "debug_assert_ne", "format_args", "matches", "vec",
    "todo", "unimplemented", "unreachable", "dbg",
}

# A conservative call-shaped pattern used ONLY inside macro token trees
# (real code is parsed by the grammar and does not need this). Matches, in
# alternation order:
#   `A::B::c(`         scoped associated/module call -> emitted as a `scoped`
#                      site so cross-file `Type::method`/`mod::fn` targets
#                      resolve (the AST walk gets these for free; the macro
#                      scanner did not, silently dropping the most common
#                      fuzz-harness idiom `assert!(Type::method(d))`).
#   `name(` / `recv.name(` / `recv.name::<T>(`   bare or dotted method chain.
# Scoped is tried first so `Codec::roundtrip(` binds the qualifier rather than
# degrading to a bare same-file-only `roundtrip`. A trailing turbofish
# (`foo::<T>(`) is NOT an identifier after `::`, so it falls through to the
# bare branch exactly as before (no scoped false-match).
_MACRO_CALL_RE = re.compile(
    r"\b("
    r"(?:[A-Za-z_][A-Za-z0-9_]*::)+[A-Za-z_][A-Za-z0-9_]*"       # A::B::c (scoped)
    r"|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"      # bare / recv.name
    r")\s*(?:::<[^>]*>)?\s*\("
)

# String / char literals inside a macro token tree, blanked BEFORE the call-shaped
# scan so call-looking text in a diagnostic message (`panic!("call init() first")`)
# is not harvested as a phantom edge. Covers raw strings (`r"..."`, `r#"..."#`),
# normal strings with escapes, and char literals; Rust lifetimes (`'a`, no closing
# quote) intentionally do not match. Best-effort, matching the scan itself.
_RUST_STR_LITERAL_RE = re.compile(
    r'r#"(?:[^"]|"(?!#))*"#'      # raw string, one hash
    r'|r"[^"]*"'                  # raw string, no hash
    r'|"(?:\\.|[^"\\])*"'         # normal string with escapes
    r"|'(?:\\.|[^'\\])'"          # char literal
)


def _blank_rust_literals(text: str) -> str:
    """Single-pass O(n) equivalent of ``_RUST_STR_LITERAL_RE.sub(" ", text)``.

    The regex form is O(n^2) on an unterminated-``r#"`` flood (its ``(?:[^"]|"(?!#))*``
    branch restarts at every position). This hand-written forward-cursor scanner blanks
    the SAME four literal forms — collapsing each matched span to a single space, exactly
    like ``re.sub(" ", ...)`` — with a monotonic index, so it is linear and cannot ReDoS.
    Running it BEFORE the length budget (rather than the reverse) also restores the calls
    that the bound-then-strip ordering dropped when a large literal pushed a real trailing
    call past the cap. A differential test asserts byte-identical output vs the regex on a
    real-code corpus (any divergence is a call-graph/reachability change and must fail).

    Deliberately matches the regex's EXACT (incomplete) scope — 1-hash raw strings only,
    no ``r##``/byte-string/``br`` forms — so the extracted call set is unchanged. Extending
    it to more literal forms would remove real phantom edges but is a call-set change; see
    issue #288 (tracked as future work, alongside the token-tree-walk that would
    retire this scanner entirely).
    """
    # An UNTERMINATED literal is left UNCHANGED, exactly like the regex: with no
    # closing delimiter the corresponding alternative fails to match, so re.sub emits
    # the single opening char and retries at the next position. Only a fully-terminated
    # literal is collapsed to one space. (Getting this wrong would blank a stray trailing
    # quote to EOF and drop real trailing calls — the divergence the differential caught.)
    n = len(text)
    out = []
    i = 0
    # Monotonic short-circuits keep the scan O(n): once we learn there is no `"#`
    # (resp. no `"`) at/after some index, every LATER raw-string opener starts
    # scanning even further right, so it is also unterminated -- return -1 without
    # re-scanning to EOF. Without this, a repeated-`r#"` flood (no closing `"#`)
    # calls find() to EOF from ~n/3 positions -> O(n^2) (a real ReDoS: measured
    # ~1.8s at 240KB). The result is byte-identical to calling find() every time.
    no_hashclose_from = None   # if set: no `"#` exists at/after this index
    no_quote_from = None       # if set: no `"`  exists at/after this index
    while i < n:
        c = text[i]
        # r#"..."#  (one hash, matching the regex's single-hash branch only)
        if c == 'r' and text.startswith('r#"', i):
            start = i + 3
            if no_hashclose_from is not None and start >= no_hashclose_from:
                close = -1
            else:
                close = text.find('"#', start)
                if close == -1:
                    no_hashclose_from = start
            if close != -1:
                out.append(' '); i = close + 2; continue
            out.append(c); i += 1; continue                  # unterminated -> unchanged
        # r"..."
        if c == 'r' and text.startswith('r"', i):
            start = i + 2
            if no_quote_from is not None and start >= no_quote_from:
                close = -1
            else:
                close = text.find('"', start)
                if close == -1:
                    no_quote_from = start
            if close != -1:
                out.append(' '); i = close + 1; continue
            out.append(c); i += 1; continue                  # unterminated -> unchanged
        # "..." — content is (?:\\.|[^"\\])*, where \\. is backslash + any NON-newline
        # (re's '.' excludes '\n' without DOTALL, so \<newline> ends the group and the
        # literal fails to match — must be replicated or the scanner over-consumes).
        if c == '"':
            j = i + 1
            matched = False
            while j < n:
                cj = text[j]
                if cj == '"':
                    matched = True; break
                if cj == '\\':
                    if j + 1 < n and text[j + 1] != '\n':
                        j += 2; continue
                    break                                    # \\. fails -> group ends, no close
                j += 1                                       # [^"\\]
            if matched:
                out.append(' '); i = j + 1; continue
            out.append(c); i += 1; continue                  # unterminated -> unchanged
        # '.' or '\.' char literal — NOT a lifetime ('a), label ('x:), or unterminated.
        # The '\X' escape form also excludes \<newline> (same '.' rule as above).
        if c == "'":
            if i + 3 < n and text[i + 1] == '\\' and text[i + 2] != '\n' and text[i + 3] == "'":
                out.append(' '); i += 4; continue            # '\X'
            if i + 2 < n and text[i + 1] not in "'\\" and text[i + 2] == "'":
                out.append(' '); i += 3; continue            # 'X'
            out.append(c); i += 1; continue                  # lifetime/label/unterminated
        out.append(c)
        i += 1
    return ''.join(out)

RUST_BUILTINS = {
    # core::fmt / println-family macro names (recovered via token-tree scan,
    # so they can appear as bare "calls" and must be filtered like any std fn)
    "format", "print", "println", "eprint", "eprintln", "write", "writeln",
    "panic", "assert", "assert_eq", "assert_ne", "debug_assert",
    "debug_assert_eq", "debug_assert_ne", "format_args", "matches", "vec",
    "todo", "unimplemented", "unreachable", "dbg",
    # Option/Result/Iterator/String/Vec/collections common method names.
    # These are checked against the BARE (post-`.`) method name as a
    # precision guard on the "receiver type unknown" fallback path, not
    # applied to typed-dispatch resolution.
    "unwrap", "unwrap_or", "unwrap_or_else", "unwrap_or_default", "unwrap_err",
    "expect", "expect_err", "clone", "to_string", "to_owned", "as_str",
    "as_ref", "as_mut", "as_slice", "as_bytes", "iter", "iter_mut",
    "into_iter", "collect", "map", "map_err", "filter", "filter_map", "fold",
    "for_each", "sum", "count", "len", "is_empty", "push", "pop", "insert",
    "remove", "contains", "contains_key", "get", "get_mut", "keys", "values",
    "entry", "or_insert", "or_insert_with", "and_then", "or_else", "ok",
    "ok_or", "is_some", "is_none", "is_ok", "is_err", "take", "replace",
    "cloned", "copied", "sort", "sort_by", "sort_by_key", "reverse", "extend",
    "append", "drain", "join", "split", "splitn", "trim", "trim_start",
    "trim_end", "to_lowercase", "to_uppercase", "starts_with", "ends_with",
    "chars", "bytes", "lines", "read_line", "read_to_string", "flush",
    "lock", "read", "write_all", "spawn", "parse", "into", "from",
    "default", "new",
}


class CallGraphBuilder:
    """Builds call graphs from extracted Rust functions."""

    RUST_LANGUAGE = Language(ts_rust.language())

    def __init__(self, extractor_output: Dict[str, Any]):
        self.functions = extractor_output.get("functions", {})
        self.classes = extractor_output.get("classes", {})
        self.imports = extractor_output.get("imports", {})
        self.trait_impls: Dict[str, List[str]] = extractor_output.get("trait_impls", {})
        self.repository = extractor_output.get("repository", "")
        self.parser = Parser(self.RUST_LANGUAGE)

        self.trait_names: Set[str] = {
            name for name, info in self.classes.items() if info.get("kind") == "trait"
        }
        # Every nominal type known in the repo (structs/enums/traits + any type
        # that owns a method). Lets F1's generic-fallthrough distinguish an
        # unknown type name (generic `T` -> fall through to the name fallback)
        # from a KNOWN type that simply lacks the method (`d: &Dog; d.meow()`
        # -> return [], never fabricate an edge to an unrelated type's method).
        self.known_types: Set[str] = set(self.classes) | {
            info.get("class_name") for info in self.functions.values() if info.get("class_name")
        }
        # Inverse of trait_impls: concrete type -> traits it implements. Lets
        # `_resolve_typed_member` find a TRAIT's shared default method when
        # called on a concrete instance that does not override it
        # (`point.default_greet()` where only `Greeter::default_greet` has a
        # body) -- the common direction trait defaults are actually used in.
        self.type_traits: Dict[str, List[str]] = defaultdict(list)
        for trait_name, impl_types in self.trait_impls.items():
            for impl_type in impl_types:
                self.type_traits[impl_type].append(trait_name)

        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}
        # Machine-readable record of macro bodies whose call-scan input was truncated by
        # the ReDoS budget (scan_budget.py). A non-empty list means the call graph for
        # those contexts is KNOWN-INCOMPLETE — downstream reachability should over-seed
        # rather than trust the callee list. See issue #288.
        self.scan_truncated: List[str] = []

    # -- public API (parity with sibling parsers) ----------------------------

    def build_call_graph(self) -> None:
        call_graph: Dict[str, List[str]] = defaultdict(list)
        reverse_call_graph: Dict[str, List[str]] = defaultdict(list)

        name_to_ids = self._build_name_index()

        for func_id, func_info in self.functions.items():
            code = func_info.get("code", "")
            file_path = func_info.get("file_path", "")
            caller_class = func_info.get("class_name")

            var_types = self._collect_var_types(code, name_to_ids)
            fn_aliases = self._collect_fn_aliases(code, name_to_ids, file_path)
            # Merge the enclosing impl's generic bounds (`impl<T: Shape> Foo<T>`,
            # recorded by the extractor) with the fn's OWN generics; the fn's own
            # bound wins on a letter collision (inner shadows outer). Without the
            # impl-level bounds a receiver typed as the impl's `T` would fall to a
            # bare lookup on the letter and be hijacked by a blanket pseudo-type (D).
            type_param_bounds = {
                **func_info.get("impl_type_param_bounds", {}),
                **self._collect_type_param_bounds(code),
            }
            calls = self._find_calls_in_code(code, file_path, name_to_ids)

            for call in calls:
                resolved_ids = self._resolve_call(
                    call, file_path, caller_class, name_to_ids, var_types, fn_aliases,
                    type_param_bounds,
                )
                for resolved_id in resolved_ids:
                    if resolved_id != func_id:
                        if resolved_id not in call_graph[func_id]:
                            call_graph[func_id].append(resolved_id)
                        if func_id not in reverse_call_graph[resolved_id]:
                            reverse_call_graph[resolved_id].append(func_id)

        self.call_graph = dict(call_graph)
        self.reverse_call_graph = dict(reverse_call_graph)

    def build(self) -> Dict[str, Any]:
        self.build_call_graph()
        return self.export()

    def export(self) -> Dict[str, Any]:
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
        total_edges = sum(len(callees) for callees in self.call_graph.values())
        num_funcs = len(self.functions)
        out_degrees = [len(self.call_graph.get(f, [])) for f in self.functions]
        in_degrees = [len(self.reverse_call_graph.get(f, [])) for f in self.functions]
        isolated = sum(
            1 for f in self.functions
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

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        write_json(output_path, results)

    # -- indexing -------------------------------------------------------------

    def _build_name_index(self) -> Dict[str, List[str]]:
        name_to_ids: Dict[str, List[str]] = defaultdict(list)
        for func_id, func_info in self.functions.items():
            name = func_info.get("name", "")
            qualified_name = func_info.get("qualified_name", "")
            if name:
                name_to_ids[name].append(func_id)
            if qualified_name and qualified_name != name:
                name_to_ids[qualified_name].append(func_id)
        return name_to_ids

    # -- call-site extraction ---------------------------------------------------

    def _find_calls_in_code(
        self, code: str, caller_file: str,
        name_to_ids: Optional[Dict[str, List[str]]] = None,
    ) -> List[dict]:
        """Return call-site descriptors: {"kind": "bare"|"field"|"scoped", ...}."""
        sites: List[dict] = []
        if not code:
            return sites
        try:
            tree = self.parser.parse(code.encode("utf-8"))
        except Exception:
            return sites
        source = code.encode("utf-8")

        stack = [tree.root_node]
        entered_fn = False
        while stack:
            node = stack.pop()
            if node.type == "function_item":
                # The outermost function_item IS this unit; a NESTED `fn` is its own
                # extracted unit (`outer::inner`) that collects its own call sites
                # under its own generic bounds. Do not descend into a nested fn body
                # here — attributing its calls to the outer unit resolves them under
                # the outer fn's (wrong) bounds and fabricates phantom edges. Closures
                # (closure_expression) are NOT function_items, so they still belong to
                # this unit, which is correct (they capture the outer bounds).
                if entered_fn:
                    continue
                entered_fn = True
            if node.type == "call_expression":
                callee = node.children[0] if node.children else None
                site = self._describe_callee(callee, source)
                if site is not None:
                    sites.append(site)
            elif node.type == "macro_invocation":
                self._scan_macro_body(node, source, sites)
            stack.extend(node.children)

        # The RUST_BUILTINS set is a precision guard for the UNKNOWN-receiver
        # fallback path only (see `_resolve_unknown_receiver_method`), NOT a reason
        # to delete a resolvable call at extraction time. A builtin-named site is
        # dropped here ONLY when the name is a pure std/library name — i.e. it does
        # NOT name any known repo function/method (`repo_names`) and is not shadowed
        # in the caller's own file. When the name IS a real repo function/method,
        # the site is kept and resolution decides precisely (typed dispatch) or
        # conservatively (the unknown-receiver builtin guard). This mirrors the
        # Swift parser's filter, whose `text in repo_names` clause keeps exactly
        # these real calls; the Rust port had dropped that clause, silently
        # deleting typed cross-file `.get()/.parse()/...`-style edges.
        shadowing = self._same_file_function_names(caller_file)
        repo_names = set(name_to_ids) if name_to_ids else set()
        filtered = []
        for site in sites:
            bare = site.get("bare_filter_name")
            if (bare is None or bare in shadowing or bare not in RUST_BUILTINS
                    or bare in repo_names):
                filtered.append(site)
        return filtered

    def _describe_callee(self, callee: Optional[Node], source: bytes) -> Optional[dict]:
        if callee is None:
            return None
        t = callee.type

        if t == "generic_function":
            # Turbofish call: unwrap to the real callee, ignore type_arguments.
            inner = None
            for child in callee.children:
                if child.type in ("field_expression", "scoped_identifier", "identifier"):
                    inner = child
                    break
            return self._describe_callee(inner, source)

        if t == "identifier":
            name = self._text(callee, source)
            return {"kind": "bare", "name": name, "bare_filter_name": name}

        if t == "field_expression":
            receiver = callee.children[0] if callee.children else None
            field = None
            for child in callee.children:
                if child.type == "field_identifier":
                    field = child
            if field is None:
                return None
            method = self._text(field, source)
            return {
                "kind": "field", "receiver": receiver, "method": method,
                "bare_filter_name": method,
            }

        if t == "scoped_identifier":
            qualifier, leaf = self._split_scoped(callee, source)
            if not leaf:
                return None
            return {
                "kind": "scoped", "qualifier": qualifier, "leaf": leaf,
                "bare_filter_name": None,
            }

        return None

    def _split_scoped(self, node: Node, source: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Split a `scoped_identifier` into (immediate qualifier text, leaf name).

        `Point::new` -> ("Point", "new"); `Self::helper` -> ("Self", "helper");
        `Widget::<i32>::other` -> ("Widget", "other") (generic_type unwrapped);
        `std::cmp::max` -> ("cmp", "max") (only the immediate segment is kept —
        deep module paths are not fully resolved, see limitations).
        """
        children = node.children
        if not children:
            return None, None
        leaf_node = children[-1]
        if leaf_node.type != "identifier":
            return None, None
        leaf = self._text(leaf_node, source)

        qualifier_node = None
        for child in children[:-1]:
            if child.type in ("scoped_identifier", "identifier", "generic_type", "crate", "super", "self"):
                qualifier_node = child
        if qualifier_node is None:
            return None, leaf

        if qualifier_node.type in ("identifier", "crate", "super", "self"):
            return self._text(qualifier_node, source), leaf
        if qualifier_node.type == "generic_type":
            base = None
            for c in qualifier_node.children:
                if c.type in ("type_identifier",):
                    base = c
                    break
            return (self._text(base, source) if base is not None else None), leaf
        if qualifier_node.type == "scoped_identifier":
            # Deeper nesting (`crate::utils::helper`, `std::f64::consts::PI`):
            # take only the LAST segment of the inner path as the qualifier.
            _, inner_leaf = self._split_scoped(qualifier_node, source)
            return inner_leaf, leaf
        return None, leaf

    def _scan_macro_body(self, node: Node, source: bytes, sites: List[dict]) -> None:
        """Best-effort recovery of calls inside a macro's opaque token tree.

        tree-sitter-rust does not parse macro arguments as expressions, so a
        call like `self.greet()` inside `format!("{}", self.greet())` is
        invisible to the AST walk above. For a small set of well-known
        macros whose arguments are ordinary expressions (format/print/assert/
        vec/...), regex-recover call-shaped identifiers from the raw token
        text. It recovers bare, dotted, and scoped (`Type::method`) call names
        -- it cannot see argument structure -- so results feed the same
        bare/field/scoped resolution paths as the AST walk, with a conservative
        shape.

        NOTE (2026-08-15): "opaque token tree" describes only how THIS scanner
        treats the body, not the grammar. tree-sitter DOES lex the `token_tree`
        into structured nodes (string_literal / identifier / nested token_tree),
        so a node-walk could recover these calls without any regex or scan
        budget. That rewrite is deferred (see issue #288 R1/T); the
        regex path is retained for now with a linear literal-stripper in front.
        """
        macro_name = None
        token_tree = None
        for child in node.children:
            if child.type == "identifier" and macro_name is None:
                macro_name = self._text(child, source)
            elif child.type == "token_tree":
                token_tree = child
        if macro_name not in _SCANNABLE_MACROS or token_tree is None:
            return
        text = self._text(token_tree, source)
        # Blank literals FIRST, via the linear _blank_rust_literals (byte-identical to
        # _RUST_STR_LITERAL_RE.sub but O(n), so it cannot ReDoS the way the regex did on an
        # unterminated-raw-string flood). Stripping before the budget also collapses a large
        # string literal to one space, so a real trailing call is no longer pushed past the
        # cap -- fixing the recall regression the earlier bound-first ordering introduced.
        text = _blank_rust_literals(text)
        # THEN bound the stripped text for _MACRO_CALL_RE, which is still O(n^2) on an
        # adversarial dotted/scoped chain with no trailing '('. This residual (a call after
        # >8KB of non-literal token soup can be truncated) is tracked in issue #288.
        from utilities.scan_budget import bound_macro_scan_text
        text, _truncated = bound_macro_scan_text(text, context=f"rust macro {macro_name}")
        if _truncated:
            self.scan_truncated.append(f"rust macro {macro_name}")
        for match in _MACRO_CALL_RE.finditer(text):
            call_name = match.group(1)
            if "::" in call_name:
                # Scoped `A::B::c` -> a `scoped` site with the IMMEDIATE
                # qualifier (segment just before the leaf), matching the shape
                # `_split_scoped` produces for an AST scoped_identifier so it
                # routes through the same `_resolve_scoped` path (associated-fn
                # via class_name, module via mod-file). Add-only vs the prior
                # bare capture: a `Type::method(` token that previously yielded
                # bare `method` (same-file-only) now yields the qualified call.
                qualifier, leaf = call_name.rsplit("::", 1)
                immediate = qualifier.rsplit("::", 1)[-1]
                sites.append({
                    "kind": "scoped", "qualifier": immediate, "leaf": leaf,
                    "bare_filter_name": None,
                })
            elif "." in call_name:
                receiver_name, method = call_name.rsplit(".", 1)
                if receiver_name == "self":
                    sites.append({
                        "kind": "field", "receiver": "self", "method": method,
                        "bare_filter_name": method, "receiver_is_self": True,
                    })
                else:
                    sites.append({
                        "kind": "field", "receiver": receiver_name, "method": method,
                        "bare_filter_name": method, "receiver_is_self": False,
                    })
            else:
                sites.append({"kind": "bare", "name": call_name, "bare_filter_name": call_name})

    def _same_file_function_names(self, caller_file: str) -> Set[str]:
        if not caller_file:
            return set()
        return {
            info.get("name", "")
            for info in self.functions.values()
            if info.get("file_path") == caller_file and info.get("name")
        }

    def _text(self, node: Node, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    # -- receiver static-type inference ----------------------------------------

    def _collect_var_types(
        self, code: str, name_to_ids: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, str]:
        """Map local variable/parameter name -> its declared/inferred type.

        Sources, in order of confidence: parameter type annotations
        (`other: &Point` -> Point), `let x: Type = ...` annotations,
        `let x = Type { .. }` struct-literal initializers, and (best-effort)
        `let x = Type::assoc(...)` associated-function calls -- this assumes
        the common constructor idiom (`Type::new()` returns `Self`/`Type`),
        which is not guaranteed by the type system but is the dominant
        real-world pattern and errs toward more (not fewer) resolved edges,
        matching this codebase's established over-approximation stance.
        A name reassigned to a conflicting type is dropped as ambiguous.
        """
        var_types: Dict[str, str] = {}
        ambiguous: Set[str] = set()

        def _set(name: Optional[str], typ: Optional[str]) -> None:
            if not name or not typ:
                return
            if name in ambiguous:
                return
            if name in var_types and var_types[name] != typ:
                ambiguous.add(name)
                var_types.pop(name, None)
                return
            var_types[name] = typ

        if not code:
            return var_types
        try:
            tree = self.parser.parse(code.encode("utf-8"))
        except Exception:
            return var_types
        source = code.encode("utf-8")

        # A local `let` bound to a CLOSURE shadows a same-named free function as
        # the call target: `let helper = || ...; let x = helper()` calls the
        # closure, not a repo `fn helper`. Collect only closure bindings -- a
        # non-callable rebind (`let load = 5`) can never be `load()`-called, so it
        # does not shadow a function call and must not block return-type inference.
        local_closures: Set[str] = set()
        lstack = [tree.root_node]
        while lstack:
            n = lstack.pop()
            if n.type == "let_declaration":
                name = None
                seen_eq = False
                for c in n.children:
                    if c.type == "identifier" and name is None and not seen_eq:
                        name = self._text(c, source)
                    elif c.type == "=":
                        seen_eq = True
                    elif seen_eq and c.type == "closure_expression" and name:
                        local_closures.add(name)
            lstack.extend(n.children)

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == "parameter":
                pname = None
                ptype = None
                seen_colon = False
                for c in node.children:
                    if c.type == "identifier" and pname is None:
                        pname = self._text(c, source)
                    elif c.type == ":":
                        seen_colon = True
                    elif seen_colon and ptype is None:
                        ptype = c
                if pname and ptype is not None:
                    from .function_extractor import _bare_type_name
                    _set(pname, _bare_type_name(ptype, source))
            elif node.type == "let_declaration":
                name = None
                for c in node.children:
                    if c.type == "identifier" and name is None:
                        name = self._text(c, source)
                        break
                if name:
                    _set(name, self._infer_let_type(
                        node, source, name_to_ids, local_closures))
            stack.extend(node.children)
        return var_types

    def _assoc_return_type(
        self, qualifier: str, leaf: Optional[str],
        name_to_ids: Optional[Dict[str, List[str]]],
    ) -> Optional[str]:
        """Return the recorded return type of associated fn `qualifier::leaf`, if
        known and not `Self`. Lets `let w = Factory::make()` type `w` as make()'s
        real return type (Widget) instead of the constructor-idiom guess (Factory).
        `Self` returns fall through to the qualifier (the `Type::new() -> Self` case).
        """
        if not leaf or not name_to_ids:
            return None
        rts = set()
        for cand in name_to_ids.get(leaf, []):
            info = self.functions.get(cand, {})
            if info.get("class_name") == qualifier:
                rt = info.get("return_type")
                if rt and rt != "Self":
                    rts.add(rt)
        # Two same-named types (`Factory` in different files) with differing
        # return types is unresolvable here -- decline rather than guess the
        # first, which would fabricate a wrong-type edge. Mirrors the
        # uniqueness guard in `_free_fn_return_type`.
        return next(iter(rts)) if len(rts) == 1 else None

    def _free_fn_return_type(
        self, fn_name: str, name_to_ids: Optional[Dict[str, List[str]]],
    ) -> Optional[str]:
        """Return the recorded return type of a FREE function `fn_name`, if a single
        unambiguous non-`Self` type. Lets `let c = load()` (where `load() -> Cfg`)
        type `c` as Cfg, so a later `c.method()` resolves precisely instead of hitting
        the unknown-receiver gate and blacking out. Precise (typed) -> zero phantom.
        """
        if not name_to_ids:
            return None
        rts = set()
        for cand in name_to_ids.get(fn_name, []):
            info = self.functions.get(cand, {})
            if info.get("class_name"):  # must be a free function, not a method
                continue
            rt = info.get("return_type")
            if rt and rt != "Self":
                rts.add(rt)
        return next(iter(rts)) if len(rts) == 1 else None

    def _infer_let_type(
        self, node: Node, source: bytes,
        name_to_ids: Optional[Dict[str, List[str]]] = None,
        local_closures: Optional[Set[str]] = None,
    ) -> Optional[str]:
        from .function_extractor import _bare_type_name

        # `let x: Type = ...;` -- explicit annotation wins.
        seen_colon = False
        for c in node.children:
            if c.type == ":":
                seen_colon = True
                continue
            if c.type == "=":
                break
            if seen_colon and c.type not in (":",):
                t = _bare_type_name(c, source)
                if t:
                    return t

        # `let x = Type { .. };`
        for c in node.children:
            if c.type == "struct_expression":
                for g in c.children:
                    if g.type in ("type_identifier", "scoped_type_identifier"):
                        return _bare_type_name(g, source)

        # `let x = Type::assoc(...)` / `let x = Type::<T>::assoc(...)`
        for c in node.children:
            if c.type == "call_expression":
                callee = c.children[0] if c.children else None
                if callee is not None and callee.type == "generic_function":
                    for gc in callee.children:
                        if gc.type == "scoped_identifier":
                            callee = gc
                            break
                if callee is not None and callee.type == "scoped_identifier":
                    qualifier, _leaf = self._split_scoped(callee, source)
                    if qualifier and qualifier not in ("Self",):
                        # Prefer the assoc fn's ACTUAL return type (`make() -> Widget`)
                        # over the constructor-idiom assumption that it returns the
                        # qualifier (`Factory`). Falls back to the qualifier when the
                        # return type is unknown or `Self` (the `Type::new()` case).
                        return self._assoc_return_type(qualifier, _leaf, name_to_ids) or qualifier
                if callee is not None and callee.type == "identifier":
                    # `let c = load()` where `load() -> Cfg` -> type c as Cfg, so a
                    # later `c.method()` resolves precisely (recovering the
                    # unknown-receiver blackout) with zero phantom. Skip when the
                    # name is a local closure binding shadowing the free fn --
                    # typing from the free fn would be a wrong-type phantom.
                    fname = self._text(callee, source)
                    if not (local_closures and fname in local_closures):
                        rt = self._free_fn_return_type(fname, name_to_ids)
                        if rt:
                            return rt
        return None

    def _collect_fn_aliases(
        self, code: str, name_to_ids: Dict[str, List[str]], caller_file: str,
    ) -> Dict[str, List[str]]:
        """Map a local name bound to a FUNCTION VALUE -> that function's id(s).

        `let p: fn() = tgt; p();` and `let q = tgt; q();` bind a callable to a
        variable; a later `p()`/`q()` is a real edge to `tgt` that bare-name
        resolution misses. Only a RHS that is a *bare identifier
        naming a known FREE function* creates an alias -- never a call, closure,
        method, or arbitrary expression. The RHS is resolved through the SAME
        gate a bare call uses -- free functions only (a bare identifier in value
        position is never an inherent method), same-file-preferred, unique-else-
        drop -- so the alias cannot over-link to a same-named method on an
        unrelated type or to a cross-file namesake (V18-1/V18-2). A name bound
        to two different functions is dropped as ambiguous.
        """
        def _alias_targets(rhs: str) -> List[str]:
            free = [
                c for c in name_to_ids.get(rhs, [])
                if not self.functions.get(c, {}).get("class_name")
                and not self.functions.get(c, {}).get("has_self")
            ]
            if not free:
                return []
            same_file = [c for c in free if self._in_file(c, caller_file)]
            if same_file:
                return same_file
            return free if len(free) == 1 else []
        aliases: Dict[str, List[str]] = {}
        ambiguous: Set[str] = set()
        if not code:
            return aliases
        try:
            tree = self.parser.parse(code.encode("utf-8"))
        except Exception:
            return aliases
        source = code.encode("utf-8")

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == "let_declaration":
                name = None
                rhs = None
                seen_eq = False
                for c in node.children:
                    if c.type == "identifier" and name is None and not seen_eq:
                        name = self._text(c, source)
                    elif c.type == "=":
                        seen_eq = True
                    elif seen_eq and rhs is None and c.type == "identifier":
                        rhs = self._text(c, source)
                if name and rhs:
                    targets = _alias_targets(rhs)
                    if targets:
                        if name in ambiguous:
                            pass
                        elif name in aliases and aliases[name] != targets:
                            ambiguous.add(name)
                            aliases.pop(name, None)
                        else:
                            aliases[name] = targets
            stack.extend(node.children)
        return aliases

    def _collect_type_param_bounds(self, code: str) -> Dict[str, List[str]]:
        """Map a function's generic type-parameter letter -> its bound trait(s).

        `fn f<B: Shape>(...)` and `fn f<B>(...) where B: Shape` both yield
        `{"B": ["Shape"]}`. A receiver typed as a bounded generic param can then
        dispatch to the trait's conformers via the SAME `trait_impls` closure the
        `&dyn Trait` path uses -- nominal typing makes the conformer set knowable
        and bounded, so this is a reachability-safe over-approximation, not a
        guess (extended from `dyn` to generic bounds; the Swift parser's
        protocol-conformer dispatch is the reference).
        """
        bounds: Dict[str, List[str]] = {}
        if not code:
            return bounds
        try:
            tree = self.parser.parse(code.encode("utf-8"))
        except Exception:
            return bounds
        src = code.encode("utf-8")

        # ONLY the outermost function_item's own generics -- a nested
        # `fn inner<B: Other>` inside the body must not bleed its bound into the
        # outer fn's `B` (scope correctness).
        fn = None
        queue = [tree.root_node]
        while queue:
            n = queue.pop(0)
            if n.type == "function_item":
                fn = n
                break
            queue.extend(n.children)
        if fn is None:
            return bounds

        def _traits(tb_node) -> List[str]:
            return [self._text(c, src) for c in tb_node.children if c.type == "type_identifier"]

        def _add(param, tb):
            if param:
                bounds.setdefault(param, [])
                for t in _traits(tb):
                    if t not in bounds[param]:
                        bounds[param].append(t)

        def _param(node):
            pid = None
            for cc in node.children:
                if cc.type == "type_identifier" and pid is None:
                    pid = self._text(cc, src)
                elif cc.type == "trait_bounds":
                    _add(pid, cc)

        for c in fn.children:  # direct children only: <...> and where-clause
            if c.type == "type_parameters":
                for tp in c.children:
                    if tp.type in ("type_parameter", "constrained_type_parameter"):
                        _param(tp)
            elif c.type == "where_clause":
                for wp in c.children:
                    if wp.type == "where_predicate":
                        _param(wp)
        return bounds

    # -- resolution -------------------------------------------------------------

    def _resolve_call(
        self, site: dict, caller_file: str, caller_class: Optional[str],
        name_to_ids: Dict[str, List[str]], var_types: Dict[str, str],
        fn_aliases: Dict[str, List[str]], type_param_bounds: Dict[str, List[str]],
    ) -> List[str]:
        kind = site["kind"]
        if kind == "bare":
            return self._resolve_bare(site["name"], caller_file, name_to_ids, fn_aliases)
        if kind == "field":
            return self._resolve_field(site, caller_file, caller_class, name_to_ids, var_types, type_param_bounds)
        if kind == "scoped":
            return self._resolve_scoped(site, caller_file, caller_class, name_to_ids)
        return []

    def _resolve_bare(
        self, call_name: str, caller_file: str, name_to_ids: Dict[str, List[str]],
        fn_aliases: Optional[Dict[str, List[str]]] = None,
    ) -> List[str]:
        # A local variable bound to a function value: `let p = tgt; p()` -> tgt
        # Checked before name resolution because `p` is not itself a
        # function name; the alias only exists when RHS named a known function.
        if fn_aliases and call_name in fn_aliases:
            return fn_aliases[call_name]

        # A bare `foo()` can only resolve to a FREE function -- never an inherent
        # or trait method (those need a receiver or a `Type::`/`self.` path). So
        # exclude any candidate that belongs to a type; this also stops a
        # blanket-impl pseudo-type method (`class_name="T"`) from being a
        # bare-call target.
        def _free(ids):
            return [c for c in ids if not self.functions.get(c, {}).get("class_name")]

        # A bare call may be an aliased `use` import: `use foo::bar as baz;`
        # then `baz()`. Expand to the real leaf name and try file-based
        # resolution via that import's module hint first.
        for imp in self.imports.get(caller_file, []):
            if imp.get("kind") == "use" and imp.get("alias") == call_name:
                target = self._resolve_via_use(imp, name_to_ids)
                if target:
                    return target
                call_name_for_fallback = imp.get("leaf", call_name)
                same_file = _free([
                    c for c in name_to_ids.get(call_name_for_fallback, [])
                    if self._in_file(c, caller_file)
                ])
                if same_file:
                    return same_file

        candidates = _free(name_to_ids.get(call_name, []))
        if not candidates:
            return []
        same_file = [c for c in candidates if self._in_file(c, caller_file)]
        if same_file:
            return same_file
        # A bare call to a name imported from an EXTERNAL crate (`use
        # std::thread::spawn`) is that external symbol, not a cross-file repo
        # function of the same name -- linking to the repo namesake is a
        # wrong-target phantom. Same-file (checked above) still wins; a genuine
        # repo import (`use crate::..`) has no external root and is unaffected.
        if self._name_is_externally_imported(call_name, caller_file):
            return []
        if len(candidates) == 1:
            return candidates
        return []

    def _resolve_via_use(self, imp: dict, name_to_ids: Dict[str, List[str]]) -> List[str]:
        leaf = imp.get("leaf")
        if not leaf:
            return []
        candidates = name_to_ids.get(leaf, [])
        return candidates if len(candidates) == 1 else []

    # Crate roots that are unambiguously NOT part of the analyzed repo. A `use`
    # rooted here binds an external symbol; `crate`/`super`/`self`-rooted paths
    # (and bare local-mod paths) are repo-internal and never match.
    _EXTERNAL_CRATE_ROOTS = frozenset({"std", "core", "alloc", "proc_macro", "test"})

    def _name_is_externally_imported(self, call_name: str, caller_file: str) -> bool:
        """True if `call_name` is brought into `caller_file` by a `use` rooted in a
        known external crate (`std`/`core`/`alloc`/...) AND is not ALSO repo-imported
        (`use crate::`/`self`/`super`) in the same file. Such a bare call is the
        external symbol, so it must not resolve to a same-named repo function. A
        coexisting repo import means some scope legitimately calls the repo function
        -- imports are tracked per file, not per scope, so we can't tell which call
        is which; decline to force-drop and let candidate resolution decide."""
        ext = repo = False
        for imp in self.imports.get(caller_file, []):
            if imp.get("kind") != "use":
                continue
            if (imp.get("alias") or imp.get("leaf")) != call_name:
                continue
            root = (imp.get("path") or "").split("::", 1)[0]
            if root in self._EXTERNAL_CRATE_ROOTS:
                ext = True
            elif root in ("crate", "self", "super"):
                repo = True
        return ext and not repo

    def _resolve_field(
        self, site: dict, caller_file: str, caller_class: Optional[str],
        name_to_ids: Dict[str, List[str]], var_types: Dict[str, str],
        type_param_bounds: Optional[Dict[str, List[str]]] = None,
    ) -> List[str]:
        """Resolve a method-call site to function ID(s).

        `receiver` is either a real tree-sitter `Node` (from an actual
        `field_expression` in the AST) or a plain `str` (a dotted name
        recovered from a macro's opaque token tree by `_scan_macro_body`,
        which has no node to point to). Both shapes are normalized to a
        receiver "kind" (self / named variable / other) before dispatch.
        """
        method = site["method"]
        receiver = site.get("receiver")

        if isinstance(receiver, str):
            is_self = site.get("receiver_is_self", False)
            recv_name = None if is_self else receiver
        else:
            is_self = receiver is not None and receiver.type == "self"
            if not is_self and receiver is not None and receiver.type == "identifier":
                recv_name = self._node_text_cache(receiver)
            else:
                recv_name = None
                if not is_self:
                    # Chained call / index / parenthesized receiver: type
                    # cannot be inferred from local text alone.
                    return self._resolve_unknown_receiver_method(method, caller_file, name_to_ids)

        if is_self:
            if caller_class:
                return self._resolve_typed_member(caller_class, method, caller_file, name_to_ids)
            return []

        if recv_name:
            recv_type = var_types.get(recv_name)
            if recv_type:
                # Generic trait-bound receiver (`item: &B` where `B: Shape`)
                # is resolved FIRST and never via a concrete-type lookup on the
                # letter: dispatch to the intersection of the bound traits'
                # conformers (for generics). Checking bounds before the
                # concrete lookup is what stops a blanket `impl<T: X> Y for T`
                # (which mints a pseudo-type `"T"`) from hijacking every generic
                # receiver named `T`/`B` repo-wide.
                bounds = (type_param_bounds or {}).get(recv_type)
                if bounds is not None:
                    return self._resolve_generic_bound_member(bounds, method, name_to_ids)

                typed = self._resolve_typed_member(recv_type, method, caller_file, name_to_ids)
                if typed:
                    return typed
                # F1: an unknown (external / unbounded generic) type name falls
                # through to the name fallback so an unambiguous method still
                # resolves. But a KNOWN type that simply lacks the method
                # (`d: &Dog; d.meow()`) must NOT fall through -- that fabricated
                # an edge to an unrelated type's same-named method.
                if recv_type in self.known_types:
                    return []
        return self._resolve_unknown_receiver_method(method, caller_file, name_to_ids)

    def _node_text_cache(self, node: Node) -> str:
        # Receiver identifier text; source bytes aren't threaded here, so this
        # relies on tree-sitter Node.text being available on the bound node.
        try:
            return node.text.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _resolve_generic_bound_member(
        self, bound_traits: List[str], method: str, name_to_ids: Dict[str, List[str]],
    ) -> List[str]:
        """Dispatch a call on a generic receiver `B: T1 + T2` to the INTERSECTION
        of the bound traits' conformers (the receiver's concrete type implements
        *every* bound, so only types conforming to all bounds are possible),
        plus any trait-default body on a bound. Nominal + bounded, so it is a
        reachability-safe over-approximation, not a guess. Returns [] when no
        bound is a known trait, or no conformer/default has the method -- never
        falls back to name matching (that is what the pseudo-type `"T"` from a
        blanket impl would otherwise hijack).
        """
        known = [t for t in bound_traits if t in self.trait_names]
        if not known:
            return []
        conformer_sets = [set(self.trait_impls.get(t, [])) for t in known]
        # A bound whose conformer set is EMPTY is *unconstrained*, not impossible:
        # marker/blanket/derive/cross-crate impls are invisible to the extractor
        # (blanket pairs are deliberately skipped in function_extractor), so an empty
        # set means "conformers unknown", and must NOT annihilate the edges the other
        # bounds legitimately establish (`B: Shape + Marker` still reaches Shape's
        # conformers). Intersect only over bounds that actually constrain — those with
        # >=1 known conformer. Reachability over-approximation, not a guess.
        constraining = [s for s in conformer_sets if s]
        conformers = set.intersection(*constraining) if constraining else set()
        allowed = conformers | set(known)  # concrete conformers + trait-default bodies
        result: List[str] = []
        for cand in name_to_ids.get(method, []):
            if self.functions.get(cand, {}).get("class_name") in allowed and cand not in result:
                result.append(cand)
        return result

    def _resolve_unknown_receiver_method(
        self, method: str, caller_file: str, name_to_ids: Dict[str, List[str]],
    ) -> List[str]:
        """Fallback for a method call whose receiver's static type is unknown.

        Precision-favoring: only resolves if the bare method name is NOT a
        common std/builtin method name (guards against `.unwrap()`/`.clone()`
        spuriously linking to an unrelated same-named user function), and
        only if it uniquely identifies one function in the whole repo (never
        connects to "every same-named method" -- that is a namespace leak).
        """
        if method in RUST_BUILTINS:
            same_file = [
                c for c in name_to_ids.get(method, []) if self._in_file(c, caller_file)
            ]
            return same_file
        candidates = [
            c for c in name_to_ids.get(method, [])
            if self.functions.get(c, {}).get("has_self")
        ]
        if not candidates:
            return []
        same_file = [c for c in candidates if self._in_file(c, caller_file)]
        # Unknown-receiver gate: only emit an edge when the receiver-less resolution is
        # UNAMBIGUOUS. When several same-named `&self` methods live in the same
        # file (e.g. Dog::speak and Cat::speak) and the receiver's static type is
        # unknown (inferred from a fn-return, struct field, `dyn Trait`, or a
        # shadowed binding), we cannot tell which is meant, so we emit no edge
        # rather than fan out to ALL of them — the previous behaviour fabricated
        # false edges (a `Dog` receiver linking to `Cat::speak`).
        # Trade-off: this drops an over-approximation a reachability pass could
        # have leaned on; a unique same-file OR unique repo-wide name still binds.
        if len(same_file) == 1:
            return same_file
        if len(candidates) == 1:
            return candidates
        # Known limitation (deliberate, not a bug): when >=2 same-named `&self`
        # methods remain and the receiver type is unknown, we decline. Exported
        # candidates self-seed so declining them is free; a PRIVATE inherent method
        # whose sole edge is declined can black out. That blackout is RECOVERED
        # upstream wherever the receiver type is inferable -- e.g. `let c = load()`
        # with `load() -> Cfg` types the receiver (see _free_fn_return_type), so the
        # call never reaches this gate. A blanket union of the residual truly-ambiguous
        # case would add a cross-type phantom (Dog->Cat.speak) per call site, so it is
        # not done here.
        return []

    def _resolve_typed_member(
        self, recv_type: str, method: str, caller_file: str,
        name_to_ids: Dict[str, List[str]],
    ) -> List[str]:
        """Resolve `method` on a known receiver type (struct/enum/trait name).

        Direct hits: functions whose `class_name` equals `recv_type`. Two
        trait-aware fallbacks handle the cases a direct match misses,
        symmetric in either direction:

        1. `recv_type` IS a trait and has no matching method directly (this
           is either a required method with no shared body, or the call site
           is itself inside that trait's own default-method body and cannot
           know its concrete Self): connect to the same-named method on
           every concrete type known to implement the trait (`trait_impls`).
        2. `recv_type` is a concrete type that does not override `method`,
           but implements some trait providing a shared default body for it
           (`point.default_greet()` resolving to `Greeter::default_greet`
           when `Point` never overrides it) -- the common direction trait
           defaults are actually used in.

        Both are reachability-safe over-approximations, not a guess at a
        single answer: real Rust dynamic/generic dispatch genuinely may
        invoke any of the connected implementations.
        """
        matches: List[str] = []
        for cand in name_to_ids.get(method, []):
            info = self.functions.get(cand, {})
            if info.get("class_name") == recv_type or info.get("qualified_name") == f"{recv_type}.{method}":
                if cand not in matches:
                    matches.append(cand)

        is_trait_recv = recv_type in self.trait_names
        if is_trait_recv:
            # Trait receiver (dyn/generic dispatch): EVERY conformer's override
            # is a runtime target, not only the trait's default body. Always
            # union the conformer fan-out with any direct match -- a direct hit
            # on the default body must NOT suppress the overrides (V19-1).
            for other_type in self.trait_impls.get(recv_type, []):
                for cand in name_to_ids.get(method, []):
                    if self.functions.get(cand, {}).get("class_name") == other_type and cand not in matches:
                        matches.append(cand)
        elif not matches:
            # Concrete type that does not override `method` -> the trait default
            # body it inherits (`point.default_greet()` -> Greeter::default_greet).
            for other_type in self.type_traits.get(recv_type, []):
                for cand in name_to_ids.get(method, []):
                    if self.functions.get(cand, {}).get("class_name") == other_type and cand not in matches:
                        matches.append(cand)

        if not matches:
            return []
        # For a trait (dyn) receiver every conformer is genuinely reachable
        # regardless of file, so the same-file preference is the wrong knob and
        # would truncate the fan-out (V19-3); apply it only to concrete receivers.
        if is_trait_recv:
            return matches
        same_file = [c for c in matches if self._in_file(c, caller_file)]
        return same_file if same_file else matches

    def _resolve_scoped(
        self, site: dict, caller_file: str, caller_class: Optional[str],
        name_to_ids: Dict[str, List[str]],
    ) -> List[str]:
        qualifier = site.get("qualifier")
        leaf = site.get("leaf")
        if not leaf:
            return []

        if qualifier == "Self":
            if caller_class:
                return self._resolve_typed_member(caller_class, leaf, caller_file, name_to_ids)
            return []

        # Step 1: direct qualified-name match ("Point.new" or "inner::inner_fn").
        # Cheap and precise -- covers same-type associated calls and inline
        # (same-file) module-qualified calls without any file-path guessing.
        if qualifier:
            for form in (f"{qualifier}.{leaf}", f"{qualifier}::{leaf}"):
                candidates = name_to_ids.get(form, [])
                if candidates:
                    same_file = [c for c in candidates if self._in_file(c, caller_file)]
                    return same_file if same_file else candidates

        # Step 2: qualifier is a known class/struct/enum/trait name -- typed
        # associated-function or (for a trait) default-method dispatch.
        if qualifier and (
            any(info.get("class_name") == qualifier for info in self.functions.values())
            or qualifier in self.trait_names
        ):
            resolved = self._resolve_typed_member(qualifier, leaf, caller_file, name_to_ids)
            if resolved:
                return resolved

        # Step 3: qualifier is a module (`mod foo;` / `mod foo { .. }`) --
        # resolve via the file that module maps to, tried both relative to
        # the caller's own directory and to the repo root (the common case
        # for `crate::foo::bar()` where `foo` is declared at the crate root).
        if qualifier:
            candidates = name_to_ids.get(leaf, [])
            if candidates:
                target_files = self._mod_target_files(qualifier, caller_file)
                if target_files:
                    matched = [
                        c for c in candidates
                        if self.functions.get(c, {}).get("file_path") in target_files
                    ]
                    if matched:
                        return matched

        # Step 4: same-file bare-leaf match, then unique-name fallback.
        candidates = name_to_ids.get(leaf, [])
        if not candidates:
            return []
        same_file = [c for c in candidates if self._in_file(c, caller_file)]
        if same_file:
            return same_file
        if len(candidates) == 1:
            return candidates
        # The qualifier bound nothing in Steps 1-3 and the raw leaf is ambiguous.
        # Fall back to exactly what a bare `leaf(` call resolves to (free-function
        # filter + import/external handling) -- this is what the pre-scoped-recovery
        # bare capture produced, so macro scoped-call recovery stays strictly
        # ADD-ONLY and never drops an edge the bare path would have kept (e.g. a
        # leaf shared by a free fn and a method: raw count == 2 here, but the bare
        # resolver picks the unique FREE function). Purely additive: only reached
        # when the raw fallback above would have returned [].
        return self._resolve_bare(leaf, caller_file, name_to_ids)

    def _mod_target_files(self, mod_name: str, caller_file: str) -> Set[str]:
        """Candidate file paths a `mod <mod_name>;` declaration could map to.

        Checked relative to both the caller's own directory (the common,
        correct case) and the repo root (covers `crate::mod_name::fn()` from
        a deeply nested caller when `mod_name` is actually declared at the
        crate root) -- see the module-level docstring for why this is a
        best-effort heuristic rather than full crate-path resolution.
        """
        declaring_files = {
            f for f, entries in self.imports.items()
            for e in entries if e.get("kind") == "mod" and e.get("name") == mod_name
        }
        targets: Set[str] = set()
        for declaring_file in declaring_files:
            base_dir = posixpath.dirname(declaring_file)
            for candidate_dir in (base_dir, ""):
                targets.add(posixpath.normpath(posixpath.join(candidate_dir, f"{mod_name}.rs")))
                targets.add(posixpath.normpath(posixpath.join(candidate_dir, mod_name, "mod.rs")))
        return targets

    def _in_file(self, cand_id: str, caller_file: str) -> bool:
        return self.functions.get(cand_id, {}).get("file_path") == caller_file
