"""
Stage 3: Call Graph Builder for Swift

Builds a bidirectional call graph from extracted Swift declarations.

Swift is a module-wide-namespace language with NO file-path imports (unlike Zig's
`@import("path")`), heavy overloading, and rich dispatch (self / Self / super /
Type.static / typed member / constructor / protocol). This resolver is a bounded,
tree-sitter-based approximation (NOT a full type checker) tuned to MAXIMIZE
reachability recall while avoiding gross same-name over-connection:

  tier 1 lexical alias (`let f = handler; f()`)
  tier 2 member call `recv.method` dispatched on the receiver's static type:
            - self/Self -> caller's enclosing type
            - typed local/param -> that type
            - Type.method -> static/type member on Type
            - unknown receiver -> bare-name fallback
  tier 3 constructor call `Type(...)` -> that type's init units
  tier 4 bare unqualified call -> enclosing type, then same file, then unique
            global; ambiguous-across-unrelated-types is DROPPED (namespace-leak)
  plus function-reference arguments (`map(transform)`, `use: handleRequest`)
            -> caller -> referenced function (callback reachability)
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from utilities.file_io import write_json

from tree_sitter import Language, Parser, Node


def _load_swift_language() -> Language:
    import tree_sitter_swift as ts_swift
    return Language(ts_swift.language())


# Swift stdlib / global funcs + Sequence/Collection methods whose names would add
# noise if treated as user calls. Filtered ONLY when no same-file user function
# shadows the name. NOTE: deliberately excludes TYPE names (String/Int/Array/...):
# constructor resolution needs type names live (`Array(...)` is a constructor call,
# not a filtered builtin), and an unresolved type name simply yields no edge anyway.
SWIFT_BUILTINS = {
    "print", "debugPrint", "dump", "assert", "assertionFailure", "precondition",
    "preconditionFailure", "fatalError", "abort", "min", "max", "abs", "swap",
    "zip", "stride", "sequence", "repeatElement",
    # Sequence / Collection higher-order + common methods (their trailing-closure
    # bodies' inner calls are still attributed to the enclosing unit).
    "map", "flatMap", "compactMap", "filter", "forEach", "reduce", "sorted",
    "sort", "first", "last", "contains", "allSatisfy", "append", "insert",
    "remove", "removeAll", "removeFirst", "removeLast", "joined", "prefix",
    "suffix", "enumerated", "reversed", "count", "isEmpty",
}

# The bare-callable GLOBAL free functions within SWIFT_BUILTINS. A bare ``print()`` /
# ``max()`` is the stdlib global, never an implicit-``self`` method — so a repo METHOD
# named after one of these must NOT bypass the builtin drop, else every bare global call
# phantom-edges to that one method (an in-degree explosion since these are called
# everywhere). The remaining (Collection/Sequence) builtins ARE idiomatically bare
# implicit-self method calls (``filter()`` == ``self.filter()``), so the method
# bypass applies to them.
_SWIFT_GLOBAL_FUNCS = {
    "print", "debugPrint", "dump", "assert", "assertionFailure", "precondition",
    "preconditionFailure", "fatalError", "abort", "min", "max", "abs", "swap",
    "zip", "stride", "sequence", "repeatElement",
}

# Contextual keywords whose trailing-closure form (`defer {... }`, a stored
# `deinit {... }` / `willSet {... }` / `get {... }` snippet) reparses as a
# call_expression whose callee is the keyword. They are never real user calls
# (all are reserved words, so no repo function can bear the name), so they resolve
# to nothing today — dropping them just removes noise from the call-site tally and
# the health metric, and pre-empts a phantom `deinit`->`deinit` edge if a `deinit`
# snippet were ever indexed by name.
_ACCESSOR_KEYWORD_CALLS = {"deinit", "willSet", "didSet", "get", "set", "defer"}

# Bare-name calls that stay ambiguous after same-type / same-file / unique
# resolution fan out to at most this many candidates (recall over precision, per
# the maximize-reachability goal); a larger candidate set is dropped to cap the
# namespace-leak blast radius. Tunable after measuring out-degree on real repos.
_AMBIGUOUS_FANOUT_MAX = 3


def _is_subsequence(sub, seq) -> bool:
    """True if every element of `sub` appears in `seq` in order (not necessarily
    contiguous). Used to check a call's labeled args are an ordered subset of a
    candidate's declared labels."""
    it = iter(seq)
    return all(x in it for x in sub)


class CallGraphBuilder:
    """Builds call graphs from extracted Swift functions."""

    def __init__(self, extractor_output: Dict[str, Any]):
        self.functions = extractor_output.get("functions", {})
        self.classes = extractor_output.get("classes", {})
        self.imports = extractor_output.get("imports", {})
        self.repository = extractor_output.get("repository", "")
        # Bare names of types actually DECLARED in the repo (class/struct/actor/enum/
        # protocol units — NOT types that are only `extension`-ed). Used to decide the
        # constructor-fallback policy: an unmatched ctor call on an external (extended-
        # only) type emits no edge (it is the stdlib ctor), while an unmatched call on
        # a repo-declared type keeps the recall-first all-inits fallback.
        self._repo_declared = {info.get("name") for info in self.classes.values() if info.get("name")}
        # bare function/method name -> its return type, ONLY when every unit of that
        # name shares one return type (conservative: an overloaded name with divergent
        # returns yields no typing, so we never mis-type `let x = f()`). Types more
        # receivers -> more typed-member dispatch instead of unknown-receiver drops
        # (convergent fix for the real-miss + untyped-tier phantom).
        self._func_return = self._build_return_index()
        # type bare-name -> direct supertype/protocol bare-names (from the
        # extractor's inheritance/extension-conformance clauses). Closed
        # transitively so a call dispatches to a method on a superclass or a
        # conformed protocol's extension, not only the exact receiver type.
        self.inheritance = extractor_output.get("inheritance", {})
        self._inherit_closure = self._compute_inherit_closure()
        # Reverse: protocol/base -> transitive conformers/subclasses. A call on a
        # receiver typed as a protocol or base class must reach the concrete
        # implementations (`any Authorizer`.authorize -> every conformer's
        # authorize), Swift's dominant dispatch shape on a protocol-heavy target.
        self._conformer_closure = self._compute_reverse_closure()
        self.parser = Parser(_load_swift_language())
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}
        # Diagnostics: an unusually low resolved-edge count on a large call-site
        # population is a silent-under-connection signal ('s health-check).
        self.stats_extra: Dict[str, int] = {}

    def _build_return_index(self) -> Dict[str, str]:
        """bare name -> return type, kept only when unambiguous across all its units."""
        by_name: Dict[str, set] = defaultdict(set)
        for info in self.functions.values():
            n = info.get("name")
            rt = info.get("return_type")
            if n and rt:
                by_name[n].add(rt)
        return {n: next(iter(rts)) for n, rts in by_name.items() if len(rts) == 1}

    def _compute_inherit_closure(self) -> Dict[str, set]:
        direct = {k: set(v) for k, v in self.inheritance.items()}
        closure: Dict[str, set] = {}
        for t in direct:
            seen: set = set()
            stack = list(direct.get(t, ()))
            while stack:
                s = stack.pop()
                if s in seen:
                    continue
                seen.add(s)
                stack.extend(direct.get(s, ()))
            closure[t] = seen
        return closure

    def _compute_reverse_closure(self) -> Dict[str, set]:
        """type bare-name -> ALL transitive conformers/subclasses (reverse edges)."""
        reverse: Dict[str, set] = defaultdict(set)
        for sub, supers in self.inheritance.items():
            for sup in supers:
                reverse[sup].add(sub)
        closure: Dict[str, set] = {}
        for t in reverse:
            seen: set = set()
            stack = list(reverse.get(t, ()))
            while stack:
                s = stack.pop()
                if s in seen:
                    continue
                seen.add(s)
                stack.extend(reverse.get(s, ()))
            closure[t] = seen
        return closure

    # -- canonical API ------------------------------------------------------

    def build_call_graph(self) -> None:
        call_graph: Dict[str, List[str]] = defaultdict(list)
        reverse_call_graph: Dict[str, List[str]] = defaultdict(list)

        name_to_ids = self._build_name_index()
        type_names, ctor_index = self._build_type_index(name_to_ids)

        try:
            alias_to_target = self._build_alias_index(name_to_ids)
        except Exception:
            alias_to_target = {}

        # Real site-level accounting (the old `total_call_sites` deduped
        # names per body and `resolved_edges` counted fan-out-inflated edges, so
        # neither was a resolution rate). Count actual call occurrences.
        sites_total = 0
        sites_resolved = 0
        sites_unresolved_repo_name = 0
        self._ctor_unmatched_sites = 0
        self._unknown_builtin_drops = 0
        self._unknown_builtin_drops_repo_named = 0
        for func_id, func_info in self.functions.items():
            code = func_info.get("code", "")
            file_path = func_info.get("file_path", "")
            caller_class = func_info.get("class_name")

            var_types, local_names, var_qualified = self._collect_var_types(code, type_names)
            call_sites, arg_refs = self._find_calls_in_code(code, file_path)

            for site in call_sites:
                sites_total += 1
                ids = self._resolve_call(
                    site, file_path, caller_class, name_to_ids, type_names,
                    ctor_index, alias_to_target, func_id, var_types, var_qualified)
                if ids:
                    sites_resolved += 1
                else:
                    # unresolved but a same-named unit EXISTS in the repo → a
                    # missed-edge candidate (vs a genuinely external call).
                    bare = site["text"].rsplit(".", 1)[-1]
                    if bare in name_to_ids or site["text"] in type_names:
                        sites_unresolved_repo_name += 1
                for rid in ids:
                    if rid != func_id:  # no self-calls (see SELF_EDGE note in validator)
                        if rid not in call_graph[func_id]:
                            call_graph[func_id].append(rid)
                        if func_id not in reverse_call_graph[rid]:
                            reverse_call_graph[rid].append(func_id)

            # Function-reference arguments (`register(handler)` / `use: handleRequest`):
            # scoped — skip locals (they are values), link only on a UNIQUE match.
            for ref in sorted(arg_refs):
                if ref in local_names:
                    continue
                ids = name_to_ids.get(ref, [])
                if len(ids) == 1 and ids[0] != func_id:
                    if ids[0] not in call_graph[func_id]:
                        call_graph[func_id].append(ids[0])
                    if func_id not in reverse_call_graph[ids[0]]:
                        reverse_call_graph[ids[0]].append(func_id)

        # Determinism: emit sorted adjacency lists (set/resolution order must not leak).
        self.call_graph = {k: sorted(v) for k, v in call_graph.items()}
        self.reverse_call_graph = {k: sorted(v) for k, v in reverse_call_graph.items()}
        self.stats_extra.update({
            "call_site_occurrences": sites_total,
            "sites_resolved": sites_resolved,
            "sites_unresolved_repo_name": sites_unresolved_repo_name,
            "site_resolution_rate": round(sites_resolved / sites_total, 3) if sites_total else 0,
            "ctor_unmatched_sites": self._ctor_unmatched_sites,
            "unknown_builtin_drops": self._unknown_builtin_drops,
            "unknown_builtin_drops_repo_named": self._unknown_builtin_drops_repo_named,
            "edge_count": sum(len(v) for v in self.call_graph.values()),
        })

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
            # Carry inheritance through so a saved call_graph.json can re-drive the
            # builder (export() dropped it, breaking round-trip re-analysis).
            "inheritance": self.inheritance,
            "statistics": self.get_statistics(),
        }

    def get_statistics(self) -> Dict[str, Any]:
        total_edges = sum(len(c) for c in self.call_graph.values())
        num_funcs = len(self.functions)
        out_degrees = [len(self.call_graph.get(f, [])) for f in self.functions]
        in_degrees = [len(self.reverse_call_graph.get(f, [])) for f in self.functions]
        isolated = sum(
            1 for f in self.functions
            if not self.call_graph.get(f) and not self.reverse_call_graph.get(f)
        )
        stats = {
            "total_functions": num_funcs,
            "total_edges": total_edges,
            "avg_out_degree": round(total_edges / num_funcs, 2) if num_funcs else 0,
            "avg_in_degree": round(total_edges / num_funcs, 2) if num_funcs else 0,
            "max_out_degree": max(out_degrees) if out_degrees else 0,
            "max_in_degree": max(in_degrees) if in_degrees else 0,
            "isolated_functions": isolated,
            "isolated_ratio": round(isolated / num_funcs, 3) if num_funcs else 0,
        }
        stats.update(self.stats_extra)
        return stats

    def get_dependencies(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Transitive callees of func_id up to depth (BFS). Canonical cross-parser
        interface parity with the Zig/C builders (
        'keep sibling parsers in lockstep'; these were missing on the Swift builder)."""
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
        """Transitive callers of func_id up to depth (BFS); parity with siblings."""
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

    # -- indexes ------------------------------------------------------------

    def _build_name_index(self) -> Dict[str, List[str]]:
        name_to_ids: Dict[str, List[str]] = defaultdict(list)
        for func_id, func_info in self.functions.items():
            name = func_info.get("name", "")
            qn = func_info.get("qualified_name", "")
            if name:
                name_to_ids[name].append(func_id)
            if qn and qn != name:
                name_to_ids[qn].append(func_id)
        return name_to_ids

    def _build_type_index(self, name_to_ids) -> Tuple[Set[str], Dict[str, List[str]]]:
        """Return (known bare type names, ctor_index: type_name -> [init func_ids]).

        A call whose callee is a known type name (`Point(...)`) is a constructor
        call — the declared units are `Point.init`, which `name_to_ids['init']`
        cannot resolve by the callee text `Point`. Index them by type name.
        """
        type_names: Set[str] = set()
        for info in self.classes.values():
            n = info.get("name")
            if n:
                type_names.add(n)
        # Also treat any class_name that carries methods as a known type.
        for info in self.functions.values():
            cn = info.get("class_name")
            if cn:
                type_names.add(cn)

        ctor_index: Dict[str, List[str]] = defaultdict(list)
        for func_id, info in self.functions.items():
            if info.get("unit_type") == "constructor" and info.get("class_name"):
                ctor_index[info["class_name"]].append(func_id)
        return type_names, dict(ctor_index)

    def _build_alias_index(self, name_to_ids) -> Dict[str, Dict[str, Set[str]]]:
        """Per-function `let f = knownFn` aliases (over-approximated as sets)."""
        alias_to_target: Dict[str, Dict[str, Set[str]]] = defaultdict(dict)
        for func_id, func_info in self.functions.items():
            code = func_info.get("code", "")
            if not code:
                continue
            try:
                tree = self.parser.parse(code.encode("utf-8"))
            except Exception:
                continue
            self._collect_aliases(tree.root_node, code.encode("utf-8"),
                                  name_to_ids, alias_to_target[func_id])
        return alias_to_target

    def _collect_aliases(self, root: Node, source: bytes, name_to_ids, aliases) -> None:
        """`let f = handler` where handler is a known function → alias f->handler.

        Iterative worklist walk (never self-recursive) so a pathologically deep
        AST cannot overflow the Python stack and abort the whole build.
        """
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "property_declaration":
                name = self._pattern_name(node, source)
                # RHS must be a bare identifier naming a known function (not a
                # call `= make()`, not an arbitrary expression).
                rhs = self._eq_rhs_identifier(node, source)
                if name and rhs and rhs in name_to_ids:
                    aliases.setdefault(name, set()).add(rhs)
            elif node.type == "assignment":
                # a REASSIGNMENT `f = b` (in a branch) — `var f = a; if c { f = b }
                # else { f = d }; f()` must union {a,b,d}, not keep only the initial
                # binding. The reassignment is an `assignment` node (LHS
                # `directly_assignable_expression > simple_identifier`), which the
                # property_declaration walk missed → only the first target survived
                # (the zig #167 alias-set-union lesson, unapplied to Swift assignments).
                # Flow-insensitive union = recall. Only a BARE-var LHS counts: `self.f`,
                # `arr[i]`, `obj.cb` are NOT local-var aliases.
                lhs = self._assignment_bare_lhs(node, source)
                rhs = self._eq_rhs_identifier(node, source)
                if lhs and rhs and rhs in name_to_ids:
                    aliases.setdefault(lhs, set()).add(rhs)
            stack.extend(node.children)

    def _assignment_bare_lhs(self, node: Node, source: bytes) -> Optional[str]:
        """LHS var name of `f = ...` iff the LHS is a BARE variable (a
        `directly_assignable_expression` wrapping a single simple_identifier). Returns
        None for `self.f =...` / `arr[i] =...` / `obj.cb =...` (not local aliases)."""
        lhs = next((c for c in node.children if c.type == "directly_assignable_expression"), None)
        if lhs is None:
            return None
        named = [g for g in lhs.children if g.is_named]
        if len(named) == 1 and named[0].type == "simple_identifier":
            return self._text(named[0], source)
        return None

    # -- receiver type model ------------------------------------------------

    def _collect_var_types(self, code: str, type_names=frozenset()) -> Tuple[Dict[str, str], Set[str], Dict[str, str]]:
        """Return (var_types, local_names, var_qualified) for one unit body.

        var_types maps a local var / parameter name -> its base static type, from:
          - `let/var x = Type(...)` (constructor-initializer type)
          - `let/var x: Type` (type annotation; optional/generic reduced)
          - function `parameter` name: Type (the caller's own parameters)
        A name redeclared with a conflicting type is dropped (ambiguous).
        local_names is every locally-bound identifier (all let/var patterns +
        parameters, typed or not) — used to keep an argument that is a local VALUE
        from being mistaken for a function reference.
        var_qualified maps a name -> the QUALIFIED constructed type for a
        `let x = Outer.Inner(...)` binding : `let` is immutable, so the
        dynamic type is EXACTLY the constructed nominal — a canonical-identity hint
        that _typed_members uses to narrow a bare-name collision (SeqA.Iterator vs
        SeqB.Iterator) WITHOUT the SUB-0 build. Recorded only for `let` (a `var` can
        be reassigned to another conformer — dropping that edge is a false negative);
        conflicting hints for one name are dropped. The hint NARROWS with a recall
        floor (empty subset -> keep the full bare set), so it can never drop an edge
        the bare path would reach (protects protocol-extension defaults / conformers).
        """
        var_types: Dict[str, str] = {}
        local_names: Set[str] = set()
        var_qualified: Dict[str, str] = {}
        ambiguous: Set[str] = set()
        qual_ambiguous: Set[str] = set()
        if not code:
            return var_types, local_names, var_qualified
        try:
            tree = self.parser.parse(code.encode("utf-8"))
        except Exception:
            return var_types, local_names, var_qualified
        src = code.encode("utf-8")

        def record(name: Optional[str], typ: Optional[str]):
            if name:
                local_names.add(name)
            if not name or not typ:
                return
            if name in ambiguous:
                return
            if name in var_types and var_types[name] != typ:
                ambiguous.add(name)
                var_types.pop(name, None)
            else:
                var_types[name] = typ

        def record_qual(name: Optional[str], qual: Optional[str]):
            if not name or not qual or name in qual_ambiguous:
                return
            if name in var_qualified and var_qualified[name] != qual:
                qual_ambiguous.add(name)
                var_qualified.pop(name, None)
            else:
                var_qualified[name] = qual

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == "property_declaration":
                name = self._pattern_name(node, src)
                typ = self._annotation_base_type(node, src)
                qual, tail = self._let_qualified_ctor(node, src)
                # only treat a `let x = A.B()` tail as a type when B is a
                # KNOWN repo type — else an uppercase ENUM CASE (`Result.Success(1)`) or
                # a static factory is misread as the nonexistent type `Success`, and
                # tier-2 typed dispatch dead-ends to no members (dropping a real edge).
                if tail is not None and tail not in type_names:
                    qual = tail = None
                if typ is None:
                    typ = self._ctor_init_type(node, src)
                # Unannotated `let x = Outer.Inner()`: _ctor_init_type only reads a
                # bare `Inner()` callee, so type the var from the qualified tail too.
                if typ is None and tail is not None:
                    typ = tail
                record(name, typ)
                record_qual(name, qual)
            elif node.type == "parameter":
                pname, ptype = self._param_name_type(node, src)
                record(pname, ptype)
            stack.extend(node.children)
        return var_types, local_names, var_qualified

    def _let_qualified_ctor(self, node: Node, src: bytes) -> Tuple[Optional[str], Optional[str]]:
        """For a `let x = Outer.Inner(...)` property_declaration return
        (qualified_type='Outer.Inner', bare_tail='Inner'); else (None, None).

        Requires: a `let` binding (value_binding_pattern -> `let`); an RHS
        call_expression whose callee is a navigation_expression whose final component
        is uppercase-initial (a type, not `obj.makeThing()`). `var` bindings and
        bare `Inner()` calls return (None, None)."""
        vbp = next((c for c in node.children if c.type == "value_binding_pattern"), None)
        if vbp is None or not any(c.type == "let" for c in vbp.children):
            return None, None
        call = next((c for c in node.children if c.type == "call_expression"), None)
        if call is None:
            return None, None
        callee = call.children[0] if call.children else None
        if callee is None or callee.type != "navigation_expression":
            return None, None
        suffix = next((c for c in reversed(callee.children)
                       if c.type == "navigation_suffix"), None)
        if suffix is None:
            return None, None
        tid = next((c for c in suffix.children if c.type == "simple_identifier"), None)
        tail = self._text(tid, src) if tid is not None else None
        if not tail or not tail[:1].isupper():
            return None, None
        return self._text(callee, src), tail

    def _annotation_base_type(self, node: Node, src: bytes) -> Optional[str]:
        """`x: Foo` / `x: Foo?` -> 'Foo'. Binds NOTHING for collection/tuple/
        function types (`x: [Foo]` must NOT bind x to the element type Foo)."""
        ann = next((c for c in node.children if c.type == "type_annotation"), None)
        if ann is None:
            return None
        tnode = next((c for c in ann.children if c.type != ":"), None)
        return self._nominal_base(tnode, src)

    def _nominal_base(self, tnode: Optional[Node], src: bytes) -> Optional[str]:
        """Reduce a type node to its base nominal name, soundly.

        - `optional_type` -> unwrap the wrapped type (`Foo?` -> Foo).
        - `user_type` -> its direct `type_identifier` (`Box<Int>` -> Box; do
                              NOT descend `type_arguments`, which would bind the
                              generic argument instead of the nominal).
        - `type_identifier`-> itself.
        - array/dictionary/tuple/function/metatype/protocol-composition -> None
          (binding a collection variable to its element type is a real bug — a
          `[Foo]` local's `.append(...)` must not dispatch to Foo's members).
        """
        if tnode is None:
            return None
        t = tnode.type
        if t == "optional_type":
            inner = next((c for c in tnode.children if c.type not in ("?", "!")), None)
            return self._nominal_base(inner, src)
        if t == "user_type":
            tid = next((c for c in tnode.children if c.type == "type_identifier"), None)
            return self._text(tid, src) if tid is not None else None
        if t == "type_identifier":
            return self._text(tnode, src)
        return None

    def _ctor_init_type(self, node: Node, src: bytes) -> Optional[str]:
        """`x = Type(...)` -> 'Type' (constructor), OR `x = foo()` -> foo's unique
        return type. The latter types a receiver from a factory/accessor call
        (`let c = makeClient(); c.send()`), so `c.send` dispatches on Client instead
        of falling through to the unknown-receiver path (fix)."""
        rhs = self._eq_rhs_node(node)
        if rhs is not None and rhs.type == "call_expression":
            callee = rhs.children[0] if rhs.children else None
            if callee is not None and callee.type == "simple_identifier":
                name = self._text(callee, src)
                # Strip leading underscores before the case test so a generated
                # `_StorageClass()` (the pattern) is still recognised as a ctor
                # (`'_'.isupper()` is False, so it was never typed).
                if name.lstrip("_")[:1].isupper():
                    return name  # constructor call -> the type itself
                # lowercase factory/accessor call -> its unique repo return type.
                rt = self._func_return.get(name)
                if rt is not None:
                    return rt
        return None

    def _param_name_type(self, node: Node, src: bytes) -> Tuple[Optional[str], Optional[str]]:
        """(internal_name, base_type) for a `parameter` node: `label name : Type`.

        The internal name (the one usable inside the body) is the identifier just
        before `:`; the type node follows `:`.
        """
        idents = [g for g in node.children if g.type == "simple_identifier"]
        if not idents:
            return None, None
        internal = self._text(idents[-1], src) if len(idents) >= 2 else self._text(idents[0], src)
        seen_colon = False
        type_node = None
        for c in node.children:
            if c.type == ":":
                seen_colon = True
                continue
            if seen_colon and c.type not in (",", "=") and not c.type.endswith("comment"):
                type_node = c
                break
        return internal, self._nominal_base(type_node, src)

    # -- call extraction ----------------------------------------------------

    def _find_calls_in_code(self, code: str, caller_file: str = ""):
        """Return (call_sites, arg_refs).

        call_sites: a LIST of per-occurrence records — {text, labels, arity,
          trailing} — for each `call_expression` / `constructor_expression`. `text`
          is a bare name (`foo`) or dotted receiver form (`recv.method`) or a bare
          type name (generic ctor). Preserving per-site argument labels is what lets
          the resolver pick the right init/overload instead of fanning out to all of
          them (the dominant phantom-edge class). A parse failure is RECORDED, not
          regex-approximated (Swift syntax defeats regex call detection).
        arg_refs: bare identifiers passed as arguments that may be function refs.
        """
        sites: List[dict] = []
        arg_refs: Set[str] = set()
        try:
            tree = self.parser.parse(code.encode("utf-8"))
        except Exception:
            self.stats_extra["reparse_error_bodies"] = self.stats_extra.get("reparse_error_bodies", 0) + 1
            return sites, arg_refs
        # tree-sitter returns an ERROR-bearing tree rather than raising, so an
        # `except` alone reports 0 failures while real bodies fail to parse.
        if tree.root_node.has_error:
            self.stats_extra["reparse_error_bodies"] = self.stats_extra.get("reparse_error_bodies", 0) + 1
        self._extract_calls(tree.root_node, code.encode("utf-8"), sites, arg_refs)

        shadowing = self._same_file_function_names(caller_file)
        repo_names = self._repo_function_names()
        # Filter builtins ONLY on BARE (unqualified) calls (a dotted member call is
        # decided by its receiver type) and drop accessor-keyword reparse phantoms.
        # A bare builtin-named call is KEPT when its name is a user-declared function
        # ANYWHERE in the repo, not just the caller's file: Swift idiomatically splits
        # one type across extensions in sibling files, so an implicit-`self` call to
        # the type's own `filter()`/`count()`/`remove()` method (name ∈ SWIFT_BUILTINS)
        # declared elsewhere would otherwise be silently dropped, taking its whole
        # subtree out of reachability — a silent false-negative. The resolver still
        # scopes the kept site by caller class/file; an unresolvable one is counted,
        # not dropped.
        kept = [
            s for s in sites
            if s["text"] not in _ACCESSOR_KEYWORD_CALLS
            and (
                "." in s["text"]
                or s["text"] in shadowing
                or (s["text"] in repo_names and s["text"] not in _SWIFT_GLOBAL_FUNCS)
                or s["text"] not in SWIFT_BUILTINS
            )
        ]
        return kept, arg_refs

    def _extract_calls(self, root: Node, source: bytes, sites: List[dict], arg_refs: Set[str]) -> None:
        """Iterative worklist walk collecting per-occurrence call-site records.

        Handles `call_expression` (callee = `simple_identifier` plain/ctor, or
        `navigation_expression` `recv.method`) AND `constructor_expression`
        (`Box<Int>(...)` — a generic/explicit ctor whose callee is a `user_type`,
        NOT a call_expression, so it was previously invisible → missed edges).
        A trailing-closure `lambda_literal` in `call_suffix` is counted toward arity;
        calls inside it are visited by the same walk (attributed to the enclosing unit).
        """
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "call_expression" and not self._is_subscript(node):
                callee = node.children[0] if node.children else None
                if callee is not None:
                    if callee.type == "simple_identifier":
                        labels, arity, trailing, unlabeled_trailing = self._call_labels(node, source)
                        sites.append({"text": self._text(callee, source),
                                      "labels": labels, "arity": arity, "trailing": trailing,
                                      "unlabeled_trailing": unlabeled_trailing})
                    elif callee.type == "navigation_expression":
                        dotted = self._navigation_text(callee, source)
                        if dotted:
                            labels, arity, trailing, unlabeled_trailing = self._call_labels(node, source)
                            # `member=True` marks EVERY navigation-derived call as a
                            # member call. A COMPLEX receiver (`makeClient().send()`,
                            # `items[i].load()`, `opt?.h.run()`) is reduced by
                            # _navigation_text to the bare method (no dot), so without
                            # this flag it looked like a bare call and re-entered the
                            # caller-locality heuristics — bypassing the fix.
                            sites.append({"text": dotted, "labels": labels,
                                          "arity": arity, "trailing": trailing,
                                          "unlabeled_trailing": unlabeled_trailing, "member": True})
                self._collect_arg_refs(node, source, arg_refs)
            elif node.type == "constructor_expression":
                # `Box<Int>(value: 1)` — callee is a `user_type`; the base nominal is
                # the constructor target. Generics-heavy code (NIO/protobuf/collections)
                # uses these routinely.
                ut = next((c for c in node.children if c.type == "user_type"), None)
                tname = None
                if ut is not None:
                    tid = next((g for g in ut.children if g.type == "type_identifier"), None)
                    if tid is not None:
                        tname = self._text(tid, source)
                if tname:
                    labels, arity, trailing, unlabeled_trailing = self._call_labels(node, source)
                    sites.append({"text": tname, "labels": labels, "arity": arity,
                                  "trailing": trailing, "unlabeled_trailing": unlabeled_trailing,
                                  "ctor": True})
            stack.extend(node.children)

    def _call_labels(self, call_node: Node, source: bytes):
        """Return (labels, arity, trailing, unlabeled_trailing) for a call/constructor.

        labels: one entry per argument (parenthesized value args AND trailing closures),
          in source order — the external label str, or None for a positional/elided-label
          argument. A SECONDARY trailing closure (SE-0279: `separator: {... }`) carries
          its label spelled as `simple_identifier ':' lambda_literal` directly under
          call_suffix — NOT wrapped in a value_argument — so it is extracted here, not by
          the value_argument path. The PRIMARY trailing closure's label is elided at the
          call site (Swift trailing-closure syntax).
        arity: total arguments. trailing: count of trailing closures.
        unlabeled_trailing: trailing closures whose label is elided (the primary). The
          matcher lets that many REQUIRED decl labels go UNspelled — a trailing closure
          fills its parameter without the call spelling the label; requiring it to be
          spelled wrongly rejects the true overload (recall loss).
        """
        labels: List[Optional[str]] = []
        trailing = 0
        unlabeled_trailing = 0
        suffix = next((c for c in call_node.children if c.type == "call_suffix"), None)
        # NOTE: a generic constructor_expression (`Box<Int>(value: 1)`) wraps its args in a
        # `constructor_suffix` node, which this walk does NOT descend — so generic ctors
        # currently yield no labels (a pre-existing over-fan-out gap, tracked as; not
        # touched by this fix). Plain call_expression uses call_suffix, handled here.
        if suffix is not None:
            containers = [suffix]
        else:
            containers = [c for c in call_node.children
                          if c.type in ("value_arguments", "lambda_literal")]
        for cont in containers:
            if cont is None:
                continue
            children = [cont] if cont.type == "value_arguments" else list(cont.children)
            i = 0
            while i < len(children):
                c = children[i]
                if c.type == "value_arguments":
                    for arg in c.children:
                        if arg.type != "value_argument":
                            continue
                        lbl = next((g for g in arg.children
                                    if g.type == "value_argument_label"), None)
                        if lbl is not None:
                            sid = next((g for g in lbl.children
                                        if g.type == "simple_identifier"), None)
                            labels.append(self._text(sid, source) if sid is not None else None)
                        else:
                            labels.append(None)  # positional
                    i += 1
                elif (c.type == "simple_identifier" and i + 2 < len(children)
                      and children[i + 1].type == ":"
                      and children[i + 2].type == "lambda_literal"):
                    labels.append(self._text(c, source))   # labeled secondary trailing closure
                    trailing += 1
                    i += 3
                elif c.type == "lambda_literal":
                    labels.append(None)                     # primary trailing closure (label elided)
                    trailing += 1
                    unlabeled_trailing += 1
                    i += 1
                else:
                    i += 1
        arity = len(labels)
        return labels, arity, trailing, unlabeled_trailing

    def _is_subscript(self, call_node: Node) -> bool:
        """True for a subscript access `x[i]` (value_arguments led by `[`)."""
        suffix = next((c for c in call_node.children if c.type == "call_suffix"), None)
        if suffix is None:
            return False
        va = next((c for c in suffix.children if c.type == "value_arguments"), None)
        if va is None or not va.children:
            return False
        return va.children[0].type == "["

    def _navigation_text(self, nav: Node, source: bytes) -> Optional[str]:
        """Reduce a navigation_expression to `receiver.method`.

        receiver = first child (`simple_identifier` | `self_expression` |
        nested `navigation_expression` | call/other expr); method = the
        `simple_identifier` under the `navigation_suffix`.
        """
        method = None
        recv_node = None
        for c in nav.children:
            if c.type == "navigation_suffix":
                sid = next((g for g in c.children if g.type == "simple_identifier"), None)
                if sid is not None:
                    method = self._text(sid, source)
            elif recv_node is None and c.type != ".":
                recv_node = c
        if method is None:
            return None
        if recv_node is None:
            return method
        if recv_node.type == "self_expression":
            return f"self.{method}"
        if recv_node.type == "simple_identifier":
            return f"{self._text(recv_node, source)}.{method}"
        if recv_node.type == "navigation_expression":
            inner = self._navigation_text(recv_node, source)
            recv = inner.rsplit(".", 1)[-1] if inner else None
            return f"{recv}.{method}" if recv else method
        # Complex receiver (call/subscript/paren) — unknown static type; dispatch
        # on the bare method name downstream (recall-preserving fallback).
        return method

    def _collect_arg_refs(self, call_node: Node, source: bytes, arg_refs: Set[str]) -> None:
        suffix = next((c for c in call_node.children if c.type == "call_suffix"), None)
        if suffix is None:
            return
        va = next((c for c in suffix.children if c.type == "value_arguments"), None)
        if va is None:
            return
        for arg in va.children:
            if arg.type != "value_argument":
                continue
            # The value expression is the LAST named child (a `value_argument_label`
            # + `:` may precede it). A bare `simple_identifier` value is a candidate
            # function reference. Reading only DIRECT `simple_identifier` children
            # missed every LABELED ref (`use: handleRequest`, `sorted(by:)`) because
            # 0.7.3 wraps the label in a `value_argument_label` node — 6210 sites.
            named = [g for g in arg.children if g.is_named]
            if not named:
                continue
            val = named[-1]
            if val.type == "simple_identifier":
                arg_refs.add(self._text(val, source))
            elif val.type == "selector_expression":
                # `#selector(handleTap)` / `action: #selector(foo)` — the target
                # method is a function reference (target-action idiom). The target
                # id sits INSIDE the selector_expression, so the bare-identifier
                # check above missed it. Take the last
                # simple_identifier (handles `#selector(Type.method)` too).
                sids = [g for g in val.children if g.type == "simple_identifier"]
                if sids:
                    arg_refs.add(self._text(sids[-1], source))

    def _same_file_function_names(self, caller_file: str) -> Set[str]:
        if not caller_file:
            return set()
        return {
            info.get("name", "")
            for info in self.functions.values()
            if info.get("file_path") == caller_file and info.get("name")
        }

    def _repo_function_names(self) -> Set[str]:
        """User-declared METHOD names across the repo (cached).

        Only METHOD names (``class_name`` present) bypass the SWIFT_BUILTINS drop:
        the rationale is a type's own method (e.g. ``filter()``) split into a sibling
        ``extension`` file, reached via implicit ``self``. A FREE function named after
        a stdlib builtin (``max``/``min``/``zip``/``print``/…) is NOT covered — bypassing
        the drop for it would fabricate a phantom edge at every bare stdlib call of that
        name across unrelated files. Free-function shadows stay on the
        same-file ``shadowing`` gate. ``self.functions`` is fully populated before any
        call extraction, so this snapshot is complete/stable.
        """
        cached = getattr(self, "_repo_names_cache", None)
        if cached is None:
            cached = {
                info.get("name", "")
                for info in self.functions.values()
                if info.get("name") and info.get("class_name")
            }
            self._repo_names_cache = cached
        return cached

    # -- resolution ---------------------------------------------------------

    def _in_file(self, cand_id: str, caller_file: str) -> bool:
        """Same-file membership by the structured `file_path` FIELD, not a fragile
        func_id string-prefix (`c.startswith(f"{file}:")`) that breaks if a path
        contains ':' or the id format changes."""
        return self.functions.get(cand_id, {}).get("file_path") == caller_file

    def _resolve_call(self, site, caller_file, caller_class, name_to_ids,
                      type_names, ctor_index, alias_to_target, caller_id,
                      var_types, var_qualified=None) -> List[str]:
        call_name = site["text"]
        # tier 1: alias expansion (a `let f = knownFn; f()` alias → its targets).
        targets = (alias_to_target or {}).get(caller_id, {}).get(call_name)
        names = sorted(targets) if targets else [call_name]

        resolved: List[str] = []
        for name in names:
            for rid in self._resolve_name(name, site, caller_file, caller_class,
                                          name_to_ids, type_names, ctor_index,
                                          var_types, var_qualified):
                if rid not in resolved:
                    resolved.append(rid)
        return resolved

    def _resolve_name(self, call_name, site, caller_file, caller_class, name_to_ids,
                      type_names, ctor_index, var_types, var_qualified=None) -> List[str]:
        # A member call reduced to a bare method (COMPLEX receiver — `foo().bar()`,
        # `arr[i].m()`) has no dot in its text but is NOT a call on the caller, so it
        # must not use the caller-locality heuristics. Detect it structurally
        # from the `member` flag, not from punctuation.
        member_unknown_recv = bool(site.get("member")) and "." not in call_name
        # tier 2: member call `recv.method`
        if "." in call_name and call_name not in name_to_ids:
            receiver, _, method = call_name.rpartition(".")
            is_super = receiver == "super"
            recv_type = None
            if receiver in ("self", "Self", "super"):
                recv_type = caller_class
            elif var_types and receiver in var_types:
                recv_type = var_types[receiver]
            elif receiver in type_names:
                recv_type = receiver  # Type.staticMethod / Type.init / Outer.Inner(...)

            # nested-type / qualified constructor `Outer.Inner(...)` — `method`
            # is itself a known type name, so this is a constructor of that nested
            # type, NOT a method call. Resolve to its (label-matched) inits.
            if method in type_names and method not in ("init",):
                # `Outer.Inner(...)` / `Msg1.Storage(...)` — pass the FULL qualified
                # target (`call_name` = receiver.method) so _match_ctors filters to the
                # right nested type's inits, not every same-bare-named type's.
                return self._match_ctors(method, ctor_index, site, caller_file,
                                         qualified_type=call_name)

            if recv_type is not None:
                if method == "init":
                    # `Type.init` / `self.init` / `Self.init` -> that type's ctors;
                    # `super.init` -> the SUPERtype's ctors (P-4: the old code used
                    # caller_class, binding super.init to the SUBCLASS's own inits).
                    if is_super:
                        out = []
                        for sup in sorted(self._inherit_closure.get(caller_class, ())):
                            out.extend(self._match_ctors(sup, ctor_index, site, caller_file))
                        return out
                    return self._match_ctors(recv_type, ctor_index, site, caller_file)
                # Known receiver type: dispatch on that type + its hierarchy. `super`
                # dispatches on the SUPERtypes only (not the caller's own class).
                accept = self._dispatch_types(recv_type, is_super)
                members = self._typed_members(accept, recv_type, method, name_to_ids)
                # Known receiver: a trailing closure may fill a required label unspelled
                #. Safe to relax here — this dispatches on a KNOWN type's own
                # overloads (no unknown-receiver decline, no bare-name fan-out cap).
                narrowed = self._match_overloads(members, site, allow_unlabeled_trailing=True)
                # apply the `let x = Outer.Inner()` qualified-identity
                # narrowing AFTER signature matching, not before — filtering bare-name
                # matches first kept an arity-INCOMPATIBLE same-qualified candidate and
                # dropped the real inherited/compatible one (`v.m()` -> Base.m). Floor:
                # an empty subset keeps the full narrowed set (never fewer edges than
                # signature matching alone), preserving the SeqA/SeqB collision win.
                if var_qualified and not is_super and narrowed:
                    qh = var_qualified.get(receiver)
                    if qh:
                        # guard : the unlabeled-trailing allowance is
                        # TYPE-BLIND — it can admit a same-qualified DECOY overload
                        # (`x.run { }` admitting `Outer.Inner.run(name:)`), which the
                        # var_qualified subset then prefers, EVICTING the strictly-matched
                        # inherited target (`Base.run(_:)`). Both share the qualified name,
                        # so no set-diff gate sees the loss. If the relaxation added a
                        # candidate, skip the subset — mirror the `_match_ctors`
                        # `relaxed_added` guard (same pattern constructor side).
                        relaxed_added = (
                            site.get("unlabeled_trailing", 0) > 0
                            and set(self._compatible_subset(members, site,
                                                            allow_unlabeled_trailing=True))
                            != set(self._compatible_subset(members, site)))
                        if not relaxed_added:
                            subset = [c for c in narrowed
                                      if self.functions.get(c, {}).get("qualified_name", "")
                                      in (f"{qh}.{method}",)
                                      or self.functions.get(c, {}).get("qualified_name", "")
                                      .endswith(f".{qh}.{method}")]
                            if subset:
                                return subset
                return narrowed
            # Unknown receiver type: bare method name (recall) unless it is a stdlib
            # name (an unknown-receiver `a.append`/`xs.map` is the external method,
            # not a same-named user fn — resolving it fabricates edges).
            if method in SWIFT_BUILTINS:
                # reason-coding: an unknown-receiver builtin-named call DECLINES
                # (X.1 — resolving `x.append()` on an untyped receiver to a repo-defined
                # `Foo.append` is a cross-scope guess; most such calls target stdlib
                # collections, so a guess adds net phantom). Count the declines — and
                # separately the ones where the repo ALSO defines that name (the real
                # recall cost of this policy) — so it is observable and revisitable.
                self._unknown_builtin_drops = getattr(self, "_unknown_builtin_drops", 0) + 1
                if method in name_to_ids:
                    self._unknown_builtin_drops_repo_named = getattr(
                        self, "_unknown_builtin_drops_repo_named", 0) + 1
                return []
            call_name = method
            member_unknown_recv = True

        # tier 3: constructor call `Type(...)` / `Self(...)`.
        if call_name == "Self" and caller_class:
            return self._match_ctors(caller_class, ctor_index, site, caller_file)
        if call_name in type_names and call_name not in name_to_ids:
            return self._match_ctors(call_name, ctor_index, site, caller_file)

        candidates = name_to_ids.get(call_name, [])
        if not candidates:
            return []

        # tier 4: bare unqualified — enclosing type (+ its hierarchy), same file,
        # unique, else bounded fan-out. Apply the signature matcher at each step so a
        # bare overloaded call narrows to the compatible overloads.
        # The enclosing-type preference applies ONLY to a genuinely-bare call `foo()`
        # (which could be the caller's own method). An unknown-receiver member call
        # `recv.foo()` that fell through here is NOT on the caller — preferring the
        # caller's enclosing type wrongly matched EVERY unit sharing the caller's bare
        # class_name (e.g. inside `SeqA.Iterator.next`, `base.next()` fanned to all 38
        # `Iterator.next` across files — /, 948 phantom edges on
        # swift-async-algorithms). For such calls skip straight to same-file/unique/
        # bounded so a huge ambiguous set is capped/dropped, not matched.
        # Both the enclosing-type AND same-file steps are CALLER-LOCALITY heuristics
        # (the target is the caller's own method / near the caller). Neither applies
        # to an unknown-receiver member call `recv.foo()` — the method is on `recv`,
        # not the caller. Applying same-file to it made a `.traverse()` in a giant
        # generated protobuf file fan out to all 157 same-name `visitX` methods in
        # that file (uncapped same-file tier; +54k edges on a large Swift corpus).
        # For an unknown-receiver member call, go straight to unique / bounded-fanout.
        if not member_unknown_recv:
            if caller_class:
                accept = {caller_class} | self._inherit_closure.get(caller_class, set())
                same_type = [c for c in candidates
                             if self.functions.get(c, {}).get("class_name") in accept]
                if same_type:
                    # a BARE call `run { }` inside a class is implicit `self.run` --
                    # this dispatches on the caller's own type hierarchy, so the trailing-
                    # closure allowance resolves the required-label-filled overload like the
                    # explicit-receiver path (:908).
                    #
                    # RECALL FLOOR : enable the relaxation ONLY when strict
                    # matching already found a compatible candidate. If strict finds NONE,
                    # `_match_overloads` returns the FULL same_type set (recall fallback) --
                    # and the type-blind relaxation would narrow that to a decoy, EVICTING a
                    # real target the strict matcher missed for an UNRELATED reason (a
                    # variadic / parameter-pack callee whose arity is under-counted fails the
                    # arity bound under BOTH strict and relaxed, so it only ever survives via
                    # the fallback). Evicted and retained share leaf AND qualified name, so
                    # no set-diff oracle can see the loss. Gating on a non-empty strict subset
                    # keeps the fallback intact (0 lost) while still refining a real
                    # resolution (238 gained) -- strictly dominant on the corpus.
                    if self._compatible_subset(same_type, site):
                        return self._match_overloads(same_type, site,
                                                     allow_unlabeled_trailing=True)
                    return self._match_overloads(same_type, site)
            same_file = [c for c in candidates if self._in_file(c, caller_file)]
            if same_file:
                # (same-FILE tier only — the enclosing-type tier above keeps its
                # recall fallback, since dropping a real same-type method overload is
                # a false negative): an INCOMPATIBLE same-file free-function candidate
                # must not block a signature-compatible one in another file (a same-
                # file `helper(x:)` shadowed a cross-file `helper(y:)` the call
                # `helper(y:1)` actually targets). Prefer the strict-compatible same-
                # file subset; if none compatible here but a compatible exists
                # elsewhere, fall through so it wins; else keep the recall fallback.
                sf_ok = [c for c in same_file
                         if self._labels_compatible(site, self.functions.get(c, {}))]
                if sf_ok:
                    return sf_ok
                any_compatible = any(self._labels_compatible(site, self.functions.get(c, {}))
                                     for c in candidates)
                if not any_compatible:
                    return self._match_overloads(same_file, site)
        if len(candidates) == 1:
            return candidates
        narrowed = self._match_overloads(candidates, site)
        if len(narrowed) <= _AMBIGUOUS_FANOUT_MAX:
            return narrowed
        return []

    def _dispatch_types(self, recv_type: str, is_super: bool) -> set:
        """Accepted declaring types for a member dispatch on `recv_type`.

        Non-super: recv_type + supertypes (inherited/protocol-default) + conformers/
        subclasses (dynamic dispatch). Super: the supertypes ONLY (a `super.m()` call
        must reach the superclass implementation, never the caller's own)."""
        if is_super:
            return set(self._inherit_closure.get(recv_type, set()))
        return ({recv_type}
                | self._inherit_closure.get(recv_type, set())
                | self._conformer_closure.get(recv_type, set()))

    def _typed_members(self, accept: set, recv_type: str, method: str, name_to_ids) -> List[str]:
        matches: List[str] = []
        for cand in name_to_ids.get(method, []):
            info = self.functions.get(cand, {})
            cn = info.get("class_name")
            qn = info.get("qualified_name", "")
            if cn in accept or qn == f"{recv_type}.{method}" \
                    or qn.endswith(f".{recv_type}.{method}"):
                if cand not in matches:
                    matches.append(cand)
        return matches

    def _match_ctors(self, type_name: str, ctor_index, site, caller_file="", qualified_type=None) -> List[str]:
        """Resolve a constructor call to the label/arity-COMPATIBLE inits of the
        type. A `Type(...)` call used to link to EVERY init overload (79% of
        edges on swift-argument-parser; one `Option(name:)` → all 21 inits). Narrow
        by the call's argument labels; unmatched → all-inits fallback + counter
        (recall: a missed edge silently prunes the paid scan, an unrecoverable FN).

        Bare-name COLLISION guard: when the bare type name is declared in MANY files
        (SwiftProtobuf generates a nested `_StorageClass` per message — 202 units, 30
        files, identical `()` signatures the matcher cannot separate → one call fanned
        to ~101 phantom inits, 20,705 edges into that one bucket on a large Swift corpus),
        prefer the SAME-FILE init(s): a private/nested storage type is only ever
        constructed within its own type's file. A uniquely-named type has all its
        inits in one file, so this never narrows a legitimate cross-file `Foo()`.
        """
        ids = ctor_index.get(type_name, [])
        if not ids:
            return []
        matched = self._compatible_subset(ids, site, allow_unlabeled_trailing=True)
        # (zero churn): a call with an EXPLICIT qualified target
        # (`Msg1.Storage(...)`, `Outer.Inner(...)`) carries canonical identity that the
        # bare `ctor_index[type_name]` throws away — it returns every `Storage.init`
        # across all files. When the qualified type is known, keep only the inits whose
        # qualified_name matches it (`Msg1.Storage.init`). Cut 6→1 on the probe; −289
        # phantom inits on protobuf, −11 on nio.
        if matched and qualified_type:
            exact = [c for c in matched
                     if self.functions.get(c, {}).get("qualified_name", "") in
                     (f"{qualified_type}.init",)
                     or self.functions.get(c, {}).get("qualified_name", "").endswith(f".{qualified_type}.init")]
            if exact:
                return exact
        if matched:
            # The unlabeled-trailing allowance is TYPE-BLIND: a trailing closure may fill
            # any required-labeled param, so the allowance can admit a same-file DECOY init
            # (e.g. `Widget { }` admitting `init(name: String)`). If it added a candidate,
            # skip the same-file tie-break — otherwise that decoy would evict the true
            # cross-file init the STRICT matcher already resolved (; both share the
            # qualified name, so no set-diff gate can see the loss). Non-trailing-closure
            # calls (protobuf `_StorageClass()`) are unaffected: strict == relaxed there.
            relaxed_added = (site.get("unlabeled_trailing", 0) > 0
                             and set(matched) != set(self._compatible_subset(ids, site)))
            if (caller_file and not relaxed_added
                    and len({self.functions.get(c, {}).get("file_path")
                             for c in matched}) > 1):
                same_file = [c for c in matched if self._in_file(c, caller_file)]
                if same_file:
                    return same_file
            return matched
        # No compatible init. The fallback policy DEPENDS on whether the type is
        # repo-DECLARED or merely repo-EXTENDED (external):
        # - external type (String/Data/Logger — extended in-repo, not declared):
        # an unmatched call is almost certainly the STDLIB constructor
        # (`String(format:)` matches no repo `extension String` init), so emit NO
        # edge. Falling back to all repo extension inits fabricated the dominant
        # phantom class on security-pcc (String.init in-degree 13,025; avg 4.87
        # edges per ctor site). This is the "extension of an external type"
        # hazard from the design review, now measured at scale.
        # - repo-declared type: keep the recall-first all-inits fallback (a
        # construction of OUR type reaches OUR init; a missed edge silently prunes
        # the paid scan).
        if type_name not in self._repo_declared:
            return []
        self._ctor_unmatched_sites = getattr(self, "_ctor_unmatched_sites", 0) + 1
        return list(ids)

    def _compatible_subset(self, cand_ids: List[str], site, allow_unlabeled_trailing=False) -> List[str]:
        """The candidates whose parameter list is compatible with the call site's
        labels/arity — NO fallback. Empty means "none matched" (the caller decides
        what to do with that).

        ``allow_unlabeled_trailing`` is set for constructor matching AND for a known-
        receiver method dispatch on an EXPLICIT receiver, where a trailing-closure
        DSL / trailing closure (`Prefix { }`, `Many { } separator: { }`, `r.run { }`)
        legitimately fills a required param without spelling its label. It is NOT set for
        the bare-name / unknown-receiver fan-out path: broadening the compatible set there
        would tip a unique-resolution into a non-unique DECLINE and silently drop a real
        edge (measured: it dropped 395 edges corpus-wide, incl. Alamofire `Protected.write`)."""
        if len(cand_ids) <= 1:
            return list(cand_ids)
        return [c for c in cand_ids
                if self._sig_compatible(site, self.functions.get(c, {}), allow_unlabeled_trailing)]

    def _match_overloads(self, cand_ids: List[str], site, allow_unlabeled_trailing=False) -> List[str]:
        """Filter a same-name candidate set to the signature-compatible ones.
        Conformer fan-out (same signature on different types) survives — only same-
        name OVERLOADS (different signatures) get narrowed. If NONE are compatible,
        keep the full set (recall over precision — for a METHOD, the missed edge is
        the expensive error). Constructors use `_compatible_subset` directly so they
        can apply the external-type no-edge policy instead of this recall fallback.

        ``allow_unlabeled_trailing`` is set ONLY for a KNOWN-receiver method dispatch on
        an EXPLICIT receiver (`r.run { }` where `run(while:)` is required-but-
        closure-filled). Like the constructor case, a trailing closure fills its param
        without spelling the label; strict matching wrongly resolves to an all-defaulted
        decoy and starves the true overload. The other method sites stay STRICT for
        SITE-SPECIFIC reasons, not one blanket cap/decline rule :
          - bare-name fan-out (the `<= _AMBIGUOUS_FANOUT_MAX` gate below): relaxing can
            grow the set past the cap -> the whole set is dropped. THIS is the cap case.
          - implicit-self enclosing-type dispatch (`same_type`, returns directly, no cap):
            relaxing IS a valid recovery, but a SEPARATE measured change needing
            its own recall gate (corpus delta +238/-477) — deferred, not cap-blocked.
          - same-file free-function fallback (returns directly, no cap): relaxing is a
            measured no-op (0 corpus sites) — left strict for consistency."""
        compat = self._compatible_subset(cand_ids, site, allow_unlabeled_trailing)
        return compat if compat else list(cand_ids)

    def _labels_compatible(self, site, cand_info) -> bool:
        """Label-only compatibility (subsequence + required-named), WITHOUT the
        arity bounds. Used by the fall-through gate (E): `_sig_compatible`
        has no variadic model — a variadic decl (`process(_ v: Int...)`) fails the
        arity bound yet is really compatible, so vetoing a same-file candidate on
        ARITY could redirect a real edge to a phantom cross-file overload. An arity
        mismatch only costs precision here (keep the same-file candidate), never recall;
        only a LABEL mismatch is trustworthy enough to fall through to another scope."""
        decl_labels = cand_info.get("signature", []) or []
        decl_defaults = cand_info.get("param_defaults") or [False] * len(decl_labels)
        if len(decl_defaults) != len(decl_labels):
            decl_defaults = [False] * len(decl_labels)
        labeled = [l for l in site.get("labels", []) if l]
        decl_named = [decl_labels[i] for i in range(len(decl_labels))
                      if decl_labels[i] not in (None, "_")]
        if not _is_subsequence(labeled, decl_named):
            return False
        required_named = {decl_labels[i] for i in range(len(decl_labels))
                          if not decl_defaults[i] and decl_labels[i] not in (None, "_")}
        return required_named.issubset(set(labeled))

    def _sig_compatible(self, site, cand_info, allow_unlabeled_trailing=False) -> bool:
        """Ordered-subsequence-with-defaults matcher. A call binds to a decl if
        every labeled arg appears among the decl's labels in order, every REQUIRED
        (non-default) NAMED decl label is supplied, and the arity is feasible.

        ``allow_unlabeled_trailing`` (constructor context only): let up to
        `unlabeled_trailing` required labels go unspelled — a trailing closure fills its
        param without the call spelling the label (`Prefix { }` -> `init(while:)`)."""
        decl_labels = cand_info.get("signature", []) or []
        decl_defaults = cand_info.get("param_defaults") or [False] * len(decl_labels)
        if len(decl_defaults) != len(decl_labels):
            decl_defaults = [False] * len(decl_labels)
        call_labels = site.get("labels", [])
        arity = site.get("arity", len(call_labels))
        trailing = site.get("trailing", 0)

        labeled = [l for l in call_labels if l]
        decl_named = [decl_labels[i] for i in range(len(decl_labels)) if decl_labels[i] not in (None, "_")]
        if not _is_subsequence(labeled, decl_named):
            return False
        required_named = {decl_labels[i] for i in range(len(decl_labels))
                          if not decl_defaults[i] and decl_labels[i] not in (None, "_")}
        allowance = site.get("unlabeled_trailing", 0) if allow_unlabeled_trailing else 0
        if len(required_named - set(labeled)) > allowance:
            return False
        n_params = len(decl_labels)
        n_required = sum(1 for d in decl_defaults if not d)
        # +1 arity slack for variadics / trailing-closure param modeling imperfection.
        if arity > n_params + 1:
            return False
        if arity < n_required - trailing:
            return False
        return True

    # -- small helpers ------------------------------------------------------

    def _pattern_name(self, node: Node, src: bytes) -> Optional[str]:
        pat = next((c for c in node.children if c.type == "pattern"), None)
        if pat is not None:
            sid = next((g for g in pat.children if g.type == "simple_identifier"), None)
            if sid is not None:
                return self._text(sid, src)
        return None

    def _eq_rhs_node(self, node: Node) -> Optional[Node]:
        seen_eq = False
        for c in node.children:
            if c.type == "=":
                seen_eq = True
                continue
            if seen_eq and c.type not in (";",):
                return c
        return None

    def _eq_rhs_identifier(self, node: Node, src: bytes) -> Optional[str]:
        rhs = self._eq_rhs_node(node)
        if rhs is not None and rhs.type == "simple_identifier":
            return self._text(rhs, src)
        return None

    def _bare(self, call_name: str) -> str:
        return call_name.rsplit(".", 1)[-1]

    def _text(self, node: Node, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
