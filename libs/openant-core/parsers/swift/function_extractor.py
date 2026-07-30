"""
Stage 2: Function Extractor for Swift

Extracts functions, methods, initializers, deinitializers, and call-bearing
property accessors from Swift source files using tree-sitter.

Node-type names below were verified against tree-sitter-swift 0.7.3 by parsing
representative fixtures (see openant-work/SWIFT-PARSER-DESIGN.md). Guessing
tree-sitter node names silently extracts nothing — every name here is grounded.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from utilities.file_io import write_json

from tree_sitter import Language, Parser, Node


def _load_swift_language() -> Language:
    """Load the Swift tree-sitter grammar lazily.

    The grammar package (``tree-sitter-swift``) is an optional runtime
    dependency. Importing it at module top level would make the entire Swift
    parser unimportable in any environment where the package is absent (e.g. a
    clean install that does not need Swift support). Resolving it here, on first
    use, lets the module import unconditionally and surfaces a clear, actionable
    error only when the Swift parser is actually exercised.
    """
    try:
        import tree_sitter_swift as ts_swift
    except ImportError as exc:  # pragma: no cover - exercised via the no-dep test
        raise ImportError(
            "The Swift parser requires the 'tree-sitter-swift' package, which is "
            "not installed. Install it with `pip install tree-sitter-swift` "
            "(declared in pyproject.toml / requirements.txt)."
        ) from exc
    return Language(ts_swift.language())


# Container declaration kinds that introduce a type scope. `class_declaration`
# is the tree-sitter-swift node for class / struct / actor / enum / extension
# (disambiguated by its leading keyword child); protocol has its own node.
_CONTAINER_TYPES = {"class_declaration", "protocol_declaration"}

# The leading keyword child of a class_declaration tells us the real kind.
_CONTAINER_KEYWORDS = {"class", "struct", "actor", "enum", "extension"}

_VISIBILITY_EXPORTED = {"public", "open"}

# Declaration node types that are NOT executable top-level statements. Everything
# else at the top level of `main.swift` runs at program start (incl. a
# `try_expression`/`await_expression` daemon root), so `_emit_toplevel` collects by
# EXCLUDING these rather than allow-listing call_expression (which missed async roots).
_TOP_LEVEL_EXCLUDE = {
    "import_declaration", "class_declaration", "protocol_declaration",
    "function_declaration", "init_declaration", "deinit_declaration",
    "typealias_declaration", "associatedtype_declaration",
    "operator_declaration", "precedence_group_declaration",
    "comment", "multiline_comment",
}


class _TypeContext:
    """Enclosing-type scope threaded through the walk.

    - ``path``: full nested type path (Outer.Inner) → makes qualified_name /
      func_id unique across different outer scopes (prevents sibling collision).
    - ``bare``: bare leaf type name (Inner) → the receiver resolver matches a
      call's static receiver TYPE, which is bare, so class_name must be bare.
    - ``exported``: True iff every enclosing type is public/open (a public member
      inside an internal type is NOT externally callable — Swift access rules).
    - ``default_public``: the nearest enclosing ``public extension`` / ``public``
      container sets the default member access to public for members without an
      explicit visibility modifier.
    """

    __slots__ = ("path", "bare", "exported", "default_public")

    def __init__(self, path: Optional[str], bare: Optional[str],
                 exported: bool, default_public: bool):
        self.path = path
        self.bare = bare
        self.exported = exported
        self.default_public = default_public


class FunctionExtractor:
    """Extracts functions, methods and accessors from Swift source via tree-sitter."""

    def __init__(self, repo_path: str, scan_results: Dict[str, Any]):
        self.repo_path = Path(repo_path).resolve()
        self.scan_results = scan_results
        self.parser = Parser(_load_swift_language())

    # -- public API ---------------------------------------------------------

    def extract(self) -> Dict[str, Any]:
        """Extract all declarations from scanned files.

        Returns the functions.json structure (functions, classes, imports, stats).
        """
        functions: Dict[str, Any] = {}
        classes: Dict[str, Any] = {}
        imports: Dict[str, List[str]] = {}
        # type bare-name -> set of direct supertype/conformance bare-names. Merges
        # class/struct/actor/enum inheritance clauses AND `extension T: P` clauses.
        # The call-graph builder closes this transitively for superclass / protocol
        # -default dispatch (a call resolves to a method on a supertype/protocol
        # extension, not only the exact receiver type).
        inheritance: Dict[str, set] = {}
        files_processed = 0
        files_with_errors = 0

        # Prepass: the set of bare type names declared `public`/`open` anywhere.
        # A member of an `extension T { public func... }` is public API iff the
        # TARGET type T is public — the extension's own (absent) modifier does not
        # make an explicitly-public member internal. Without this, 720 public
        # security-pcc units were wrongly marked internal, gutting library-mode.
        self._public_types, self._repo_types = self._collect_public_types()

        for file_info in self.scan_results.get("files", []):
            file_path = file_info["path"]
            full_path = self.repo_path / file_path

            try:
                with open(full_path, "rb") as f:
                    source = f.read()

                tree = self.parser.parse(source)
                file_imports: List[str] = []
                root_ctx = _TypeContext(None, None, exported=True, default_public=False)
                self._walk(tree.root_node, source, file_path,
                           functions, classes, file_imports, inheritance, root_ctx)
                self._emit_toplevel(tree.root_node, source, file_path, functions)
                imports[file_path] = file_imports
                files_processed += 1
            except Exception as e:  # pragma: no cover - defensive per-file guard
                # One malformed file must never abort the whole repo parse
                # (mirrors parsers/python guard). Record and continue.
                print(f"Error processing {file_path}: {e}")
                files_with_errors += 1

        # Post-pass: re-classify framework-owned execution roots as `main` entry
        # points using conformance/attribute info now that ALL types + extension
        # conformances are known. Covers @main types, Swift-ArgumentParser
        # `ParsableCommand.run()`, SwiftUI `App.body`, and `Codable init(from:)`
        # (untrusted-payload decode) — daemon/CLI/XPC roots that seed nothing
        # otherwise. Conformances arrive via extensions in other files, so this
        # must run after the whole-repo walk.
        self._apply_framework_entry_points(functions, classes, inheritance)

        return {
            "repository": str(self.repo_path),
            "extraction_time": datetime.now().isoformat(),
            "functions": functions,
            "classes": classes,
            "imports": imports,
            "inheritance": {k: sorted(v) for k, v in inheritance.items()},
            "statistics": {
                "total_functions": len(functions),
                "total_classes": len(classes),
                "files_processed": files_processed,
                "files_with_errors": files_with_errors,
            },
        }

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        write_json(output_path, results)

    # -- walk ---------------------------------------------------------------

    def _walk(self, node: Node, source: bytes, file_path: str,
              functions: Dict[str, Any], classes: Dict[str, Any],
              imports_list: List[str], inheritance: Dict[str, set],
              ctx: _TypeContext, top_level: bool = True) -> None:
        """Recursively walk the AST, threading the enclosing-type context.

        `top_level` is True only for the direct children of `source_file` (true
        module scope). It distinguishes a file-scope global `let h = {…}` from a
        LOCAL `let x = …` inside a function body — both have `ctx.bare is None`
        (function bodies reset the type context, E-04), so ctx alone can't tell them
        apart, and must only emit the file-scope ones (not every local var)."""
        child_ctx = ctx

        if node.type == "import_declaration":
            mod = self._import_module(node, source)
            if mod:
                imports_list.append(mod)

        elif node.type in _CONTAINER_TYPES:
            info = self._container_info(node, source, ctx)
            if info is not None:
                bare, full_path, exported, default_public, is_type_decl, supers, container_attrs = info
                if is_type_decl:  # class/struct/actor/enum/protocol (not extension)
                    struct_id = f"{file_path}:{full_path}"
                    classes[struct_id] = {
                        "name": bare,
                        "qualified_name": full_path,
                        "file_path": file_path,
                        "start_line": node.start_point[0] + 1,
                        "end_line": node.end_point[0] + 1,
                        "inherits": sorted(supers),
                        # Container attributes (@main / @objcMembers / …) so the
                        # framework-entry post-pass can seed an @main type's root.
                        "decorators": container_attrs,
                    }
                if supers:
                    inheritance.setdefault(bare, set()).update(supers)
                child_ctx = _TypeContext(full_path, bare, exported, default_public)

        elif node.type in ("function_declaration", "init_declaration", "deinit_declaration"):
            self._emit_function(node, source, file_path, functions, ctx)
            # Descend into the body with a FUNCTION scope (no enclosing type): a
            # nested local `func` is function-scoped, NOT a method of the enclosing
            # type. Threading the type context down made `func m(){ func h(){} }`
            # emit `Outer.h` with class_name=Outer — a phantom method (83 on the
            # real target). A local TYPE still starts a fresh type scope via the
            # container branch, so nested types are unaffected.
            child_ctx = _TypeContext(None, None, exported=False, default_public=False)

        elif node.type == "property_declaration":
            self._emit_property_accessors(node, source, file_path, functions, ctx, top_level)

        elif node.type == "subscript_declaration":
            self._emit_subscript_accessors(node, source, file_path, functions, ctx)

        # Children of `source_file` are module scope (top_level); anything deeper is
        # inside a type/function/block and is NOT a file-scope global.
        child_top = node.type == "source_file"
        for child in node.children:
            self._walk(child, source, file_path, functions, classes,
                       imports_list, inheritance, child_ctx, child_top)

    def _emit_toplevel(self, root: Node, source: bytes, file_path: str,
                       functions: Dict[str, Any]) -> None:
        """Synthesize a `main` unit for a ``main.swift`` file's top-level code.

        Swift runs executable top-level statements only in ``main.swift`` (or
        script mode). Those statements are direct `call_expression` /
        `property_declaration` children of `source_file` — inside NO function
        unit, so their calls (and everything transitively reachable from the
        program's real entry) would be invisible. The repo-wide N4 keep-all net
        does NOT fire when any other entry point exists, so a mixed repo (one
        `@main` app + several `main.swift` tools) would silently prune the tools.
        Emit one `unit_type='main'` unit per such file so it seeds reachability.
        """
        if Path(file_path).name.lower() != "main.swift":
            return
        # Collect ALL executable top-level statements via a DENYLIST of declaration
        # nodes (not an allowlist): a daemon root is `try await Daemon().start()`,
        # which parses as a top-level `try_expression`/`await_expression` — an
        # allowlist of `call_expression` missed it, blacking out the real entry of
        # every async daemon (cb_attestationd, ensemblewardend,...). Anything that
        # is not an import/type/func/typealias/operator declaration or a comment runs
        # at program start in main.swift and belongs in the synthetic main unit.
        parts = []
        start_line = None
        end_line = None
        for c in root.children:
            if not c.is_named:
                continue
            if c.type in _TOP_LEVEL_EXCLUDE:
                continue
            parts.append(self._text(c, source))
            ln = c.start_point[0] + 1
            start_line = ln if start_line is None else min(start_line, ln)
            end_line = (c.end_point[0] + 1) if end_line is None else max(end_line, c.end_point[0] + 1)
        if not parts:
            return
        func_id = f"{file_path}:<top-level>"
        functions[func_id] = {
            "name": "main",
            "qualified_name": "<top-level>",
            "file_path": file_path,
            "start_line": start_line or 1,
            "end_line": end_line or 1,
            "code": "\n".join(parts),
            "class_name": None,
            "module_name": None,
            "parameters": [],
            "unit_type": "main",
            "signature": [],
            "param_defaults": [],
            "decorators": [],
            "is_exported": False,
            "is_static": False,
        }

    # -- containers ---------------------------------------------------------

    def _container_info(self, node: Node, source: bytes, ctx: _TypeContext):
        """Return (bare, full_path, exported, default_public, is_type_decl, supers)
        for a type/extension/protocol declaration, or None if unnamed.

        Generic parameters (`<T>`) are stripped from the identity: the nominal
        declaration is `Box`, not `Box<T>` (constraints are not part of identity).
        For an `extension`, the target name comes from the `user_type` child and
        the full dotted path is preserved as the bare leaf's qualifier; we do NOT
        create a class unit for an extension (it augments an existing type).
        """
        kw = None
        for c in node.children:
            if c.type in _CONTAINER_KEYWORDS or c.type == "protocol":
                kw = c.type
                break
        is_extension = (kw == "extension")
        is_type_decl = node.type == "protocol_declaration" or (
            kw in {"class", "struct", "actor", "enum"}
        )

        # Name: `type_identifier` direct child (class/struct/actor/enum/protocol)
        # or the type_identifier(s) under the `user_type` child (extension, possibly
        # qualified: `extension Foundation.Data`, `extension Outer.Inner.Baz`). The
        # bare LEAF is the receiver-dispatch key; the FULL dotted path qualifies the
        # member ids so `extension Outer.Inner` members read Outer.Inner.m (not Baz.m).
        bare = None
        ext_full = None
        if is_extension:
            ut = next((c for c in node.children if c.type == "user_type"), None)
            if ut is not None:
                tids = [g for g in ut.children if g.type == "type_identifier"]
                if tids:
                    bare = self._text(tids[-1], source)
                    ext_full = ".".join(self._text(t, source) for t in tids)
        else:
            tid = next((c for c in node.children if c.type == "type_identifier"), None)
            if tid is not None:
                bare = self._text(tid, source)
        if not bare:
            return None

        vis, _static, attrs, has_modifiers = self._modifier_info(node, source)
        type_public = vis in _VISIBILITY_EXPORTED

        if is_extension:
            full_path = ext_full or bare
            # An extension member is public API iff the TARGET type is public-in-repo
            # OR external (e.g. `public extension String`) — never when the target is
            # a repo type declared internal. The extension's own (usually absent)
            # modifier does NOT make an explicitly-public member internal
            #.
            target_ok = (bare in getattr(self, "_public_types", ())
                         or bare not in getattr(self, "_repo_types", ()))
            exported = ctx.exported and target_ok
            # Only `public extension` makes UNMODIFIED members public by default.
            default_public = type_public
        else:
            full_path = f"{ctx.path}.{bare}" if ctx.path else bare
            # A type with no explicit modifier is module-internal → not exported.
            exported = ctx.exported and type_public
            # class/struct/actor/enum members default to internal.
            default_public = False

        supers = self._supertypes(node, source)
        return bare, full_path, exported, default_public, is_type_decl, supers, attrs

    def _supertypes(self, node: Node, source: bytes) -> set:
        """Bare names in the inheritance clause (superclass + conformed protocols).

        `class Impl: Base, Proto {...}` / `extension Foo: Bar {...}` → the
        `inheritance_specifier` children each hold a `user_type > type_identifier`.
        These feed the call-graph builder's superclass / protocol-default dispatch.
        """
        supers: set = set()
        for c in node.children:
            if c.type == "inheritance_specifier":
                tid = self._base_type_identifier(c, source)
                if tid:
                    supers.add(tid)
        return supers

    def _base_type_identifier(self, node: Node, source: bytes) -> Optional[str]:
        """First `type_identifier` anywhere under ``node`` (breadth-first)."""
        stack = [node]
        while stack:
            n = stack.pop(0)
            if n.type == "type_identifier":
                return self._text(n, source)
            stack.extend(n.children)
        return None

    def _collect_public_types(self) -> tuple:
        """Return (public_type_names, all_repo_type_names) — bare names of every
        type declaration in the repo, and the subset declared `public`/`open`.
        Extensions do NOT count (only a real declaration sets a type's access). Used
        to decide extension-member export: a member is public iff its target type is
        public-in-repo OR external (not a repo type at all) — never when the target
        is a repo type that is internal. One lightweight extra parse per file."""
        public: set = set()
        all_types: set = set()
        for file_info in self.scan_results.get("files", []):
            try:
                with open(self.repo_path / file_info["path"], "rb") as f:
                    src = f.read()
            except OSError:
                continue
            try:
                tree = self.parser.parse(src)
            except Exception:
                continue
            stack = [tree.root_node]
            while stack:
                n = stack.pop()
                if n.type == "protocol_declaration" or (
                    n.type == "class_declaration"
                    and any(c.type in {"class", "struct", "actor", "enum"} for c in n.children)
                ):
                    tid = next((c for c in n.children if c.type == "type_identifier"), None)
                    if tid is not None:
                        name = self._text(tid, src)
                        all_types.add(name)
                        vis, _s, _a, _h = self._modifier_info(n, src)
                        if vis in _VISIBILITY_EXPORTED:
                            public.add(name)
                stack.extend(n.children)
        return public, all_types

    # Framework protocols whose conforming types own a runtime-invoked execution
    # root — seed those roots so a daemon/CLI/decode entry surface isn't pruned.
    _COMMAND_PROTOS = {"ParsableCommand", "AsyncParsableCommand", "ParsableArguments"}
    _APP_PROTOS = {"App", "Scene"}
    _DECODE_PROTOS = {"Decodable", "Codable"}

    def _apply_framework_entry_points(self, functions: Dict[str, Any],
                                      classes: Dict[str, Any], inheritance: Dict[str, set]) -> None:
        """Re-classify runtime-invoked execution roots as `unit_type='main'`.

        Swift binaries frequently have NO literal `main`: an `@main` type's entry
        member, a `ParsableCommand.run()` (ArgumentParser calls it), a SwiftUI
        `App.body`, or `Codable init(from:)` decoding untrusted input are all
        runtime-invoked. Without seeding these, whole daemons/CLIs/XPC decoders are
        pruned (14/27 @main binaries + 924/1357 pccvre CLI units on the real
        target). Conformances arrive via extensions across files, so this runs
        after the whole-repo walk over the transitive conformance closure.
        """
        direct = {k: set(v) for k, v in inheritance.items()}
        closures: Dict[str, set] = {}
        for t in direct:
            seen: set = set()
            stack = list(direct.get(t, ()))
            while stack:
                s = stack.pop()
                if s in seen:
                    continue
                seen.add(s)
                stack.extend(direct.get(s, ()))
            closures[t] = seen
        main_types = {c["name"] for c in classes.values() if "@main" in (c.get("decorators") or [])}
        for f in functions.values():
            cls = f.get("class_name")
            if not cls:
                continue
            name = f.get("name")
            supers = closures.get(cls, set()) | {cls}
            if ((cls in main_types and name in ("main", "run", "callAsFunction", "body"))
                    or (name == "run" and (supers & self._COMMAND_PROTOS))
                    or (name == "body" and (supers & self._APP_PROTOS))
                    or (name == "init" and (supers & self._DECODE_PROTOS)
                        and "from" in (f.get("signature") or []))):
                f["unit_type"] = "main"

    # -- functions ----------------------------------------------------------

    def _emit_function(self, node: Node, source: bytes, file_path: str,
                       functions: Dict[str, Any], ctx: _TypeContext) -> None:
        """Emit a func / init / deinit unit."""
        if node.type == "init_declaration":
            name = "init"
        elif node.type == "deinit_declaration":
            name = "deinit"
        else:
            name = self._decl_name(node, source)
        if not name:
            return

        vis, is_static, attrs, has_modifiers = self._modifier_info(node, source)
        params, labels, defaults = self._params_and_labels(node, source)

        if ctx.bare:
            qualified_name = f"{ctx.path}.{name}"
            class_name = ctx.bare
            unit_type = "constructor" if name == "init" else "method"
        else:
            qualified_name = name
            class_name = None
            unit_type = "function"
        # A `main` entry (top-level or `@main` type's `static func main`) is the
        # program execution root — classify as 'main' so the reachability seeder
        # recognises it (ENTRY_POINT_TYPES). Over-approximating main is safe.
        if name == "main":
            unit_type = "main"

        exported = self._member_exported(vis, ctx)
        self._store(functions, file_path, qualified_name, class_name, unit_type,
                    name, labels, params, attrs, exported, is_static, node, source,
                    defaults=defaults, return_type=self._return_base_type(node, source))

    def _return_base_type(self, node: Node, source: bytes) -> Optional[str]:
        """Base nominal name of a function's `-> ReturnType`, or None.

        Conservative (used to type `let x = foo()` receivers): the node right after
        `->` — a `user_type` yields its `type_identifier`; an `optional_type` is
        unwrapped; collection/tuple/function/opaque/`some`/`any` types yield None so
        we never type a receiver we can't resolve to a single nominal. `init` returns
        its own type; `Self`-returning funcs yield None (contextual)."""
        seen_arrow = False
        for c in node.children:
            if c.type == "->":
                seen_arrow = True
                continue
            if seen_arrow and c.is_named:
                return self._nominal_of(c, source)
        return None

    def _nominal_of(self, tnode: Node, source: bytes) -> Optional[str]:
        if tnode.type == "optional_type":
            inner = next((c for c in tnode.children if c.type not in ("?", "!")), None)
            return self._nominal_of(inner, source) if inner is not None else None
        if tnode.type == "user_type":
            tid = next((c for c in tnode.children if c.type == "type_identifier"), None)
            return self._text(tid, source) if tid is not None else None
        if tnode.type == "type_identifier":
            return self._text(tnode, source)
        return None

    def _emit_property_accessors(self, node: Node, source: bytes, file_path: str,
                                 functions: Dict[str, Any], ctx: _TypeContext,
                                 top_level: bool = False) -> None:
        """Emit call-bearing accessor units for a property_declaration.

        Swift hides real execution behind properties: computed getters/setters,
        willSet/didSet observers, and call-bearing lazy initializers. Their bodies
        routinely contain security-relevant calls, so omitting them would prune
        those callees as unreachable. Each accessor becomes a synthetic method
        unit (schema-compatible unit_type 'method').
        """
        prop = self._pattern_name(node, source)
        if not prop:
            return
        vis, is_static, attrs, _ = self._modifier_info(node, source)
        exported = self._member_exported(vis, ctx)
        base_q = f"{ctx.path}.{prop}" if ctx.path else prop

        # Accessors: computed get/set + willSet/didSet observers. No early break —
        # a property can carry an initializer AND observers, and breaking after the
        # initializer dropped the observer units.
        for child in node.children:
            if child.type == "computed_property":
                self._emit_computed_accessors(child, source, file_path, functions,
                                              ctx, base_q, attrs, exported, is_static)
            elif child.type == "willset_didset_block":
                for clause in child.children:
                    if clause.type == "willset_clause":
                        self._store_accessor(functions, file_path, f"{base_q}.willSet",
                                             ctx, attrs, exported, is_static, clause, source)
                    elif clause.type == "didset_clause":
                        self._store_accessor(functions, file_path, f"{base_q}.didSet",
                                             ctx, attrs, exported, is_static, clause, source)

        # Stored/lazy initializer: `static let shared = Manager()` (the singleton),
        # `lazy var c = makeClient()`, stored closures `let h: T = {... }`, and
        # try/await/ternary-wrapped initializers. Store ONLY the initializer RHS node
        # — storing the whole property_declaration double-attributed a `didSet` body
        # the observer unit already owns.
        # also emit at FILE scope (ctx.bare is None) — a global stored
        # closure/factory in an ordinary file (`Config.swift: let handler = { sink() }`)
        # was previously NEVER extracted (the branch was gated in-type only), so its
        # body's calls were invisible to the whole pipeline. Guard main.swift, whose
        # top-level synthesis already captures its file-scope statements (avoid double).
        is_main_file = Path(file_path).name.lower() == "main.swift"
        # Emit for: an IN-TYPE property (ctx.bare set) OR a true FILE-SCOPE global
        # (top_level, non-main). A LOCAL var inside a function body is neither
        # (top_level False, ctx.bare None) → not emitted, so we don't fabricate a unit
        # per local `let` (the over-emission the first draft caused: +5249 local
        # vars on security-pcc).
        if ctx.bare is not None or (top_level and not is_main_file):
            rhs = self._eq_rhs(node)
            if rhs is not None and self._is_call_bearing(rhs):
                self._store_accessor(functions, file_path, base_q, ctx, attrs,
                                     exported, is_static, rhs, source)

    def _eq_rhs(self, node: Node) -> Optional[Node]:
        """The first named node after `=` in a property_declaration (the initializer)."""
        seen_eq = False
        for c in node.children:
            if c.type == "=":
                seen_eq = True
                continue
            if seen_eq and c.is_named:
                return c
        return None

    def _is_call_bearing(self, node: Node) -> bool:
        """True if a `call_expression` or closure (`lambda_literal`) appears anywhere
        under ``node`` — so a literal initializer (`= 0`) emits no spurious unit while
        `= try makeClient()` / `= { work() }` / `= a ? f() : g()` do."""
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type in ("call_expression", "lambda_literal"):
                return True
            stack.extend(n.children)
        return False

    def _emit_computed_accessors(self, comp: Node, source: bytes, file_path: str,
                                 functions: Dict[str, Any], ctx: _TypeContext,
                                 base_q: str, attrs, exported, is_static) -> None:
        getters = [c for c in comp.children if c.type == "computed_getter"]
        setters = [c for c in comp.children if c.type == "computed_setter"]
        if not getters and not setters:
            # Getter-only shorthand: `var x: Int { return f() }` — body is a bare
            # `statements` under computed_property. Emit as the getter.
            if any(c.type == "statements" for c in comp.children):
                self._store_accessor(functions, file_path, base_q, ctx, attrs,
                                     exported, is_static, comp, source)
            return
        for g in getters:
            self._store_accessor(functions, file_path, base_q, ctx, attrs,
                                 exported, is_static, g, source)
        for s in setters:
            self._store_accessor(functions, file_path, f"{base_q}.set", ctx, attrs,
                                 exported, is_static, s, source)

    def _emit_subscript_accessors(self, node: Node, source: bytes, file_path: str,
                                  functions: Dict[str, Any], ctx: _TypeContext) -> None:
        vis, is_static, attrs, _ = self._modifier_info(node, source)
        exported = self._member_exported(vis, ctx)
        base_q = f"{ctx.path}.subscript" if ctx.path else "subscript"
        comp = next((c for c in node.children if c.type == "computed_property"), None)
        if comp is not None:
            self._emit_computed_accessors(comp, source, file_path, functions, ctx,
                                          base_q, attrs, exported, is_static)

    # -- storage / overload-safe ids ---------------------------------------

    def _store(self, functions, file_path, qualified_name, class_name, unit_type,
               name, labels, params, attrs, exported, is_static, node, source,
               defaults=None, return_type=None) -> None:
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        func_id = self._unique_id(functions, file_path, qualified_name, labels, start_line)
        functions[func_id] = {
            "name": name,
            "qualified_name": qualified_name,
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "code": self._text(node, source),
            "class_name": class_name,
            "module_name": None,
            "parameters": params,
            "unit_type": unit_type,
            # Swift-specific metadata used by the call-graph resolver / reachability.
            "signature": labels,          # external argument labels (overload key)
            "param_defaults": defaults if defaults is not None else [False] * len(labels),
            "return_type": return_type,   # base nominal of `-> T` (types `let x = f()` receivers)
            "decorators": attrs,          # @attributes (entry_point_detector reads these)
            "is_exported": exported,
            "is_static": is_static,
        }

    def _store_accessor(self, functions, file_path, qualified_name, ctx, attrs,
                        exported, is_static, node, source) -> None:
        """Store a synthetic accessor unit (getter/setter/observer/lazy-init)."""
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        func_id = self._unique_id(functions, file_path, qualified_name, [], start_line)
        functions[func_id] = {
            "name": qualified_name.rsplit(".", 1)[-1],
            "qualified_name": qualified_name,
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "code": self._text(node, source),
            "class_name": ctx.bare,
            "module_name": None,
            "parameters": [],
            "unit_type": "method",
            "signature": [],
            "param_defaults": [],
            "decorators": attrs,
            "is_exported": exported,
            "is_static": is_static,
        }

    def _unique_id(self, functions, file_path, qualified_name, labels, start_line) -> str:
        """Build a collision-free func_id.

        Swift heavily overloads functions and initializers, so `file:qualified_name`
        is NOT unique — a plain `functions[base] =...` would silently overwrite
        earlier overloads/inits (dropping whole units and their edges). On a
        collision, disambiguate by the external argument labels, then by start
        line as a final tiebreak. The name / qualified_name indexes still collect
        all overloads under the shared name, so a bare-name call resolves to the
        bounded overload set (reachability-safe).
        """
        base = f"{file_path}:{qualified_name}"
        if base not in functions:
            return base
        sig = "(" + ",".join(labels) + ")"
        cand = base + sig
        if cand not in functions:
            return cand
        return f"{cand}#{start_line}"

    # -- node helpers -------------------------------------------------------

    def _decl_name(self, node: Node, source: bytes) -> Optional[str]:
        """First direct `simple_identifier` child = the declared function name.

        Parameters' identifiers live under `parameter` nodes (not direct
        children), so scanning DIRECT children yields the function name, never a
        parameter name. Operator functions (`func ==`) have no simple_identifier
        and return None (operators are deferred; not emitted as units in v1).
        """
        for c in node.children:
            if c.type == "simple_identifier":
                return self._text(c, source)
        # Operator function (`func ==`, `prefix func !`, `func <>`): no
        # simple_identifier — the operator token / `custom_operator` sits right
        # after `func`, before `(`. Emit it so the operator BODY's out-edges (e.g.
        # `constantTimeCompare(...)` in an Equatable `==`) are not lost (385 bodies
        # on the real target). Operator USES aren't call_expression, so no in-edges.
        after_func = False
        for c in node.children:
            if c.type == "func":
                after_func = True
                continue
            if after_func:
                if c.type == "(":
                    break
                txt = self._text(c, source).strip()
                if txt:
                    return txt
        return None

    def _pattern_name(self, node: Node, source: bytes) -> Optional[str]:
        """Property name from `pattern > simple_identifier`."""
        pat = next((c for c in node.children if c.type == "pattern"), None)
        if pat is not None:
            sid = next((g for g in pat.children if g.type == "simple_identifier"), None)
            if sid is not None:
                return self._text(sid, source)
        return None

    def _modifier_info(self, node: Node, source: bytes) -> Tuple[Optional[str], bool, List[str], bool]:
        """Return (visibility, is_static, attributes, has_modifiers_block).

        Reads the optional `modifiers` child plus any bare `class`/`static`
        keyword children (tree-sitter-swift emits `class func` as a bare `class`
        keyword child, `static func` as modifiers>property_modifier).
        """
        vis = None
        is_static = False
        attrs: List[str] = []
        has_modifiers = False
        # Bare `class`/`static` keyword before `func` marks a type method.
        for c in node.children:
            if c.type == "class":
                is_static = True
            elif c.type == "static":
                is_static = True
        mods = next((c for c in node.children if c.type == "modifiers"), None)
        if mods is not None:
            has_modifiers = True
            for m in mods.children:
                if m.type == "visibility_modifier":
                    vis = self._text(m, source).strip()
                elif m.type == "property_modifier":
                    if self._text(m, source).strip() in ("static", "class"):
                        is_static = True
                elif m.type == "attribute":
                    name = self._attribute_name(m, source)
                    if name:
                        attrs.append(name)
        return vis, is_static, attrs, has_modifiers

    def _attribute_name(self, attr: Node, source: bytes) -> Optional[str]:
        """`@main` / `@objc` / `@MainActor` → '@main' etc. (base name, args dropped)."""
        ut = next((c for c in attr.children if c.type == "user_type"), None)
        if ut is not None:
            tid = next((g for g in ut.children if g.type == "type_identifier"), None)
            if tid is not None:
                return "@" + self._text(tid, source)
        # Some attributes render the identifier directly.
        tid = next((c for c in attr.children if c.type in ("type_identifier", "simple_identifier")), None)
        if tid is not None:
            return "@" + self._text(tid, source)
        return None

    def _params_and_labels(self, node: Node, source: bytes):
        """Return (param_internal_names, external_labels, has_default_flags).

        A `parameter` node is `[external_label]? internal_name : type`. When two
        simple_identifiers are present the first is the external label (`_` means
        the label is omitted at call sites); with one, it serves as both. A default
        value shows up as `=` + expression SIBLINGS following the `parameter` node
        (not inside it) — verified against tree-sitter-swift 0.7.3. The default flag
        drives the call-site signature matcher: a defaulted param may be omitted at
        the call, a required (non-default) named param may not.
        """
        params: List[str] = []
        labels: List[str] = []
        defaults: List[bool] = []
        kids = node.children
        for i, c in enumerate(kids):
            if c.type != "parameter":
                continue
            idents = [g for g in c.children if g.type == "simple_identifier"]
            if not idents:
                continue
            if len(idents) >= 2:
                label = self._text(idents[0], source)
                internal = self._text(idents[1], source)
            else:
                label = internal = self._text(idents[0], source)
            # Look ahead: a `=` before the next parameter/`)` marks a default.
            has_def = False
            for j in range(i + 1, len(kids)):
                t = kids[j].type
                if t == "=":
                    has_def = True
                    break
                if t in ("parameter", ")"):
                    break
            params.append(internal)
            labels.append(label)
            defaults.append(has_def)
        return params, labels, defaults

    def _member_exported(self, vis: Optional[str], ctx: _TypeContext) -> bool:
        """A member is externally exported iff every enclosing type is public/open
        AND the member is public/open (or inherits public default from a
        `public extension`/`public` container). A public method in an internal
        type is not part of the public API."""
        if not ctx.exported:
            return False
        if vis in _VISIBILITY_EXPORTED:
            return True
        if vis is None:  # no explicit modifier → inherit container default
            return ctx.default_public
        return False  # private / fileprivate / internal

    def _import_module(self, node: Node, source: bytes) -> Optional[str]:
        """`import Foundation` → 'Foundation'. Swift imports are module-level, not
        file paths — recorded for provenance only (resolution is module-wide)."""
        for c in node.children:
            if c.type in ("identifier", "simple_identifier", "type_identifier"):
                return self._text(c, source)
        # `import class Foo.Bar` etc.: take the last identifier-ish token.
        txt = self._text(node, source).replace("import", "", 1).strip()
        return txt.split()[-1].split(".")[0] if txt else None

    def _text(self, node: Node, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
