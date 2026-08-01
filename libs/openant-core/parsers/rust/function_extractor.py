"""
Stage 2: Function Extractor for Rust

Extracts functions, methods, impl blocks, traits, modules and `use` imports
from Rust source files using tree-sitter.

Node-type names match the tree-sitter-rust grammar actually in use (verified
by dumping real parse trees before writing this module — see the parser's
design notes). In particular:

- ``function_item`` is a `fn` with a body; ``function_signature_item`` is a
  trait method declaration with NO body (just a signature + `;`). Only the
  former has code worth extracting as an analysis unit.
- ``impl_item`` is either an inherent impl (`impl Type { .. }`) or a trait
  impl (`impl Trait for Type { .. }`); which one determines whether a
  `type_identifier`/`generic_type` child precedes or follows the `for` token.
- ``trait_item`` holds required methods (`function_signature_item`, no body)
  and default methods (`function_item`, has a body) in its `declaration_list`.
- ``mod_item`` either has a `declaration_list` body (inline module) or ends in
  `;` (file-backed module, e.g. `mod foo;` naming `foo.rs`/`foo/mod.rs`).
- `self`/`Self` are distinct: a value receiver is node type ``self``
  (keyword), while `Self` (the type) is an ordinary ``identifier`` used
  inside a ``scoped_identifier`` (e.g. `Self::new`).
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from utilities.file_io import write_json

from tree_sitter import Language, Parser, Node


def _load_rust_language() -> Language:
    """Load the Rust tree-sitter grammar lazily.

    The grammar package (``tree-sitter-rust``) is an optional runtime
    dependency. Importing it at module top level would make the entire Rust
    parser unimportable in any environment where the package is absent.
    Resolving it here, on first use, lets the module import unconditionally
    and surfaces a clear, actionable error only when the Rust parser is
    actually exercised.
    """
    try:
        import tree_sitter_rust as ts_rust
    except ImportError as exc:  # pragma: no cover - exercised via the no-dep test
        raise ImportError(
            "The Rust parser requires the 'tree-sitter-rust' package, which is "
            "not installed. Install it with `pip install tree-sitter-rust` "
            "(declared in pyproject.toml / requirements.txt)."
        ) from exc
    return Language(ts_rust.language())


# Attributes marking a function as a test. Matches "test" and any qualified
# form ending in "::test" (`#[tokio::test]`, `#[async_std::test]`). Does not
# attempt to match custom test-harness attribute names beyond this.
_TEST_ATTR_RE = re.compile(r"^(?:[\w:]+::)?test$")

# `#[cfg(test)]` (and the common `#[cfg(any(test, ...))]` shape) marking an
# entire module as test-only. Word-bounded so `cfg(feature = "testing")`
# does not false-positive.
_CFG_TEST_RE = re.compile(r"^cfg\s*\(.*\btest\b")

# Attribute names (after stripping any `crate::` qualifier) that mark a
# function as an HTTP route handler in the dominant Rust web frameworks
# (actix-web, rocket, poem, ntex). Axum/warp are excluded: they route via
# `Router::route("/path", get(handler))` at the call site, not a decorator on
# the handler, so there is nothing for a per-function attribute check to see.
_ROUTE_ATTR_NAMES = {"get", "post", "put", "delete", "patch", "head", "options", "route"}

# Type-like node kinds that can appear as the Self type / trait name of an
# `impl` block, or as the RHS of a `let x: <type> = ...` annotation.
_TYPE_NODE_KINDS = ("type_identifier", "generic_type", "scoped_type_identifier")

# Non-nominal Self-type node kinds that are absent from _TYPE_NODE_KINDS but CAN be
# an impl target: `impl Trait for u32 / [u8;4] / (i32,i32) / () / &T / *const T /
# dyn X`. Collected in _handle_impl so their methods are extracted (bug I); for the
# genuinely non-nominal ones _bare_type_name returns None and _handle_impl falls
# back to the raw type text, while reference/dynamic types unwrap to their nominal
# base as usual.
_IMPL_SELF_EXTRA_KINDS = (
    "primitive_type", "array_type", "tuple_type", "unit_type",
    "reference_type", "pointer_type", "dynamic_type",
)


def _bare_type_name(node: Optional[Node], source: bytes) -> Optional[str]:
    """Reduce a type node to its bare (unqualified, non-generic) name.

    ``Widget<T>`` -> ``Widget``; ``foo::Bar`` -> ``Bar``; ``&Point`` -> ``Point``;
    ``Vec<i32>`` -> ``Vec``. Returns None for primitive types / anything with
    no nominal identifier (references to tuples, function pointers, etc).
    """
    if node is None:
        return None
    t = node.type
    if t in ("type_identifier", "identifier"):
        return _text(node, source)
    if t == "generic_type":
        # First child names the base type: `Widget` in `Widget<T>`, or a
        # nested generic_type/scoped_type_identifier for `foo::Widget<T>`.
        for child in node.children:
            if child.type in _TYPE_NODE_KINDS:
                return _bare_type_name(child, source)
        return None
    if t == "scoped_type_identifier":
        # Module-qualified type: `foo::Bar` -> take the LAST identifier-like
        # segment (`Bar`), which is what a same-crate `impl` block or call
        # would use as the bare type name.
        last = None
        for child in node.children:
            if child.type in ("type_identifier", "identifier"):
                last = child
        return _text(last, source) if last is not None else None
    if t == "reference_type":
        # `&Point` / `&mut Point` / `&'a Point` -> unwrap to Point;
        # `&dyn Shape` -> unwrap through the dynamic_type to Shape (val_3_19).
        for child in node.children:
            if child.type in _TYPE_NODE_KINDS or child.type == "dynamic_type":
                return _bare_type_name(child, source)
        return None
    if t == "dynamic_type":
        # `dyn Shape` / `dyn Shape + Send` -> the trait's bare name, so a
        # `&dyn Shape` receiver types as `Shape` and dispatches to Shape's
        # conformers via trait_impls (val_3_19; `dyn Shape` is a `dynamic_type`
        # node, verified against the installed grammar per pr_2_1).
        for child in node.children:
            r = _bare_type_name(child, source)
            if r:
                return r
        return None
    if t in ("bounded_type", "generic_type_with_turbofish"):
        for child in node.children:
            r = _bare_type_name(child, source)
            if r:
                return r
    return None


def _impl_generic_bounds(impl_node: Node, source: bytes) -> Dict[str, List[str]]:
    """Map an impl block's OWN generic param letter -> its bound trait(s).

    `impl<T: Shape + Draw> Foo<T>` and `impl<T> Foo<T> where T: Shape` both yield
    `{"T": ["Shape", ...]}`. Only the impl header's own generics (the `<...>` before
    the self type, plus the where-clause) are read. Threaded onto each method so a
    receiver typed as the impl's generic param (`x: &T`) dispatches to the bound
    trait's conformers -- the SAME reachability-safe closure fn-level bounds use --
    instead of falling to a bare lookup on the letter `T` (which a blanket impl's
    pseudo-type `T` would poison). Mirrors CallGraphBuilder._collect_type_param_bounds.
    """
    bounds: Dict[str, List[str]] = {}

    def _traits(tb: Node) -> List[str]:
        return [_text(c, source) for c in tb.children if c.type == "type_identifier"]

    def _add(param: Optional[str], tb: Node) -> None:
        if not param:
            return
        bounds.setdefault(param, [])
        for t in _traits(tb):
            if t not in bounds[param]:
                bounds[param].append(t)

    def _param(node: Node) -> None:
        pid = None
        for cc in node.children:
            if cc.type == "type_identifier" and pid is None:
                pid = _text(cc, source)
            elif cc.type == "trait_bounds":
                _add(pid, cc)

    seen_for = False
    for child in impl_node.children:
        if child.type == "for":
            seen_for = True
        elif child.type == "type_parameters" and not seen_for:
            for tp in child.children:
                if tp.type in ("type_parameter", "constrained_type_parameter"):
                    _param(tp)
        elif child.type == "where_clause":
            for wp in child.children:
                if wp.type == "where_predicate":
                    _param(wp)
    return bounds


def _text(node: Optional[Node], source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


class FunctionExtractor:
    """Extracts functions, impls, traits, modules and imports from Rust source."""

    def __init__(self, repo_path: str, scan_results: Dict[str, Any], skip_tests: bool = False):
        self.repo_path = Path(repo_path).resolve()
        self.scan_results = scan_results
        self.skip_tests = skip_tests
        self.parser = Parser(_load_rust_language())
        # Accumulated across every file: (trait_name, concrete_type_name) pairs
        # from every `impl Trait for Type` block seen. Used by the call graph
        # builder to over-approximate calls made from a trait's default-method
        # body (which cannot know its concrete Self statically).
        self._trait_impl_pairs: List[Tuple[str, str]] = []

    def extract(self) -> Dict[str, Any]:
        """Extract all functions/classes/imports from scanned files.

        Returns a functions.json-shaped structure per the parser-authoring
        guide, plus a ``trait_impls`` side table consumed only by this
        parser's own call_graph_builder.
        """
        functions: Dict[str, Any] = {}
        classes: Dict[str, Any] = {}
        imports: Dict[str, List[dict]] = {}
        files_processed = 0
        files_with_errors = 0

        for file_info in self.scan_results.get("files", []):
            file_path = file_info["path"]
            full_path = self.repo_path / file_path

            try:
                with open(full_path, "rb") as f:
                    source = f.read()

                tree = self.parser.parse(source)
                file_imports: List[dict] = []
                ctx = {
                    "qual_prefix": "",
                    "class_name": None,
                    "module_path": (),
                    "in_test_scope": False,
                }
                self._walk(
                    tree.root_node, source, file_path, functions, classes,
                    file_imports, ctx,
                )
                imports[file_path] = file_imports
                files_processed += 1

            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                files_with_errors += 1

        trait_impls: Dict[str, List[str]] = {}
        for trait_name, type_name in self._trait_impl_pairs:
            trait_impls.setdefault(trait_name, [])
            if type_name not in trait_impls[trait_name]:
                trait_impls[trait_name].append(type_name)

        return {
            "repository": str(self.repo_path),
            "extraction_time": datetime.now().isoformat(),
            "functions": functions,
            "classes": classes,
            "imports": imports,
            "trait_impls": trait_impls,
            "statistics": {
                "total_functions": len(functions),
                "total_classes": len(classes),
                "files_processed": files_processed,
                "files_with_errors": files_with_errors,
            },
        }

    # -- structural walk -----------------------------------------------------

    def _walk(
        self,
        root: Node,
        source: bytes,
        file_path: str,
        functions: Dict[str, Any],
        classes: Dict[str, Any],
        imports_local: List[dict],
        ctx: dict,
    ) -> None:
        """Iteratively scan sibling lists, threading module/impl/fn context.

        Iterative (explicit worklist), not recursive: a worklist entry means
        "scan this node's direct children as one sibling list under this
        ctx". A pathologically deep source file cannot overflow the Python
        stack. Attributes (`#[...]`) are collected locally per sibling list
        and attach only to the item immediately following them, matching
        real Rust attribute-attachment scoping.
        """
        worklist: List[Tuple[Node, dict]] = [(root, ctx)]

        while worklist:
            node, cur_ctx = worklist.pop()
            pending_attrs: List[str] = []

            for child in node.children:
                t = child.type

                if t == "attribute_item":
                    pending_attrs.append(self._attribute_text(child, source))
                    continue

                if t == "use_declaration":
                    self._collect_use(child, source, imports_local)
                    pending_attrs = []
                    continue

                if t == "mod_item":
                    self._handle_mod(
                        child, source, file_path, functions, classes,
                        imports_local, cur_ctx, pending_attrs, worklist,
                    )
                    pending_attrs = []
                    continue

                if t in ("struct_item", "enum_item", "union_item"):
                    self._record_class(child, source, file_path, classes, t)
                    pending_attrs = []
                    continue

                if t == "trait_item":
                    self._handle_trait(
                        child, source, file_path, classes, cur_ctx, worklist,
                    )
                    pending_attrs = []
                    continue

                if t == "impl_item":
                    self._handle_impl(child, source, cur_ctx, worklist)
                    pending_attrs = []
                    continue

                if t == "function_signature_item":
                    # Trait method declaration with no body -- nothing to
                    # analyze as its own unit. The concrete implementation
                    # (in some `impl Trait for Type`) is what carries code.
                    pending_attrs = []
                    continue

                if t == "function_item":
                    self._handle_function(
                        child, source, file_path, functions, cur_ctx,
                        pending_attrs, worklist,
                    )
                    pending_attrs = []
                    continue

                # Anything else (block, let_declaration, if_expression,
                # match_expression, closure_expression, unsafe_block, ...)
                # may still contain nested fn/impl/struct/mod definitions
                # (Rust allows local `fn`/`struct`/`impl` inside a function
                # body). Keep scanning its children under the SAME context.
                worklist.append((child, cur_ctx))
                pending_attrs = []

    # -- mod / trait / impl handling -----------------------------------------

    def _handle_mod(
        self, node: Node, source: bytes, file_path: str,
        functions: Dict[str, Any], classes: Dict[str, Any],
        imports_local: List[dict], ctx: dict, attrs: List[str],
        worklist: List[Tuple[Node, dict]],
    ) -> None:
        name = None
        body = None
        for child in node.children:
            if child.type == "identifier" and name is None:
                name = _text(child, source)
            elif child.type == "declaration_list":
                body = child

        if not name:
            return

        is_cfg_test = any(_CFG_TEST_RE.match(a) for a in attrs)

        if body is None:
            # `mod foo;` -- the module's real content lives in another file
            # (foo.rs or foo/mod.rs, resolved relative to this file's
            # directory). Record it so the call graph builder can map
            # `foo::bar()` call sites to that file.
            imports_local.append({
                "kind": "mod", "name": name, "alias": None, "leaf": name,
            })
            return

        if is_cfg_test and self.skip_tests:
            # Whole module is test-only and tests are excluded: skip its
            # entire subtree (nothing inside is analyzed), matching the
            # file-level skip-tests philosophy used elsewhere in this parser.
            return

        new_prefix = f"{ctx['qual_prefix']}::{name}" if ctx["qual_prefix"] else name
        new_ctx = {
            "qual_prefix": new_prefix,
            "class_name": None,
            "module_path": ctx["module_path"] + (name,),
            "in_test_scope": ctx["in_test_scope"] or is_cfg_test,
        }
        worklist.append((body, new_ctx))

    def _handle_trait(
        self, node: Node, source: bytes, file_path: str,
        classes: Dict[str, Any], ctx: dict, worklist: List[Tuple[Node, dict]],
    ) -> None:
        name = None
        body = None
        for child in node.children:
            if child.type == "type_identifier" and name is None:
                name = _text(child, source)
            elif child.type == "declaration_list":
                body = child

        if not name:
            return

        classes[name] = {
            "name": name,
            "file_path": file_path,
            "start_line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "code": _text(node, source),
            "kind": "trait",
        }

        if body is None:
            return

        new_prefix = f"{ctx['qual_prefix']}::{name}" if ctx["qual_prefix"] else name
        new_ctx = {
            "qual_prefix": new_prefix,
            "class_name": name,
            "module_path": ctx["module_path"],
            "in_test_scope": ctx["in_test_scope"],
            # A trait method (required or default) can never carry its own
            # `pub` keyword -- it is always as visible as the trait itself.
            # Treat every method defined directly in a trait body as exported
            # rather than relying on a `pub` prefix that cannot appear here.
            "in_trait_impl": True,
        }
        worklist.append((body, new_ctx))

    def _handle_impl(
        self, node: Node, source: bytes, ctx: dict, worklist: List[Tuple[Node, dict]],
    ) -> None:
        type_nodes: List[Tuple[Node, bool]] = []
        seen_for = False
        body = None
        impl_generics: Set[str] = set()
        for child in node.children:
            if child.type == "for":
                seen_for = True
                continue
            if child.type == "type_parameters" and not seen_for:
                # the impl's OWN generic params, e.g. `impl<T: Foo> Bar for T`.
                for tp in child.children:
                    if tp.type in ("type_parameter", "constrained_type_parameter"):
                        for cc in tp.children:
                            if cc.type == "type_identifier":
                                impl_generics.add(_text(cc, source))
                                break
            if child.type in _TYPE_NODE_KINDS or child.type in _IMPL_SELF_EXTRA_KINDS:
                type_nodes.append((child, seen_for))
            elif child.type == "declaration_list":
                body = child

        if seen_for:
            before = [n for n, f in type_nodes if not f]
            after = [n for n, f in type_nodes if f]
            trait_node = before[0] if before else None
            self_node = after[0] if after else None
        else:
            trait_node = None
            self_node = type_nodes[0][0] if type_nodes else None

        self_type = _bare_type_name(self_node, source)
        if not self_type and self_node is not None:
            # Non-nominal Self type (primitive `u32`, array `[u8; 4]`, tuple
            # `(i32, i32)`, unit `()`): `_bare_type_name` only names nominal types,
            # so `impl Serialize for u32` would be dropped ENTIRELY -- every method
            # in the block lost from extraction, the graph, and reachability. Fall
            # back to the raw type text so the methods are still extracted (keyed by
            # that type spelling).
            self_type = _text(self_node, source).strip()
        trait_name = _bare_type_name(trait_node, source)

        if not self_type or body is None:
            return

        # A blanket impl `impl<T: Foo> Bar for T` targets the impl's OWN generic
        # parameter, not a concrete type. Registering the letter `T` as a
        # conformer of Bar mints a pseudo-type that fabricates cross-file edges
        # (every `T`-named impl collides). Skip it -- resolving a blanket to its
        # supertrait's conformers is a separate feature, not a bogus concrete
        # conformer.
        if trait_name and self_type not in impl_generics:
            self._trait_impl_pairs.append((trait_name, self_type))

        new_prefix = f"{ctx['qual_prefix']}::{self_type}" if ctx["qual_prefix"] else self_type
        new_ctx = {
            "qual_prefix": new_prefix,
            "class_name": self_type,
            "module_path": ctx["module_path"],
            "in_test_scope": ctx["in_test_scope"],
            "in_trait_impl": trait_name is not None,
            "impl_trait": trait_name,
            "impl_type_param_bounds": _impl_generic_bounds(node, source),
        }
        worklist.append((body, new_ctx))

    def _record_class(
        self, node: Node, source: bytes, file_path: str,
        classes: Dict[str, Any], kind: str,
    ) -> None:
        name = None
        for child in node.children:
            if child.type == "type_identifier":
                name = _text(child, source)
                break
        if not name:
            return
        classes[name] = {
            "name": name,
            "file_path": file_path,
            "start_line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "code": _text(node, source),
            "kind": kind.replace("_item", ""),
        }

    # -- function handling ----------------------------------------------------

    def _handle_function(
        self, node: Node, source: bytes, file_path: str,
        functions: Dict[str, Any], ctx: dict, attrs: List[str],
        worklist: List[Tuple[Node, dict]],
    ) -> None:
        name = None
        params_node = None
        has_self = False
        for child in node.children:
            if child.type == "identifier" and name is None:
                name = _text(child, source)
            elif child.type == "parameters":
                params_node = child

        if not name or params_node is None:
            return

        parameters: List[str] = []
        for p in params_node.children:
            if p.type == "self_parameter":
                has_self = True
            elif p.type == "parameter":
                for sub in p.children:
                    if sub.type == "identifier":
                        parameters.append(_text(sub, source))
                        break
                    if sub.type == "tuple_pattern":
                        # Destructured param, e.g. `(a, b): (i32, i32)` -- no
                        # single bound name; skip rather than mis-name it.
                        break

        is_test_attr = any(_TEST_ATTR_RE.match(a) for a in attrs)
        if (is_test_attr or ctx["in_test_scope"]) and self.skip_tests:
            return

        class_name = ctx["class_name"]
        if class_name:
            qualified_name = f"{ctx['qual_prefix']}.{name}"
        else:
            qualified_name = f"{ctx['qual_prefix']}::{name}" if ctx["qual_prefix"] else name

        unit_type = self._classify(
            name, class_name, has_self, attrs, is_test_attr, ctx["in_test_scope"],
        )

        code = _text(node, source)
        is_exported = code.lstrip().startswith("pub") or bool(ctx.get("in_trait_impl"))

        module_name = "::".join(ctx["module_path"]) if ctx["module_path"] else None

        func_id = f"{file_path}:{qualified_name}"
        if func_id in functions:
            # Same qualified_name already taken -- e.g. `impl Display for P` and
            # `impl Debug for P` both yield `P.fmt`, or an inherent method plus a
            # same-named trait method. Without disambiguation the second silently
            # clobbers the first (a whole unit lost from the graph AND reachability).
            # Append the trait (or `impl`) so both survive. The FIRST occurrence
            # keeps the plain id, so class_name-based resolution and existing
            # `Type.method` references are unchanged; only the colliding sibling
            # gets the `#trait` suffix.
            disc = ctx.get("impl_trait") or "impl"
            candidate = f"{file_path}:{qualified_name}#{disc}"
            n = 2
            while candidate in functions:
                candidate = f"{file_path}:{qualified_name}#{disc}{n}"
                n += 1
            func_id = candidate
        functions[func_id] = {
            "name": name,
            "qualified_name": qualified_name,
            "file_path": file_path,
            "start_line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "code": code,
            "class_name": class_name,
            "module_name": module_name,
            "parameters": parameters,
            "unit_type": unit_type,
            "is_exported": is_exported,
            "has_self": has_self,
            "decorators": attrs,
            # Bounds of the enclosing impl's own generics (`impl<T: Shape> Foo<T>`),
            # so a receiver typed as `T` in this method dispatches to the trait's
            # conformers (bug D). Empty for free functions / inherent-non-generic impls.
            "impl_type_param_bounds": ctx.get("impl_type_param_bounds", {}),
        }

        block = None
        for child in node.children:
            if child.type == "block":
                block = child
                break
        if block is not None:
            new_ctx = {
                "qual_prefix": qualified_name,
                "class_name": None,
                "module_path": ctx["module_path"],
                "in_test_scope": ctx["in_test_scope"] or is_test_attr,
            }
            worklist.append((block, new_ctx))

    def _classify(
        self, name: str, class_name: Optional[str], has_self: bool,
        attrs: List[str], is_test_attr: bool, in_test_scope: bool,
    ) -> str:
        if is_test_attr or in_test_scope:
            return "test"

        if name == "main":
            return "main"

        for attr in attrs:
            leaf = attr.split("::")[-1]
            leaf = leaf.split("(", 1)[0].strip()
            if leaf.lower() in _ROUTE_ATTR_NAMES:
                return "route_handler"

        if class_name:
            if has_self:
                return "method"
            if name in ("new", "create", "make", "default", "from", "with_capacity", "build"):
                return "constructor"
            return "singleton_method"

        return "function"

    # -- use-declaration parsing ---------------------------------------------

    def _attribute_text(self, node: Node, source: bytes) -> str:
        """Text of the `attribute` node inside `#[ ... ]`, e.g. "test", "get(\"/x\")"."""
        for child in node.children:
            if child.type == "attribute":
                return _text(child, source)
        return _text(node, source)

    def _collect_use(self, node: Node, source: bytes, imports_local: List[dict]) -> None:
        """Flatten a `use` declaration into leaf import records.

        Handles: simple paths, `as` aliasing, and grouped `{a, b as c}`
        lists. Wildcard imports (`use foo::*;`) are recorded with a `*` leaf
        for visibility but are not resolvable to a specific symbol -- a same-
        file call still resolves via plain name lookup regardless (the
        dominant `use super::*;` case in `#[cfg(test)] mod tests` is same-file
        and needs no import resolution at all).
        """
        # Find the path-bearing child (skip `use`, `pub`/visibility_modifier, `;`).
        target = None
        for child in node.children:
            if child.type in (
                "scoped_identifier", "identifier", "use_as_clause",
                "use_list", "scoped_use_list", "use_wildcard",
            ):
                target = child
                break
        if target is None:
            return
        for path_segs, leaf, alias in self._flatten_use_node(target, source, ()):
            if leaf == "*" or not leaf:
                continue
            imports_local.append({
                "kind": "use",
                "path": "::".join(path_segs),
                "leaf": leaf,
                "alias": alias,
            })

    def _flatten_use_node(
        self, node: Node, source: bytes, prefix: Tuple[str, ...],
    ) -> List[Tuple[Tuple[str, ...], str, Optional[str]]]:
        t = node.type
        if t == "identifier" or t == "crate" or t == "super" or t == "self":
            text = _text(node, source)
            return [(prefix + (text,), text, None)]
        if t == "scoped_identifier":
            left = node.children[0] if node.children else None
            right = node.children[-1] if node.children else None
            if left is None or right is None:
                return []
            left_path = self._flatten_use_node(left, source, prefix)
            base_prefix = left_path[0][0] if left_path else prefix
            if right.type in ("identifier", "self"):
                leaf_text = _text(right, source)
                if leaf_text == "self":
                    leaf_text = base_prefix[-1] if base_prefix else ""
                return [(base_prefix + (leaf_text,), leaf_text, None)]
            return self._flatten_use_node(right, source, base_prefix)
        if t == "use_as_clause":
            inner = node.children[0] if node.children else None
            alias_node = node.children[-1] if node.children else None
            if inner is None or alias_node is None:
                return []
            inner_results = self._flatten_use_node(inner, source, prefix)
            alias_text = _text(alias_node, source)
            return [(path, leaf, alias_text) for path, leaf, _ in inner_results]
        if t == "scoped_use_list":
            # `path::{a, b}` -- children: scoped_identifier(path), '::', use_list
            base = None
            use_list = None
            for child in node.children:
                if child.type in ("scoped_identifier", "identifier"):
                    base = child
                elif child.type == "use_list":
                    use_list = child
            base_path = self._flatten_use_node(base, source, prefix) if base is not None else []
            base_prefix = base_path[0][0] if base_path else prefix
            if use_list is None:
                return []
            return self._flatten_use_node(use_list, source, base_prefix)
        if t == "use_list":
            results: List[Tuple[Tuple[str, ...], str, Optional[str]]] = []
            for child in node.children:
                if child.type in (
                    "identifier", "self", "use_as_clause", "scoped_identifier",
                    "scoped_use_list", "use_list",
                ):
                    results.extend(self._flatten_use_node(child, source, prefix))
            return results
        if t == "use_wildcard":
            return [(prefix, "*", None)]
        return []

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        write_json(output_path, results)
