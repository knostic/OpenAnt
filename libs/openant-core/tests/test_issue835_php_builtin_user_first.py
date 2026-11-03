"""#835 — the PHP built-in veto fires BEFORE the user-function lookup: a
user function named like a built-in (``namespace App; function hash(...)
{}`` called as ``hash($x)``) loses its inbound edge — the caller's call
resolves to nothing and the callee is orphaned in the graph, taking its
whole subtree out of reachability. Seven of the eight families with
builtin-veto machinery resolve the shape the other way (C, Go, Python,
Swift, Ruby, Zig, Rust — each keeps the user-named call with scope
guards); PHP is the lone outlier. The file's own framework-dispatch rule
names the correct shape: a dispatcher routes to its callback "only when
NOT shadowed by a user-defined function of the same name (which would
be the real call target)" — the built-in veto lacked exactly this
shadow check.

THE RULING (the issue's fix-direction — the same shape the file already
applies at :319 and Ruby applies to builtins): a USER-DEFINED function
consultation BEFORE the built-in veto, at all three sites (:306 the
free-function path, :375 the string-callback path, :907 the regex
fallback). The scope is the resolver's own (same file / use-imports /
namespace-compatible — ``_resolve_simple_call``), so a GENUINE built-in
call is never rescued to an unrelated function: a builtin call with no
user function of that name in scope behaves exactly as before.

Shapes:
  S1 -- the WITNESS: a same-file user function named like a built-in
        (`hash`) keeps its inbound edge — the issue's own probe shape.
  S2 -- the differential control: a NON-builtin user function (`digest`)
        in the same fixture keeps its edge (the pre-existing behavior
        unchanged).
  S3 -- the genuine-builtin control: a builtin call with NO user
        function of that name in scope still drops (the veto's own
        purpose intact) — and the higher-order builtins
        (call_user_func/array_map) still resolve their CALLBACK arg.
  S4 -- the callback path (:375): a string callback naming a
        user-shadowed builtin (`call_user_func('hash')` with a user
        `hash`) keeps the edge to the USER function — the shadow is the
        real target (the file's own framework rule).
  S5 -- the regex fallback path (:907): unparseable code with a
        user-shadowed builtin call keeps the edge (the same shape the
        tree-walk path now keeps).
  S6 -- the scoping guard: a user `hash` in an UNRELATED namespace is
        never rescued — a builtin call with no same-file /
        import-resolved / namespace-compatible user function still
        drops (Ruby's "never rescued to an unrelated method").
  S7 -- the qualified-call shape: `\\App\\hash()` (explicitly
        namespaced) keeps its edge — the qualified name reduces to bare
        hash and funnels into the SAME unshadowed veto at base (a
        BASE-RED witness of this PR's root cause; PR#140 fixed only the
        member/scoped halves).
"""

import importlib.util
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def _load(unique, relpath):
    spec = importlib.util.spec_from_file_location(unique, str(CORE / relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cgb = _load("php_cgb_835", "parsers/php/call_graph_builder.py")
CallGraphBuilder = _cgb.CallGraphBuilder


def _build(funcs, classes=None, imports=None):
    b = CallGraphBuilder({"functions": funcs, "classes": classes or {},
                          "imports": imports or {}, "repository": "/r"})
    b.build_call_graph()
    return b


# ---------------------------------------------------------------------------
# S1/S2/S3 — the free-function path (:306)
# ---------------------------------------------------------------------------
def test_builtin_named_user_function_keeps_its_edge():
    """The issue's own probe shape: `hash` is a PHP built-in AND a
    same-file user function — the user function is the real call target
    (the shadow), and the edge to it must survive."""
    from parsers.php.call_graph_builder import PHP_BUILTINS as _PHP_BUILTINS
    assert "hash" in _PHP_BUILTINS, "the shadowed name must be a real builtin"
    b = _build({
        "app.php:App\\handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            "namespace_name": "App",
            "code": "function handler($req) { $a = hash($req); return $a; }"},
        "app.php:App\\hash": {
            "name": "hash", "file_path": "app.php", "class_name": None,
            "namespace_name": "App",
            "code": "function hash($x) { return $x; }"},
    })
    edges = b.call_graph.get("app.php:App\\handler", [])
    assert "app.php:App\\hash" in edges, (
        f"the user-shadowed builtin's inbound edge was dropped: {edges!r}")


def test_non_builtin_user_function_control_unchanged():
    b = _build({
        "app.php:App\\handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            "namespace_name": "App",
            "code": "function handler($req) { $a = digest($req); return $a; }"},
        "app.php:App\\digest": {
            "name": "digest", "file_path": "app.php", "class_name": None,
            "namespace_name": "App",
            "code": "function digest($x) { return $x; }"},
    })
    assert "app.php:App\\digest" in b.call_graph.get("app.php:App\\handler", [])


def test_genuine_builtin_still_drops_and_callbacks_still_resolve():
    b = _build({
        "app.php:handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            # strlen: a genuine builtin, no user fn named strlen in scope
            "code": "function handler($s) { return strlen($s); }"},
        "app.php:cb": {
            "name": "cb", "file_path": "app.php", "class_name": None,
            "code": "function cb() {}"},
    })
    assert b.call_graph.get("app.php:handler", []) == [], (
        "a genuine builtin call resolved somewhere: "
        f"{b.call_graph.get('app.php:handler')!r}")
    # the higher-order builtins keep their callback dispatch
    b2 = _build({
        "app.php:h2": {
            "name": "h2", "file_path": "app.php", "class_name": None,
            "code": "function h2() { call_user_func('cb'); }"},
        "app.php:cb": {
            "name": "cb", "file_path": "app.php", "class_name": None,
            "code": "function cb() {}"},
    })
    assert "app.php:cb" in b2.call_graph.get("app.php:h2", [])


# ---------------------------------------------------------------------------
# S4 — the string-callback path (:375)
# ---------------------------------------------------------------------------
def test_shadowed_builtin_string_callback_resolves_the_user_function():
    """`call_user_func('hash')` with a user `hash` in scope: the string
    callback names the USER function (the shadow is the real target —
    the file's own framework rule) — the edge must reach it."""
    from parsers.php.call_graph_builder import PHP_BUILTINS as _PHP_BUILTINS
    assert "hash" in _PHP_BUILTINS, "the shadowed name must be a real builtin"
    b = _build({
        "app.php:handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            "code": "function handler() { call_user_func('hash'); }"},
        "app.php:hash": {
            "name": "hash", "file_path": "app.php", "class_name": None,
            "code": "function hash() {}"},
    })
    assert "app.php:hash" in b.call_graph.get("app.php:handler", []), (
        f"the callback to a user-shadowed builtin dropped: "
        f"{b.call_graph.get('app.php:handler')!r}")


# ---------------------------------------------------------------------------
# S5 — the regex fallback path (:907)
# ---------------------------------------------------------------------------
def test_shadowed_builtin_keeps_edge_on_regex_fallback():
    """The :907 sibling (`_extract_calls_regex`): the fallback extraction
    must resolve a user-shadowed builtin name to the user function —
    the same shape the tree-walk path now keeps."""
    from parsers.php.call_graph_builder import PHP_BUILTINS as _PHP_BUILTINS
    assert "hash" in _PHP_BUILTINS, "the shadowed name must be a real builtin"
    b = CallGraphBuilder({
        "functions": {
            "app.php:handler": {
                "name": "handler", "file_path": "app.php", "class_name": None,
                "code": "function handler() { hash($x); }"},
            "app.php:hash": {
                "name": "hash", "file_path": "app.php", "class_name": None,
                "code": "function hash($x) {}"},
        },
        "classes": {}, "imports": {}, "repository": "/r"})
    calls = b._extract_calls_regex("hash($x);", "app.php:handler")
    assert "app.php:hash" in calls, (
        f"the regex fallback dropped the user-shadowed builtin: {calls!r}")
    # and the genuine builtin still skips there
    b2 = CallGraphBuilder({
        "functions": {
            "app.php:h": {
                "name": "h", "file_path": "app.php", "class_name": None,
                "code": "function h() {}"},
        },
        "classes": {}, "imports": {}, "repository": "/r"})
    calls2 = b2._extract_calls_regex("strlen($x);", "app.php:h")
    assert calls2 == set(), calls2


# ---------------------------------------------------------------------------
# S6 — the scoping guard (Ruby's "never rescued to an unrelated method")
# ---------------------------------------------------------------------------
def test_unrelated_namespace_user_function_is_never_rescued():
    """A user `hash` declared in an UNRELATED namespace does not rescue a
    builtin call from a different namespace — the resolver's own scope
    (namespace-compatible) is the guard."""
    b = _build({
        "a.php:Other\\handler": {
            "name": "handler", "file_path": "a.php", "class_name": None,
            "namespace_name": "Other",
            "code": "function handler($r) { return hash($r); }"},
        "b.php:App\\hash": {
            "name": "hash", "file_path": "b.php", "class_name": None,
            "namespace_name": "App",
            "code": "function hash($x) { return $x; }"},
    })
    edges = b.call_graph.get("a.php:Other\\handler", [])
    assert "b.php:App\\hash" not in edges, (
        f"a builtin call was rescued to an unrelated namespace: {edges!r}")


# ---------------------------------------------------------------------------
# S7 — the qualified-call shape (a base-red witness: the qualified name
# reduces to bare hash and funnels into the same unshadowed veto)
# ---------------------------------------------------------------------------
def test_qualified_namespaced_call_still_resolves():
    # the prod-hunk symbol: the resolver under fix is the prod module's own
    from parsers.php.call_graph_builder import PHP_BUILTINS as _PHP_BUILTINS
    assert "hash" in _PHP_BUILTINS, (
        "the prod built-in list must name hash — the shadowed name")
    b = _build({
        "app.php:App\\handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            "namespace_name": "App",
            "code": "function handler($r) { return \\App\\hash($r); }"},
        "app.php:App\\hash": {
            "name": "hash", "file_path": "app.php", "class_name": None,
            "namespace_name": "App",
            "code": "function hash($x) { return $x; }"},
    })
    assert "app.php:App\\hash" in b.call_graph.get("app.php:App\\handler", [])


# ---------------------------------------------------------------------------
# S8-S11 — the opus-seat catches (executed against the first fix)
# ---------------------------------------------------------------------------
def test_method_named_like_builtin_never_shadows():
    """The opus F1 catch, executed: functions_by_name indexes METHODS, so
    the bare membership gate fired for Order::count — a PHP-mandated
    interface method name inside PHP_BUILTINS — and the resolver's import
    path (which lacks the class_name filter) FABRICATED an edge from a
    genuine count() call to the method. A method never shadows a global
    function."""
    b = _build({
        # the caller imports the class whose method is named like a
        # builtin (the PSR-4 shape the opus seat probed)
        "src/Http/OrderController.php:OrderController.index": {
            "name": "index", "file_path": "src/Http/OrderController.php",
            "class_name": "OrderController",
            "code": "function index($items) { return count($items); }"},
        "src/Models/Order.php:Order.count": {
            "name": "count", "file_path": "src/Models/Order.php",
            "class_name": "Order",
            "code": "public function count() {}"},
    }, imports={"src/Http/OrderController.php": {"App/Models/Order": "use"}})
    edges = b.call_graph.get("src/Http/OrderController.php:OrderController.index", [])
    assert "src/Models/Order.php:Order.count" not in edges, (
        f"a genuine builtin call was rescued to a CLASS METHOD: {edges!r}")


def test_out_of_scope_user_named_callback_builtin_keeps_dispatch():
    """The opus F2 catch, executed: an array_map declared in an UNRELATED
    namespace (out of the caller's scope) — the user-first gate must
    FALL THROUGH (not return) so the CALLBACK_BUILTINS dispatch still
    resolves the callback argument; the unconditional return lost an
    edge base produced (an outright false negative). The prod-hunk
    predicate is pinned directly: array_map IS shadowed (a user free
    function exists) yet the dispatch still fires — the fall-through's
    own contract — and the prod module's own CALLBACK_BUILTINS names the
    dispatch this shape must keep."""
    from parsers.php.call_graph_builder import CALLBACK_BUILTINS as _PHP_CB
    assert _PHP_CB.get("array_map") is not None, (
        "the prod module's callback dispatch table lost array_map")
    b = _build({
        "a.php:Other\\handler": {
            "name": "handler", "file_path": "a.php", "class_name": None,
            "namespace_name": "Other",
            "code": "function handler($x) { array_map('cb', $x); }"},
        "a.php:Other\\cb": {
            "name": "cb", "file_path": "a.php", "class_name": None,
            "namespace_name": "Other",
            "code": "function cb($v) {}"},
        "b.php:App\\array_map": {
            "name": "array_map", "file_path": "b.php", "class_name": None,
            "namespace_name": "App",
            "code": "function array_map($c, $x) {}"},
    })
    edges = b.call_graph.get("a.php:Other\\handler", [])
    assert "a.php:Other\\cb" in edges, (
        f"the out-of-scope user-named array_map skipped the callback "
        f"dispatch (the F2 false negative): {edges!r}")
    # the unrelated App\array_map itself is NOT the target
    assert "b.php:App\\array_map" not in edges


def test_in_scope_user_named_callback_builtin_resolves_the_shadow():
    """The F2 flip side: a user array_map IN the caller's scope IS the
    call target (the shadow) — the callback dispatch is pre-empted
    CORRECTLY for this shape."""
    from parsers.php.call_graph_builder import PHP_BUILTINS as _PHP_BUILTINS
    assert "array_map" in _PHP_BUILTINS, "the shadowed name must be a real builtin"
    b = _build({
        "a.php:Other\\handler": {
            "name": "handler", "file_path": "a.php", "class_name": None,
            "namespace_name": "Other",
            "code": "function handler($x) { array_map('cb', $x); }"},
        "a.php:Other\\array_map": {
            "name": "array_map", "file_path": "a.php", "class_name": None,
            "namespace_name": "Other",
            "code": "function array_map($c, $x) {}"},
    })
    edges = b.call_graph.get("a.php:Other\\handler", [])
    assert "a.php:Other\\array_map" in edges, (
        f"the in-scope user shadow did not resolve: {edges!r}")


def test_in_scope_shadow_keeps_the_callback_arg_edge():
    """The astra-r1 catch, executed: when the IN-SCOPE user shadow of a
    HIGHER-ORDER builtin (array_map) resolves, base's callback-arg edge
    is RETAINED alongside it. The shadow is the real callee, but its
    dispatch semantics are user code — unknowable statically — and base
    seeded the argument edge under builtin-assumed semantics; dropping
    it traded a guaranteed edge for a variable-invocation false
    negative (the over-seed rule: a reachability-safe FP beats an FN).
    RED at base via the missing shadow edge (the core bug) and at the
    first-fix head via the missing cb edge (the astra catch) — the node
    pins both directions."""
    from parsers.php.call_graph_builder import CALLBACK_BUILTINS as _PHP_CB
    assert _PHP_CB.get("array_map") is not None, (
        "the prod module's callback dispatch table lost array_map")
    b = _build({
        "a.php:Other\\handler": {
            "name": "handler", "file_path": "a.php", "class_name": None,
            "namespace_name": "Other",
            "code": "function handler($x) { array_map('cb', $x); }"},
        "a.php:Other\\array_map": {
            "name": "array_map", "file_path": "a.php", "class_name": None,
            "namespace_name": "Other",
            "code": "function array_map($c, $x) {}"},
        "a.php:Other\\cb": {
            "name": "cb", "file_path": "a.php", "class_name": None,
            "namespace_name": "Other",
            "code": "function cb($v) {}"},
    })
    edges = b.call_graph.get("a.php:Other\\handler", [])
    assert "a.php:Other\\array_map" in edges, (
        f"the in-scope user shadow did not resolve: {edges!r}")
    assert "a.php:Other\\cb" in edges, (
        f"the shadow resolution dropped base's callback-arg edge (the "
        f"astra-r1 false negative): {edges!r}")


def test_method_named_callback_builtin_keeps_dispatch():
    """The opus P2b shape: a CLASS METHOD named call_user_func never
    shadows — the callback dispatch must still fire."""
    b = _build({
        "app.php:handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            "code": "function handler() { call_user_func('cb'); }"},
        "app.php:cb": {
            "name": "cb", "file_path": "app.php", "class_name": None,
            "code": "function cb() {}"},
        "app.php:User.call_user_func": {
            "name": "call_user_func", "file_path": "app.php",
            "class_name": "User",
            "code": "public function call_user_func() {}"},
    })
    edges = b.call_graph.get("app.php:handler", [])
    assert "app.php:cb" in edges, (
        f"a method-named call_user_func killed the callback dispatch: "
        f"{edges!r}")


def test_the_global_escape_never_rescues_a_namespaced_user_function():
    """The opus F3 catch, executed: a leading-backslash hash call —
    the explicit global escape; a namespaced user `hash` never shadows
    it (base dropped the edge and this fix must keep that drop for this
    shape, not rescue the user function)."""
    b = _build({
        "app.php:App\\handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            "namespace_name": "App",
            "code": "function handler($r) { return \\hash('sha256', $r); }"},
        "app.php:App\\hash": {
            "name": "hash", "file_path": "app.php", "class_name": None,
            "namespace_name": "App",
            "code": "function hash($x) { return $x; }"},
    })
    edges = b.call_graph.get("app.php:App\\handler", [])
    assert "app.php:App\\hash" not in edges, (
        f"the explicit-global-escape call rescued a namespaced user "
        f"function: {edges!r}")


# ---------------------------------------------------------------------------
# S13 — the fable-r1 F1 sink: the import path must not resolve a METHOD
# when a repo-wide FREE function of the name opened the gate
# ---------------------------------------------------------------------------
def test_import_path_never_resolves_a_method_for_a_genuine_builtin():
    """The fable-r1 F1 catch (the opus F1 shape, one sink deeper): the
    gate's predicate is REPO-WIDE (any free function of the name opens
    it) but the step-2 import sink is PER-IMPORT and lacked the
    class_name filter — a genuine `hash()` call in a file that uses
    Hasher (whose METHOD is named hash) fabricated an edge to the
    method. The gate opens (the repo-wide free fn exists — correct);
    the SINK must not resolve the method."""
    from parsers.php.call_graph_builder import PHP_BUILTINS as _PHP_BUILTINS
    assert "hash" in _PHP_BUILTINS, "the shadowed name must be a real builtin"
    b = _build({
        # the caller imports the class whose METHOD is named like the
        # builtin (the PSR-4 shape), and calls the GENUINE builtin
        "src/Http/Ctl.php:Ctl.index": {
            "name": "index", "file_path": "src/Http/Ctl.php",
            "class_name": "Ctl",
            "code": "function index($x) { return hash('sha256', $x); }"},
        "src/Security/Hasher.php:Hasher.hash": {
            "name": "hash", "file_path": "src/Security/Hasher.php",
            "class_name": "Hasher",
            "code": "public function hash() {}"},
        # a repo-wide FREE function of the name exists (an unrelated
        # namespace) — the gate correctly opens; the import sink must
        # still not resolve the METHOD
        "src/Legacy.php:App\\Legacy.hash": {
            "name": "hash", "file_path": "src/Legacy.php",
            "class_name": None, "namespace_name": "Legacy",
            "code": "function hash($x) { return $x; }"},
    }, imports={"src/Http/Ctl.php": {"App/Security/Hasher": "use"}})
    edges = b.call_graph.get("src/Http/Ctl.php:Ctl.index", [])
    assert "src/Security/Hasher.php:Hasher.hash" not in edges, (
        f"the import path resolved a METHOD for a genuine builtin call "
        f"(the fable-r1 F1 sink): {edges!r}")
    assert "src/Legacy.php:App\\Legacy.hash" not in edges, (
        f"the out-of-scope free function was rescued by the import path: "
        f"{edges!r}")


# ---------------------------------------------------------------------------
# S15/S16 — the list-contract guards (the astra-r1 amend's wiring): the
# refactor made one call node able to own TWO edges, and every return site
# in _resolve_function_call now speaks the list contract — these two pin
# the wiring paths the 14 #835 nodes never flow through (the E1/E2
# green-revert class the C4 runner flagged at the first amended head).
# ---------------------------------------------------------------------------
def test_framework_dispatch_through_the_list_contract():
    """S15: a genuine framework dispatcher (add_action — NOT a PHP
    builtin, no user function of that name) still routes to its callback
    argument through the LIST contract — the edge must be the real
    function ID, never the per-character debris of a str iterated as a
    sequence (the pre-existing #71 behavior, kept byte-for-byte in
    meaning by the refactor)."""
    from parsers.php.call_graph_builder import FRAMEWORK_CALLBACKS as _PHP_FW
    assert _PHP_FW.get("add_action") is not None, (
        "the prod module's framework dispatch table lost add_action")
    b = _build({
        "app.php:handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            "code": "function handler() { add_action('init', 'cb'); }"},
        "app.php:cb": {
            "name": "cb", "file_path": "app.php", "class_name": None,
            "code": "function cb() {}"},
    })
    edges = b.call_graph.get("app.php:handler", [])
    assert "app.php:cb" in edges, (
        f"the framework dispatch lost its callback edge: {edges!r}")


def test_unresolvable_bare_call_emits_no_edge():
    """S16: a bare call to a non-builtin name with NO user function of
    that name anywhere reaches the FINAL return of
    _resolve_function_call and must emit NO edge — nothing resolves, so
    nothing may be fabricated (and the list contract's empty return must
    flow through the extraction loop without breaking it)."""
    b = _build({
        "app.php:handler": {
            "name": "handler", "file_path": "app.php", "class_name": None,
            "code": "function handler($x) { return missing_fn($x); }"},
    })
    edges = b.call_graph.get("app.php:handler", [])
    assert edges == [], (
        f"an unresolvable non-builtin bare call fabricated an edge: "
        f"{edges!r}")
