"""SE-0279 trailing-closure argument labels in call resolution.

`Many { } separator: { } terminator: { }` (result-builder DSL) carries the secondary
trailing-closure labels as `simple_identifier ':' lambda_literal` directly under
call_suffix — NOT as value_arguments. Before the fix, `_call_labels` returned labels=[]
for these, so the overload matcher could not narrow (Many fanned to all 48 init overloads,
a 57%-of-edges phantom flood) and — worse — a call like `Prefix { }` misresolved to an
all-defaulted overload while the true `init(while:)` (whose closure param is required but
filled by the primary trailing closure, label elided) was wrongly rejected (a recall loss).

The fix: extract the secondary labels and count the unlabeled primary; the matcher lets
that many REQUIRED labels go unspelled (a trailing closure fills its param without spelling
the label). Additive to recall — proven drop-only==0 on the 60-repo corpus.
"""
import importlib.util
import pathlib
import sys

import tree_sitter_swift as tss
from tree_sitter import Language, Parser

_HERE = pathlib.Path(__file__).resolve().parent
_CORE = _HERE.parents[2]
sys.path.insert(0, str(_CORE))


def _cgb():
    spec = importlib.util.spec_from_file_location(
        "swift_cgb_tcl", _CORE / "parsers" / "swift" / "call_graph_builder.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # minimal extractor_output; we only exercise pure helpers
    return mod.CallGraphBuilder({"functions": {}, "classes": {}, "files": {}})


def _first_call(src: bytes, name: str):
    lang = Language(tss.language())
    root = Parser(lang).parse(src).root_node
    found = []

    def walk(n):
        if n.type in ("call_expression", "constructor_expression"):
            head = src[n.start_byte:n.end_byte].decode()
            if head.startswith(name):
                found.append(n)
        for c in n.children:
            walk(c)
    walk(root)
    return found[0]


def test_call_labels_extracts_secondary_trailing_closure_labels():
    b = _cgb()
    src = b"let x = Many { a() } separator: { b() } terminator: { c() }\n"
    node = _first_call(src, "Many")
    labels, arity, trailing, unlabeled = b._call_labels(node, src)
    assert "separator" in labels and "terminator" in labels   # were dropped before the fix
    assert trailing == 3
    assert unlabeled == 1                                       # the primary `{ a() }`
    assert arity == 3


def test_call_labels_primary_only_is_one_unlabeled():
    b = _cgb()
    src = b"let x = Prefix { p() }\n"
    node = _first_call(src, "Prefix")
    labels, arity, trailing, unlabeled = b._call_labels(node, src)
    assert labels == [None] and trailing == 1 and unlabeled == 1


def test_sig_compatible_accepts_trailing_closure_filled_required_param():
    """The recall fix: `Prefix { }` (labels=[], one unlabeled trailing closure) must match
    `init(while:)` whose `while` is REQUIRED but filled by the primary closure. Before the
    fix `required_named ⊆ labeled` rejected it -> the true overload was starved."""
    b = _cgb()
    site = {"labels": [None], "arity": 1, "trailing": 1, "unlabeled_trailing": 1}
    init_while = {"signature": ["while"], "param_defaults": [False]}
    # constructor context (allow_unlabeled_trailing=True): the primary closure fills `while`
    assert b._sig_compatible(site, init_while, allow_unlabeled_trailing=True) is True
    # method/unknown-receiver context (default False): stays strict — broadening there would
    # tip a unique resolution into a decline and drop a real edge (the 395-edge regression)
    assert b._sig_compatible(site, init_while) is False
    # and a spelled-label call with no unlabeled trailing still requires the label
    site_no_trailing = {"labels": [], "arity": 0, "trailing": 0, "unlabeled_trailing": 0}
    assert b._sig_compatible(site_no_trailing, init_while, allow_unlabeled_trailing=True) is False


def test_sig_compatible_narrows_many_by_secondary_labels():
    """`Many { } separator: { } terminator: { }` must match the (element:separator:terminator:)
    overload and REJECT (element:separator:) — the secondary labels now narrow it."""
    b = _cgb()
    site = {"labels": [None, "separator", "terminator"], "arity": 3, "trailing": 3,
            "unlabeled_trailing": 1}
    est = {"signature": ["element", "separator", "terminator"],
           "param_defaults": [False, False, False]}
    es = {"signature": ["element", "separator"], "param_defaults": [False, False]}
    assert b._sig_compatible(site, est, allow_unlabeled_trailing=True) is True
    assert b._sig_compatible(site, es, allow_unlabeled_trailing=True) is False   # terminator not in decl


def test_match_overloads_known_receiver_relaxes_trailing_closure():
    """CL-2: a KNOWN-receiver method call `r.run { }` where `run(while:)` is required but
    filled by the primary trailing closure must reach `run(while:)`, not just the
    all-defaulted `run(times:)` decoy. The relaxation is passed ONLY on the known-receiver
    dispatch; the method DEFAULT (bare-name / unknown-receiver) stays strict so it can't
    exceed the ambiguity cap or trip the unknown-receiver decline."""
    b = _cgb()
    b.functions = {
        "F:Runner.run(while)": {"signature": ["while"], "param_defaults": [False],
                                "qualified_name": "Runner.run", "class_name": "Runner"},
        "F:Runner.run(times)": {"signature": ["times"], "param_defaults": [True],
                                "qualified_name": "Runner.run", "class_name": "Runner"},
    }
    cands = ["F:Runner.run(while)", "F:Runner.run(times)"]
    site = {"labels": [None], "arity": 1, "trailing": 1, "unlabeled_trailing": 1}
    relaxed = b._match_overloads(cands, site, allow_unlabeled_trailing=True)
    assert "F:Runner.run(while)" in relaxed          # true target reached (CL-2 fixed)
    strict = b._match_overloads(cands, site)          # method default = strict
    assert "F:Runner.run(while)" not in strict        # the bug: decoy-only, true target starved


def _resolve_go_edges(tmp_path, src: str):
    """Run the real scan->extract->build pipeline on `src` and return the
    qualified names Caller.go resolves to."""
    from parsers.swift.repository_scanner import RepositoryScanner
    from parsers.swift.function_extractor import FunctionExtractor
    from parsers.swift.call_graph_builder import CallGraphBuilder
    (tmp_path / "Sources").mkdir()
    (tmp_path / "Sources" / "Poc.swift").write_text(src)
    scan = RepositoryScanner(str(tmp_path)).scan()
    ext = FunctionExtractor(str(tmp_path), scan).extract()
    cg = CallGraphBuilder(ext).build()
    graph = cg.get("call_graph", cg)
    for caller, callees in graph.items():
        if "Caller" in caller and "go" in caller:
            return [cg.get("functions", {}).get(x, {}).get("qualified_name", x)
                    for x in callees]
    return []


def test_c2_subset_keeps_inherited_target_when_relaxation_admits_decoy(tmp_path):
    """cx3/CL-2 guard: the TYPE-BLIND unlabeled-trailing allowance can admit a
    same-qualified DECOY overload (`Outer.Inner.run(name:)`), which the var_qualified
    subset then prefers, EVICTING the strictly-matched inherited target (`Base.run(_:)`).
    Both share the qualified name so no set-diff gate sees the loss. The `relaxed_added`
    guard (mirroring `_match_ctors`) must keep the inherited target."""
    names = _resolve_go_edges(tmp_path, (
        "class Base { func run(_ body: () -> Void) { realTargetMarker() } }\n"
        "enum Outer { class Inner: Base { func run(name: String) { decoyMarker() } } }\n"
        "class Caller { func go() { let x = Outer.Inner(); x.run { } } }\n"))
    assert any("Base.run" in n for n in names), f"inherited Base.run evicted: {names}"


def test_c2_subset_still_narrows_qualified_identity_without_trailing_closure(tmp_path):
    """The guard must NOT disable legitimate var_qualified narrowing: a spelled call
    `x.next(idx:)` with no trailing closure (no relaxation) must still narrow to the
    receiver's qualified type (`SeqB.next`), not fan to the same-leaf `SeqA.next`."""
    names = _resolve_go_edges(tmp_path, (
        "class SeqA { func next(idx: Int) { aMarker() } }\n"
        "class SeqB { func next(idx: Int) { bMarker() } }\n"
        "class Caller { func go() { let x = SeqB(); x.next(idx: 1) } }\n"))
    assert names == ["SeqB.next"], f"var_qualified narrowing regressed: {names}"


def _resolve_go_sigs(tmp_path, src: str):
    """Like _resolve_go_edges but returns the SIGNATURES of the reached callees
    (overloads sharing a qualified name are distinguished by signature)."""
    from parsers.swift.repository_scanner import RepositoryScanner
    from parsers.swift.function_extractor import FunctionExtractor
    from parsers.swift.call_graph_builder import CallGraphBuilder
    (tmp_path / "Sources").mkdir()
    (tmp_path / "Sources" / "Poc.swift").write_text(src)
    cg = CallGraphBuilder(FunctionExtractor(
        str(tmp_path), RepositoryScanner(str(tmp_path)).scan()).extract()).build()
    graph = cg.get("call_graph", cg)
    for caller, callees in graph.items():
        if "Caller" in caller and "go" in caller:
            return [tuple(cg.get("functions", {}).get(x, {}).get("signature") or [])
                    for x in callees]
    return []


def test_bare_implicit_self_call_reaches_trailing_closure_overload(tmp_path):
    """CL-2b: a BARE call `run { }` inside a class is implicit `self.run` and dispatches
    on the enclosing-type tier (`same_type`), which was left strict by CL-2. The true
    `run(while:)` (required label filled by the primary trailing closure) was starved to
    the all-defaulted `run(times:)` decoy. Relaxing the enclosing-type dispatch (no cx3
    guard needed -- it returns directly, no var_qualified subset / fan-out cap) recovers
    it. This is the implicit-self parity of the explicit-receiver CL-2 fix."""
    sigs = _resolve_go_sigs(tmp_path, (
        "class Caller {\n"
        "  func run(while cond: () -> Bool) { realTargetMarker() }\n"
        "  func run(times: Int = 1) { decoyMarker() }\n"
        "  func go() { run { return false } }\n"
        "}\n"))
    assert ("while",) in sigs, f"bare implicit-self run(while:) starved: {sigs}"


def test_cl2b_recall_floor_keeps_variadic_target_strict_found_nothing(tmp_path):
    """CL-2b recall floor (Fable): when STRICT matching finds no compatible same_type
    overload, `_match_overloads` returns the full recall fallback. The type-blind
    relaxation must NOT replace that fallback -- a variadic (or parameter-pack) callee
    under-counts its arity and fails the arity bound under both strict and relaxed, so it
    survives ONLY via the fallback. Relaxing here would narrow to a decoy and EVICT the
    real target (same leaf AND qualified name -> invisible to set-diff oracles). The floor
    (relax only when the strict subset is non-empty) keeps the real target reachable."""
    sigs = _resolve_go_sigs(tmp_path, (
        "class Caller {\n"
        "  func put(_ items: Int..., done: () -> Void) { realTargetMarker(); done() }\n"
        "  func put(_ a: Int, _ b: Int, _ c: Int, into bucket: String) { decoyMarker() }\n"
        "  func go() { put(1, 2, 3) { self.realTargetMarker() } }\n"
        "}\n"))
    assert ("_", "done") in sigs, f"variadic put(_:done:) evicted by relaxation: {sigs}"
