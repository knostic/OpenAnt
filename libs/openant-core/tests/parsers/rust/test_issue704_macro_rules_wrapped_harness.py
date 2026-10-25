"""#704: recognize macro_rules!-wrapped fuzz harnesses in the Rust parser.

PR #234 broadened harness recognition to aliased libFuzzer + AFL forms and
DEFERRED one form explicitly ("macro_rules!-wrapped harnesses ... tracked as a
follow-up"); no issue was opened until #704. The deferral is the #228 mechanism
for that shape: a crate wraps its harness in its OWN `macro_rules!` (the common
multi-target pattern), the invocation's token tree is opaque, tree-sitter
emits no `function_item` for the expansion, and the closure's calls never enter
the call graph — a pure fuzz-target crate is pruned before analysis.

Recognition stays over-seed-safe and guard-first:
  - macro-DEFINITION scanning: the file's local `macro_rules!` bodies are
    collected during the walk (any nesting depth);
  - an invocation whose bare name is LOCALLY DEFINED (not import-resolved) and
    whose definition body contains a harness form is a harness invocation —
    the local-definition lookup IS the over-match guard (a name that imports
    resolves through the import path first and never reaches the local map);
  - the harness form inside a body: the distinctive libFuzzer `fuzz_target!`,
    path-qualified `afl::fuzz!`, or a bare `fuzz!` gated on the file's own AFL
    macro scope (`#[macro_use] extern crate afl` / `use afl::*`);
  - the LIFT: the harness-bearing rule body is re-parsed as a wrapper fn and
    walked with the ORDINARY extractor, so the inner `fuzz_target!` parses as
    a real node and the existing direct machinery lifts the actual closure
    (typed `main` + `synthetic_harness` by its own merge). The wrapper fn is a
    vehicle — never a unit.

Disclosed edges (the conservative-minimal scope, corrected per the fable hunt):
  - the transitive-chain edge (pinned both ways): a wrapper whose rule
    body carries a harness token of its own AND invokes another local
    wrapper inside a LIFTED closure IS recognized at every level (the
    nested-lines pin); a NAME-ONLY chain — a wrapper whose body names
    another wrapper but carries no harness token of its own — is NOT
    recognized (under-seed, the disclosed limit, pinned);
  - an imported name resolves before the local map even when a local
    definition also exists (the pathological both-imported-and-local file;
    under-seed, pinned);
  - a `$`-metavariable body PARSES (tree-sitter accepts `$` tokens) and seeds
    a harness unit whose metavariable callees resolve to NOTHING (a dead
    `$name(data)` call) — the #228 callee blackout persists for THAT form
    (pinned below: the unit seeds, the callees stay empty);
  - two invocations of the SAME wrapper seed ONE unit (identical closure
    text — the dedup; the reachable set is identical); two DIFFERENT
    wrappers in one file seed BOTH (the fable-F1 collision fix — the second
    is renamed `fuzz_target__wrappedN`, never dropped);
  - the definitions are SAME-FILE: a wrapper whose macro_rules! lives in a
    sibling file (`#[macro_use] mod common;` pulling common.rs) is a
    DISCLOSED LIMIT (the typical multi-target layout needs cross-file
    collection — pinned below as not-seeded); a wrapper defined INSIDE
    `#[macro_use] mod m { .. }` in the SAME file IS covered (the full-tree
    pre-scan, the fable-F6 fix);
  - the fall-through re-opens a textual-match class (the fable-r2 S1
    disclosure): a rule body whose fuzz_target! mention lives in a COMMENT
    or string literal, invoked WITH a closure argument, seeds via the
    fall-through (the lift's real parse found nothing, the direct path
    takes the invocation's own closure) — over-seed direction, a contrived
    shape; the LONGER-token variant stays refused (pinned below);
  - the pre-scan reads definitions inside `#[cfg(test)]` mod bodies the
    walk itself skips, so a test-only macro invoked at top level seeds
    under skip_tests (over-seed; the shape needs #[macro_use] to compile);
  - an imported macro name resolves through the import BEFORE the local map,
    inverting Rust's textual-scope-first precedence for a pathological file
    that both imports and locally defines the same name (under-seed, rare);
  - a self-/mutually-recursive wrapper (or an AFL-style tt-muncher that
    re-invokes itself) seeds ONCE PER INVOCATION SITE — the designed
    _lift_stack recursion guard, not an interpreter-bounded RecursionError
    (the fable-r7 F1 catch: before the guard, a 12-line tt-muncher file
    exploded to 330 harnesses); pinned below (the self/mutual/tt-muncher
    trio);
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import build  # noqa: E402
from _rust_helpers import (  # noqa: E402
    FunctionExtractor,
    RepositoryScanner,
)
# The PROD module directly — the witness screen's channel: each gate witness
# loads a symbol from the prod-hunk file (parsers/rust/function_extractor.py)
# in its own body, never an inline re-implementation. The helper loads the
# same module by package path; the pin asserts they are one class. NOTE: the
# import carries NO alias on purpose — the screen resolves `from X import Y`
# to the SUBMODULE only unaliased (an asname binds the package).
from parsers.rust import function_extractor  # noqa: E402


def _extract_gated(tmp_path, files, skip_tests):
    """The PRODUCTION wiring for the test-gating pins: the shared `build`
    helper threads skip_tests to the SCANNER only (the extractor runs with
    its default False — a helper inconsistency this suite works around by
    constructing the stages directly, exactly as the pipeline driver does:
    `FunctionExtractor(repo, scan, skip_tests=...)`)."""
    for name, src in files.items():
        f = pathlib.Path(tmp_path) / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(src, newline="\n")  # LF-explicit (the #723 windows CI leg)
    scan = RepositoryScanner(str(tmp_path), skip_tests=skip_tests).scan()
    return FunctionExtractor(str(tmp_path), scan,
                             skip_tests=skip_tests).extract()

FRAME = """
pub struct Frame;
impl Frame {
    pub fn decode(d: &[u8]) -> Frame { Frame }
}
"""

WRAPPER = """
macro_rules! fuzz_entry {
    () => {
        fuzz_target!(|data: &[u8]| { let _ = Frame::decode(data); });
    };
}
"""


def _harness_ids(cg):
    return [k for k, v in cg["functions"].items() if v.get("synthetic_harness")]


def _one(tmp_path, fuzz_src, skip_tests=True):
    _, cg = build(tmp_path, {"src.rs": FRAME, "fuzz/h.rs": fuzz_src},
                  skip_tests=skip_tests)
    return cg


# --- the falsifier's shape: MUST be recognized (RED pre-fix: 0 harnesses) ---

def test_wrapped_libfuzzer_harness_is_seeded(tmp_path):
    """The #704 acceptance: a macro_rules!-wrapped harness produces a
    synthetic entry-point unit at HEAD (at base the invocation is opaque and
    the whole harness is invisible — the #228 blackout for this form)."""
    assert function_extractor.FunctionExtractor is FunctionExtractor  # the prod class
    assert hasattr(function_extractor.FunctionExtractor, "_lift_wrapped_harness"), (
        "the wrapper lift is missing from the prod extractor")
    cg = _one(tmp_path, WRAPPER + "fuzz_entry!();\n")
    ids = _harness_ids(cg)
    assert len(ids) == 1, (
        f"the macro_rules!-wrapped harness was not seeded (ids={ids}) — "
        "the #234 deferral still in force")
    info = cg["functions"][ids[0]]
    assert info["unit_type"] == "main", "a harness unit must seed reachability"


def test_wrapped_harness_closure_calls_enter_the_graph(tmp_path):
    """The #228 mechanism, not just the seed: the closure body's calls must
    enter the call graph (Frame::decode must be reachable FROM the harness)."""
    assert function_extractor.FunctionExtractor is FunctionExtractor  # the prod class
    cg = _one(tmp_path, WRAPPER + "fuzz_entry!();\n")
    ids = _harness_ids(cg)
    assert len(ids) == 1
    decode_ids = [k for k in cg["functions"] if k.endswith(".decode")]
    assert decode_ids, "the FRAME helper's decode is missing from the graph"
    harness_id, decode_id = ids[0], decode_ids[0]
    callees = set(cg.get("call_graph", {}).get(harness_id, ()))
    assert decode_id in callees, (
        "the wrapped harness's closure call never entered the call graph — "
        "the harness seeds reachability but its callees stay blacked out")


def test_wrapped_afl_path_qualified_is_seeded(tmp_path):
    assert hasattr(function_extractor.FunctionExtractor, "_wrapped_macro_body"), (
        "the expansion-shape helper is missing from the prod extractor")
    cg = _one(tmp_path, """
macro_rules! fuzz_case {
    () => { afl::fuzz!(|data: &[u8]| { let _ = Frame::decode(data); }); };
}
fuzz_case!();
""")
    assert len(_harness_ids(cg)) == 1, "afl::fuzz! inside a local macro was not seeded"


def test_wrapped_bare_fuzz_with_afl_macro_scope_is_seeded(tmp_path):
    # the generic `fuzz` is NEVER unconditionally accepted — the afl gate is
    # the whole difference for this shape (the guard this witness exercises)
    assert "fuzz" not in function_extractor.FunctionExtractor._FUZZ_MACRO_NAMES
    cg = _one(tmp_path, """
#[macro_use]
extern crate afl;
macro_rules! fuzz_case {
    () => { fuzz!(|data: &[u8]| { let _ = Frame::decode(data); }); };
}
fuzz_case!();
""")
    assert len(_harness_ids(cg)) == 1, (
        "a bare fuzz! inside a local macro body was not seeded despite the "
        "file's own #[macro_use] afl scope")


# --- the over-match guards (MUST stay unseeded — the #234 control) ---

def test_local_macro_without_harness_shape_is_not_seeded(tmp_path):
    """A locally-defined macro that does NOT wrap a harness is never a
    harness — the body shape is load-bearing, not the local-ness."""
    cg = _one(tmp_path, """
macro_rules! helper {
    () => { let _ = Frame::decode(&[]); };
}
helper!();
""")
    assert _harness_ids(cg) == [], "a non-harness local macro was mis-lifted"


def test_imported_macro_name_without_local_definition_is_not_seeded(tmp_path):
    """The alias guard survives the new path: a bare name that IMPORTS (an
    unrelated crate's macro aliased to a plausible name) resolves through the
    import first and never consults the local map."""
    cg = _one(tmp_path, "use evil::thing as fuzz_entry;\nfuzz_entry!(|d| { let _ = d; });\n")
    assert _harness_ids(cg) == [], "an imported alias leaked into the local-map path"


def test_bare_fuzz_in_macro_body_without_afl_scope_is_not_seeded(tmp_path):
    """The afl gate applies inside macro bodies too: a bare `fuzz!` in a file
    that does not scope afl's macros is not a harness invocation."""
    cg = _one(tmp_path, """
macro_rules! maybe_fuzz {
    () => { fuzz!(|d: &[u8]| { let _ = d; }); };
}
maybe_fuzz!();
""")
    assert _harness_ids(cg) == [], "the afl gate was bypassed inside a macro body"


# --- scope/gating behavior ---

def test_wrapped_invocation_inside_test_fn_skipped_when_tests_excluded(tmp_path):
    """The in_test_scope gate covers the wrapped form: a wrapped invocation
    inside a #[test] fn is a test, not an entry point, and skips when tests
    are excluded (the gate fires in _handle_fuzz_target BEFORE the wrapper
    dispatch) — pinned against the PRODUCTION wiring (see _extract_gated)."""
    ext = _extract_gated(tmp_path, {"src.rs": FRAME, "fuzz/h.rs": WRAPPER + """
#[test]
fn calls_the_harness() { fuzz_entry!(); }
"""}, skip_tests=True)
    ids = [k for k, v in ext["functions"].items() if v.get("synthetic_harness")]
    assert ids == [], "an in-test-scope wrapped harness was seeded"


def test_wrapped_invocation_inside_test_fn_kept_when_tests_included(tmp_path):
    ext = _extract_gated(tmp_path, {"src.rs": FRAME, "fuzz/h.rs": WRAPPER + """
#[test]
fn calls_the_harness() { fuzz_entry!(); }
"""}, skip_tests=False)
    ids = [k for k, v in ext["functions"].items() if v.get("synthetic_harness")]
    assert len(ids) == 1, "the test-included pass lost the harness"


@pytest.mark.xfail(strict=True, reason=(
    "the PRE-EXISTING statement-attr leak (both forms; the over-seed, "
    "reachability-safe direction) — retires LOUDLY when the attr threading "
    "is fixed (its own issue): the XPASS failure is the retirement signal"))
def test_cfg_test_attr_on_the_invocation_statement_leaks_PRE_EXISTING(tmp_path):
    """The disclosed PRE-EXISTING side-finding (NOT introduced by #704 — the
    direct form leaks identically at the base; verified while writing this
    suite): a `#[cfg(test)]` attribute on the invocation's STATEMENT is
    dropped at the statement boundary (the walk pushes the
    expression_statement with the attrs cleared), so it never reaches
    _handle_fuzz_target's attr gate. The leak is the over-seed direction —
    a test-gated harness seeds reachability, which a SAST engine treats as
    the safe false positive; the docstring's attr-gate claim is corrected
    alongside. STRICT-DECORATOR form (the fable-F7 catch): the imperative
    pytest.xfail() could never XPASS — it retired SILENTLY; the decorator
    fails the suite when the leak is fixed."""
    ext = _extract_gated(tmp_path, {"src.rs": FRAME, "fuzz/h.rs": WRAPPER + "#[cfg(test)]\nfuzz_entry!();\n"}, skip_tests=True)
    ids = [k for k, v in ext["functions"].items() if v.get("synthetic_harness")]
    # the DESIRED state (the #702 strict-xfail pattern): the gated
    # invocation seeds NOTHING. At HEAD the leak is live → this assert
    # fails → xfail (the suite stays green while the side-finding is
    # disclosed); when the attr threading is fixed the assert passes →
    # XPASS → strict → the suite fails LOUDLY and the pin retires.
    assert ids == [], (
        f"the statement-attr leak is live: {ids} — the disclosed "
        "pre-existing side-finding (both forms leak it; over-seed, "
        "reachability-safe)")


def test_two_invocations_of_one_wrapper_seed_one_unit(tmp_path):
    """Two invocations of the same wrapper expand to identical closure text —
    the dedup keeps ONE unit (the reachable set is identical; disclosed)."""
    cg = _one(tmp_path, WRAPPER + "fuzz_entry!();\nfuzz_entry!();\n")
    assert len(_harness_ids(cg)) == 1, "identical expansions double-seeded"


def test_base_direct_fuzz_target_still_seeded(tmp_path):
    """The direct path is untouched by the wrapper machinery."""
    cg = _one(tmp_path, "fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); });\n")
    assert len(_harness_ids(cg)) == 1, "the direct fuzz_target! form regressed"


# --- the fable-r1 remediation pins ---

def test_two_different_wrappers_in_one_file_seed_both(tmp_path):
    """The fable-F1 collision fix: two DIFFERENT wrapped harnesses in one
    file both seed (the second is renamed, never silently dropped — the drop
    was the under-seed direction; a whole crate's harness edges were lost)."""
    cg = _one(tmp_path, """
macro_rules! w1 {
    () => { fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); }); };
}
macro_rules! w2 {
    () => { fuzz_target!(|d: &[u8]| { let _ = Frame::encode(d); }); };
}
fn encode_helper(d: &[u8]) -> u8 { 0 }
pub fn Frame_encode(d: &[u8]) -> u8 { encode_helper(d) }
w1!();
w2!();
""")
    ids = _harness_ids(cg)
    assert len(ids) == 2, f"expected both wrapped harnesses, got {ids}"
    # the vehicle never leaks as a unit
    assert all("__wrapped_macro_harness__" not in k for k in cg["functions"]), (
        "the wrapper vehicle leaked as a unit")
    # both closures' callees enter the graph (each harness reaches its own)
    callees = {k: set(cg["call_graph"].get(k, ())) for k in ids}
    assert any(c for c in callees.values()), "neither harness carries edges"


def test_two_invocations_of_one_wrapper_still_dedup(tmp_path):
    """The dedup SURVIVES the collision fix: identical expansion text (two
    invocations of ONE wrapper) still seeds exactly one unit."""
    cg = _one(tmp_path, WRAPPER + "fuzz_entry!();\nfuzz_entry!();\n")
    assert len(_harness_ids(cg)) == 1, "identical expansions double-seeded"


def test_unaliased_afl_import_scopes_wrapped_bare_fuzz(tmp_path):
    """The fable-F2 fix: `use afl::fuzz;` (the documented afl.rs form, which
    the DIRECT path accepts) also scopes a bare `fuzz!` inside a local
    macro body — the body gate now mirrors the direct path exactly."""
    cg = _one(tmp_path, """
use afl::fuzz;
macro_rules! fuzz_case {
    () => { fuzz!(|data: &[u8]| { let _ = Frame::decode(data); }); };
}
fuzz_case!();
""")
    assert len(_harness_ids(cg)) == 1, (
        "use afl::fuzz; did not scope the wrapped bare fuzz! — the body gate "
        "diverged from the direct path")


def test_aliased_afl_import_does_not_scope_wrapped_bare_fuzz(tmp_path):
    """The alias stays a non-scope: `use afl::fuzz as f;` does not bind the
    bare name `fuzz`, so a body calling `fuzz!` is not afl's (the guard)."""
    cg = _one(tmp_path, """
use afl::fuzz as f;
macro_rules! fuzz_case {
    () => { fuzz!(|data: &[u8]| { let _ = Frame::decode(data); }); };
}
fuzz_case!();
""")
    assert _harness_ids(cg) == [], "the aliased afl import mis-scoped fuzz!"


def test_pass_through_wrapper_seeds_from_the_invocation(tmp_path):
    """The fable-F3 fix: a PASS-THROUGH wrapper (`($c:expr) => {
    fuzz_target!($c) }`) carries no closure in its rule body — the closure
    lives at the INVOCATION. The lift merges nothing and falls through to
    the direct path, which lifts the invocation's own closure."""
    cg = _one(tmp_path, """
macro_rules! fuzz_entry {
    ($closure:expr) => { libfuzzer_sys::fuzz_target!($closure); };
}
fuzz_entry!(|data: &[u8]| { let _ = Frame::decode(data); });
""")
    assert len(_harness_ids(cg)) == 1, (
        "the pass-through wrapper (closure at the invocation) seeded nothing")


def test_wrapper_defined_inside_a_macro_use_mod_is_found(tmp_path):
    """The fable-F6 fix: a definition nested inside `#[macro_use] mod m {
    macro_rules! ... }` in the SAME file, invoked at the top level BELOW it
    — the full-tree PRE-SCAN fills the map before the LIFO worklist order
    can miss it."""
    cg = _one(tmp_path, """
#[macro_use]
mod m {
    macro_rules! fuzz_entry {
        () => { fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); }); };
    }
}
fuzz_entry!();
""")
    assert len(_harness_ids(cg)) == 1, (
        "the mod-nested definition was missed (the LIFO walk-order class)")


def test_wrapper_in_a_sibling_file_is_the_disclosed_limit(tmp_path):
    """The DISCLOSED SAME-FILE limit (pinned): a wrapper whose macro_rules!
    lives in a sibling file (`#[macro_use] mod common;` pulling common.rs)
    is NOT recognized — cross-file-in-crate collection is the follow-up."""
    files = {"src.rs": FRAME, "fuzz/h.rs": "#[macro_use]\nmod common;\nfuzz_entry!();\n",
             "common.rs": "macro_rules! fuzz_entry {\n    () => { fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); }); };\n}\n"}
    import pathlib as _pl
    d = _pl.Path(tmp_path)
    for name, src in files.items():
        f = d / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(src, newline="\n")
    from _rust_helpers import RepositoryScanner as _RS, FunctionExtractor as _FE
    scan = _RS(str(d), skip_tests=True).scan()
    ext = _FE(str(d), scan, skip_tests=True).extract()
    ids = [k for k, v in ext["functions"].items() if v.get("synthetic_harness")]
    assert ids == [], (
        f"cross-file collection happened — the disclosed limit moved; "
        f"update the docstring and this pin (ids={ids})")


def test_dollar_metavariable_body_seeds_with_dead_callees(tmp_path):
    """The DISCLOSED $-metavariable limit (pinned, the fable-F4 correction):
    such a body PARSES (not skipped) and seeds a harness whose metavariable
    callees resolve to nothing — the unit exists (over-seed) but the #228
    callee blackout persists for THIS form."""
    cg = _one(tmp_path, """
macro_rules! fuzz_entry {
    ($name:ident) => { fuzz_target!(|d: &[u8]| { $name(d); }); };
}
fuzz_entry!(some_target);
""")
    ids = _harness_ids(cg)
    assert len(ids) == 1, "the $-body failed to seed (the disclosure said it seeds)"
    callees = cg["call_graph"].get(ids[0], [])
    assert callees == [], (
        f"a $-metavariable callee resolved to something ({callees}) — "
        "the dead-callee disclosure drifted")


def test_wrapper_body_defining_and_invoking_its_own_inner_macro(tmp_path):
    """The IN-WALK collection branch: a lifted body that DEFINES its own
    macro_rules! and invokes it must resolve through the map the walk fills
    (the file-tree pre-scan cannot see inside macro bodies — only the in-walk
    branch collects for the synth trees). The C4 row for the in-walk branch
    hunk was green until this pin."""
    cg = _one(tmp_path, """
macro_rules! outer {
    () => {
        macro_rules! inner_h {
            () => { fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); }); };
        }
        inner_h!();
    };
}
outer!();
""")
    ids = _harness_ids(cg)
    assert len(ids) == 1, (
        f"the inner macro defined+invoked inside the lifted body was not "
        f"resolved (ids={ids}) — the in-walk map collection is dead")


def test_wrapper_inside_a_pass_through_closure_keeps_definition_lines(tmp_path):
    """The DIRECT merge's file-absolute marker path (the C4 row was green
    until this pin): a wrapper invoked INSIDE a pass-through's closure —
    the fall-through lifts the invocation's closure with the direct path,
    the wrapper lift inside it merges FILE-absolute tagged units, and the
    direct merge must pass them through WITHOUT re-offsetting."""
    cg = _one(tmp_path, """
macro_rules! leaf_w {
    () => { fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); }); };
}
macro_rules! pass_through {
    ($c:expr) => { fuzz_target!($c); };
}
pass_through!(|d: &[u8]| { leaf_w!(); });
""")
    ids = _harness_ids(cg)
    assert len(ids) == 2, (
        f"expected the pass-through closure harness + the leaf harness, got {ids}")
    by_callees = {k: set(cg["call_graph"].get(k, ())) for k in ids}
    leaf = [k for k, c in by_callees.items()
            if any(x.endswith(".decode") for x in c)]
    assert leaf, f"the leaf harness's decode edge missing: {by_callees}"
    # the leaf harness reports ITS OWN definition's line — 3 in THIS
    # fixture (the triple-quote source carries a LEADING blank line, so the
    # leaf's rule sits on line 3), never a synth-relative or double-offset
    # value
    info = cg["functions"][leaf[0]]
    assert info["start_line"] == 3, (
        f"the leaf harness start_line {info['start_line']} is not its "
        "definition's line 3 — the marker path double-offsets")


def test_name_only_wrapper_chain_is_the_disclosed_limit(tmp_path):
    """The transitive-chain limit, pinned (the fable-r6 N1 catch): a wrapper
    whose rule body carries NO harness token of its own and only NAMES
    another local wrapper never starts a lift — 0 harnesses (the under-seed
    disclosed limit; the invocation-inside-a-lifted-closure form IS
    recognized, pinned by the nested-lines test)."""
    cg = _one(tmp_path, """
macro_rules! leaf_w {
    () => { fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); }); };
}
macro_rules! outer {
    () => { leaf_w!(); };
}
outer!();
""")
    assert _harness_ids(cg) == [], (
        "the name-only chain was followed — the disclosed limit moved; "
        "update the docstrings and this pin")


def test_import_before_local_precedence_is_the_disclosed_limit(tmp_path):
    """The import-first precedence, pinned (the fable-r6 N1 catch): a name
    that IMPORTS resolves through the import path and never consults the
    local map, even when a local macro_rules! of the same name exists —
    the under-seed direction for the pathological both-imported-and-local
    file (real Rust resolves the local textual definition first)."""
    cg = _one(tmp_path, """
use evil::thing as leaf_w;
macro_rules! leaf_w {
    () => { fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); }); };
}
leaf_w!();
""")
    assert _harness_ids(cg) == [], (
        "the local definition won over the import — the disclosed "
        "precedence moved; update the docstrings and this pin")


def test_self_recursive_wrapper_seeds_once(tmp_path):
    """The recursion-guard pin (the fable-r7 F1 catch): a wrapper invoking
    ITSELF inside its own closure seeds exactly ONE harness — the
    _lift_stack guard, designed, not interpreter-bounded."""
    cg = _one(tmp_path, """
macro_rules! rec {
    () => { fuzz_target!(|d: &[u8]| { rec!(); let _ = Frame::decode(d); }); };
}
rec!();
""")
    assert len(_harness_ids(cg)) == 1, (
        f"the self-recursive wrapper seeded {len(_harness_ids(cg))} — the "
        "recursion guard broke")


def test_mutually_recursive_wrappers_seed_each_body_once(tmp_path):
    cg = _one(tmp_path, """
macro_rules! a {
    () => { fuzz_target!(|d: &[u8]| { b!(); let _ = Frame::decode(d); }); };
}
macro_rules! b {
    () => { fuzz_target!(|d: &[u8]| { a!(); let _ = Frame::decode(d); }); };
}
a!();
""")
    ids = _harness_ids(cg)
    assert len(ids) == 2, (
        f"the mutual pair seeds each distinct closure once (got {len(ids)}: "
        f"{ids}) — the recursion guard broke")


def test_afl_tt_muncher_wrapper_seeds_once_per_invocation(tmp_path):
    """The idiomatic-AFL shape (a tt-muncher whose rule re-invokes itself):
    ONE harness per invocation site, never the pre-guard 330-unit explosion."""
    cg = _one(tmp_path, """
#[macro_use]
extern crate afl;
macro_rules! fuzz_all {
    ($first:expr $(, $rest:expr)*) => { fuzz!(|d: &[u8]| { $first(d); }); fuzz_all!($($rest),*); };
}
fuzz_all!(Frame::decode, Frame::decode, Frame::decode);
""")
    assert len(_harness_ids(cg)) == 1, (
        f"the tt-muncher seeded {len(_harness_ids(cg))} harnesses — the "
        "recursion guard broke")


def test_nested_wrapper_lines_are_file_absolute_at_every_level(tmp_path):
    """The fable-r3 B1-M6 pin: the wrapper-merge marker READ must survive —
    the mutant that always offsets re-breaks the nested case (the leaf
    double-offsets to 8+). Asserts both harnesses' lines land on their OWN
    definitions' lines at the file-absolute convention."""
    cg = _one(tmp_path, """
macro_rules! leaf_w {
    () => { fuzz_target!(|d: &[u8]| { struct LocalTy; let _: LocalTy = LocalTy; let _ = Frame::decode(d); }); };
}
macro_rules! outer_w {
    () => {
        fuzz_target!(|d: &[u8]| { leaf_w!(); let _ = Frame::decode(d); });
    };
}
outer_w!();
""")
    ids = _harness_ids(cg)
    assert len(ids) == 2, ids
    lines = {k: cg["functions"][k]["start_line"] for k in ids}
    # the leaf's closure is on line 3, the outer's on line 7 (this fixture
    # carries the leading blank line, so 1-based: leaf closure 3, outer
    # closure 7)
    assert sorted(lines.values()) == [3, 7], (
        f"the nested wrappers' lines {lines} are not their definitions' "
        "lines (3, 7) — the marker read double-offsets")
    # the fable-r4 F5-b pin: a harness-local TYPE inside the leaf closure
    # lands on ITS definition's line (3) at every wrapper depth — the class
    # marker must pass through the direct class loop too
    local = cg["classes"].get("LocalTy")
    assert local is not None, "the fixture's struct vanished from the classes table"
    assert local.get("start_line") == 3, (
        f"the harness-local LocalTy line {local.get('start_line')} is not "
        "its definition's line 3 — the class marker double-offsets")
    # the fable-r3 F4 pin (extended per the r5 F7 catch): the PRIVATE
    # merge-control marker never leaks into the public tables — neither the
    # functions NOR the classes (wrapped_macro_alias stays — informative)
    for k, v in cg["functions"].items():
        assert "_wrapped_lift_file_absolute" not in v, (
            f"the private marker leaked into the public functions table at {k}")
    for k, v in cg["classes"].items():
        assert "_wrapped_lift_file_absolute" not in v, (
            f"the private marker leaked into the public classes table at {k}")


def test_wrapper_with_own_closure_invoked_twice_with_args_lifts_once(tmp_path):
    """The fable-r3 B1-M7 pin: a wrapper carrying its OWN closure, invoked
    twice WITH closure args — each invocation's lift dedups to the body's
    closure; the dedup must COUNT as lifted (the mutant that drops the
    merged+=1 falls through and order-dependently seeds the invocation
    args as a second harness)."""
    cg = _one(tmp_path, """
macro_rules! w {
    () => { fuzz_target!(|d: &[u8]| { let _ = Frame::decode(d); }); };
}
w!(|x: &[u8]| { let _ = x; });
w!(|y: &[u8]| { let _ = y; });
""")
    ids = _harness_ids(cg)
    assert len(ids) == 1, (
        f"expected exactly the body-closure harness, got {ids} — the "
        "fall-through double-lifted the invocation args")


def test_line_offsets_land_on_the_macro_definition_lines(tmp_path):
    """The fable-F8 pin: the lifted unit's line numbers are the macro
    DEFINITION's real lines (the rule body embedded at synth line 0 + the
    rule's start line), never the invocation's, never synth-relative."""
    wrapper = """macro_rules! fuzz_entry {
    () => {
        fuzz_target!(|data: &[u8]| { let _ = Frame::decode(data); });
    };
}
"""
    cg = _one(tmp_path, wrapper + "\n\n\n\nfuzz_entry!();\n")
    ids = _harness_ids(cg)
    assert len(ids) == 1
    info = cg["functions"][ids[0]]
    # the closure body sits on wrapper line 3 EXACTLY (1-based; this local
    # `wrapper` fixture has NO leading blank line, unlike the module WRAPPER)
    # — the exact pin kills the zero-offset mutant (the fable-r2 M2 catch:
    # the loose 2..4 window admitted the mutant's line 2)
    assert info["start_line"] == 3, (
        f"the harness start_line {info['start_line']} is not the closure's "
        "real line 3 — the offset math broke")
    assert info["start_line"] > 0, "a synth-relative/negative line leaked"


def test_longer_fuzz_named_token_in_a_body_is_not_a_harness_form(tmp_path):
    """The \b-anchor pin, LOAD-BEARING form (the fable-r2 M4 catch): the
    plain fixture (the longer token in a direct body) was indistinguishable
    — the lift's real parse rejects it regardless. THIS fixture routes the
    body's match through the fall-through: a pass-through rule whose body
    names the LONGER token `my_fuzz_target!`, invoked WITH a closure — at
    HEAD the shape gate refuses (the word boundary holds) so nothing seeds;
    the dropped-\b mutant matches the body, the lift merges nothing, the
    fall-through seeds the invocation's closure — the pin kills it. Doubles
    as the S1 disclosure's honest direction: a LONGER token is never a
    harness form, even through the fall-through."""
    cg = _one(tmp_path, """
macro_rules! helper {
    ($c:expr) => { my_fuzz_target!($c); };
}
helper!(|d: &[u8]| { let _ = Frame::decode(d); });
""")
    assert _harness_ids(cg) == [], (
        "a longer fuzz-named token rode the substring through the "
        "fall-through — the \b anchor broke")
