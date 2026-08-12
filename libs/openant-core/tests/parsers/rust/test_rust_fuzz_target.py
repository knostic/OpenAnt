"""libFuzzer `fuzz_target!` harness extraction (F8).

The closure body of `fuzz_target!(|data| { .. })` is the real program entry
point but lives inside an opaque macro token_tree, so no `function_item` is
emitted and the decode calls it makes never enter the call graph. The parser
synthesizes an `is_entry_point`/`unit_type=main` unit carrying that body as
ordinary Rust so structural reachability seeds it. These tests lock in the
body-extraction (incl. the string/comment brace-safety that a naive text scan
gets wrong) and guard against over-triggering on non-fuzz macros.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import build, leaf  # noqa: E402

# A resolvable decode target so the harness edge can be asserted.
FRAME = """
pub struct Frame;
impl Frame {
    pub fn decode(d: &[u8]) -> Frame { Frame }
}
"""


def _harness(k, body):
    return {"src.rs": FRAME, f"fuzz/{k}.rs": f"fuzz_target!(|data: &[u8]| {body});\n"}


def _fuzz_ids(cg):
    # Multiple harnesses in one file get a `#N` collision suffix on the id.
    return [k for k in cg["functions"] if k.rsplit(":", 1)[-1].startswith("fuzz_target")]


def _callees(cg, fid):
    return [leaf(c) for c in cg["call_graph"].get(fid, [])]


def test_block_form_seeds_decode(tmp_path):
    _, cg = build(tmp_path, _harness("f", "{ let _ = Frame::decode(data); }"), skip_tests=False)
    ids = _fuzz_ids(cg)
    assert len(ids) == 1
    assert cg["functions"][ids[0]]["unit_type"] == "main"
    assert any("decode" in c for c in _callees(cg, ids[0]))


def test_string_and_comment_braces_do_not_truncate(tmp_path):
    # A `}` inside a comment and a string must not desync body extraction and
    # drop the trailing decode call (the naive text-scan regression).
    body = (
        '{\n'
        '    // a stray } inside a comment\n'
        '    let s = "closing } brace in a string";\n'
        '    let _ = Frame::decode(data);\n'
        '}'
    )
    _, cg = build(tmp_path, _harness("f", body), skip_tests=False)
    ids = _fuzz_ids(cg)
    assert ids, "no fuzz_target unit synthesized"
    assert "Frame::decode" in cg["functions"][ids[0]]["code"]
    assert any("decode" in c for c in _callees(cg, ids[0]))


def test_expr_form_no_block(tmp_path):
    # `fuzz_target!(|d| expr)` with no `{ }` body must still seed the call.
    _, cg = build(tmp_path, _harness("f", "Frame::decode(data)"), skip_tests=False)
    ids = _fuzz_ids(cg)
    assert ids, "expr-form harness produced no unit"
    assert any("decode" in c for c in _callees(cg, ids[0]))


def test_path_qualified_macro(tmp_path):
    files = {
        "src.rs": FRAME,
        "fuzz/f.rs": "libfuzzer_sys::fuzz_target!(|data: &[u8]| { let _ = Frame::decode(data); });\n",
    }
    _, cg = build(tmp_path, files, skip_tests=False)
    assert _fuzz_ids(cg), "path-qualified fuzz_target! not recognized"


def test_multiple_harnesses_one_file(tmp_path):
    src = (
        "fuzz_target!(|data: &[u8]| { let _ = Frame::decode(data); });\n"
        "fuzz_target!(|data: &[u8]| { let _ = Frame::decode(data); });\n"
    )
    _, cg = build(tmp_path, {"src.rs": FRAME, "fuzz/f.rs": src}, skip_tests=False)
    assert len(_fuzz_ids(cg)) == 2


def test_non_fuzz_macro_does_not_synthesize(tmp_path):
    # A normal macro invocation must not be mistaken for a harness.
    _, cg = build(tmp_path, {"src.rs": "fn g() { let v = vec![1, 2, 3]; }\n"}, skip_tests=False)
    assert not _fuzz_ids(cg)


def test_nested_fn_in_harness_no_phantom_no_loss(tmp_path):
    # A nested `fn decode` inside the closure, plus a cross-file global `fn decode`.
    # The bare `decode(data)` call MUST bind to the LOCAL nested fn (same-file), not
    # phantom-resolve to the unrelated global, AND the nested fn's own callee
    # (`local_only`) must stay reachable. Regression for the PR#205 Fix-E invariant
    # ("nested fn is its own unit, so no edge is lost") which flattening violated.
    repo = {
        "huffman.rs": "pub fn decode(x: &[u8]) -> u32 { 0 }\n",  # unrelated cross-file global
        "fuzz/h.rs": (
            "fuzz_target!(|data: &[u8]| {\n"
            "    fn decode(d: &[u8]) -> u32 { local_only(); 0 }\n"
            "    fn local_only() {}\n"
            "    let _ = decode(data);\n"
            "});\n"
        ),
    }
    _, cg = build(tmp_path, repo, skip_tests=False)
    all_edges = {(leaf(c), leaf(t)) for c, ts in cg["call_graph"].items() for t in ts}
    hid = _fuzz_ids(cg)[0]
    hleaf = leaf(hid)
    # (a) no phantom: the harness must NOT edge to the cross-file global huffman::decode
    assert ("huffman.rs" not in "".join(
        t for c, ts in cg["call_graph"].items() if leaf(c) == hleaf for t in ts
    )), f"phantom edge to cross-file global decode: {cg['call_graph'].get(hid)}"
    # (b) no reachability loss: local_only (only reachable via the nested decode)
    # stays in the graph — as its own same-file unit `fuzz_target::local_only`.
    assert any("local_only" in callee for _, callee in all_edges), \
        f"reachability lost: local_only orphaned; edges={sorted(all_edges)}"
    # (c) the nested decode is its OWN unit (restores PR#205 Fix-E precondition)
    assert any(leaf(f).endswith("::decode") for f in cg["functions"]), \
        f"nested fn not extracted as a unit; units={[leaf(f) for f in cg['functions']]}"


def test_harness_factoring_logic_into_local_fn_reaches_target(tmp_path):
    # A harness that factors ALL its logic into a local `fn` reached 0 edges under
    # the flat lift (nested fn invisible → outer `run(d)` resolves to nothing).
    # After same-file extraction the decode target is reachable via the chain.
    repo = {
        "src.rs": "pub struct Frame; impl Frame { pub fn decode(d: &[u8]) {} }\n",
        "fuzz/h.rs": "fuzz_target!(|d: &[u8]| { fn run(x: &[u8]) { Frame::decode(x); } run(d); });\n",
    }
    _, cg = build(tmp_path, repo, skip_tests=False)
    all_edges = {(leaf(c), leaf(t)) for c, ts in cg["call_graph"].items() for t in ts}
    assert any(callee.endswith("::run") for _, callee in all_edges), all_edges
    assert any("decode" in callee for _, callee in all_edges), \
        f"decode unreachable from harness→local fn chain; edges={sorted(all_edges)}"


def test_synthetic_harness_is_marked(tmp_path):
    # The harness unit carries the `synthetic_harness` tag (used downstream to
    # special-case it — e.g. exclude from the blackout structural-seed count).
    _, cg = build(tmp_path, _harness("f", "{ let _ = 1; }"), skip_tests=False)
    hid = _fuzz_ids(cg)[0]
    assert cg["functions"][hid].get("synthetic_harness") is True


def _apply_reachability(cg, repo_path):
    import importlib
    return importlib.import_module(
        "parsers.rust.test_pipeline"
    ).apply_reachability_filter(cg, str(repo_path))


def test_pure_fuzz_only_library_keeps_safety_net(tmp_path):
    # A pure-library-with-fuzz target (only fuzz harnesses, no real main/route/CLI)
    # must NOT silently filter down to the harness-reachable set — the library's
    # real API is often macro-hidden from the call graph (httparse `complete!`),
    # so dropping everything the harness doesn't reach is a silent coverage loss.
    # Synthetic harnesses seed the BFS but are NOT real structural entry points,
    # so the keep-all blackout safety net must still fire.
    repo = {
        "lib.rs": (
            "pub fn unreached_public_api() {}\n"
            "pub struct T; impl T { pub fn parse(d: &[u8]) {} }\n"
        ),
        "fuzz/h.rs": "fuzz_target!(|d: &[u8]| { T::parse(d); });\n",
    }
    _, cg = build(tmp_path, repo, skip_tests=False)
    kept = set(_apply_reachability(cg, tmp_path)["functions"].keys())
    assert any(leaf(k) == "unreached_public_api" for k in kept), \
        f"pure-fuzz-only library silently dropped un-reached public API; kept={sorted(leaf(k) for k in kept)}"


def test_nested_harness_struct_does_not_clobber_real_type(tmp_path):
    # A harness that declares a `struct` re-using a real crate type's name must
    # NOT overwrite the real type's `classes` entry (bare-name keyed). The real
    # definition (file/line/code) must survive.
    repo = {
        "src.rs": "pub struct Cfg { pub real_field: u32 }\nimpl Cfg { pub fn run(&self) {} }\n",
        "z_fuzz/h.rs": "fuzz_target!(|d: &[u8]| { struct Cfg { bogus: u8 } let _ = Cfg { bogus: 0 }; });\n",
    }
    _, cg = build(tmp_path, repo, skip_tests=False)
    cfg = cg.get("classes", {}).get("Cfg", {})
    assert cfg.get("file_path") == "src.rs", f"real Cfg clobbered by harness struct: {cfg}"
    assert "bogus" not in str(cfg.get("code", "")), f"real Cfg code overwritten: {cfg}"


def test_hybrid_lib_with_bin_still_filters(tmp_path):
    # A hybrid target (a real `fn main` bin + fuzz harnesses) keeps real structural
    # seeds, so the keep-all net does NOT fire and reachability still prunes — the
    # neqo case. An unreachable helper must be filtered out.
    repo = {
        "lib.rs": (
            "pub fn dead_helper() {}\n"
            "pub struct T; impl T { pub fn parse(d: &[u8]) {} }\n"
        ),
        "src/bin/cli.rs": "fn main() { let _ = 1; }\n",
        "fuzz/h.rs": "fuzz_target!(|d: &[u8]| { T::parse(d); });\n",
    }
    _, cg = build(tmp_path, repo, skip_tests=False)
    kept = {leaf(k) for k in _apply_reachability(cg, tmp_path)["functions"].keys()}
    assert "dead_helper" not in kept, f"hybrid target failed to prune; kept={sorted(kept)}"
