"""the macro token-tree regex scan must not harvest call-shaped text from
INSIDE string literals. `println!("call init() first")` must not fabricate an edge
to an unrelated `init`; real calls OUTSIDE the literal (`format!("{}", foo())`)
must still be recovered."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import build, edges  # noqa: E402


def test_no_phantom_from_call_shaped_string_literal(tmp_path):
    repo = {"lib.rs": 'pub fn connect() { panic!("not ready: call init() first"); }\npub fn init() {}\n'}
    e = edges(build(tmp_path, repo)[1])
    assert ("connect", "init") not in e, e


def test_real_call_outside_literal_still_recovered(tmp_path):
    repo = {"lib.rs": 'pub fn caller() { println!("{}", helper()); }\npub fn helper() -> i32 { 1 }\n'}
    e = edges(build(tmp_path, repo)[1])
    assert ("caller", "helper") in e, e


def test_macro_wrapped_scoped_call_recovered_cross_file(tmp_path):
    # A `Type::method(` call inside a scannable macro must recover the SCOPED
    # call so a cross-file associated fn resolves (the AST walk gets this for
    # free; the macro-body scanner used to drop the qualifier and degrade to a
    # bare same-file-only `method`, which fails cross-file). General, not
    # harness-specific — the same gap that silently no-op'd fuzz-harness seeding.
    repo = {
        "caller.rs": "pub fn caller(d: &[u8]) { assert!(Codec::roundtrip(d)); }\n",
        "codec.rs": "pub struct Codec;\nimpl Codec { pub fn roundtrip(d: &[u8]) -> bool { true } }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("caller", "Codec.roundtrip") in e, e


def test_macro_wrapped_bare_call_still_bare(tmp_path):
    # Regression guard: a non-scoped bare call in a macro must STILL be
    # recovered as before (the scoped alternation must not shadow bare calls).
    repo = {"lib.rs": 'pub fn caller() { assert_eq!(helper(), 1); }\npub fn helper() -> i32 { 1 }\n'}
    e = edges(build(tmp_path, repo)[1])
    assert ("caller", "helper") in e, e
