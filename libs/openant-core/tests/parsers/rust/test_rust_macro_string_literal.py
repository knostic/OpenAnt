"""the macro token-tree regex scan must not harvest call-shaped text from
INSIDE string literals. `println!("call init() first")` must not fabricate an edge
to an unrelated `init`; real calls OUTSIDE the literal (`format!("{}", foo())`)
must still be recovered."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, edges  # noqa: E402


def test_no_phantom_from_call_shaped_string_literal(tmp_path):
    repo = {"lib.rs": 'pub fn connect() { panic!("not ready: call init() first"); }\npub fn init() {}\n'}
    e = edges(build(tmp_path, repo)[1])
    assert ("connect", "init") not in e, e


def test_real_call_outside_literal_still_recovered(tmp_path):
    repo = {"lib.rs": 'pub fn caller() { println!("{}", helper()); }\npub fn helper() -> i32 { 1 }\n'}
    e = edges(build(tmp_path, repo)[1])
    assert ("caller", "helper") in e, e
