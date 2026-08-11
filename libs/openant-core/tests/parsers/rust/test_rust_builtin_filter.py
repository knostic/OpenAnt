"""RUST_BUILTINS filter must not drop TYPED/resolvable method-call edges.

A method call whose method name happens to be in RUST_BUILTINS (get/parse/new/...)
on a KNOWN receiver type must still resolve — the builtin guard is a precision knob
for the UNKNOWN-receiver fallback only (see _resolve_unknown_receiver_method), not a
reason to delete a fully-resolvable typed method edge at extraction time.
"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import build, edges  # noqa: E402


def test_typed_cross_file_builtin_named_method_resolves(tmp_path):
    repo = {
        "a.rs": "pub struct Cache;\nimpl Cache { pub fn get(&self) -> i32 { secret() } }\nfn secret() -> i32 { 1 }\n",
        "b.rs": "use crate::a::Cache;\npub fn run(c: &Cache) -> i32 { c.get() }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    # 'get' is in RUST_BUILTINS but the receiver is typed (&Cache) and Cache::get is
    # unambiguous -> the edge MUST exist (previously dropped by the pre-resolution filter).
    assert ("run", "Cache.get") in e, e


def test_bare_builtin_named_free_fn_resolves(tmp_path):
    # a bare call to a free fn named like a builtin ('parse') is a real edge.
    repo = {
        "a.rs": "pub fn parse() -> i32 { 1 }\n",
        "b.rs": "use crate::a::parse;\npub fn run() -> i32 { parse() }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("run", "parse") in e, e
