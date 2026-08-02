"""Regressions from return-type inference: it must DECLINE (not guess) when the
producer is ambiguous or locally shadowed, otherwise it fabricates a wrong-type edge."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import build, edges  # noqa: E402


def test_assoc_return_ambiguous_duplicate_type_declines(tmp_path):
    # Two types both named Factory with different-return make(): don't guess one.
    repo = {
        "f1.rs": "pub struct Widget; impl Widget { pub fn spin(&self) {} }\n"
                 "pub struct Factory; impl Factory { pub fn make() -> Widget { Widget } }\n",
        "f2.rs": "pub struct Gear; impl Gear { pub fn spin(&self) {} }\n"
                 "pub struct Factory; impl Factory { pub fn make() -> Gear { Gear } }\n",
        "main.rs": "use crate::f2::Factory;\npub fn caller() { let x = Factory::make(); x.spin(); }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("caller", "Widget.spin") not in e, e   # must NOT guess f1's Widget
    assert ("caller", "Gear.spin") not in e, e      # can't know it's f2's Gear either -> decline both


def test_free_fn_return_local_closure_shadow_declines(tmp_path):
    repo = {
        "cfg.rs": "pub struct Cfg; impl Cfg { pub fn spin(&self) {} }\npub fn helper() -> Cfg { Cfg }\n",
        "w.rs": "pub struct Widget; impl Widget { pub fn new() -> Widget { Widget } pub fn spin(&self) {} }\n",
        "main.rs": "use crate::w::Widget;\npub fn caller() { let helper = || Widget::new(); let x = helper(); x.spin(); }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("caller", "Cfg.spin") not in e, e       # helper is a local closure, NOT the free fn


def test_std_imported_name_does_not_link_to_repo_namesake(tmp_path):
    # `use std::thread::spawn` makes bare `spawn()` a std call, NOT the repo `fn spawn`.
    repo = {
        "workers.rs": "pub fn spawn(n: i32) -> i32 { n }\n",
        "main.rs": "use std::thread::spawn;\npub fn run_thread() { let h = spawn(); }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("run_thread", "spawn") not in e, e


def test_crate_imported_name_still_links_to_repo_fn(tmp_path):
    # Control: a genuine repo import must STILL resolve (no over-decline / recall loss).
    repo = {
        "workers.rs": "pub fn spawn(n: i32) -> i32 { n }\n",
        "main.rs": "use crate::workers::spawn;\npub fn run_thread() { let h = spawn(1); }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("run_thread", "spawn") in e, e


def test_free_fn_return_survives_noncallable_name_reuse(tmp_path):
    # `let load = 5` reuses the name but is not callable -- must NOT block typing
    # `let c = load()` from the free fn. Decoy Other::method forces receiver typing.
    repo = {
        "lib.rs": "pub struct Cfg; impl Cfg { pub fn method(&self) {} }\n"
                  "pub struct Other; impl Other { pub fn method(&self) {} }\n"
                  "pub fn load() -> Cfg { Cfg }\n",
        "caller.rs": "fn go() { let c = load(); c.method(); let load = 5; let _ = load + 1; }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("go", "Cfg.method") in e, e


def test_repo_import_survives_coexisting_std_import_other_scope(tmp_path):
    # mod b legitimately `use crate::worker::take`; mod a's std import must not
    # poison it (imports are file-scoped).
    repo = {
        "worker.rs": "pub fn take() -> i32 { 0 }\n",
        "caller.rs": "mod a { use std::mem::take; pub fn f() { let mut v = vec![1]; let _ = take(&mut v); } }\n"
                     "mod b { use crate::worker::take; pub fn g() { take(); } }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("b::g", "take") in e, e
