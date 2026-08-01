"""`let x = Type::assoc()` should type `x` by the assoc fn's ACTUAL return
type, not the blanket assumption that `Type::assoc()` returns `Type`. `Factory::
make() -> Widget` must type the binding as Widget (recovering `w.process()` ->
Widget.process and NOT fabricating Factory.process). The dominant `Type::new() ->
Self` idiom must still resolve to Type."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, edges  # noqa: E402


def test_factory_return_type_used_for_receiver(tmp_path):
    repo = {"lib.rs": """
        pub struct Widget; impl Widget { pub fn process(&self) {} }
        pub struct Factory; impl Factory { pub fn make() -> Widget { Widget } pub fn process(&self) {} }
        pub fn run() { let w = Factory::make(); w.process(); }
    """}
    e = edges(build(tmp_path, repo)[1])
    assert ("run", "Widget.process") in e, e        # real: w is a Widget
    assert ("run", "Factory.process") not in e, e   # phantom: w is NOT a Factory


def test_new_returns_self_still_resolves(tmp_path):
    # the dominant constructor idiom (Type::new() -> Self) must keep working.
    repo = {"lib.rs": """
        pub struct Point; impl Point { pub fn new() -> Self { Point } pub fn dist(&self) -> f64 { 0.0 } }
        pub fn run() { let p = Point::new(); p.dist(); }
    """}
    assert ("run", "Point.dist") in edges(build(tmp_path, repo)[1])
