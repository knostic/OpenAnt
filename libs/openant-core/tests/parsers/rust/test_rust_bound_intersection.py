"""a multi-bound generic must not lose all edges when one bound trait has
no recorded conformers (marker/blanket/derive/cross-crate impls are invisible to
the extractor). An unseen conformer set is 'unconstrained', not 'empty' — it must
not annihilate the edges the other bounds establish (reachability over-approx)."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, edges  # noqa: E402


def test_multi_bound_survives_impl_less_marker(tmp_path):
    repo = {"lib.rs": """
        pub trait Shape { fn area(&self) -> f64; }
        pub struct Circle; impl Shape for Circle { fn area(&self) -> f64 { 1.0 } }
        pub struct Square; impl Shape for Square { fn area(&self) -> f64 { 2.0 } }
        pub trait Marker {}
        impl<X: Shape> Marker for X {}
        pub fn total<B: Shape + Marker>(b: &B) -> f64 { b.area() }
    """}
    e = edges(build(tmp_path, repo)[1])
    assert ("total", "Circle.area") in e, e
    assert ("total", "Square.area") in e, e
