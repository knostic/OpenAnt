"""a method receiver typed as an IMPL-level generic param (`impl<T: Shape>
Holder<T> { fn m(&self, x: &T) { x.area() } }`) must dispatch to the bound trait's
conformers -- same as a fn-level bound. Previously the impl-level bound was invisible
(only fn-level generics were read), so `x: T` fell to a bare-name lookup on the
letter `T`, which an unrelated blanket `impl<U: _> Audit for U` had poisoned with a
pseudo-type `T.area` -> phantom edge + the real conformer edge dropped."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import build, edges  # noqa: E402


def test_impl_level_bound_dispatches_to_conformers(tmp_path):
    repo = {"lib.rs": """
        pub trait Shape { fn area(&self) -> f64; }
        pub struct Circle; impl Shape for Circle { fn area(&self) -> f64 { 1.0 } }
        pub trait Debugx {}
        pub trait Audit { fn area(&self); }
        impl<U: Debugx> Audit for U { fn area(&self) {} }
        pub struct Holder<T> { x: T }
        impl<T: Shape> Holder<T> { pub fn measure(&self, x: &T) -> f64 { x.area() } }
    """}
    e = edges(build(tmp_path, repo)[1])
    assert ("Holder.measure", "Circle.area") in e, e     # real conformer edge recovered
    assert ("Holder.measure", "T.area") not in e, e      # blanket pseudo-type phantom gone
