"""Generic trait-bound dispatch for Rust (val_3_19 extension).

A call on a receiver whose type is a generic parameter bounded by a trait
(`fn f<B: Shape>(x: &B) { x.area() }` / `where B: Shape`) must dispatch to the
trait's conformers via the SAME `trait_impls` closure already used for
`&dyn Trait` receivers -- not decline. Nominal typing makes the conformer set
knowable and bounded, so this is a reachability-safe over-approximation, not a
guess. Mirrors the Swift parser's protocol-conformer dispatch (the reference
implementation this brings Rust to parity with).
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, edges  # noqa: E402


def test_inline_bound_dispatches_to_conformers(tmp_path):
    repo = {
        "lib.rs": """
            pub trait Shape { fn area(&self) -> f64; }
            pub struct Circle; impl Shape for Circle { fn area(&self) -> f64 { 3.14 } }
            pub struct Square; impl Shape for Square { fn area(&self) -> f64 { 4.0 } }
            pub fn print_area<B: Shape>(item: &B) -> f64 { item.area() }
        """
    }
    _, cg = build(tmp_path, repo)
    e = edges(cg)
    # the generic receiver `item: &B` where `B: Shape` must reach BOTH conformers
    assert ("print_area", "Circle.area") in e, e
    assert ("print_area", "Square.area") in e, e


def test_where_clause_bound_dispatches(tmp_path):
    repo = {
        "lib.rs": """
            pub trait Greet { fn hello(&self) -> i32; }
            pub struct Dog; impl Greet for Dog { fn hello(&self) -> i32 { 1 } }
            pub fn run<G>(g: &G) -> i32 where G: Greet { g.hello() }
        """
    }
    _, cg = build(tmp_path, repo)
    assert ("run", "Dog.hello") in edges(cg)


def test_bound_dispatch_excludes_non_conformers(tmp_path):
    # A non-conformer with a same-named method must NOT get a false edge.
    repo = {
        "lib.rs": """
            pub trait Shape { fn area(&self) -> f64; }
            pub struct Circle; impl Shape for Circle { fn area(&self) -> f64 { 1.0 } }
            pub struct Rect;   impl Rect { fn area(&self) -> f64 { 2.0 } }   // NOT Shape
            pub fn measure<B: Shape>(b: &B) -> f64 { b.area() }
        """
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("measure", "Circle.area") in e, e
    assert ("measure", "Rect.area") not in e, e   # precision: bounded to conformers


def test_blanket_impl_does_not_poison_generic_param(tmp_path):
    # `impl<T: Foo> Bar for T` registers a pseudo-type "T"; a generic receiver
    # named T in an UNRELATED function must NOT hijack to that blanket body.
    repo = {
        "lib.rs": """
            pub trait Foo {}
            pub trait Bar { fn m(&self); }
            impl<T: Foo> Bar for T { fn m(&self) {} }
            pub trait Qux {}
            pub struct Gadget; impl Qux for Gadget {} impl Gadget { fn m(&self) {} }
            pub fn victim<T: Qux>(y: &T) { y.m() }
        """
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("victim", "Gadget.m") in e, e
    assert ("victim", "T.m") not in e, e   # no blanket-pseudo-type leak


def test_multi_bound_uses_conformer_intersection(tmp_path):
    # `B: Shape + Draw` -> x's type implements BOTH, so only the intersection of
    # conformers is possible; a Shape-only type with a same-named method is a
    # phantom, and a Draw-only type is also excluded.
    repo = {
        "lib.rs": """
            pub trait Shape {}
            pub trait Draw { fn render(&self); }
            pub struct Rect;   impl Shape for Rect {} impl Draw for Rect { fn render(&self) {} }
            pub struct Circle; impl Draw for Circle { fn render(&self) {} }   // Draw only
            pub struct Sq;     impl Shape for Sq {} impl Sq { fn render(&self) {} }  // Shape only
            pub fn call_render<B: Shape + Draw>(x: &B) { x.render() }
        """
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("call_render", "Rect.render") in e, e       # the only Shape+Draw type
    assert ("call_render", "Sq.render") not in e, e     # Shape-only -> phantom
    assert ("call_render", "Circle.render") not in e, e # Draw-only -> not in intersection


def test_nested_generic_item_does_not_bleed_bounds(tmp_path):
    repo = {
        "lib.rs": """
            pub trait ShapeX { fn measure(&self); }
            pub trait DrawX  { fn measure(&self); }
            pub struct RX; impl ShapeX for RX { fn measure(&self) {} }
            pub struct CX; impl DrawX  for CX { fn measure(&self) {} }
            pub fn outer<B: ShapeX>(x: &B) {
                fn inner<B: DrawX>(y: &B) { y.measure() }
                x.measure()
            }
        """
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("outer", "RX.measure") in e, e       # outer's B is ShapeX
    assert ("outer", "CX.measure") not in e, e   # inner's B: DrawX must not bleed
