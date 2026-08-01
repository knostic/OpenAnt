"""a nested fn's call sites must be attributed to the nested unit, not bled
into the OUTER fn (and resolved under the outer fn's — wrong — generic bounds).
`fn outer<B:Shape>(){ fn inner<B:Logger>(l:&B){ l.log() } ... }` must not create
`outer -> Circle.log` (Circle is Shape, not Logger). The inner unit keeps its edge."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, edges  # noqa: E402


def test_nested_fn_calls_not_bled_into_outer(tmp_path):
    repo = {"lib.rs": """
        pub trait Shape { fn area(&self); }
        pub trait Logger { fn log(&self); }
        pub struct Circle; impl Shape for Circle { fn area(&self){} } impl Circle { fn log(&self){} }
        pub fn outer<B: Shape>(s: &B) { fn inner<B: Logger>(l: &B) { l.log(); } s.area(); }
    """}
    e = edges(build(tmp_path, repo)[1])
    assert ("outer", "Circle.area") in e, e          # outer's real call survives
    assert ("outer", "Circle.log") not in e, e       # nested inner's call must NOT bleed to outer
