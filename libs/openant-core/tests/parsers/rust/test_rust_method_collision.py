"""two same-named methods on one type (the ubiquitous `impl Display for P`
+ `impl Debug for P`, both `fn fmt`) must both be extracted. Previously both mapped
to func_id `file:P.fmt` and the second silently clobbered the first (data loss:
a whole unit vanished from the graph and reachability)."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import extract  # noqa: E402


def test_same_name_methods_both_extracted(tmp_path):
    ext = extract(tmp_path, {"a.rs": """
        pub struct P;
        impl std::fmt::Display for P { fn fmt(&self) {} }
        impl std::fmt::Debug for P { fn fmt(&self) {} }
    """})
    fmts = [f for f in ext["functions"].values() if f["name"] == "fmt" and f["class_name"] == "P"]
    assert len(fmts) == 2, [f["qualified_name"] for f in fmts]


def test_inherent_plus_trait_same_name_both_extracted(tmp_path):
    ext = extract(tmp_path, {"a.rs": """
        pub trait Draw { fn render(&self); }
        pub struct W;
        impl W { fn render(&self) -> i32 { 1 } }
        impl Draw for W { fn render(&self) {} }
    """})
    renders = [f for f in ext["functions"].values() if f["name"] == "render" and f["class_name"] == "W"]
    assert len(renders) == 2, [f["qualified_name"] for f in renders]
