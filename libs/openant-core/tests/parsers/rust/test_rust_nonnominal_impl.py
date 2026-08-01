"""trait/inherent impls on non-nominal Self types (primitive/array/tuple/
unit) must still have their methods extracted. `_bare_type_name` names only nominal
types, so `impl Serialize for u32` was dropped entirely (every method lost)."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import extract  # noqa: E402


def test_nonnominal_self_impls_extracted(tmp_path):
    ext = extract(tmp_path, {"a.rs": """
        pub trait Enc { fn enc(&self); }
        impl Enc for u32 { fn enc(&self) {} }
        impl Enc for [u8; 4] { fn enc(&self) {} }
        impl Enc for (i32, i32) { fn enc(&self) {} }
        pub struct Ok1; impl Enc for Ok1 { fn enc(&self) {} }
    """})
    encs = [f for f in ext["functions"].values() if f["name"] == "enc"]
    assert len(encs) == 4, sorted(f["class_name"] for f in encs)
