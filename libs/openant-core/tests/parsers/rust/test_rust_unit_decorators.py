"""Bug J: Rust unit metadata must carry `decorators` (parity with the Swift parser),
so dataset units expose the function's attributes like every sibling parser."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import extract, CallGraphBuilder, UnitGenerator  # noqa: E402


def test_unit_metadata_carries_decorators(tmp_path):
    ext = extract(tmp_path, {"lib.rs": "#[inline]\npub fn f() {}\n"})
    cg = CallGraphBuilder(ext).build()
    dataset, _ = UnitGenerator(cg, str(tmp_path)).generate()
    units = dataset["units"]
    assert units, "no units generated"
    for u in units:
        assert "decorators" in u["metadata"], u["metadata"].keys()
    # the #[inline] attribute must survive into unit metadata (not just call_graph)
    assert any(u["metadata"]["decorators"] == ["inline"] for u in units), \
        [u["metadata"]["decorators"] for u in units]
