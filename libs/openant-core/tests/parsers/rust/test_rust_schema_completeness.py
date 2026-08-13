"""B-schema (extractor -> unit field contract) for Rust.

Guards the producer/consumer field-drift family: a field the extractor produces
must survive into the generated unit / analyzer_output, machine-checked so a
future field addition that forgets to thread through fails loudly. Mirrors the
swift/zig schema-completeness tests.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import extract, CallGraphBuilder, UnitGenerator  # noqa: E402

_SRC = {
    "widget.rs": """
        pub struct Widget { id: i32 }
        impl Widget {
            pub fn new(id: i32) -> Self { Widget { id } }
            pub fn render(&self) -> i32 { self.compute() }
            fn compute(&self) -> i32 { 0 }
        }
    """
}


def _run(tmp_path):
    ext = extract(tmp_path, _SRC)
    cg = CallGraphBuilder(ext).build()
    dataset, analyzer = UnitGenerator(cg, str(tmp_path)).generate(name="s")
    return ext, dataset, analyzer


def test_every_extracted_function_has_a_unit(tmp_path):
    ext, dataset, _ = _run(tmp_path)
    unit_ids = {u["id"] for u in dataset["units"]}
    assert unit_ids == set(ext["functions"].keys())


def test_unit_required_fields_present(tmp_path):
    _, dataset, _ = _run(tmp_path)
    for u in dataset["units"]:
        assert "id" in u and "unit_type" in u
        origin = u["code"]["primary_origin"]
        for key in ("file_path", "start_line", "end_line", "function_name", "class_name"):
            assert key in origin, f"missing {key} in primary_origin of {u['id']}"
        assert "dependency_metadata" in u["code"]


def test_analyzer_output_camelcase_and_isexported_roundtrip(tmp_path):
    ext, _, analyzer = _run(tmp_path)
    for fid, af in analyzer["functions"].items():
        for key in ("name", "unitType", "code", "filePath", "startLine",
                    "endLine", "isExported", "parameters", "className"):
            assert key in af, f"analyzer function {fid} missing {key}"
        # isExported must be carried from the extractor's is_exported, NOT
        # recomputed from a code-prefix heuristic downstream.
        assert af["isExported"] == bool(ext["functions"][fid]["is_exported"])

    # the public API surface is actually flagged exported; the private fn is not
    exported = {fid.split(":", 1)[1] for fid, af in analyzer["functions"].items() if af["isExported"]}
    assert "Widget.render" in exported
    assert "Widget.compute" not in exported
