"""Schema-completeness / field-contract guard for the PHP parser.

The PHP function_extractor (PRODUCER) emits a per-function ``func_data`` dict;
the unit_generator (CONSUMER, ``create_unit``) must surface the
analysis-relevant keys at their mapped location in the assembled unit. A
*key-drift* (consumer reads a different key name than the producer writes) or
a *dropped field* (producer writes it, consumer never copies it) silently
degrades the dataset -- exactly the failure mode of [BUG 28]/[BUG 43].

This test runs the real pipeline on a representative PHP source that exercises
every relevant field, then asserts -- per an explicit CONTRACT map -- that each
produced field reaches its mapped unit location with the produced value. It is
a small reusable drift-catcher: add a new producer field + its mapping here and
it will fail until ``create_unit`` carries it through.
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder
from parsers.php.unit_generator import UnitGenerator


# Source exercising: namespace (braced, so the extractor propagates it),
# a static method, a non-static public method, and parameters.
_SOURCE = (
    "<?php\n"
    "namespace App\\Foo {\n"
    "  class C {\n"
    "    public static function s($a, $b) { return 1; }\n"
    "    private function p() { return 2; }\n"
    "  }\n"
    "}\n"
)


def _run_pipeline(php_source: str, filename: str = "m.php"):
    repo = tempfile.mkdtemp()
    Path(repo, filename).write_text(php_source)
    extractor_output = FunctionExtractor(repo).extract_all([filename])
    builder = CallGraphBuilder(extractor_output)
    builder.build_call_graph()
    result = UnitGenerator(builder.export()).generate_units()
    units = {u["id"]: u for u in result["units"]}
    return extractor_output["functions"], units


# CONTRACT: producer key -> how to read the mapped value off the assembled unit.
# Each entry is (extractor_func_data_key, unit_location_reader). Extend this map
# whenever the extractor grows an analysis-relevant field that the unit exposes.
_CONTRACT = {
    "name": lambda u: u["code"]["primary_origin"]["function_name"],
    "class_name": lambda u: u["code"]["primary_origin"]["class_name"],
    "unit_type": lambda u: u["unit_type"],
    "start_line": lambda u: u["code"]["primary_origin"]["start_line"],
    "end_line": lambda u: u["code"]["primary_origin"]["end_line"],
    "parameters": lambda u: u["metadata"]["parameters"],
    # The two field-drift legs this guard exists for:
    "namespace_name": lambda u: u["metadata"]["namespace"],  # BUG 43
    "is_static": lambda u: u["metadata"]["is_static"],        # BUG 28
}


def test_extractor_to_unit_field_contract():
    """Every contracted producer field must reach its mapped unit location."""
    functions, units = _run_pipeline(_SOURCE)
    assert functions, "extractor produced no functions"

    failures = []
    for func_id, func_data in functions.items():
        unit = units.get(func_id)
        assert unit is not None, f"no unit generated for {func_id}"
        for producer_key, reader in _CONTRACT.items():
            produced = func_data.get(producer_key)
            exposed = reader(unit)
            if exposed != produced:
                failures.append(
                    f"{func_id}: key {producer_key!r} produced={produced!r} "
                    f"but unit exposes {exposed!r}"
                )

    assert not failures, "Field-contract drift detected:\n  " + "\n  ".join(failures)


def test_visibility_is_a_known_producer_gap():
    """KNOWN PRODUCER GAP (out of scope here, recorded as a regression marker).

    The extractor computes ``_get_visibility`` but ``_process_function_node``
    never stores a ``visibility`` key in ``func_data``; the unit_generator then
    fabricates a default ``'public'`` via ``func_data.get('visibility',
    'public')``. So a ``private`` method is reported as ``public``. This is a
    PRODUCER omission (function_extractor.py), distinct from the two CONSUMER
    field-drift bugs fixed in this run -- left for a separate fix. When the
    extractor starts emitting ``visibility``, this test will fail, prompting a
    move of ``visibility`` into the ``_CONTRACT`` map above.
    """
    functions, units = _run_pipeline(_SOURCE)
    # The private method's true visibility is 'private', but the producer never
    # emits the key, so the unit currently mis-reports it as the default.
    priv = units["m.php:C.p"]
    assert "visibility" not in functions["m.php:C.p"], (
        "Extractor now emits 'visibility' -- promote it into _CONTRACT and "
        "drop this gap marker."
    )
    assert priv["metadata"]["visibility"] == "public", (
        "Unit still defaults visibility; gap unchanged."
    )


def test_static_and_namespace_present_in_contract():
    """Self-check: the two bug-driven keys are actually in the contract map.

    Guards against someone silently deleting the drift-prone entries and
    leaving a green-but-toothless test.
    """
    assert "is_static" in _CONTRACT
    assert "namespace_name" in _CONTRACT
