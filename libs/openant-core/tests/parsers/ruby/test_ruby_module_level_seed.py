"""Bug B12 (Ruby): file-scope top-level script code must be emitted as a
`module_level` unit so it is a call-graph node and an entry-point seed.

A Ruby script whose top level runs `name = ARGV[0]; process_input(name)` (no
enclosing class/module) is executable code that reads untrusted input (ARGV)
and dispatches into a helper. The Ruby function extractor only emitted `def`
methods, so this file-scope code was NEITHER a unit NOR a call-graph node:
`process_input` had no reachable caller and entry_point_detector Check-4
(unit_type == 'module_level' with an input pattern) had nothing to seed.

Mirror the Python/PHP extractors: emit the top-level statements as a synthetic
`__module__` unit with unit_type='module_level', carrying the ARGV/$stdin code,
so the call-graph builder wires its calls and the detector can seed it.
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[3]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def _load(unique_name, relpath):
    spec = importlib.util.spec_from_file_location(unique_name, str(CORE / relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_fe = _load("ruby_function_extractor_b12", "parsers/ruby/function_extractor.py")
_cgb = _load("ruby_call_graph_builder_b12", "parsers/ruby/call_graph_builder.py")
FunctionExtractor = _fe.FunctionExtractor
CallGraphBuilder = _cgb.CallGraphBuilder


def _build(files):
    d = tempfile.mkdtemp()
    for name, code in files.items():
        with open(os.path.join(d, name), "w") as fh:
            fh.write(code)
    extractor = FunctionExtractor(d)
    result = extractor.extract_all(list(files.keys()))
    builder = CallGraphBuilder(result)
    builder.build_call_graph()
    return result, builder


SCRIPT = (
    "name = ARGV[0]\n"
    "process_input(name)\n"
    "def process_input(x)\n"
    "  system(x)\n"
    "end\n"
)


def test_file_scope_script_is_module_level_unit_and_reaches_helper():
    result, builder = _build({"script.rb": SCRIPT})

    # (1) A module_level unit exists whose code carries ARGV.
    module_units = [
        (fid, d)
        for fid, d in result["functions"].items()
        if d.get("unit_type") == "module_level"
    ]
    assert module_units, (
        "expected a module_level unit for file-scope script code; got unit types "
        f"{[d.get('unit_type') for d in result['functions'].values()]}"
    )
    mod_id, mod_data = module_units[0]
    assert "ARGV" in mod_data.get("code", ""), (
        f"module_level unit code must carry ARGV; got {mod_data.get('code')!r}"
    )

    # (2) process_input is reachable from the module_level unit.
    proc_id = "script.rb:process_input"
    assert proc_id in result["functions"], list(result["functions"])
    reachable = builder.get_dependencies(mod_id)
    assert proc_id in reachable, (
        f"process_input must be reachable from the module_level unit; "
        f"deps={reachable}, edges={builder.call_graph.get(mod_id)}"
    )


def test_module_level_script_is_seeded_as_entry_point():
    """The emitted module_level unit must actually be SEEDED by the detector
    (Check-4: unit_type=='module_level' carrying a user-input pattern) — else the
    ARGV -> system(x) sink stays unreachable from any taint entry point."""
    from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector

    result, builder = _build({"script.rb": SCRIPT})
    mod_id = next(
        fid for fid, d in result["functions"].items()
        if d.get("unit_type") == "module_level"
    )
    detector = EntryPointDetector(result["functions"], builder.call_graph)
    entry_points = detector.detect_entry_points()
    assert mod_id in entry_points, (
        "the module_level unit reading ARGV must be seeded as an entry point; "
        f"reasons={detector.entry_point_details.get(mod_id)}"
    )


def test_method_reading_argv_behind_main_guard_is_seeded():
    """The dominant Ruby CLI shape: ARGV read inside a method invoked from an
    `if __FILE__ == $0` guard. The sink lives in a `function` unit, so ARGV must
    seed via Check-3 (USER_INPUT_PATTERNS) — the module-level guard itself has no
    input pattern to seed on. Parity with the Python main-guard (sys.argv)."""
    from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector

    script = (
        "def run\n"
        "  system(ARGV[0])\n"
        "end\n"
        "if __FILE__ == $0\n"
        "  run\n"
        "end\n"
    )
    result, builder = _build({"cli.rb": script})
    detector = EntryPointDetector(result["functions"], builder.call_graph)
    entry_points = detector.detect_entry_points()
    run_id = "cli.rb:run"
    assert run_id in result["functions"], list(result["functions"])
    assert run_id in entry_points, (
        "a method reading ARGV must be seeded even when the ARGV read is behind a "
        f"main-guard method; reasons={detector.entry_point_details.get(run_id)}, all={entry_points}"
    )
