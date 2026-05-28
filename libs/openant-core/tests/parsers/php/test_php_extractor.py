"""Regression tests for the PHP function extractor + entry-point detector.

Covers three confirmed defects:

  * Procedural top-level blackout:
    parsers/php/function_extractor.py only emits units for
    function/method/class/interface/trait/namespace nodes; top-level
    procedural statements (assignments, echo, hook registrations) fall
    through the catch-all else branch and produce NO unit. The Python
    parser has a module-level synthesizer (extract_module_level_code ->
    unit_type='module_level'); PHP had none, so a WordPress-style
    plugin.php is invisible to reachability seeding.

  * Entry-point seeding for PHP:
    utilities/agentic_enhancer/entry_point_detector.py USER_INPUT_PATTERNS
    and MODULE_LEVEL_INPUT_PATTERNS were Python/JS-only; no PHP superglobal
    ($_GET/$_POST/$_REQUEST/...) was ever recognised, so a PHP handler that
    reads $_POST was never flagged as an entry point.

  * Closures not modeled as units:
    anonymous_function and arrow_function nodes fell through the same else
    branch, so closures and arrow functions were never extracted as units.

NOTE on import strategy: ``function_extractor.py`` is a basename shared by
every parser (php/python/go/...), so a bare ``import function_extractor``
would collide. Each module is loaded under a UNIQUE name via
``importlib.util.spec_from_file_location``.

The call-graph dispatch portions (closure dispatch edges, WordPress
do_action edges, XML-RPC dispatch, alias->FQN resolution) live in
parsers/php/call_graph_builder.py, which is out of this unit's file scope;
they are covered/tracked elsewhere. These tests assert only the
extraction-layer + entry-point-seeding behavior owned by this unit.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_unique(rel_path: str, unique_name: str):
    """Load a module from libs/openant-core/<rel_path> under a unique name.

    function_extractor.py recurs across parsers, so a bare import would
    collide; spec_from_file_location with a unique name avoids that.
    """
    abs_path = _CORE_ROOT / rel_path
    spec = importlib.util.spec_from_file_location(unique_name, abs_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


_php_fe = _load_unique("parsers/php/function_extractor.py", "isolated_php_function_extractor")
PhpFunctionExtractor = _php_fe.FunctionExtractor

_epd = _load_unique(
    "utilities/agentic_enhancer/entry_point_detector.py", "isolated_entry_point_detector"
)
EntryPointDetector = _epd.EntryPointDetector


def _extract(tmp_path: Path, filename: str, source: str):
    """Write a PHP file and run the real extractor over the repo dir."""
    repo = tmp_path
    (repo / filename).write_text(source)
    extractor = PhpFunctionExtractor(str(repo))
    return extractor.extract_all()


# ---------------------------------------------------------------------------
# Procedural top-level code must become a unit
# ---------------------------------------------------------------------------

PROCEDURAL_PLUGIN = """<?php
$config = $_GET['mode'];
echo do_query($config);
add_action('wp_ajax_x', 'handler');

function handler() {
    $v = $_POST['data'];
    return run_sql($v);
}

function do_query($q) {
    return run_sql($q);
}

function run_sql($s) {
    return $s;
}
"""


def test_procedural_top_level_extracted_as_module_level_unit(tmp_path):
    """Top-level PHP statements must produce a synthetic module_level unit."""
    result = _extract(tmp_path, "plugin.php", PROCEDURAL_PLUGIN)
    units = result["functions"]

    # Pre-fix: only the 3 named functions exist, no module-level unit.
    module_units = [
        fid for fid, fd in units.items() if fd.get("unit_type") == "module_level"
    ]
    assert module_units, (
        "expected a module_level unit synthesised for top-level procedural code; "
        f"got unit_types={sorted({fd.get('unit_type') for fd in units.values()})}"
    )

    # The synthesized unit's code must include the top-level statements
    # (the $_GET read and the add_action hook registration).
    mod_code = units[module_units[0]]["code"]
    assert "$_GET" in mod_code
    assert "add_action" in mod_code


def test_named_functions_still_extracted_alongside_module_level(tmp_path):
    """The module-level synthesis must not drop the named function units."""
    result = _extract(tmp_path, "plugin.php", PROCEDURAL_PLUGIN)
    names = {fd["name"] for fd in result["functions"].values()}
    assert {"handler", "do_query", "run_sql"}.issubset(names)


CLASS_ONLY_SOURCE = """<?php
namespace App;

use Foo\\Bar;

class C {
    public function m() {
        return 1;
    }
}
"""


def test_class_only_file_has_no_module_level_unit(tmp_path):
    """A file with no file-scope executable code must NOT get a module_level unit.

    Guards against the synthesizer treating namespace/use tokens or class
    declarations as 'top-level code'.
    """
    result = _extract(tmp_path, "clean.php", CLASS_ONLY_SOURCE)
    module_units = [
        fid
        for fid, fd in result["functions"].items()
        if fd.get("unit_type") == "module_level"
    ]
    assert not module_units, (
        "class-only file must not synthesise a module_level unit; "
        f"got {module_units}"
    )


# ---------------------------------------------------------------------------
# PHP superglobals must seed entry points
# ---------------------------------------------------------------------------


def test_php_superglobal_handler_is_entry_point(tmp_path):
    """A handler reading $_POST must be flagged as an entry point (Check 3)."""
    result = _extract(tmp_path, "plugin.php", PROCEDURAL_PLUGIN)
    detector = EntryPointDetector(result["functions"], {})
    detector.detect_entry_points()

    handler_id = next(
        fid for fid, fd in result["functions"].items() if fd["name"] == "handler"
    )
    assert detector.is_entry_point(handler_id), (
        "handler reads $_POST['data'] and must be an entry point; "
        f"reason={detector.get_entry_point_reason(handler_id)!r}"
    )


def test_php_module_level_with_superglobal_is_entry_point(tmp_path):
    """The synthesized module_level unit reading $_GET must seed via Check 4."""
    result = _extract(tmp_path, "plugin.php", PROCEDURAL_PLUGIN)
    detector = EntryPointDetector(result["functions"], {})
    detector.detect_entry_points()

    module_ids = [
        fid
        for fid, fd in result["functions"].items()
        if fd.get("unit_type") == "module_level"
    ]
    assert module_ids, "no module_level unit was synthesised"
    assert any(detector.is_entry_point(mid) for mid in module_ids), (
        "the module_level unit reads $_GET and registers a wp_ajax hook; "
        "it must be flagged as an entry point"
    )


# ---------------------------------------------------------------------------
# Anonymous closures and arrow functions must become units
# ---------------------------------------------------------------------------

CLOSURE_SOURCE = """<?php
function outer() {
    $cb = function ($x) {
        return helper($x);
    };
    $cb(5);
    $arrow = fn($z) => transform($z);
    $arrow(1);
}

function helper($x) {
    return $x;
}

function transform($z) {
    return $z;
}
"""


def test_anonymous_closure_extracted_as_unit(tmp_path):
    """An anonymous_function must be emitted as a closure unit."""
    result = _extract(tmp_path, "closures.php", CLOSURE_SOURCE)
    closure_units = [
        fid
        for fid, fd in result["functions"].items()
        if fd.get("unit_type") == "closure"
    ]
    assert closure_units, (
        "expected at least one closure unit for the anonymous_function / "
        f"arrow_function; unit_types="
        f"{sorted({fd.get('unit_type') for fd in result['functions'].values()})}"
    )


def test_arrow_function_extracted_as_unit(tmp_path):
    """Both the anonymous closure and the arrow function must be units (2 total)."""
    result = _extract(tmp_path, "closures.php", CLOSURE_SOURCE)
    closure_units = [
        fd
        for fd in result["functions"].values()
        if fd.get("unit_type") == "closure"
    ]
    assert len(closure_units) == 2, (
        "expected exactly two closure units (one anonymous_function + one "
        f"arrow_function); got {len(closure_units)}"
    )


def test_closure_units_capture_their_body(tmp_path):
    """Closure units must carry the closure body in their code field."""
    result = _extract(tmp_path, "closures.php", CLOSURE_SOURCE)
    bodies = "\n".join(
        fd["code"]
        for fd in result["functions"].values()
        if fd.get("unit_type") == "closure"
    )
    assert "helper" in bodies  # from the anonymous closure body
    assert "transform" in bodies  # from the arrow function body


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
