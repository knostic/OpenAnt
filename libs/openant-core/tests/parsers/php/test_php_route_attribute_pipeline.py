"""End-to-end regression for PHP 8 #[Route] attribute entry-point seeding
through the php *reachable* pipeline.

The per-parser reachable path (parsers/php/test_pipeline.py) rebuilds every unit
through a field whitelist before running EntryPointDetector. That whitelist
dropped 'decorators', so a #[Route] handler on a class NOT named *Controller
seeded ZERO entry points on this path and was pruned by the reachability filter
(Units: 1 -> 0) — while the raw-detector unit tests stayed green. This drives the
whole pipeline (parse_repository -> normalization -> detector -> reachability
filter) so the fix is exercised on the shipped path.
"""
import json
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[3]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from core.parser_adapter import parse_repository  # noqa: E402

ROUTE_PHP = (
    "<?php\n"
    "namespace App\\Api;\n"
    "class ProductApi {\n"
    '    #[Route("/products/{id}", methods: ["GET"])]\n'
    "    public function show($id) { return $id; }\n"
    "}\n"
)


def test_route_attribute_handler_survives_reachability_filter(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "ProductApi.php").write_text(ROUTE_PHP)
    out = tmp_path / "out"
    out.mkdir()

    parse_repository(
        str(repo), str(out), language="php",
        processing_level="reachable", skip_tests=True, name="t",
    )

    cg = json.loads((out / "call_graph.json").read_text())
    funcs = cg.get("functions", {})
    hid = "src/ProductApi.php:ProductApi.show"
    assert hid in funcs, f"handler missing from call graph: {list(funcs)}"
    assert funcs[hid].get("decorators"), (
        "the #[Route] attribute must reach the reachable pipeline as a decorator; "
        f"got {funcs[hid].get('decorators')!r}"
    )

    # At processing_level='reachable' a unit survives only if reachable from a
    # seed. The handler is the only function, so it survives iff it was seeded as
    # an entry point (which requires decorators to survive the normalization).
    blob = json.dumps(json.loads((out / "dataset.json").read_text()))
    assert "ProductApi.show" in blob, (
        "the #[Route] handler was pruned from the reachable dataset -> it was not "
        "seeded (decorators dropped by the pipeline normalization whitelist)"
    )
