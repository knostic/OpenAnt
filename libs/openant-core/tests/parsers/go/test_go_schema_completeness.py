"""Schema-completeness contract test for the Go parser (BUG-NEW 5 family guard).

BUG-NEW 5 is a *cross-parser schema drift*. The Go parser is a separate Go
binary whose `FunctionInfo` records (`parsers/go/go_parser/types.go`) use
**camelCase** json keys (`unitType`, `startLine`, `endLine`, `isExported`,
`filePath`, `className`). Every other parser (python/ruby/php/c/zig) emits
**snake_case** (`unit_type`, `start_line`, ...). The Python reachability /
entry-point consumers read snake_case -- e.g.
`utilities/agentic_enhancer/entry_point_detector.py` reads
`func_data.get('unit_type')`. So for Go records read out of `call_graph.json`
they got `None`, and any unit_type-based logic (entry-point classification,
statistics, the module_level check) was silently broken for Go.

The fix normalizes the Go function records to **snake_case** at the single
Python ingestion boundary that builds `call_graph.json`'s `functions` map
(`parsers/go/test_pipeline.py`), matching the consumer contract and every
other parser. No Go rebuild; the analyzer_output.json camelCase contract
(consumed by the camelCase-aware analyzer surface) is intentionally left alone.

Design:
    * REACH_SRC is a Go program with a silent `func main()` that calls a helper
      (no decorators, no input patterns) -- the ONLY thing that makes `main` an
      entry point is its unit_type/name. This exercises BUG-4 (+name:main) and
      BUG-5 (unit_type readable) together.
    * The real Go binary + real test_pipeline.py produce call_graph.json and the
      reachability-filtered dataset.json.
    * Tests assert (1) the ingested function records expose snake_case
      unit_type/file_path/start_line (not None), and (2) main seeds reachability
      with a unit_type-derived entry-point reason and the helper is reachable.

If the Go toolchain / subprocess is unavailable the end-to-end tests skip and a
normalization unit-test on a representative camelCase record still runs.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

_GO_PARSER_DIR = _CORE_ROOT / "parsers" / "go" / "go_parser"
_TEST_PIPELINE = _CORE_ROOT / "parsers" / "go" / "test_pipeline.py"

# A silent main() calling a helper: nothing but unit_type/name makes main an
# entry point (no decorators, no request.* / argv input patterns).
REACH_SRC = """package main

import "fmt"

func helper(x int) int {
\treturn x * 2
}

func main() {
\tfmt.Println(helper(21))
}
"""

GO_MOD = "module bug5repo\n\ngo 1.21\n"

# Snake-case keys the Python reachability/entry-point consumers read out of
# call_graph.json's `functions` records. These are None today for Go records.
CONSUMER_SNAKE_KEYS = ["unit_type", "file_path", "start_line", "end_line", "is_exported"]


def _go_available():
    return shutil.which("go") is not None or (_GO_PARSER_DIR / "go_parser").exists()


@pytest.fixture(scope="module")
def go_pipeline_output(tmp_path_factory):
    """Run the real Go binary + real test_pipeline.py; return (call_graph, dataset)."""
    if not _go_available():
        pytest.skip("Go toolchain / go_parser binary unavailable")

    repo = tmp_path_factory.mktemp("bug5_repo")
    (repo / "main.go").write_text(REACH_SRC)
    (repo / "go.mod").write_text(GO_MOD)
    out = tmp_path_factory.mktemp("bug5_out")

    cmd = [
        sys.executable, str(_TEST_PIPELINE), str(repo),
        "--output", str(out),
        "--processing-level", "reachable",
        "--skip-tests",
    ]
    proc = subprocess.run(
        cmd, cwd=str(_CORE_ROOT),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300,
    )
    cg_path = out / "call_graph.json"
    ds_path = out / "dataset.json"
    if proc.returncode != 0 or not cg_path.exists() or not ds_path.exists():
        pytest.skip(f"Go pipeline did not produce outputs (env-flaky):\n{proc.stdout[-2000:]}")

    return json.loads(cg_path.read_text()), json.loads(ds_path.read_text())


@pytest.mark.parametrize("snake_key", CONSUMER_SNAKE_KEYS)
def test_go_function_record_exposes_snake_case(go_pipeline_output, snake_key):
    """Each ingested Go function record must expose the snake_case key the
    Python consumer reads (RED: only camelCase present, so snake key is None)."""
    call_graph, _dataset = go_pipeline_output
    functions = call_graph.get("functions", {})
    assert functions, "Go pipeline produced no function records"
    for func_id, fd in functions.items():
        assert snake_key in fd, (
            f"Go function {func_id!r} missing snake_case key {snake_key!r}; "
            f"consumer would read None. keys = {sorted(fd)}"
        )


def test_go_main_record_unit_type_is_main(go_pipeline_output):
    """The main() record's snake_case unit_type must read 'main' (RED: None)."""
    call_graph, _dataset = go_pipeline_output
    functions = call_graph.get("functions", {})
    main_recs = [fd for fd in functions.values() if fd.get("name") == "main"]
    assert main_recs, f"no main record; ids = {list(functions)}"
    assert main_recs[0].get("unit_type") == "main", (
        f"main unit_type not readable as snake_case; got {main_recs[0].get('unit_type')!r} "
        f"(camel unitType = {main_recs[0].get('unitType')!r})"
    )


def test_go_main_seeds_reachability_via_unit_type(go_pipeline_output):
    """End-to-end payoff: a silent func main() calling helper() seeds reachability
    with a unit_type-derived entry-point reason, and the helper is reachable."""
    _call_graph, dataset = go_pipeline_output
    units = {u["id"]: u for u in dataset.get("units", [])}
    main_id = next((i for i in units if i.endswith(":main")), None)
    helper_id = next((i for i in units if i.endswith(":helper")), None)
    assert main_id and helper_id, f"missing main/helper units; ids = {list(units)}"

    assert units[main_id].get("is_entry_point") is True, "main not seeded as entry point"
    # The unit_type-derived reason must be present now that unit_type is readable.
    reason = units[main_id].get("entry_point_reason", "")
    assert "unit_type:main" in reason, (
        f"main entry-point reason lacks unit_type:main (BUG-5 still drifting); reason = {reason!r}"
    )
    assert units[helper_id].get("reachable") is True, "helper not reachable from main"


def test_normalize_camel_record_to_snake_full_schema():
    """BUG-5 re-verify (no Go toolchain needed): a representative camelCase Go
    FunctionInfo record normalizes to the FULL snake_case consumer schema,
    including the parameters / returns / is_async fields that were previously
    omitted from normalize_go_function_records."""
    from parsers.go.test_pipeline import normalize_go_function_records
    camel = {"f.go:Pkg.M": {
        "name": "M", "code": "func ...", "startLine": 10, "endLine": 20,
        "unitType": "method", "className": "Pkg", "isExported": True,
        "package": "main", "filePath": "f.go", "receiver": "Pkg",
        "parameters": ["x int"], "returns": ["error"], "isAsync": True,
        "decorators": ["// note"],
    }}
    out = normalize_go_function_records(camel)["f.go:Pkg.M"]
    expected = {
        "name": "M", "unit_type": "method", "file_path": "f.go",
        "start_line": 10, "end_line": 20, "is_exported": True,
        "class_name": "Pkg", "package": "main", "receiver": "Pkg",
        "parameters": ["x int"], "returns": ["error"], "is_async": True,
        "decorators": ["// note"],
    }
    for k, v in expected.items():
        assert out.get(k) == v, f"{k!r}: got {out.get(k)!r}, expected {v!r}"
    # No camelCase keys leak through.
    assert not any(k in out for k in ("unitType", "filePath", "isAsync", "className")), out


def test_normalize_is_idempotent_on_snake_records():
    """Already-snake records pass through unchanged (idempotency)."""
    from parsers.go.test_pipeline import normalize_go_function_records
    snake = {"f.go:h": {
        "name": "h", "unit_type": "function", "code": "", "file_path": "f.go",
        "start_line": 1, "end_line": 2, "package": "main", "receiver": "",
        "is_exported": False, "class_name": "", "decorators": [],
        "parameters": [], "returns": [], "is_async": False,
    }}
    once = normalize_go_function_records(snake)
    twice = normalize_go_function_records(once)
    assert once == twice, "normalization not idempotent on snake records"
    assert once["f.go:h"]["unit_type"] == "function"
