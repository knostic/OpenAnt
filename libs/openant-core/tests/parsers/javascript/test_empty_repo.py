"""Regression test for graceful handling of a zero-JS-file repository.

A directory with zero JS-family source files must NOT be treated as a parser
failure. repository_scanner.js exits 0 with an empty file list; the JS pipeline
then hit ``if not files: return False`` in ``run_typescript_analyzer``, which
made ``run_full_pipeline`` early-return without ``results['success']``, so
``main`` did ``sys.exit(1)``. ``_parse_javascript`` then raised
``RuntimeError`` on the non-zero exit, aborting the whole scan instead of
yielding a 0-unit result.

The Python, Ruby and Zig parsers all treat an empty repo gracefully (zig writes
an empty dataset and returns 0). This test pins the JS parser to the same
contract: zero files -> success + empty analyzer/dataset output, so the adapter
returns a valid empty ParseResult.

Loaded via importlib under a UNIQUE module name to avoid colliding with the
many other modules named ``test_pipeline`` across the parser packages.
"""

import importlib.util
import os

import pytest

from utilities.file_io import write_json

_CORE_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
_JS_PIPELINE = os.path.join(
    _CORE_ROOT, "parsers", "javascript", "test_pipeline.py"
)


def _load_js_pipeline():
    spec = importlib.util.spec_from_file_location(
        "isolated_js_pipeline_under_test", _JS_PIPELINE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def js_pipeline():
    return _load_js_pipeline()


def _make_pipeline(js_pipeline, tmp_path, repo):
    repo.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    pipeline = js_pipeline.PipelineTest(
        repo_path=str(repo),
        output_dir=str(out),
        processing_level=js_pipeline.ProcessingLevel.ALL,
        skip_tests=True,
    )
    return pipeline, out


def _write_empty_scan(pipeline, out):
    """Simulate repository_scanner.js succeeding with zero JS files."""
    scan_path = os.path.join(str(out), "scan_results.json")
    write_json(
        scan_path,
        {"files": [], "statistics": {"totalFiles": 0, "byExtension": {}}},
    )
    pipeline.scan_results_file = scan_path


def test_zero_js_files_analyzer_succeeds_gracefully(js_pipeline, tmp_path):
    """run_typescript_analyzer must NOT report failure on an empty repo."""
    pipeline, out = _make_pipeline(js_pipeline, tmp_path, tmp_path / "empty_repo")
    _write_empty_scan(pipeline, out)

    ok = pipeline.run_typescript_analyzer()

    assert ok is True, (
        "zero JS files must be a graceful empty result, not a stage failure"
    )


def test_zero_js_files_writes_empty_outputs(js_pipeline, tmp_path):
    """An empty repo must leave a valid empty analyzer + dataset on disk so the
    adapter reads units_count=0 instead of crashing."""
    pipeline, out = _make_pipeline(js_pipeline, tmp_path, tmp_path / "empty_repo")
    _write_empty_scan(pipeline, out)

    assert pipeline.run_typescript_analyzer() is True

    analyzer_path = os.path.join(str(out), "analyzer_output.json")
    dataset_path = os.path.join(str(out), "dataset.json")
    assert os.path.exists(analyzer_path), "empty repo must still write analyzer_output.json"
    assert os.path.exists(dataset_path), "empty repo must still write dataset.json"

    from utilities.file_io import read_json

    analyzer = read_json(analyzer_path)
    dataset = read_json(dataset_path)
    assert analyzer.get("functions", {}) == {}
    assert dataset.get("units", []) == []
