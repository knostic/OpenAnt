"""Regression test for the ``build_pipeline_output`` return-contract bug.

``build_pipeline_output`` was annotated ``-> str``
with a docstring claiming it returns "The output_path written to" (a single
str), but its sole ``return`` statement is ``return output_path,
len(findings_data)`` — a ``tuple[str, int]``. The annotation/docstring grew
stale when the function gained a second return value (the findings count);
the one binding caller (``openant/cli.py`` ``cmd_report``) was migrated to
unpack the tuple, but the signature + docstring were left behind.

This test pins the *real* runtime contract: the function returns a 2-tuple of
``(output_path: str, findings_count: int)``, and the declared return
annotation must agree with that real return type. It fails at base because
the annotation is ``str`` while the value is a tuple.
"""

import json
import sys
import typing
from pathlib import Path

import pytest

# Allow `import core.reporter` when tests run from repo root or elsewhere.
_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

from core import reporter  # noqa: E402


@pytest.fixture
def results_file(tmp_path: Path) -> Path:
    """Minimal results.json (no confirmed findings) accepted by the reporter."""
    results = {
        "results": [],
        "code_by_route": {},
        "metrics": {"total": 0, "vulnerable": 0, "safe": 0},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def test_returns_tuple_of_path_and_findings_count(tmp_path: Path, results_file: Path):
    """The actual return value is a 2-tuple ``(str, int)``, not a bare str."""
    out_path = tmp_path / "pipeline_output.json"
    ret = reporter.build_pipeline_output(
        results_path=str(results_file),
        output_path=str(out_path),
        repo_name="example/return-contract",
        language="python",
    )

    assert isinstance(ret, tuple), f"expected a tuple return, got {type(ret).__name__}"
    assert len(ret) == 2, f"expected a 2-tuple, got len {len(ret)}"
    path, findings_count = ret
    assert isinstance(path, str)
    assert path == str(out_path)
    assert isinstance(findings_count, int)


def test_return_annotation_matches_real_tuple_contract():
    """The declared ``-> ...`` annotation must agree with the real tuple return.

    At base the annotation is ``str`` (single value) which contradicts the
    real ``tuple[str, int]`` return — this assertion is the RED.
    """
    hints = typing.get_type_hints(reporter.build_pipeline_output)
    ret_ann = hints.get("return")

    origin = typing.get_origin(ret_ann)
    assert origin is tuple, (
        "build_pipeline_output return annotation must be a tuple to match its "
        f"real `return output_path, len(findings_data)`; got {ret_ann!r}"
    )

    args = typing.get_args(ret_ann)
    assert args == (str, int), (
        f"return annotation should be tuple[str, int]; got tuple{list(args)!r}"
    )


def test_docstring_no_longer_claims_single_path_return():
    """The Returns: docstring must not claim a single ``output_path`` return."""
    doc = reporter.build_pipeline_output.__doc__ or ""
    assert "The *output_path* written to." not in doc, (
        "docstring still claims a single output_path return; it should describe "
        "the (output_path, findings_count) tuple"
    )
