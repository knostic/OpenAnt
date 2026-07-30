"""A7: Go<->Python language-DETECTION parity.

The supported-language SET is already guarded (test_language_registry.py / Go
TestSupportedMatchesConfig), and each runtime's detection is already unit-tested
SEPARATELY — but with independently hand-authored expectations, so the two could
drift on the SAME input (they historically did, on tie-breaks). This test and its
Go twin (apps/openant-cli/internal/languages/detection_parity_test.go) consume ONE
shared golden (config/testdata/detection_parity.json) so the expected outcomes are
single-sourced and cannot diverge.

This is the Python half: materialize each golden tree as empty files, run
detect_languages, compare the RANKED ordered list (or assert the error outcome).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.parser_adapter import detect_languages

_GOLDEN = Path(__file__).parents[3] / "config" / "testdata" / "detection_parity.json"


def _load_fixtures():
    data = json.loads(_GOLDEN.read_text())
    return [(f["name"], f) for f in data["fixtures"]]


def _materialize(root: Path, tree: list[str]) -> None:
    for rel in tree:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")  # detection reads names only; empty is fine


def test_golden_file_exists_and_is_nonempty():
    fixtures = _load_fixtures()
    assert len(fixtures) >= 7, "golden must carry the full parity set"


@pytest.mark.parametrize("name,fixture", _load_fixtures())
def test_detection_matches_golden(name, fixture, tmp_path):
    _materialize(tmp_path, fixture["tree"])
    expect = fixture["expect"]

    if isinstance(expect, dict) and expect.get("error"):
        with pytest.raises(ValueError):
            detect_languages(str(tmp_path))
        return

    ranked = list(detect_languages(str(tmp_path)))  # dict is ordered (-count, name)
    assert ranked == expect, f"{name}: detected {ranked}, golden expects {expect}"
