"""A hostile finding.short_name must not steer the disclosure filename.

``short_name`` is model-produced / repo-influenced free text, interpolated into the
on-disk disclosure filename ``DISCLOSURE_NN_<short_name>.md``. A ``/`` (traversal) or a
non-str value would previously crash disclosure generation (FileNotFoundError writing
into a missing intermediate dir / AttributeError on ``.replace``). generate_all and the
``python -m report`` CLI now ``os.path.basename(str(...))`` the value, so it stays a bare
leaf inside the disclosures dir. This locks that behavior at the generate_all call site
(the one hardening in this branch that otherwise shipped without a test).
"""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# parents[2] = the openant-core root, so `from report import generator` resolves to the
# real package rather than this tests/report/ directory (which would shadow it).
_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub

from report import generator  # noqa: E402


def _pipeline(short_name):
    return {
        "repository": {"name": "test", "language": "python"},
        "application_type": "web_app",
        "findings": [{
            "id": "VULN-001", "name": "t", "short_name": short_name,
            "location": {"file": "app.py", "function": "app.py:vuln"},
            "cwe_id": 79, "cwe_name": "XSS",
            "stage1_verdict": "vulnerable", "stage2_verdict": "confirmed",
        }],
    }


@pytest.mark.parametrize("short_name", [
    "../../etc/passwd",      # traversal
    "/etc/passwd",           # absolute
    "a/b/c",                 # nested
    12345,                   # non-str
    ["x"],                   # non-str container
    None,                    # falls back to id
    "",                      # empty -> id/finding
])
def test_hostile_short_name_stays_a_leaf_in_disclosures_dir(tmp_path, monkeypatch, short_name):
    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(_pipeline(short_name)))
    out_dir = tmp_path / "out"

    # No LLM: stub the two generators and validation so we exercise only the
    # filename-derivation path in generate_all.
    monkeypatch.setattr(generator, "generate_summary_report", lambda *a, **k: ("summary", {}))
    monkeypatch.setattr(generator, "generate_disclosure", lambda *a, **k: ("disclosure body", {}))
    monkeypatch.setattr(generator, "validate_pipeline_output", lambda *a, **k: None)

    class _NoopBinding:
        pass

    class _Reg:
        def get(self, _phase):
            return _NoopBinding()

    generator.generate_all(str(po_path), str(out_dir), registry=_Reg())

    disclosures = out_dir / "disclosures"
    written = list(disclosures.glob("*.md"))
    assert len(written) == 1, f"expected one disclosure, got {written}"
    name = written[0].name
    # It must be a bare leaf directly inside disclosures/, no traversal escape.
    assert written[0].parent == disclosures
    assert "/" not in name and ".." not in name
    assert name.startswith("DISCLOSURE_") and name.endswith(".md")
    # Nothing was written outside the output dir.
    assert not (tmp_path / "etc").exists()
    assert not Path("/etc/passwd.md").exists()


@pytest.mark.parametrize("short_name", ["../../etc/passwd", "/etc/passwd", 12345, ["x"]])
def test_cli_disclosures_hostile_short_name_stays_a_leaf(tmp_path, monkeypatch, short_name):
    """The `python -m report disclosures` CLI path carries the SAME (byte-identical)
    safe_name hardening as generate_all — cover it too so both sites are locked."""
    import argparse
    from report import __main__ as report_main

    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(_pipeline(short_name)))
    out_dir = tmp_path / "cli_out"

    monkeypatch.setattr(report_main, "_build_report_binding", lambda *a, **k: object())
    monkeypatch.setattr(report_main, "generate_disclosure", lambda *a, **k: ("body", {}))
    monkeypatch.setattr(report_main, "validate_pipeline_output", lambda *a, **k: None)

    report_main.cmd_disclosures(argparse.Namespace(input=str(po_path), output=str(out_dir)))

    written = list(out_dir.glob("*.md"))
    assert len(written) == 1, f"expected one disclosure, got {written}"
    name = written[0].name
    assert written[0].parent == out_dir
    assert "/" not in name and ".." not in name
    assert name.startswith("DISCLOSURE_") and name.endswith(".md")
    assert not (tmp_path / "etc").exists()
