"""Regression tests for disclosure source fidelity.

The LLM that renders disclosures used to "minimally rewrite" the vulnerable
code snippet, which produced fabricated code in DISCLOSURE_01 (ping) and
DISCLOSURE_05 (run_query). The fix injects a pre-rendered, verbatim code
block via a dedicated ``vulnerable_code_section`` field so the LLM never
has the opportunity to rewrite it.
"""

import json
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Allow `import core.reporter` when tests run from repo root or elsewhere.
_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

# The project's venv has a broken `anthropic` install (ErrorObject import fails
# in some sub-dependency). Stub it before `report.generator` is imported so the
# test suite can run without touching the venv. Real API calls are never made
# in this file — all disclosure generation is mocked.
if "anthropic" not in sys.modules:
    stub = types.ModuleType("anthropic")
    stub.Anthropic = MagicMock()
    stub.RateLimitError = type("RateLimitError", (Exception,), {})
    stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = stub

from core import reporter  # noqa: E402
from report import generator  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture — minimal results.json reproducing the disclosure-fabrication
# scenario (ping + run_query) end-to-end.
# ---------------------------------------------------------------------------

PING_CODE = (
    "@app.route('/ping', methods=['GET'])\n"
    "def ping():\n"
    "    ip = request.args.get('ip', '')\n"
    "    result = subprocess.check_output(['ping', '-c', '4', ip])\n"
    "    return result"
)

RUN_QUERY_CODE = (
    "def run_query(query):\n"
    "    # Simulating a database query without proper sanitization (SQL Injection risk)\n"
    '    return "Query result for: " + query'
)


@pytest.fixture
def results_file(tmp_path: Path) -> Path:
    """Build a minimal results.json fixture and return its path."""
    results = {
        "dataset": "disclosure-fidelity-fixture",
        "results": [
            {
                "unit_id": "VulnerablePythonScript.py:ping",
                "route_key": "VulnerablePythonScript.py:ping",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /ping?ip=-w 1000",
                "reasoning": "ip passed to subprocess without validation",
            },
            {
                "unit_id": "VulnerablePythonScript.py:run_query",
                "route_key": "VulnerablePythonScript.py:run_query",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /user?id=' OR '1'='1' --",
                "reasoning": "query concatenation reaches run_query",
            },
        ],
        "code_by_route": {
            "VulnerablePythonScript.py:ping": PING_CODE,
            "VulnerablePythonScript.py:run_query": RUN_QUERY_CODE,
        },
        "confirmed_findings": [
            {
                "unit_id": "VulnerablePythonScript.py:ping",
                "route_key": "VulnerablePythonScript.py:ping",
                "verdict": "vulnerable",
                "finding": "vulnerable",
            },
            {
                "unit_id": "VulnerablePythonScript.py:run_query",
                "route_key": "VulnerablePythonScript.py:run_query",
                "verdict": "vulnerable",
                "finding": "vulnerable",
            },
        ],
        "metrics": {"total": 2, "vulnerable": 2, "safe": 0},
    }

    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


@pytest.fixture
def pipeline_output(tmp_path: Path, results_file: Path) -> dict:
    """Invoke build_pipeline_output() and return the written JSON."""
    out_path = tmp_path / "pipeline_output.json"
    reporter.build_pipeline_output(
        results_path=str(results_file),
        output_path=str(out_path),
        repo_name="example/vulnerable-test-app",
        language="python",
    )
    return json.loads(out_path.read_text())


# ---------------------------------------------------------------------------
# Build-pipeline-output: the emitted finding must carry a pre-rendered,
# verbatim Vulnerable Code markdown section.
# ---------------------------------------------------------------------------

def test_pipeline_output_carries_vulnerable_code_section(pipeline_output: dict):
    findings = pipeline_output["findings"]
    assert len(findings) == 2

    for finding in findings:
        section = finding.get("vulnerable_code_section")
        assert section, f"vulnerable_code_section missing from {finding.get('id')}"
        assert section.startswith("## Vulnerable Code"), (
            f"section must start with a markdown heading: {section[:80]!r}"
        )
        # File path is surfaced in the section so the reader can locate the code.
        assert "VulnerablePythonScript.py" in section
        # Code fence with the language hint.
        assert "```python" in section


def test_ping_section_contains_verbatim_source(pipeline_output: dict):
    """Real ping() has @app.route, check_output, and -c 4 — must appear verbatim."""
    ping = next(
        f for f in pipeline_output["findings"]
        if f["location"]["function"].endswith(":ping")
    )
    section = ping["vulnerable_code_section"]

    # Every line of the real source must appear verbatim.
    for line in PING_CODE.splitlines():
        assert line in section, f"missing real source line: {line!r}"

    # Guard against the fabricated variant the LLM used to emit.
    assert "subprocess.run(" not in section, "fabricated subprocess.run leaked back in"
    assert "capture_output=True" not in section


def test_run_query_section_contains_verbatim_source(pipeline_output: dict):
    """Real run_query() is 3 lines, not a Flask-route hybrid — must appear verbatim."""
    run_query = next(
        f for f in pipeline_output["findings"]
        if f["location"]["function"].endswith(":run_query")
    )
    section = run_query["vulnerable_code_section"]

    for line in RUN_QUERY_CODE.splitlines():
        assert line in section, f"missing real source line: {line!r}"

    # Guard against the fabricated variant (simulate_query / request.args read).
    assert "simulate_query(" not in section
    assert "request.args.get" not in section


# ---------------------------------------------------------------------------
# Tier 1: _splice_code_section — deterministic post-processing
# ---------------------------------------------------------------------------

REAL_PING_SECTION = (
    "## Vulnerable Code\n\n"
    "`VulnerablePythonScript.py`:\n\n"
    "```python\n"
    "@app.route('/ping', methods=['GET'])\n"
    "def ping():\n"
    "    ip = request.args.get('ip', '')\n"
    "    result = subprocess.check_output(['ping', '-c', '4', ip])\n"
    "    return result\n"
    "```"
)

# Simulates an LLM that ignored the "don't generate code" instruction
# and emitted its own fabricated Vulnerable Code section.
LLM_OUTPUT_WITH_FABRICATED_CODE = (
    "# Security Disclosure: Command Injection in Ping\n\n"
    "**Product:** test\n"
    "**Type:** CWE-78 (Command Injection)\n\n"
    "## Summary\n\n"
    "The ping function is vulnerable.\n\n"
    "## Vulnerable Code\n\n"
    "`VulnerablePythonScript.py`:\n\n"
    "```python\n"
    "def ping(ip):\n"
    "    result = subprocess.run(['ping', ip], capture_output=True)\n"
    "    return result.stdout\n"
    "```\n\n"
    "The ip parameter is not validated.\n\n"
    "## Steps to Reproduce\n\n"
    "**Step 1:** Send a request.\n\n"
    "## Impact\n\n"
    "- RCE\n\n"
    "## Suggested Fix\n\n"
    "Validate input.\n"
)

# Simulates an LLM that obeyed and did NOT generate a code section.
LLM_OUTPUT_WITHOUT_CODE = (
    "# Security Disclosure: Command Injection in Ping\n\n"
    "**Product:** test\n"
    "**Type:** CWE-78 (Command Injection)\n\n"
    "## Summary\n\n"
    "The ping function is vulnerable.\n\n"
    "The ip parameter is not validated.\n\n"
    "## Steps to Reproduce\n\n"
    "**Step 1:** Send a request.\n\n"
    "## Impact\n\n"
    "- RCE\n\n"
    "## Suggested Fix\n\n"
    "Validate input.\n"
)


def test_splice_replaces_fabricated_code():
    """When the LLM outputs a fabricated code block, the post-processor
    must strip it and insert the real one."""
    result = generator._splice_code_section(
        LLM_OUTPUT_WITH_FABRICATED_CODE, REAL_PING_SECTION
    )

    # Real code present
    assert "subprocess.check_output" in result
    assert "'-c', '4'" in result

    # Fabricated code gone
    assert "subprocess.run" not in result
    assert "capture_output=True" not in result
    assert "def ping(ip)" not in result

    # Real section appears exactly once
    assert result.count("## Vulnerable Code") == 1


def test_splice_inserts_when_no_code_section():
    """When the LLM obeys and omits the code section, the post-processor
    must insert the real one before Steps to Reproduce."""
    result = generator._splice_code_section(
        LLM_OUTPUT_WITHOUT_CODE, REAL_PING_SECTION
    )

    # Real code present
    assert "subprocess.check_output" in result

    # Inserted before Steps to Reproduce
    code_pos = result.index("## Vulnerable Code")
    steps_pos = result.index("## Steps to Reproduce")
    assert code_pos < steps_pos, "code section must appear before Steps to Reproduce"


def test_splice_preserves_other_sections():
    """Summary, Steps, Impact, Suggested Fix must all survive the splice."""
    result = generator._splice_code_section(
        LLM_OUTPUT_WITH_FABRICATED_CODE, REAL_PING_SECTION
    )

    for heading in ["## Summary", "## Steps to Reproduce", "## Impact", "## Suggested Fix"]:
        assert heading in result, f"{heading} was destroyed by splice"


# ---------------------------------------------------------------------------
# Tier 2: generate_disclosure() full mock flow — the OUTPUT must contain
# the real code, even when the LLM returns fabricated code.
# ---------------------------------------------------------------------------

class _FakeAnthropic:
    """Replacement for anthropic.Anthropic — returns fabricated code to prove
    the post-processor catches it."""

    def __init__(self, *args, **kwargs):
        self.messages = self

    def create(self, **kwargs):
        _FakeAnthropic.last_prompt = kwargs["messages"][0]["content"]
        # Return a disclosure WITH fabricated code — the post-processor must fix it.
        return _FakeResponse()


class _FakeResponse:
    class _Content:
        text = LLM_OUTPUT_WITH_FABRICATED_CODE

    content = [_Content()]

    class _Usage:
        input_tokens = 10
        output_tokens = 50

    usage = _Usage()


@pytest.fixture
def patched_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
    monkeypatch.setattr(generator.anthropic, "Anthropic", _FakeAnthropic)


def test_generate_disclosure_output_has_real_code(patched_anthropic, pipeline_output):
    """Even when the LLM returns fabricated code, the final output from
    generate_disclosure() must contain the real source."""
    ping = next(
        f for f in pipeline_output["findings"]
        if f["location"]["function"].endswith(":ping")
    )

    text, _usage = generator.generate_disclosure(ping, product_name="fixture")

    # Real code in the output
    assert "subprocess.check_output" in text, "real code must be in final output"
    assert "'-c', '4'" in text

    # Fabricated code NOT in the output
    assert "subprocess.run" not in text, "fabricated code must be stripped from output"
    assert "capture_output=True" not in text
    assert "def ping(ip)" not in text


def test_generate_disclosure_prompt_has_no_source_code(patched_anthropic, pipeline_output):
    """The prompt sent to Claude must NOT contain the vulnerable source code —
    the LLM should never see it, so it can't fabricate a rewritten version."""
    ping = next(
        f for f in pipeline_output["findings"]
        if f["location"]["function"].endswith(":ping")
    )

    generator.generate_disclosure(ping, product_name="fixture")
    prompt = _FakeAnthropic.last_prompt

    # The actual source code must not appear in the prompt.
    assert "subprocess.check_output" not in prompt, (
        "real source code must not appear in the prompt"
    )
    assert "```python" not in prompt or PING_CODE.splitlines()[0] not in prompt, (
        "code fence with real source must not appear in the prompt"
    )
