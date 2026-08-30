"""#215 (NahumKorda): every finding carries a rankable severity.

The reporter's evidence — 82 Stage-2-upheld findings, 6 with cwe_id/impact/steps, 0 with any
severity — traced to a schema mismatch re-derived first-hand at HEAD: the finding record's
rich fields (`impact`, `steps_to_reproduce`, `suggested_fix`, the detailed `description`) are
read from ``finding["vulnerabilities"][0]`` (core/reporter.py:378-401), an array NO prompt asks
for — the Stage-1 contract (prompts/vulnerability_analysis.py:239-247) is flat:
finding/reasoning/attack_vector/confidence/cwe_id/cwe_name. The only producer of
``vulnerabilities[]`` is the JSON corrector's legacy ``_VULN_SCHEMA``
(utilities/json_corrector.py:30-45), which carries a 4-level severity enum
(CRITICAL|HIGH|MEDIUM|LOW) nested where nothing downstream reads it. The reporter's
well-formed 6 are most plausibly the corrector-repaired subset (checkable on their data via
the ``json_corrected`` transit field from #366).

The fix (the reporter's goal is downstream triage — rank/filter/SLA; the hard-retry means is
rejected as the false-negative direction: a model that never emits the field would lose its
findings to ERROR):

* Stage-1 prompt: ``"severity": "critical" | "high" | "medium" | "low"`` — required key in the
  assessment JSON (the enum the corrector's legacy schema already uses, canonical lowercase
  like ``finding``).
* ``_normalize_result`` stamps severity AFTER the verdict decision — never producing the error
  shape, never touching the error key (the #426 composition invariant): a model-supplied
  valid enum is kept (``severity_source: "model"``); anything else derives conservatively
  from the verdict (``vulnerable→high``, ``bypassable→medium``; never a derived critical —
  a verdict cannot know criticality) with ``severity_source: "derived"``. ERROR rows get NO
  severity — they are not findings.
* The finding record threads ``severity`` + ``severity_source`` (present-only, both
  construction paths); CSV gains the column; SARIF gains the rule's ``security-severity``
  property (level stays verdict-based); the summary table gains the column; the HTML/CLI
  table gains a column with the sort staying verdict-primary (the verdict order encodes
  epistemic status — an unverified vulnerable must not sink under a confirmed medium).
* ``report/schema.py``: Optional on Finding, NOT required (old artifacts must validate).
* Read-time derivation in the reporter for OLD artifacts (pre-PR results/resumed
  checkpoints): no severity present → derive + mark.
"""
import sys
from pathlib import Path

import pytest

CORE = str(Path(__file__).resolve().parents[2])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

SEVERITIES = ("critical", "high", "medium", "low")


# ---------------------------------------------------------------------------
# A. the producer — _normalize_result stamping (the #426 composition invariant)
# ---------------------------------------------------------------------------

def test_model_severity_kept_and_marked():
    from core.analysis_core import _normalize_result

    out = _normalize_result({"finding": "vulnerable", "severity": "HIGH",
                             "reasoning": "r"})
    assert out["verdict"] == "VULNERABLE"
    assert out["severity"] == "high"          # canonical lowercase
    assert out["severity_source"] == "model"


def test_off_enum_severity_derives():
    from core.analysis_core import _normalize_result

    out = _normalize_result({"finding": "vulnerable", "severity": "severe-ish"})
    assert out["severity"] == "high"
    assert out["severity_source"] == "derived"


def test_absent_severity_derives_from_verdict():
    from core.analysis_core import _normalize_result

    for finding, want in [("vulnerable", "high"), ("bypassable", "medium")]:
        out = _normalize_result({"finding": finding})
        assert out["severity"] == want, finding
        assert out["severity_source"] == "derived"


def test_never_a_derived_critical():
    from core.analysis_core import _normalize_result

    for finding in ("vulnerable", "bypassable"):
        out = _normalize_result({"finding": finding})
        assert out.get("severity") != "critical", finding


def test_error_rows_get_no_severity():
    from core.analysis_core import _normalize_result

    for shape in ({"finding": "maybe exploitable"},            # unrecognized -> ERROR
                  {"reasoning": "cannot determine"},           # neither-key -> ERROR
                  {"verdict": None, "reasoning": "refusal"}):   # null verdict, no finding -> ERROR
        out = _normalize_result(shape)
        assert out["verdict"] == "ERROR", shape
        assert "severity" not in out and "severity_source" not in out, shape


def test_non_finding_verdicts_carry_no_severity():
    """Wave finding (both reviewers): a severity on a safe/protected/
    inconclusive row defeats the triage filter (severity=low would return
    mostly non-findings) — the prompt itself says null for those. Only the
    FINDING verdicts (vulnerable/bypassable) carry severity; a stale model
    severity on a non-finding row is dropped."""
    from core.analysis_core import _normalize_result

    for finding in ("safe", "protected", "inconclusive", "insufficient_context"):
        out = _normalize_result({"finding": finding})
        assert "severity" not in out and "severity_source" not in out, finding
        # even when the model supplied one
        out = _normalize_result({"finding": finding, "severity": "critical"})
        assert "severity" not in out, finding


# ---------------------------------------------------------------------------
# B. the prompt + the corrector schema alignment
# ---------------------------------------------------------------------------

def test_stage1_prompt_asks_for_severity():
    from prompts.vulnerability_analysis import get_analysis_prompt

    text = get_analysis_prompt("code", "ctx")
    assert '"severity"' in text
    for word in ("critical", "high", "medium", "low"):
        assert word in text


def test_corrector_schema_carries_severity_top_level():
    from utilities.json_corrector import _VULN_SCHEMA

    # The legacy nested array kept its enum; the TOP-LEVEL shape the Stage-1
    # reply uses must carry severity too, in the SAME position the prompt
    # puts it — otherwise a corrected reply and a clean reply carry severity
    # in two shapes.
    assert '"severity"' in _VULN_SCHEMA
    import json as _json
    top = _VULN_SCHEMA
    assert top.index('"severity"') < top.index('"vulnerabilities"'), \
        "severity must appear at the top level, before the nested array"


# ---------------------------------------------------------------------------
# C. the finding record threads severity + source (both construction paths)
# ---------------------------------------------------------------------------

def _build_po(rows):
    """Write an experiment fixture to disk and run the real builder
    (build_pipeline_output takes file paths, not dicts)."""
    import json as _json
    import tempfile
    exp = {"results": rows, "metrics": {}, "code_by_route": {}}
    with tempfile.TemporaryDirectory() as d:
        rp = Path(d) / "experiment.json"
        op = Path(d) / "pipeline_output.json"
        rp.write_text(_json.dumps(exp))
        from core.reporter import build_pipeline_output
        build_pipeline_output(str(rp), str(op))
        return _json.loads(op.read_text())


def _finding_row(severity=None, source=None, **extra):
    row = {"finding": "vulnerable", "reasoning": "r", "attack_vector": "av",
           "cwe_id": 79, "cwe_name": "XSS", "route_key": "f.py:g"}
    if severity is not None:
        row["severity"] = severity
    if source is not None:
        row["severity_source"] = source
    row.update(extra)
    return row


def test_pipeline_output_finding_record_carries_severity():
    from core.reporter import build_pipeline_output

    po = _build_po([_finding_row(severity="high", source="model")])
    recs = po["findings"]
    assert len(recs) == 1
    assert recs[0]["severity"] == "high"
    assert recs[0]["severity_source"] == "model"


def test_pipeline_output_derives_severity_for_old_artifacts():
    """The read-time derivation site: pre-PR results carry no severity —
    the reporter derives + marks, so old scans rank in the new surfaces."""
    from core.reporter import build_pipeline_output

    po = _build_po([_finding_row()])  # no severity anywhere
    assert po["findings"][0]["severity"] == "high"
    assert po["findings"][0]["severity_source"] == "derived"


# ---------------------------------------------------------------------------
# D. the schema layer (old artifacts validate)
# ---------------------------------------------------------------------------

def test_schema_finding_severity_optional():
    from report.schema import Finding

    base = {"id": "VULN-001", "name": "vulnerable", "short_name": "VULNERABLE",
            "location": {"file": "a.py", "function": "f"},
            "cwe_id": 79, "cwe_name": "XSS",
            "stage1_verdict": "VULNERABLE", "stage2_verdict": "confirmed"}
    old = Finding.from_dict(base)                 # no severity: validates
    assert old.severity is None
    new = Finding.from_dict({**base, "severity": "high",
                            "severity_source": "model"})
    assert new.severity == "high" and new.severity_source == "model"


# ---------------------------------------------------------------------------
# E. the consumer surfaces (CSV / summary) + the verdict-primary sort
# ---------------------------------------------------------------------------

def test_csv_has_severity_column():
    import csv
    import json as _json
    import tempfile
    from report.csv_export import export_csv

    with tempfile.TemporaryDirectory() as d:
        exp_path = str(Path(d) / "experiment.json")
        ds_path = str(Path(d) / "dataset.json")
        out = str(Path(d) / "out.csv")
        Path(exp_path).write_text(_json.dumps(
            {"results": [_finding_row(severity="high", source="model")],
             "metrics": {}, "code_by_route": {}}))
        Path(ds_path).write_text(_json.dumps({"units": []}))
        export_csv(exp_path, ds_path, out)
        with open(out, newline="") as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = [dict(zip(header, r)) for r in reader]
    assert "severity" in header
    assert "severity_source" in header  # the provenance the triager filters on
    # the row carries both values
    assert rows and rows[0].get("severity") == "high"
    assert rows[0].get("severity_source") == "model"


def test_findings_table_sort_stays_verdict_primary():
    """Wave r2 (t#3): the old pin was vacuous (it asserted the taxonomy, not
    the sort — green with the entire diff reverted). The precise pin: the
    report-data sort's key tuple must order by verdict_priority FIRST (the
    verdict encodes epistemic status; severity is rank/filter metadata)."""
    import inspect
    import openant.cli as cli

    src = inspect.getsource(cli)
    i = src.find("findings.sort(key=lambda")
    assert i > 0, "the report-data sort not found"
    sort_expr = src[i:i+200]
    assert "verdict_priority.get(f[\"verdict\"]" in sort_expr and \
           sort_expr.index("verdict_priority.get") < sort_expr.index("dt_status_priority"), \
           f"the sort must stay verdict-primary; got: {sort_expr}"


# ---------------------------------------------------------------------------
# G. wave round-1 findings — the re-derivation, the corrected source, the
#    summary threading, the read-time gates
# ---------------------------------------------------------------------------

def test_derived_severity_rerives_from_final_verdict():
    """Wave finding (both reviewers): Stage 2 reclassifies `finding` in
    three places without touching severity. A DERIVED stamp must re-derive
    from the FINAL verdict at every read-time site — an upgraded
    bypassable->vulnerable row ranks high, a downgraded one medium."""
    from core.reporter import _severity_fields

    row = {"finding": "vulnerable", "severity": "medium", "severity_source": "derived"}
    assert _severity_fields(row) == {"severity": "high", "severity_source": "derived"}
    row = {"finding": "bypassable", "severity": "high", "severity_source": "derived"}
    assert _severity_fields(row) == {"severity": "medium", "severity_source": "derived"}
    row = {"finding": "bypassable", "severity": "critical", "severity_source": "model"}
    assert _severity_fields(row) == {"severity": "critical", "severity_source": "model"}
    # a CORRECTED value re-derives its rank (the repair's extractor may have
    # fabricated it) but keeps the provenance label
    row = {"finding": "vulnerable", "severity": "low", "severity_source": "corrected"}
    assert _severity_fields(row) == {"severity": "high", "severity_source": "corrected"}
    # WAVE r3 #5: the SAME contract at the cli/csv copies (previously pinned
    # on the reporter only — a divergence there could not go RED)
    from openant.cli import _severity_for_result as _cli_sev
    from report.csv_export import _severity_for as _csv_sev
    assert _cli_sev({"finding": "vulnerable", "severity": "low",
                     "severity_source": "corrected"}) == "high"
    assert _csv_sev({"finding": "vulnerable", "severity": "low",
                     "severity_source": "corrected"}) == "high"
    assert _cli_sev({"finding": "bypassable", "severity": "high",
                     "severity_source": "derived"}) == "medium"
    assert _csv_sev({"finding": "bypassable", "severity": "high",
                     "severity_source": "derived"}) == "medium"
    assert _cli_sev({"finding": "vulnerable", "severity": "critical",
                     "severity_source": "model"}) == "critical"
    assert _csv_sev({"finding": "vulnerable", "severity": "critical",
                     "severity_source": "model"}) == "critical"


def test_read_time_sites_gate_non_findings():
    from report.csv_export import _severity_for
    from openant.cli import _severity_for_result

    for row in ({"finding": "safe"}, {"finding": "error"},
                {"verdict": "ERROR"}, {"reasoning": "refusal"}):
        assert _severity_for(row) == "", row
        assert _severity_for_result(row) == "", row


def test_corrected_record_severity_behavior(monkeypatch):
    """Wave r1 (prod#5) + r2 (t#4): the corrected-adoption provenance, as
    BEHAVIOR (the r1 grep pin could not fail under mutation). Drive the real
    analyze_unit with a stubbed parse + corrector: a garbage corrected
    severity lands DERIVED (r2 c#1: the restamp must not relabel derived as
    corrected); a valid one lands CORRECTED."""
    from core import analysis_core
    import utilities.json_corrector as jc

    class _Adapter:
        name = "anthropic"
        supports_tools = True

        def complete(self, **kwargs):
            from utilities.llm.adapter import TextBlock as _TB
            class _Reply:
                # the adapter-shaped reply: content blocks + usage
                content = [_TB(text="garbled prose")]  # unparseable
                input_tokens = 1
                output_tokens = 1
                def __getattr__(self, name):
                    return None
            return _Reply()

        def validate(self, model):  # pragma: no cover
            pass

    def _tool_binding():
        from utilities.llm import PhaseBinding
        return PhaseBinding(phase="analyze", adapter=_Adapter(),
                            model="claude-test", provider_name="anthropic")

    # the direct parse fails (ERROR verdict) -> the corrector is consulted
    monkeypatch.setattr(analysis_core, "parse_response",
                        lambda r: {"verdict": "ERROR", "finding": "error"})
    binding = _tool_binding()

    def corrected_extract_with(valid):
        def fake_simple_text(binding, prompt, **k):
            sev = '"severity": "HIGH"' if valid else '"severity": "garbage"'
            return ('{"finding": "vulnerable", ' + sev +
                    ', "reasoning": "r", "cwe_id": 79}')
        return fake_simple_text

    for valid, want_src, want_sev in ((True, "corrected", "high"),
                                      (False, "derived", "high")):
        monkeypatch.setattr(jc, "simple_text", corrected_extract_with(valid))
        out = analysis_core.analyze_unit(
            binding=binding,
            unit={"id": "f.py:g", "code": {"primary_code": "x = 1"}},
            json_corrector=jc.JSONCorrector(binding))
        assert out.get("verdict") == "VULNERABLE", (valid, out.get("verdict"))
        assert out.get("severity") == want_sev, (valid, out.get("severity"))
        assert out.get("severity_source") == want_src, (valid, out.get("severity_source"))


def test_summary_prompt_receives_severity():
    """Wave finding (surf#1): _compact_for_summary's fixed key list never
    included severity — the summary column was LLM-guessed."""
    from report.generator import _compact_for_summary

    data = {"findings": [{"id": "VULN-001", "severity": "high",
                          "severity_source": "model"}]}
    compact = _compact_for_summary(data)
    assert compact["findings"][0]["severity"] == "high"
    assert compact["findings"][0]["severity_source"] == "model"


def test_summary_template_row_has_severity_cell():
    from pathlib import Path as P
    tpl = (P(__file__).resolve().parents[1] / "report" / "prompts" / "summary.txt").read_text()
    assert "{severity}" in tpl
    assert "lowercase" not in tpl
    assert tpl.count("| # | Vulnerability | Location | CWE | Severity | Verified |") == 1


def test_max_iterations_downgrade_strips_severity():
    """Wave r2 (both): the 'Max iterations reached' downgrade displays an
    inconclusive row — its severity must be EMPTY (no CRITICAL badge on an
    unverified row; no inconclusive.critical rule in Code Scanning)."""
    from openant.cli import _severity_for_result

    row = {"finding": "vulnerable", "severity": "critical",
           "severity_source": "model",
           "verification": {"explanation": "Max iterations reached"}}
    assert _severity_for_result(row, "inconclusive") == ""
    # and without the downgrade: the model value keeps
    assert _severity_for_result(row, "vulnerable") == "critical"


def test_twin_severity_parity():
    """Wave r2 (both): the twin stamps AFTER the uppercase fold (core's
    order — stamping before it lost a model severity on a lowercase-verdict
    reply), and the severity block is finding-gated."""
    from utilities.context_corrector import ContextCorrector

    nr = ContextCorrector._normalize_result
    # lowercase verdict, model severity (direct-parse paths feed the twin
    # exactly this shape) — the fold happens FIRST, the stamp keeps it
    out = nr({"verdict": "vulnerable", "severity": "critical"})
    assert out["verdict"] == "VULNERABLE"
    assert out["severity"] == "critical" and out["severity_source"] == "model"
    # finding-gated
    out = nr({"verdict": "safe", "severity": "critical"})
    assert "severity" not in out
    # shared enum (no drift)
    out = nr({"finding": "vulnerable", "severity": "HIGH"})
    assert out["severity"] == "high" and out["severity_source"] == "model"


def test_summary_table_is_contiguous():
    """Wave r2 (t#5): a blank line between the separator and the example
    row terminates the markdown table (the exemplar the summary LLM copies
    was header-only + an orphan row). Every findings-table line contiguous."""
    from pathlib import Path as P
    lines = (P(__file__).resolve().parents[1] / "report" / "prompts"
             / "summary.txt").read_text().split("\n")
    i = next(k for k, l in enumerate(lines)
             if l.startswith("| # | Vulnerability"))
    assert lines[i + 1].startswith("|---"), "separator row must follow directly"
    assert lines[i + 2].startswith("| 1 |") and "{severity}" in lines[i + 2], (
        "the example row must be contiguous and carry the severity cell")


def test_the_one_severity_enum_everywhere():
    """Wave r2 (t#10): five copies of the enum diverged silently — the
    canonical home is verdict_taxonomy; every importer shares it."""
    import importlib
    import openant.cli as cli
    import report.csv_export as csvx
    from core import analysis_core, reporter
    from core.verdict_taxonomy import SEVERITIES

    assert analysis_core.SEVERITIES is SEVERITIES
    assert csvx._SEVERITIES is SEVERITIES
    assert cli._SEVERITY_ORDER is SEVERITIES
    # reporter imports SEVERITIES by name; the value must be the same object
    assert importlib.import_module("core.reporter").SEVERITIES is SEVERITIES


def test_report_data_projection_wires_severity():
    """Deep-refute #2: the Python->Go key contract is unpinned — deleting
    the projection lines left every test green. Source-pin (weak form
    acknowledged) + the Go tags pinned on the Go side."""
    import inspect
    import openant.cli as cli

    src = inspect.getsource(cli)
    i = src.find("findings.append({")
    block = src[i:i+1200]
    assert '"severity": _sev' in block and '"severity_source": _sev_src' in block, (
        "the report-data projection must wire severity + severity_source")
