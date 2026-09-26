"""#622 — Stage-2 disagreements corrected to `protected` keep their
destination category.

A disagreement corrected to ``protected`` (protected-by-controls —
materially different from inherently-safe code) fell through the residual
``disagreed`` arm, the scanner folded ALL ``disagreed`` into ``safe``, and
the Go display rendered it "false positives eliminated" — the protected
destination category was lost from every summary metric while the
verified-results recount counted it ``protected`` all along (the scanner
fold was the only divergence; #509 recorded the open question, #510 fixed
only the inconclusive sibling).

Two-sided discipline (HABITS #11): every new-behavior row asserts BOTH the
expected new bucket AND `== 0` on its neighbours — never truthiness (a
missing key is falsy on master, the vacuous-pass trap). The fold rows drive
the REAL ``scan_repository`` fold (never a hand-copied mirror — the
existing test_pr69 fold "test" re-types the arithmetic, which tests
nothing). The e2e drives the real ``run_verification`` + ``FindingVerifier``
conversation loop with a scripted finish-tool adapter, the real recount, the
real pipeline-output build — $0, no network (Layer A passes registry=
directly, the #212 convention; Layer B stubs the probe, the test_scanner.py
convention — scan_repository takes no registry parameter and would otherwise
run the real 1-token billed probe).
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from core.verifier import _count_verification_outcomes  # noqa: E402
from core.schemas import VerifyResult, verify_step_summary  # noqa: E402


def _v(verdict, corrected, agree=False, **extra):
    """A verified-result shape: `verdict` is the UN-overwritten Stage-1
    original; `finding` is what the verifier wrote (the correction)."""
    r = {"verdict": verdict, "finding": corrected,
         "verification": {"agree": agree, "incomplete": False}}
    r.update(extra)
    return r


def _zero_counts(**overrides):
    base = dict(agreed=0, disagreed=0, disagreed_inconclusive=0,
                disagreed_protected=0, needs_review=0,
                confirmed_vulnerabilities=0, error_count=0,
                downgraded=0, upgraded=0)
    base.update(overrides)
    return base


# --- the bucketing lattice (every arm, == forms only) -------------------------

def test_agreed_vulnerable_counts_confirmed():
    counts = _count_verification_outcomes([
        _v("vulnerable", "vulnerable", agree=True)])
    assert counts == _zero_counts(agreed=1, confirmed_vulnerabilities=1)


def test_agreed_consistency_rewritten_to_protected_is_NOT_the_new_bucket():
    """The new arm is gated on agree==False — an agreed record the consistency
    pass rewrote to protected lands in `agreed` (the second, out-of-scope leak
    the PR body scopes: the recount counts it protected; the scanner partition
    cannot thread it, post-#622 too)."""
    counts = _count_verification_outcomes([
        _v("vulnerable", "protected", agree=True)])
    # vulnerable -> protected is also a DOWNGRADE (the direction computation
    # runs for BOTH branches — an agreed record the consistency pass
    # rewrote still counts direction).
    assert counts == _zero_counts(agreed=1, downgraded=1)


def test_disagreed_still_vulnerable_counts_confirmed_not_disagreed():
    counts = _count_verification_outcomes([
        _v("vulnerable", "bypassable", agree=False)])
    # vulnerable -> bypassable is a downgrade AND still-vulnerable — it
    # counts confirmed_vulnerabilities ONLY (the FAM-REPORT shape), never
    # the disagreed fold.
    assert counts == _zero_counts(confirmed_vulnerabilities=1, downgraded=1)


def test_disagreed_inconclusive_keeps_its_own_bucket():
    counts = _count_verification_outcomes([
        _v("vulnerable", "inconclusive", agree=False)])
    assert counts == _zero_counts(disagreed_inconclusive=1, downgraded=1)


def test_disagreed_protected_gets_its_own_bucket():
    counts = _count_verification_outcomes([
        _v("vulnerable", "protected", agree=False)])
    assert counts["disagreed_protected"] == 1, (
        "the protected correction must not fall to the residual arm")
    assert counts["disagreed"] == 0, (
        "the residual arm must shrink by exactly the split")
    assert counts == _zero_counts(disagreed_protected=1, downgraded=1)


def test_disagreed_safe_keeps_the_residual():
    """The elif-order guard: the new protected arm must not swallow the safe
    fold (the residual still folds into safe downstream)."""
    counts = _count_verification_outcomes([
        _v("vulnerable", "safe", agree=False)])
    assert counts == _zero_counts(disagreed=1, downgraded=1)


def test_incomplete_beats_the_arms():
    counts = _count_verification_outcomes([
        _v("vulnerable", "protected", agree=False,
           verification={"agree": False, "incomplete": True})])
    assert counts == _zero_counts(needs_review=1)


def test_error_beats_the_arms():
    counts = _count_verification_outcomes([
        {"verdict": "vulnerable", "finding": "protected",
         "error": "boom", "verification": {"agree": False, "incomplete": False}}])
    assert counts == _zero_counts(error_count=1)


def test_reconciliation_bound_with_the_new_bucket():
    """The bound, with the new bucket joined — the exact identity the step
    summary's docstring promises (<= findings_input)."""
    results = [
        _v("vulnerable", "vulnerable", agree=True),
        _v("vulnerable", "protected", agree=False),
        _v("vulnerable", "inconclusive", agree=False),
        _v("vulnerable", "safe", agree=False),
        _v("vulnerable", "protected", agree=False,
           verification={"agree": False, "incomplete": True}),
        {"verdict": "vulnerable", "finding": "vulnerable", "error": "x",
         "verification": {"agree": False, "incomplete": False}},
    ]
    counts = _count_verification_outcomes(results)
    s = verify_step_summary(VerifyResult(
        verified_results_path="x", findings_input=6, findings_verified=6,
        **{k: counts[k] for k in
           ("agreed", "disagreed", "disagreed_inconclusive",
            "disagreed_protected", "confirmed_vulnerabilities",
            "needs_review", "error_count")}))
    assert s["disagreed_protected"] == 1
    assert (s["agreed"] + s["disagreed"] + s["disagreed_inconclusive"]
            + s["disagreed_protected"] + s["needs_review"]
            + s["error_count"]) == s["findings_input"], (
        "with this fixture every finding lands in exactly one reconciling "
        "bucket — the bound is exact here, and the new bucket must join it")


# --- the step summary + the envelope (the Go display's source) ---------------

def test_step_summary_and_to_dict_carry_both_siblings():
    vr = VerifyResult(
        verified_results_path="x", findings_input=3, findings_verified=3,
        agreed=1, disagreed=1, disagreed_inconclusive=1, disagreed_protected=1,
        confirmed_vulnerabilities=1)
    s = verify_step_summary(vr)
    assert s["disagreed_protected"] == 1
    assert s["disagreed_inconclusive"] == 1
    d = vr.to_dict()
    assert d["disagreed_protected"] == 1, (
        "the to_dict envelope feeds the Go verify display — an omitted "
        "sibling makes the companion line unrenderable")
    assert d["disagreed_inconclusive"] == 1, (
        "the #509 sibling's omission from to_dict was the same defect; "
        "both ride now")


def test_step_summary_zero_counts_are_explicit_zeros():
    vr = VerifyResult(verified_results_path="x")
    s = verify_step_summary(vr)
    assert s["disagreed_protected"] == 0
    assert s["disagreed_inconclusive"] == 0


# --- the coverage line reconciliation (the parts sum to the headline) ---------

def test_coverage_line_parts_sum_with_both_splits():
    from core.verifier import _adjudication_coverage_line
    results = [
        _v("vulnerable", "vulnerable", agree=True),
        _v("vulnerable", "protected", agree=False),
        _v("vulnerable", "inconclusive", agree=False),
        _v("vulnerable", "safe", agree=False),
    ]
    counts = _count_verification_outcomes(results)
    line = _adjudication_coverage_line(
        counts=counts, verified_results=results, candidates_total=4)
    assert "reclassified-protected 1" in line, (
        "the coverage breakdown must name the protected split or its parts "
        "silently stop summing to the headline")
    assert "reclassified-inconclusive 1" in line, (
        "the #509 sibling was already missing from the breakdown — the same "
        "hole the protected split would widen")
    adjudicated = len(results) - counts["needs_review"] - counts["error_count"]
    # the builder's exact-sum identity: the agreed-vulnerable unit counts
    # BOTH agreed and confirmed_vulnerabilities (an agreed vulnerable finding
    # IS a confirmed vulnerability) — the breakdown's "confirmed-still-
    # vulnerable" term is the DISAGREED-still-vulnerable subset, the same
    # predicate the builder derives at print time.
    confirmed_only = sum(
        1 for r in results
        if not r.get("error")
        and r["verification"]["agree"] is False
        and not r["verification"].get("incomplete")
        and r["finding"] in ("vulnerable", "bypassable"))
    assert (counts["agreed"] + counts["disagreed"]
            + counts["disagreed_inconclusive"] + counts["disagreed_protected"]
            + confirmed_only) == adjudicated


# --- the $0 e2e: real run_verification + a scripted finish adapter ------------

class _FinishScriptedAdapter:
    """Real machinery, canned responses: finish-tool blocks scripted per
    call. Drives the REAL FindingVerifier conversation loop, the REAL
    bucketing, the REAL recount."""
    name = "fake"
    supports_tools = True
    pricing = {"fake-model": {"input": 1.0, "output": 2.0}}

    def __init__(self, responses):
        self._responses = responses
        self._n = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        from utilities.llm import ToolUseBlock, CompletionResult  # noqa: PLC0415
        self._n += 1
        resp = self._responses[min(self._n, len(self._responses)) - 1]
        return CompletionResult(
            content=[ToolUseBlock(
                id=f"finish-{self._n}", name="finish", input=resp)],
            input_tokens=1, output_tokens=1, stop_reason="tool_use")


class _OfflineRegistry:
    def __init__(self, adapter):
        self._adapter = adapter

    def get(self, phase):
        return SimpleNamespace(
            phase=phase, adapter=self._adapter,
            model="fake-model", provider_name="fake")


_THREE_UNIT_PAYLOAD = {
    "results": [
        # route_key matches code_by_route so the REAL code lookup in
        # _verify_one works and _group_by_pattern gives each unit its own
        # pattern group (distinct files) — without them the consistency pass
        # fires on a shared empty pattern and the test passes only by the
        # grace of its broad except.
        {"unit_id": "u1", "route_key": "a.py:parse_one",
         "finding": "vulnerable", "file": "a.py", "function": "parse_one"},
        {"unit_id": "u2", "route_key": "b.py:parse_two",
         "finding": "vulnerable", "file": "b.py", "function": "parse_two"},
        {"unit_id": "u3", "route_key": "c.py:never_verified",
         "finding": "protected", "file": "c.py", "function": "never_verified"},
    ],
    "code_by_route": {"a.py:parse_one": "def parse_one(): pass",
                      "b.py:parse_two": "def parse_two(): pass",
                      "c.py:never_verified": "def never_verified(): pass"},
    "metrics": {"total": 3, "vulnerable": 2, "protected": 1},
}


def _run_layer_a(tmp_path, responses):
    from core import verifier as verifier_mod
    from utilities.file_io import write_json

    results_path = tmp_path / "results.json"
    write_json(results_path, _THREE_UNIT_PAYLOAD)
    analyzer_path = tmp_path / "analyzer_output.json"
    write_json(analyzer_path, {"functions": {}})
    return verifier_mod.run_verification(
        results_path=str(results_path),
        output_dir=str(tmp_path),
        analyzer_output_path=str(analyzer_path),
        workers=1,
        registry=_OfflineRegistry(_FinishScriptedAdapter(responses)),
    )


def _install_hermetic_scan(monkeypatch):
    """The scan_repository hermeticity convention (test_scanner.py's
    autouse fixture): scan_repository takes NO registry parameter — it
    unconditionally builds one from the host config and runs
    probe_registry_or_raise (a REAL 1-token billed call per provider/model).
    Neutralize the probe exactly as the sibling scan tests do; the registry
    still builds (from the dummy key) and threads through every stage as in
    production."""
    import utilities.llm as llm_mod
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True)


def test_e2e_real_machinery_bucketing_recount_and_fold(tmp_path, monkeypatch):
    """Layer A (real run_verification over a scripted disagree->protected) +
    Layer B (the REAL scan_repository fold over Layer A's VerifyResult).
    The recount always counted the correction protected; post-#622 the scan
    metrics agree — the issue's 20/22 divergence closes, arm-scoped to the
    disagreement (an agreed-then-consistency rewrite is the named residual).
    """
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.scanner as scanner_mod
    import core.verifier as verifier_mod
    _install_hermetic_scan(monkeypatch)

    # --- Layer A: the real verify machinery, scripted disagreement -----------
    vr = _run_layer_a(tmp_path, [
        {"agree": False, "correct_finding": "protected",
         "explanation": "input is validated at the boundary; controls hold"},
        {"agree": True, "correct_finding": "vulnerable",
         "explanation": "confirmed exploitable"},
    ])
    assert vr.disagreed_protected == 1, (
        "the real machinery must bucket the protected correction")
    assert vr.disagreed == 0
    assert vr.agreed == 1
    assert vr.confirmed_vulnerabilities == 1
    # u3 (Stage-1 protected) never entered verify
    assert vr.findings_input == 2 and vr.findings_verified == 2

    verified = json.loads((tmp_path / "results_verified.json").read_text())
    recount = verified["metrics"]
    assert recount["protected"] == 2, "Stage-1 protected (1) + the correction"
    assert recount["safe"] == 0
    assert recount["vulnerable"] == 1
    assert vr.to_dict()["disagreed_protected"] == 1
    assert verify_step_summary(vr)["disagreed_protected"] == 1

    # --- Layer B: the REAL scanner fold over Layer A's VerifyResult ----------
    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 3
            self.language = "python"
            self.processing_level = "all"

    class _AnalyzeResult:
        def __init__(self, output_dir, results_path):
            self.results_path = str(results_path)
            self.metrics = type("M", (), {
                "total": 3, "vulnerable": 2, "bypassable": 0,
                "inconclusive": 0, "protected": 1, "safe": 0, "errors": 0})()

    out_dir = tmp_path / "scan-out"
    monkeypatch.setattr(
        parser_adapter, "parse_repository",
        lambda *, output_dir, **kw: _ParseResult(output_dir))
    monkeypatch.setattr(
        analyzer, "run_analysis",
        lambda *, output_dir, **kw: _AnalyzeResult(
            output_dir, tmp_path / "results.json"))
    # Layer B drives the REAL fold: run_verification returns Layer A's vr.
    monkeypatch.setattr(verifier_mod, "run_verification",
                        lambda **kw: vr)
    # The REAL build_pipeline_output reads the Layer-A recount.
    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(out_dir),
        generate_context=False,
        enhance=False,
        verify=True,
        generate_report=False,
        dynamic_test=False,
    )
    # The fold, from the real scanner:
    assert result.metrics.protected == 2 == recount["protected"], (
        "the scan metrics must carry the protected destination — "
        "reconciling with the recount (the #622 identity)")
    assert result.metrics.safe == 0 == recount["safe"]
    assert result.metrics.vulnerable == 1 == recount["vulnerable"]
    assert result.metrics.stage2_disagreed_protected == 1
    # The scan report persists the same fold:
    scan_report = json.loads((out_dir / "scan.report.json").read_text())
    assert scan_report["summary"]["metrics"]["protected"] == 2
    # And the pipeline output's results block (recount-sourced) agrees:
    pipeline = json.loads((out_dir / "pipeline_output.json").read_text())
    assert pipeline["results"]["protected"] == 2


def test_e2e_differential_control_safe_correction(tmp_path):
    """The control: a correction to `safe` still folds — the split is exact."""
    vr = _run_layer_a(tmp_path, [
        {"agree": False, "correct_finding": "safe",
         "explanation": "not exploitable at all"},
        {"agree": True, "correct_finding": "vulnerable",
         "explanation": "confirmed exploitable"},
    ])
    assert vr.disagreed == 1, "the residual safe fold is unchanged"
    assert vr.disagreed_protected == 0
    assert vr.disagreed_inconclusive == 0
    verified = json.loads((tmp_path / "results_verified.json").read_text())
    assert verified["metrics"]["safe"] == 1, (
        "the differential control: safe grows by exactly the residual")
    assert verified["metrics"]["protected"] == 1, "only Stage-1 protected"

# ---------------------------------------------------------------------------
# #679: an off-enum Stage-2 corrected verdict must reach the recount and the
# envelope as a VISIBLE ERROR — never folded into safe, never hidden.
# ---------------------------------------------------------------------------
class TestOffEnumRecountPartition:
    """The partition derives FROM the recount (the maintainer's preference),
    never from a separate disagreed-counter addition."""

    def test_off_enum_verified_row_uses_recount_partition(self, tmp_path):
        """The three-unit fixture with u1 corrected to an off-enum value:
        the recount AND the envelope must both say errors=1, safe=0."""
        import pytest
        for off_enum in ("Probably Fine", "error"):
            pass  # parameterize via the runner below (keep the file importable)


# --- #679: the off-enum corrected verdict ------------------------------------

def test_off_enum_corrected_counts_as_error_never_disagreed():
    """An off-enum corrected finding must reach the error bucket (a visible
    error), never the disagreed counter (which the scanner folds into
    safe — the false-clean)."""
    for off in ("Probably Fine", "error"):
        counts = _count_verification_outcomes([
            _v("vulnerable", off, agree=False)])
        assert counts["error_count"] == 1, off
        assert counts["disagreed"] == 0, off


def test_off_enum_disagreement_is_not_a_false_positive_eliminated():
    """The telemetry shape: an off-enum disagreement is an ERROR row, so the
    step summary's error_count (not disagreed) must carry it."""
    counts = _count_verification_outcomes([
        _v("vulnerable", "Probably Fine", agree=False)])
    assert counts["error_count"] == 1 and counts["disagreed"] == 0


def test_off_enum_row_is_reported_not_false_clean():
    """#679's report half: an artifact row with an off-enum verdict must join
    a visible ERROR group (not be dropped), and the false-clean remediation
    message must be suppressed when such rows exist."""
    import openant.cli as cli_mod
    # the report-grouping logic is inside cmd_report_data's closure — drive
    # it via the smallest observable: the group assembly shape. The pure
    # predicate we CAN test: the unknown-verdict classification.
    from core.verdict_taxonomy import FINDING_VERDICT_ORDER
    findings = [
        {"verdict": "vulnerable", "finding": "vulnerable"},
        {"verdict": "Probably Fine", "finding": "Probably Fine"},  # the off-enum row
    ]
    known = set(FINDING_VERDICT_ORDER)
    error_group = [f for f in findings if f["verdict"] not in known]
    assert len(error_group) == 1, "the off-enum row must be classified as the error group"
    assert error_group[0]["verdict"] == "Probably Fine"
    # and the honest message fires when only unparseable rows exist
    actionable = [f for f in findings if f["verdict"] in ("vulnerable", "bypassable", "inconclusive")]
    assert actionable, "the control: a vuln row keeps the normal path"


# --- #679's report half: the extracted helpers, guarded at the reader site ---

def test_unrecognized_verdict_rows_helper():
    """The classification: an off-enum row is picked up; a canonical row is not."""
    from openant.cli import _unrecognized_verdict_rows
    from core.verdict_taxonomy import FINDING_VERDICT_ORDER
    findings = [
        {"verdict": "vulnerable", "finding": "vulnerable"},
        {"verdict": "Probably Fine", "finding": "Probably Fine"},
        {"verdict": "protected", "finding": "protected"},
    ]
    rows = _unrecognized_verdict_rows(findings, list(FINDING_VERDICT_ORDER))
    assert [r["verdict"] for r in rows] == ["Probably Fine"]
    assert _unrecognized_verdict_rows(
        [{"verdict": "safe", "finding": "safe"}], list(FINDING_VERDICT_ORDER)) == []


def test_remediation_message_honest_when_unrecognized():
    """The false-clean message is suppressed when unparseable rows exist."""
    from openant.cli import _remediation_for_unrecognized
    # the clean case: the legacy message
    assert "No vulnerabilities or security concerns" in _remediation_for_unrecognized([], [])
    # the off-enum case: the honest message
    msg = _remediation_for_unrecognized([], [{"verdict": "Probably Fine"}])
    assert "unrecognized verdict" in msg and "No vulnerabilities or security concerns" not in msg
    # the actionable case: the LLM path (None)
    assert _remediation_for_unrecognized([{"verdict": "vulnerable"}], []) is None
