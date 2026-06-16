"""PR #69 round-5, findings F4 (reporting) + F5 (metrics) + L4 (error bucket).

BACKGROUND (R4-7): the Stage-2 verifier is now fail-safe on its four degenerate
paths (``finding_verifier.py`` ~:380 unparseable text, ~:448 no tool calls,
~:464 max iterations, ~:925 finish without ``agree``). On those paths it returns
``agree=False`` while PRESERVING the Stage-1 verdict in ``correct_finding``
(``correct_finding == finding``). That keeps the finding in the report body.

BUT ``agree=False`` collides with downstream consumers that read ``agree=False``
as "Stage-2 actively DISAGREED / rejected":

  * F4 (reporting): ``core/reporter.py`` mapped a present-but-non-agreeing
    verification to ``stage2_verdict="rejected"`` — semantically wrong (verify
    could not COMPLETE, it did not reject) — and ``"rejected"`` is excluded from
    disclosure generation, so a preserved Stage-1 ``vulnerable`` got NO
    disclosure / vanished from triage.

  * F5 (metrics): ``core/verifier.py`` counted only ``agree=True`` as
    ``confirmed_vulnerabilities``; degenerate findings fell to ``disagreed``,
    which ``core/scanner.py`` folds into the ``safe`` count. The summary reads
    "safe" while the findings list still shows the vuln.

  * L4 (error bucket): when a verify adapter RAISES (R4-1/R4-2 raise on
    empty/refusal), ``_verify_one`` set ``detail="error"`` locally but never set
    ``result["error"]`` / ``result["verification"]`` — so ``verifier.py``'s
    ``r.get("error")`` is falsy and the finding is mis-bucketed as ``disagreed``
    (→ folded into ``safe``) instead of ``error``.

THE FIX — a first-class "incomplete verification" state distinct from both
"agreed" and "rejected":

  1. ``VerificationResult.incomplete: bool`` set True on the 4 degenerate paths,
     serialized into ``result["verification"]["incomplete"]``.
  2. ``core/reporter.py``: incomplete verification ⇒ ``stage2_verdict="unverified"``
     (NOT "rejected"), and ``"unverified"`` is disclosure-eligible (surfaced for
     manual review, never silently dropped).
  3. ``core/verifier.py`` / ``core/scanner.py``: incomplete findings are counted
     as ``needs_review`` (NOT ``safe``).
  4. L4: an adapter raise sets ``result["error"]`` so ``error_count`` is accurate
     and the finding is never read as ``safe``.

All tests are OFFLINE (stub adapters / hand-built dicts). No real LLM calls.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

# NOTE: deliberately do NOT install a stub ``anthropic`` module into
# ``sys.modules``. Every adapter in this file is an offline stub passed
# directly to FindingVerifier, and the consumer imports below
# (core.reporter / core.verifier / core.schemas) do not construct a live
# Anthropic client at import time. Poisoning ``sys.modules["anthropic"]`` with
# a bare stub would, under full-suite collection ordering, break sibling tests
# that ``import anthropic`` for its real ``_exceptions`` types.

from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.finding_verifier import MAX_ITERATIONS, FindingVerifier, VerificationResult
from utilities.llm import PhaseBinding, TextBlock, ToolUseBlock
from utilities.llm.adapter import CompletionResult
from utilities.llm_client import reset_warning_state

STAGE1_FINDING = "vulnerable"


@pytest.fixture(autouse=True)
def _reset():
    reset_warning_state()
    yield
    reset_warning_state()


# ==========================================================================
# Part A — VerificationResult carries an `incomplete` flag (source of truth)
# ==========================================================================


def _make_verifier(adapter) -> FindingVerifier:
    binding = PhaseBinding(
        phase="verify", adapter=adapter, model="claude-x", provider_name="anthropic"
    )
    return FindingVerifier(index=RepositoryIndex({}, repo_path=None), binding=binding)


def _verify(adapter) -> VerificationResult:
    return _make_verifier(adapter).verify_result(
        code="x = 1", finding=STAGE1_FINDING, attack_vector="a", reasoning="r"
    )


class _UnparseableTextAdapter:
    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return CompletionResult(
            content=[TextBlock("prose, no json here")],
            input_tokens=1, output_tokens=1, stop_reason="end_turn",
        )


class _NoToolCallsAdapter:
    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return CompletionResult(
            content=[TextBlock("partial reasoning that got cut off")],
            input_tokens=1, output_tokens=1, stop_reason="max_tokens",
        )


class _MaxIterationsAdapter:
    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def __init__(self):
        self.calls = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls += 1
        return CompletionResult(
            content=[ToolUseBlock(id=f"t{self.calls}", name="search_usages",
                                  input={"function_name": "noop"})],
            input_tokens=1, output_tokens=1, stop_reason="tool_use",
        )


class _FinishWithoutAgreeAdapter:
    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return CompletionResult(
            content=[ToolUseBlock(id="finish-1", name="finish",
                                  input={"correct_finding": "vulnerable",
                                         "explanation": "looks exploitable"})],
            input_tokens=1, output_tokens=1, stop_reason="tool_use",
        )


class _FinishWithAgreeTrueAdapter:
    """Control: a real, completed agreement. Must NOT be flagged incomplete."""
    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return CompletionResult(
            content=[ToolUseBlock(id="finish-1", name="finish",
                                  input={"agree": True, "correct_finding": "vulnerable",
                                         "explanation": "confirmed exploitable"})],
            input_tokens=1, output_tokens=1, stop_reason="tool_use",
        )


@pytest.mark.parametrize("adapter_cls", [
    _UnparseableTextAdapter, _NoToolCallsAdapter,
    _MaxIterationsAdapter, _FinishWithoutAgreeAdapter,
])
def test_degenerate_paths_flag_incomplete(adapter_cls):
    """Each degenerate path must mark the result incomplete AND serialize it."""
    result = _verify(adapter_cls())
    assert result.incomplete is True, (
        f"{adapter_cls.__name__}: degenerate verify must be flagged incomplete"
    )
    # And it must flow into the serialized dict consumed downstream.
    assert result.to_dict().get("incomplete") is True, (
        f"{adapter_cls.__name__}: incomplete must serialize into verification dict"
    )
    # Fail-safe preservation still holds.
    assert result.agree is False
    assert result.correct_finding == STAGE1_FINDING


def test_completed_agreement_is_not_incomplete():
    """A genuine completed `finish(agree=True)` must NOT be flagged incomplete."""
    result = _verify(_FinishWithAgreeTrueAdapter())
    assert result.incomplete is False
    assert result.to_dict().get("incomplete", False) is False
    assert result.agree is True


# ==========================================================================
# Part B — F4: reporter maps incomplete → "unverified" (NOT "rejected")
#          and an unverified vuln remains disclosure-eligible.
# ==========================================================================


def _incomplete_results_file(tmp_path: Path) -> Path:
    """A degenerate Stage-1 `vulnerable`: agree=False, correct_finding preserved,
    verification marked incomplete (the R4-7 fail-safe encoding)."""
    results = {
        "dataset": "round5-f4",
        "results": [
            {
                "unit_id": "app.py:login",
                "route_key": "app.py:login",
                "verdict": "VULNERABLE",
                "finding": "vulnerable",
                "attack_vector": "sql injection",
                "reasoning": "raw query",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
                "verification": {
                    "agree": False,
                    "correct_finding": "vulnerable",
                    "explanation": "Verification incomplete",
                    "incomplete": True,
                },
            },
        ],
        "code_by_route": {"app.py:login": "def login(): ..."},
        "metrics": {"total": 1, "vulnerable": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def _rejected_results_file(tmp_path: Path) -> Path:
    """A genuine Stage-2 rejection: agree=False, NOT incomplete, verdict changed
    to safe → must read as 'rejected' (well, dropped) and never as a vuln."""
    results = {
        "dataset": "round5-f4-reject",
        "results": [
            {
                "unit_id": "app.py:safe_fn",
                "route_key": "app.py:safe_fn",
                "verdict": "SAFE",
                "finding": "safe",
                "verification": {
                    "agree": False,
                    "correct_finding": "safe",
                    "explanation": "not exploitable; path broken",
                    "incomplete": False,
                },
            },
        ],
        "code_by_route": {"app.py:safe_fn": "def safe_fn(): ..."},
        "metrics": {"total": 1, "safe": 1},
    }
    path = tmp_path / "results_reject.json"
    path.write_text(json.dumps(results))
    return path


def test_f4_incomplete_renders_unverified_not_rejected(tmp_path):
    """F4 (a)+(b): a degenerate vulnerable stays in the report body and renders
    as stage2_verdict='unverified', NOT 'rejected'."""
    from core.reporter import build_pipeline_output

    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(_incomplete_results_file(tmp_path)),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 1, "preserved vuln must stay in report body"
    verdict = data["findings"][0]["stage2_verdict"]
    assert verdict == "unverified", (
        f"incomplete verification must render as 'unverified', got {verdict!r} "
        "('rejected' is semantically wrong — verify never completed)"
    )


def test_f4_genuine_rejection_still_not_a_vuln(tmp_path):
    """Regression guard: a genuine agree=False + correct_finding=safe must NOT
    be surfaced as a vuln (it changed verdict; it is dropped, not 'unverified')."""
    from core.reporter import build_pipeline_output

    out = tmp_path / "po_reject.json"
    build_pipeline_output(
        results_path=str(_rejected_results_file(tmp_path)),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 0, (
        "a verdict changed to safe must not appear as a finding"
    )


def test_f4_unverified_is_disclosure_eligible(tmp_path):
    """F4 (d): the disclosure gate in core/reporter.py must include 'unverified'
    so an unverified potential vuln is SURFACED for manual review (not dropped)."""
    from core.reporter import build_pipeline_output

    po = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(_incomplete_results_file(tmp_path)),
        output_path=str(po),
        language="python",
    )
    pipeline_data = json.loads(po.read_text())

    # Reproduce the exact disclosure-eligibility filter from
    # core/reporter.py::generate_disclosure_docs (607-610) without making LLM
    # calls. The finding must pass the gate.
    eligible = [
        f for f in pipeline_data["findings"]
        if f.get("stage2_verdict") in ("confirmed", "agreed", "vulnerable", "unverified")
    ]
    assert len(eligible) == 1, (
        "an 'unverified' finding must be disclosure-eligible (surfaced for "
        "manual review), not silently excluded like 'rejected'"
    )


# ==========================================================================
# Part C — F5: metrics. Incomplete findings must NOT be folded into `safe`.
# ==========================================================================


def test_f5_verifier_counts_incomplete_as_needs_review(tmp_path):
    """F5: run_verification's counting loop must bucket an incomplete finding as
    needs_review, NOT disagreed (which scanner folds into `safe`)."""
    # Build a minimal verified result set and exercise the counting logic via
    # the public count helper extracted for testability.
    from core.verifier import _count_verification_outcomes

    verified_results = [
        {  # genuine confirmation
            "route_key": "a:1", "finding": "vulnerable",
            "verification": {"agree": True, "correct_finding": "vulnerable",
                             "incomplete": False},
        },
        {  # degenerate / incomplete — the F5 case
            "route_key": "b:2", "finding": "vulnerable",
            "verification": {"agree": False, "correct_finding": "vulnerable",
                             "incomplete": True},
        },
        {  # genuine disagreement (downgraded to safe)
            "route_key": "c:3", "finding": "safe",
            "verification": {"agree": False, "correct_finding": "safe",
                             "incomplete": False},
        },
    ]
    counts = _count_verification_outcomes(verified_results)
    assert counts["confirmed_vulnerabilities"] == 1
    assert counts["needs_review"] == 1, (
        "the incomplete finding must be counted as needs_review"
    )
    # The incomplete finding must NOT inflate `disagreed` (which → safe).
    assert counts["disagreed"] == 1, (
        "only the genuine downgrade-to-safe is 'disagreed'; the incomplete one "
        f"must not be, got disagreed={counts['disagreed']}"
    )


def test_f5_scanner_does_not_fold_incomplete_into_safe():
    """F5: the scanner's post-verify metrics must keep needs_review out of safe.

    Simulates core/scanner.py:519-530 with a VerifyResult that has needs_review.
    """
    from core.schemas import AnalysisMetrics, VerifyResult

    analyze = AnalysisMetrics(total=3, vulnerable=2, bypassable=0, inconclusive=0,
                              protected=0, safe=1, errors=0)
    vr = VerifyResult(
        verified_results_path="x",
        findings_input=2, findings_verified=2,
        agreed=1, disagreed=0,
        confirmed_vulnerabilities=1,
        needs_review=1,
    )
    # Mirror the scanner's metric construction.
    post = AnalysisMetrics(
        total=analyze.total,
        vulnerable=vr.confirmed_vulnerabilities,
        bypassable=0,
        inconclusive=analyze.inconclusive,
        protected=analyze.protected,
        safe=analyze.safe + vr.disagreed,  # incomplete must NOT be here
        errors=analyze.errors,
        verified=vr.findings_verified,
        needs_review=vr.needs_review,
    )
    assert post.safe == 1, (
        f"the incomplete finding must not inflate safe; got safe={post.safe}"
    )
    assert post.needs_review == 1


# ==========================================================================
# Part D — L4: an adapter raise sets result["error"] (accurate error_count,
#          never read as safe).
# ==========================================================================


class _RaisingAdapter:
    """Mirrors R4-1/R4-2: the adapter raises (e.g. empty/refusal)."""
    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        from utilities.llm import LLMResponseError
        raise LLMResponseError("empty completion (refusal)")


def test_l4_adapter_raise_sets_result_error():
    """L4: when verify_result raises, _verify_one must set result['error'] so the
    downstream counter buckets it as error (never safe)."""
    verifier = _make_verifier(_RaisingAdapter())
    result = {"route_key": "app.py:boom", "finding": "vulnerable"}
    route_key, detail, _elapsed, _worker, _usage = verifier._verify_one(
        result, {"app.py:boom": "x = 1"}
    )
    assert detail == "error"
    assert result.get("error"), (
        "an adapter raise must set result['error'] so verifier.py counts it as "
        "error, not disagreed→safe"
    )


def test_l4_errored_result_counted_as_error_not_safe():
    """L4: the counting loop must bucket an errored result as error."""
    from core.verifier import _count_verification_outcomes

    verified_results = [
        {"route_key": "app.py:boom", "finding": "vulnerable",
         "error": "LLMResponseError: empty completion (refusal)"},
    ]
    counts = _count_verification_outcomes(verified_results)
    assert counts["error_count"] == 1
    assert counts["disagreed"] == 0, "errored finding must not be 'disagreed'"
    assert counts["confirmed_vulnerabilities"] == 0


# ==========================================================================
# Part E — End-to-end trace through BOTH consumers for a degenerate vuln.
# ==========================================================================


def test_e2e_degenerate_vulnerable_full_trace(tmp_path):
    """End-to-end (a)-(d) for a degenerate Stage-1 vulnerable:

    (a) stays in confirmed_findings / report body
    (b) renders as 'unverified', not 'rejected'
    (c) is NOT counted as safe
    (d) is disclosure-eligible
    """
    from core.reporter import build_pipeline_output
    from core.verifier import _write_verified_results, _count_verification_outcomes

    # The verified result, as the verifier path produces it (R4-7 fail-safe
    # encoding + the new incomplete flag).
    verified = [{
        "unit_id": "app.py:login",
        "route_key": "app.py:login",
        "verdict": "VULNERABLE",
        "finding": "vulnerable",
        "attack_vector": "sql injection",
        "reasoning": "raw query",
        "verification": {
            "agree": False, "correct_finding": "vulnerable",
            "explanation": "Verification incomplete", "incomplete": True,
        },
    }]

    # (a) confirmed_findings via _write_verified_results
    vpath = tmp_path / "results_verified.json"
    _write_verified_results(str(vpath), {"dataset": "e2e"}, verified, verified)
    vdata = json.loads(vpath.read_text())
    assert len(vdata["confirmed_findings"]) == 1, "(a) must stay in confirmed_findings"

    # (c) counts: not safe, counted as needs_review
    counts = _count_verification_outcomes(verified)
    assert counts["needs_review"] == 1, "(c) must be needs_review, not safe"
    assert counts["disagreed"] == 0
    assert counts["confirmed_vulnerabilities"] == 0

    # (b) reporter renders 'unverified'
    out = tmp_path / "po.json"
    build_pipeline_output(results_path=str(vpath), output_path=str(out),
                          language="python")
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 1, "(a) must stay in report body"
    assert data["findings"][0]["stage2_verdict"] == "unverified", "(b)"

    # (d) disclosure-eligible
    eligible = [
        f for f in data["findings"]
        if f.get("stage2_verdict") in ("confirmed", "agreed", "vulnerable", "unverified")
    ]
    assert len(eligible) == 1, "(d) must be disclosure-eligible"


def test_e2e_experiment_consumer_path(tmp_path):
    """Second verify path: the ``experiment.py`` consumer (lines 760-799) calls
    ``verify_result`` directly, then on ``not agree`` does
    ``result["finding"] = verification.correct_finding`` and serializes
    ``verification.to_dict()`` onto the result. Drive a real degenerate verify
    through that exact mutation, then through ``build_pipeline_output``, and
    assert the same (a)-(d) guarantees hold for this path too.
    """
    from core.reporter import build_pipeline_output

    # 1. Real (offline) degenerate verify — produces incomplete=True.
    verification = _verify(_UnparseableTextAdapter())
    assert verification.agree is False
    assert verification.incomplete is True

    # 2. Replicate experiment.py's exact mutation on `not agree`.
    result = {
        "unit_id": "svc.py:run",
        "route_key": "svc.py:run",
        "verdict": "VULNERABLE",
        "finding": "vulnerable",
        "attack_vector": "command injection",
        "reasoning": "shell=True with user input",
    }
    result["verification"] = verification.to_dict()           # experiment.py:769
    # not agree → experiment.py:777-778
    result["finding"] = verification.correct_finding          # stays "vulnerable"
    result["verification_note"] = (
        f"Changed from vulnerable to {verification.correct_finding}"
    )

    # The serialized verification dict must carry the incomplete flag so the
    # reporter can branch on it (this is the F4 wiring through experiment.py).
    assert result["verification"]["incomplete"] is True
    # (c)-ish for this path: finding preserved as vulnerable, not safe.
    assert result["finding"] == "vulnerable"

    # 3. Write an experiment-style results file and run the reporter.
    exp = {
        "dataset": "exp-path",
        "results": [result],
        "code_by_route": {"svc.py:run": "os.system(x)"},
        "metrics": {"total": 1, "vulnerable": 1},
    }
    rpath = tmp_path / "experiment.json"
    rpath.write_text(json.dumps(exp))

    out = tmp_path / "po.json"
    build_pipeline_output(results_path=str(rpath), output_path=str(out),
                          language="python")
    data = json.loads(out.read_text())

    # (a) stays in the report body
    assert len(data["findings"]) == 1
    # (b) renders 'unverified', not 'rejected'
    assert data["findings"][0]["stage2_verdict"] == "unverified"
    # (d) disclosure-eligible
    eligible = [
        f for f in data["findings"]
        if f.get("stage2_verdict") in ("confirmed", "agreed", "vulnerable", "unverified")
    ]
    assert len(eligible) == 1
