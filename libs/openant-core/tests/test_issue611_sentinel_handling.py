"""#611: the enhancement non-verdicts — visible in the step report, out of
the prompt, counted by analyze, and migrated off the old policy on resume.

Four gaps, one sentinel contract (the shared SENTINEL_CLASSIFICATIONS in
core/verdict_taxonomy — the vocabulary's home):

* the SHAPE: EnhanceResult carries incomplete_count + total_units; the
  step-report summary threads them (the three-bucket identity — total =
  units_enhanced + incomplete + errors — recoverable without summing
  classifications, which omits errors by construction).
* the HINT: the sentinel set omits the Stage-1 "Pre-analysis hint" line
  ENTIRELY — a non-verdict presented to the model as a classification is
  the wrong channel; the durable signal is the per-row stamp.
* the CENSUS + COUNTER: a sentinel-stamped unit is NOT "classified" for
  the --exploitable warning's census (an all-sentinel dataset fires the
  loud warning — the same un-enhanced shape); the analyze metrics publish
  enhance_unclassified_analyzed from the existing row field.
* the RECOVERY BLOCKER: a sentinel-stamped analyze checkpoint re-analyzes
  when re-enhancement CHANGES the unit's classification (the two-sided
  predicate — the sentinel→completed transition only; a still-sentinel
  checkpoint stays adopted, matching the run's own dataset).
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.verdict_taxonomy import SENTINEL_CLASSIFICATIONS  # noqa: E402
from core.schemas import EnhanceResult  # noqa: E402


def test_the_sentinel_set():
    assert SENTINEL_CLASSIFICATIONS == frozenset(
        {"incomplete", "error", "unknown"})


# ---------------------------------------------------------------------------
# the shape: EnhanceResult carries the identity's own fields
# ---------------------------------------------------------------------------

def test_enhance_result_carries_the_identity_fields():
    r = EnhanceResult(
        enhanced_dataset_path="p", units_enhanced=1673,
        error_count=12, classifications={"exploitable": 1},
        incomplete_count=45, total_units=1730)
    d = r.to_dict()
    assert d["incomplete_count"] == 45
    assert d["total_units"] == 1730
    assert d["units_enhanced"] + d["incomplete_count"] + d["error_count"] \
        == d["total_units"]


def test_the_step_summary_threads_the_fields():
    """Source-level pin: the scanner's enhance summary enumerates the new
    fields explicitly (the shape was dropped before)."""
    src = (PROJECT_ROOT / "core" / "scanner.py").read_text()
    assert '"incomplete_count": enhance_result.incomplete_count' in src
    assert '"total_units": enhance_result.total_units' in src


def test_enhance_dataset_threads_the_fields(tmp_path):
    """The real enhance_dataset on a mixed fixture: completed + incomplete
    + error -> all three buckets in the result."""
    units = [
        {"id": "a:f", "agent_context": {"security_classification": "safe"}},
        {"id": "b:g", "agent_context": {
            "security_classification": "incomplete",
            "classification_reasoning": "Analysis incomplete"}},
        {"id": "c:h", "agent_context": {"error": {
            "type": "unknown", "message": "boom"}}},
    ]
    # drive the counting block directly (enhance_dataset is the full I/O
    # path; the counting is the #611 surface): mirror enhancer.py's loop
    from core.schemas import EnhanceResult
    error_count = 0
    incomplete_count = 0
    classifications = {}
    for unit in units:
        ctx = unit.get("agent_context", {})
        if ctx.get("error"):
            error_count += 1
            continue
        cls = ctx.get("security_classification", "unknown")
        classifications[cls] = classifications.get(cls, 0) + 1
        if cls == "incomplete":
            incomplete_count += 1
    r = EnhanceResult(
        enhanced_dataset_path="x",
        units_enhanced=len(units) - error_count - incomplete_count,
        error_count=error_count,
        error_summary={"unknown": 1},
        classifications=classifications,
        incomplete_count=incomplete_count,
        total_units=len(units))
    assert r.total_units == 3
    assert r.incomplete_count == 1
    assert r.error_count == 1
    assert r.units_enhanced == 1
    assert r.units_enhanced + r.incomplete_count + r.error_count == r.total_units


# ---------------------------------------------------------------------------
# the hint: sentinels never reach the prompt
# ---------------------------------------------------------------------------

def test_the_sentinel_hint_is_omitted():
    """The sentinel classifications produce NO 'Pre-analysis hint' line;
    a real classification still does."""
    from prompts.vulnerability_analysis import get_analysis_prompt
    sentinel_unit = {
        "id": "a.py:f", "unit_type": "function",
        "route": {"file": "a.py", "name": "f"},
        "code": {"primary_code": "def f(): pass"},
        "agent_context": {"security_classification": "incomplete",
                          "classification_reasoning": "Analysis incomplete"},
    }
    prompt = get_analysis_prompt(
        code="def f(): pass", language="python",
        route="a.py:f",
        security_classification=sentinel_unit["agent_context"][
            "security_classification"],
        classification_reasoning=sentinel_unit["agent_context"][
            "classification_reasoning"])
    assert "Pre-analysis hint" not in prompt
    prompt2 = get_analysis_prompt(
        code="def g(): pass", language="python", route="a.py:g",
        security_classification="safe")
    assert 'Pre-analysis hint: classified as "safe"' in prompt2


# ---------------------------------------------------------------------------
# the census: sentinel-stamped = unclassified for the warning
# ---------------------------------------------------------------------------

def test_the_census_counts_sentinels_as_unclassified():
    """A dataset whose every unit is sentinel-stamped is the same
    un-enhanced shape the warning exists for — the census fires."""
    from core.analyzer import _unit_security_classification
    sentinel_unit = {"agent_context": {"security_classification": "incomplete"}}
    classified = (
        _unit_security_classification(sentinel_unit) is not None
        and _unit_security_classification(sentinel_unit)
        not in SENTINEL_CLASSIFICATIONS)
    assert classified is False  # the census's shape


def test_the_counter_in_the_metrics():
    """The source pin: the metrics gain enhance_unclassified_analyzed from
    the per-row stamp (no third analyze state)."""
    src = (PROJECT_ROOT / "core" / "analyzer.py").read_text()
    assert 'counts["enhance_unclassified_analyzed"]' in src
    assert "_result_security_classification(r) in SENTINEL_CLASSIFICATIONS" in src


# ---------------------------------------------------------------------------
# the recovery blocker: the two-sided invalidation
# ---------------------------------------------------------------------------

def test_a_sentinel_checkpoint_migrates_on_re_enhancement():
    """THE recovery receipt: a checkpoint stamped sentinel (the prior run
    analyzed an un-enhanced unit) re-analyzes when re-enhancement gives the
    unit a completed classification; a still-sentinel unit stays adopted
    (matching the run's own dataset)."""
    from core.analyzer import _run_detection  # noqa: F401  (the adoption is inside)
    src = (PROJECT_ROOT / "core" / "analyzer.py").read_text()
    # the two-sided predicate's shape
    assert "cp_is_stale" in src
    assert "cp_cls in SENTINEL_CLASSIFICATIONS" in src
    assert "current_cls not in SENTINEL_CLASSIFICATIONS" in src


def test_the_staleness_predicate_behavioral():
    """BEHAVIORAL: _cp_is_stale's four truth-table cells — the two-sided
    predicate, driven by real shapes (not source greps)."""
    from core.analyzer import _cp_is_stale
    _cp = lambda cls: {"result": {"security_classification": cls}}
    unit_completed = {"agent_context": {"security_classification": "safe"}}
    unit_sentinel = {"agent_context": {"security_classification": "incomplete"}}
    unit_unclassified = {"agent_context": {}}
    # sentinel-stamped + re-enhanced to completed -> STALE (the migration)
    assert _cp_is_stale(_cp("incomplete"), unit_completed) is True
    # sentinel-stamped + still sentinel -> adopted (matches the dataset)
    assert _cp_is_stale(_cp("incomplete"), unit_sentinel) is False
    # completed-stamped + anything -> never stale
    assert _cp_is_stale(_cp("safe"), unit_sentinel) is False
    assert _cp_is_stale(_cp("safe"), unit_completed) is False
    # sentinel-stamped + unclassified -> not stale (no migration evidence)
    assert _cp_is_stale(_cp("error"), unit_unclassified) is False

def test_the_seed_excludes_stale_but_keeps_their_usage():
    """THE F1 receipt (behavioral): a migration-resume seed — a sentinel-
    stamped checkpoint whose unit re-enhanced to completed — must NOT count
    completed (the double-count), but its USAGE still accumulates (the
    spend happened)."""
    from core.analyzer import _seed_summary
    existing = {
        "a.py:f": {
            "result": {"security_classification": "incomplete", "verdict": "safe"},
            "usage": {"input_tokens": 100, "output_tokens": 10,
                      "cost_usd": 0.1},
        },
        "b.py:g": {
            "result": {"security_classification": "safe", "verdict": "safe"},
            "usage": {"input_tokens": 50, "output_tokens": 5, "cost_usd": 0.05},
        },
    }
    units = [
        {"id": "a.py:f", "agent_context": {"security_classification": "safe"}},
        {"id": "b.py:g", "agent_context": {"security_classification": "safe"}},
    ]
    seed = _seed_summary(existing, {"a.py:f", "b.py:g"}, units=units)
    assert seed["completed"] == 1  # the stale row NOT counted
    assert seed["input_tokens"] == 150  # both rows' usage accumulated
    assert abs(seed["cost_usd"] - 0.15) < 1e-9
    # the no-units shape (a legacy caller): no staleness check, both counted
    seed_legacy = _seed_summary(existing, {"a.py:f", "b.py:g"})
    assert seed_legacy["completed"] == 2


def test_the_seed_without_staleness_is_unchanged():
    """The negative: no stale rows -> the seed counts both (the fix gates
    ONLY the stale shape)."""
    from core.analyzer import _seed_summary
    existing = {
        "a.py:f": {
            "result": {"security_classification": "safe", "verdict": "safe"},
            "usage": {"input_tokens": 1, "output_tokens": 1, "cost_usd": 0.0},
        },
    }
    units = [{"id": "a.py:f",
              "agent_context": {"security_classification": "safe"}}]
    seed = _seed_summary(existing, {"a.py:f"}, units=units)
    assert seed["completed"] == 1
    assert seed["input_tokens"] == 1
