"""#598: an unknown adapter price is never silently replaced with the
Anthropic catalogue rate.

The masquerade: ``TokenTracker.record_call``'s pricing resolution had a
legacy fallback — when the adapter's pricing map missed the model, it
substituted the ANTHROPIC catalogue's rate before the #216 unknown-pricing
path ever saw it. A model that missed its own adapter's map but existed in
the Anthropic catalogue got a wrong non-zero cost with **no warning and
``cost_incomplete=False``** — defeating the fail-visible design #216 built,
with a number worse than the $0-with-flag it replaced (an operator
reconciling against a provider bill sees a plausible-looking cost).

The fix deletes BOTH substitution fallbacks (``record_call``'s and
``_extract_usage``'s) and threads the incompleteness metadata through the
CLI report consumer (``_usage_to_info`` previously dropped it — the
report-phase masquerade would have survived the tracker fix alone).

The census pin (source-level): every production ``record_call``/
``_extract_usage`` call passes ``pricing=`` — the 14+2+2 receipts (the
first +1 is #616's verifier exception-path record; the second is #609's
agent exception-path record — the enhance loop records its failed
attempts the same way).
"""

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import TokenTracker, reset_warning_state  # noqa: E402


class _Err:
    def __init__(self):
        self.lines = []


# ---------------------------------------------------------------------------
# the masquerade (the honest RED): the cross-provider substitution
# ---------------------------------------------------------------------------

def test_the_masquerade_is_dead_the_loud_path_lives(tmp_path, capsys):
    """THE receipt: an OpenAI-compatible adapter configured with a Claude
    model id — the adapter's map misses, the (deleted) fallback would have
    found the Anthropic catalogue rate and reported a plausible non-zero
    cost with cost_incomplete=False. Post-fix: the #216 loud path (the
    one-time warning + $0 + cost_incomplete=True + the id recorded)."""
    reset_warning_state()
    tracker = TokenTracker()
    # the OpenAI map genuinely misses this id (the Anthropic map has it)
    from core.model_registry import pricing_map
    assert pricing_map("openai").get("claude-sonnet-4-6") is None
    rec = tracker.record_call(
        model="claude-sonnet-4-6", input_tokens=1000, output_tokens=1000,
        pricing=None)  # the lookup miss
    totals = tracker.get_totals()
    assert rec["cost_usd"] == 0.0
    assert totals["cost_incomplete"] is True
    assert "claude-sonnet-4-6" in totals["unpriced_models"]
    err = capsys.readouterr().err
    assert "unknown" in err.lower() or "no pricing" in err.lower()


def test_the_control_the_anthropic_miss_is_unchanged(capsys):
    """The CONTROL: an anthropic-map miss behaved correctly before and
    after — the fix changes only the substitution, never this path."""
    reset_warning_state()
    tracker = TokenTracker()
    rec = tracker.record_call(
        model="totally-unknown-model-x", input_tokens=10, output_tokens=10,
        pricing=None)
    assert rec["cost_usd"] == 0.0
    assert tracker.get_totals()["cost_incomplete"] is True
    capsys.readouterr()  # the warning fired


def test_a_priced_call_is_unchanged():
    """The fix deletes only the fallback: an explicit pricing dict still
    produces the exact arithmetic."""
    reset_warning_state()
    tracker = TokenTracker()
    rec = tracker.record_call(
        model="m", input_tokens=1_000_000, output_tokens=1_000_000,
        pricing={"input": 2.0, "output": 10.0})
    assert abs(rec["cost_usd"] - 12.0) < 1e-9
    assert tracker.get_totals()["cost_incomplete"] is False


# ---------------------------------------------------------------------------
# the generator's half (the second instance)
# ---------------------------------------------------------------------------

def test_extract_usage_marks_incomplete_never_substitutes():
    """The report generator's own fallback (a MODEL_PRICING global read) is
    deleted with the same doctrine: a miss is cost_incomplete + the model
    attribution — never the Anthropic rate."""
    from report.generator import _extract_usage
    usage = _extract_usage(1000, 1000, "claude-sonnet-4-6", pricing=None)
    assert usage["cost_usd"] == 0.0
    assert usage["cost_incomplete"] is True
    assert usage["unpriced_models"] == ["claude-sonnet-4-6"]


def test_merge_usage_unions_the_unpriced_attribution():
    from report.generator import _merge_usage
    merged = _merge_usage([
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
         "cost_usd": 0.0, "cost_incomplete": True,
         "unpriced_models": ["a"]},
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
         "cost_usd": 0.0, "cost_incomplete": True,
         "unpriced_models": ["b", "a"]},
    ])
    assert merged["cost_incomplete"] is True
    assert merged["unpriced_models"] == ["a", "b"]


def test_the_cli_report_carries_the_incompleteness():
    """The consumer separation's second half: _usage_to_info previously
    DROPPED cost_incomplete/unpriced_models — the CLI report's usage read
    cost_incomplete=False while the pipeline's usage was incomplete."""
    from core.reporter import _usage_to_info
    info = _usage_to_info({
        "input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
        "cost_usd": 0.0, "cost_incomplete": True,
        "unpriced_models": ["claude-sonnet-4-6"]})
    assert info.cost_incomplete is True
    assert info.unpriced_models == ["claude-sonnet-4-6"]
    assert info.to_dict()["cost_incomplete"] is True


def test_the_cli_report_defaults_still_clean():
    from core.reporter import _usage_to_info
    info = _usage_to_info({
        "input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
        "cost_usd": 3.0})
    assert info.cost_incomplete is False
    assert info.unpriced_models == []


# ---------------------------------------------------------------------------
# the census pin (source-level: the invariant the fix relies on)
# ---------------------------------------------------------------------------

def test_every_production_call_site_passes_pricing():
    """Every production ``record_call``/``_extract_usage`` call site passes
    ``pricing=`` — the invariant that made deleting the fallback safe.
    Walks ALL non-test packages (a future unthreaded caller anywhere in
    the tree shows here with its file:line)."""
    root = PROJECT_ROOT
    offenders = []
    checked = 0
    for py in root.rglob("*.py"):
        rel = py.relative_to(root)
        parts = rel.parts
        # tests are the only intentional loud-path callers; venvs and
        # fixtures are not the tree. Exclusion is PATH-based ("tests" in
        # parts), NOT name-based — a name filter ("test" in py.name) hid
        # production modules like dynamic_tester/test_generator.py and
        # parsers/*/test_pipeline.py from the census (none call record_call
        # today; now they are walked and would be caught if they ever do).
        if "tests" in parts or "venv" in parts or ".venv" in parts \
                or "fixtures" in parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name in ("record_call", "_extract_usage"):
                if not any(k.arg == "pricing" for k in node.keywords):
                    offenders.append(f"{rel}:{node.lineno}")
                checked += 1
    assert checked == 18, f"the census changed: {checked} sites (was 18)"
    assert not offenders, f"unthreaded production callers: {offenders}"


def test_the_fallback_is_absent_from_source():
    """The masquerade's own shape never returns: the Anthropic-catalogue
    substitution must not exist in either consumer's pricing resolution."""
    src = (PROJECT_ROOT / "utilities" / "llm_client.py").read_text(encoding="utf-8")
    assert 'pricing = pricing_map("anthropic").get(model)' not in src
    gen = (PROJECT_ROOT / "report" / "generator.py").read_text(encoding="utf-8")
    assert "from utilities.llm_client import MODEL_PRICING" not in gen


def test_seed_summary_returns_the_prior_unpriced_ids():
    """The resume READER, EXECUTED: _seed_summary (the real function the
    analyzer's resume path runs) returns the prior run's unpriced ids
    from the per-unit checkpoint rows — the half the resume forwarding
    consumes."""
    from core.analyzer import _seed_summary
    seed = _seed_summary({
        "u1": {"result": {"verdict": "safe"},
               "usage": {"input_tokens": 10, "output_tokens": 5,
                          "cost_usd": 0.01, "cost_incomplete": True,
                          "unpriced_models": ["m/a", "m/b"]}},
        "u2": {"result": {"verdict": "ERROR"},
               "usage": {"input_tokens": 1, "output_tokens": 1,
                          "cost_usd": 0.0}},
    })
    assert seed["unpriced_models"] == {"m/a", "m/b"}
    # usage over ALL rows — the ERRORED row's tokens count too (the
    # #316/#324 contract; lowercase "error" would NOT be an errored row
    # under analyze_result_is_error — exact "ERROR")
    assert seed["input_tokens"] == 11


def test_every_resume_forwarding_passes_the_ids():
    """The five add_prior_usage call sites (the four this PR threaded +
    llm-reach, pre-existing) forward the unpriced ids — the regression
    was collected-but-dropped at the call. A source pin (the call sites
    sit inside heavy resume machinery; the reader is pinned EXECUTED
    above and the tracker merge by #216's tests)."""
    import re
    for path in ("core/analyzer.py",
                 "utilities/finding_verifier.py",
                 "utilities/context_enhancer.py",
                 "utilities/dynamic_tester/__init__.py",
                 "core/llm_reachability.py"):
        src = (PROJECT_ROOT / path).read_text(encoding="utf-8")
        calls = re.findall(r"add_prior_usage\(", src)
        forwarded = re.findall(r"unpriced_models=", src)
        assert calls and len(forwarded) >= len(calls), (
            f"{path}: {len(calls)} add_prior_usage call(s), "
            f"{len(forwarded)} unpriced_models forwarding(s)")


def test_the_enhancer_checkpoint_writer_persists_the_ids(tmp_path):
    """The fix round's WRITER, EXECUTED (the deep-refute's catch: reverting
    it passed every other test): _save_unit_checkpoint — the real function,
    self-free — persists agent_metadata's unpriced ids into the per-unit
    usage block, including the zero-token unpriced edge."""
    import json
    from utilities.context_enhancer import ContextEnhancer
    unit = {"id": "u.py:f", "agent_context": {"agent_metadata": {
        "input_tokens": 10, "output_tokens": 5, "cost_usd": 0.01,
        "unpriced_models": ["m/a"]}}}
    ContextEnhancer._save_unit_checkpoint(None, unit, str(tmp_path))
    # the filename is disambiguated (case-collision-safe) — glob it
    cp = json.loads(next(iter(tmp_path.glob("*.json"))).read_text())
    assert cp["id"] == "u.py:f"
    assert cp["usage"]["unpriced_models"] == ["m/a"]
    # the zero-token unpriced edge writes the block too (the gate term)
    unit2 = {"id": "u2.py:f", "agent_context": {"agent_metadata": {
        "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
        "unpriced_models": ["m/b"]}}}
    ContextEnhancer._save_unit_checkpoint(None, unit2, str(tmp_path))
    cps = {json.loads(p.read_text())["id"]:
           json.loads(p.read_text()) for p in tmp_path.glob("*.json")}
    assert cps["u2.py:f"]["usage"]["unpriced_models"] == ["m/b"]


def test_the_dynamic_test_writer_and_restore_are_pinned():
    """The dynamic-test side: (a) a source pin on the two writer lines and
    the restore line (the deep-refute showed each revertibly invisibly);
    (b) the to_dict roundtrip EXECUTED — the persisted schema carries the
    ids. The full run-harness writer test (the #333-shape extension) is
    the named follow-up."""
    src = (PROJECT_ROOT / "utilities" / "dynamic_tester" / "__init__.py"
           ).read_text(encoding="utf-8")
    assert src.count('result.unpriced_models = list(unit_usage.get('
                     '"unpriced_models") or [])') == 2
    assert ('unpriced_models=list(cp_data.get("unpriced_models") '
            'or []),') in src
    from utilities.dynamic_tester.models import DynamicTestResult
    d = DynamicTestResult(finding_id="F1", status="CONFIRMED", details="",
                          unpriced_models=["m/a"]).to_dict()
    assert d["unpriced_models"] == ["m/a"]
