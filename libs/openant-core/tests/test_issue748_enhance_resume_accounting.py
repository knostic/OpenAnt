"""Issue #748: enhance's resume accounting must count the DATASET, not the
checkpoint directory — and it must retire the errors it seeds.

The corpus receipts (the issue): progress lines read ``Done: 1825/1819``
(completed above total — stale checkpoint-dir ids counted as completed),
``_summary.json`` carried completed+incomplete > total_units on 8 of 27 runs,
and a phase=done summary reported ``errors: 528`` while ZERO errored
checkpoints existed on disk — the 528 were the resume seed's counts,
re-attempted by the run (none re-errored), and the main loop's success path
never retired them (only the retry round decrements).

Contract locked here (the issue's falsifier, authored at filing time):

* a resume over a checkpoint dir containing stale ids (files naming units
  absent from the dataset — a prior dataset, a unit outside a diff scope, a
  manual stray) counts NONE of them: restored_callback, _summary_completed
  and the summary identity (completed + incomplete + errors ==
  total_units) stay dataset-scoped, in BOTH resume paths (agentic and
  single-shot);
* an errored dataset unit restored by a resume is re-attempted by the main
  loop, and its seeded error is RETIRED when it lands a verdict (completed
  or incomplete) — the summary reports errors only for units whose
  checkpoints are errored NOW; and
* a re-errored seed counts ONCE (one unit, one error — the retry round's
  contract, mirrored into the main loop).

The agentic drives run the REAL ``enhance_dataset_agentic`` flow with
the agent call stubbed, real per-unit checkpoints on disk, and the real
``_summary.json`` emission (the #293 convention this file family follows);
the single-shot drive runs the REAL ``enhance_dataset`` flow, whose
observable is the restored callback (the path writes no _summary.json —
its resume accounting is the restored count and the skip set).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.agentic_enhancer.agent import INCOMPLETE_CLASSIFICATION  # noqa: E402
from utilities.llm_client import TokenTracker, reset_warning_state  # noqa: E402


def _read_summary(checkpoint_dir) -> dict:
    return json.loads((Path(checkpoint_dir) / "_summary.json").read_text())


def _agentic_cp(unit_id: str, agent_context: dict, usage: dict | None = None):
    """A per-unit checkpoint file shaped as _save_unit_checkpoint writes it."""
    cp = {"id": unit_id, "context_key": "agent_context",
          "agent_context": agent_context}
    if usage is not None:
        cp["usage"] = usage
    return cp


class _Adapter:
    name = "anthropic"
    supports_tools = True
    pricing = {}


def _binding():
    from utilities.llm import PhaseBinding
    return PhaseBinding(phase="enhance", adapter=_Adapter(), model="m",
                        provider_name="anthropic")


def _agentic_enhancer():
    # a FRESH tracker per drive: the resume seed injects the restored
    # checkpoints' usage via add_prior_usage, and the drives seed NON-ZERO
    # usage (5/5) — into the PROCESS-GLOBAL tracker it would leak across
    # tests (reset_warning_state does not reset it; #609's own drives pass
    # their own tracker for exactly this reason).
    import utilities.context_enhancer as ce
    return ce, ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())


def _analyzer_out(tmp_path) -> str:
    out = tmp_path / "a.json"
    out.write_text(json.dumps({"results": []}))
    return str(out)


def _write_cp(cp_dir, name, payload):
    (Path(cp_dir) / f"{name}.json").write_text(json.dumps(payload))


# ---------------------------------------------------------------------------
# the stale-id inflation — the agentic path (Done: 1825/1819's mechanism)
# ---------------------------------------------------------------------------
def test_resume_counts_only_dataset_members(tmp_path, monkeypatch):
    """A stale checkpoint id (not in the dataset) is not a completion: the
    restored count, _summary_completed and the summary identity stay
    dataset-scoped (the issue's falsifier half 1)."""
    reset_warning_state()
    ce, enhancer = _agentic_enhancer()

    re_enhanced: list = []

    def _no_new_work(unit, index, binding, tracker, verbose):
        re_enhanced.append(unit.get("id"))

    monkeypatch.setattr(ce, "enhance_unit_with_agent", _no_new_work)

    dataset = {"units": [
        {"id": "dc", "code": "x=1"},
        {"id": "di", "code": "x=1"},
    ]}
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    # dc: completed (safe). di: completed but INCOMPLETE-classified (#293's
    # restored third bucket). STALE: a checkpoint naming a unit absent from
    # the dataset — the #748 inflation.
    _write_cp(cp_dir, "dc", _agentic_cp(
        "dc", {"security_classification": "safe"}))
    _write_cp(cp_dir, "di", _agentic_cp(
        "di", {"security_classification": INCOMPLETE_CLASSIFICATION}))
    _write_cp(cp_dir, "stale", _agentic_cp(
        "NOT_IN_DATASET", {"security_classification": "safe"}))

    restored: list[int] = []
    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir),
        restored_callback=restored.append)
    reset_warning_state()

    # the counter is the LIVE guard: _enhance_one wraps the agent call in
    # `except Exception`, so a raise inside the fake would be swallowed into
    # a counted "error" unit and never fail the test directly (r1-F1).
    assert re_enhanced == [], (
        f"restored units were re-enhanced: {re_enhanced!r}")
    assert restored == [2], (
        f"the restored count must be dataset-scoped (2 members, not 2 + "
        f"the stale id): {restored!r}")
    s = _read_summary(cp_dir)
    assert s["total_units"] == 2
    assert s["completed"] == 1, (
        f"a stale id inflated completed past the dataset: {s!r}")
    assert s["incomplete"] == 1
    assert s["errors"] == 0
    assert (s["completed"] + s["incomplete"] + s["errors"]
            == s["total_units"]), (
        f"the summary identity broke under stale ids: {s!r}")


# ---------------------------------------------------------------------------
# the seed retirement — the main loop's landing (errors: 528's mechanism)
# ---------------------------------------------------------------------------
def test_resume_retires_the_seeded_error(tmp_path, monkeypatch):
    """An errored dataset unit is re-attempted by the resume's main loop; a
    verdict landing RETIRES the seeded error — the phase=done summary
    reports errors only for units errored NOW (the issue's falsifier
    half 2)."""
    reset_warning_state()
    ce, enhancer = _agentic_enhancer()

    scripted = {"d2": "safe", "d3": "safe"}

    def fake_enhance(unit, index, binding, tracker, verbose):
        cls = scripted[unit["id"]]
        unit["agent_context"] = {
            "security_classification": cls,
            "agent_metadata": {"input_tokens": 1, "output_tokens": 1,
                               "cost_usd": 0.0},
        }

    monkeypatch.setattr(ce, "enhance_unit_with_agent", fake_enhance)

    dataset = {"units": [
        {"id": "d2", "code": "x=1"},
        {"id": "d3", "code": "x=1"},
    ]}
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    # d2's checkpoint is ERRORED (run 1) — the seed counts it, the main loop
    # re-attempts it, and run 2's verdict must RETIRE the seed.
    _write_cp(cp_dir, "d2", _agentic_cp(
        "d2", {"security_classification": "error",
               "error": {"type": "auth"}},
        usage={"input_tokens": 5, "output_tokens": 5, "cost_usd": 0.0}))

    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["total_units"] == 2
    assert s["completed"] == 2, s
    assert s["errors"] == 0, (
        f"the re-attempted unit landed a verdict but the seeded error was "
        f"never retired — zero errored checkpoints exist on disk now: {s!r}")
    # the retirement is EXACT: the seeded type leaves the breakdown too
    # (errors and sum(breakdown.values()) agree; a retirement that leaves
    # the type behind is the r1-F3 symptom moved one field over).
    assert s.get("error_breakdown", {}) == {}, (
        f"the seeded error retired but its breakdown type stayed: {s!r}")
    assert (s["completed"] + s["incomplete"] + s["errors"]
            == s["total_units"]), s


def test_seeded_error_landing_incomplete_retires_the_seed(tmp_path, monkeypatch):
    """The seeded error retires on an INCOMPLETE landing too (the corpus's
    own shape: the 528 re-attempted, none re-errored, "though up to 18
    landed incomplete") — the summary reports completed 0 / incomplete 1 /
    errors 0 with an empty breakdown, the identity intact."""
    reset_warning_state()
    ce, enhancer = _agentic_enhancer()

    def fake_enhance(unit, index, binding, tracker, verbose):
        unit["agent_context"] = {
            "security_classification": INCOMPLETE_CLASSIFICATION,
            "agent_metadata": {"input_tokens": 1, "output_tokens": 1,
                               "cost_usd": 0.0},
        }

    monkeypatch.setattr(ce, "enhance_unit_with_agent", fake_enhance)

    dataset = {"units": [{"id": "d2", "code": "x=1"}]}
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    _write_cp(cp_dir, "d2", _agentic_cp(
        "d2", {"security_classification": "error",
               "error": {"type": "auth"}},
        usage={"input_tokens": 5, "output_tokens": 5, "cost_usd": 0.0}))

    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["total_units"] == 1
    assert s["completed"] == 0, s
    assert s["incomplete"] == 1, (
        f"the seeded unit landed incomplete but did not count as such: {s!r}")
    assert s["errors"] == 0, (
        f"the seeded error was not retired on the incomplete landing "
        f"(the corpus's own shape — up to 18 landed incomplete): {s!r}")
    assert s.get("error_breakdown", {}) == {}, (
        f"the exact retirement did not reach the breakdown on the "
        f"incomplete landing: {s!r}")
    assert (s["completed"] + s["incomplete"] + s["errors"]
            == s["total_units"]), s


def test_resume_reerrored_seed_counts_once(tmp_path, monkeypatch):
    """A seeded unit that re-errored on re-attempt counts ONCE (one unit,
    one error — the retry round's contract, mirrored into the main loop's
    landing)."""
    reset_warning_state()
    ce, enhancer = _agentic_enhancer()

    def fake_enhance(unit, index, binding, tracker, verbose):
        raise RuntimeError("run 2 also exploded")

    monkeypatch.setattr(ce, "enhance_unit_with_agent", fake_enhance)

    dataset = {"units": [{"id": "d2", "code": "x=1"}]}
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    _write_cp(cp_dir, "d2", _agentic_cp(
        "d2", {"security_classification": "error",
               "error": {"type": "auth"}},
        usage={"input_tokens": 5, "output_tokens": 5, "cost_usd": 0.0}))

    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["total_units"] == 1
    assert s["errors"] == 1, (
        f"the seed + the main loop's error branch double-counted one "
        f"unit's error (one unit, one error): {s!r}")
    assert s["completed"] == 0
    assert s["incomplete"] == 0
    assert (s["completed"] + s["incomplete"] + s["errors"]
            == s["total_units"]), s


# ---------------------------------------------------------------------------
# the stale-id inflation — the single-shot sibling path (:474's mirror)
# ---------------------------------------------------------------------------
def test_singleshot_resume_counts_only_dataset_members(tmp_path, monkeypatch):
    """The single-shot resume path (llm_context checkpoints) has the same
    raw-id counting sibling: a stale id must not reach the #218 baseline
    rebase (the restored callback is the path's observable)."""
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    def _no_new_work(unit, all_units):
        raise AssertionError("restored units must not be re-enhanced")

    monkeypatch.setattr(enhancer, "enhance_unit", _no_new_work)

    dataset = {"units": [
        {"id": "u1", "unit_type": "function", "code": {"primary_origin":
         {"file_path": "a.py", "function_name": "u1"}},
         "metadata": {"direct_calls": [], "direct_callers": []}},
    ]}
    cp_dir = tmp_path / "cp"
    cp_dir.mkdir()
    _write_cp(cp_dir, "u1", {"id": "u1", "context_key": "llm_context",
                             "llm_context": {"verdict": "v"}})
    _write_cp(cp_dir, "stale", {"id": "NOT_IN_DATASET",
                                 "context_key": "llm_context",
                                 "llm_context": {"verdict": "v"}})

    restored: list[int] = []
    enhancer.enhance_dataset(
        dataset, workers=1, checkpoint_path=str(cp_dir),
        restored_callback=restored.append)

    assert restored == [1], (
        f"the single-shot restored count must be dataset-scoped "
        f"(1 member, not 1 + the stale id): {restored!r}")
