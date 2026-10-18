"""#802 — a resume's kept-set recomputation must not silently absorb the
prior run's unfinished work.

The kept-set recomputation (the closure re-seeded by the LLM-promoted entry
points) is not compared against the prior run's scope ANYWHERE: the analyze
seed's foreign-row skip (``_seed_summary``'s unit-membership predicate) and
the enhance paths' stale-restored intersections (#748) both DROP the prior
run's rows silently — "excluded from the counters; counted nowhere else". A
unit that ERRORED in the prior run (the exact work a resume exists to
finish) can therefore leave scope with ``degraded: false``, the headline
error count FALLING (reading as repair while it means "we stopped covering
them"), and no surface recording the difference.

The campaign's evidence (run 2 → run 3, 58,306 units): 89 units left the
kept set; 88 of them carried ``finding: "error"`` in run 2 and kept their
byte-identical error checkpoints into run 3 — never re-analyzed, counted
nowhere. 105 stale enhance checkpoints sat in the monotonic dir the same
way. The #788 sort fix closed the ORDERING trigger; what remains at master
is the invisibility — none of the issue's three asks exists.

The fix this file locks (the ask (a), the delta surface): every resume
that shrinks the covered population REPORTS the delta — which units left,
with their prior verdicts — in the phase's ``_summary.json`` (present-only
when nonzero) and on the phase result objects. The ask (b) — pinning the
errored units for retry — is the stronger follow-up, deliberately not
absorbed (the delta is the honesty fix; the retry ledger changes recovery
policy).

Shapes:

  S1 -- the WITNESS (red at base): the analyze leg — a REAL two-run
        run_analysis drive (the #663 fake shape): run 1 units {a:err, b:ok,
        c:ok} with a:err landing an ERRORED checkpoint row; run 2 (the
        resume, same output_dir) with a's unit gone from the population
        (the --limit/diff-filter/re-parse shrink the code comment names) —
        the dropped ERRORED row must be REPORTED (the _summary.json block
        + the AnalyzeResult), not silently absorbed while the error count
        falls 1 -> 0.
  S2 -- the WITNESS (red at base): the enhance agentic leg — the REAL
        enhance_dataset_agentic drive (the #748 shape): a pre-seeded
        ERRORED checkpoint row (agent_context.error) for a unit absent
        from this run's dataset + a completed row for a member — the delta
        must reach the enhance _summary.json (the durable artifact the
        campaign read) and the phase holder.
  S3 -- the WITNESS (red at base): the enhance single-shot leg through the
        REAL core.enhancer runner (the #213-era registry seam) — the
        EnhanceResult carries the delta + to_dict emits it (the standalone
        enhance CLI's envelope reads it; the scan-level step report does
        NOT aggregate it — the r1-F3 finding, a named follow-up, recorded
        in the manifest's documented_limitations).
  S4 -- the classifier contract (unit): _seed_summary's delta — the
        prior-verdict split (errored vs completed), the capped id sample,
        absent when nothing dropped, absent when the population is not
        constrained (a fresh run's empty dir).
  S5 -- the artifact contract (unit): write_summary's resume_delta is
        present-only — never an empty block, never a key when the delta
        is None.
  S9 -- the WITNESS (red at base): the VERIFY leg (the r1-F4 catch — the
        same absorption, unnamed): the two-run REAL verify_batch drive;
        the delta reaches the verify _summary.json.
  S10/S11 -- the PER-UNIT progress windows (the r1-F1 catch): an
        interrupt AFTER a unit lands leaves the per-unit write on disk —
        the campaign's own interrupted-12k-run shape; the delta must be
        in THAT window's summary, not only the initial/final ones.
  S12 -- the retry-pass window (r1-F1): an interrupt DURING the retry
        pass leaves the per-retried-unit write on disk.
  S13 -- the agentic per-retried-unit window (r1-F1; the mislabel
        caught at r2 and relabeled at r3/r4): an interrupt on the second
        retried unit of ROUND 1 leaves the per-retried-unit write on disk
        (no round-end write exists in the loop; only round 1 starts).
  S14/S15 -- the CROSS-MODE census (the r1-F2 catch): the row's own
        context_key decides the prior verdict — a mode switch between
        runs must not misclassify a prior-mode ERRORED row as completed.
  S16/S17 -- the verify lifecycle windows (the r1-F4 extension's own
        mirror sites): the initial + per-unit verify writes carry the
        delta mid-flight.
  S7/S8 -- the retry-pass/budget-retry resumes with the member unit NEW
        in run 2 (the r1-F5 drive fix) + the identity asserts.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import TokenTracker, reset_warning_state  # noqa: E402

THE_BLOCK_KEYS = {"dropped_from_scope", "dropped_errored_prior_run",
                  "dropped_completed_prior_run", "dropped_errored_ids"}


def _read_summary(checkpoint_dir) -> dict:
    return json.loads((Path(checkpoint_dir) / "_summary.json").read_text())


def _agentic_cp(unit_id: str, agent_context: dict, usage: dict | None = None):
    cp = {"id": unit_id, "context_key": "agent_context",
          "agent_context": agent_context}
    if usage is not None:
        cp["usage"] = usage
    return cp


def _write_cp(cp_dir, name, payload):
    (Path(cp_dir) / f"{name}.json").write_text(json.dumps(payload))


class _Adapter:
    name = "anthropic"
    supports_tools = True
    pricing = {}


def _binding(phase="enhance"):
    from utilities.llm import PhaseBinding
    return PhaseBinding(phase=phase, adapter=_Adapter(), model="m",
                        provider_name="anthropic")


def _analyze_registry():
    from utilities.llm import PhaseBinding

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(),
                                model="m", provider_name="anthropic")

    return _FakeRegistry()


def _analyzer_out(tmp_path) -> str:
    out = tmp_path / "a.json"
    out.write_text(json.dumps({"results": []}))
    return str(out)


# ---------------------------------------------------------------------------
# S1 — the analyze witness: the two-run REAL drive
# ---------------------------------------------------------------------------
def test_the_resume_reports_the_dropped_errored_unit(tmp_path, monkeypatch):
    """Run 1: {a:err, b:ok, c:ok} with a:err landing an ERRORED row.
    Run 2 (the resume, same output_dir): the population is {b:ok, c:ok} —
    a:err left scope (the legit shrink). The dropped ERRORED row must be
    reported in run 2's _summary.json (with its prior verdict + id) and on
    the AnalyzeResult — at base the row is absorbed silently and the error
    count falls 1 -> 0 with no surface saying what moved (the issue's own
    RED shape)."""
    from core import analyzer

    reset_warning_state()
    out = tmp_path / "out"
    run1_dataset = tmp_path / "run1.json"
    run1_dataset.write_text(json.dumps({"units": [
        {"id": "a:err", "code": "x=1"},
        {"id": "b:ok", "code": "x=1"},
        {"id": "c:ok", "code": "x=1"},
    ]}))

    def fake_detection_run1(units, binding, json_corrector, app_context,
                            workers, checkpoint=None, summary_callback=None):
        # mimic _process_and_save's side effects exactly: each row is
        # CHECKPOINTED (the delta reads the checkpoint rows) and the
        # summary callback fires per unit (the counters).
        rows = []
        for u in units:
            if u["id"] == "a:err":
                res = {"unit_id": "a:err", "finding": "error",
                       "verdict": "ERROR",
                       "error": "Error code: 402 - the storm shape",
                       "error_info": {"type": "api_status",
                                      "status_code": 402}}
                finding = "error"
            else:
                res = {"unit_id": u["id"], "finding": "safe",
                       "verdict": "SAFE", "confidence": 90,
                       "vulnerabilities": [], "reasoning": "r"}
                finding = "safe"
            if checkpoint is not None:
                checkpoint.save(u["id"], {"result": res,
                                          "route_key": u["id"],
                                          "code_for_route": ""})
            if summary_callback is not None:
                summary_callback(finding, usage={})
            rows.append(res)
        return rows, {u["id"]: "" for u in units}

    monkeypatch.setattr(analyzer, "_run_detection", fake_detection_run1)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:t"})
    analyzer.run_analysis(str(run1_dataset), str(out),
                          registry=_analyze_registry(), workers=1)

    s1 = _read_summary(out / "analyze_checkpoints")
    assert s1["errors"] == 1, s1

    # ---- run 2: the resume with a's unit out of the population ----
    reset_warning_state()
    run2_dataset = tmp_path / "run2.json"
    run2_dataset.write_text(json.dumps({"units": [
        {"id": "b:ok", "code": "x=1"},
        {"id": "c:ok", "code": "x=1"},
    ]}))

    def fake_detection_run2(units, binding, json_corrector, app_context,
                            workers, checkpoint=None, summary_callback=None):
        return [], {u["id"]: "" for u in units}

    monkeypatch.setattr(analyzer, "_run_detection", fake_detection_run2)
    result2 = analyzer.run_analysis(str(run2_dataset), str(out),
                                     registry=_analyze_registry(), workers=1)
    reset_warning_state()

    s2 = _read_summary(out / "analyze_checkpoints")
    # the headline: the error count fell (1 -> 0) — the run no longer
    # reads clean-while-shrunk; the delta explains the fall.
    assert s2["errors"] == 0, s2
    delta = s2.get("resume_delta")
    assert delta, (
        "the dropped prior-run ERRORED unit was absorbed silently: the "
        f"resume's _summary.json carries no resume_delta block: {s2!r}")
    assert delta["dropped_from_scope"] == 1, delta
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_completed_prior_run"] == 0, delta
    assert delta["dropped_errored_ids"] == ["a:err"], delta
    assert result2.resume_delta == delta, (
        "the AnalyzeResult must carry the same delta (the scan-level "
        f"consumer's field): {result2.resume_delta!r}")


# ---------------------------------------------------------------------------
# S2 — the enhance agentic witness: the pre-seeded foreign ERRORED row
# ---------------------------------------------------------------------------
def test_the_enhance_resume_reports_the_dropped_errored_unit(tmp_path, monkeypatch):
    """The campaign's 105-orphan shape: the enhance agentic path's stale
    intersection drops a prior-run ERRORED checkpoint row (a unit absent
    from this run's dataset) silently — the #748 fix scoped the counters
    but the DROPPED rows are still counted nowhere. The delta must reach
    the enhance _summary.json (the durable artifact) and the holder."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    def _no_new_work(unit, index, binding, tracker, verbose):
        raise AssertionError("no member unit needs work: all rows are "
                             f"either adopted or foreign: {unit.get('id')!r}")

    monkeypatch.setattr(ce, "enhance_unit_with_agent", _no_new_work)

    dataset = {"units": [{"id": "y:member", "code": "x=1"}]}
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    # the member's completed row (adopted) + the FOREIGN rows: one errored
    # in the prior run (the exact unfinished work), one completed.
    _write_cp(cp_dir, "y", _agentic_cp(
        "y:member", {"security_classification": "safe"}))
    _write_cp(cp_dir, "x", _agentic_cp(
        "x:gone", {"security_classification": "unknown",
                   "error": {"type": "rate_limit", "kind": "quota",
                             "message": "per-day cap"}}))
    _write_cp(cp_dir, "w", _agentic_cp(
        "w:gone", {"security_classification": "safe"}))

    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    delta = s.get("resume_delta")
    assert delta, (
        "the foreign rows were absorbed silently: the enhance _summary.json "
        f"carries no resume_delta block: {s!r}")
    assert delta["dropped_from_scope"] == 2, delta
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_completed_prior_run"] == 1, delta
    assert delta["dropped_errored_ids"] == ["x:gone"], delta
    assert getattr(enhancer, "_resume_delta", None) == delta, (
        "the phase holder must carry the delta (the EnhanceResult seam): "
        f"{getattr(enhancer, '_resume_delta', None)!r}")
    # the identity still holds (the delta is BESIDE the counters, not in them)
    assert (s["completed"] + s["incomplete"] + s["errors"]
            == s["total_units"]), s


# ---------------------------------------------------------------------------
# S3 — the enhance single-shot witness through the REAL runner
# ---------------------------------------------------------------------------
def test_the_single_shot_enhance_resume_reports_the_delta_on_the_result(tmp_path, monkeypatch):
    """The single-shot path writes no _summary.json — its delta's surfaces
    are the EnhanceResult + to_dict (the STANDALONE enhance CLI's envelope
    reads it; the scan-level step report does NOT aggregate it — the
    r1-F3/r2-F4 correction, a named follow-up). Drive the REAL
    core.enhancer runner (the registry seam stubbed) twice: run 1 errors
    x:err (the LLM call raises; the errored default context is
    checkpointed), run 2's dataset drops x:err — the result must report the
    dropped ERRORED row."""
    reset_warning_state()
    import core.enhancer as enh

    monkeypatch.setattr("utilities.llm.probe_registry_or_raise", lambda r: None)
    monkeypatch.setattr("core.enhancer.load_config_file", lambda: {})
    monkeypatch.setattr("core.enhancer.build_phase_registry", lambda cf, lc: _analyze_registry())
    monkeypatch.setattr("core.enhancer.resolve_llm_config", lambda cf, n=None: None)

    out = tmp_path / "enhanced.json"

    def _llm_ok_payload():
        return json.dumps({"missing_dependencies": [], "additional_callers": [],
                          "data_flow": {}, "imports": [], "reasoning": "r",
                          "confidence": 0.9, "security_classification": "safe"})

    def _llm_err(binding, prompt, max_tokens=None, tracker=None):
        # dispatch on the prompt's unit id (the prompt embeds **ID:** `x:err`)
        if "x:err" in prompt:
            raise RuntimeError("the per-day cap")
        return _llm_ok_payload()

    def _llm_ok(binding, prompt, max_tokens=None, tracker=None):
        return _llm_ok_payload()

    def _dataset(units):
        p = tmp_path / ("d%d.json" % len(units))
        p.write_text(json.dumps({"units": units}))
        return str(p)

    import utilities.context_enhancer as ce
    def _unit(uid):
        return {"id": uid, "code": {"primary_code": "x=1",
                                     "primary_origin": {"function_name": "f",
                                                        "file_path": "a.py"}}}

    monkeypatch.setattr(ce, "simple_text", _llm_err)
    r1 = enh.enhance_dataset(
        dataset_path=_dataset([_unit("x:err"), _unit("y:ok")]),
        output_path=str(out), mode="single-shot")
    assert r1.error_count == 1, (
        f"run 1 must land one errored enhance row: {r1.error_count!r}")

    monkeypatch.setattr(ce, "simple_text", _llm_ok)
    r2 = enh.enhance_dataset(
        dataset_path=_dataset([_unit("y:ok")]),
        output_path=str(out), mode="single-shot")
    reset_warning_state()

    delta = r2.resume_delta
    assert delta, (
        "the single-shot resume absorbed the dropped ERRORED row silently "
        f"— the EnhanceResult carries no resume_delta: {r2!r}")
    assert delta["dropped_from_scope"] == 1, delta
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_errored_ids"] == ["x:err"], delta
    # the envelope's read path (the CLI consumer's field) carries it too
    d = r2.to_dict()
    assert d.get("resume_delta") == delta, d


# ---------------------------------------------------------------------------
# S4 — the seed-classifier contract (unit)
# ---------------------------------------------------------------------------
def test_the_seed_classifies_the_dropped_rows_by_prior_verdict():
    from core import analyzer

    def _row(uid, errored):
        if errored:
            return {"result": {"unit_id": uid, "finding": "error",
                               "verdict": "ERROR",
                               "error": "Error code: 402 - storm"}}
        return {"result": {"unit_id": uid, "finding": "safe",
                           "verdict": "SAFE", "confidence": 90,
                           "vulnerabilities": [], "reasoning": "r"}}

    existing = {
        "gone-err": _row("gone-err", True),
        "gone-ok": _row("gone-ok", False),
        "kept": _row("kept", False),
    }
    seed = analyzer._seed_summary(existing, {"kept"}, units=[])
    delta = seed.get("resume_delta")
    assert delta == {"dropped_from_scope": 2,
                     "dropped_errored_prior_run": 1,
                     "dropped_completed_prior_run": 1,
                     "dropped_errored_ids": ["gone-err"]}, delta

    # nothing dropped -> NO block (present-only)
    seed_none = analyzer._seed_summary(existing, {"gone-err", "gone-ok", "kept"},
                                       units=[])
    assert "resume_delta" not in seed_none, seed_none

    # an unconstrained population (unit_ids=None) -> no delta (the caller
    # did not scope; the foreign-row concept is undefined)
    seed_free = analyzer._seed_summary(existing, None, units=[])
    assert "resume_delta" not in seed_free, seed_free

    # the id sample is CAPPED (the campaign precedent: the first 20 sorted)
    many = {("gone-%03d" % i): _row("gone-%03d" % i, True) for i in range(30)}
    seed_many = analyzer._seed_summary(many, {"kept"}, units=[])
    ids = seed_many["resume_delta"]["dropped_errored_ids"]
    assert len(ids) == 20, ids
    assert ids == sorted("gone-%03d" % i for i in range(30))[:20], ids
    assert seed_many["resume_delta"]["dropped_from_scope"] == 30


# ---------------------------------------------------------------------------
# S5 — the artifact contract: write_summary present-only
# ---------------------------------------------------------------------------
def test_the_summary_delta_is_present_only(tmp_path):
    from core.checkpoint import StepCheckpoint

    sc = StepCheckpoint.__new__(StepCheckpoint)
    sc.step_name = "analyze"
    sc.dir = str(tmp_path / "cp")
    sc.ensure_dir()

    block = {"dropped_from_scope": 1, "dropped_errored_prior_run": 1,
             "dropped_completed_prior_run": 0, "dropped_errored_ids": ["u"]}
    sc.write_summary(2, 1, 0, {}, phase="done", resume_delta=block)
    s = _read_summary(sc.dir)
    assert s["resume_delta"] == block, s
    assert set(s["resume_delta"]) == THE_BLOCK_KEYS, s

    sc.write_summary(2, 2, 0, {}, phase="done")
    s2 = _read_summary(sc.dir)
    assert "resume_delta" not in s2, (
        f"the block must be present-only: {s2!r}")
    sc.write_summary(2, 2, 0, {}, phase="done", resume_delta=None)
    s3 = _read_summary(sc.dir)
    assert "resume_delta" not in s3, s3


# ---------------------------------------------------------------------------
# S6 — the interrupted resume: the delta is on disk BEFORE completion
# ---------------------------------------------------------------------------
def test_the_interrupted_resume_keeps_the_delta(tmp_path, monkeypatch):
    """The campaign's own shape is the interrupted 12k-unit run: an operator
    reading the summary MID-FLIGHT must see what left scope, not only after
    the run completes. Run 2 (the resume, a:err's unit gone) raises
    KeyboardInterrupt inside the detection pass — the #313/#417 contract
    re-raises; the in_progress _summary.json left on disk must already
    carry the delta (the initial write site, not just the final done
    write)."""
    from core import analyzer

    reset_warning_state()
    out = tmp_path / "out"
    ds = tmp_path / "ds.json"
    ds.write_text(json.dumps({"units": [
        {"id": "a:err", "code": "x=1"}, {"id": "b:ok", "code": "x=1"}]}))

    def fake_detection_run1(units, binding, jc, ac, workers,
                            checkpoint=None, summary_callback=None):
        rows = []
        for u in units:
            if u["id"] == "a:err":
                res = {"unit_id": "a:err", "finding": "error",
                       "verdict": "ERROR",
                       "error": "Error code: 402 - the storm shape",
                       "error_info": {"type": "api_status",
                                      "status_code": 402}}
                finding = "error"
            else:
                res = {"unit_id": u["id"], "finding": "safe",
                       "verdict": "SAFE", "confidence": 90,
                       "vulnerabilities": [], "reasoning": "r"}
                finding = "safe"
            if checkpoint is not None:
                checkpoint.save(u["id"], {"result": res,
                                          "route_key": u["id"],
                                          "code_for_route": ""})
            if summary_callback is not None:
                summary_callback(finding, usage={})
            rows.append(res)
        return rows, {u["id"]: "" for u in units}

    monkeypatch.setattr(analyzer, "_run_detection", fake_detection_run1)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:t"})
    analyzer.run_analysis(str(ds), str(out),
                          registry=_analyze_registry(), workers=1)

    reset_warning_state()
    ds2 = tmp_path / "ds2.json"
    ds2.write_text(json.dumps({"units": [{"id": "b:ok", "code": "x=1"}]}))

    def fake_interrupt(units, binding, jc, ac, workers,
                       checkpoint=None, summary_callback=None):
        raise KeyboardInterrupt("the mid-flight stop")

    monkeypatch.setattr(analyzer, "_run_detection", fake_interrupt)
    import pytest
    with pytest.raises(KeyboardInterrupt):
        analyzer.run_analysis(str(ds2), str(out),
                               registry=_analyze_registry(), workers=1)
    reset_warning_state()

    s = _read_summary(out / "analyze_checkpoints")
    assert s["phase"] == "in_progress", s
    delta = s.get("resume_delta")
    assert delta, (
        "the interrupted resume's in_progress summary must carry the "
        f"delta: {s!r}")
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_errored_ids"] == ["a:err"], delta


# ---------------------------------------------------------------------------
# S7 — the retry pass keeps the delta (the in-run transient class)
# ---------------------------------------------------------------------------
def test_the_retry_pass_keeps_the_delta(tmp_path, monkeypatch):
    """A resume can drop prior-run rows AND land its own in-run retryable
    error in the same pass — the retry loop's summary writes must keep
    carrying the delta (the retry-round mirror sites), and the final done
    write must not lose it."""
    from core import analyzer

    reset_warning_state()
    out = tmp_path / "out"
    # run 1's population: ONLY the unit that will be dropped (its errored
    # row is the delta's subject). The run-2 member is NEW (no run-1 row)
    # — the shape the real code produces (a completed row is skipped by
    # the restore queue; the r1-F5 catch).
    ds = tmp_path / "ds.json"
    ds.write_text(json.dumps({"units": [
        {"id": "a:err", "code": "x=1"}]}))

    def fake_detection_run1(units, binding, jc, ac, workers,
                            checkpoint=None, summary_callback=None):
        res = {"unit_id": "a:err", "finding": "error", "verdict": "ERROR",
               "error": "Error code: 402 - storm",
               "error_info": {"type": "api_status", "status_code": 402}}
        if checkpoint is not None:
            checkpoint.save("a:err", {"result": res, "route_key": "a:err",
                                      "code_for_route": ""})
        if summary_callback is not None:
            summary_callback("error", usage={})
        return [res], {"a:err": ""}

    monkeypatch.setattr(analyzer, "_run_detection", fake_detection_run1)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:t"})
    analyzer.run_analysis(str(ds), str(out),
                          registry=_analyze_registry(), workers=1)

    reset_warning_state()
    ds2 = tmp_path / "ds2.json"
    ds2.write_text(json.dumps({"units": [{"id": "b:retry", "code": "x=1"}]}))

    def fake_detection_run2(units, binding, jc, ac, workers,
                           checkpoint=None, summary_callback=None):
        # an in-run retryable error for the member unit
        res = {"unit_id": "b:retry", "finding": "error", "verdict": "ERROR",
               "error": "429 RESOURCE_EXHAUSTED. Quota exceeded.",
               "error_info": {"type": "rate_limit", "kind": "throttle",
                              "retry_after": 0.1}}
        if summary_callback is not None:
            summary_callback("error", usage={})
        return [res], {u["id"]: "" for u in units}

    def fake_process(binding, unit, i, jc, ac, max_tokens=None):
        res = {"unit_id": unit["id"], "finding": "safe", "verdict": "SAFE",
               "confidence": 90, "vulnerabilities": [], "reasoning": "r"}
        return {"result": res, "route_key": unit["id"],
                "code_for_route": "", "finding": "safe",
                "elapsed": 0.0, "usage": {}}

    monkeypatch.setattr(analyzer, "_run_detection", fake_detection_run2)
    monkeypatch.setattr(analyzer, "_process_unit", fake_process)
    result2 = analyzer.run_analysis(str(ds2), str(out),
                                    registry=_analyze_registry(), workers=1)
    reset_warning_state()

    s = _read_summary(out / "analyze_checkpoints")
    delta = s.get("resume_delta")
    assert delta, f"the retry-pass resume lost the delta: {s!r}"
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_errored_ids"] == ["a:err"], delta
    assert result2.resume_delta == delta, (
        f"the AnalyzeResult must agree with the summary: {result2.resume_delta!r}")
    # the member unit was retried and recovered: it is NOT an error now,
    # and the identity holds through the retry pass (the r1-F5 catch)
    assert s["errors"] == 0, s
    assert (s["completed"] + s["incomplete"] + s["errors"]
            == s["total_units"]), s
    assert s["completed"] == 1, s


# ---------------------------------------------------------------------------
# S2c — the interrupted AGENTIC resume: the enhance summary mid-flight
# ---------------------------------------------------------------------------
def test_the_interrupted_agentic_resume_keeps_the_delta(tmp_path, monkeypatch):
    """The agentic path's initial summary write (the resume-seed block) must
    carry the delta before any unit is processed — an interrupted enhance
    resume leaves the in_progress summary on disk and the operator reads
    exactly that file."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    def _interrupt(unit, index, binding, tracker, verbose):
        raise KeyboardInterrupt("the mid-flight stop")

    monkeypatch.setattr(ce, "enhance_unit_with_agent", _interrupt)

    # y:member is restored from its checkpoint; z:new has NO row, so it is
    # the one unit the executor processes — the interrupt fires on it.
    dataset = {"units": [{"id": "y:member", "code": "x=1"},
                         {"id": "z:new", "code": "x=1"}]}
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    _write_cp(cp_dir, "y", _agentic_cp(
        "y:member", {"security_classification": "safe"}))
    _write_cp(cp_dir, "x", _agentic_cp(
        "x:gone", {"security_classification": "unknown",
                   "error": {"type": "rate_limit", "kind": "quota",
                             "message": "per-day cap"}}))

    import pytest
    with pytest.raises(KeyboardInterrupt):
        enhancer.enhance_dataset_agentic(
            dataset, analyzer_output_path=_analyzer_out(tmp_path),
            repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["phase"] == "in_progress", s
    delta = s.get("resume_delta")
    assert delta, (
        f"the interrupted agentic resume's summary lost the delta: {s!r}")
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_errored_ids"] == ["x:gone"], delta


# ---------------------------------------------------------------------------
# S8 — the BUDGET-retry round keeps the delta (the #569 raised-cap class)
# ---------------------------------------------------------------------------
def test_the_budget_retry_round_keeps_the_delta(tmp_path, monkeypatch):
    """The #569 class: a budget-exhaustion empty completion retries ONCE at
    a raised cap — that round's summary writes are a DISTINCT site from
    the #292 same-cap retry's. A resume carrying a prior-run dropped row
    AND landing its own budget exhaustion must keep the delta through the
    raised-cap round and the final done write."""
    from core import analyzer

    reset_warning_state()
    out = tmp_path / "out"
    # run 1's population: only the dropped unit; the run-2 member is NEW
    ds = tmp_path / "ds.json"
    ds.write_text(json.dumps({"units": [
        {"id": "a:err", "code": "x=1"}]}))

    def fake_detection_run1(units, binding, jc, ac, workers,
                            checkpoint=None, summary_callback=None):
        res = {"unit_id": "a:err", "finding": "error", "verdict": "ERROR",
               "error": "Error code: 402 - storm",
               "error_info": {"type": "api_status", "status_code": 402}}
        if checkpoint is not None:
            checkpoint.save("a:err", {"result": res, "route_key": "a:err",
                                      "code_for_route": ""})
        if summary_callback is not None:
            summary_callback("error", usage={})
        return [res], {"a:err": ""}

    monkeypatch.setattr(analyzer, "_run_detection", fake_detection_run1)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:t"})
    analyzer.run_analysis(str(ds), str(out),
                          registry=_analyze_registry(), workers=1)

    reset_warning_state()
    ds2 = tmp_path / "ds2.json"
    ds2.write_text(json.dumps({"units": [{"id": "b:budget", "code": "x=1"}]}))

    _budget_msg = ("OpenAIAdapter returned an empty completion (no text or "
                   "tool calls; finish_reason='length'); the output budget "
                   "was consumed before any visible content (reasoning "
                   "models spend it on hidden reasoning)")

    def fake_detection_run2(units, binding, jc, ac, workers,
                            checkpoint=None, summary_callback=None):
        res = {"unit_id": "b:budget", "finding": "error", "verdict": "ERROR",
               "error": _budget_msg,
               "error_info": {"type": "empty_completion",
                              "message": _budget_msg}}
        if summary_callback is not None:
            summary_callback("error", usage={})
        return [res], {u["id"]: "" for u in units}

    def fake_process(binding, unit, i, jc, ac, max_tokens=None):
        res = {"unit_id": unit["id"], "finding": "safe", "verdict": "SAFE",
               "confidence": 90, "vulnerabilities": [], "reasoning": "r"}
        return {"result": res, "route_key": unit["id"],
                "code_for_route": "", "finding": "safe",
                "elapsed": 0.0, "usage": {}}

    monkeypatch.setattr(analyzer, "_run_detection", fake_detection_run2)
    monkeypatch.setattr(analyzer, "_process_unit", fake_process)
    result2 = analyzer.run_analysis(str(ds2), str(out),
                                    registry=_analyze_registry(), workers=1)
    reset_warning_state()

    s = _read_summary(out / "analyze_checkpoints")
    delta = s.get("resume_delta")
    assert delta, f"the budget-retry resume lost the delta: {s!r}"
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_errored_ids"] == ["a:err"], delta
    assert result2.resume_delta == delta
    # the budget retry recovered the member unit, and the identity holds
    assert s["errors"] == 0, s
    assert (s["completed"] + s["incomplete"] + s["errors"]
            == s["total_units"]), s
    assert s["completed"] == 1, s


# ---------------------------------------------------------------------------
# S2d — the agentic RETRY rounds keep the delta (the transient-error loop)
# ---------------------------------------------------------------------------
def test_the_agentic_retry_rounds_keep_the_delta(tmp_path, monkeypatch):
    """The agentic path's bounded post-loop transient-error retry (the
    MAX_RETRY_ROUNDS loop) writes its own summary between rounds — a
    resume carrying a prior-run dropped row AND landing an in-run
    retryable error must keep the delta through every round and the done
    write."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    # first call: raise the transient (counted as the round's error);
    # second call: recover.
    calls: dict = {}

    from utilities.llm import LLMRateLimitError

    def _flaky_agent(unit, index, binding, tracker, verbose):
        if unit["id"] == "z:flaky" and unit["id"] not in calls:
            calls[unit["id"]] = 1
            raise LLMRateLimitError("429 RESOURCE_EXHAUSTED. Retry later.",
                                     retry_after=0.1)

    monkeypatch.setattr(ce, "enhance_unit_with_agent", _flaky_agent)

    dataset = {"units": [{"id": "y:member", "code": "x=1"},
                         {"id": "z:flaky", "code": "x=1"}]}
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    _write_cp(cp_dir, "y", _agentic_cp(
        "y:member", {"security_classification": "safe"}))
    _write_cp(cp_dir, "x", _agentic_cp(
        "x:gone", {"security_classification": "unknown",
                   "error": {"type": "rate_limit", "kind": "quota",
                             "message": "per-day cap"}}))

    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    delta = s.get("resume_delta")
    assert delta, f"the agentic retry rounds lost the delta: {s!r}"
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_errored_ids"] == ["x:gone"], delta
    # the identity holds with the retry's recovery
    assert (s["completed"] + s["incomplete"] + s["errors"]
            == s["total_units"]), s
    assert s["errors"] == 0, s


# ---------------------------------------------------------------------------
# S9 — the VERIFY witness: the third leg of the resume chain (r1-F4)
# ---------------------------------------------------------------------------
def test_the_verify_resume_reports_the_dropped_errored_unit(tmp_path, monkeypatch):
    """The verify leg had the IDENTICAL absorption (the r1-F4 finding): a
    foreign verify checkpoint row — including an ERRORED one (the #286
    adapter-raise class) — was never visited, never counted. Verify's
    population shrinks whenever analyze's does, so the same silently-
    absorbed unfinished work. The two-run REAL verify_batch drive."""
    from core.checkpoint import StepCheckpoint
    from utilities.finding_verifier import FindingVerifier

    reset_warning_state()
    binding = _binding("verify")

    class _Idx:
        pass

    def fake_verify_one(self, result, code_by_route):
        route = result.get("route_key", "unknown")
        if result.get("unit_id") == "a:err" or route == "a:err":
            result["error"] = "LLMRateLimitError: Error code: 429"
            result.setdefault("verification", {})["incomplete"] = True
            return route, "error", 0.0, "w", {}
        result["verification"] = {"agree": True, "correct_finding": "safe"}
        return route, "agree:safe", 0.0, "w", {}

    monkeypatch.setattr(FindingVerifier, "_verify_one", fake_verify_one)

    cp_dir = tmp_path / "verify_checkpoints"
    cp = StepCheckpoint("Verify", str(tmp_path))
    cp.dir = str(cp_dir)

    run1 = [
        {"unit_id": "a:err", "route_key": "a:err", "finding": "vulnerable",
         "attack_vector": "a", "reasoning": "r"},
        {"unit_id": "b:ok", "route_key": "b:ok", "finding": "vulnerable",
         "attack_vector": "a", "reasoning": "r"},
    ]
    v = FindingVerifier(index=_Idx(), binding=binding)
    v.verify_batch(run1, {"a:err": "x", "b:ok": "x"}, workers=1, checkpoint=cp)
    s1 = _read_summary(cp_dir)
    assert s1["errors"] == 1, s1

    # run 2 (the resume): the population drops a:err's finding
    reset_warning_state()
    run2 = [
        {"unit_id": "b:ok", "route_key": "b:ok", "finding": "vulnerable",
         "attack_vector": "a", "reasoning": "r"},
    ]
    v2 = FindingVerifier(index=_Idx(), binding=binding)
    v2.verify_batch(run2, {"b:ok": "x"}, workers=1, checkpoint=cp)
    reset_warning_state()

    s2 = _read_summary(cp_dir)
    delta = s2.get("resume_delta")
    assert delta, (
        "the verify resume absorbed the dropped ERRORED row silently "
        f"— no resume_delta block: {s2!r}")
    assert delta["dropped_from_scope"] == 1, delta
    assert delta["dropped_errored_prior_run"] == 1, delta
    assert delta["dropped_errored_ids"] == ["a:err"], delta
    assert (s2["completed"] + s2["incomplete"] + s2["errors"]
            == s2["total_units"]), s2


# ---------------------------------------------------------------------------
# S10/S11 — the PER-UNIT progress windows (r1-F1: the interrupt AFTER the
# first unit lands leaves the per-unit write on disk, not the initial one)
# ---------------------------------------------------------------------------
def test_the_analyze_interrupt_after_a_unit_keeps_the_delta(tmp_path, monkeypatch):
    """The campaign's own shape: the interrupted 12k-unit run where units
    ALREADY landed. The on-disk summary at the interrupt is the PER-UNIT
    progress write — the most-executed write in the phase — so THIS window,
    not the initial-write window, is the one the delta must survive."""
    from core import analyzer
    import pytest

    reset_warning_state()
    out = tmp_path / "out"
    ds = tmp_path / "ds.json"
    ds.write_text(json.dumps({"units": [
        {"id": "a:err", "code": "x"}, {"id": "b:ok", "code": "x"},
        {"id": "c:new", "code": "x"}]}))

    def run1(units, binding, jc, ac, workers, checkpoint=None,
             summary_callback=None):
        rows = []
        for u in units:
            if u["id"] == "a:err":
                res = {"unit_id": "a:err", "finding": "error",
                       "verdict": "ERROR", "error": "402"}
                f = "error"
            else:
                res = {"unit_id": u["id"], "finding": "safe",
                       "verdict": "SAFE", "confidence": 90,
                       "vulnerabilities": [], "reasoning": "r"}
                f = "safe"
            if u["id"] != "c:new":
                checkpoint.save(u["id"], {"result": res,
                                          "route_key": u["id"],
                                          "code_for_route": ""})
                summary_callback(f, usage={})
            rows.append(res)
        return rows, {u["id"]: "" for u in units}

    monkeypatch.setattr(analyzer, "_run_detection", run1)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:t"})
    analyzer.run_analysis(str(ds), str(out),
                          registry=_analyze_registry(), workers=1)

    reset_warning_state()
    ds2 = tmp_path / "ds2.json"
    ds2.write_text(json.dumps({"units": [
        {"id": "b:ok", "code": "x"}, {"id": "c:new", "code": "x"}]}))

    def run2(units, binding, jc, ac, workers, checkpoint=None,
             summary_callback=None):
        # ONE member lands (c:new), THEN the interrupt
        res = {"unit_id": "c:new", "finding": "safe", "verdict": "SAFE",
               "confidence": 90, "vulnerabilities": [], "reasoning": "r"}
        checkpoint.save("c:new", {"result": res, "route_key": "c:new",
                                  "code_for_route": ""})
        summary_callback("safe", usage={})
        raise KeyboardInterrupt("after one unit")

    monkeypatch.setattr(analyzer, "_run_detection", run2)
    with pytest.raises(KeyboardInterrupt):
        analyzer.run_analysis(str(ds2), str(out),
                              registry=_analyze_registry(), workers=1)
    reset_warning_state()

    s = _read_summary(out / "analyze_checkpoints")
    assert s["phase"] == "in_progress" and s["completed"] == 2, s
    delta = s.get("resume_delta")
    assert delta, (
        f"the per-unit progress write dropped the delta: {s!r}")
    assert delta["dropped_errored_ids"] == ["a:err"], delta


def test_the_agentic_interrupt_after_a_unit_keeps_the_delta(tmp_path, monkeypatch):
    """The enhance-side per-unit window: the same shape one leg over."""
    import pytest
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())
    seen: list = []

    def agent(unit, index, binding, tracker, verbose):
        seen.append(unit.get("id"))
        if len(seen) == 2:
            raise KeyboardInterrupt("after one unit")
        unit["agent_context"] = {"security_classification": "safe"}

    monkeypatch.setattr(ce, "enhance_unit_with_agent", agent)
    cp_dir = tmp_path / "cp"
    cp_dir.mkdir()
    _write_cp(cp_dir, "x", _agentic_cp(
        "x:gone", {"security_classification": "unknown",
                   "error": {"type": "rate_limit", "kind": "quota",
                             "message": "per-day cap"}}))

    with pytest.raises(KeyboardInterrupt):
        enhancer.enhance_dataset_agentic(
            {"units": [{"id": "n1", "code": "x"}, {"id": "n2", "code": "x"}]},
            analyzer_output_path=_analyzer_out(tmp_path),
            repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["phase"] == "in_progress" and s["completed"] == 1, s
    delta = s.get("resume_delta")
    assert delta, (
        f"the agentic per-unit progress write dropped the delta: {s!r}")
    assert delta["dropped_errored_ids"] == ["x:gone"], delta


# ---------------------------------------------------------------------------
# S12 — the RETRY-ROUND window (r1-F1: an interrupt during the retry pass
# leaves the per-retried-unit write on disk)
# ---------------------------------------------------------------------------
def test_the_interrupt_inside_the_retry_keeps_the_delta(tmp_path, monkeypatch):
    """An interrupt DURING the retry pass (after the first retried unit
    lands) leaves the per-retried-unit write on disk — the window the
    retry-pass threading serves."""
    from core import analyzer
    import pytest

    reset_warning_state()
    out = tmp_path / "out"
    cp = out / "analyze_checkpoints"
    cp.mkdir(parents=True)
    _write_cp(cp, "a", {"id": "a:err", "result": {
        "unit_id": "a:err", "finding": "error", "verdict": "ERROR",
        "error": "402"}})

    ds = tmp_path / "ds.json"
    ds.write_text(json.dumps({"units": [{"id": "b", "code": "x"},
                                         {"id": "c", "code": "x"}]}))

    def det(units, binding, jc, ac, workers, checkpoint=None,
            summary_callback=None):
        rows = []
        for u in units:
            rows.append({"unit_id": u["id"], "finding": "error",
                         "verdict": "ERROR", "error": "429 RESOURCE_EXHAUSTED",
                         "error_info": {"type": "rate_limit",
                                        "kind": "throttle",
                                        "retry_after": 0.0}})
            summary_callback("error", usage={})
        return rows, {u["id"]: "" for u in units}

    n = [0]

    def proc(binding, unit, i, jc, ac, max_tokens=None):
        n[0] += 1
        if n[0] == 2:
            raise KeyboardInterrupt("during the second retry")
        res = {"unit_id": unit["id"], "finding": "safe", "verdict": "SAFE",
               "confidence": 90, "vulnerabilities": [], "reasoning": "r"}
        return {"result": res, "route_key": unit["id"],
                "code_for_route": "", "finding": "safe",
                "elapsed": 0.0, "usage": {}}

    monkeypatch.setattr(analyzer, "_run_detection", det)
    monkeypatch.setattr(analyzer, "_process_unit", proc)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:t"})
    monkeypatch.setattr(analyzer, "get_rate_limiter",
                        lambda: type("RL", (), {
                            "time_until_ready": lambda s: 0,
                            "wait_if_needed": lambda s: None})())
    with pytest.raises(KeyboardInterrupt):
        analyzer.run_analysis(str(ds), str(out),
                              registry=_analyze_registry(), workers=1)
    reset_warning_state()

    s = _read_summary(cp)
    assert s["phase"] == "in_progress" and s["completed"] == 1, s
    delta = s.get("resume_delta")
    assert delta, (
        f"the per-retried-unit write dropped the delta: {s!r}")
    assert delta["dropped_errored_ids"] == ["a:err"], delta


# ---------------------------------------------------------------------------
# S13 — the agentic per-retried-unit window (relabeled at r3/r4)
# ---------------------------------------------------------------------------
def test_the_agentic_interrupt_inside_the_retry_rounds_keeps_the_delta(tmp_path, monkeypatch):
    """An interrupt on the SECOND RETRIED UNIT of round 1 leaves the
    per-retried-unit write on disk — the window the agentic retry-threading
    serves (the r2-F1 + r3-F2 corrections: no round-end write exists in the
    loop; the drive's call #4 is z2's retry in ROUND 1, after z1's
    round-1 recovery; only 'Retry round 1/3' ever starts)."""
    import pytest
    reset_warning_state()
    import utilities.context_enhancer as ce
    from utilities.llm import LLMRateLimitError
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())
    calls: list = []

    def agent(unit, index, binding, tracker, verbose):
        if unit["id"] in ("z1:flaky", "z2:flaky"):
            calls.append(unit["id"])
            if len(calls) == 4:
                # z2's retry inside ROUND 1 (call 3 = z1 recovered): the
                # PER-RETRIED-UNIT write is the summary now on disk
                raise KeyboardInterrupt("on the second retried unit of round 1")
            if unit["id"] == "z1:flaky" and len(calls) >= 3:
                # round 1 recovers z1; z2's own retry stays inside round 1
                unit["agent_context"] = {"security_classification": "safe"}
                return
            raise LLMRateLimitError("429 RESOURCE_EXHAUSTED. Retry later.",
                                    retry_after=0.1)
        unit["agent_context"] = {"security_classification": "safe"}

    monkeypatch.setattr(ce, "enhance_unit_with_agent", agent)
    cp_dir = tmp_path / "cp"
    cp_dir.mkdir()
    _write_cp(cp_dir, "x", _agentic_cp(
        "x:gone", {"security_classification": "unknown",
                   "error": {"type": "rate_limit", "kind": "quota",
                             "message": "per-day cap"}}))

    with pytest.raises(KeyboardInterrupt):
        enhancer.enhance_dataset_agentic(
            {"units": [{"id": "y:member", "code": "x"},
                       {"id": "z1:flaky", "code": "x"},
                       {"id": "z2:flaky", "code": "x"}]},
            analyzer_output_path=_analyzer_out(tmp_path),
            repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["phase"] == "in_progress", s
    delta = s.get("resume_delta")
    assert delta, (
        f"the agentic retry-round write dropped the delta: {s!r}")
    assert delta["dropped_errored_ids"] == ["x:gone"], delta


# ---------------------------------------------------------------------------
# S14/S15 — the CROSS-MODE census (r1-F2: the row's own context_key)
# ---------------------------------------------------------------------------
def _ss_llm_cp(unit_id, errored):
    ctx = {"missing_dependencies": [], "additional_callers": [],
           "data_flow": {"inputs": [], "outputs": [], "tainted_variables": [],
                         "security_relevant_flows": []},
           "imports": [], "reasoning": "LLM analysis failed, using static analysis only",
           "confidence": 0.3, "security_classification": "unknown"}
    if errored:
        ctx["error"] = {"type": "rate_limit", "kind": "quota",
                        "message": "per-day cap"}
    return {"id": unit_id, "context_key": "llm_context", "llm_context": ctx}


def test_the_single_shot_census_classifies_agentic_rows_by_their_own_key(tmp_path, monkeypatch):
    """r1-F2: a mode switch between runs (agentic -> single-shot) must not
    misclassify a prior-mode ERRORED row as completed — the 88-casualty
    class labeled as its opposite. The row's own context_key decides."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    def _no_work(unit, all_units):
        raise AssertionError("the member is restored; no work is needed")

    monkeypatch.setattr(ce.ContextEnhancer, "enhance_unit", _no_work)
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    # the member's COMPLETED row is an agent_context row; the foreign rows
    # too (a prior AGENTIC run wrote them — one errored, one completed)
    _write_cp(cp_dir, "y", _agentic_cp("y:member",
                                       {"security_classification": "safe"}))
    _write_cp(cp_dir, "x", _agentic_cp(
        "x:gone", {"security_classification": "unknown",
                   "error": {"type": "rate_limit", "kind": "quota",
                             "message": "per-day cap"}}))
    _write_cp(cp_dir, "w", _agentic_cp("w:gone",
                                       {"security_classification": "safe"}))

    dataset = {"units": [{"id": "y:member",
                          "code": {"primary_code": "x=1",
                                   "primary_origin": {"function_name": "f",
                                                      "file_path": "a.py"}}}]}
    enhancer.enhance_dataset(dataset, checkpoint_path=str(cp_dir), workers=1)
    reset_warning_state()

    delta = getattr(enhancer, "_resume_delta", None)
    assert delta, "the single-shot census missed the foreign rows entirely"
    assert delta["dropped_from_scope"] == 2, delta
    assert delta["dropped_errored_prior_run"] == 1, (
        f"the prior-mode ERRORED row was misclassified as completed "
        f"(the r1-F2 bug): {delta!r}")
    assert delta["dropped_errored_ids"] == ["x:gone"], delta


def test_the_agentic_census_classifies_single_shot_rows_by_their_own_key(tmp_path, monkeypatch):
    """The mirror direction: single-shot rows seen by the agentic path."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    def _no_work(unit, index, binding, tracker, verbose):
        raise AssertionError("the member is restored; no work is needed")

    monkeypatch.setattr(ce, "enhance_unit_with_agent", _no_work)
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    _write_cp(cp_dir, "y", _ss_llm_cp("y:member", False))
    _write_cp(cp_dir, "x", _ss_llm_cp("x:gone", True))
    _write_cp(cp_dir, "w", _ss_llm_cp("w:gone", False))

    enhancer.enhance_dataset_agentic(
        {"units": [{"id": "y:member", "code": "x=1"}]},
        analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    delta = getattr(enhancer, "_resume_delta", None)
    assert delta, "the agentic census missed the foreign rows entirely"
    assert delta["dropped_from_scope"] == 2, delta
    assert delta["dropped_errored_prior_run"] == 1, (
        f"the prior-mode ERRORED row was misclassified as completed "
        f"(the r1-F2 bug): {delta!r}")
    assert delta["dropped_errored_ids"] == ["x:gone"], delta


# ---------------------------------------------------------------------------
# S16/S17 — the VERIFY lifecycle windows (the initial + per-unit writes)
# ---------------------------------------------------------------------------
def _verify_drive(tmp_path, monkeypatch, interrupt_on_call):
    """The shared two-part verify drive: a foreign ERRORED row seeded, the
    member unit restored, a NEW unit whose verification interrupts at
    ``interrupt_on_call`` (1 = the first call leaves the INITIAL write on
    disk; 2 = after one lands, the PER-UNIT write)."""
    from core.checkpoint import StepCheckpoint
    from utilities.finding_verifier import FindingVerifier
    import pytest

    reset_warning_state()
    binding = _binding("verify")
    cp_dir = tmp_path / "verify_checkpoints"
    cp_dir.mkdir(parents=True)
    # the prior run's foreign ERRORED row + the member's completed row
    _write_cp(cp_dir, "a", {"id": "a:err",
                            "verification": {"agree": False,
                                             "correct_finding": "error"},
                            "finding": "error",
                            "verification_note": "n",
                            "error": "LLMRateLimitError: Error code: 429"})
    _write_cp(cp_dir, "b", {"id": "b:ok",
                            "verification": {"agree": True,
                                             "correct_finding": "safe"},
                            "finding": "safe",
                            "verification_note": "n"})

    calls = [0]

    class _Idx:
        pass

    def fake_verify_one(self, result, code_by_route):
        calls[0] += 1
        if calls[0] >= interrupt_on_call:
            raise KeyboardInterrupt("the mid-flight stop")
        result["verification"] = {"agree": True, "correct_finding": "safe"}
        return result.get("route_key"), "agree:safe", 0.0, "w", {}

    monkeypatch.setattr(FindingVerifier, "_verify_one", fake_verify_one)
    cp = StepCheckpoint("Verify", str(tmp_path))
    cp.dir = str(cp_dir)
    v = FindingVerifier(index=_Idx(), binding=binding)
    with pytest.raises(KeyboardInterrupt):
        v.verify_batch(
            [{"unit_id": "b:ok", "route_key": "b:ok", "finding": "vulnerable",
              "attack_vector": "a", "reasoning": "r"},
             {"unit_id": "c:new", "route_key": "c:new", "finding": "vulnerable",
              "attack_vector": "a", "reasoning": "r"},
             {"unit_id": "d:new", "route_key": "d:new", "finding": "vulnerable",
              "attack_vector": "a", "reasoning": "r"}],
            {"b:ok": "x", "c:new": "x", "d:new": "x"}, workers=1, checkpoint=cp)
    reset_warning_state()
    return _read_summary(cp_dir)


def test_the_verify_interrupt_before_a_unit_keeps_the_delta(tmp_path, monkeypatch):
    """The verify INITIAL write's window: an interrupt before any unit
    lands leaves the seed-block write on disk."""
    s = _verify_drive(tmp_path, monkeypatch, interrupt_on_call=1)
    # the restored member seeds completed=1; no NEW unit landed yet
    assert s["phase"] == "in_progress" and s["completed"] == 1, s
    delta = s.get("resume_delta")
    assert delta, f"the verify initial write dropped the delta: {s!r}"
    assert delta["dropped_errored_ids"] == ["a:err"], delta


def test_the_verify_interrupt_after_a_unit_keeps_the_delta(tmp_path, monkeypatch):
    """The verify PER-UNIT write's window: an interrupt after the first
    unit lands leaves the progress write on disk."""
    s = _verify_drive(tmp_path, monkeypatch, interrupt_on_call=2)
    # the restored member + the one landed NEW unit
    assert s["phase"] == "in_progress" and s["completed"] == 2, s
    delta = s.get("resume_delta")
    assert delta, f"the verify per-unit write dropped the delta: {s!r}"
    assert delta["dropped_errored_ids"] == ["a:err"], delta


# ---------------------------------------------------------------------------
# S18 — the hostile-row tolerance lock (the r2-F3 catch)
# ---------------------------------------------------------------------------
def test_a_non_dict_context_row_does_not_crash_the_single_shot_census(tmp_path, monkeypatch):
    """The r3-F1 catch: stripping the isinstance guard from the
    single-shot census ALONE survives an agentic-only drive — this leg
    drives the llm_context-keyed hostile rows through the REAL
    single-shot path (no crash, the hostile rows read NOT-errored, the
    real ERRORED row classifies)."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    def _no_work(unit, all_units):
        raise AssertionError("the member is restored; no work is needed")

    monkeypatch.setattr(ce.ContextEnhancer, "enhance_unit", _no_work)
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    _write_cp(cp_dir, "y", _ss_llm_cp("y:member", False))
    # the hostile rows, keyed the single-shot way
    _write_cp(cp_dir, "n", {"id": "n:gone", "context_key": "llm_context",
                             "llm_context": None})
    _write_cp(cp_dir, "s", {"id": "s:gone", "context_key": "llm_context",
                             "llm_context": "corrupt"})
    _write_cp(cp_dir, "x", _ss_llm_cp("x:gone", True))

    # MUST NOT RAISE (the pre-guard head crashed on this leg too)
    dataset = {"units": [{"id": "y:member",
                          "code": {"primary_code": "x=1",
                                   "primary_origin": {"function_name": "f",
                                                      "file_path": "a.py"}}}]}
    enhancer.enhance_dataset(dataset, checkpoint_path=str(cp_dir), workers=1)
    reset_warning_state()

    delta = getattr(enhancer, "_resume_delta", None)
    assert delta, "the single-shot census missed the foreign rows entirely"
    assert delta["dropped_from_scope"] == 3, delta
    assert delta["dropped_errored_prior_run"] == 1, (
        f"the non-dict contexts must read NOT-errored (the tolerance), "
        f"and the real ERRORED row must still classify: {delta!r}")
    assert delta["dropped_errored_ids"] == ["x:gone"], delta


def test_a_non_dict_context_row_does_not_crash_the_agentic_census(tmp_path, monkeypatch):
    """r2-F3: a foreign row whose context is null or a STRING (a corrupt or
    hand-edited checkpoint file) must not crash the resume — the base
    tolerated the row; the census mirrors _load_completed_units' isinstance
    tolerance (the row reads NOT-errored, the resume proceeds)."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    def _no_work(unit, index, binding, tracker, verbose):
        raise AssertionError("the member is restored; no work is needed")

    monkeypatch.setattr(ce, "enhance_unit_with_agent", _no_work)
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    _write_cp(cp_dir, "y", _agentic_cp("y:member",
                                       {"security_classification": "safe"}))
    # the hostile rows: a NULL context and a STRING context
    _write_cp(cp_dir, "n", {"id": "n:gone", "context_key": "agent_context",
                             "agent_context": None})
    _write_cp(cp_dir, "s", {"id": "s:gone", "context_key": "agent_context",
                             "agent_context": "corrupt"})
    # an ERRORED row alongside, to prove the crash did not eat the real one
    _write_cp(cp_dir, "x", _agentic_cp(
        "x:gone", {"security_classification": "unknown",
                   "error": {"type": "rate_limit", "kind": "quota",
                             "message": "per-day cap"}}))

    # MUST NOT RAISE (the pre-guard head crashed here: AttributeError)
    enhancer.enhance_dataset_agentic(
        {"units": [{"id": "y:member", "code": "x=1"}]},
        analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    delta = getattr(enhancer, "_resume_delta", None)
    assert delta, "the census missed the foreign rows entirely"
    assert delta["dropped_from_scope"] == 3, delta
    assert delta["dropped_errored_prior_run"] == 1, (
        f"the non-dict contexts must read NOT-errored (the tolerance), "
        f"and the real ERRORED row must still classify: {delta!r}")
    assert delta["dropped_errored_ids"] == ["x:gone"], delta


# ---------------------------------------------------------------------------
# S19 — the ZERO-DROP resume: the holder's present-only contract
# ---------------------------------------------------------------------------
def test_a_zero_drop_resume_keeps_the_holder_absent(tmp_path, monkeypatch):
    """The battery's every agentic/single-shot drive carries foreign rows —
    the ZERO-drop resume was uncovered. This node pins the holder's own
    present-only contract: a fresh instance reads None (the __init__ the
    C4 write-site floor demanded cover for — this direct read is what
    makes the init observable), a zero-drop checkpointed run keeps it
    None (the census assigns build_resume_delta(()) -> None), and the
    phase _summary.json carries NO resume_delta key."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    enhancer = ce.ContextEnhancer(binding=_binding(), tracker=TokenTracker())

    # the fresh instance: None, never an empty block
    assert enhancer._resume_delta is None, (
        "the holder's fresh-instance contract is None (present-only), "
        f"not {enhancer._resume_delta!r}")

    def _no_work(unit, index, binding, tracker, verbose):
        raise AssertionError("the member is restored; no work is needed")

    monkeypatch.setattr(ce, "enhance_unit_with_agent", _no_work)
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    # every row IS a member: nothing foreign, nothing dropped
    _write_cp(cp_dir, "y", _agentic_cp("y:member",
                                       {"security_classification": "safe"}))

    enhancer.enhance_dataset_agentic(
        {"units": [{"id": "y:member", "code": "x=1"}]},
        analyzer_output_path=_analyzer_out(tmp_path),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    # the zero-drop run: the holder stays None and the summary carries
    # NO block (a block here would cry wolf on every clean resume)
    assert enhancer._resume_delta is None, (
        f"the zero-drop holder must stay None: {enhancer._resume_delta!r}")
    s = _read_summary(cp_dir)
    assert "resume_delta" not in s, (
        f"the zero-drop summary must carry no block: {s!r}")
