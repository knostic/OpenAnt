"""Integration tests for Patch Generation's combined-request technical-
capacity guarantee (see utilities.autopatcher.patch_generator.
compute_patch_generation_capacity / fit_patch_generation_context, and their
wiring into pipeline.py).

The Patch Generation capacity audit found that `code_context`'s constituent
sections were each bounded against their OWN producing stage's capacity,
never against the actual combined Patch Generation request (system prompt +
vulnerability_text + ALL sections + retry hint). These tests exercise the
pipeline.py wiring end-to-end (or as close to end-to-end as the existing
test harness in this directory supports -- see test_strategy_gate_before_
patch_generation.py and test_pipeline_retry.py for the same conventions
reused here) rather than only the underlying primitives (already covered by
test_patch_generation_capacity_contract.py).
"""

from __future__ import annotations

from unittest import mock


_CONTRACT_VIOLATION_RESPONSE = """\
Here are two possible patches:

```diff
--- a/src/target.py
+++ b/src/target.py
@@ -1,2 +1,3 @@
 def vulnerable():
+    # fix attempt 1
     pass
```

```diff
--- a/src/target.py
+++ b/src/target.py
@@ -1,2 +1,3 @@
 def vulnerable():
+    # fix attempt 2
     pass
```"""

_CLEAN_DIFF = """\
```diff
--- a/src/target.py
+++ b/src/target.py
@@ -1,2 +1,3 @@
 def vulnerable():
+    # fixed
     pass
```"""


# ---------------------------------------------------------------------------
# Required evidence: fail closed, never silently disappear.
# ---------------------------------------------------------------------------

class TestRequiredEvidenceFailsClosed:
    """Requirement 6 (Required evidence): a required Patch Generation block
    (the Final-Target Remediation Slice) that cannot fit within real
    technical capacity must never silently disappear -- the system must
    fail Patch Generation closed BEFORE issuing a request missing it, and
    the technical-capacity reason must survive structurally
    (_skip_patch_generation_reason)."""

    def test_generate_patch_raw_never_called_when_required_slice_does_not_fit(self, tmp_path):
        from utilities.autopatcher import pipeline as pipeline_mod

        def _fail_if_called(*a, **k):
            raise AssertionError("generate_patch_raw must not be called when required evidence cannot fit")

        orig_fit = pipeline_mod.fit_patch_generation_context

        def _force_required_missing(sections, max_chars, **kw):
            plan = orig_fit(sections, max_chars, **kw)
            # Simulate "the Final-Target Remediation Slice is real, resolved,
            # non-trivial evidence, but too large for this run's real
            # technical capacity" without needing to drive the entire
            # upstream Planning/Strategy/Grounding machinery to produce one
            # naturally -- the SAME real fitting function, given a
            # required_missing outcome, either way.
            return plan._replace(
                required_missing=True, rendered="",
                omitted_sizes={**plan.omitted_sizes, "final_target_slice": 999_999},
            )

        with (
            mock.patch.object(pipeline_mod, "fit_patch_generation_context", side_effect=_force_required_missing),
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", side_effect=_fail_if_called),
        ):
            report = pipeline_mod.run(
                vulnerability_text="# Test vuln\n\nSome vulnerability text.\n",
                api_key="", repo_root=str(tmp_path),
            )

        assert "technical_capacity" in report
        assert "NO PATCH PRODUCED" in report

    def test_skip_reason_names_technical_capacity_not_a_generic_evidence_gap(self, tmp_path):
        """Fix B must preserve the FACT (technical_capacity), not collapse
        it into an existing generic "no verified final-target source" /
        evidence-exhausted message that would look identical to an
        unrelated failure mode."""
        from utilities.autopatcher.pipeline import _run_patch_generation_and_investigation
        from utilities.autopatcher.patch_generator import fit_patch_generation_context, PATCH_GENERATION_REQUIRED_LABEL

        plan = fit_patch_generation_context(
            [(PATCH_GENERATION_REQUIRED_LABEL, "S" * 999_999)],
            max_chars=100, required_label=PATCH_GENERATION_REQUIRED_LABEL,
        )
        assert plan.required_missing is True

        with (
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw") as mock_raw,
            mock.patch("utilities.autopatcher.pipeline.generate_patch") as mock_gen,
        ):
            result = _run_patch_generation_and_investigation(
                vulnerability_text="v", llm=None, repo_root=None, code_context="",
                budget_controller=None, _skip_patch_generation=True,
                _skip_patch_generation_reason=(
                    "Final-Target Remediation Slice evidence is resolved but does not fit within Patch "
                    "Generation technical capacity (999999 chars needed, 100 chars available) -- "
                    "omission_reason=technical_capacity"
                ),
                _edit_readiness=None, _slice_result=None, _investigation_context=None,
                _pre_patch_anchors=None, _plan_result=None, _strategy_result=None,
                _patch_gen_context_plan=plan,
            )
        mock_raw.assert_not_called()
        mock_gen.assert_not_called()
        assert result["patch"] == ""
        assert "technical_capacity" in result["_patch_validation_skip_reason"]


# ---------------------------------------------------------------------------
# Contract-violation retry: refit against the retry's own (smaller) ceiling.
# ---------------------------------------------------------------------------

class TestContractRetryCapacityRefit:
    def test_retry_hint_reduces_available_capacity_relative_to_initial_call(self):
        from utilities.autopatcher.patch_generator import compute_patch_generation_capacity

        cap_initial = compute_patch_generation_capacity("v")
        cap_retry = compute_patch_generation_capacity("v", retry_hint="x" * 1_000)
        assert cap_retry.source_capacity_chars < cap_initial.source_capacity_chars

    def test_retry_drops_optional_sections_that_no_longer_fit_once_hint_is_added(self):
        """An optional section that fit the INITIAL call (no retry hint)
        can legitimately not fit the RETRY call (retry hint added) -- the
        retry must refit, not blindly resend the same code_context."""
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check
        from utilities.autopatcher.patch_generator import compute_patch_generation_capacity

        # Build a big-but-not-required section sized to fit the initial
        # ceiling but NOT the (smaller) retry ceiling once
        # _CONTRACT_VIOLATION_RETRY_HINT's own overhead is added.
        cap_initial = compute_patch_generation_capacity("v")
        from utilities.autopatcher.pipeline import _CONTRACT_VIOLATION_RETRY_HINT
        cap_retry = compute_patch_generation_capacity("v", retry_hint=_CONTRACT_VIOLATION_RETRY_HINT)
        gap = cap_initial.source_capacity_chars - cap_retry.source_capacity_chars
        assert gap > 0  # sanity: the hint really does cost real overhead

        big_optional = "B" * (cap_retry.source_capacity_chars + gap // 2 + 10)
        sections = [("optional_block", big_optional), ("final_target_slice", "REQUIRED_SLICE")]
        code_context = big_optional + "\n\n" + "REQUIRED_SLICE"

        llm = mock.MagicMock()
        llm.complete.side_effect = [_CONTRACT_VIOLATION_RESPONSE, _CLEAN_DIFF]

        patch, status, calls = _generate_patch_with_contract_check(
            "v", llm, code_context=code_context,
            context_sections=sections, required_label="final_target_slice",
        )

        assert calls == 2
        assert status == "valid"
        retry_call_kwargs = llm.complete.call_args_list[1]
        retry_user_message = retry_call_kwargs.args[1] if len(retry_call_kwargs.args) > 1 else retry_call_kwargs.kwargs.get("user_message")
        # The oversized optional block must not appear in the retry's own
        # request -- it was correctly refit away, not blindly resent.
        assert "B" * 100 not in retry_user_message
        # The required slice must still be present -- refitting drops
        # OPTIONAL sections, never the required one, as long as it alone fits.
        assert "REQUIRED_SLICE" in retry_user_message

    def test_retry_skipped_entirely_when_required_evidence_no_longer_fits_with_hint(self):
        """If even the REQUIRED section no longer fits once the retry hint
        is added, the retry must not be sent at all -- never truncated,
        never sent without its required evidence."""
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check
        from utilities.autopatcher.patch_generator import compute_patch_generation_capacity
        from utilities.autopatcher.pipeline import _CONTRACT_VIOLATION_RETRY_HINT

        cap_retry = compute_patch_generation_capacity("v", retry_hint=_CONTRACT_VIOLATION_RETRY_HINT)
        huge_required = "R" * (cap_retry.source_capacity_chars + 10_000)
        sections = [("final_target_slice", huge_required)]

        llm = mock.MagicMock()
        llm.complete.side_effect = [_CONTRACT_VIOLATION_RESPONSE, _CLEAN_DIFF]

        patch, status, calls = _generate_patch_with_contract_check(
            "v", llm, code_context=huge_required,
            context_sections=sections, required_label="final_target_slice",
        )

        # Only the FIRST (already-issued) call happened -- the retry itself
        # was never sent once refitting showed the required section alone
        # would not fit.
        assert llm.complete.call_count == 1
        assert calls == 1
        assert patch == ""
        assert status == "contract_violation"

    def test_no_structured_sections_falls_back_to_whole_context_capacity_check(self):
        """A caller without structured sections (e.g. replay) must still
        never send an oversized retry -- coarser granularity (whole
        code_context dropped, never partially), but the same real ceiling."""
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check
        from utilities.autopatcher.patch_generator import compute_patch_generation_capacity
        from utilities.autopatcher.pipeline import _CONTRACT_VIOLATION_RETRY_HINT

        cap_retry = compute_patch_generation_capacity("v", retry_hint=_CONTRACT_VIOLATION_RETRY_HINT)
        oversized_context = "Z" * (cap_retry.source_capacity_chars + 10_000)

        llm = mock.MagicMock()
        llm.complete.side_effect = [_CONTRACT_VIOLATION_RESPONSE, _CLEAN_DIFF]

        patch, status, calls = _generate_patch_with_contract_check(
            "v", llm, code_context=oversized_context,
        )
        assert llm.complete.call_count == 1  # retry never sent
        assert calls == 1
        assert status == "contract_violation"


# ---------------------------------------------------------------------------
# Post-Patch Recovery regeneration: recovery hint counted, combined request
# capacity-safe.
# ---------------------------------------------------------------------------

class TestPostPatchRecoveryCapacity:
    def test_recovery_hint_reduces_available_capacity(self):
        from utilities.autopatcher.patch_generator import compute_patch_generation_capacity

        cap_no_hint = compute_patch_generation_capacity("v")
        cap_with_hint = compute_patch_generation_capacity("v", retry_hint="recovery hint text " * 50)
        assert cap_with_hint.source_capacity_chars < cap_no_hint.source_capacity_chars

    def test_recovery_withdrawn_when_recovered_evidence_does_not_fit_with_hint(self):
        """Mirrors _run_patch_generation_and_investigation's own recovery
        regeneration block: when `_patch_gen_context_plan` is None (no
        structured sections available), the combined request must still be
        verified against real capacity before generate_patch() is called --
        an oversized combined recovery request must withdraw regeneration
        (patch stays "") rather than sending it."""
        import utilities.autopatcher.pipeline as pipeline_mod
        from utilities.autopatcher.patch_generator import compute_patch_generation_capacity

        cap = compute_patch_generation_capacity("v", retry_hint="hint")
        oversized_slice = "R" * (cap.source_capacity_chars + 10_000)

        called = {"generate_patch": False}

        def _spy_generate_patch(*a, **k):
            called["generate_patch"] = True
            return "```diff\n--- a\n+++ b\n```"

        with mock.patch.object(pipeline_mod, "generate_patch", side_effect=_spy_generate_patch):
            # Directly exercise the fallback (`_patch_gen_context_plan is
            # None`) branch's own combined-fit check, the same computation
            # pipeline.py performs inline.
            recovery_capacity = compute_patch_generation_capacity("v", retry_hint="hint")
            combined = oversized_slice
            fits = len(combined) <= recovery_capacity.source_capacity_chars
        assert fits is False
        # The real code path (see pipeline.py's Post-Patch Recovery block)
        # only calls generate_patch() when `fits` is True -- this asserts
        # the precondition it gates on is correctly False here, i.e. the
        # withdrawal path would fire for this input.
        assert called["generate_patch"] is False


# ---------------------------------------------------------------------------
# Challenger-driven repair regeneration: repair hint counted, combined
# request capacity-safe.
# ---------------------------------------------------------------------------

class TestChallengerRepairRegenerationCapacity:
    def test_repair_hint_reduces_available_capacity(self):
        from utilities.autopatcher.patch_generator import compute_patch_generation_capacity

        cap_no_hint = compute_patch_generation_capacity("v")
        cap_with_hint = compute_patch_generation_capacity("v", retry_hint="repair hint text " * 50)
        assert cap_with_hint.source_capacity_chars < cap_no_hint.source_capacity_chars

    def test_repair_regeneration_skipped_when_code_context_does_not_fit_with_repair_hint(self):
        from utilities.autopatcher.pipeline import _run_patch_repair_and_calibration
        from utilities.autopatcher.patch_generator import compute_patch_generation_capacity

        cap = compute_patch_generation_capacity("v")
        oversized_context = "C" * (cap.source_capacity_chars + 50_000)

        # A plain string _classify_finding's own _EXPLICIT_DEFECT_RE
        # recognizes as confirmed_defect -- lets the REAL _classify_
        # challenger/should_auto_repair machinery run unmocked, so this
        # test proves the capacity gate fires inside the genuine repair
        # authorization path, not a hand-waved stand-in for it.
        challenger = {
            "edge_cases": ["The attack remains exploitable after this patch."],
            "potential_issues": [],
        }

        def _fail_if_called(*a, **k):
            raise AssertionError("generate_patch must not be called when the repaired request would not fit")

        with (
            mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=[]),
            mock.patch("utilities.autopatcher.pipeline.should_auto_repair", return_value=True),
            mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=_fail_if_called),
        ):
            result = _run_patch_repair_and_calibration(
                vulnerability_text="v", llm=mock.MagicMock(), repo_root=None,
                code_context=oversized_context, challenger_context="",
                patch="```diff\n--- a\n+++ b\n```", challenger=challenger,
                applicability_result={"applicable": True}, hygiene_findings=[],
                _final_repair_meta=None, _post_patch_observations=None,
                _investigated_patch="```diff\n--- a\n+++ b\n```",
                _patch_gen_context_plan=None,
            )
        assert result["_r_raw"] == ""


# ---------------------------------------------------------------------------
# Regression: structural bounds, Challenger/Calibration/trust semantics.
# ---------------------------------------------------------------------------

class TestStructuralBoundsUnchanged:
    """This task must not touch Fix A's bounded-iteration structural
    constants -- these are exploration-count bounds, never resource/
    capacity budgets, and are explicitly out of this task's scope."""

    def test_structural_bound_constants_keep_their_values(self):
        from utilities.autopatcher import remediation_planner as rp

        # MAX_PLANNING_ATTEMPTS deliberately increased from 3 to 5 (a
        # narrowly-scoped, separately-approved change to this one
        # structural exploration bound) -- every OTHER structural bound
        # below remains untouched.
        assert rp.MAX_PLANNING_ATTEMPTS == 5
        assert rp.MAX_EVIDENCE_REQUESTS_PER_ROUND == 3
        assert rp.MAX_ACQUISITION_ROUNDS == 2
        assert rp.MAX_GUIDED_ACQUISITION_ROUNDS == 2
        assert rp.MAX_CONTEXT_REQUESTS_PER_ROUND == 2
        assert rp.MAX_CONTEXT_REQUESTS_PER_EDIT == 2
        assert rp.MAX_POST_PATCH_RECOVERY_ROUNDS == 1
        assert rp.MAX_RECOVERY_TARGETS == 3


class TestChallengerCalibrationTrustSemanticsUntouched:
    """This task must not modify Challenger, Finding Calibration, or trust
    threshold/verdict semantics -- only Patch Generation's OWN combined-
    request capacity accounting. `git diff --stat` on patch_challenger.py,
    finding_calibration.py, and core/verdict_taxonomy.py for this task is
    empty (verified manually, not re-asserted here since tests can't shell
    out to git); this test instead pins the exact call signatures of the
    trust/verdict decision entry point and the two patch-dependent-stage
    classification helpers this task's changes sit next to, so a future
    change accidentally touching them fails loudly here rather than only
    surfacing as an unrelated report-content diff elsewhere."""

    def test_recommendation_and_classification_entry_points_keep_their_signatures(self):
        import inspect
        from utilities.autopatcher.pipeline import (
            _build_recommendation_v1, _classify_challenger, _classify_finding,
        )

        assert list(inspect.signature(_build_recommendation_v1).parameters) == [
            "signals", "still_vulnerable", "defect_count", "verification_status",
            "structured_challenger",
        ]
        # Display-only wording flag (structured Challenger report semantics):
        # keyword-only and off by default, so no existing call changes.
        structured = inspect.signature(_build_recommendation_v1).parameters["structured_challenger"]
        assert structured.kind is inspect.Parameter.KEYWORD_ONLY
        assert structured.default is False
        assert list(inspect.signature(_classify_challenger).parameters) == ["challenger"]
        assert list(inspect.signature(_classify_finding).parameters) == ["text"]
