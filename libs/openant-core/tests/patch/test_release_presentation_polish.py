"""Release presentation polish (release preparation step 3).

Presentation only: the terminal and the Trust Report must state what the
existing pipeline already established -- never more. Every test here pins
wording/structure; none may observe a changed decision or signal value.

Covers:
- Deploy After Validation never claims the vulnerability is fixed.
- Adversarial-review signal notes are evidence-scoped.
- Non-blocking adverse Trust Signal rows read "❌ Concern", not "❌ Blocked".
- Structured Challenger concerns never yield the legacy "No actionable
  adversarial findings found" fallback.
- NO PATCH PRODUCED reports describe no property of a nonexistent patch.
- The terminal closing block agrees with the report.
- The batch runner's report-parsing contract still holds.
- Parser diagnostic noise is hidden under Auto Patcher's quiet gate.
"""
from __future__ import annotations

import sys
import textwrap
from unittest import mock

import pytest

import core.parser_adapter as parser_adapter
from utilities.autopatcher import pipeline as pl
from utilities.autopatcher import progress
from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
from utilities.autopatcher.tools.run_cve_batch import parse_trust_report

PATCH = (
    "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
    " def foo():\n-    return 1\n+    return 2\n"
)
APPLIES = {"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""}
REVIEW = (
    "**Explanation:**\nThe code was vulnerable because of X.\n\n"
    "**Affected areas:**\n- mod.py\n\n"
    "**Validation notes:**\n- Test with payload Y.\n"
)
INVARIANT = (
    "A resolved request path must not escape the configured data root directory, whether "
    "through '../' components, absolute paths, or symlinks pointing outside the root."
)
UNGROUNDED = "planning_ungrounded: ungrounded_unresolvable"
NO_OPEN_CONCERN = (
    "No blocking or unresolved adversarial concern (heuristic review; not independent verification)"
)
OVERCLAIMS = (
    "addresses the attack vector",
    "confirms fix approach",
    "found no remaining exploit path",
    "test files cover this module",
    "low regression risk",
    "Security gain",
)


def _concern(consequence, role):
    return {
        "concern_role": role,
        "description": f"a {consequence.lower()} concern",
        "default_execution_reachability": None,
        "requires_explicit_non_default_action": "not_applicable",
        "contract_addresses_override": "not_applicable",
        "malformed": False,
        "malformed_reason": None,
        "consequence": consequence,
    }


def _structured(*consequences):
    """Structured Challenger output whose aggregate comes from the
    production aggregation rule, never asserted by hand."""
    concerns = [_concern(c, "primary" if i == 0 else "additional") for i, c in enumerate(consequences)]
    status, still = _derive_status_from_concerns(concerns, legacy_prose_present=False)
    return {
        "verification_status": status, "still_vulnerable": still,
        "edge_cases": [], "potential_issues": [], "summary": "",
        "concerns": concerns, "schema_version": "concerns_v2",
    }


def _result(*, challenger, patch=PATCH, impact_level="low", applicability=APPLIES,
            vulnerability_text="# Test vulnerability\n\nSome description.", repo_root=None):
    return pl.PipelineResult(
        vulnerability_text=vulnerability_text,
        patch=patch,
        review=REVIEW if patch else "",
        score_text="",
        challenger=challenger,
        impact={
            "impact_level": impact_level, "changed_files": [], "affected_files": [],
            "impact_summary": "", "recommendations": [], "usage_matches": [],
        },
        hygiene=[],
        applicability=applicability,
        security_invariant=INVARIANT if patch else None,
        repo_root=repo_root,
        detected_language="python",
    )


SCENARIOS = {
    "green": dict(challenger=_structured("NON_BLOCKING", "NON_BLOCKING")),
    "orange_blocking": dict(challenger=_structured("BLOCKING", "UNRESOLVED")),
    "orange_insufficient": dict(challenger=_structured("UNRESOLVED")),
    "orange_high_impact": dict(challenger=_structured("NON_BLOCKING"), impact_level="high"),
    "do_not_apply": dict(
        challenger=_structured("NON_BLOCKING"),
        applicability={"applicable": False, "skipped": False, "skipped_reason": None,
                       "error": None, "stderr": "error: patch failed: mod.py:1"},
    ),
    "no_patch": dict(
        challenger={}, patch="",
        applicability={"applicable": None, "skipped": True, "skipped_reason": UNGROUNDED,
                       "error": None, "stderr": ""},
    ),
}
EXPECTED_HEADING = {
    "green": "🟢 DEPLOY AFTER VALIDATION",
    "orange_blocking": "🟠 MANUAL REVIEW REQUIRED",
    "orange_insufficient": "🟠 MANUAL REVIEW REQUIRED",
    "orange_high_impact": "🟠 MANUAL REVIEW REQUIRED",
    "do_not_apply": "🔴 DO NOT APPLY",
    "no_patch": "⚫ NO PATCH PRODUCED",
}


@pytest.fixture(autouse=True)
def _reset_progress():
    progress.configure()
    yield
    progress.reset_for_tests()


def _render(name, capsys):
    report = pl._build_report(_result(**SCENARIOS[name]))
    return report, capsys.readouterr().err


def _section(report, heading):
    start = report.index(f"\n{heading}\n")
    end = report.find("\n## ", start + 1)
    return report[start:end if end != -1 else None]


def _trust_rows(report):
    return [line for line in report.splitlines() if line.startswith("| ") and " | " in line[2:]]


# ---------------------------------------------------------------------------
# 1. Green never claims verified vulnerability closure
# ---------------------------------------------------------------------------

class TestGreenNoClosureClaim:
    def test_report_reason_states_evidence_not_a_fix(self, capsys):
        report, _ = _render("green", capsys)
        assert report.splitlines()[2] == "## 🟢 DEPLOY AFTER VALIDATION"
        rec = _section(report, "## Recommendation")
        assert "**Deploy After Validation**" in rec
        assert "applies cleanly with no hygiene issues" in rec
        assert "raised no blocking or unresolved concern" in rec
        assert "not proof that the vulnerability is fixed" in rec
        assert "validation actions" in rec

    def test_terminal_green_reason_not_proof(self, capsys):
        _, err = _render("green", capsys)
        assert "🟢 DEPLOY AFTER VALIDATION" in err
        assert "Not proof that the vulnerability is fixed." in err
        assert "Next      Complete the validation actions in the Trust Report before deploying." in err

    @pytest.mark.parametrize("name", sorted(SCENARIOS))
    def test_no_overclaim_strings_on_either_surface(self, name, capsys):
        report, err = _render(name, capsys)
        for phrase in OVERCLAIMS:
            assert phrase not in report, (name, phrase)
            assert phrase not in err, (name, phrase)


# ---------------------------------------------------------------------------
# 2. Adversarial-review wording is evidence-scoped; values unchanged
# ---------------------------------------------------------------------------

class TestAdversarialReviewWording:
    @pytest.mark.parametrize("challenger", [
        _structured("NON_BLOCKING", "NON_BLOCKING"),
        {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""},
    ], ids=["structured", "legacy"])
    def test_not_still_vulnerable_notes_are_evidence_scoped(self, challenger):
        signals = pl._compute_trust_signals([], APPLIES, pl._classify_challenger(challenger), "Good", "low")
        assert signals["remediation_alignment"]["value"] == "Aligned"
        assert signals["security_improvement"]["value"] == "High"
        assert signals["remediation_alignment"]["notes"] == NO_OPEN_CONCERN
        assert signals["security_improvement"]["notes"] == NO_OPEN_CONCERN

    def test_green_trust_row_wording(self, capsys):
        report, _ = _render("green", capsys)
        row = next(r for r in _trust_rows(report) if r.startswith("| Does it address the vulnerability?"))
        assert row == f"| Does it address the vulnerability? | ✅ Good | {NO_OPEN_CONCERN} |"

    def test_test_and_impact_notes_describe_static_heuristics(self):
        signals = pl._compute_trust_signals([], APPLIES, pl._classify_challenger({}), "Good", "low")
        assert signals["test_availability"]["value"] == "Tests Available"
        assert signals["test_availability"]["notes"] == (
            "Good — related test files found by file name (not run; coverage not measured)"
        )
        assert signals["deployment_safety"]["value"] == "Low Risk"
        assert signals["deployment_safety"]["notes"] == "Localized change · small static impact surface"
        no_tests = pl._compute_trust_signals([], APPLIES, pl._classify_challenger({}), "None", "low")
        assert no_tests["test_availability"]["notes"] == "No related test files found by file name"


# ---------------------------------------------------------------------------
# 3. "Blocked" only where the signal actually blocks
# ---------------------------------------------------------------------------

class TestConcernNotBlocked:
    def test_orange_rows_never_say_blocked(self, capsys):
        for name in ("orange_blocking", "orange_insufficient", "orange_high_impact"):
            report, _ = _render(name, capsys)
            assert report.splitlines()[2] == "## 🟠 MANUAL REVIEW REQUIRED", name
            assert not [r for r in _trust_rows(report) if "❌ Blocked" in r], name

    def test_high_impact_row_is_concern(self, capsys):
        report, _ = _render("orange_high_impact", capsys)
        row = next(r for r in _trust_rows(report) if r.startswith("| Is deployment risk low?"))
        assert "| ❌ Concern |" in row

    def test_do_not_apply_integrity_row_is_blocked(self, capsys):
        report, _ = _render("do_not_apply", capsys)
        assert report.splitlines()[2] == "## 🔴 DO NOT APPLY"
        row = next(r for r in _trust_rows(report) if r.startswith("| Does the patch apply?"))
        assert "| ❌ Blocked |" in row

    @pytest.mark.parametrize("key,value,question", [
        ("remediation_alignment", "Misaligned", "Does it address the vulnerability?"),
        ("coverage_confidence", "Low", "Are there unresolved concerns?"),
        ("deployment_safety", "High Risk", "Is deployment risk low?"),
    ])
    def test_non_blocking_adverse_values_render_concern(self, key, value, question):
        signals = pl._compute_trust_signals([], APPLIES, pl._classify_challenger({}), "Good", "low")
        signals[key] = {"value": value, "label": value, "notes": "x"}
        signals["source_verification"] = {"value": "Confirmed", "label": "", "notes": ""}
        signals["existing_test_comparison"] = {"value": "PASS", "label": "", "notes": ""}
        table = pl._render_trust_signals_table(signals)
        row = next(line for line in table.splitlines() if line.startswith(f"| {question} |"))
        assert "| ❌ Concern |" in row
        # None of these values can block: only patch_integrity reaches Do
        # Not Apply (I4). (coverage_confidence is display-only -- no gate
        # reads it.)
        assert pl._build_recommendation_v1(signals)["decision"] != "Do Not Apply"

    def test_legend_describes_rendered_rows(self, capsys):
        report, _ = _render("orange_high_impact", capsys)
        legend = _section(report, "## Trust Signals").split("| Question |")[0]
        for row in _trust_rows(report)[1:8]:
            question = row.split(" | ")[0][2:]
            assert f'"{question}"' in legend, question
        assert "Static heuristics, nothing executed" in legend
        assert "test-file name matching" in legend
        assert "not independent verification" in legend
        assert "Patch Integrity" not in legend

    def test_high_impact_reason_says_assessed_not_unverified(self, capsys):
        report, _ = _render("orange_high_impact", capsys)
        rec = _section(report, "## Recommendation")
        assert "Deployment risk was assessed as high (HIGH impact surface)." in rec
        assert "could not be verified" not in rec


# ---------------------------------------------------------------------------
# 4. Structured Challenger concerns never produce stale legacy fallbacks
# ---------------------------------------------------------------------------

class TestStructuredChallengerFallbacks:
    @pytest.mark.parametrize("name", ["orange_blocking", "orange_insufficient"])
    def test_no_actionable_fallback_absent(self, name, capsys):
        report, _ = _render(name, capsys)
        assert "| BLOCKING |" in report or "| UNRESOLVED |" in report
        assert "No actionable adversarial findings found" not in report
        assert (
            "None generated: test suggestions are not derived from structured Challenger "
            "concerns — see the Challenger concerns section above."
        ) in report

    def test_legacy_without_findings_keeps_legacy_fallback(self, capsys):
        legacy = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        report = pl._build_report(_result(challenger=legacy))
        assert "- No actionable adversarial findings found." in report

    def test_manual_review_fallback_has_no_anchor_wording(self, tmp_path, capsys):
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_foo():\n    pass\n" * 5, encoding="utf-8")
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        result = _result(challenger=_structured("BLOCKING"), repo_root=tmp_path)
        result.security_invariant = None
        report = pl._build_report(result)
        actions = _section(report, "## Validation Actions")
        assert "Perform quick manual review" in actions
        assert "No specific validation items were generated; brief manual inspection advised" in actions
        assert "anchor" not in actions.lower()


# ---------------------------------------------------------------------------
# 5. Report consistency: security property, alignment de-duplication, summary
# ---------------------------------------------------------------------------

class TestReportConsistency:
    def test_security_property_shown_once_in_full(self, capsys):
        report, _ = _render("orange_blocking", capsys)
        assert report.count(INVARIANT) == 1
        actions = _section(report, "## Validation Actions")
        assert f"Security property: {INVARIANT}" in actions
        assert "**Top action:** Verify the security property this patch must restore" in report

    def test_alignment_notes_not_repeated_in_recommendation(self, capsys):
        report, _ = _render("orange_insufficient", capsys)
        notes = (
            "Available evidence is insufficient to verify the fix; no residual "
            "vulnerability has been demonstrated"
        )
        assert notes not in _section(report, "## Recommendation")
        assert report.count(notes) == 1  # the Trust Signals row only
        assert "Remediation alignment:" not in report

    def test_summary_uses_description_paragraph_not_title(self):
        vuln = textwrap.dedent("""\
            # urllib3 is a user-friendly HTTP client library for Python.

            ## Vulnerability description

            **Advisory:** CVE-2023-43804
            **Severity:** MEDIUM (CVSS: 5.9)
            **Type:** CWE-200

            urllib3 is a user-friendly HTTP client library for Python. It is possible for a user to
            leak a Cookie header via redirects to a different origin.

            ## Affected products

            - urllib3
            """)
        original = str(vuln)
        report = pl._build_report(_result(challenger=_structured("UNRESOLVED"), vulnerability_text=vuln))
        summary = _section(report, "## Vulnerability summary")
        assert "leak a Cookie header via redirects to a different origin." in summary
        assert "**Advisory:**" not in summary
        assert vuln == original  # display only; the LLM input text is untouched

    def test_finding_summary_skips_metadata_bullets(self):
        vuln = (
            "# SQL Injection\n\n## Vulnerability description\n\n"
            "- **Finding ID:** F-1\n- **CWE:** CWE-89 (SQLi)\n\n"
            "User input reaches a raw SQL query.\n"
        )
        assert pl._extract_summary(vuln) == "User input reaches a raw SQL query."

    def test_summary_falls_back_to_title(self):
        assert pl._extract_summary("# SQL Injection\n\nSome details") == "SQL Injection"


# ---------------------------------------------------------------------------
# 6. NO PATCH PRODUCED describes no property of a nonexistent patch
# ---------------------------------------------------------------------------

NOT_APPLICABLE = "*Not applicable — no patch was produced.*"


class TestNoPatchReport:
    def test_sections_do_not_describe_a_patch(self, capsys):
        report, _ = _render("no_patch", capsys)
        for heading in ("## Patch Hygiene", "## Post-Patch Investigation", "## Impact Surface", "### Test Support"):
            assert NOT_APPLICABLE in _section(report, heading), heading
        for absent in (
            "No obvious hygiene issues detected", "low operational risk", "(local)",
            "application logic in unknown", "Rating: None", "Target file: unknown",
            "### Behavior Summary", "### Suggested Tests", "No actionable adversarial findings",
            "## Trust Signals", "## Recommendation", "## Explanation",
        ):
            assert absent not in report, absent

    def test_card_is_neutral_and_states_recorded_reason(self, capsys):
        report, _ = _render("no_patch", capsys)
        card = report.split("\n---\n")[0]
        assert "## ⚫ NO PATCH PRODUCED" in card
        assert "Run completed without a final candidate patch." in card
        assert "Reason: The remediation plan could not be grounded in repository evidence." in card
        assert "Files changed: 0" in card
        assert "The pipeline did not produce" not in card

    def test_applicability_keeps_raw_reason_for_batch_runner(self, capsys):
        report, _ = _render("no_patch", capsys)
        assert f"*(Skipped — {UNGROUNDED}.)*" in _section(report, "## Patch Applicability")

    def test_repository_context_intro_does_not_assume_a_patch(self):
        from utilities.autopatcher.repository_grounding_models import (
            DiscoveryEvidence, GroundingDecision, RepositoryCandidate, RepositoryGroundingResult,
        )
        evidence = DiscoveryEvidence(pass_name="explicit_path", tier=3, matched_tokens=None,
                                     total_occurrences=None, hit_line=0, resolution_strategy=None)
        grounding = RepositoryGroundingResult(
            rendered_context="x",
            candidates=[RepositoryCandidate(path="retry.py", evidence=[evidence], best_tier=3)],
            decisions=[GroundingDecision(path="retry.py", outcome="primary_full_file",
                                         snippet_ranges=None, bytes_contributed=0, truncated=False)],
            extraction_signals={}, budget=None,
        )
        no_patch = pl._render_repository_context_section(grounding, no_patch=True)
        assert "No patch was produced from them." in no_patch
        assert "before** the patch was generated" not in no_patch
        assert "before** the patch was generated" in pl._render_repository_context_section(grounding)

    def test_input_source_note_does_not_claim_absent_sections(self):
        from utilities.autopatcher.run_metadata import RunMetadata, render_metadata_section
        meta = RunMetadata(
            timestamp="t", input_source="v.md", repo_root="r", repo_commit="c",
            llm_provider="mock", llm_model="mock", llm_mode="MOCK", output_path="o",
            patcher_commit="p", input_type="cve", advisory_id="CVE-2000-0001", advisory_source="NVD",
        )
        md = render_metadata_section(meta)
        assert "Recommendation and Trust Signals, when present" in md
        assert "The Recommendation and Trust Signals in this report are" not in md


class TestNoPatchReasonDescriptions:
    @pytest.mark.parametrize("raw,expected", [
        ("planning_ungrounded: ungrounded_unresolvable", "could not be grounded in repository evidence"),
        ("planning_ungrounded: ungrounded_max_attempts", "could not be grounded in repository evidence"),
        ("Planner Claim Verifier: causal contradiction not cleared after one bounded revision "
         "(second verification, mode=REJECTED: UNRESOLVED)", "contradiction in the remediation plan"),
        ("Final Remediation Strategy named a target/mechanism but reported "
         "target_authority_unresolved=True -- repository evidence remains insufficient to justify "
         "granting edit authority to it", "not sufficient to justify editing it"),
        ("Final-Target Remediation Slice evidence is resolved but does not fit within Patch "
         "Generation technical capacity (156610 chars needed, 156277 chars available) -- "
         "omission_reason=technical_capacity", "context capacity (156610 chars needed, 156277 available)"),
        ("no verified final-target source", "verified, patch-ready source"),
        ("Patch Generator response invalid (status=contract_violation) after bounded contract "
         "regeneration (2 call(s))", "still invalid after one bounded regeneration"),
        ("empty diff after stripping fences", "contained no diff, or the generated patch was withdrawn"),
        ("not a git repository", "contained no diff, or the generated patch was withdrawn"),
    ])
    def test_known_reasons(self, raw, expected):
        assert expected in pl._describe_no_patch_reason(raw)

    def test_unknown_reason_shown_verbatim_not_guessed(self):
        assert pl._describe_no_patch_reason("something new") == "Reason recorded by the run: something new."

    def test_no_reason(self):
        assert pl._describe_no_patch_reason(None) is None
        assert pl._describe_no_patch_reason("") is None


# ---------------------------------------------------------------------------
# 7. Terminal closing block, and terminal <-> report agreement
# ---------------------------------------------------------------------------

def _banner_lines(err):
    lines = err.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("─") and i + 1 < len(lines)
                 and lines[i + 1][:1] in ("🟢", "🟡", "🟠", "🔴", "⚫"))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("─"))
    return lines[start + 1:end]


class TestTerminalClosingBlock:
    def test_no_patch_terminal(self, capsys):
        _, err = _render("no_patch", capsys)
        assert "– Trust signals not applicable: no candidate patch was produced" in err
        assert "Trust signals evaluated" not in err
        assert _banner_lines(err) == [
            "⚫ NO PATCH PRODUCED",
            "Run completed without a final candidate patch.",
            "Reason    The remediation plan could not be grounded in repository evidence.",
            "Next      No patch to review or deploy; see the Trust Report for details.",
        ]

    def test_orange_terminal_reason_concerns_next(self, capsys):
        _, err = _render("orange_blocking", capsys)
        assert "✓ Trust signals evaluated" in err
        assert _banner_lines(err) == [
            "🟠 MANUAL REVIEW REQUIRED",
            "Reason    A structured adversarial-review concern met the deterministic blocking rule; "
            "the underlying issue has not been independently verified.",
            "Concerns  1 blocking · 1 unresolved · 0 non-blocking Challenger concern(s)",
            "Next      A human reviewer must resolve the open questions in the Trust Report before "
            "any deployment.",
        ]

    def test_do_not_apply_terminal(self, capsys):
        _, err = _render("do_not_apply", capsys)
        lines = _banner_lines(err)
        assert lines[0] == "🔴 DO NOT APPLY"
        assert lines[1].startswith("Reason    Patch has critical issues or does not apply")
        assert lines[-1] == "Next      Do not deploy this patch; see the Trust Report for the failed check."

    @pytest.mark.parametrize("name", sorted(SCENARIOS))
    def test_terminal_and_report_agree(self, name, capsys):
        report, err = _render(name, capsys)
        heading = report.splitlines()[2]
        assert heading == f"## {EXPECTED_HEADING[name]}"
        lines = _banner_lines(err)
        assert lines[0] == heading[3:]
        concerns = next((l for l in lines if l.startswith("Concerns  ")), None)
        if concerns is not None:
            counts = concerns[len("Concerns  "):].replace(" Challenger concern(s)", "")
            assert f"{counts} of " in _section(report, "## Challenger concerns")

    def test_no_terminal_decision_lines_under_quiet(self, capsys):
        progress.configure(quiet=True)
        pl._build_report(_result(**SCENARIOS["orange_blocking"]))
        assert capsys.readouterr().err == ""


class TestValidateStageLine:
    """The Validate stage reports completing the adversarial review -- and
    never presents completion as passing it when concerns remain."""

    _PATCH_DIFF = (
        "```diff\n--- a/mod.py\n+++ b/mod.py\n@@ -1,2 +1,3 @@\n"
        " def foo():\n+    pass\n     return 1\n```"
    )

    def _run(self, tmp_path, challenger, capsys):
        def _fake_raw(vulnerability_text, llm, code_context="", retry_hint="", stage="patch_generation"):
            return self._PATCH_DIFF

        with (
            mock.patch.object(pl, "generate_patch_raw", side_effect=_fake_raw),
            mock.patch.object(pl, "challenge_patch", return_value=challenger),
        ):
            report = pl.run(vulnerability_text="# Test vulnerability\n\nSome description.\n",
                            api_key="", repo_root=str(tmp_path))
        return report, capsys.readouterr().err

    def test_open_concerns_get_warning(self, tmp_path, capsys):
        _, err = self._run(tmp_path, _structured("BLOCKING", "NON_BLOCKING"), capsys)
        assert "⚠ Adversarial review completed — concerns remain" in err
        assert "Patch evaluated" not in err

    def test_cleared_review_gets_checkmark(self, tmp_path, capsys):
        _, err = self._run(tmp_path, _structured("NON_BLOCKING"), capsys)
        assert "✓ Adversarial review completed" in err
        assert "concerns remain" not in err
        assert "Patch evaluated" not in err


# ---------------------------------------------------------------------------
# 8. Batch runner report-parsing contract
# ---------------------------------------------------------------------------

class TestBatchParserContract:
    @pytest.mark.parametrize("name,outcome,decision", [
        ("green", "GREEN", "Deploy After Validation"),
        ("orange_blocking", "ORANGE", "Manual Review Required"),
        ("orange_high_impact", "ORANGE", "Manual Review Required"),
        ("do_not_apply", "RED", "Do Not Apply"),
        ("no_patch", "GRAY", "No Patch Produced"),
    ])
    def test_parse_trust_report(self, name, outcome, decision, tmp_path, capsys):
        report, _ = _render(name, capsys)
        path = tmp_path / "report.md"
        path.write_text(report, encoding="utf-8")
        info = parse_trust_report(path)
        assert info["parse_error"] is None
        assert info["inconsistency"] is None
        assert info["outcome"] == outcome
        assert info["decision"] == decision
        if outcome == "GRAY":
            assert info["recommendation_section_decision"] is None
            assert info["applicability_skip_reason"] == UNGROUNDED
            assert info["files_changed"] == 0
        else:
            assert info["recommendation_section_decision"] == decision
            assert info["files_changed"] == 1


# ---------------------------------------------------------------------------
# 9. Parser diagnostic noise under Auto Patcher's quiet gate
# ---------------------------------------------------------------------------

class TestParserQuietGate:
    def _script(self, tmp_path, exit_code):
        script = tmp_path / "fake_parser.py"
        script.write_text(textwrap.dedent(f"""\
            import json, os, sys
            out = sys.argv[sys.argv.index("--output") + 1]
            os.makedirs(out, exist_ok=True)
            json.dump({{"units": []}}, open(os.path.join(out, "dataset.json"), "w"))
            print("PARSER PIPELINE TEST")
            sys.exit({exit_code})
            """), encoding="utf-8")
        return script

    def _parse(self, tmp_path, monkeypatch, exit_code):
        script = self._script(tmp_path, exit_code)
        monkeypatch.setattr(parser_adapter, "parser_script_path", lambda language: script)
        repo = tmp_path / "repo"
        repo.mkdir()
        return parser_adapter._parse_via_subprocess("go", str(repo), str(tmp_path / "out"), "all")

    def test_quiet_hides_child_stdout(self, tmp_path, monkeypatch, capfd):
        monkeypatch.setenv("AUTOPATCHER_PARSER_QUIET", "1")
        self._parse(tmp_path, monkeypatch, exit_code=0)
        out, err = capfd.readouterr()
        assert "PARSER PIPELINE TEST" not in out + err

    def test_quiet_failure_replays_child_stdout(self, tmp_path, monkeypatch, capfd):
        monkeypatch.setenv("AUTOPATCHER_PARSER_QUIET", "1")
        with pytest.raises(RuntimeError, match="parser failed with exit code 1"):
            self._parse(tmp_path, monkeypatch, exit_code=1)
        assert "PARSER PIPELINE TEST" in capfd.readouterr().err

    def test_without_quiet_output_unchanged(self, tmp_path, monkeypatch, capfd):
        monkeypatch.delenv("AUTOPATCHER_PARSER_QUIET", raising=False)
        self._parse(tmp_path, monkeypatch, exit_code=0)
        assert "PARSER PIPELINE TEST" in capfd.readouterr().err
