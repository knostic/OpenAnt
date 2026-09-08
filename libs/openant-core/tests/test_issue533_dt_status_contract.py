"""Tests for issue #533 — the dynamic-test step status contract.

The dynamic-test producer wrote its counted failures under ``summary["errors"]``
(an int), but the #285/#376 partial-status contract reads
``summary["error_count"]`` (the well-typed int) or the ctx error list — so a
dynamic-test run with counted generation/build failures reported
``status: "success"`` (the receipt: a monitored run's
``dynamic-test.report.json`` carried ``"status": "success"`` beside
``"errors": 1``).

The fix: a shared ``dynamic_test_step_summary()`` helper in core/schemas.py
(the #300 verify_step_summary precedent — one construction shape so the
pipeline and the standalone CLI cannot drift), adding ``error_count`` beside
the retained ``errors`` key. Both call sites (core/scanner.py, openant/cli.py)
use it.
"""
from __future__ import annotations

import json
import os
import sys



from core.schemas import (
    DynamicTestStepResult,
    ScanResult,
    dynamic_test_step_summary,
)
from core.step_report import step_context


def _dt_result(errors=1, confirmed=0):
    return DynamicTestStepResult(
        findings_tested=2, confirmed=confirmed, not_reproduced=0, blocked=0,
        inconclusive=0, errors=errors,
        results_json_path="/x.json", results_md_path="/x.md",
    )


class TestStatusContract:
    def test_counted_errors_make_status_partial(self, tmp_path):
        """THE #533 regression: a dynamic-test step with a counted failure
        must report partial, never success."""
        out = str(tmp_path)
        # The FIXED producer shape (the shared helper — what both call
        # sites now write): a counted error must read partial. On the
        # pristine base the helper does not exist (the machinery RED).
        with step_context("dynamic-test", out) as ctx:
            ctx.summary = dynamic_test_step_summary(_dt_result(errors=1))
        with open(os.path.join(out, "dynamic-test.report.json")) as fh:
            report = json.load(fh)
        assert report["status"] == "partial", (
            f"a counted dynamic-test failure must not read success; got "
            f"{report['status']!r} — summary: {report.get('summary')}")
        assert report["summary"]["error_count"] == 1
        # The errors key is a persisted contract — retained, not dropped.
        assert report["summary"]["errors"] == 1

    def test_zero_errors_stay_success(self, tmp_path):
        out = str(tmp_path)
        with step_context("dynamic-test", out) as ctx:
            ctx.summary = dynamic_test_step_summary(_dt_result(errors=0))
        with open(os.path.join(out, "dynamic-test.report.json")) as fh:
            report = json.load(fh)
        assert report["status"] == "success"
        assert report["summary"]["error_count"] == 0

    def test_helper_is_the_shared_shape(self):
        """The #300 pattern: ONE construction site for the summary dict."""
        helper = getattr(sys.modules['core.schemas'], 'dynamic_test_step_summary', None)
        assert helper is not None, "dynamic_test_step_summary must exist in core/schemas.py"
        result = DynamicTestStepResult(
            findings_tested=2, confirmed=1, not_reproduced=0, blocked=0,
            inconclusive=0, errors=1,
            results_json_path="/x.json", results_md_path="/x.md",
        )
        s = helper(result)
        assert s["error_count"] == 1
        assert s["errors"] == 1        # the display key retained
        assert s["confirmed"] == 1
        assert set(s) == {
            "findings_tested", "confirmed", "not_reproduced", "blocked",
            "inconclusive", "errors", "error_count",
        }

    def test_both_call_sites_use_the_helper(self):
        """Both producers route through the shared shape — the standalone
        CLI site (openant/cli.py) must not drift from the pipeline site
        (core/scanner.py); the need-check round found the second site."""
        repo = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))
        with open(os.path.join(repo, "libs", "openant-core",
                            "core", "scanner.py")) as fh:
            scanner_src = fh.read()
        with open(os.path.join(repo, "libs", "openant-core",
                                "openant", "cli.py")) as fh:
            cli_src = fh.read()
        assert "dynamic_test_step_summary(" in scanner_src
        assert "dynamic_test_step_summary(" in cli_src
        # Exclusivity (the review round): no THIRD inline construction site
        # may appear in either file — the helper is the only shape.
        assert '"findings_tested":' not in scanner_src
        assert '"findings_tested":' not in cli_src

    def test_aggregate_inherits_partial(self, tmp_path):
        """The aggregate walk: clean steps + one partial dynamic-test ⇒
        the scan report's status is partial (an otherwise-clean aggregate
        must not stay green over a failed dynamic test)."""
        from core.scanner import _write_scan_report

        clean = {"status": "success", "cost_usd": 0.0, "duration_seconds": 1.0,
                 "token_usage": {}}
        partial = {"status": "partial", "cost_usd": 0.01, "duration_seconds": 2.0,
                   "token_usage": {}, "summary": {"error_count": 1}}
        result = ScanResult(
            output_dir=str(tmp_path), language="python",
            units_count=2, languages=["python"],
        )
        p = _write_scan_report(str(tmp_path), result, [clean, partial])
        with open(p) as fh:
            agg = json.load(fh)
        assert agg["status"] == "partial"

    def test_scanner_block_orders_helper_before_degrade(self):
        """The wiring-order tripwire (the review round): the helper assignment
        sits INSIDE the dynamic-test step_context body BEFORE the degrade
        except (a regression moving it after the catch would erase the
        counted-failure evidence with the skip dict)."""
        repo = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))
        with open(os.path.join(repo, "libs", "openant-core",
                               "core", "scanner.py")) as fh:
            src = fh.read()
        block = src[src.index('step_context("dynamic-test"'):]
        block = block[:block.index("with step_context", 10) if "with step_context" in block[10:] else len(block)]
        i_helper = block.index("dynamic_test_step_summary(")
        i_degrade = block.index('ctx.summary = {"skipped": True')
        assert i_helper < i_degrade, (
            "the summary assignment must precede the degrade except; "
            f"helper at {i_helper}, degrade at {i_degrade}")
