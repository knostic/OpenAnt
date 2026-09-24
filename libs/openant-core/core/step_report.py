"""
Step report context manager.

Wraps a pipeline step to automatically capture timing, cost, and errors
into a StepReport, then writes {step}.report.json to the output directory.

Usage::

    with step_context("parse", output_dir, inputs={...}) as ctx:
        # do work ...
        ctx.summary = {"total_units": 123, "reachable_units": 79}
        ctx.outputs = {"dataset_path": "/tmp/out/dataset.json"}
"""

import sys
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone

from core.schemas import StepReport


@contextmanager
def step_context(step: str, output_dir: str, inputs: dict | None = None):
    """Context manager that builds a StepReport around a pipeline step.

    Automatically captures:
    - timestamp (UTC ISO 8601)
    - duration (wall-clock seconds)
    - cost / token usage (from ``core.tracking`` if available)
    - errors (any exception that propagates, or any error appended to
      ``report.errors`` inside the block — in which case the step's status
      is derived as ``"error"`` at exit rather than left at ``"success"``.
      Errors also win over an explicitly-set ``"skipped"``: a step that
      both marks itself skipped and records errors reports ``"error"``.)

    The caller should set ``ctx.summary`` and ``ctx.outputs`` inside the
    ``with`` block. On exit the report is written to ``{output_dir}/{step}.report.json``.

    Yields a StepReport instance (mutable — set summary/outputs on it).
    """
    report = StepReport(
        step=step,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        inputs=inputs or {},
    )

    start = time.monotonic()

    # Snapshot starting cost so we can compute the delta
    start_cost, start_tokens = _snapshot_usage()
    # #605: a failed START snapshot must not become a fabricated zero
    # baseline — the delta is unavailable, not zero.
    _accounting_error = start_cost is None

    try:
        yield report
    except Exception as exc:
        report.status = "error"
        report.errors.append(str(exc))
        print(f"[{step}] ERROR: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        raise
    except KeyboardInterrupt:
        # #420 (the #417/#418/#419 contract): an interrupt propagating through
        # a step must not leave an on-disk artifact claiming success — the
        # finally below would write the DEFAULT status="success" with an
        # empty summary. `except Exception` above cannot catch it, so a
        # propagating KI marks the step "interrupted": the resume path and
        # the artifact readers can see the run was cut short. stdout envelope
        # unaffected — no envelope is emitted on the KI path; the Go
        # exit-130 contract still works. This is the stderr/file channel.
        report.status = "interrupted"
        raise
    except SystemExit as exc:
        # wave r1 (opus): SystemExit is NOT an interrupt — it is how
        # deterministic error exits are signalled (report/generator.py's
        # validation sys.exit(1), generate_context's unsupported-type
        # sys.exit(2)). Mapping it to "interrupted" erased the cause and
        # contradicted the exit code (the Go contract reads "interrupted"
        # as 130). Non-zero codes are ERROR with the cause recorded;
        # a zero code is a deliberate early exit (interrupted, no error).
        code = exc.code if isinstance(exc.code, int) else (1 if exc.code else 0)
        if code != 0:
            report.status = "error"
            report.errors.append(f"SystemExit: {code}")
            print(f"[{step}] ERROR: SystemExit({code})", file=sys.stderr)
        else:
            report.status = "interrupted"
        raise
    except BaseException:
        # GeneratorExit / anything else non-Exception: the run was cut
        # short, not failed — same artifact contract as the KI branch.
        report.status = "interrupted"
        raise
    finally:
        # Issue #209/#285: a step that records errors via
        # ``ctx.errors.append(...)`` or that counts per-item failures in
        # ``summary["error_count"]`` (exception caught BY DESIGN) must not
        # report success. Derive the status from evidence at exit:
        # non-empty ``errors`` OR a positive integer ``error_count`` in
        # ``summary`` ⇒ ``"partial"`` — deliberately NOT ``"error"`` (which
        # stays reserved for the propagating-exception path). The scanner's
        # degrade idiom (status="skipped", reason in summary, no errors) is
        # unaffected.
        if report.status not in ("error", "interrupted"):
            _summary = report.summary if isinstance(report.summary, dict) else {}
            _counted = _summary.get("error_count")
            _error_count = _counted if isinstance(_counted, int) and _counted > 0 else 0
            if report.errors or _error_count:
                report.status = "partial"

        report.duration_seconds = round(time.monotonic() - start, 2)

        # Capture cost delta
        end_cost, end_snapshot = _snapshot_usage()
        if end_cost is None:
            _accounting_error = True
        if _accounting_error:
            # #605: either endpoint failed — the DELTA is unavailable.
            # Write zeros WITHOUT subtracting (a fabricated baseline yields
            # negative cost/tokens or charges another step's spend) and
            # mark the step's accounting as errored, never complete-looking.
            report.cost_usd = 0.0
            report.token_usage = {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "cost_incomplete": True,
                "accounting_error": True,
            }
            # A healthy END snapshot's unpriced ids survive the sentinel:
            # the delta is unavailable but the WHICH-MODEL disclosure is
            # not (a start-failed step carrying the run's only unpriced
            # spend must not lose the ids from the aggregate).
            if end_snapshot and end_snapshot.get("unpriced_models"):
                report.token_usage["unpriced_models"] = \
                    end_snapshot["unpriced_models"]
        else:
            report.cost_usd = round(end_cost - start_cost, 6)
            report.token_usage = {
                "input_tokens": end_snapshot.get("input", 0) - start_tokens.get("input", 0),
                "output_tokens": end_snapshot.get("output", 0) - start_tokens.get("output", 0),
                "total_tokens": end_snapshot.get("total", 0) - start_tokens.get("total", 0),
            }
            # #626: the step's cache deltas (present-only).
            for _ck in ("cache_read", "cache_write"):
                if _ck in end_snapshot or _ck in start_tokens:
                    _delta = (end_snapshot.get(_ck, 0)
                              - start_tokens.get(_ck, 0))
                    if _delta:
                        report.token_usage[_ck] = _delta
            # #216: a step whose cost is incomplete (any call on an unpriced
            # model) must say so IN the artifact — OR the end snapshot's marker
            # (run-cumulative, so a step after unpriced spend also flags).
            if end_snapshot.get("cost_incomplete"):
                report.token_usage["cost_incomplete"] = True
                report.token_usage["unpriced_models"] = end_snapshot.get(
                    "unpriced_models", [])
                # F661-2 (2026-09-22): the cache-unpriced ids too — a
                # cache-only incompleteness must name its model (#216's
                # name-the-model, extended to the cache path).
                if end_snapshot.get("unpriced_cache_models"):
                    report.token_usage["unpriced_cache_models"] = \
                        end_snapshot["unpriced_cache_models"]
            # #605: a mid-run accounting drop (another phase's hand-off)
            # surfaces here too — the marker is run-cumulative through the
            # tracker totals, the same accepted trade as #216's.
            from utilities.llm_client import _accounting_error_count
            if _accounting_error_count():
                # A mid-run drop is an INCOMPLETE-COST condition too: the
                # step's (and the scan's) cost figure does not include the
                # dropped spend — both markers, never one without the other.
                report.token_usage["accounting_error"] = True
                report.token_usage["cost_incomplete"] = True
        report.write(output_dir)
        print(
            f"[{step}] Report: {output_dir}/{step}.report.json "
            f"({report.duration_seconds}s, ${report.cost_usd:.4f})",
            file=sys.stderr,
        )


def _snapshot_usage() -> tuple[float | None, dict | None]:
    """Return (cost_usd, {input, output, total, cost_incomplete,
    unpriced_models}) from the global tracker.

    Returns (None, None) on failure — the caller must skip the delta
    subtraction and mark the accounting errored (#605: never a
    complete-looking zero snapshot).
    """
    try:
        from core.tracking import get_usage
        usage = get_usage()
        snap = {
            "input": usage.total_input_tokens,
            "output": usage.total_output_tokens,
            "total": usage.total_tokens,
            "cost_incomplete": usage.cost_incomplete,
            "unpriced_models": usage.unpriced_models,
        }
        # #626: the cache line items, present-only (a no-cache run's
        # snapshot shape is byte-identical to the pre-#626 one).
        if usage.total_cache_read_tokens:
            snap["cache_read"] = usage.total_cache_read_tokens
        if usage.total_cache_write_tokens:
            snap["cache_write"] = usage.total_cache_write_tokens
        if usage.unpriced_cache_models:
            snap["unpriced_cache_models"] = usage.unpriced_cache_models
        return usage.total_cost_usd, snap
    except Exception as exc:
        # #605: a failed snapshot is a SENTINEL, never a complete-looking
        # zero — the caller must skip the subtraction (a fabricated baseline
        # produces negative deltas or charges another step's spend) and
        # mark the step's accounting incomplete.
        print(f"[step-report] accounting snapshot failed ({type(exc).__name__}): "
              f"{exc}", file=sys.stderr)
        return None, None
