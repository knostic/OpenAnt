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
    - errors (any exception that propagates)

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

    try:
        yield report
    except Exception as exc:
        report.status = "error"
        report.errors.append(str(exc))
        print(f"[{step}] ERROR: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        raise
    finally:
        report.duration_seconds = round(time.monotonic() - start, 2)

        # Capture cost delta
        end_cost, end_tokens = _snapshot_usage()
        report.cost_usd = round(end_cost - start_cost, 6)
        report.token_usage = {
            "input_tokens": end_tokens.get("input", 0) - start_tokens.get("input", 0),
            "output_tokens": end_tokens.get("output", 0) - start_tokens.get("output", 0),
            "total_tokens": end_tokens.get("total", 0) - start_tokens.get("total", 0),
        }

        report.write(output_dir)
        print(
            f"[{step}] Report: {output_dir}/{step}.report.json "
            f"({report.duration_seconds}s, ${report.cost_usd:.4f})",
            file=sys.stderr,
        )


def _snapshot_usage() -> tuple[float, dict]:
    """Return (cost_usd, {input, output, total}) from the global tracker.

    Returns zeroes if the tracker isn't available (e.g. for local-only steps).
    """
    try:
        from core.tracking import get_usage
        usage = get_usage()
        return usage.total_cost_usd, {
            "input": usage.total_input_tokens,
            "output": usage.total_output_tokens,
            "total": usage.total_tokens,
        }
    except Exception:
        return 0.0, {"input": 0, "output": 0, "total": 0}
