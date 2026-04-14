"""
Shared checkpoint utilities for resumable pipeline steps.

Each LLM-heavy step (enhance, analyze, verify) can save per-unit checkpoint
files so interrupted runs resume where they left off. The checkpoint dir
lives next to the output file:

    {scan_dir}/enhance_checkpoints/
    {scan_dir}/analyze_checkpoints/
    {scan_dir}/verify_checkpoints/

On success (all units done), the checkpoint dir is cleaned up automatically.

Usage:

    cp = StepCheckpoint("enhance", output_dir="/path/to/scan/dir")
    completed = cp.load()                 # set of unit IDs already done
    ...process units...
    cp.save(unit_id, data_dict)           # save one unit
    cp.cleanup()                          # remove dir on success
"""

import json
import os
import shutil
import sys
from datetime import datetime, timezone

from utilities.safe_filename import safe_filename
from pathlib import Path


SUMMARY_FILE = "_summary.json"


class StepCheckpoint:
    """Manages per-unit checkpoint files for a pipeline step."""

    def __init__(self, step_name: str, output_dir: str):
        """
        Args:
            step_name: Pipeline step name (enhance, analyze, verify).
            output_dir: Directory where step outputs live (scan dir).
        """
        self.step_name = step_name
        self.dir = os.path.join(output_dir, f"{step_name}_checkpoints")

    @property
    def exists(self) -> bool:
        """True if a checkpoint directory exists with at least one unit file."""
        if not os.path.isdir(self.dir):
            return False
        return any(f.endswith(".json") and f != SUMMARY_FILE
                   for f in os.listdir(self.dir))

    def count(self) -> int:
        """Number of per-unit checkpoint files (excludes _summary.json)."""
        if not os.path.isdir(self.dir):
            return 0
        return sum(1 for f in os.listdir(self.dir)
                   if f.endswith(".json") and f != SUMMARY_FILE)

    def ensure_dir(self):
        """Create the checkpoint directory if it doesn't exist."""
        os.makedirs(self.dir, exist_ok=True)

    def load(self) -> dict[str, dict]:
        """Load all checkpointed units.

        Returns:
            Dict mapping unit_id -> checkpoint data dict.
        """
        results = {}
        if not os.path.isdir(self.dir):
            return results

        for filename in os.listdir(self.dir):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(self.dir, filename)
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                unit_id = data.get("id")
                if unit_id:
                    results[unit_id] = data
            except (json.JSONDecodeError, OSError):
                continue

        return results

    def load_ids(self, skip_errors: bool = True) -> set[str]:
        """Load just the set of completed unit IDs.

        Args:
            skip_errors: If True, don't count units that errored as completed.
                Supports all four phase formats: enhance, analyze, verify, dynamic-test.
        """
        ids = set()
        loaded = self.load()
        for unit_id, data in loaded.items():
            if skip_errors:
                # Enhance: agent_context.error
                agent_ctx = data.get("agent_context", {})
                if agent_ctx.get("error"):
                    continue
                # Analyze: result.verdict/finding
                result = data.get("result", {})
                if result.get("verdict") == "ERROR" or result.get("finding") == "error":
                    continue
                # Verify: verification empty or correct_finding == "error"
                if "verification" in data:
                    v = data.get("verification", {})
                    if not v or v.get("correct_finding") == "error":
                        continue
                # Dynamic-test: top-level status == "ERROR"
                if data.get("status") == "ERROR":
                    continue
            ids.add(unit_id)
        return ids

    def save(self, unit_id: str, data: dict):
        """Save a single unit's checkpoint.

        Args:
            unit_id: The unit identifier.
            data: Dict to persist (must include 'id' key).
        """
        self.ensure_dir()
        filename = self._safe_filename(unit_id) + ".json"
        filepath = os.path.join(self.dir, filename)
        data["id"] = unit_id  # ensure id is always present
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def write_summary(
        self,
        total_units: int,
        completed: int,
        errors: int,
        error_breakdown: dict,
        phase: str = "in_progress",
        usage: dict | None = None,
    ):
        """Write/overwrite _summary.json in checkpoint dir.

        Called from the main thread (as_completed loop) — no lock needed.

        Args:
            total_units: Total units in the step.
            completed: Number of successfully completed units.
            errors: Number of errored units.
            error_breakdown: Dict of error_type -> count.
            phase: ``"in_progress"`` or ``"done"``.
            usage: Optional dict with ``input_tokens``, ``output_tokens``,
                ``cost_usd`` accumulated so far for this step.
        """
        self.ensure_dir()
        filepath = os.path.join(self.dir, SUMMARY_FILE)
        data = {
            "step": self.step_name,
            "phase": phase,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "total_units": total_units,
            "completed": completed,
            "errors": errors,
            "error_breakdown": error_breakdown,
        }
        if usage is not None:
            data["usage"] = usage
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def read_summary(checkpoint_dir: str) -> dict | None:
        """Read _summary.json from a checkpoint directory.

        Returns:
            Parsed dict or None if not found / unreadable.
        """
        filepath = os.path.join(checkpoint_dir, SUMMARY_FILE)
        if not os.path.isfile(filepath):
            return None
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def cleanup(self):
        """Remove the checkpoint directory (call on successful completion)."""
        if os.path.isdir(self.dir):
            shutil.rmtree(self.dir)
            print(f"[{self.step_name}] Cleaned up checkpoints", file=sys.stderr)

    _safe_filename = staticmethod(safe_filename)

    @staticmethod
    def status(checkpoint_dir: str) -> dict:
        """Return accurate checkpoint status by reading actual checkpoint files.

        This is the single source of truth for checkpoint counts. The Go CLI
        calls this via ``python -m openant checkpoint-status`` instead of
        doing its own file scanning.

        Returns:
            Dict with keys: step, checkpoint_dir, completed, errors,
            total_files, total_units, phase, error_breakdown.
        """
        # Derive step name from directory name (e.g. "enhance_checkpoints" → "enhance")
        dir_name = os.path.basename(checkpoint_dir.rstrip("/"))
        step = dir_name.replace("_checkpoints", "") if dir_name.endswith("_checkpoints") else dir_name

        result = {
            "step": step,
            "checkpoint_dir": checkpoint_dir,
            "completed": 0,
            "errors": 0,
            "total_files": 0,
            "total_units": 0,
            "phase": "unknown",
            "error_breakdown": {},
        }

        if not os.path.isdir(checkpoint_dir):
            return result

        # Read _summary.json for total_units and phase
        summary = StepCheckpoint.read_summary(checkpoint_dir)
        if summary:
            result["total_units"] = summary.get("total_units", 0)
            result["phase"] = summary.get("phase", "unknown")

        # Read all checkpoint files and classify each
        completed = 0
        errors = 0
        error_breakdown = {}

        for filename in os.listdir(checkpoint_dir):
            if not filename.endswith(".json") or filename == SUMMARY_FILE:
                continue
            filepath = os.path.join(checkpoint_dir, filename)
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                errors += 1
                error_breakdown["unreadable"] = error_breakdown.get("unreadable", 0) + 1
                continue

            unit_id = data.get("id")
            if not unit_id:
                errors += 1
                error_breakdown["missing_id"] = error_breakdown.get("missing_id", 0) + 1
                continue

            # Check for errors. Each phase stores checkpoint data differently:
            #   - enhance: agent_context.error is set
            #   - analyze: result.verdict == "ERROR" or result.finding == "error"
            #   - verify: verification is empty or verification.correct_finding == "error"
            #   - dynamic-test: top-level status == "ERROR"
            is_error = False
            err_type = None

            # Enhance-style: agent_context.error
            agent_ctx = data.get("agent_context", {})
            if agent_ctx.get("error"):
                is_error = True
                err = agent_ctx["error"]
                err_type = err.get("type", "unknown") if isinstance(err, dict) else "unknown"

            # Analyze-style: result.verdict or result.finding
            elif "result" in data:
                res = data.get("result", {})
                if res.get("verdict") == "ERROR" or res.get("finding") == "error":
                    is_error = True
                    err_type = "analysis_error"

            # Verify-style: verification empty or correct_finding == "error"
            elif "verification" in data:
                v = data.get("verification", {})
                if not v or v.get("correct_finding") == "error":
                    is_error = True
                    err_type = "verification_error"

            # Dynamic-test-style: top-level status == "ERROR"
            elif data.get("status") == "ERROR":
                is_error = True
                err_type = "test_error"

            if is_error:
                errors += 1
                if err_type:
                    error_breakdown[err_type] = error_breakdown.get(err_type, 0) + 1
            else:
                completed += 1

        result["completed"] = completed
        result["errors"] = errors
        result["total_files"] = completed + errors
        result["error_breakdown"] = error_breakdown

        return result


def auto_checkpoint_dir(output_path: str, step_name: str) -> str:
    """Derive the checkpoint directory from the output file path.

    For enhance: output_path is dataset_enhanced.json
        -> same dir / enhance_checkpoints/
    For analyze: output_dir contains results.json
        -> output_dir / analyze_checkpoints/
    For verify: output_dir contains results_verified.json
        -> output_dir / verify_checkpoints/
    """
    if os.path.isdir(output_path):
        return os.path.join(output_path, f"{step_name}_checkpoints")
    return os.path.join(os.path.dirname(os.path.abspath(output_path)),
                        f"{step_name}_checkpoints")
