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

import hashlib
import json
import os
import shutil
import threading
import sys
from datetime import datetime, timezone

from utilities.safe_filename import SAFE_FILENAME_MAX_LEN, safe_filename
from utilities.file_io import read_json, write_json
from core.backend_identity import FINGERPRINT_FILE
from pathlib import Path


SUMMARY_FILE = "_summary.json"

# Sidecar files that live inside a checkpoint dir but are NOT per-unit results.
# They must be excluded from every checkpoint counter (exists/count/status/load)
# and from the Go DetectFallback scan, or a resume would over-count "completed"
# units by the number of sidecars.
_RESERVED_FILES = frozenset({SUMMARY_FILE, FINGERPRINT_FILE})

# #317: save() runs in worker threads (the enhancer's and the analyzer's
# ThreadPoolExecutor pools), so the exists-then-write disambiguation has a
# TOCTOU race: two case siblings in flight could both see bare-not-exists
# and both write it (last wins — the collision for that run). A module-level
# lock held across resolve+write; microseconds against multi-second LLM
# calls. Covers every phase — the verifier and dynamic tester save through
# StepCheckpoint.save too. SINGLE-PROCESS SCOPE (panel round-3): this is a
# threading lock — two CONCURRENT CLI invocations writing the same checkpoint
# dir (an unsupported shape: they would also race every results file in the
# output dir) are NOT serialized by it. Within one process (the supported
# shape: a single run's worker pools) it fully orders resolve+write.
_save_lock = threading.Lock()


def disambiguated_checkpoint_path(ckpt_dir: str, unit_id: str) -> str:
    """The collision-safe checkpoint filepath for ``unit_id`` (#317).

    The bare ``safe_filename(unit_id) + ".json"`` when free or already holding
    THIS unit's data (a resume/refresh overwrites its own file); when the
    name is taken by a DIFFERENT unit's checkpoint — the case-insensitive
    filesystem collision (``pkg/Foo.py:run`` vs ``pkg/foo.py:run``) — the
    case-sensitive hash suffix disambiguates (the long-name mechanism,
    capped so name + .json fits the 255-char limit). On case-SENSITIVE
    filesystems the check never fires for a case-only pair: two real files,
    the naming scheme unchanged.

    HOME STABILITY: once a unit's data lives at the suffixed path (its
    disambiguated home), later saves keep writing THERE even when the bare
    name has freed up (the sibling's file deleted, the dir moved to a
    case-sensitive fs) — otherwise the fresh result would land at the bare
    name and ORPHAN the suffixed twin, and the two same-id files would
    resolve by listdir order (arbitrary) — the non-convergence class #317
    fixed, resurrected (wave round-1 finding).
    """
    safe = safe_filename(unit_id)
    if len(safe) > SAFE_FILENAME_MAX_LEN:
        # The truncated regime: safe_filename already appended the
        # case-sensitive hash (name -> prefix[:233] + _ + 16 hex of the FULL
        # id), so the name is INJECTIVE — a different unit cannot reach it.
        # Disambiguation is a no-op here BY CONSTRUCTION; the early-out
        # states it instead of leaving it to the 233-constant coupling
        # between the two files (wave round-1: the coupling was load-
        # bearing and nothing said so).
        return os.path.join(ckpt_dir, safe + ".json")
    bare = os.path.join(ckpt_dir, safe + ".json")
    h = hashlib.sha256(unit_id.encode()).hexdigest()[:16]
    stem = safe[: 255 - len(".json") - len(h) - 1]
    home = os.path.join(ckpt_dir, f"{stem}_{h}.json")

    def _holds_this_unit(path):
        try:
            existing = read_json(path)
        except Exception:
            # a corrupt/foreign .json must not crash every later save of
            # this unit — unreadable reads as no id (the garbage is
            # overwrite-able; write_json is atomic).
            return False
        return isinstance(existing, dict) and existing.get("id") == unit_id

    if os.path.exists(bare):
        try:
            existing = read_json(bare)
        except Exception:
            existing = None
        existing_id = existing.get("id") if isinstance(existing, dict) else None
        if existing_id == unit_id:
            # Panel round-3 (self-heal): if BOTH the bare name and this
            # unit's suffixed home hold the same id (a dual-stale-file
            # state — fable judged it code-unreachable, sonnet asked for
            # the class to self-heal "however it arises"), consolidate to
            # the NEWER file and delete the superseded twin — otherwise
            # the id-keyed restore's last-wins could keep serving the
            # stale one indefinitely. mtime decides freshness; both
            # files provably hold this unit's id.
            if os.path.exists(home) and _holds_this_unit(home):
                try:
                    # TIE-BREAK: equal mtimes (one clock tick on Windows)
                    # fall through to the bare overwrite — both files
                    # provably hold this unit's id, so the dual state heals
                    # either way; only WHICH copy survives is arbitrary.
                    if os.path.getmtime(home) > os.path.getmtime(bare):
                        _atomic_unlink(bare)
                        return home
                    _atomic_unlink(home)
                except OSError:
                    pass  # best-effort: the ordinary overwrite still lands
            return bare  # its own file — overwrite in place
        if existing_id is not None:
            return home  # a sibling's — this unit's disambiguated home
        # corrupt bare: the HOME STABILITY probe still applies (wave r2 —
        # returning bare here while this unit already lives at its home
        # would recreate the two-same-id-files state the sibling's
        # corruption just made room for).
        if os.path.exists(home) and _holds_this_unit(home):
            return home
        return bare  # overwrite the garbage
    # the bare name is free — but this unit may already live at its
    # suffixed home (the sibling that held the bare name is gone): keep
    # writing THERE, or the twin orphans.
    if os.path.exists(home) and _holds_this_unit(home):
        return home
    return bare


def _atomic_unlink(path: str) -> None:
    """Best-effort remove; a missing file (case-insensitive fs aliasing,
    concurrent cleanup) is success. Under _save_lock at every caller."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def save_checkpoint_under_lock(ckpt_dir: str, unit_id: str, data: dict) -> str:
    """Resolve + write a unit's checkpoint under the #317 save lock (the
    TOCTOU guard for worker-thread saves). The caller is responsible for
    setting data["id"]; this stamps it."""
    with _save_lock:
        filepath = disambiguated_checkpoint_path(ckpt_dir, unit_id)
        data["id"] = unit_id
        write_json(filepath, data)
    return filepath


def id_keyed_checkpoint_map(ckpt_dir: str) -> dict:
    """Map every checkpoint file's ``id`` (from its CONTENT) to its path.

    #317: completion detection is content-based; restoration must be too —
    a filename-computed lookup strands old-scheme files (detected complete,
    restore no-ops -> empty contexts -> fewer findings) and restores the
    WRONG unit's data when the computed name is taken by a sibling. One
    listdir + read pass; unreadable files are skipped (detection's own
    convention).
    """
    mapping = {}
    if not os.path.isdir(ckpt_dir):
        return mapping
    for name in os.listdir(ckpt_dir):
        if not name.endswith(".json") or name in _RESERVED_FILES:
            continue
        p = os.path.join(ckpt_dir, name)
        try:
            data = read_json(p)
        except Exception:
            continue
        if isinstance(data, dict) and data.get("id"):
            mapping[data["id"]] = p
    return mapping


def analyze_result_is_error(res) -> bool:
    """Is an analyze-style ``result`` an error (retried, never adopted as complete)?

    The single shared predicate for every resume-facing consumer
    (``StepCheckpoint.load_ids``, ``StepCheckpoint.status``, and
    ``analyzer._cp_is_error`` / the summary seed loop). Four hand-copies of
    the two-arm test drifted within one PR — keep them in agreement here.

    Error shapes:
      * ``verdict == "ERROR"`` or ``finding == "error"`` — the explicit error;
      * neither an EFFECTIVE verdict nor an EFFECTIVE finding — a malformed
        model reply (#324's JSON-shaped refusal). "Effective" = a non-empty
        string: a ``{"verdict": null}`` refusal carries the key but no
        verdict, and must not be counted completed.

    Verdict-first: a row where both keys are present and disagree is
    classified by its verdict ("ERROR" wins). ``_count_verdicts`` is
    finding-first — a legacy ``{"verdict": "ERROR", "finding": "vulnerable"}``
    row is an error here (retried) but counted vulnerable there; the retried
    outcome replaces it, so the disagreement is transient. An
    unrecognized-but-effective verdict (``"SAY WHAT"``) is NOT an error here
    — that drop is the documented F13 partition gap, deliberately out of
    scope (#316/#324).
    """
    if not isinstance(res, dict):
        # A hand-edited/corrupt "result": null row must not crash the
        # classifier (status() is the Go CLI's checkpoint-status source).
        return True
    verdict = res.get("verdict")
    finding = res.get("finding")
    if verdict == "ERROR" or finding == "error":
        return True
    has_verdict = isinstance(verdict, str) and verdict.strip() != ""
    has_finding = isinstance(finding, str) and finding.strip() != ""
    return not (has_verdict or has_finding)


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
        return any(f.endswith(".json") and f not in _RESERVED_FILES
                   for f in os.listdir(self.dir))

    def count(self) -> int:
        """Number of per-unit checkpoint files (excludes _summary.json)."""
        if not os.path.isdir(self.dir):
            return 0
        return sum(1 for f in os.listdir(self.dir)
                   if f.endswith(".json") and f not in _RESERVED_FILES)

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
            if not filename.endswith(".json") or filename in _RESERVED_FILES:
                continue
            filepath = os.path.join(self.dir, filename)
            try:
                data = read_json(filepath)
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
                if "result" in data and analyze_result_is_error(result):
                    # #324: neither-key / ineffective-verdict rows are
                    # malformed replies, not completed units. Scoped to
                    # analyze-style rows ("result" key present) — the other
                    # three phases never write it.
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

        #317: collision-safe via ``disambiguated_checkpoint_path`` — on a
        case-insensitive filesystem (macOS default, Windows) two unit IDs
        differing only in case (ordinary Go exported/unexported pairs)
        compute the same filename; the second save silently overwrote the
        first, and the lost unit was re-analyzed and re-paid on every
        resume. On case-SENSITIVE filesystems the naming scheme is
        unchanged (the check never fires for a case-only pair).
        """
        self.ensure_dir()
        save_checkpoint_under_lock(self.dir, unit_id, data)

    # ------------------------------------------------------------------
    # Backend-identity adopt gate (I2, minimal)
    # ------------------------------------------------------------------

    def sync_identity(self, fingerprint: dict, *, verbose: bool = True) -> dict:
        """Gate checkpoint adoption on backend identity.

        Call AFTER ``self.dir`` is finalized (respect any dir override, e.g.
        the verifier's ``verify_checkpoints``) and BEFORE any ``load()`` — it
        decides whether the prior checkpoints in this dir may be adopted by the
        current backend, and if not it archives them aside and starts fresh.

        Returns ``{"status", "archived_to", "warnings"}`` where status is one
        of:

          * ``new``    — no sidecar and no units: stamp and proceed.
          * ``legacy`` — units present but no sidecar (a pre-feature dir): we
            cannot verify identity, so ADOPT (never spuriously re-pay) and
            stamp for next time.
          * ``match``  — sidecar KEY digest equals the current one: adopt.
          * ``reset``  — sidecar KEY mismatch OR a corrupt/unreadable sidecar:
            archive the whole dir aside (preserve-not-destroy) and start fresh
            so the new backend re-pays.

        FAIL-CLOSED: a corrupt / unreadable sidecar is treated as ``reset``
        (archive + re-run), NEVER adopt — an unverifiable identity must not
        silently serve another backend's verdicts.
        """
        sidecar_path = os.path.join(self.dir, FINGERPRINT_FILE)
        has_units = self.exists
        warnings: list[str] = []

        sidecar_present = os.path.isfile(sidecar_path)
        existing = None
        corrupt = False
        if sidecar_present:
            try:
                existing = read_json(sidecar_path)
                if not isinstance(existing, dict):
                    corrupt = True
            except (json.JSONDecodeError, OSError, ValueError):
                corrupt = True

        # Corrupt / unreadable sidecar → FAIL CLOSED (archive + re-run).
        if corrupt:
            archived_to = self._archive_dir(fingerprint.get("key_digest", ""))
            os.makedirs(self.dir, exist_ok=True)
            self._write_fingerprint(fingerprint)
            msg = ("checkpoint identity sidecar was unreadable/corrupt; refusing "
                   "to adopt possibly-stale checkpoints (fail-closed). Archived "
                   f"to {archived_to}. Re-running this phase.")
            warnings.append(msg)
            if verbose:
                print(f"[{self.step_name}] {msg}", file=sys.stderr)
            return {"status": "reset", "archived_to": archived_to,
                    "warnings": warnings}

        # No sidecar recorded.
        if not sidecar_present:
            self._write_fingerprint(fingerprint)
            status = "legacy" if has_units else "new"
            if status == "legacy" and verbose:
                print(f"[{self.step_name}] Adopting pre-existing checkpoints "
                      f"with no identity stamp (legacy); stamping for next run.",
                      file=sys.stderr)
            return {"status": status, "archived_to": None, "warnings": warnings}

        # KEY match → adopt (refresh the stamp).
        if existing.get("key_digest") == fingerprint.get("key_digest"):
            self._write_fingerprint(fingerprint)
            return {"status": "match", "archived_to": None, "warnings": warnings}

        # KEY mismatch → backend identity changed. Archive and reset.
        archived_to = self._archive_dir(fingerprint.get("key_digest", ""))
        os.makedirs(self.dir, exist_ok=True)
        self._write_fingerprint(fingerprint)
        msg = ("backend identity changed since last run; prior checkpoints were "
               "NOT adopted (they would be a silent false-negative). Archived to "
               f"{archived_to}. Re-running this phase.")
        warnings.append(msg)
        if verbose:
            print(f"[{self.step_name}] {msg}", file=sys.stderr)
        return {"status": "reset", "archived_to": archived_to,
                "warnings": warnings}

    def _write_fingerprint(self, fingerprint: dict) -> None:
        self.ensure_dir()
        payload = dict(fingerprint)
        payload["written_at"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        write_json(os.path.join(self.dir, FINGERPRINT_FILE), payload)

    def _archive_dir(self, key_digest: str) -> str:
        """Move the current checkpoint dir aside — never delete it."""
        short = key_digest.split(":")[-1][:8] or "reset"
        base = self.dir.rstrip("/")
        dest = f"{base}.superseded-{short}"
        n = 1
        while os.path.exists(dest):
            dest = f"{base}.superseded-{short}-{n}"
            n += 1
        shutil.move(self.dir, dest)
        return dest

    def write_summary(
        self,
        total_units: int,
        completed: int,
        errors: int,
        error_breakdown: dict,
        phase: str = "in_progress",
        usage: dict | None = None,
        incomplete: int = 0,
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
            incomplete: #293 — units that ended WITHOUT a verdict (the loop
                ran out / gave up): neither completed nor errored. All three
                buckets are always emitted so ``completed + incomplete +
                errors == total_units`` is visible and checkable; callers
                that predate the third bucket default it to 0.
        """
        self.ensure_dir()
        filepath = os.path.join(self.dir, SUMMARY_FILE)
        data = {
            "step": self.step_name,
            "phase": phase,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "total_units": total_units,
            "completed": completed,
            "incomplete": incomplete,
            "errors": errors,
            "error_breakdown": error_breakdown,
        }
        if usage is not None:
            data["usage"] = usage
        write_json(filepath, data)
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
            return read_json(filepath)
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
            Dict with keys: step, checkpoint_dir, completed, incomplete,
            errors, total_files, total_units, phase, error_breakdown.
        """
        # Derive step name from directory name (e.g. "enhance_checkpoints" → "enhance")
        dir_name = os.path.basename(checkpoint_dir.rstrip("/"))
        step = dir_name.replace("_checkpoints", "") if dir_name.endswith("_checkpoints") else dir_name

        result = {
            "step": step,
            "checkpoint_dir": checkpoint_dir,
            "completed": 0,
            "incomplete": 0,
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
        incomplete = 0
        errors = 0
        error_breakdown = {}

        for filename in os.listdir(checkpoint_dir):
            if not filename.endswith(".json") or filename in _RESERVED_FILES:
                continue
            filepath = os.path.join(checkpoint_dir, filename)
            try:
                data = read_json(filepath)
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
            #   - enhance: error under agent_context (agentic) / llm_context (single-shot)
            #   - analyze: result.verdict == "ERROR" or result.finding == "error"
            #   - verify: verification is empty or verification.correct_finding == "error"
            #   - dynamic-test: top-level status == "ERROR"
            #   - verify adapter-raise (#286): top-level "error" key
            is_error = False
            is_incomplete = False
            err_type = None

            # Enhance-style: error under the context named by ``context_key``
            # (agent_context for agentic, llm_context for single-shot). Legacy
            # agentic checkpoints omit context_key → default agent_context.
            ctx_key = data.get("context_key", "agent_context")
            enhance_ctx = data.get(ctx_key, {})
            if isinstance(enhance_ctx, dict) and enhance_ctx.get("error"):
                is_error = True
                err = enhance_ctx["error"]
                err_type = err.get("type", "unknown") if isinstance(err, dict) else "unknown"

            # Analyze-style: result.verdict or result.finding
            elif "result" in data:
                if analyze_result_is_error(data.get("result", {})):
                    is_error = True
                    err_type = "analysis_error"

            # Verify-style: verification empty or correct_finding == "error";
            # #293: a non-empty verification carrying incomplete=True (verdict
            # present, loop never finished) is the third state
            elif "verification" in data:
                v = data.get("verification", {})
                if not v or v.get("correct_finding") == "error":
                    is_error = True
                    err_type = "verification_error"
                elif v.get("incomplete"):
                    is_incomplete = True

            # Dynamic-test-style: top-level status == "ERROR"
            elif data.get("status") == "ERROR":
                is_error = True
                err_type = "test_error"

            # #286/#293: a top-level "error" key (the verify adapter-raise
            # marker) beats every other classification — an errored verify
            # checkpoint carries BOTH "error" and verification.incomplete.
            if not is_error and data.get("error"):
                is_error = True
                is_incomplete = False
                err_type = "error_key"

            # #293: enhance-style incomplete — the agent's degenerate exit
            # (security_classification == "incomplete") is not a completion
            if not is_error and not is_incomplete and isinstance(enhance_ctx, dict):
                if enhance_ctx.get("security_classification") == "incomplete":
                    is_incomplete = True

            if is_error:
                errors += 1
                if err_type:
                    error_breakdown[err_type] = error_breakdown.get(err_type, 0) + 1
            elif is_incomplete:
                incomplete += 1
            else:
                completed += 1

        result["completed"] = completed
        result["incomplete"] = incomplete
        result["errors"] = errors
        result["total_files"] = completed + incomplete + errors
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
