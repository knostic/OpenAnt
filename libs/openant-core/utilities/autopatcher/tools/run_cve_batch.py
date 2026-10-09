#!/usr/bin/env python3
"""
run_cve_batch.py -- the standard batch runner for OpenAnt Auto Patcher
real-CVE regression/evaluation runs.

Evaluation tooling only: it never changes Auto Patcher behavior and never
interprets anything beyond run_traced.py's own artifacts. For every case in
one or more YAML evaluation manifests it

  1. makes a fresh clone of the manifest repository, checks out the exact
     manifest SHA, and verifies HEAD, origin and a clean work tree;
  2. runs run_traced.py (same directory) unchanged, as a subprocess, in the
     case attempt's OWN working directory, with the canonical evaluation flags

         --context-budget-policy always --max-context-budget-windows 10
         --blind-evaluation --blind-strip-same-repo-github-references

     capturing stdout/stderr to per-case log files;
  3. classifies the attempt from run_traced's trace/run_manifest.json and the
     Trust Report's decision card (the heading pipeline.py documents as the
     anchor for tests/tooling) -- a valid "No Patch Produced" (Gray) outcome
     is never confused with a failed execution;
  4. writes batch_summary.md / batch_summary.json / batch_results.csv and one
     results ZIP, and supports --resume for interrupted batches.

Isolation contract (experimentally validated for --jobs 4): every case
attempt has its own checkout (repo/), output directory (output/) and working
directory (cwd/). The last one is mandatory: run_traced.py sets
AUTOPATCHER_DEBUG=1 and the pipeline's debug writers resolve ./reports/debug/
against the process CWD.

POSIX only (process groups, flock). Full usage, layout, statistics
semantics, resume rules and exit codes: RUN_CVE_BATCH.md (this directory).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import platform
import re
import secrets
import shlex
import signal
import subprocess
import sys
import threading
import time
import traceback
import zipfile
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

try:
    import fcntl
except ImportError:  # Windows: the runner is POSIX-only (main refuses);
    fcntl = None     # importing this module for its pure helpers must still work.

import yaml

# utilities/autopatcher/tools/run_cve_batch.py -> tools -> autopatcher ->
# utilities -> <openant-core root>
TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Reused, not reimplemented: the blind-evaluation policy table and the GitHub
# remote identity parser run_traced.py itself uses for same-repo stripping.
from utilities.autopatcher.tools.blind_evaluation import (  # noqa: E402
    BLIND_FILTER_POLICIES,
    DEFAULT_BLIND_FILTER_POLICY,
    github_repository_identity,
)

RUNNER_NAME = "run_cve_batch.py"
RUNNER_VERSION = "1.0.0"
BATCH_SCHEMA_VERSION = 1
RESULT_SCHEMA_VERSION = 1

RUN_TRACED = TOOLS_DIR / "run_traced.py"
DEFAULT_BATCH_ROOT = Path("/tmp/openant-cve-batches")
DEFAULT_JOBS = 2
VALIDATED_MAX_JOBS = 4  # the largest concurrency proven safe experimentally
DEFAULT_CASE_TIMEOUT_MINUTES = 120.0
DEFAULT_HEARTBEAT_SECONDS = 300
GIT_CLONE_TIMEOUT = 3600
GIT_TIMEOUT = 300
SHUTDOWN_GRACE_SECONDS = 20

# Exit codes (also documented in RUN_CVE_BATCH.md and every batch_summary.md).
EXIT_COMPLETE = 0          # every requested case has a valid Auto Patcher outcome
EXIT_CASE_FAILURES = 1     # finished, but at least one case FAILED
EXIT_INVALID_INPUT = 2     # bad input/usage or a failed precondition; nothing ran
EXIT_INCOMPLETE = 3        # some requested cases have not been run (yet)
EXIT_ZIP_FAILED = 4        # cases summarized, but the results ZIP could not be written
EXIT_INTERRUPTED = 130     # stopped by SIGINT/SIGTERM/SIGHUP; resume with --resume

# The canonical real-CVE regression flags (see run_traced.py and
# TRACING_AND_DEBUGGING.md §5/§25). The budget flags are deprecated no-ops in
# run_traced.py today; they are preserved so commands stay identical to the
# established regression runs.
CONTEXT_BUDGET_POLICY = "always"
MAX_CONTEXT_BUDGET_WINDOWS = 10
CONTEXT_BUDGET_FLAGS = (
    "--context-budget-policy", CONTEXT_BUDGET_POLICY,
    "--max-context-budget-windows", str(MAX_CONTEXT_BUDGET_WINDOWS),
)
BLIND_FLAGS = ("--blind-evaluation", "--blind-strip-same-repo-github-references")

# Non-secret environment variables worth recording for reproducibility. The
# full environment is never written anywhere (it can hold credentials).
RECORDED_ENV_VARS = (
    "LLM_PROVIDER", "LLM_MODEL", "LLM_MAX_TOKENS", "OPENANT_MODELS_CONFIG",
    "OPENANT_LANGUAGES_CONFIG", "AUTOPATCHER_DEBUG", "XDG_CONFIG_HOME",
    "PYTHONPATH", "VIRTUAL_ENV",
)


# ---------------------------------------------------------------------------
# Outcome vocabulary
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Outcome:
    key: str
    decision: str
    emoji: str
    patch_produced: bool


# Every terminal value pipeline.py can render on the Trust Report's first
# heading: the four Recommendation Policy decisions (_DECISION_CARD_EMOJI) plus
# the no-patch execution-outcome card (_render_no_patch_card). "Deploy With
# Caution" is listed even though it is rare, so it can never be silently
# folded into another category.
OUTCOMES = (
    Outcome("GREEN", "Deploy After Validation", "🟢", True),
    Outcome("YELLOW", "Deploy With Caution", "🟡", True),
    Outcome("ORANGE", "Manual Review Required", "🟠", True),
    Outcome("RED", "Do Not Apply", "🔴", True),
    Outcome("GRAY", "No Patch Produced", "⚫", False),
)
OUTCOME_BY_KEY = {o.key: o for o in OUTCOMES}
OUTCOME_BY_HEADLINE = {o.decision.upper(): o for o in OUTCOMES}
FAILED = "FAILED"
INCOMPLETE = "INCOMPLETE"
CATEGORIES = tuple(o.key for o in OUTCOMES) + (FAILED, INCOMPLETE)
CATEGORY_LABELS = {
    **{o.key: f"{o.emoji} {o.key.title()} — {o.decision}" for o in OUTCOMES},
    FAILED: "✖ FAILED — infrastructure/execution failure",
    INCOMPLETE: "… INCOMPLETE — not run yet / interrupted",
}

FAILURE_KINDS = {
    "clone_failed": "git clone of the manifest repository failed",
    "revision_not_found": "the manifest SHA is not in the clone and `git fetch origin <sha>` failed",
    "checkout_failed": "git checkout of the manifest SHA failed",
    "sha_mismatch": "HEAD after checkout differs from the manifest SHA",
    "origin_mismatch": "the clone's origin URL differs from the manifest URL",
    "dirty_checkout": "the fresh checkout is not clean",
    "timeout": "run_traced.py exceeded the per-case timeout and was killed",
    "killed_by_signal": "run_traced.py was terminated by a signal",
    "run_traced_usage_error": "run_traced.py exited 2 without a run manifest (argument/prerequisite error)",
    "blind_evaluation_aborted": "blind evaluation refused the advisory (BlindEvaluationError); the case cannot be run blind",
    "advisory_fetch_failed": "fetching the CVE record from NVD failed (CVEFetchError/CVENotFoundError)",
    "provider_rate_limit": "LLM provider rate limit / overload",
    "provider_error": "LLM provider or LLM configuration error",
    "environment_error": "run_traced.py prerequisite failure (TestComparisonEnvironmentError)",
    "run_traced_exception": "run_traced.py raised an exception (a failure run manifest was written)",
    "run_traced_crashed": "run_traced.py exited non-zero without a usable run manifest",
    "run_manifest_missing": "run_traced.py exited 0 but wrote no trace/run_manifest.json",
    "run_manifest_corrupt": "trace/run_manifest.json is not a valid JSON object",
    "run_manifest_not_success": "run_traced.py exited 0 but its run manifest status is not 'success'",
    "run_manifest_mismatch": "run manifest identity (CVE, commit, checkout, output) does not match this attempt",
    "blind_evaluation_unverified": "the run manifest does not prove blind evaluation was applied and verified",
    "trust_report_missing": "the Trust Report named by the run manifest does not exist",
    "recommendation_unparseable": "the Trust Report decision card does not name a known outcome",
    "recommendation_inconsistent": "the Trust Report decision card and its Recommendation section disagree",
    "runner_exception": "unexpected exception inside the batch runner itself",
}

_RATE_LIMIT_TYPES = frozenset({"LLMRateLimitError", "RateLimitError", "OverloadedError"})
_PROVIDER_TYPES = frozenset({
    "LLMError", "LLMAuthError", "LLMConnectionError", "LLMNotFoundError",
    "LLMResponseError", "LLMRefusalError", "ConfigError", "ModelUnavailableError",
    "APIError", "APIConnectionError", "APITimeoutError", "APIStatusError",
    "InternalServerError", "AuthenticationError", "PermissionDeniedError",
    "ServiceUnavailableError",
})
_RATE_LIMIT_RE = re.compile(
    r"Error code: (?:429|529)\b|rate_limit_error|overloaded_error|rate[ _-]?limit|too many requests",
    re.IGNORECASE,
)
# llm_client re-raises every provider failure as a RuntimeError with one of
# these message shapes (call_llm: "<Provider> API call failed: <LLMError>";
# adapter construction: "No usable credential for provider ..."; env checks:
# "LLM_PROVIDER=..." / "LLM_MODEL=..."). The rate-limit regex is only ever
# applied to messages already identified as provider failures.
_PROVIDER_MESSAGE_RE = re.compile(r"^(?:\S+ API call failed: |No usable credential for provider |LLM_(?:PROVIDER|MODEL)=)")
_ADVISORY_FETCH_TYPES = frozenset({"CVEFetchError", "CVENotFoundError"})
_EXCEPTION_LINE_RE = re.compile(
    r"^(?P<type>[A-Za-z_][\w.]*(?:Error|Exception|Interrupt|Exit))(?::\s?(?P<msg>.*))?$"
)
_RETRY_LIKE_RE = re.compile(r"(?:_retry|_reattempt|_revision|_reverification|_regeneration)$")
_NORMAL_EXECUTION_OUTCOMES = frozenset({"generated", "settled", "ready", "success", "completed"})

CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BATCH_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_ATTEMPT_DIR_RE = re.compile(r"^attempt-(\d+)$")
REQUIRED_CASE_FIELDS = ("id", "repo", "cve", "sha")
OPTIONAL_STRING_FIELDS = (
    "display_name", "language", "group", "category", "selection_reason",
    "tag", "ghsa", "expected_outcome", "notes",
)
UNSUPPORTED_CASE_FIELDS = {
    "advisory_file": "file-mode advisory cases are not supported (this runner invokes run_traced.py --cve)",
}
KNOWN_TOP_LEVEL_KEYS = frozenset({"cases", "group", "name", "description"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ManifestError(Exception):
    """Invalid batch input; carries every problem found, not just the first."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("\n".join(self.errors))


class RunnerSetupError(Exception):
    """A precondition for running anything failed (nothing was executed)."""


class BatchLockedError(RunnerSetupError):
    pass


class _StopRequested(Exception):
    """Internal: the batch is shutting down; do not start new work."""


class BatchInterrupted(BaseException):
    """Raised in the main thread by the SIGINT/SIGTERM/SIGHUP handler. A
    BaseException (like KeyboardInterrupt) so no `except Exception` can
    swallow an interrupt."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: "datetime | None") -> "str | None":
    return ts.isoformat(timespec="milliseconds") if ts else None


def parse_iso(value) -> "datetime | None":
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "—"
    total = int(round(float(seconds)))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def fmt_bytes(n) -> str:
    if n is None:
        return "—"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def fmt_percent(value) -> str:
    return "n/a" if value is None else f"{value:.1f}%"


def percent(count: int, denominator: int) -> "float | None":
    return None if denominator == 0 else round(100.0 * count / denominator, 2)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def write_json_atomic(path: Path, obj) -> None:
    write_text_atomic(path, json.dumps(obj, indent=2, ensure_ascii=False, default=str) + "\n")


def read_json(path: Path):
    """(object, None) or (None, error string). Never raises."""
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, "missing"
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"unreadable: {exc}"
    except ValueError as exc:
        return None, f"invalid JSON: {exc}"


def read_text_capped(path: Path, max_bytes: int = 4 * 1024 * 1024) -> str:
    try:
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if size > max_bytes:
                fh.seek(size - max_bytes)
            data = fh.read()
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def clip(text, limit: int = 400) -> "str | None":
    if text is None:
        return None
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def rel_to(path, base: Path) -> "str | None":
    if not path:
        return None
    try:
        return os.path.relpath(str(path), str(base))
    except ValueError:
        return str(path)


def _resolved(path) -> "Path | None":
    if not path:
        return None
    try:
        return Path(path).resolve()
    except (OSError, RuntimeError):
        return None


def same_path(a, b) -> bool:
    ra, rb = _resolved(a), _resolved(b)
    return ra is not None and ra == rb


def path_inside(path, root) -> bool:
    rp, rr = _resolved(path), _resolved(root)
    if rp is None or rr is None:
        return False
    return rp == rr or rr in rp.parents


def json_safe(value):
    """YAML can produce dates etc.; keep metadata JSON-serializable."""
    return json.loads(json.dumps(value, default=str))


def _git_text(args, cwd, timeout: int = GIT_TIMEOUT) -> "str | None":
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            env=_git_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def _git_env() -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"  # never block a worker on a credential prompt
    return env


# ---------------------------------------------------------------------------
# Manifest loading and validation
# ---------------------------------------------------------------------------

class _StrictSafeLoader(yaml.SafeLoader):
    """yaml.SafeLoader that rejects duplicate mapping keys instead of silently
    keeping the last one (a duplicated `sha:` must never pass unnoticed)."""


def _construct_mapping_no_duplicates(loader, node, deep=False):
    seen = set()
    for key_node, _value in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue  # `<<: *base` merge keys are flattened by SafeConstructor itself
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError:
            duplicate = False
        if duplicate:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark,
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_duplicates,
)


def repo_url_problem(url: str) -> "str | None":
    parts = urlsplit(url)
    if parts.scheme != "https":
        return "must be an https:// URL"
    if "@" in parts.netloc:
        return "must not embed credentials (userinfo) in the URL"
    if parts.query or parts.fragment:
        return "must not carry a query string or fragment"
    if github_repository_identity(url) is None:
        return (
            "must name a GitHub repository (https://github.com/<owner>/<repo>[.git]); "
            "same-repository GitHub reference stripping, part of the canonical "
            "blind-evaluation setup, needs a GitHub origin"
        )
    return None


@dataclass
class LoadedManifests:
    inputs: list
    cases: list


def _validate_manifest_document(data, path: Path, input_index: int, digest: str):
    errors: list[str] = []
    cases: list[dict] = []
    if not isinstance(data, dict):
        return cases, [f"{path}: top level must be a mapping with a `cases` list"], None
    unknown = sorted(str(k) for k in set(data) - KNOWN_TOP_LEVEL_KEYS)
    if unknown:
        errors.append(
            f"{path}: unknown top-level key(s) {unknown}; allowed: {sorted(KNOWN_TOP_LEVEL_KEYS)}"
        )
    group = data.get("group")
    if group is not None and not (isinstance(group, str) and group.strip()):
        errors.append(f"{path}: top-level `group` must be a non-empty string")
        group = None
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        errors.append(f"{path}: `cases` must be a non-empty list")
        return cases, errors, group
    for index, raw in enumerate(raw_cases, 1):
        where = f"{path.name}: case #{index}"
        if not isinstance(raw, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        if isinstance(raw.get("id"), str):
            where += f" ({raw['id']})"
        problems = []
        for key in REQUIRED_CASE_FIELDS:
            value = raw.get(key)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"missing or empty string field `{key}`")
            elif value != value.strip():
                problems.append(f"`{key}` has leading/trailing whitespace")
        if not problems:
            if not CASE_ID_RE.fullmatch(raw["id"]):
                problems.append(
                    "`id` must be 1-128 characters of [A-Za-z0-9._-] starting with a letter or digit"
                )
            if not CVE_RE.fullmatch(raw["cve"]):
                problems.append(f"`cve` must look like CVE-YYYY-NNNN (got {raw['cve']!r})")
            if not SHA_RE.fullmatch(raw["sha"]):
                problems.append(
                    f"`sha` must be the full 40-character lowercase hex commit SHA (got {raw['sha']!r})"
                )
            url_problem = repo_url_problem(raw["repo"])
            if url_problem:
                problems.append(f"`repo` {raw['repo']!r} {url_problem}")
        for key in OPTIONAL_STRING_FIELDS:
            if raw.get(key) is not None and not isinstance(raw[key], str):
                problems.append(f"`{key}` must be a string")
        tags = raw.get("tags")
        if tags is not None and not (isinstance(tags, list) and all(isinstance(t, str) for t in tags)):
            problems.append("`tags` must be a list of strings")
        for key, why in UNSUPPORTED_CASE_FIELDS.items():
            if key in raw:
                problems.append(f"`{key}`: {why}")
        if problems:
            errors.extend(f"{where}: {p}" for p in problems)
            continue
        cases.append({
            "id": raw["id"],
            "cve": raw["cve"],
            "repo": raw["repo"],
            "sha": raw["sha"],
            "display_name": raw.get("display_name"),
            "language": raw.get("language"),
            "group": raw.get("group") or group,
            "repo_identity": github_repository_identity(raw["repo"]).slug,
            "source": {
                "manifest": str(path),
                "manifest_sha256": digest,
                "input_index": input_index,
                "index": index,
            },
            "metadata": json_safe(raw),
        })
    return cases, errors, group


def _location(case: dict) -> str:
    src = case["source"]
    return f"{Path(src['manifest']).name} case #{src['index']} ({case['id']})"


def _cross_case_errors(cases: list, allow_duplicate_cve: bool) -> list:
    errors = []
    by_id: dict = {}
    by_identity: dict = {}
    by_cve: dict = {}
    for case in cases:
        key = case["id"].lower()
        if key in by_id:
            other = by_id[key]
            note = "" if other["id"] == case["id"] else " (ids differ only by case; they would collide on disk)"
            errors.append(f"duplicate case id: {_location(other)} and {_location(case)}{note}")
            continue
        by_id[key] = case
        identity = (case["repo_identity"], case["sha"], case["cve"])
        if identity in by_identity:
            errors.append(
                f"duplicate case: {_location(by_identity[identity])} and {_location(case)} are the "
                "same CVE at the same repository and SHA"
            )
            continue
        by_identity[identity] = case
        by_cve.setdefault(case["cve"], []).append(case)
    if not allow_duplicate_cve:
        for cve, group in by_cve.items():
            if len(group) > 1:
                errors.append(
                    f"{cve} appears in {len(group)} cases ({', '.join(_location(c) for c in group)}); "
                    "pass --allow-duplicate-cve if that is intentional"
                )
    return errors


def load_manifests(paths, *, allow_duplicate_cve: bool = False) -> LoadedManifests:
    errors: list[str] = []
    inputs: list[dict] = []
    cases: list[dict] = []
    seen: dict = {}
    for input_index, given in enumerate(paths, 1):
        path = Path(given).expanduser()
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            errors.append(f"{given}: manifest file not found")
            continue
        if not resolved.is_file():
            errors.append(f"{given}: not a regular file")
            continue
        if str(resolved) in seen:
            errors.append(f"{given}: the same manifest file was given more than once")
            continue
        seen[str(resolved)] = input_index
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            errors.append(f"{resolved}: cannot be read: {exc}")
            continue
        digest = sha256_bytes(raw)
        try:
            data = yaml.load(raw.decode("utf-8"), Loader=_StrictSafeLoader)  # noqa: S506 -- strict SafeLoader subclass
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            errors.append(f"{resolved}: malformed YAML: {exc}")
            continue
        doc_cases, doc_errors, group = _validate_manifest_document(data, resolved, input_index, digest)
        errors.extend(doc_errors)
        inputs.append({
            "input_index": input_index,
            "path": str(resolved),
            "sha256": digest,
            "case_count": len(doc_cases),
            "group": group,
            "name": data.get("name") if isinstance(data, dict) else None,
            "_raw": raw,
        })
        cases.extend(doc_cases)
    errors.extend(_cross_case_errors(cases, allow_duplicate_cve))
    if not paths:
        errors.append("no manifest given")
    if errors:
        raise ManifestError(errors)
    return LoadedManifests(inputs, cases)


def select_cases(cases: list, wanted) -> list:
    """Keep manifest order; `wanted` (from --case) only filters."""
    if not wanted:
        selected = list(cases)
    else:
        known = {c["id"] for c in cases}
        missing = [w for w in wanted if w not in known]
        if missing:
            raise ManifestError([f"--case {m!r} is not a case id in the given manifest(s)" for m in missing])
        keep = set(wanted)
        selected = [c for c in cases if c["id"] in keep]
    for order, case in enumerate(selected, 1):
        case["order"] = order
    return selected


# ---------------------------------------------------------------------------
# Provenance: OpenAnt work tree, interpreter, environment, secrets
# ---------------------------------------------------------------------------

def collect_openant_state() -> dict:
    """HEAD, dirty status and a content fingerprint of the OpenAnt work tree
    (tracked diff + untracked file hashes) -- used to record provenance and to
    refuse resuming a batch against different code. `_diff` (raw bytes of
    `git diff HEAD --binary`) is popped by the caller before serializing."""
    top = _git_text(["rev-parse", "--show-toplevel"], cwd=PROJECT_ROOT)
    head = _git_text(["rev-parse", "HEAD"], cwd=top) if top else None
    if not top or not head:
        raise RunnerSetupError(f"cannot read the OpenAnt git state from {PROJECT_ROOT}")
    # A read-only observer must never write .git/index (it runs before and
    # after every case, possibly while the developer uses git in this repo):
    # --no-optional-locks keeps `status` from refreshing the index, and
    # diff.autoRefreshIndex=false does the same for `diff` (whose output for
    # stat-only changes stays empty either way).
    status = subprocess.run(
        ["git", "--no-optional-locks", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=top, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=GIT_TIMEOUT,
    )
    diff = subprocess.run(
        ["git", "--no-optional-locks", "-c", "diff.autoRefreshIndex=false", "diff", "HEAD", "--binary"],
        cwd=top, capture_output=True, timeout=GIT_TIMEOUT,
    )
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=top, capture_output=True, timeout=GIT_TIMEOUT,
    )
    if status.returncode or diff.returncode or untracked.returncode:
        raise RunnerSetupError("cannot read the OpenAnt git work-tree status")
    fingerprint = hashlib.sha256(head.encode() + b"\0" + diff.stdout)
    untracked_files = []
    for name in sorted(n for n in untracked.stdout.decode("utf-8", "surrogateescape").split("\0") if n):
        path = Path(top) / name
        try:
            digest = sha256_file(path) if path.is_file() and not path.is_symlink() else "not-a-regular-file"
        except OSError:
            digest = "unreadable"
        untracked_files.append({"path": name, "sha256": digest})
        fingerprint.update(f"\0{name}\0{digest}".encode("utf-8", "surrogateescape"))
    lines = [line for line in status.stdout.splitlines() if line.strip()]
    return {
        "work_tree": top,
        "head": head,
        "dirty": bool(lines),
        "status_porcelain": lines,
        "tracked_diff_sha256": sha256_bytes(diff.stdout) if diff.stdout else None,
        "untracked_files": untracked_files,
        "fingerprint": fingerprint.hexdigest(),
        "_diff": diff.stdout,
    }


def probe_python(executable: str) -> dict:
    code = (
        "import json, platform, sys; print(json.dumps({'executable': sys.executable, "
        "'version': platform.python_version(), 'version_info': list(sys.version_info[:3])}))"
    )
    try:
        proc = subprocess.run([executable, "-c", code], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerSetupError(f"--python {executable!r} cannot be executed: {exc}") from exc
    if proc.returncode != 0:
        raise RunnerSetupError(f"--python {executable!r} failed: {clip(proc.stderr, 300)}")
    try:
        info = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise RunnerSetupError(f"--python {executable!r} gave unexpected output") from exc
    if tuple(info["version_info"][:2]) < (3, 11):
        raise RunnerSetupError(
            f"run_traced.py requires Python 3.11+; {executable!r} is {info['version']}"
        )
    info["requested"] = executable
    return info


# What run_traced.py imports only AFTER argument parsing (core.patch pulls in
# the pipeline), so `--help` alone cannot prove these are importable.
LAZY_IMPORT_PROBE = ("core.patch", "utilities.autopatcher.pipeline")


def probe_run_traced(python: str, run_traced: str) -> None:
    """Fail before any checkout or LLM work if run_traced.py cannot run:
    `<python> run_traced.py --help` must succeed (module-level imports +
    argument parser), and -- for the canonical run_traced.py -- the modules it
    imports lazily after parsing (core.patch and the Auto Patcher pipeline)
    must import too. Nothing is executed beyond imports."""
    try:
        proc = subprocess.run([python, run_traced, "--help"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
                              cwd=str(Path(run_traced).parent), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerSetupError(f"cannot execute {run_traced} with {python}: {exc}") from exc
    if proc.returncode != 0:
        raise RunnerSetupError(
            f"`{python} {run_traced} --help` failed with exit {proc.returncode} -- is OpenAnt installed for "
            f"this interpreter?\n{clip(proc.stderr, 600)}"
        )
    if not same_path(run_traced, RUN_TRACED):
        return  # a substituted script (testing hook) has no lazy OpenAnt imports to verify
    modules = ", ".join(LAZY_IMPORT_PROBE)
    code = f"import sys; sys.path.insert(0, sys.argv[1]); import {modules}"
    try:
        proc = subprocess.run([python, "-c", code, str(PROJECT_ROOT)], capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=300, cwd=str(PROJECT_ROOT), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerSetupError(f"cannot probe the Auto Patcher imports with {python}: {exc}") from exc
    if proc.returncode != 0:
        raise RunnerSetupError(
            f"{python} cannot import {modules} (run_traced.py imports them after argument parsing), "
            f"so every case would crash:\n{clip(proc.stderr, 600)}"
        )


def canonical_run_traced_flags(explicit_policy: "str | None") -> list:
    return [*CONTEXT_BUDGET_FLAGS, *BLIND_FLAGS,
            *(["--blind-filter-policy", explicit_policy] if explicit_policy else [])]


def run_config_problems(run_config: dict) -> list:
    """A stored run configuration must still describe the canonical evaluation
    setup -- resume never trusts an edited batch_manifest.json."""
    problems = []
    policy = run_config.get("blind_filter_policy")
    if policy not in BLIND_FILTER_POLICIES:
        return [f"unknown blind_filter_policy {policy!r}"]
    expected = canonical_run_traced_flags(policy if run_config.get("blind_filter_policy_explicit") else None)
    if run_config.get("run_traced_flags") != expected:
        problems.append(f"run_traced_flags {run_config.get('run_traced_flags')!r} are not the canonical {expected!r}")
    if run_config.get("expected_blind_rule_id") != BLIND_FILTER_POLICIES[policy]:
        problems.append("expected_blind_rule_id does not match the blind filter policy")
    if (run_config.get("context_budget_policy") != CONTEXT_BUDGET_POLICY
            or run_config.get("max_context_budget_windows") != MAX_CONTEXT_BUDGET_WINDOWS):
        problems.append("context budget settings are not the canonical ones")
    if run_config.get("blind_evaluation") is not True or run_config.get("same_repo_github_stripping") is not True:
        problems.append("blind evaluation / same-repo GitHub stripping are not both enabled")
    return problems


def recorded_environment() -> dict:
    return {name: os.environ[name] for name in RECORDED_ENV_VARS if name in os.environ}


_SECRET_ENV_NAME_RE = re.compile(
    r"API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY", re.IGNORECASE,
)
_SECRET_CONFIG_KEY_RE = re.compile(r"api_?key|token|secret|password", re.IGNORECASE)
_MIN_SECRET_LENGTH = 12


def _config_secret_values(node, found: set) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and _SECRET_CONFIG_KEY_RE.search(str(key)):
                if len(value.strip()) >= _MIN_SECRET_LENGTH:
                    found.add(value.strip())
            else:
                _config_secret_values(value, found)
    elif isinstance(node, list):
        for item in node:
            _config_secret_values(item, found)


def collect_secret_values(environ=None, include_openant_config: bool = True) -> list:
    """Exact credential values the ZIP must never contain: environment
    variables with credential-like names, plus API keys in OpenAnt's
    config.json (located with OpenAnt's own default_config_path()). Values
    stay in memory only; they are never printed or written."""
    env = os.environ if environ is None else environ
    found: set = set()
    for name, value in env.items():
        if _SECRET_ENV_NAME_RE.search(name) and value and len(value.strip()) >= _MIN_SECRET_LENGTH:
            found.add(value.strip())
    if include_openant_config:
        try:
            from utilities.llm.registry import default_config_path

            cfg = default_config_path()
            if cfg.is_file():
                _config_secret_values(json.loads(cfg.read_text(encoding="utf-8")), found)
        except Exception:  # best-effort: a broken config must not break packaging
            pass
    return sorted(v.encode("utf-8") for v in found)


# ---------------------------------------------------------------------------
# Batch directory layout and lock
# ---------------------------------------------------------------------------

class BatchLayout:
    def __init__(self, batch_dir: Path):
        self.dir = batch_dir
        self.manifest = batch_dir / "batch_manifest.json"
        self.summary_md = batch_dir / "batch_summary.md"
        self.summary_json = batch_dir / "batch_summary.json"
        self.results_csv = batch_dir / "batch_results.csv"
        self.inputs_dir = batch_dir / "inputs"
        self.logs_dir = batch_dir / "logs"
        self.provenance_dir = batch_dir / "provenance"
        self.cases_dir = batch_dir / "cases"
        self.log_file = self.logs_dir / "batch.log"
        self.lock_file = batch_dir / ".batch.lock"

    def case_dir(self, case_id: str) -> Path:
        return self.cases_dir / case_id

    def attempt_dir(self, case_id: str, attempt: int) -> Path:
        return self.case_dir(case_id) / f"attempt-{attempt:02d}"

    def zip_path(self, batch_id: str) -> Path:
        return self.dir / f"{batch_id}-results.zip"

    def attempts(self, case_id: str) -> list:
        """[(number, path)] sorted numerically."""
        found = []
        case_dir = self.case_dir(case_id)
        if case_dir.is_dir():
            for entry in case_dir.iterdir():
                m = _ATTEMPT_DIR_RE.match(entry.name)
                if m and entry.is_dir() and not entry.is_symlink():
                    found.append((int(m.group(1)), entry))
        return sorted(found)


def attempt_paths(attempt_dir: Path) -> dict:
    output = attempt_dir / "output"
    return {
        "attempt_dir": attempt_dir,
        "repo": attempt_dir / "repo",
        "cwd": attempt_dir / "cwd",
        "output": output,
        "trace": output / "trace",
        "stdout": attempt_dir / "stdout.log",
        "stderr": attempt_dir / "stderr.log",
        "command": attempt_dir / "command.json",
        "result": attempt_dir / "result.json",
        "runner_error": attempt_dir / "runner_error.txt",
    }


class BatchLock:
    """Exclusive flock on <batch>/.batch.lock: one runner per batch directory.
    Released automatically if the process dies."""

    def __init__(self, layout: BatchLayout):
        self.path = layout.lock_file
        self._fh = None

    def __enter__(self):
        fh = open(self.path, "a+", encoding="utf-8")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fh.seek(0)
            holder = fh.read().strip()
            fh.close()
            raise BatchLockedError(
                f"batch {self.path.parent} is in use by another runner ({holder or 'unknown holder'})"
            ) from None
        fh.seek(0)
        fh.truncate()
        fh.write(json.dumps({"pid": os.getpid(), "host": platform.node(), "since": iso(utc_now())}))
        fh.flush()
        self._fh = fh
        return self

    def __exit__(self, *exc):
        if self._fh is not None:
            self._fh.seek(0)
            self._fh.truncate()
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None
        return False


# ---------------------------------------------------------------------------
# Reading run_traced artifacts
# ---------------------------------------------------------------------------

def _as_str(value) -> "str | None":
    return value if isinstance(value, str) else None


def read_checkpoint_stages(path: Path) -> "list | None":
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    stages = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            return None
        stages.append(record.get("stage") if isinstance(record, dict) else None)
    return stages


def read_run_manifest(trace_dir: Path) -> dict:
    """Extract the fields the batch needs from trace/run_manifest.json. Never
    raises; `present`/`parse_error` describe what was found."""
    path = trace_dir / "run_manifest.json"
    info: dict = {"path": str(path), "present": False, "parse_error": None}
    data, error = read_json(path)
    if error == "missing":
        return info
    info["present"] = True
    if error:
        info["parse_error"] = error
        return info
    if not isinstance(data, dict):
        info["parse_error"] = "not a JSON object"
        return info
    target = data.get("target_repository") if isinstance(data.get("target_repository"), dict) else {}
    openant = data.get("openant") if isinstance(data.get("openant"), dict) else {}
    llm = data.get("llm") if isinstance(data.get("llm"), dict) else {}
    executions = []
    for entry in data.get("executions") or []:
        if isinstance(entry, dict):
            executions.append({
                "execution_id": _as_str(entry.get("execution_id")),
                "canonical_stage": _as_str(entry.get("canonical_stage")),
                "outcome": _as_str(entry.get("outcome")),
                "llm_calls": len(entry.get("llm_calls") or []),
            })
    blind = None
    raw_blind = data.get("blind_evaluation")
    if isinstance(raw_blind, dict):
        same_repo = raw_blind.get("same_repo_github_policy")
        blind = {
            "enabled": raw_blind.get("enabled"),
            "rule_id": raw_blind.get("rule_id"),
            "status": raw_blind.get("status"),
            "pipeline_input_verified": raw_blind.get("pipeline_input_verified"),
            "vulnerability_artifact_verified": raw_blind.get("vulnerability_artifact_verified"),
            "same_repo_github_policy_enabled": same_repo.get("enabled") if isinstance(same_repo, dict) else None,
            "removed_count": raw_blind.get("removed_count"),
            "error": raw_blind.get("error"),
            "run_error": raw_blind.get("run_error"),
        }
    checkpoints_name = Path(_as_str(data.get("checkpoints_file")) or "checkpoints.jsonl").name
    stages = read_checkpoint_stages(trace_dir / checkpoints_name)
    llm_call_count = data.get("llm_call_count")
    info.update({
        "status": _as_str(data.get("status")),
        "error_type": _as_str(data.get("error_type")),
        "error_message": _as_str(data.get("error_message")),
        "schema_version": data.get("schema_version"),
        "input_type": _as_str(data.get("input_type")),
        "input_id": _as_str(data.get("input_id")),
        "repo_root": _as_str(data.get("repo_root")) or _as_str(target.get("repo_root")),
        "output_dir": _as_str(data.get("output_dir")),
        "repo_commit": _as_str(target.get("repo_commit")),
        "patcher_commit": _as_str(openant.get("patcher_commit")),
        "provider": _as_str(llm.get("provider")),
        "model": _as_str(llm.get("model")),
        "context_budget_policy": data.get("context_budget_policy"),
        "max_context_budget_windows": data.get("max_context_budget_windows"),
        "trust_report_path": _as_str(data.get("trust_report_path")),
        "vulnerability_path": _as_str(data.get("vulnerability_path")),
        "llm_call_count": llm_call_count if isinstance(llm_call_count, int) else None,
        "checkpoint_stages": stages,
        "executions": executions,
        "blind": blind,
        "debug_artifacts": [a for a in data.get("autopatcher_debug_artifacts") or [] if isinstance(a, str)],
    })
    return info


_DECISION_CARD_RE = re.compile(r"^##\s+(?P<emoji>\S+)\s+(?P<label>[A-Z][A-Z ]*[A-Z])\s*$")
# The Recommendation line: "**<Decision>**", optionally led by the decision
# card's icon ("🟢 **Deploy After Validation**"); reports without it parse too.
_BOLD_LINE_RE = re.compile(r"^(?:(?P<emoji>[^\s*]+)\s+)?\*\*(?P<text>[^*]+)\*\*\s*$")
_SKIPPED_RE = re.compile(r"^\*\(Skipped — (?P<reason>.*?)\.?\)\*\s*$")
_FILES_CHANGED_RE = re.compile(r"^Files changed:\s*(?P<n>\d+)\s*$")


# Column-0 only, exactly like the pipeline's own fence rule
# (patch_generator.py): a diff context line " ```" of a patched Markdown file
# must never open or close a fence here.
_FENCE_RE = re.compile(r"^(`{3,}|~{3,})")


def _heading_indices(lines: list) -> list:
    """Indices of column-0 `## ` headings outside fenced code blocks -- a
    patched Markdown file's diff context (` ## Recommendation`) or fenced
    model output can never pose as a report section."""
    found, fence = [], None
    for i, line in enumerate(lines):
        m = _FENCE_RE.match(line)
        if m:
            marker = m.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence) and not line.strip()[len(marker):]:
                fence = None
            continue
        if fence is None and line.startswith("## "):
            found.append(i)
    return found


def _section_first_line(lines: list, headings: list, heading: str) -> "str | None":
    for pos, index in enumerate(headings):
        if lines[index].rstrip() == heading:
            end = headings[pos + 1] if pos + 1 < len(headings) else len(lines)
            for follow in lines[index + 1:end]:
                if follow.strip():
                    return follow.strip()
            return None
    return None


def parse_trust_report(path: Path) -> dict:
    """Read the Trust Report's decision card -- its first level-2 heading,
    `## <emoji> <DECISION>` (pipeline._render_decision_card) or
    `## ⚫ NO PATCH PRODUCED` (pipeline._render_no_patch_card) -- and
    cross-check it against the `## Recommendation` section."""
    info = {
        "path": str(path), "present": False, "parse_error": None, "inconsistency": None,
        "headline": None, "outcome": None, "decision": None,
        "recommendation_section_decision": None, "files_changed": None,
        "applicability_skip_reason": None,
    }
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return info
    except (OSError, UnicodeDecodeError) as exc:
        info.update(present=True, parse_error=f"unreadable: {exc}")
        return info
    info["present"] = True
    lines = text.splitlines()
    headings = _heading_indices(lines)
    if not headings:
        info["parse_error"] = "no level-2 heading (decision card) found"
        return info
    heading_index = headings[0]
    heading = lines[heading_index].strip()
    info["headline"] = heading[3:].strip()
    match = _DECISION_CARD_RE.match(heading)
    outcome = OUTCOME_BY_HEADLINE.get(match.group("label")) if match else None
    if outcome is None:
        info["parse_error"] = f"first heading is not a known decision card: {heading!r}"
        return info
    info.update(outcome=outcome.key, decision=outcome.decision)
    card_end = headings[1] if len(headings) > 1 else len(lines)
    for line in lines[heading_index + 1:card_end]:
        m = _FILES_CHANGED_RE.match(line.strip())
        if m:
            info["files_changed"] = int(m.group("n"))
    rec_line = _section_first_line(lines, headings, "## Recommendation")
    rec_match = _BOLD_LINE_RE.match(rec_line) if rec_line else None
    info["recommendation_section_decision"] = rec_match.group("text").strip() if rec_match else None
    rec_emoji = rec_match.group("emoji") if rec_match else None
    skip_line = _section_first_line(lines, headings, "## Patch Applicability")
    skip_match = _SKIPPED_RE.match(skip_line) if skip_line else None
    info["applicability_skip_reason"] = skip_match.group("reason") if skip_match else None

    problems = []
    if match.group("emoji").rstrip("\ufe0f") != outcome.emoji:
        problems.append(f"decision card emoji {match.group('emoji')!r} does not belong to {outcome.decision!r}")
    rec = info["recommendation_section_decision"]
    if outcome.patch_produced:
        if rec is None:
            problems.append("no `## Recommendation` decision found")
        elif rec.lower() != outcome.decision.lower():
            problems.append(f"decision card says {outcome.decision!r} but Recommendation says {rec!r}")
        elif rec_emoji is not None and rec_emoji.rstrip("\ufe0f") != outcome.emoji:
            problems.append(f"Recommendation icon {rec_emoji!r} does not belong to {outcome.decision!r}")
    elif rec is not None:
        problems.append(f"no-patch card but the Recommendation section says {rec!r}")
    if problems:
        info["inconsistency"] = "; ".join(problems)
    return info


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def parse_trace_summary(stderr_text: str) -> "dict | None":
    """run_traced.py's human Trace Summary (stderr, success path only): LLM
    calls, tokens and cost from OpenAnt's canonical TokenTracker. Cost is as
    printed (rounded to cents)."""
    text = _ANSI_RE.sub("", stderr_text or "")
    start = text.rfind("Trace Summary")
    if start < 0:
        return None
    block = text[start:]
    calls = re.search(r"^LLM calls\s+(\d+)\s*$", block, re.MULTILINE)
    tokens = re.search(r"^Tokens\s+([\d,]+)\s*$", block, re.MULTILINE)
    cost = re.search(r"^Cost\s+\$([\d,]+(?:\.\d+)?)\s*$", block, re.MULTILINE)
    if not (calls or tokens or cost):
        return None
    return {
        "llm_calls": int(calls.group(1)) if calls else None,
        "tokens": int(tokens.group(1).replace(",", "")) if tokens else None,
        "cost_usd": float(cost.group(1).replace(",", "")) if cost else None,
        "source": "run_traced.py Trace Summary (stderr); cost rounded to cents",
    }


def _last_exception(stderr_text: str):
    for line in reversed((stderr_text or "").splitlines()):
        if not line or line[0].isspace():
            continue
        m = _EXCEPTION_LINE_RE.match(line.strip())
        if m:
            return m.group("type"), (m.group("msg") or "").strip()
    return None, None


def _last_error_line(stderr_text: str) -> str:
    for line in reversed((stderr_text or "").splitlines()):
        if line.strip():
            return line.strip()
    return "(no stderr output)"


def error_kind(error_type, error_message) -> str:
    short = (error_type or "").rsplit(".", 1)[-1]
    message = error_message or ""
    if short == "BlindEvaluationError":
        return "blind_evaluation_aborted"
    if short == "TestComparisonEnvironmentError":
        return "environment_error"
    if short in _ADVISORY_FETCH_TYPES:
        return "advisory_fetch_failed"  # NVD, not the LLM provider -- even on HTTP 429
    provider = (short in _PROVIDER_TYPES or short in _RATE_LIMIT_TYPES
                or (short == "RuntimeError" and bool(_PROVIDER_MESSAGE_RE.match(message))))
    if not provider:
        return "run_traced_exception"
    if short in _RATE_LIMIT_TYPES or _RATE_LIMIT_RE.search(message):
        return "provider_rate_limit"
    return "provider_error"


# ---------------------------------------------------------------------------
# Attempt classification (pure)
# ---------------------------------------------------------------------------

def identity_mismatches(rm: dict, case: dict, paths: dict) -> list:
    problems = []
    if rm.get("input_type") not in (None, "cve"):
        problems.append(f"input_type {rm.get('input_type')!r} is not 'cve'")
    if rm.get("input_id") != case["cve"]:
        problems.append(f"input_id {rm.get('input_id')!r} is not this case's {case['cve']}")
    if rm.get("repo_commit") != case["sha"]:
        problems.append(f"target_repository.repo_commit {rm.get('repo_commit')!r} is not the manifest SHA")
    if not same_path(rm.get("repo_root"), paths["repo"]):
        problems.append(f"repo_root {rm.get('repo_root')!r} is not this attempt's checkout")
    if not same_path(rm.get("output_dir"), paths["output"]):
        problems.append(f"output_dir {rm.get('output_dir')!r} is not this attempt's output directory")
    trust_report = rm.get("trust_report_path")
    if not trust_report or not path_inside(trust_report, paths["output"]):
        problems.append(f"trust_report_path {trust_report!r} is not inside this attempt's output directory")
    return problems


def blind_problems(blind, run_config: dict) -> list:
    if blind is None:
        return ["the run manifest has no blind_evaluation block"]
    problems = []
    if blind.get("enabled") is not True:
        problems.append("blind_evaluation.enabled is not true")
    if blind.get("status") != "verified":
        problems.append(f"blind_evaluation.status is {blind.get('status')!r}, not 'verified'")
    if blind.get("rule_id") != run_config["expected_blind_rule_id"]:
        problems.append(
            f"blind_evaluation.rule_id is {blind.get('rule_id')!r}, expected "
            f"{run_config['expected_blind_rule_id']!r}"
        )
    if blind.get("pipeline_input_verified") is not True:
        problems.append("pipeline_input_verified is not true")
    if blind.get("vulnerability_artifact_verified") is not True:
        problems.append("vulnerability_artifact_verified is not true")
    if run_config.get("same_repo_github_stripping") and blind.get("same_repo_github_policy_enabled") is not True:
        problems.append("same-repository GitHub stripping was requested but is not recorded as enabled")
    if blind.get("error") or blind.get("run_error"):
        problems.append(f"blind_evaluation error recorded: {clip(blind.get('error') or blind.get('run_error'), 160)}")
    return problems


def collect_anomalies(*, rm: dict, case: dict, paths: dict, run_config: dict,
                      openant_head, checkout) -> list:
    """Warnings that do not invalidate the outcome but must stay visible."""
    anomalies = []
    stages = rm.get("checkpoint_stages")
    if stages is None:
        anomalies.append("checkpoints.jsonl missing or unreadable")
    elif rm.get("llm_call_count") is not None and len(stages) != rm["llm_call_count"]:
        anomalies.append(
            f"llm_call_count {rm['llm_call_count']} != {len(stages)} checkpoints.jsonl records"
        )
    debug_root = paths["cwd"] / "reports" / "debug"
    for artifact in rm.get("debug_artifacts") or []:
        if not path_inside(artifact, debug_root):
            anomalies.append(f"debug artifact outside this attempt's CWD: {artifact}")
    if openant_head and rm.get("patcher_commit") and rm["patcher_commit"] != openant_head:
        anomalies.append(
            f"run used OpenAnt commit {rm['patcher_commit'][:12]}, batch session recorded {openant_head[:12]}"
        )
    if rm.get("provider") == "mock":
        anomalies.append("LLM provider was 'mock' -- not a real evaluation")
    if (rm.get("context_budget_policy") != run_config.get("context_budget_policy")
            or rm.get("max_context_budget_windows") != run_config.get("max_context_budget_windows")):
        anomalies.append(
            "context budget settings in the run manifest "
            f"({rm.get('context_budget_policy')!r}/{rm.get('max_context_budget_windows')!r}) differ "
            "from the batch configuration"
        )
    if checkout:
        if checkout.get("post_run_head") not in (None, case["sha"]):
            anomalies.append(f"target checkout HEAD moved during the run (now {checkout['post_run_head']})")
        if checkout.get("post_run_clean") is False:
            anomalies.append("target checkout was modified during the run")
    return anomalies


def classify_attempt(*, case: dict, paths: dict, run_config: dict, openant_head,
                     checkout, execution, stop_requested: bool, run_manifest,
                     trust_report, stderr_text: str) -> dict:
    """Decide one attempt's status from evidence only. Returns status
    ('completed' | 'failed' | 'interrupted'), failure_kind/detail, outcome,
    decision and anomalies."""
    verdict = {"status": None, "failure_kind": None, "failure_detail": None,
               "outcome": None, "decision": None, "anomalies": []}

    def failed(kind: str, detail) -> dict:
        verdict.update(status="failed", failure_kind=kind, failure_detail=clip(detail))
        return verdict

    ran_ok = bool(execution) and execution.get("exit_code") == 0 and not execution.get("timed_out")
    if stop_requested and not ran_ok:
        verdict.update(status="interrupted", failure_detail="the batch was stopped before this attempt finished")
        return verdict
    if not checkout:
        return failed("runner_exception", "checkout step did not run")
    if checkout.get("failure_kind"):
        return failed(checkout["failure_kind"], checkout.get("detail"))
    if not execution:
        return failed("runner_exception", "run_traced.py was not executed")
    if execution.get("timed_out"):
        return failed("timeout", f"run_traced.py exceeded {execution.get('timeout_seconds')}s and was killed")
    code = execution.get("exit_code")
    rm = run_manifest or {"present": False}
    if code != 0:
        if isinstance(code, int) and code < 0:
            return failed("killed_by_signal", f"run_traced.py was killed by signal {-code}")
        if rm.get("present") and not rm.get("parse_error") and rm.get("status") == "failed":
            etype, emsg = rm.get("error_type"), rm.get("error_message")
            return failed(error_kind(etype, emsg), f"exit {code}; {etype}: {emsg}")
        etype, emsg = _last_exception(stderr_text)
        if etype and error_kind(etype, emsg) in ("provider_rate_limit", "provider_error"):
            return failed(error_kind(etype, emsg), f"exit {code}; {etype}: {emsg}")
        if code == 2:
            return failed("run_traced_usage_error", f"exit 2; {_last_error_line(stderr_text)}")
        detail = f"{etype}: {emsg}" if etype else _last_error_line(stderr_text)
        if rm.get("status") == "success":
            detail = "after writing a success run manifest; " + detail
        return failed("run_traced_crashed", f"exit {code}; {detail}")
    if not rm.get("present"):
        return failed("run_manifest_missing", f"{paths['trace'] / 'run_manifest.json'} was not written")
    if rm.get("parse_error"):
        return failed("run_manifest_corrupt", rm["parse_error"])
    if rm.get("status") != "success":
        return failed("run_manifest_not_success", f"exit 0 but run manifest status is {rm.get('status')!r}")
    mismatches = identity_mismatches(rm, case, paths)
    if mismatches:
        return failed("run_manifest_mismatch", "; ".join(mismatches))
    problems = blind_problems(rm.get("blind"), run_config)
    if problems:
        return failed("blind_evaluation_unverified", "; ".join(problems))
    if not trust_report or not trust_report.get("present"):
        return failed("trust_report_missing", f"{rm.get('trust_report_path')} does not exist")
    if trust_report.get("parse_error"):
        return failed("recommendation_unparseable", trust_report["parse_error"])
    if trust_report.get("inconsistency"):
        return failed("recommendation_inconsistent", trust_report["inconsistency"])
    verdict.update(status="completed", outcome=trust_report["outcome"], decision=trust_report["decision"])
    verdict["anomalies"] = collect_anomalies(
        rm=rm, case=case, paths=paths, run_config=run_config,
        openant_head=openant_head, checkout=checkout,
    )
    return verdict


def derived_run_facts(rm: "dict | None", trust_report: "dict | None", outcome) -> dict:
    """Per-attempt facts read straight from the trace (no interpretation)."""
    rm = rm or {}
    stages = rm.get("checkpoint_stages") or []
    seen: set = set()
    retry_like = []
    for stage in stages:
        if stage and _RETRY_LIKE_RE.search(stage):
            retry_like.append(stage)
        elif stage in seen:
            retry_like.append(f"{stage} (repeat)")
        seen.add(stage)
    executions = rm.get("executions") or []
    skipped = [f"{e['canonical_stage']}: {e['outcome']}" for e in executions
               if (e.get("outcome") or "").startswith("skipped")]
    no_patch_reason = None
    if outcome == "GRAY":
        no_patch_reason = (trust_report or {}).get("applicability_skip_reason")
        if not no_patch_reason:
            unusual = [e for e in executions if e.get("outcome") and e["outcome"] not in _NORMAL_EXECUTION_OUTCOMES]
            if unusual:
                no_patch_reason = f"{unusual[0]['canonical_stage']}: {unusual[0]['outcome']}"
    return {
        "llm_calls": rm.get("llm_call_count"),
        "llm_call_stages": stages,
        "retry_like_llm_calls": retry_like,
        "skipped_stages": skipped,
        "no_patch_reason": no_patch_reason,
    }


# ---------------------------------------------------------------------------
# Session execution (checkout + run_traced, with bounded parallelism)
# ---------------------------------------------------------------------------

def _signal_group(proc: subprocess.Popen, sig) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def terminate_group(proc: subprocess.Popen, sig=signal.SIGTERM, grace: float = SHUTDOWN_GRACE_SECONDS) -> None:
    _signal_group(proc, sig)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        _signal_group(proc, signal.SIGKILL)
        proc.wait()


class Console:
    """Serialized, timestamped progress lines to stdout and logs/batch.log."""

    def __init__(self, log_path: "Path | None" = None, stream=None):
        self._lock = threading.Lock()
        self._stream = stream or sys.stdout
        self._log_path = log_path

    def line(self, text: str = "", stamp: bool = False) -> None:
        now = datetime.now()
        shown = f"[{now:%H:%M:%S}] {text}" if stamp else text
        with self._lock:
            try:
                print(shown, file=self._stream, flush=True)
            except UnicodeEncodeError:
                print(shown.encode("ascii", "backslashreplace").decode("ascii"), file=self._stream, flush=True)
            if self._log_path:
                # One short append per line: nothing is left open if the
                # runner dies, and every line is on disk immediately.
                with open(self._log_path, "a", encoding="utf-8") as log:
                    log.write(f"{iso(utc_now())} {text}\n")

    def close(self) -> None:
        self._log_path = None


class SessionContext:
    def __init__(self, *, layout, run_config, session_no, openant_head, openant_fingerprint,
                 console, case_timeout, scheduled_total, batch_dir):
        self.layout = layout
        self.run_config = run_config
        self.session_no = session_no
        self.openant_head = openant_head
        self.openant_fingerprint = openant_fingerprint
        self._openant_lock = threading.Lock()
        self.console = console
        self.case_timeout = case_timeout
        self.scheduled_total = scheduled_total
        self.batch_dir = batch_dir
        self.stop_event = threading.Event()
        # Re-entrant: the second-signal handler (kill_all) runs in the main
        # thread and may interrupt it while it already holds this lock.
        self.lock = threading.RLock()
        self._procs: dict = {}
        self.running: dict = {}  # case_id -> (monotonic start, attempt number)
        self.finished = 0
        self._kill_timer = None

    def spawn(self, key: str, argv: list, **kwargs) -> subprocess.Popen:
        with self.lock:
            if self.stop_event.is_set():
                raise _StopRequested()
            proc = subprocess.Popen(argv, start_new_session=True, **kwargs)
            self._procs[key] = proc
            return proc

    def release(self, key: str) -> None:
        with self.lock:
            self._procs.pop(key, None)

    def request_stop(self) -> None:
        self.stop_event.set()
        with self.lock:
            procs = list(self._procs.values())
        for proc in procs:
            _signal_group(proc, signal.SIGINT)
        if self._kill_timer is None:
            self._kill_timer = threading.Timer(SHUTDOWN_GRACE_SECONDS, self.kill_all)
            self._kill_timer.daemon = True
            self._kill_timer.start()

    def kill_all(self) -> None:
        with self.lock:
            procs = list(self._procs.values())
        for proc in procs:
            _signal_group(proc, signal.SIGKILL)

    def cancel_kill_timer(self) -> None:
        if self._kill_timer is not None:
            self._kill_timer.cancel()

    def openant_snapshot(self) -> dict:
        """Current OpenAnt work-tree identity (cheap: ~0.1 s). Compared with
        the session's recorded fingerprint to detect code edits mid-batch."""
        with self._openant_lock:
            try:
                state = collect_openant_state()
            except Exception as exc:  # observability only; never fails a case
                return {"error": f"{type(exc).__name__}: {exc}", "fingerprint": None, "at": iso(utc_now())}
        return {"head": state["head"], "dirty": state["dirty"], "fingerprint": state["fingerprint"],
                "at": iso(utc_now())}

    def mark_started(self, case: dict, attempt: int) -> None:
        with self.lock:
            self.running[case["id"]] = (time.monotonic(), attempt)
            running, done = len(self.running), self.finished
        self.console.line(
            f"START   {case['id']}  {case['cve']}  attempt {attempt}"
            f"   · running {running} · done {done}/{self.scheduled_total}",
            stamp=True,
        )

    def mark_finished(self, case: dict) -> int:
        with self.lock:
            self.running.pop(case["id"], None)
            self.finished += 1
            return self.finished


@dataclass
class _GitResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    stop_seen: bool = False  # batch stop already requested when git exited


def run_git(ctx: SessionContext, key: str, args: list, cwd, timeout: int) -> _GitResult:
    proc = ctx.spawn(
        key, ["git", *args], cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, env=_git_env(), text=True,
    )
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
            return _GitResult(proc.returncode, out, err, stop_seen=ctx.stop_event.is_set())
        except subprocess.TimeoutExpired:
            terminate_group(proc)
            out, err = proc.communicate()
            return _GitResult(proc.returncode if proc.returncode is not None else -1, out, err, True,
                              stop_seen=ctx.stop_event.is_set())
    finally:
        ctx.release(key)


def _git_failure(result: _GitResult) -> str:
    if result.timed_out:
        return "git timed out"
    return clip(result.stderr.strip() or result.stdout.strip() or f"git exited {result.returncode}", 300)


def prepare_checkout(ctx: SessionContext, case: dict, repo_dir: Path) -> dict:
    """Fresh clone at the exact manifest SHA, verified. Never reuses or
    deletes an existing directory."""
    started, t0 = utc_now(), time.monotonic()
    info = {
        "url": case["repo"], "expected_sha": case["sha"], "repo_dir": str(repo_dir),
        "observed_head": None, "verified_head": None, "origin_url": None, "clean": None,
        "fetched_revision": False, "failure_kind": None, "detail": None, "stop_requested": False,
        "started_at": iso(started), "finished_at": None, "duration_seconds": None,
    }
    last: list = []  # most recent git result, for the stop-state of a failing step

    def git(args, cwd=repo_dir, timeout=GIT_TIMEOUT) -> _GitResult:
        result = run_git(ctx, case["id"], args, cwd=cwd, timeout=timeout)
        last[:] = [result]
        return result

    def done(kind=None, detail=None) -> dict:
        info.update(failure_kind=kind, detail=detail, finished_at=iso(utc_now()),
                    duration_seconds=round(time.monotonic() - t0, 3),
                    stop_requested=bool(kind and last and last[0].stop_seen))
        return info

    sha = case["sha"]
    result = git(["clone", "--quiet", "--no-checkout", case["repo"], str(repo_dir)],
                 cwd=repo_dir.parent, timeout=GIT_CLONE_TIMEOUT)
    if result.returncode != 0:
        return done("clone_failed", _git_failure(result))

    def commit_present() -> bool:
        return git(["cat-file", "-e", f"{sha}^{{commit}}"]).returncode == 0

    if not commit_present():
        info["fetched_revision"] = True
        result = git(["fetch", "--quiet", "origin", sha], timeout=GIT_CLONE_TIMEOUT)
        if result.returncode != 0 or not commit_present():
            return done("revision_not_found", f"{sha} is not in the clone and could not be fetched: "
                        f"{_git_failure(result)}")
    result = git(["-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", sha])
    if result.returncode != 0:
        return done("checkout_failed", _git_failure(result))
    head = git(["rev-parse", "HEAD"]).stdout.strip()
    info["observed_head"] = head
    if head != sha:
        return done("sha_mismatch", f"HEAD is {head!r}, manifest SHA is {sha}")
    info["verified_head"] = head
    origin = git(["config", "--get", "remote.origin.url"]).stdout.strip()
    info["origin_url"] = origin
    if origin != case["repo"]:
        return done("origin_mismatch", f"origin is {origin!r}, manifest URL is {case['repo']!r}")
    status = git(["status", "--porcelain", "--untracked-files=all"])
    info["clean"] = status.returncode == 0 and not status.stdout.strip()
    if not info["clean"]:
        return done("dirty_checkout", "fresh checkout is not clean: " + "; ".join(status.stdout.splitlines()[:5]))
    return done()


def post_run_checkout_state(repo_dir: Path) -> dict:
    head = _git_text(["rev-parse", "HEAD"], cwd=repo_dir)
    try:
        status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo_dir,
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=GIT_TIMEOUT, env=_git_env())
        clean = status.returncode == 0 and not status.stdout.strip()
        lines = status.stdout.splitlines()[:10]
    except (OSError, subprocess.SubprocessError):
        clean, lines = None, []
    return {"post_run_head": head, "post_run_clean": clean, "post_run_status": lines}


def build_run_command(run_config: dict, case: dict, paths: dict) -> list:
    return [
        run_config["python"], run_config["run_traced"],
        "--cve", case["cve"],
        "--repo-root", str(paths["repo"]),
        "--output", str(paths["output"]),
        *run_config["run_traced_flags"],
    ]


def execute_run_traced(ctx: SessionContext, case: dict, argv: list, paths: dict) -> dict:
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"  # logs stay current; no behavioral effect
    started, t0 = utc_now(), time.monotonic()
    timed_out = False
    with open(paths["stdout"], "wb") as out, open(paths["stderr"], "wb") as err:
        proc = ctx.spawn(case["id"], argv, cwd=str(paths["cwd"]), stdout=out, stderr=err,
                         stdin=subprocess.DEVNULL, env=env)
        try:
            try:
                code = proc.wait(timeout=ctx.case_timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_group(proc)
                code = proc.returncode
            # Captured at exit: a run that ended on its own before any stop
            # request keeps its genuine classification.
            stop_seen = ctx.stop_event.is_set()
        finally:
            ctx.release(case["id"])
    return {
        "exit_code": code, "timed_out": timed_out, "timeout_seconds": ctx.case_timeout, "pid": proc.pid,
        "stop_requested": stop_seen,
        "started_at": iso(started), "finished_at": iso(utc_now()),
        "duration_seconds": round(time.monotonic() - t0, 3),
    }


def run_case_attempt(ctx: SessionContext, case: dict, attempt: int) -> dict:
    """One isolated attempt: fresh checkout + run_traced + classification.
    Always leaves a result.json; never raises."""
    attempt_dir = ctx.layout.attempt_dir(case["id"], attempt)
    paths = attempt_paths(attempt_dir)
    attempt_dir.mkdir(parents=True, exist_ok=False)  # unique by construction
    paths["cwd"].mkdir()
    started, t0 = utc_now(), time.monotonic()
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "case_id": case["id"], "cve": case["cve"], "repo": case["repo"], "sha": case["sha"],
        "attempt": attempt, "session": ctx.session_no,
        "status": "running", "failure_kind": None, "failure_detail": None,
        "outcome": None, "decision": None,
        "started_at": iso(started), "finished_at": None, "duration_seconds": None,
        "paths": {name: str(p) for name, p in paths.items()},
        "checkout": None, "command": None, "execution": None, "openant": None,
        "run_manifest": None, "trust_report": None, "usage": None,
        "llm_calls": None, "llm_call_stages": [], "retry_like_llm_calls": [],
        "skipped_stages": [], "no_patch_reason": None, "anomalies": [],
    }
    write_json_atomic(paths["result"], result)
    ctx.mark_started(case, attempt)
    checkout = execution = rm = trust_report = None
    stderr_text = ""
    stopped_before_spawn = False
    try:
        try:
            checkout = prepare_checkout(ctx, case, paths["repo"])
            result["checkout"] = checkout
            if not checkout["failure_kind"]:
                argv = build_run_command(ctx.run_config, case, paths)
                command = {
                    "argv": argv, "shell": shlex.join(argv), "cwd": str(paths["cwd"]),
                    "env": {"inherited": True, "overrides": {"PYTHONUNBUFFERED": "1"},
                            "recorded": recorded_environment()},
                    "timeout_seconds": ctx.case_timeout, "created_at": iso(utc_now()),
                }
                write_json_atomic(paths["command"], command)
                result["command"] = command
                result["openant"] = {"start": ctx.openant_snapshot()}
                execution = execute_run_traced(ctx, case, argv, paths)
                result["openant"]["end"] = ctx.openant_snapshot()
                result["execution"] = execution
                stderr_text = read_text_capped(paths["stderr"])
                rm = read_run_manifest(paths["trace"])
                if rm.get("trust_report_path"):
                    trust_report = parse_trust_report(Path(rm["trust_report_path"]))
                checkout.update(post_run_checkout_state(paths["repo"]))
        except _StopRequested:
            stopped_before_spawn = True
        if stopped_before_spawn:
            stop_requested = True
        elif execution is not None:
            stop_requested = bool(execution.get("stop_requested"))
        elif checkout is not None and checkout.get("failure_kind"):
            stop_requested = bool(checkout.get("stop_requested"))
        else:
            stop_requested = ctx.stop_event.is_set()
        verdict = classify_attempt(
            case=case, paths=paths, run_config=ctx.run_config, openant_head=ctx.openant_head,
            checkout=checkout, execution=execution, stop_requested=stop_requested,
            run_manifest=rm, trust_report=trust_report, stderr_text=stderr_text,
        )
        result.update(verdict)
        snapshots = result.get("openant") or {}
        changed = [label for label, snap in snapshots.items()
                   if snap and snap.get("fingerprint") and snap["fingerprint"] != ctx.openant_fingerprint]
        unreadable = [label for label, snap in snapshots.items() if snap and not snap.get("fingerprint")]
        result["openant_changed_during_attempt"] = bool(changed) if snapshots else None
        if changed:
            result["anomalies"].append(
                "OpenAnt work tree differed from the session's recorded state at attempt "
                f"{' and '.join(changed)} (this case may have run on other code)"
            )
        if unreadable:
            result["anomalies"].append(
                f"OpenAnt work-tree state could not be read at attempt {' and '.join(unreadable)}"
            )
        result["run_manifest"] = rm
        result["trust_report"] = trust_report
        result.update(derived_run_facts(rm, trust_report, verdict["outcome"]))
        usage = parse_trace_summary(stderr_text) if execution else None
        if usage and rm and rm.get("llm_call_count") is not None and usage["llm_calls"] != rm["llm_call_count"]:
            result["anomalies"].append(
                f"Trace Summary reports {usage['llm_calls']} LLM calls but the run manifest has "
                f"{rm['llm_call_count']}; token/cost figures ignored"
            )
            usage = None
        result["usage"] = usage
    except Exception as exc:  # a runner bug must never take down the batch
        try:
            paths["runner_error"].write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            pass
        result.update(status="failed", failure_kind="runner_exception",
                      failure_detail=clip(f"{type(exc).__name__}: {exc}"))
    finally:
        result["finished_at"] = iso(utc_now())
        result["duration_seconds"] = round(time.monotonic() - t0, 3)
        write_json_atomic(paths["result"], result)
    return result


# ---------------------------------------------------------------------------
# Batch state (validated from artifacts, never from directory existence)
# ---------------------------------------------------------------------------

def revalidate_completed(result: dict, case: dict, attempt_dir: Path, run_config: dict) -> "str | None":
    """Re-derive a recorded completion from the artifacts on disk. Returns a
    problem description, or None when the artifacts still prove the outcome."""
    paths = attempt_paths(attempt_dir)
    rm = read_run_manifest(paths["trace"])
    trust_report = parse_trust_report(Path(rm["trust_report_path"])) if rm.get("trust_report_path") else None
    verdict = classify_attempt(
        case=case, paths=paths, run_config=run_config, openant_head=None,
        checkout=result.get("checkout") or {"failure_kind": "runner_exception", "detail": "no checkout record"},
        execution=result.get("execution") or None,
        stop_requested=False, run_manifest=rm, trust_report=trust_report, stderr_text="",
    )
    if verdict["status"] != "completed":
        return f"{verdict['failure_kind']}: {verdict['failure_detail']}"
    if verdict["outcome"] != result.get("outcome"):
        return f"outcome on disk is {verdict['outcome']}, result.json says {result.get('outcome')}"
    if result.get("case_id") != case["id"] or result.get("sha") != case["sha"]:
        return "result.json belongs to a different case"
    return None


def load_case_state(layout: BatchLayout, case: dict, run_config: dict) -> dict:
    attempts = []
    for number, attempt_dir in layout.attempts(case["id"]):
        data, error = read_json(attempt_dir / "result.json")
        attempts.append({"attempt": number, "dir": attempt_dir,
                         "result": data if isinstance(data, dict) else None,
                         "error": error if error else (None if isinstance(data, dict) else "not an object")})
    state = {"case": case, "attempts": attempts, "category": INCOMPLETE, "status": "pending",
             "result": None, "note": "not run yet"}
    if not attempts:
        return state
    latest = attempts[-1]
    tag = f"attempt-{latest['attempt']:02d}"
    result = latest["result"]
    if result is None:
        state.update(status="incomplete", note=f"{tag} has no readable result.json ({latest['error']})")
        return state
    state["result"] = result
    status = result.get("status")
    if status == "completed":
        problem = revalidate_completed(result, case, latest["dir"], run_config)
        if problem:
            state.update(status="invalid", note=f"{tag} was recorded as completed but its artifacts no longer prove it: {problem}")
        elif result.get("outcome") not in OUTCOME_BY_KEY:
            state.update(status="invalid", note=f"{tag} has unknown outcome {result.get('outcome')!r}")
        else:
            state.update(status="completed", category=result["outcome"], note=None)
    elif status == "failed":
        state.update(status="failed", category=FAILED, note=None)
    elif status == "interrupted":
        state.update(status="interrupted", note=f"{tag} was interrupted")
    else:
        state.update(status="incomplete", note=f"{tag} did not finish (status {status!r}); the runner stopped or crashed")
    return state


def load_states(layout: BatchLayout, batch: dict) -> list:
    return [load_case_state(layout, case, batch["run_config"]) for case in batch["cases"]]


# ---------------------------------------------------------------------------
# Aggregation and reports
# ---------------------------------------------------------------------------

CSV_COLUMNS = (
    "order", "case_id", "cve", "display_name", "group", "language", "manifest", "repo", "sha",
    "category", "decision", "status", "failure_kind", "reason", "exit_code", "attempts",
    "started_at", "finished_at", "duration_seconds", "llm_calls", "retry_like_llm_calls",
    "skipped_stages", "tokens", "cost_usd", "provider", "model", "patcher_commit",
    "blind_rule_id", "blind_status", "anomalies", "attempt_dir", "trust_report",
    "run_manifest", "stderr_log",
)

DEFINITIONS = {
    "outcome_source": (
        "A case's outcome is the Trust Report decision card (its first level-2 heading, the "
        "anchor pipeline.py documents for tooling), cross-checked against the Recommendation "
        "section. It counts only if run_traced.py exited 0, its run manifest says 'success', "
        "the manifest identity matches the case attempt, and blind evaluation is verified."
    ),
    "gray_vs_failed": (
        "GRAY (No Patch Produced) is a legitimate Auto Patcher outcome. FAILED means no valid "
        "Auto Patcher outcome exists for the case (checkout, run_traced, manifest or report failure)."
    ),
    "denominator_all": "A: every case requested in this batch (GREEN+YELLOW+ORANGE+RED+GRAY+FAILED+INCOMPLETE).",
    "denominator_completed": (
        "B: only cases with a valid Auto Patcher outcome (GREEN+YELLOW+ORANGE+RED+GRAY); "
        "infrastructure failures and incomplete cases are excluded so they cannot distort "
        "recommendation percentages."
    ),
    "patch_producing": "Completed cases whose final candidate patch exists: GREEN, YELLOW, ORANGE, RED.",
    "retry_like_llm_calls": (
        "From checkpoints.jsonl stage tags: tags ending in _retry/_reattempt/_revision/"
        "_reverification/_regeneration, plus repeats of an earlier tag. Planning re-attempts "
        "are designed evidence-acquisition rounds, not errors."
    ),
    "usage": (
        "Tokens/cost come from run_traced.py's Trace Summary on stderr (OpenAnt's TokenTracker), "
        "only for successful runs whose printed LLM-call count matches the run manifest; cost is "
        "rounded to cents per case. Failed runs report no usage."
    ),
    "durations": (
        "Case duration = checkout + run_traced, final attempt. Wall clock = sum of the batch "
        "sessions' elapsed time."
    ),
}


def _blank_counts() -> dict:
    return {category: 0 for category in CATEGORIES}


def _sum_or_none(values):
    present = [v for v in values if v is not None]
    return sum(present) if present else None


def case_row(layout: BatchLayout, state: dict) -> dict:
    case = state["case"]
    result = state["result"] or {}
    category = state["category"]
    rm = result.get("run_manifest") or {}
    blind = rm.get("blind") or {}
    usage = result.get("usage") or {}
    latest_dir = state["attempts"][-1]["dir"] if state["attempts"] else None
    paths = attempt_paths(latest_dir) if latest_dir else None

    def existing(path):
        return rel_to(path, layout.dir) if path and Path(path).exists() else None

    if category == FAILED:
        reason = result.get("failure_detail")
    elif category == "GRAY":
        reason = result.get("no_patch_reason")
    elif category == INCOMPLETE:
        reason = state.get("note")
    else:
        reason = None
    completed = category in OUTCOME_BY_KEY
    return {
        "order": case["order"],
        "case_id": case["id"],
        "cve": case["cve"],
        "display_name": case.get("display_name") or case["repo_identity"].split("/", 1)[-1],
        "group": case.get("group"),
        "language": case.get("language"),
        "manifest": case["source"]["manifest"],
        "repo": case["repo"],
        "sha": case["sha"],
        "category": category,
        "decision": result.get("decision") if completed else None,
        "status": state["status"],
        "failure_kind": result.get("failure_kind") if category == FAILED else None,
        "reason": reason,
        "exit_code": (result.get("execution") or {}).get("exit_code"),
        "attempts": len(state["attempts"]),
        "started_at": result.get("started_at"),
        "finished_at": result.get("finished_at"),
        "duration_seconds": result.get("duration_seconds"),
        "llm_calls": result.get("llm_calls"),
        "retry_like_llm_calls": result.get("retry_like_llm_calls") or [],
        "skipped_stages": result.get("skipped_stages") or [],
        "tokens": usage.get("tokens"),
        "cost_usd": usage.get("cost_usd"),
        "provider": rm.get("provider"),
        "model": rm.get("model"),
        "patcher_commit": rm.get("patcher_commit"),
        "blind_rule_id": blind.get("rule_id"),
        "blind_status": blind.get("status"),
        "anomalies": result.get("anomalies") or [],
        "openant_changed_during_attempt": result.get("openant_changed_during_attempt"),
        "attempt_dir": rel_to(latest_dir, layout.dir) if latest_dir else None,
        "trust_report": existing(rm.get("trust_report_path")),
        "run_manifest": existing(paths["trace"] / "run_manifest.json") if paths else None,
        "stderr_log": existing(paths["stderr"]) if paths else None,
        "all_attempts": [
            {
                "attempt": a["attempt"],
                "status": (a["result"] or {}).get("status"),
                "failure_kind": (a["result"] or {}).get("failure_kind"),
                "outcome": (a["result"] or {}).get("outcome"),
                "duration_seconds": (a["result"] or {}).get("duration_seconds"),
                "llm_calls": (a["result"] or {}).get("llm_calls"),
                "dir": rel_to(a["dir"], layout.dir),
            }
            for a in state["attempts"]
        ],
    }


def _breakdown(rows: list, key: str) -> list:
    groups: dict = {}
    for row in rows:
        groups.setdefault(row.get(key) or "(none)", []).append(row)
    out = []
    for value, members in groups.items():
        counts = _blank_counts()
        for row in members:
            counts[row["category"]] += 1
        out.append({"value": value, "total": len(members), "counts": counts})
    return out


def _session_seconds(session: dict, now: datetime) -> "float | None":
    start = parse_iso(session.get("started_at"))
    end = parse_iso(session.get("finished_at")) or (now if session.get("in_progress") else None)
    return (end - start).total_seconds() if start and end else None


def build_summary(layout: BatchLayout, batch: dict, states: list, *, interrupted: bool = False,
                  running: bool = False) -> dict:
    now = utc_now()
    rows = [case_row(layout, s) for s in states]
    counts = _blank_counts()
    for row in rows:
        counts[row["category"]] += 1
    total = len(rows)
    completed = sum(counts[o.key] for o in OUTCOMES)
    if interrupted:
        status = "INTERRUPTED"
    elif running and counts[INCOMPLETE]:
        status = "RUNNING"  # regenerated mid-session; never a final status
    elif counts[INCOMPLETE]:
        status = "INCOMPLETE"
    elif counts[FAILED]:
        status = "COMPLETE_WITH_FAILURES"
    else:
        status = "COMPLETE"

    def dist(keys, denominator):
        return [{"category": k, "label": CATEGORY_LABELS[k], "count": counts[k],
                 "percent": percent(counts[k], denominator)} for k in keys]

    final_durations = [r["duration_seconds"] for r in rows if r["duration_seconds"] is not None]
    all_attempt_durations = [a["duration_seconds"] for r in rows for a in r["all_attempts"]
                             if a["duration_seconds"] is not None]
    llm_rows = [r for r in rows if r["llm_calls"] is not None]
    completed_llm = [r["llm_calls"] for r in rows if r["category"] in OUTCOME_BY_KEY and r["llm_calls"] is not None]
    usage_rows = [r for r in rows if r["tokens"] is not None or r["cost_usd"] is not None]
    sessions = batch.get("sessions") or []
    session_seconds = [s for s in (_session_seconds(x, now) for x in sessions) if s is not None]
    wall = sum(session_seconds) if session_seconds else None
    case_seconds = sum(final_durations) if final_durations else None
    failures: dict = {}
    for row in rows:
        if row["category"] == FAILED:
            entry = failures.setdefault(row["failure_kind"], {
                "description": FAILURE_KINDS.get(row["failure_kind"], ""), "cases": []})
            entry["cases"].append(row["case_id"])
    retry_counter = Counter(tag for r in rows for tag in r["retry_like_llm_calls"])
    first = sessions[0] if sessions else {}
    openant_first = first.get("openant") or {}
    openant_sessions = []
    for s in sessions:
        start, end = s.get("openant") or {}, s.get("openant_end") or {}
        openant_sessions.append({
            "session": s.get("session"),
            "start_head": start.get("head"), "start_dirty": start.get("dirty"),
            "start_fingerprint": start.get("fingerprint"),
            "end_head": end.get("head"), "end_dirty": end.get("dirty"),
            "changed_during_session": end.get("changed_during_session"),
        })
    start_fingerprints = {o["start_fingerprint"] for o in openant_sessions if o["start_fingerprint"]}
    changed_cases = sorted(r["case_id"] for r in rows if r["openant_changed_during_attempt"])
    openant_changed = (len(start_fingerprints) > 1 or bool(changed_cases)
                       or any(o["changed_during_session"] for o in openant_sessions))
    blind_rows = [r for r in rows if r["blind_status"] is not None]
    run_config = batch["run_config"]
    return {
        "schema_version": BATCH_SCHEMA_VERSION,
        "kind": "openant_cve_batch_summary",
        "generated_at": iso(now),
        "batch_id": batch["batch_id"],
        "label": batch.get("label"),
        "batch_dir": str(layout.dir),
        "status": status,
        "runner": batch["runner"],
        "created_at": batch["created_at"],
        "inputs": batch["inputs"],
        "run_config": run_config,
        "openant": {
            "commit": openant_first.get("head"),
            "dirty": openant_first.get("dirty"),
            "dirty_paths": len(openant_first.get("status_porcelain") or []),
            "sessions": openant_sessions,
            "changed_during_batch": openant_changed,
            "cases_run_on_changed_code": changed_cases,
            "run_patcher_commits": dict(Counter(r["patcher_commit"] for r in rows if r["patcher_commit"])),
        },
        "sessions": [
            {k: s.get(k) for k in ("session", "kind", "started_at", "finished_at", "jobs",
                                   "jobs_validated", "case_timeout_seconds", "result", "exit_code",
                                   "scheduled_cases", "rerun_failed")}
            for s in sessions
        ],
        "counts": {
            "requested": total,
            "completed": completed,
            "failed": counts[FAILED],
            "incomplete": counts[INCOMPLETE],
            "patch_producing": sum(counts[o.key] for o in OUTCOMES if o.patch_produced),
            "no_patch": counts["GRAY"],
            "by_category": counts,
        },
        "distribution": {
            "all_requested": {"denominator": total, "definition": DEFINITIONS["denominator_all"],
                              "rows": dist(CATEGORIES, total)},
            "completed_executions": {"denominator": completed, "definition": DEFINITIONS["denominator_completed"],
                                     "rows": dist([o.key for o in OUTCOMES], completed)},
        },
        "failures_by_kind": failures,
        "timing": {
            "wall_clock_seconds": wall,
            "sum_case_seconds_final_attempts": case_seconds,
            "sum_case_seconds_all_attempts": sum(all_attempt_durations) if all_attempt_durations else None,
            "parallel_speedup": round(case_seconds / wall, 2) if wall and case_seconds else None,
            "first_session_started_at": first.get("started_at"),
            "last_session_finished_at": sessions[-1].get("finished_at") if sessions else None,
        },
        "llm": {
            "total_calls_final_attempts": sum(r["llm_calls"] for r in llm_rows) if llm_rows else None,
            "total_calls_all_attempts": _sum_or_none(a["llm_calls"] for r in rows for a in r["all_attempts"]),
            "cases_with_call_count": len(llm_rows),
            "mean_calls_per_completed_case": round(sum(completed_llm) / len(completed_llm), 2) if completed_llm else None,
            "providers_models": [
                {"provider": p, "model": m, "cases": n}
                for (p, m), n in sorted(Counter((r["provider"], r["model"]) for r in rows if r["provider"]).items(),
                                        key=lambda kv: (-kv[1], str(kv[0])))
            ],
            "cases_with_retry_like_calls": sum(1 for r in rows if r["retry_like_llm_calls"]),
            "retry_like_calls_by_tag": dict(sorted(retry_counter.items())),
        },
        "usage": {
            "cases_with_usage": len(usage_rows),
            "total_tokens": sum(r["tokens"] for r in usage_rows if r["tokens"] is not None) if usage_rows else None,
            "total_cost_usd": round(sum(r["cost_usd"] for r in usage_rows if r["cost_usd"] is not None), 2) if usage_rows else None,
            "source": "run_traced.py Trace Summary (stderr); cost rounded to cents per case",
        },
        "blind_evaluation": {
            "policy": run_config["blind_filter_policy"],
            "expected_rule_id": run_config["expected_blind_rule_id"],
            "same_repo_github_stripping": run_config["same_repo_github_stripping"],
            "cases_with_manifest_block": len(blind_rows),
            "verified": sum(1 for r in blind_rows if r["blind_status"] == "verified"),
            "not_verified_cases": [r["case_id"] for r in blind_rows if r["blind_status"] != "verified"],
        },
        "anomalies": [{"case_id": r["case_id"], "anomaly": a} for r in rows for a in r["anomalies"]],
        "breakdown": {
            "by_manifest": _breakdown(rows, "manifest") if len(batch["inputs"]) > 1 else [],
            "by_group": _breakdown(rows, "group") if any(r["group"] for r in rows) else [],
        },
        "definitions": DEFINITIONS,
        "cases": rows,
    }


def _md(text) -> str:
    if text is None or text == "":
        return "—"
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(summary: dict) -> str:
    rc = summary["run_config"]
    counts = summary["counts"]
    timing = summary["timing"]
    llm = summary["llm"]
    usage = summary["usage"]
    blind = summary["blind_evaluation"]
    oa = summary["openant"]
    out = [f"# Auto Patcher real-CVE batch `{summary['batch_id']}`", ""]
    out.append(f"**Status: {summary['status'].replace('_', ' ')}** · generated {summary['generated_at']}")
    out += ["", "## Batch metadata", "", "| Field | Value |", "|---|---|"]
    meta = [
        ("Batch ID", f"`{summary['batch_id']}`"),
        ("Label", summary.get("label")),
        ("Batch directory", f"`{summary['batch_dir']}`"),
        ("Created", summary["created_at"]),
        ("Runner", f"{summary['runner']['name']} {summary['runner']['version']} (batch schema {summary['schema_version']})"),
    ]
    for inp in summary["inputs"]:
        meta.append(("Manifest", f"`{inp['path']}` — {inp['case_count']} case(s), sha256 `{inp['sha256'][:16]}…`, copy `{inp['copy']}`"))
    openant_by_session = {o["session"]: o for o in oa["sessions"]}
    for s in summary["sessions"]:
        jobs = f"jobs {s.get('jobs')}" + ("" if s.get("jobs_validated", True) else f" (above the validated maximum of {VALIDATED_MAX_JOBS})")
        timeout = fmt_duration(s["case_timeout_seconds"]) if s.get("case_timeout_seconds") else "none"
        o = openant_by_session.get(s["session"], {})
        code = (f"OpenAnt `{(o.get('start_head') or '?')[:12]}`{' dirty' if o.get('start_dirty') else ''}"
                + (" → **changed during session**" if o.get("changed_during_session") else ""))
        meta.append((f"Session {s['session']}", f"{s['kind']} · {s.get('started_at')} → {s.get('finished_at') or 'in progress'} · "
                     f"{jobs} · timeout {timeout} · {code} · {s.get('result') or 'running'}"))
    dirty = "clean" if oa["dirty"] is False else (f"**DIRTY** ({oa['dirty_paths']} path(s); see batch_manifest.json)" if oa["dirty"] else "unknown")
    meta += [
        ("OpenAnt commit", f"`{oa['commit']}`"),
        ("OpenAnt work tree", dirty),
        ("OpenAnt code changed during batch", (
            "**YES** — session start states differ and/or the work tree changed during a session; cases "
            f"with a change observed around their run: {', '.join(oa['cases_run_on_changed_code']) or 'none'}"
            if oa["changed_during_batch"] else "no")),
        ("Run patcher commits", ", ".join(f"`{k[:12]}` ×{v}" for k, v in oa["run_patcher_commits"].items()) or "—"),
        ("Python (run_traced)", f"{rc['python_version']} `{rc['python']}`"),
        ("run_traced.py", f"`{rc['run_traced']}`"),
        ("run_traced flags", "`" + " ".join(rc["run_traced_flags"]) + "`"),
        ("Context budget", f"policy `{rc['context_budget_policy']}`, max windows `{rc['max_context_budget_windows']}` (deprecated no-ops in run_traced.py, preserved)"),
        ("Blind evaluation", f"`{blind['expected_rule_id']}` + same-repo GitHub stripping · verified in {blind['verified']}/{blind['cases_with_manifest_block']} case(s) with a run manifest"),
        ("LLM provider / model", ", ".join(f"{p['provider']} / {p['model']} ({p['cases']})" for p in llm["providers_models"]) or "—"),
    ]
    out += [f"| {k} | {_md(v)} |" for k, v in meta]

    out += ["", "## Overall statistics", "", "| Metric | Value |", "|---|---|"]
    mean = llm["mean_calls_per_completed_case"]
    stats = [
        ("Requested cases", counts["requested"]),
        ("Completed Auto Patcher executions", counts["completed"]),
        ("Failed (infrastructure/execution)", counts["failed"]),
        ("Incomplete (not run yet / interrupted)", counts["incomplete"]),
        ("Patch-producing cases", counts["patch_producing"]),
        ("No-patch cases (Gray)", counts["no_patch"]),
        ("Wall-clock duration (sum of sessions)", fmt_duration(timing["wall_clock_seconds"])),
        ("Sum of per-case durations (final attempts)", fmt_duration(timing["sum_case_seconds_final_attempts"])),
        ("Sum of per-case durations (all attempts)", fmt_duration(timing["sum_case_seconds_all_attempts"])),
        ("Effective parallel speedup", f"{timing['parallel_speedup']}×" if timing["parallel_speedup"] else "—"),
        ("Total LLM calls (final attempts)", llm["total_calls_final_attempts"]),
        ("Total LLM calls (all attempts)", llm["total_calls_all_attempts"]),
        ("Mean LLM calls per completed case", mean),
        ("Cases with retry-like LLM calls", llm["cases_with_retry_like_calls"]),
        ("Tokens (cases with usage)", f"{usage['total_tokens']:,} ({usage['cases_with_usage']} case(s))" if usage["total_tokens"] is not None else "—"),
        ("Cost USD (cases with usage)", f"${usage['total_cost_usd']:.2f} ({usage['cases_with_usage']} case(s), rounded per case)" if usage["total_cost_usd"] is not None else "—"),
    ]
    out += [f"| {k} | {_md(v)} |" for k, v in stats]

    out += ["", "## Recommendation distribution", ""]
    for key, title in (("all_requested", "A. All requested cases"), ("completed_executions", "B. Completed Auto Patcher executions only")):
        d = summary["distribution"][key]
        out += [f"### {title} (denominator = {d['denominator']})", "", f"_{d['definition']}_", "",
                "| Outcome | Count | % |", "|---|---:|---:|"]
        out += [f"| {r['label']} | {r['count']} | {fmt_percent(r['percent'])} |" for r in d["rows"]]
        out += [f"| **Total** | **{d['denominator']}** | {'100.0%' if d['denominator'] else 'n/a'} |", ""]

    if summary["failures_by_kind"]:
        out += ["### Failures by kind", "", "| Kind | Count | Meaning | Cases |", "|---|---:|---|---|"]
        for kind, entry in sorted(summary["failures_by_kind"].items()):
            out.append(f"| `{kind}` | {len(entry['cases'])} | {_md(entry['description'])} | {_md(', '.join(entry['cases']))} |")
        out.append("")

    for key, title in (("by_manifest", "Breakdown by manifest"), ("by_group", "Breakdown by group")):
        items = summary["breakdown"][key]
        if items:
            out += [f"## {title}", "", "| Value | Total | " + " | ".join(CATEGORIES) + " |",
                    "|---|---:|" + "---:|" * len(CATEGORIES)]
            for item in items:
                out.append(f"| {_md(item['value'])} | {item['total']} | " + " | ".join(str(item["counts"][c]) for c in CATEGORIES) + " |")
            out.append("")

    out += ["## Cases", "", "| # | Case | CVE | Project | Repository | Target SHA | Outcome | Duration | LLM calls | Reason / notes | Artifacts |",
            "|---:|---|---|---|---|---|---|---:|---:|---|---|"]
    for r in summary["cases"]:
        outcome = OUTCOME_BY_KEY.get(r["category"])
        shown = f"{outcome.emoji} {r['decision']}" if outcome else ("✖ FAILED" + (f" (`{r['failure_kind']}`)" if r["failure_kind"] else "") if r["category"] == FAILED else "… INCOMPLETE")
        notes = r["reason"] or ""
        if r["attempts"] > 1:
            notes = (notes + " · " if notes else "") + f"{r['attempts']} attempts"
        if r["anomalies"]:
            notes = (notes + " · " if notes else "") + f"⚠ {len(r['anomalies'])} anomaly(ies)"
        out.append(
            f"| {r['order']} | `{r['case_id']}` | {r['cve']} | {_md(r['display_name'])} | {_md(r['repo'])} | "
            f"`{r['sha']}` | {shown} | {fmt_duration(r['duration_seconds'])} | {_md(r['llm_calls'])} | "
            f"{_md(clip(notes, 220))} | {('`' + r['attempt_dir'] + '/`') if r['attempt_dir'] else '—'} |"
        )
    out.append("")

    failed_rows = [r for r in summary["cases"] if r["category"] == FAILED]
    if failed_rows:
        out += ["## Failure details", ""]
        for r in failed_rows:
            out.append(f"- **`{r['case_id']}`** — `{r['failure_kind']}`: {_md(r['reason'])}"
                       + (f" (stderr: `{r['stderr_log']}`)" if r["stderr_log"] else ""))
        out.append("")
    if summary["anomalies"]:
        out += ["## Anomalies / warnings", ""]
        out += [f"- `{a['case_id']}`: {_md(a['anomaly'])}" for a in summary["anomalies"]]
        out.append("")
    if llm["retry_like_calls_by_tag"]:
        out += ["## Retry-like LLM calls", "", "| Stage tag | Calls |", "|---|---:|"]
        out += [f"| `{tag}` | {n} |" for tag, n in llm["retry_like_calls_by_tag"].items()]
        out.append("")
    out += ["## Definitions", ""]
    out += [f"- **{k.replace('_', ' ')}** — {v}" for k, v in summary["definitions"].items()]
    out += ["", "Exit codes: 0 every case has a valid outcome · 1 at least one case FAILED · 2 invalid input "
            "(nothing run) · 3 batch incomplete · 4 results ZIP not created · 130 interrupted.", ""]
    return "\n".join(out)


def render_csv(summary: dict) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(CSV_COLUMNS), extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in summary["cases"]:
        flat = dict(row)
        for key in ("retry_like_llm_calls", "skipped_stages", "anomalies"):
            flat[key] = "; ".join(row[key])
        writer.writerow({k: ("" if flat.get(k) is None else flat.get(k)) for k in CSV_COLUMNS})
    return buf.getvalue()


def write_summaries(layout: BatchLayout, batch: dict, *, interrupted: bool = False,
                    running: bool = False) -> dict:
    states = load_states(layout, batch)
    summary = build_summary(layout, batch, states, interrupted=interrupted, running=running)
    write_json_atomic(layout.summary_json, summary)
    write_text_atomic(layout.summary_md, render_markdown(summary))
    write_text_atomic(layout.results_csv, render_csv(summary))
    return summary


# ---------------------------------------------------------------------------
# ZIP packaging
# ---------------------------------------------------------------------------

_EXCLUDED_DIR_NAMES = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", ".venv"})
_EXCLUDED_FILE_RE = re.compile(
    r"(?:\.pyc|\.pyo|\.pem|\.key|\.p12|\.pfx)$|^(?:\.DS_Store|\.env(?:\..*)?|\.netrc|\.git-credentials|"
    r"\.npmrc|\.pypirc|id_rsa.*|id_ed25519.*|id_ecdsa.*|\.batch\.lock)$"
)


def _contains_secret(path: Path, secret_values: list) -> bool:
    if not secret_values:
        return False
    overlap = max(len(s) for s in secret_values)
    tail = b""
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            window = tail + chunk
            if any(s in window for s in secret_values):
                return True
            tail = window[-overlap:]
    return False


def build_zip(layout: BatchLayout, batch_id: str, *, include_investigation: bool = False,
              secret_values=None) -> dict:
    """Package the batch's useful artifacts into <batch>/<batch-id>-results.zip
    (entries under <batch-id>/). Excludes target checkouts (reconstructible
    from repo URL + exact SHA in case.json/result.json), VCS/cache/bytecode,
    credential-like files, symlinks, and -- unless include_investigation --
    the large derived parser outputs under output/patch/*-investigation/.
    The uncompressed batch directory is never modified."""
    secret_values = list(secret_values or [])
    target = layout.zip_path(batch_id)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    included: list = []
    excluded: dict = {}
    excluded_investigation: list = []
    warnings: list = []

    def exclude(reason: str, path: Path, size: int = 0) -> None:
        entry = excluded.setdefault(reason, {"files": 0, "bytes": 0})
        entry["files"] += 1
        entry["bytes"] += size

    for root, dirs, files in os.walk(layout.dir, followlinks=False):
        root_path = Path(root)
        rel_root = root_path.relative_to(layout.dir)
        kept_dirs = []
        for name in sorted(dirs):
            path = root_path / name
            parts = (rel_root / name).parts
            if path.is_symlink():
                exclude("symlink", path)
            elif name in _EXCLUDED_DIR_NAMES:
                exclude(f"excluded directory {name}/", path)
            elif len(parts) == 4 and parts[0] == "cases" and _ATTEMPT_DIR_RE.match(parts[2]) and name == "repo":
                exclude("target checkout (reconstructible from repo URL + SHA)", path)
            elif (not include_investigation and name.endswith("-investigation")
                  and len(parts) >= 2 and parts[-2] == "patch"):
                for sub_root, _sub_dirs, sub_files in os.walk(path, followlinks=False):
                    for sub in sorted(sub_files):
                        sub_path = Path(sub_root) / sub
                        try:
                            size = sub_path.lstat().st_size
                        except OSError:
                            size = 0
                        excluded_investigation.append({"path": str(sub_path.relative_to(layout.dir)), "bytes": size})
                        exclude("investigation output (use --zip-include-investigation)", sub_path, size)
            else:
                kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(files):
            path = root_path / name
            rel = path.relative_to(layout.dir)
            try:
                size = path.lstat().st_size
            except OSError:
                continue
            if path.is_symlink():
                exclude("symlink", path, 0)
            elif rel.parts == (target.name,) or name.endswith(".tmp") or name.endswith("-results.zip"):
                exclude("zip / temporary file", path, size)
            elif _EXCLUDED_FILE_RE.search(name):
                exclude("credential-like / cache file name", path, size)
            elif _contains_secret(path, secret_values):
                exclude("contains a credential value", path, size)
                warnings.append(f"excluded {rel}: it contains a credential value from the environment or OpenAnt config")
            else:
                included.append((path, rel, size))

    contents = {
        "batch_id": batch_id,
        "created_at": iso(utc_now()),
        "included_files": len(included),
        "included_bytes": sum(size for _p, _r, size in included),
        "excluded": excluded,
        "excluded_investigation_files": excluded_investigation,
        "include_investigation": include_investigation,
        "warnings": warnings,
        "note": "Target checkouts are not packaged; each case's repo URL and exact SHA are in "
                "cases/<id>/case.json and every attempt's result.json.",
    }
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for path, rel, _size in included:
                zf.write(path, f"{batch_id}/{rel.as_posix()}")
            zf.writestr(f"{batch_id}/zip_contents.json", json.dumps(contents, indent=2) + "\n")
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink()
    return {
        "path": str(target),
        "size_bytes": target.stat().st_size,
        "file_count": len(included) + 1,
        "excluded": excluded,
        "warnings": warnings,
        "include_investigation": include_investigation,
        "created_at": contents["created_at"],
    }


# ---------------------------------------------------------------------------
# Terminal rendering
# ---------------------------------------------------------------------------

def _result_line(case: dict, result: dict, finished: int, total: int, layout: BatchLayout) -> str:
    progress = f"· done {finished}/{total}"
    duration = fmt_duration(result.get("duration_seconds"))
    checkout = (result.get("checkout") or {}).get("duration_seconds")
    timing = f"{duration}" + (f" (checkout {fmt_duration(checkout)})" if checkout is not None else "")
    status = result.get("status")
    if status == "completed":
        outcome = OUTCOME_BY_KEY[result["outcome"]]
        extra = f"  llm {result.get('llm_calls')}" if result.get("llm_calls") is not None else ""
        warn = f"  ⚠ {len(result['anomalies'])} anomaly(ies)" if result.get("anomalies") else ""
        return f"DONE    {case['id']}  {outcome.emoji} {outcome.key} {outcome.decision}  {timing}{extra}{warn}   {progress}"
    if status == "interrupted":
        return f"STOPPED {case['id']}  interrupted  {timing}   {progress}"
    stderr_path = (result.get("paths") or {}).get("stderr")
    stderr = rel_to(stderr_path, layout.dir) if stderr_path and Path(stderr_path).is_file() else None
    return (f"FAILED  {case['id']}  {result.get('failure_kind')}: {clip(result.get('failure_detail'), 140)}"
            f"  {timing}   {progress}" + (f"  → {stderr}" if stderr else ""))


def render_terminal_summary(summary: dict, zip_info: "dict | None", layout: BatchLayout, resume_hint: str) -> list:
    counts = summary["counts"]
    lines = ["─" * 78, f"Batch {summary['batch_id']}   {summary['status'].replace('_', ' ')}",
             f"Requested {counts['requested']} · completed {counts['completed']} · failed {counts['failed']}"
             f" · incomplete {counts['incomplete']} · patch-producing {counts['patch_producing']}"
             f" · no-patch {counts['no_patch']}", ""]
    a = summary["distribution"]["all_requested"]
    b = summary["distribution"]["completed_executions"]
    b_rows = {r["category"]: r for r in b["rows"]}
    lines.append(f"{'Outcome':<46}{'All requested (n=' + str(a['denominator']) + ')':>22}{'Completed only (n=' + str(b['denominator']) + ')':>26}")
    for r in a["rows"]:
        b_row = b_rows.get(r["category"])
        b_text = f"{b_row['count']} ({fmt_percent(b_row['percent'])})" if b_row else "—"
        lines.append(f"{r['label']:<46}{str(r['count']) + ' (' + fmt_percent(r['percent']) + ')':>22}{b_text:>26}")
    if summary["failures_by_kind"]:
        lines.append("")
        lines.append("Failures:")
        for kind, entry in sorted(summary["failures_by_kind"].items()):
            lines.append(f"  {kind} ×{len(entry['cases'])}: {', '.join(entry['cases'])}")
    if summary["anomalies"]:
        lines.append(f"Anomalies: {len(summary['anomalies'])} (see batch_summary.md)")
    if summary["openant"]["changed_during_batch"]:
        lines.append("⚠ OpenAnt code changed during the batch — results may mix code versions (see batch_summary.md)")
    timing, llm = summary["timing"], summary["llm"]
    lines += ["", f"Wall clock {fmt_duration(timing['wall_clock_seconds'])} · case time "
              f"{fmt_duration(timing['sum_case_seconds_final_attempts'])} · LLM calls "
              f"{llm['total_calls_final_attempts'] if llm['total_calls_final_attempts'] is not None else '—'}"]
    lines.append(f"{'Summary':<13}{layout.summary_md}")
    lines.append(f"{'JSON/CSV':<13}{layout.summary_json.name}, {layout.results_csv.name}")
    if zip_info:
        lines.append(f"{'ZIP':<13}{zip_info['path']} ({fmt_bytes(zip_info['size_bytes'])}, {zip_info['file_count']} files)")
        for warning in zip_info.get("warnings") or []:
            lines.append(f"  ⚠ {warning}")
    if resume_hint:
        label = "Resume" if counts["incomplete"] else "Rerun failed"
        lines.append(f"{label:<13}{resume_hint}")
        if not counts["incomplete"] and set(summary["failures_by_kind"]) <= {"blind_evaluation_aborted"}:
            lines.append(f"{'':<13}(blind_evaluation_aborted is deterministic: a rerun fails the same way)")
    lines.append("─" * 78)
    return lines


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _install_signal_handlers(state: dict):
    if threading.current_thread() is not threading.main_thread():
        return None

    def handler(signum, _frame):
        state["signals"] += 1
        ctx = state.get("ctx")
        if state["signals"] == 1:
            if ctx is not None:
                # Before anything else: no new subprocess may start, and every
                # attempt ending from here on is classified as interrupted.
                ctx.stop_event.set()
            raise BatchInterrupted(signal.Signals(signum).name)
        if ctx is not None:
            ctx.kill_all()

    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        # Respect a signal the parent chose to ignore (e.g. SIGHUP under
        # nohup): a protected long batch must not die when the terminal closes.
        if signal.getsignal(sig) is signal.SIG_IGN:
            continue
        previous[sig] = signal.signal(sig, handler)
    return previous


def _restore_signal_handlers(previous) -> None:
    for sig, old in (previous or {}).items():
        signal.signal(sig, old)


def _resume_hint(layout: BatchLayout, summary: dict) -> str:
    base = f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} --resume {shlex.quote(str(layout.dir))}"
    if summary["counts"]["incomplete"]:
        return base
    if summary["counts"]["failed"]:
        return base + " --rerun-failed"
    return ""


def _exit_code_for(summary: dict) -> int:
    return {
        "COMPLETE": EXIT_COMPLETE, "COMPLETE_WITH_FAILURES": EXIT_CASE_FAILURES,
        "INCOMPLETE": EXIT_INCOMPLETE, "RUNNING": EXIT_INCOMPLETE, "INTERRUPTED": EXIT_INTERRUPTED,
    }[summary["status"]]


def _save_openant_state(layout: BatchLayout, state: dict, session_no: int) -> dict:
    diff = state.pop("_diff", b"")
    if diff:
        layout.provenance_dir.mkdir(exist_ok=True)
        target = layout.provenance_dir / f"openant_worktree-session-{session_no:02d}.diff"
        target.write_bytes(diff)
        state["tracked_diff_file"] = rel_to(target, layout.dir)
    return state


def _openant_end_state(layout: BatchLayout, start: dict, session_no: int) -> dict:
    """OpenAnt work-tree state when the session ends, compared with its start."""
    try:
        end = collect_openant_state()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "changed_during_session": None}
    diff = end.pop("_diff", b"")
    changed = end["fingerprint"] != start.get("fingerprint")
    record = {
        "head": end["head"], "dirty": end["dirty"], "fingerprint": end["fingerprint"],
        "status_porcelain": end["status_porcelain"], "changed_during_session": changed,
    }
    if changed and diff:
        layout.provenance_dir.mkdir(exist_ok=True)
        target = layout.provenance_dir / f"openant_worktree-session-{session_no:02d}-end.diff"
        target.write_bytes(diff)
        record["tracked_diff_file"] = rel_to(target, layout.dir)
    return record


def run_session(*, layout: BatchLayout, batch: dict, schedule: list, kind: str, jobs: int,
                openant: dict, case_timeout, heartbeat: int, rerun_failed: bool,
                make_zip: bool, include_investigation: bool, argv: list) -> int:
    session_no = len(batch["sessions"]) + 1
    session = {
        "session": session_no, "kind": kind, "started_at": iso(utc_now()), "finished_at": None,
        "in_progress": True, "argv": argv, "jobs": jobs, "jobs_validated": jobs <= VALIDATED_MAX_JOBS,
        "case_timeout_seconds": case_timeout, "rerun_failed": rerun_failed,
        "scheduled_cases": [c["id"] for c in schedule],
        "openant": _save_openant_state(layout, openant, session_no),
        "runner_python": {"executable": sys.executable, "version": platform.python_version()},
        "platform": platform.platform(), "host": platform.node(),
        "environment": recorded_environment(),
        "result": None, "exit_code": None, "zip": None,
    }
    batch["sessions"].append(session)
    write_json_atomic(layout.manifest, batch)
    console = Console(layout.log_file)
    run_config = batch["run_config"]
    console.line(f"OpenAnt Auto Patcher — real-CVE batch ({RUNNER_NAME} {RUNNER_VERSION})")
    for label, value in (
        ("Batch", batch["batch_id"]), ("Directory", str(layout.dir)), ("Session", f"{session_no} ({kind})"),
        ("Cases", f"{len(schedule)} scheduled of {len(batch['cases'])} in batch"),
        ("Jobs", f"{jobs}" + ("" if jobs <= VALIDATED_MAX_JOBS else f"  ⚠ above the experimentally validated maximum of {VALIDATED_MAX_JOBS}")),
        ("OpenAnt", f"{openant['head']} ({'DIRTY: ' + str(len(openant['status_porcelain'])) + ' path(s)' if openant['dirty'] else 'clean'})"),
        ("Python", f"{run_config['python_version']} {run_config['python']}"),
        ("Flags", " ".join(run_config["run_traced_flags"])),
        ("Timeout", f"{case_timeout:.0f}s per case" if case_timeout else "none"),
    ):
        console.line(f"  {label:<10} {value}")
    console.line()

    ctx = SessionContext(layout=layout, run_config=run_config, session_no=session_no,
                         openant_head=openant["head"], openant_fingerprint=openant["fingerprint"],
                         console=console, case_timeout=case_timeout,
                         scheduled_total=len(schedule), batch_dir=layout.dir)
    signal_state = {"signals": 0, "ctx": ctx}
    previous = None
    interrupted = False
    summary = None
    pool = ThreadPoolExecutor(max_workers=max(1, jobs), thread_name_prefix="cve-case")
    futures: dict = {}
    reported: set = set()

    def report(future) -> None:
        if future in reported or not future.done() or future.cancelled():
            return
        reported.add(future)
        case = futures[future]
        try:
            result = future.result()
        except Exception as exc:  # run_case_attempt never raises; be defensive anyway
            result = {"status": "failed", "failure_kind": "runner_exception",
                      "failure_detail": f"{type(exc).__name__}: {exc}", "paths": {}}
        finished = ctx.mark_finished(case)
        console.line(_result_line(case, result, finished, len(schedule), layout), stamp=True)

    try:
        try:
            previous = _install_signal_handlers(signal_state)
            for case in schedule:
                attempts = layout.attempts(case["id"])
                next_attempt = (attempts[-1][0] + 1) if attempts else 1
                futures[pool.submit(run_case_attempt, ctx, case, next_attempt)] = case
            remaining = set(futures)
            last_activity = time.monotonic()
            while remaining:
                done, remaining = wait(remaining, timeout=1.0, return_when=FIRST_COMPLETED)
                for future in sorted(done, key=lambda f: futures[f]["order"]):
                    report(future)
                if done:
                    last_activity = time.monotonic()
                    write_summaries(layout, batch, running=True)
                elif heartbeat and time.monotonic() - last_activity >= heartbeat:
                    last_activity = time.monotonic()
                    with ctx.lock:
                        running = sorted(ctx.running.items(), key=lambda kv: kv[1][0])
                        finished = ctx.finished
                    shown = ", ".join(f"{cid} ({fmt_duration(time.monotonic() - t)})" for cid, (t, _a) in running)
                    console.line(f"…       running: {shown or '(none)'}   · done {finished}/{len(schedule)}", stamp=True)
        except BatchInterrupted as exc:
            interrupted = True
            ctx.request_stop()
            console.line(f"INTERRUPT ({exc}) — stopping running cases; press Ctrl-C again to kill immediately", stamp=True)
            pool.shutdown(wait=True, cancel_futures=True)
            # Report whatever finished or stopped while shutting down; cases
            # that never started stay without an attempt (INCOMPLETE).
            for future in sorted(futures, key=lambda f: futures[f]["order"]):
                report(future)
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
            ctx.cancel_kill_timer()
            _restore_signal_handlers(previous)

        session["finished_at"] = iso(utc_now())
        session["in_progress"] = False
        session["openant_end"] = _openant_end_state(layout, openant, session_no)
        final = build_summary(layout, batch, load_states(layout, batch), interrupted=interrupted)
        session["result"] = final["status"].lower()
        session["exit_code"] = _exit_code_for(final)
        # Finalize the session record before writing the summaries that get
        # packaged (so the ZIP never holds a "running" session) and before
        # packaging itself (so a packaging crash leaves an accurate manifest).
        write_json_atomic(layout.manifest, batch)
        summary = write_summaries(layout, batch, interrupted=interrupted)
        zip_info = None
        if make_zip and not interrupted:
            try:
                zip_info = build_zip(layout, batch["batch_id"], include_investigation=include_investigation,
                                     secret_values=collect_secret_values())
            except Exception as exc:
                zip_info = {"error": f"{type(exc).__name__}: {exc}"}
                if session["exit_code"] in (EXIT_COMPLETE, EXIT_CASE_FAILURES):
                    session["exit_code"] = EXIT_ZIP_FAILED
            session["zip"] = zip_info
            batch["packaging"] = zip_info
            write_json_atomic(layout.manifest, batch)
            if "error" in zip_info:
                summary = write_summaries(layout, batch, interrupted=interrupted)
        shown_zip = zip_info if zip_info and "error" not in zip_info else None
        for line in render_terminal_summary(summary, shown_zip, layout, _resume_hint(layout, summary)):
            console.line(line)
        if zip_info and "error" in zip_info:
            console.line(f"ERROR: the results ZIP could not be created ({zip_info['error']}); "
                         f"summaries are intact. Retry with --summarize {layout.dir}")
        if interrupted:
            console.line("Interrupted: summaries were written; no ZIP was created. Resume with the command above.")
        return session["exit_code"]
    finally:
        console.close()


def _print_errors(title: str, errors) -> None:
    print(f"ERROR: {title}", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    print("Nothing was run.", file=sys.stderr)


def _case_timeout_seconds(minutes) -> "float | None":
    if minutes is None:
        return None
    return None if minutes <= 0 else round(minutes * 60.0, 3)


def batch_dir_problem(batch_dir: Path, work_tree) -> "str | None":
    """A batch inside the OpenAnt work tree at a non-ignored path would make
    its own clones and outputs look like OpenAnt code changes (and bloat
    `git status`). Ignored locations are invisible to the fingerprint."""
    if not work_tree or not path_inside(batch_dir, work_tree):
        return None
    rel = os.path.relpath(str(batch_dir), str(Path(work_tree).resolve()))
    try:
        ignored = subprocess.run(["git", "check-ignore", "-q", "--", rel], cwd=work_tree,
                                 capture_output=True, timeout=GIT_TIMEOUT).returncode == 0
    except (OSError, subprocess.SubprocessError):
        ignored = False
    if ignored:
        return None
    return (f"the batch directory {batch_dir} is inside the OpenAnt work tree ({work_tree}) at a path git "
            f"does not ignore; its checkouts and outputs would register as OpenAnt code changes. Use a "
            f"--batch-root outside the repository (default {DEFAULT_BATCH_ROOT}).")


def make_batch_id(label: "str | None") -> str:
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    slug = ""
    if label:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-._")[:40]
    return "-".join(p for p in (stamp, slug, secrets.token_hex(3)) if p)


def _check_llm_mode(allow_mock: bool) -> None:
    """Mirror llm_client._resolve_active_provider: LLM_PROVIDER is honored only
    as the literal "mock"; any other non-empty value makes every run fail."""
    provider = os.environ.get("LLM_PROVIDER", "").strip()
    if provider == "mock" and not allow_mock:
        raise RunnerSetupError(
            "LLM_PROVIDER=mock is set: these would not be real evaluations. Unset it, or pass "
            "--allow-mock-llm for a deliberate mock run."
        )
    if provider and provider != "mock":
        raise RunnerSetupError(
            f"LLM_PROVIDER={provider!r} is set; Auto Patcher rejects any value other than 'mock', so "
            "every case would fail. Unset it (the provider comes from `openant setup llm`)."
        )
    model = os.environ.get("LLM_MODEL", "").strip()
    if model and provider != "mock":
        raise RunnerSetupError(
            f"LLM_MODEL={model!r} is set; Auto Patcher rejects it for real providers "
            "(llm_client._resolve_model), so every case would fail at its first LLM call. Unset it."
        )


def _plan_lines(cases: list, header: str) -> list:
    lines = [header]
    for case in cases:
        lines.append(f"  [{case['order']:>3}] {case['id']:<48} {case['cve']:<16} {case['sha'][:12]}  "
                     f"{Path(case['source']['manifest']).name}")
    return lines


def cmd_new(args) -> int:
    try:
        loaded = load_manifests(args.manifest, allow_duplicate_cve=args.allow_duplicate_cve)
        cases = select_cases(loaded.cases, args.case)
    except ManifestError as exc:
        _print_errors("invalid batch input", exc.errors)
        return EXIT_INVALID_INPUT
    try:
        if args.jobs < 1:
            raise RunnerSetupError("--jobs must be >= 1")
        if args.batch_id and not BATCH_ID_RE.fullmatch(args.batch_id):
            raise RunnerSetupError(f"--batch-id {args.batch_id!r} must match {BATCH_ID_RE.pattern}")
        _check_llm_mode(args.allow_mock_llm)
        run_traced = Path(args.run_traced or RUN_TRACED).expanduser().resolve()
        if not run_traced.is_file():
            raise RunnerSetupError(f"run_traced script not found: {run_traced}")
        python_info = probe_python(args.python)
        probe_run_traced(python_info["executable"], str(run_traced))
        openant = collect_openant_state()
        if args.require_clean_openant and openant["dirty"]:
            raise RunnerSetupError("the OpenAnt work tree is dirty and --require-clean-openant was given:\n    "
                                   + "\n    ".join(openant["status_porcelain"]))
    except RunnerSetupError as exc:
        _print_errors(str(exc).splitlines()[0], str(exc).splitlines()[1:])
        return EXIT_INVALID_INPUT
    policy = args.blind_filter_policy
    effective_policy = policy or DEFAULT_BLIND_FILTER_POLICY
    case_timeout = _case_timeout_seconds(
        args.case_timeout_minutes if args.case_timeout_minutes is not None else DEFAULT_CASE_TIMEOUT_MINUTES)
    run_config = {
        "run_traced": str(run_traced),
        "python": python_info["executable"],
        "python_version": python_info["version"],
        "python_requested": python_info["requested"],
        "run_traced_flags": canonical_run_traced_flags(policy),
        "context_budget_policy": CONTEXT_BUDGET_POLICY,
        "max_context_budget_windows": MAX_CONTEXT_BUDGET_WINDOWS,
        "blind_evaluation": True,
        "same_repo_github_stripping": True,
        "blind_filter_policy": effective_policy,
        "blind_filter_policy_explicit": policy is not None,
        "expected_blind_rule_id": BLIND_FILTER_POLICIES[effective_policy],
        "case_timeout_seconds": case_timeout,
        "allow_mock_llm": bool(args.allow_mock_llm),
    }
    batch_root = Path(args.batch_root).expanduser()
    batch_id = args.batch_id or make_batch_id(args.label)
    batch_dir = (batch_root / batch_id).resolve()
    location_problem = batch_dir_problem(batch_dir, openant.get("work_tree"))
    if location_problem:
        _print_errors(location_problem, [])
        return EXIT_INVALID_INPUT
    if args.validate_only:
        for line in _plan_lines(cases, f"VALID: {len(cases)} case(s) from {len(loaded.inputs)} manifest(s)"):
            print(line)
        print(f"Batch directory would be: {batch_dir}")
        print(f"run_traced flags: {' '.join(run_config['run_traced_flags'])}")
        print(f"OpenAnt: {openant['head']} ({'dirty' if openant['dirty'] else 'clean'}) · jobs {args.jobs}")
        print("VALIDATE ONLY: nothing was run.")
        return 0
    layout = BatchLayout(batch_dir)
    try:
        batch_dir.parent.mkdir(parents=True, exist_ok=True)
        batch_dir.mkdir()  # atomic claim: never reuse or overwrite an existing batch
    except FileExistsError:
        _print_errors(f"batch directory already exists: {batch_dir}", [])
        return EXIT_INVALID_INPUT
    for d in (layout.inputs_dir, layout.logs_dir, layout.cases_dir):
        d.mkdir()
    inputs = []
    for inp in loaded.inputs:
        copy = layout.inputs_dir / f"{inp['input_index']:02d}-{Path(inp['path']).name}"
        copy.write_bytes(inp["_raw"])
        inputs.append({k: v for k, v in inp.items() if k != "_raw"} | {"copy": rel_to(copy, layout.dir)})
    copies = {i["input_index"]: i["copy"] for i in inputs}
    for case in cases:
        case["source"]["input_copy"] = copies[case["source"]["input_index"]]
        layout.case_dir(case["id"]).mkdir()
        write_json_atomic(layout.case_dir(case["id"]) / "case.json", case)
    batch = {
        "schema_version": BATCH_SCHEMA_VERSION,
        "kind": "openant_cve_batch",
        "runner": {"name": RUNNER_NAME, "version": RUNNER_VERSION, "path": str(Path(__file__).resolve())},
        "batch_id": batch_id,
        "label": args.label,
        "created_at": iso(utc_now()),
        "batch_dir": str(batch_dir),
        "inputs": inputs,
        "selection": {"case_filter": list(args.case) if args.case else None,
                      "allow_duplicate_cve": bool(args.allow_duplicate_cve)},
        "run_config": run_config,
        "cases": cases,
        "sessions": [],
        "packaging": None,
    }
    write_json_atomic(layout.manifest, batch)
    with BatchLock(layout):
        return run_session(layout=layout, batch=batch, schedule=cases, kind="initial", jobs=args.jobs,
                           openant=openant, case_timeout=case_timeout,
                           heartbeat=args.heartbeat_seconds, rerun_failed=False,
                           make_zip=not args.no_zip, include_investigation=args.zip_include_investigation,
                           argv=list(args.argv))


def _load_batch(path_arg) -> "tuple[BatchLayout, dict]":
    layout = BatchLayout(Path(path_arg).expanduser().resolve())
    batch, error = read_json(layout.manifest)
    if error or not isinstance(batch, dict):
        raise RunnerSetupError(f"{layout.manifest}: not a readable batch manifest ({error or 'not an object'})")
    if batch.get("kind") != "openant_cve_batch" or batch.get("schema_version") != BATCH_SCHEMA_VERSION:
        raise RunnerSetupError(f"{layout.manifest}: unsupported batch manifest (kind/schema_version)")
    if not same_path(batch.get("batch_dir"), layout.dir):
        raise RunnerSetupError(
            f"batch was created at {batch.get('batch_dir')} but is now at {layout.dir}; run manifests "
            "record absolute paths, so a moved batch cannot be resumed or re-validated"
        )
    return layout, batch


def _close_stale_sessions(batch: dict) -> None:
    """A session still marked in progress while we hold the batch lock was
    abandoned (runner killed hard). Mark it so wall-clock totals ignore it."""
    for session in batch.get("sessions") or []:
        if session.get("in_progress"):
            session["in_progress"] = False
            session["result"] = session.get("result") or "abandoned"


def cmd_resume(args) -> int:
    try:
        layout, batch = _load_batch(args.resume)
    except RunnerSetupError as exc:
        _print_errors(str(exc), [])
        return EXIT_INVALID_INPUT
    try:
        with BatchLock(layout):
            _close_stale_sessions(batch)
            run_config = batch["run_config"]
            if args.jobs < 1:
                raise RunnerSetupError("--jobs must be >= 1")
            _check_llm_mode(args.allow_mock_llm or run_config.get("allow_mock_llm", False))
            # Evaluation semantics are frozen per batch: the same interpreter,
            # run_traced.py and blind policy for every case.
            interpreter = probe_python(args.python or run_config["python"])["executable"]
            if interpreter != run_config["python"]:
                raise RunnerSetupError(
                    f"--python resolves to {interpreter}, not this batch's {run_config['python']}; "
                    "start a new batch to change the interpreter"
                )
            if args.run_traced and not same_path(args.run_traced, run_config["run_traced"]):
                raise RunnerSetupError("--run-traced differs from this batch's run_traced.py; start a new batch")
            if args.blind_filter_policy and args.blind_filter_policy != run_config["blind_filter_policy"]:
                raise RunnerSetupError(
                    f"this batch uses blind filter policy {run_config['blind_filter_policy']}; it cannot change on resume"
                )
            if not Path(run_config["run_traced"]).is_file():
                raise RunnerSetupError(f"run_traced script recorded for this batch is missing: {run_config['run_traced']}")
            problems = run_config_problems(run_config)
            if problems:
                raise RunnerSetupError("batch_manifest.json run_config no longer describes the canonical "
                                       "evaluation setup; refusing to resume:\n" + "\n".join(problems))
            probe_run_traced(run_config["python"], run_config["run_traced"])
            openant = collect_openant_state()
            if args.require_clean_openant and openant["dirty"]:
                raise RunnerSetupError("the OpenAnt work tree is dirty and --require-clean-openant was given")
            original = (batch["sessions"][0].get("openant") or {}) if batch["sessions"] else {}
            if original.get("fingerprint") and openant["fingerprint"] != original["fingerprint"]:
                if not args.allow_openant_change:
                    raise RunnerSetupError(
                        "the OpenAnt code differs from the batch's first session "
                        f"(then {original.get('head')} dirty={original.get('dirty')}, now {openant['head']} "
                        f"dirty={openant['dirty']}); resuming would mix code versions.\n"
                        "Pass --allow-openant-change to resume anyway (recorded per session), or start a new batch."
                    )
            if args.case:
                known = {c["id"] for c in batch["cases"]}
                missing = [c for c in args.case if c not in known]
                if missing:
                    raise RunnerSetupError(f"--case not in this batch: {', '.join(missing)}")
            states = load_states(layout, batch)
            schedule = []
            print(f"Resume {batch['batch_id']} — {len(states)} case(s)")
            for state in states:
                case = state["case"]
                if state["status"] == "completed":
                    run, action = False, f"skip: completed ({state['category']})"
                elif state["status"] == "failed":
                    kind = state["result"].get("failure_kind")
                    run = bool(args.rerun_failed)
                    action = f"RERUN: failed ({kind})" if run else f"keep failure ({kind}); --rerun-failed reruns it"
                else:
                    run, action = True, f"RUN: {state['status']} — {state['note']}"
                if run and args.case and case["id"] not in args.case:
                    run, action = False, action + " — not selected by --case"
                if run:
                    schedule.append(case)
                print(f"  [{case['order']:>3}] {case['id']:<48} {action}")
            if args.validate_only:
                print(f"VALIDATE ONLY: {len(schedule)} case(s) would run; nothing was run.")
                return 0
            case_timeout = (_case_timeout_seconds(args.case_timeout_minutes)
                            if args.case_timeout_minutes is not None else run_config.get("case_timeout_seconds"))
            if not schedule:
                print("Nothing to run; regenerating summaries.")
            return run_session(layout=layout, batch=batch, schedule=schedule, kind="resume", jobs=args.jobs,
                               openant=openant, case_timeout=case_timeout, heartbeat=args.heartbeat_seconds,
                               rerun_failed=bool(args.rerun_failed), make_zip=not args.no_zip,
                               include_investigation=args.zip_include_investigation, argv=list(args.argv))
    except RunnerSetupError as exc:
        lines = str(exc).splitlines()
        _print_errors(lines[0], lines[1:])
        return EXIT_INVALID_INPUT


def cmd_summarize(args) -> int:
    try:
        layout, batch = _load_batch(args.summarize)
        with BatchLock(layout):
            _close_stale_sessions(batch)
            write_json_atomic(layout.manifest, batch)
            summary = write_summaries(layout, batch)
            zip_info = None
            exit_code = _exit_code_for(summary)
            if not args.no_zip:
                try:
                    zip_info = build_zip(layout, batch["batch_id"], include_investigation=args.zip_include_investigation,
                                         secret_values=collect_secret_values())
                except Exception as exc:
                    print(f"ERROR: the results ZIP could not be created ({type(exc).__name__}: {exc})", file=sys.stderr)
                    zip_info = {"error": f"{type(exc).__name__}: {exc}"}
                    if exit_code in (EXIT_COMPLETE, EXIT_CASE_FAILURES):
                        exit_code = EXIT_ZIP_FAILED
                batch["packaging"] = zip_info
                write_json_atomic(layout.manifest, batch)
            shown_zip = zip_info if zip_info and "error" not in zip_info else None
            for line in render_terminal_summary(summary, shown_zip, layout, _resume_hint(layout, summary)):
                print(line)
            return exit_code
    except RunnerSetupError as exc:
        _print_errors(str(exc), [])
        return EXIT_INVALID_INPUT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=RUNNER_NAME,
        allow_abbrev=False,  # `--zip` must not silently mean --zip-include-investigation
        description=(
            "Run OpenAnt Auto Patcher real-CVE evaluation manifests through run_traced.py with "
            "bounded parallelism, isolated per-case checkouts/outputs/CWDs, aggregate summaries, "
            "a results ZIP, and resume. See RUN_CVE_BATCH.md."
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest", action="append", metavar="YAML",
                      help="Evaluation manifest (repeatable; cases run in the order given).")
    mode.add_argument("--resume", metavar="BATCH_DIR", help="Continue an existing batch.")
    mode.add_argument("--summarize", metavar="BATCH_DIR",
                      help="Only regenerate summaries and the ZIP of an existing batch (runs nothing).")
    parser.add_argument("--case", action="append", metavar="CASE_ID",
                        help="Restrict to these case ids (repeatable).")
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS,
                        help=f"Concurrent cases (default {DEFAULT_JOBS}; values above {VALIDATED_MAX_JOBS} are not experimentally validated).")
    parser.add_argument("--batch-root", default=str(DEFAULT_BATCH_ROOT),
                        help=f"Parent directory for new batches (default {DEFAULT_BATCH_ROOT}).")
    parser.add_argument("--batch-id", help="Explicit id for a new batch (default: UTC timestamp + random suffix).")
    parser.add_argument("--label", help="Free-text label recorded in the batch and added to its id.")
    parser.add_argument("--allow-duplicate-cve", action="store_true",
                        help="Allow one CVE in several cases with different repository/SHA.")
    parser.add_argument("--blind-filter-policy", choices=sorted(BLIND_FILTER_POLICIES),
                        help="Forward run_traced.py --blind-filter-policy (default: run_traced's own default, "
                             f"{DEFAULT_BLIND_FILTER_POLICY}).")
    parser.add_argument("--case-timeout-minutes", type=float, default=None,
                        help=f"Kill a case's run_traced.py after this many minutes (default {DEFAULT_CASE_TIMEOUT_MINUTES:g}; 0 = none).")
    parser.add_argument("--heartbeat-seconds", type=int, default=DEFAULT_HEARTBEAT_SECONDS,
                        help=f"Print the running cases after this many quiet seconds (default {DEFAULT_HEARTBEAT_SECONDS}; 0 = off).")
    parser.add_argument("--python", default=None,
                        help="Interpreter for run_traced.py (default: the one running this script; fixed per batch).")
    # Testing hook: substitute a fake run_traced.py (hermetic tests). Frozen per batch.
    parser.add_argument("--run-traced", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--allow-mock-llm", action="store_true",
                        help="Allow LLM_PROVIDER=mock (smoke tests only; results are not real evaluations).")
    parser.add_argument("--require-clean-openant", action="store_true",
                        help="Refuse to start if the OpenAnt work tree has uncommitted changes.")
    parser.add_argument("--rerun-failed", action="store_true",
                        help="With --resume: also rerun cases whose latest attempt FAILED.")
    parser.add_argument("--allow-openant-change", action="store_true",
                        help="With --resume: allow resuming after the OpenAnt code changed.")
    parser.add_argument("--no-zip", action="store_true", help="Skip creating the results ZIP.")
    parser.add_argument("--zip-include-investigation", action="store_true",
                        help="Also package output/patch/*-investigation/ (large derived parser output).")
    parser.add_argument("--validate-only", action="store_true",
                        help="Validate input and print the plan; run nothing.")
    return parser


def main(argv=None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw_argv)
    args.argv = [RUNNER_NAME, *raw_argv]
    if fcntl is None:
        _print_errors("run_cve_batch.py requires POSIX (process groups, flock)", [])
        return EXIT_INVALID_INPUT
    if args.summarize:
        return cmd_summarize(args)
    if args.resume:
        return cmd_resume(args)
    args.python = args.python or sys.executable
    return cmd_new(args)


if __name__ == "__main__":
    sys.exit(main())
