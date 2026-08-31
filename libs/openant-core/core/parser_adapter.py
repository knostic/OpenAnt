"""
Unified parser interface.

Wraps language-specific parsers (Python, JavaScript, Go, C, Ruby, PHP) with
a single function signature that accepts a repo path and returns dataset +
analyzer output.

Each parser is invoked as a subprocess to avoid import conflicts with
sys.path hacks in the original code.
"""

import contextlib
import functools
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from core.language_registry import (
    extension_map,
    load_registry,
    parser_script_path,
    skip_dirs,
    supported_languages,
)
from core.schemas import ParseResult
from utilities.child_interp import child_interpreter_env
from utilities.file_io import open_utf8, read_json, write_json
from utilities.prune_telemetry import compute_prune_telemetry

# Root of openant-core (where parsers/ lives)
_CORE_ROOT = Path(__file__).parent.parent

# JS parser directory (holds its own package.json / node_modules)
_JS_PARSER_DIR = _CORE_ROOT / "parsers" / "javascript"

def detect_languages(repo_path: str) -> dict[str, int]:
    """Count source files per language.

    This is the multi-language primitive. ``detect_language`` wraps it for the
    single-language callers, which previously threw the count map away — a repo
    that is 60% Go and 40% TypeScript was scanned as a Go repo, and the absence
    of the TypeScript was never reported anywhere.

    Directories named in ``skip_dirs`` are PRUNED rather than filtered
    per-file. This matches the Go detector's ``filepath.SkipDir`` semantics
    exactly (the two implementations previously disagreed on what "skip"
    meant), and it stops the walk descending into ``node_modules`` at all,
    which is a substantial speedup on JS monorepos.

    Args:
        repo_path: Repository root to walk.

    Returns:
        Mapping of language name → source-file count, ordered by descending
        count with ties broken alphabetically. The ordering is deterministic:
        the previous ``max(counts, key=counts.get)`` returned whichever key
        happened to be first in dict order, and the Go side's randomized map
        iteration meant the two could disagree on a tie for the same repo.

    Raises:
        ValueError: If no supported source files were found. The message is
            preserved verbatim so ``detect_language``'s contract is unchanged.
    """
    extensions = extension_map()
    skipped = skip_dirs()

    counts: dict[str, int] = {}

    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune in place so os.walk does not descend into skipped trees.
        dirnames[:] = [d for d in dirnames if d not in skipped]

        for filename in filenames:
            suffix = os.path.splitext(filename)[1].lower()
            lang = extensions.get(suffix)
            if lang is not None:
                counts[lang] = counts.get(lang, 0) + 1

    if not counts:
        raise ValueError(
            f"No supported source files found in {repo_path}. "
            "Supported languages: Python, JavaScript/TypeScript, Go, C/C++, Ruby, PHP, "
            "Zig, Swift, Rust."
        )

    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def detect_language(repo_path: str) -> str:
    """Auto-detect the primary (dominant) language of a repository.

    Preserved verbatim in signature and in the ``ValueError`` contract so every
    existing caller and test is unaffected by the multi-language work.

    Returns:
        One of: "python", "javascript", "go", "c", "ruby", "php", "zig"
    """
    return next(iter(detect_languages(repo_path)))


def parse_repository(
    repo_path: str,
    output_dir: str,
    language: str = "auto",
    processing_level: str = "reachable",
    skip_tests: bool = True,
    name: str = None,
    diff_manifest: str | None = None,
    fresh: bool = False,
    library_mode: bool = False,
) -> ParseResult:
    """Parse a repository into an OpenAnt dataset.

    Delegates to the appropriate language-specific parser. Each parser is
    invoked as a subprocess to avoid import path conflicts.

    Args:
        repo_path: Absolute path to the repository to parse.
        output_dir: Directory where dataset.json and analyzer_output.json will be written.
        language: "auto", "python", "javascript", or "go".
        processing_level: "all", "reachable", "codeql", or "exploitable".
        skip_tests: If True, exclude test files from parsing (default: True).
        name: Dataset name override (default: derived from repo path basename).
        fresh: If True, delete existing dataset.json before parsing so all
            units are regenerated from scratch. Only dataset.json is deleted;
            other artifacts in output_dir (e.g. analyzer outputs) are preserved.
        library_mode: If True, seed the public API surface as reachability
            entry points (opt-in, union-only).

    Returns:
        ParseResult with paths to generated files and stats.

    Raises:
        ValueError: If language can't be detected or is unsupported.
        RuntimeError: If the parser subprocess fails.
    """
    repo_path = os.path.abspath(repo_path)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    if fresh:
        dataset_path = os.path.join(output_dir, "dataset.json")
        # Use try/except instead of exists()+remove() to avoid a TOCTOU race
        # if a concurrent --fresh run removes the file between the two calls.
        # Only dataset.json is deleted; other artifacts (analyzer outputs, etc.)
        # in output_dir are preserved.
        try:
            os.remove(dataset_path)
            print("[Parser] --fresh: deleted existing dataset.json", file=sys.stderr)
        except FileNotFoundError:
            pass

    # Detect language if auto
    if language == "auto":
        language = detect_language(repo_path)
        print(f"  Auto-detected language: {language}", file=sys.stderr)

    # Dispatch to the right parser via the registry.
    try:
        parser = _parser_for(language)
    except KeyError:
        raise ValueError(
            f"Unsupported language: {language}. "
            f"Supported: {', '.join(supported_languages())}"
        ) from None

    result = parser(repo_path, output_dir, processing_level, skip_tests, name, library_mode)

    _maybe_apply_diff_filter(result, output_dir, diff_manifest)
    return result


@dataclass
class LanguageParseOutcome:
    """Result of parsing ONE language during a multi-language fan-out.

    Failures are data, not exceptions, because one broken toolchain must not
    cost the user every other language in the repo.

    Attributes:
        language: Registry language name.
        ok: Whether the parse succeeded.
        output_dir: The per-language directory written to.
        dataset_path: Path to this language's dataset.json, if produced.
        analyzer_output_path: Path to analyzer_output.json, if produced.
        units_count: Units parsed.
        duration_seconds: Wall-clock time for this language.
        error: Failure message, when ``ok`` is False.
        error_type: Coarse failure class, for reporting and triage.
    """

    language: str
    ok: bool
    output_dir: str
    dataset_path: str | None = None
    analyzer_output_path: str | None = None
    units_count: int = 0
    duration_seconds: float = 0.0
    error: str | None = None
    error_type: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _classify_parse_error(exc: BaseException) -> str:
    """Coarse failure class for a per-language parse error."""
    if isinstance(exc, subprocess.TimeoutExpired):
        return "timeout"
    if isinstance(exc, FileNotFoundError):
        return "missing_dependency"
    if isinstance(exc, OSError):
        return "os_error"
    if isinstance(exc, ValueError):
        return "unsupported_language"
    return "parser_failed"


def parse_repository_multi(
    repo_path: str,
    run_dir: str,
    languages: list[str],
    processing_level: str = "reachable",
    skip_tests: bool = True,
    name: str = None,
    fresh: bool = False,
    library_mode: bool = False,
    strict: bool = False,
) -> list[LanguageParseOutcome]:
    """Parse a repository once per language into per-language directories.

    Every parser writes the SAME flat filenames — ``dataset.json``,
    ``analyzer_output.json``, ``call_graph.json``, ``scan_result(s).json``,
    ``functions.json``, ``pipeline_results.json`` — into whatever output
    directory it is handed. Running two languages into one directory therefore
    means the second silently overwrites the first. Giving each language its own
    ``<run_dir>/<language>/`` is the whole reason this function exists, and it
    matches the layout the Go CLI already assumes via
    ``config.ScanDir(project, sha, language)``.

    **Sequential by design.** This loop must not be parallelised without first
    moving cost tracking off the process-global tracker: ``step_context``
    computes usage deltas against it, and concurrent languages would interleave
    those deltas and silently corrupt every per-step ``cost_usd``. Two further
    reasons: the Python parser runs in-process and mutates ``sys.path``, and
    running six tree-sitter/Node/Go parsers at once on a monorepo is a
    realistic OOM — which would lose every language, the exact outcome the
    partial-success handling below exists to prevent.

    Args:
        repo_path: Repository to parse.
        run_dir: Run root. Per-language output goes in ``<run_dir>/<language>/``.
        languages: Languages to parse, in order.
        processing_level: "all", "reachable", "codeql" or "exploitable".
        skip_tests: Exclude test files.
        name: Dataset name override.
        fresh: Delete each language's existing dataset.json first.
        library_mode: Seed the public API surface as entry points.
        strict: Re-raise the first per-language failure instead of continuing.

    Returns:
        One :class:`LanguageParseOutcome` per requested language, in order.

    Raises:
        ValueError: If ``languages`` is empty.
        RuntimeError: If EVERY language failed, aggregating each error.
    """
    if not languages:
        raise ValueError("parse_repository_multi requires at least one language")

    repo_path = os.path.abspath(repo_path)
    run_dir = os.path.abspath(run_dir)

    outcomes: list[LanguageParseOutcome] = []

    for language in languages:
        output_dir = os.path.join(run_dir, language)
        started = time.monotonic()

        try:
            result = parse_repository(
                repo_path=repo_path,
                output_dir=output_dir,
                language=language,
                processing_level=processing_level,
                skip_tests=skip_tests,
                name=name,
                fresh=fresh,
                library_mode=library_mode,
            )
        except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
            # Deliberately NOT a bare `except Exception`: a KeyboardInterrupt or
            # MemoryError mid-fan-out must abort the run, not be logged as
            # "this language failed" and then repeated for five more languages.
            outcomes.append(LanguageParseOutcome(
                language=language,
                ok=False,
                output_dir=output_dir,
                duration_seconds=time.monotonic() - started,
                error=str(exc),
                error_type=_classify_parse_error(exc),
            ))
            print(
                f"  [ERROR] {language} parser failed: {exc} — "
                "continuing with remaining languages",
                file=sys.stderr,
            )
            if strict:
                raise
            continue

        outcomes.append(LanguageParseOutcome(
            language=language,
            ok=True,
            output_dir=output_dir,
            dataset_path=result.dataset_path,
            analyzer_output_path=result.analyzer_output_path,
            units_count=result.units_count,
            duration_seconds=time.monotonic() - started,
        ))

    if not any(o.ok for o in outcomes):
        detail = "; ".join(f"{o.language}: {o.error}" for o in outcomes)
        raise RuntimeError(f"All {len(outcomes)} language parser(s) failed. {detail}")

    failed = [o for o in outcomes if not o.ok]
    if failed:
        print(
            f"[Parser] DEGRADED: {len(failed)} of {len(outcomes)} language(s) failed "
            f"({', '.join(o.language for o in failed)}). Results are incomplete.",
            file=sys.stderr,
        )

    return outcomes


def _maybe_apply_diff_filter(
    result: ParseResult,
    output_dir: str,
    diff_manifest: str | None,
) -> None:
    """Apply the diff filter to the dataset on disk if a manifest is provided.

    Annotates every unit with `diff_selected: bool` and rewrites dataset.json.
    Writes stats to {output_dir}/diff_filter.report.json for the step report
    (picked up alongside parse.report.json). If `diff_manifest` is None and
    no default manifest exists in output_dir, this is a no-op so legacy runs
    behave exactly as before.
    """
    # Resolve manifest path: explicit arg wins, else look for the default.
    if diff_manifest is None:
        default = os.path.join(output_dir, "diff_manifest.json")
        if os.path.exists(default):
            diff_manifest = default
    if not diff_manifest:
        return

    from core.diff_filter import apply_diff_filter, load_manifest

    print(f"\n[Diff Filter] Loading manifest from {diff_manifest}", file=sys.stderr)
    manifest = load_manifest(diff_manifest)

    if not os.path.exists(result.dataset_path):
        print(
            f"  [Warning] dataset {result.dataset_path} not found; skipping diff filter",
            file=sys.stderr,
        )
        return

    dataset = read_json(result.dataset_path)
    # Dataset may be a dict with "units" or a raw list.
    if isinstance(dataset, dict):
        units = dataset.get("units", [])
    else:
        units = dataset

    stats = apply_diff_filter(units, manifest)

    write_json(result.dataset_path, dataset)
    # Expose stats on the ParseResult via a side-channel file; the parse
    # step_context reads this when assembling parse.report.json.
    diff_report_path = os.path.join(output_dir, "diff_filter.report.json")
    write_json(diff_report_path, stats.to_dict())

    print(
        f"  Diff filter ({stats.scope}): {stats.selected}/{stats.total} units selected"
        + (f" ({stats.callers_added} added as callers)" if stats.callers_added else "")
        + (f", {stats.fallback_file_match} fell back to file-level" if stats.fallback_file_match else ""),
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Reachability filter (shared by Python path; JS/Go handle it internally)
# ---------------------------------------------------------------------------

# library_seed_ids is now shared in utilities/agentic_enhancer/entry_point_detector.py
# so every parser pipeline (not just Python) can seed the public API. It is loaded
# below via the same importlib path as EntryPointDetector to dodge the heavy
# utilities/__init__ imports.


def apply_reachability_filter(
    dataset: dict,
    output_dir: str,
    processing_level: str,
    extra_entry_points: "set[str] | None" = None,
    library_mode: bool = False,
) -> dict:
    """Filter dataset units to only those reachable from entry points.

    Reads the call_graph.json intermediate file produced by the parser,
    detects entry points, computes reachability via BFS, and removes
    unreachable units from the dataset.

    ``extra_entry_points`` supplements the structurally-detected seed set.
    Pass LLM-promoted unit IDs here so the BFS propagates from them even if
    the structural heuristics missed them.  Any unit that already has
    ``is_entry_point=True`` in the dataset (e.g. set by the LLM reachability
    stage) keeps that flag — this function never demotes it.

    For ``codeql`` and ``exploitable`` levels the reachability filter is
    still applied (it is a prerequisite), but the additional CodeQL /
    LLM-classification filters are not yet wired into the Python path
    and a warning is printed.

    Args:
        dataset: The full, unfiltered dataset dict (mutated in place).
        output_dir: Directory containing call_graph.json from the parser.
        processing_level: One of "reachable", "codeql", "exploitable".
        extra_entry_points: Additional unit IDs to seed the BFS (e.g. from LLM).

    Returns:
        The (possibly filtered) dataset dict.
    """
    # Import directly from source files to avoid utilities/__init__.py
    # which pulls in anthropic and other heavy LLM dependencies.
    import importlib.util

    _enhancer_dir = _CORE_ROOT / "utilities" / "agentic_enhancer"

    def _load_module(name, filename):
        spec = importlib.util.spec_from_file_location(name, _enhancer_dir / filename)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    _epd = _load_module("entry_point_detector", "entry_point_detector.py")
    _ra = _load_module("reachability_analyzer", "reachability_analyzer.py")
    EntryPointDetector = _epd.EntryPointDetector
    blackout_warning = _epd.blackout_warning
    library_seed_ids = _epd.library_seed_ids
    real_entry_point_ids = _epd.real_entry_point_ids
    ReachabilityAnalyzer = _ra.ReachabilityAnalyzer

    call_graph_path = os.path.join(output_dir, "call_graph.json")

    if not os.path.exists(call_graph_path):
        print(
            "  [Warning] call_graph.json not found — skipping reachability filter",
            file=sys.stderr,
        )
        return dataset

    print(f"\n[Reachability Filter] Filtering to {processing_level} units...", file=sys.stderr)

    call_graph_data = read_json(call_graph_path)
    functions = call_graph_data.get("functions", {})
    call_graph = call_graph_data.get("call_graph", {})
    reverse_call_graph = call_graph_data.get("reverse_call_graph", {})

    # Detect entry points structurally, then seed with any extras (e.g. LLM-promoted).
    detector = EntryPointDetector(functions, call_graph)
    entry_points = detector.detect_entry_points()
    if extra_entry_points:
        entry_points = entry_points | extra_entry_points
    # Library-mode (opt-in): the public API is the entry surface. Union-only —
    # never demotes a structurally-detected app entry point, so an app scan with
    # the flag on can only gain reachable units, never lose one.
    if library_mode:
        entry_points = entry_points | library_seed_ids(functions)

    units = dataset.get("units", [])
    original_count = len(units)

    # Empty-seed safety-net: a zero entry-point seed would prune EVERY unit
    # (the BFS frontier starts empty), silently emptying the dataset and
    # reporting a 100% reduction as success. That is the dominant failure mode
    # for non-web library / stdlib targets, whose ordinary functions are not a
    # seedable entry type. Rather than a silent total blackout, degrade to
    # pass-through (keep all units, unfiltered) and record a loud warning so the
    # degraded result is never silent. Higher-level callers may still seed
    # ``extra_entry_points`` to get real filtering.
    real_eps = real_entry_point_ids(entry_points, functions)
    if not real_eps and original_count > 0:
        why = ("Only synthetic fuzz-harness entry points detected"
               if entry_points else "No entry points detected")
        warning = (
            f"{why} — reachability cannot seed a real frontier. "
            "Returning all units unfiltered to avoid a silent blackout; "
            f"'{processing_level}' filtering was NOT applied. "
            "Use --library-mode to seed the exported public API surface."
        )
        print(f"  [Warning] {warning}", file=sys.stderr)
        dataset.setdefault("metadata", {})["reachability_filter"] = {
            "original_units": original_count,
            "entry_points": len(entry_points),
            "reachable_units": original_count,
            "filtered_out": 0,
            "reduction_percentage": 0,
            "warning": warning,
        }
        return dataset

    # Compute reachable set (BFS forward from entry points)
    reachability = ReachabilityAnalyzer(
        functions=functions,
        reverse_call_graph=reverse_call_graph,
        entry_points=entry_points,
    )
    reachable_ids = reachability.get_all_reachable()

    # Filter dataset units and stamp reachability tags
    filtered_units = []
    for u in units:
        unit_id = u.get("id", "")
        if unit_id in reachable_ids:
            u["reachable"] = True
            # Preserve any is_entry_point=True already set (e.g. by LLM stage).
            u["is_entry_point"] = (unit_id in entry_points) or u.get("is_entry_point", False)
            if unit_id in entry_points and not u.get("entry_point_reason"):
                u["entry_point_reason"] = detector.get_entry_point_reason(unit_id)
            filtered_units.append(u)

    dataset["units"] = filtered_units

    # Record filter metadata
    reduction_pct = (
        round((1 - len(filtered_units) / original_count) * 100, 1)
        if original_count > 0
        else 0
    )
    dataset.setdefault("metadata", {})["reachability_filter"] = {
        "original_units": original_count,
        "entry_points": len(entry_points),
        "reachable_units": len(filtered_units),
        "filtered_out": original_count - len(filtered_units),
        "reduction_percentage": reduction_pct,
    }

    print(f"  Entry points detected: {len(entry_points)}", file=sys.stderr)
    print(
        f"  Units: {original_count} -> {len(filtered_units)} "
        f"({reduction_pct}% reduction)",
        file=sys.stderr,
    )

    _blackout = blackout_warning(detector.entry_point_details, original_count,
                                 len(filtered_units), library_mode=library_mode)
    if _blackout:
        dataset["metadata"]["reachability_filter"]["warning"] = _blackout
        print(f"  [Warning] {_blackout}", file=sys.stderr)

    # Per-unit prune telemetry (ADDITIVE, all-language; advisory — must never crash
    # the filter). Merges classification keys + the pruned_units.json sidecar; a
    # forward-asymmetry warning is recorded only if a blackout warning did not
    # already claim the slot. call_graph/reverse_call_graph are the UN-pruned graphs.
    _rf = dataset["metadata"]["reachability_filter"]
    _pruned_ids = [u.get("id", "") for u in units if u.get("id", "") not in reachable_ids]
    _extra, _asym_warning, _orphan_advisory = compute_prune_telemetry(
        reachable_ids, sorted(_pruned_ids), call_graph, reverse_call_graph, output_dir)
    _rf.update(_extra)
    if _asym_warning and "warning" not in _rf:
        _rf["warning"] = _asym_warning
        print(f"  [Warning] {_asym_warning}", file=sys.stderr)
    # #301: the orphan-rate advisory — its own key, NEVER the reserved
    # ``warning`` slot, and it reaches the scan summary on stderr.
    if _orphan_advisory:
        _rf["orphan_advisory"] = _orphan_advisory
        print(f"  [Advisory] {_orphan_advisory}", file=sys.stderr)

    # Warn about unimplemented higher-level filters
    if processing_level == "codeql":
        print(
            "  [Warning] CodeQL filter not yet wired into the Python parser path. "
            "Returning reachable units only.",
            file=sys.stderr,
        )
    elif processing_level == "exploitable":
        print(
            "  [Warning] Exploitable filter (CodeQL + LLM classification) not yet "
            "wired into the Python parser path. Returning reachable units only.",
            file=sys.stderr,
        )

    return dataset


# Private alias kept for the Python parser path which calls it directly.
_apply_reachability_filter = apply_reachability_filter


# ---------------------------------------------------------------------------
# Python parser
# ---------------------------------------------------------------------------

def _parse_python(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None, library_mode: bool = False) -> ParseResult:
    """Invoke the Python parser.

    The Python parser has a clean `parse_repository()` function that we can
    call directly (it's the best-structured of the three).
    """
    print("[Parser] Running Python parser...", file=sys.stderr)

    # Import and call directly — the Python parser is well-structured
    parser_dir = str(_CORE_ROOT / "parsers" / "python")
    if parser_dir not in sys.path:
        sys.path.insert(0, parser_dir)

    from parsers.python.parse_repository import parse_repository as _py_parse

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    options = {
        "dataset_name": name or Path(repo_path).name,
        "output_dir": output_dir,  # For intermediate files
        "skip_tests": skip_tests,
    }

    dataset, analyzer_output = _py_parse(repo_path, options)

    # Apply reachability filter if processing_level requires it
    if processing_level != "all":
        dataset = _apply_reachability_filter(dataset, output_dir, processing_level,
                                             library_mode=library_mode)

    # Write outputs
    write_json(dataset_path, dataset)
    write_json(analyzer_output_path, analyzer_output)
    units_count = len(dataset.get("units", []))
    print(f"  Python parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path,
        units_count=units_count,
        language="python",
        processing_level=processing_level,
    )


# ---------------------------------------------------------------------------
# JavaScript/TypeScript parser
# ---------------------------------------------------------------------------

def _js_deps_installed() -> bool:
    """Return True only if a *complete* npm install has previously succeeded.

    Checking that ``node_modules/`` exists is not enough: a prior install that
    was killed (Ctrl+C, OOM, disk full) leaves a partial directory. npm writes
    ``node_modules/.package-lock.json`` at the *end* of a successful install,
    so we use that as the completion sentinel.
    """
    return (_JS_PARSER_DIR / "node_modules" / ".package-lock.json").is_file()


def _ensure_js_parser_dependencies() -> None:
    """Install the JS parser's Node dependencies on first use.

    Mirrors the Go CLI's venv bootstrap (apps/openant-cli/internal/python/runtime.go):
    the first invocation installs, subsequent invocations are a no-op. Runs only
    when a JS repo is actually being parsed, so Python/Go-only users never need npm.

    Concurrency: uses a lockfile so two parallel parses don't both run
    ``npm install`` in the same directory (which can corrupt node_modules).
    """
    if _js_deps_installed():
        return

    if not (_JS_PARSER_DIR / "package.json").is_file():
        raise RuntimeError(
            f"JS parser package.json not found at {_JS_PARSER_DIR / 'package.json'}. "
            "The openant-core install may be incomplete."
        )

    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError(
            "JavaScript parser dependencies are not installed and `npm` is not on PATH. "
            f"Install Node.js/npm, then run: npm install (from {_JS_PARSER_DIR})"
        )

    # Serialize concurrent bootstraps. The lockfile lives next to package.json so
    # it's always on the same filesystem as the install target.
    lock_path = _JS_PARSER_DIR / ".openant-npm-install.lock"
    with _file_lock(lock_path):
        # Re-check under the lock: another process may have finished while we waited.
        if _js_deps_installed():
            return

        print(
            "[Parser] Installing JS parser dependencies (first run, this may take a minute)...",
            file=sys.stderr,
        )
        # #325: PR #135 bounded the parse subprocesses and named this call
        # as a deferred follow-up ("a separate unbounded subprocess... a
        # tracked follow-up, out of scope here") — the follow-up. A stalled
        # npm (a blocking postinstall script, a registry stall outlasting
        # npm's own retry budget) hung its process indefinitely AND every
        # concurrent parse behind the lock it holds. The parse steps use
        # timeout=1800; the bootstrap gets the same convention. The named
        # diagnosis (not a bare TimeoutExpired traceback): the bound + the
        # manual recovery.
        result = subprocess.run(
            [npm, "install"],
            cwd=str(_JS_PARSER_DIR),
            stdout=sys.stderr,
            stderr=sys.stderr,
            timeout=1800,  # 30 min — the parse-step convention (PR #135)
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"`npm install` failed in {_JS_PARSER_DIR} with exit code "
                f"{result.returncode}. See npm output above for details; you can "
                f"reproduce with: npm install (from {_JS_PARSER_DIR})"
            )


@contextlib.contextmanager
def _file_lock(lock_path: Path):
    """Cross-platform exclusive file lock as a context manager.

    Uses ``msvcrt`` on Windows and ``fcntl`` elsewhere. Blocks until the lock is
    acquired, releases on exit. The lockfile itself is left in place; only the
    OS-level lock matters for mutual exclusion.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # "w" (not "a+") so the file pointer is at byte 0 — msvcrt.locking locks a
    # range starting at the *current* file position, so different positions
    # would mean non-overlapping (i.e. non-exclusive) locks.
    f = open_utf8(lock_path, "w")
    try:
        if os.name == "nt":
            import msvcrt

            f.seek(0)
            # LK_LOCK blocks (with retries) until the byte range is
            # exclusive. #325: bounded — LK_LOCK's retry budget is ~10s
            # then raises OSError, i.e. already deadline-bounded here.
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            import time

            # #325: a bare blocking LOCK_EX waits without limit behind a
            # wedged holder (a stalled npm holding this lock hung EVERY
            # concurrent parse process). Non-blocking acquisition in a
            # retry loop with a deadline — the bounded wait the issue asks
            # for; a timeout raises a named diagnosis, not an infinite
            # hang. The deadline must outlast a legitimate install (the
            # bounded npm install inside the lock holds it for up to 30
            # minutes), so the retry budget is the install bound + 5
            # minutes of slack.
            _lock_deadline = time.monotonic() + 1800 + 300
            while True:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= _lock_deadline:
                        raise RuntimeError(
                            f"the npm-install bootstrap lock at {lock_path} "
                            "was not acquired within 2100s (a concurrent "
                            "install is wedged — a stall beyond the 1800s "
                            "install bound). Re-run; if it persists, remove "
                            "the stalled process or the lockfile."
                        )
                    time.sleep(1.0)
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()


def _parse_via_subprocess(
    language: str,
    repo_path: str,
    output_dir: str,
    processing_level: str,
    skip_tests: bool = True,
    name: str = None,
    library_mode: bool = False,
) -> ParseResult:
    """Invoke a language's parser as a subprocess.

    Every non-Python parser shares one argv contract::

        <script> <repo_path> --output <dir> --processing-level <level>
                 [--name N] [--skip-tests] [--library-mode]

    and writes the same artifact set into *output_dir*. This used to be six
    near-identical function bodies (javascript, go, c, ruby, php, zig) that
    differed only in a log string, a script path, a language literal, and — for
    JavaScript alone — an npm bootstrap. Collapsing them means adding a
    language is a `config/languages.json` edit plus a `parsers/<lang>/`
    directory, rather than another copy of this function.

    The script path and the bootstrap hook both come from the registry, so the
    dispatch table and the detection table can no longer disagree.

    Args:
        language: Registry language name.
        repo_path: Absolute path to the repository to parse.
        output_dir: Directory to write dataset.json / analyzer_output.json into.
        processing_level: "all", "reachable", "codeql" or "exploitable".
        skip_tests: Exclude test files from parsing.
        name: Dataset name override.
        library_mode: Seed the public API surface as reachability entry points.

    Returns:
        ParseResult for this language.

    Raises:
        RuntimeError: If the parser subprocess exits non-zero.
        ValueError: If the language has no registered subprocess parser.
    """
    spec = load_registry().get(language)
    if spec is None or spec.parser_mode != "subprocess":
        raise ValueError(f"No subprocess parser registered for language: {language}")

    # Per-language pre-hook. Only JavaScript has one: its parser carries its
    # own package.json and needs node_modules present before it can run.
    if spec.bootstrap == "npm":
        _ensure_js_parser_dependencies()

    print(f"[Parser] Running {language} parser...", file=sys.stderr)

    parser_script = parser_script_path(language)
    if parser_script is None:
        # #273: the guard rejected the config's parser.script (absolute
        # path, .. escape, or symlink escape out of the engine root) or the
        # language has no script. Say THAT — a bare str(None) spawn would
        # fail with a misleading generic RuntimeError exactly in the
        # hostile-config scenario this guard exists for.
        raise RuntimeError(
            f"No runnable parser script for language {language!r}: the "
            "registry entry has no parser.script, or its value was "
            "rejected by the engine-root containment guard "
            "(config/languages.json may come from an untrusted source — "
            "see parser_script_path)"
        )

    cmd = [
        sys.executable, str(parser_script),
        repo_path,
        "--output", output_dir,
        "--processing-level", processing_level,
    ]

    if name:
        cmd.extend(["--name", name])
    if skip_tests:
        cmd.append("--skip-tests")
    if library_mode:
        cmd.append("--library-mode")

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,  # 30 min — large repos, tree-sitter/Node/Go toolchains
        # #303: the child resolves THIS checkout by construction — the shared
        # venv's editable .pth (re-pointable mid-scan by a concurrent session)
        # cannot win over an explicit PYTHONPATH entry.
        env=child_interpreter_env(),
    )

    if result.returncode != 0:
        raise RuntimeError(f"{language} parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  {language} parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language=language,
        processing_level=processing_level,
    )


# Named aliases, preserved so any test or downstream import that references a
# parser by its original symbol keeps working.
_parse_javascript = functools.partial(_parse_via_subprocess, "javascript")
_parse_go = functools.partial(_parse_via_subprocess, "go")
_parse_c = functools.partial(_parse_via_subprocess, "c")
_parse_ruby = functools.partial(_parse_via_subprocess, "ruby")
_parse_php = functools.partial(_parse_via_subprocess, "php")
_parse_zig = functools.partial(_parse_via_subprocess, "zig")

ParserFn = Callable[..., ParseResult]


def _parser_for(language: str) -> ParserFn:
    """Resolve the parser callable for a language.

    Resolution order matters:

    1. A module-level ``_parse_<language>`` attribute, looked up DYNAMICALLY.
       This is what preserves the long-standing monkeypatch seam — tests swap
       ``parser_adapter._parse_python`` to stub out parsing (see
       tests/test_parse_fresh.py). Capturing the function object once at import
       time would silently ignore those patches, turning a stubbed test into a
       real parse.
    2. Otherwise, build the subprocess parser straight from the registry, so a
       language added to ``config/languages.json`` works without also needing a
       hand-written alias here.

    Raises:
        KeyError: If the language is not in the registry.
        ValueError: If the registry marks it in-process but no implementation
            is bound — a config error, not a user error.
    """
    spec = load_registry()[language]

    override = globals().get(f"_parse_{language}")
    if override is not None:
        return override

    if spec.parser_mode == "inprocess":
        raise ValueError(
            f"Language {language!r} is registered as in-process but has no "
            f"_parse_{language} implementation."
        )
    return functools.partial(_parse_via_subprocess, language)
