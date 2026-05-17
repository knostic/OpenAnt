"""
Unified parser interface.

Wraps language-specific parsers (Python, JavaScript, Go, C, Ruby, PHP) with
a single function signature that accepts a repo path and returns dataset +
analyzer output.

Each parser is invoked as a subprocess to avoid import conflicts with
sys.path hacks in the original code.
"""

import contextlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from core.schemas import ParseResult
from utilities.file_io import open_utf8, read_json, write_json

# Root of openant-core (where parsers/ lives)
_CORE_ROOT = Path(__file__).parent.parent

# JS parser directory (holds its own package.json / node_modules)
_JS_PARSER_DIR = _CORE_ROOT / "parsers" / "javascript"

# Shared language detection config (single source of truth: config/languages.json)
_LANGUAGES_CONFIG = Path(__file__).parent.parent.parent.parent / "config" / "languages.json"


def _load_language_config() -> dict:
    return read_json(_LANGUAGES_CONFIG)


def detect_language(repo_path: str) -> str:
    """Auto-detect the primary language of a repository.

    Counts source files by extension and returns the dominant language.
    Extension mappings and skip directories are loaded from config/languages.json.

    Returns:
        One of: "python", "javascript", "go", "c", "ruby", "php", "zig"
    """
    config = _load_language_config()
    skip_dirs = set(config["skip_dirs"])
    extensions = config["extensions"]

    repo = Path(repo_path)
    counts: dict[str, int] = {}

    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        # Skip configured non-source dirs
        if any(p in skip_dirs for p in f.parts):
            continue

        suffix = f.suffix.lower()
        if suffix in extensions:
            lang = extensions[suffix]
            counts[lang] = counts.get(lang, 0) + 1

    if not counts:
        raise ValueError(
            f"No supported source files found in {repo_path}. "
            "Supported languages: Python, JavaScript/TypeScript, Go, C/C++, Ruby, PHP, Zig."
        )

    return max(counts, key=counts.get)


def parse_repository(
    repo_path: str,
    output_dir: str,
    language: str = "auto",
    processing_level: str = "reachable",
    skip_tests: bool = True,
    name: str = None,
    diff_manifest: str | None = None,
    fresh: bool = False,
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

    # Dispatch to the right parser
    if language == "python":
        result = _parse_python(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "javascript":
        result = _parse_javascript(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "go":
        result = _parse_go(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "c":
        result = _parse_c(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "ruby":
        result = _parse_ruby(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "php":
        result = _parse_php(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "zig":
        result = _parse_zig(repo_path, output_dir, processing_level, skip_tests, name)
    else:
        raise ValueError(f"Unsupported language: {language}")

    _maybe_apply_diff_filter(result, output_dir, diff_manifest)
    return result


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

def apply_reachability_filter(
    dataset: dict,
    output_dir: str,
    processing_level: str,
    extra_entry_points: "set[str] | None" = None,
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

    # Compute reachable set (BFS forward from entry points)
    reachability = ReachabilityAnalyzer(
        functions=functions,
        reverse_call_graph=reverse_call_graph,
        entry_points=entry_points,
    )
    reachable_ids = reachability.get_all_reachable()

    # Filter dataset units and stamp reachability tags
    units = dataset.get("units", [])
    original_count = len(units)
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

def _parse_python(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
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
        dataset = _apply_reachability_filter(dataset, output_dir, processing_level)

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
        result = subprocess.run(
            [npm, "install"],
            cwd=str(_JS_PARSER_DIR),
            stdout=sys.stderr,
            stderr=sys.stderr,
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
            # LK_LOCK blocks (with retries) until the byte range is exclusive.
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()


def _parse_javascript(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the JavaScript/TypeScript parser.

    The JS parser is a PipelineTest class that runs Node.js subprocesses.
    We invoke it via subprocess to avoid the sys.path hacks.
    """
    _ensure_js_parser_dependencies()

    print("[Parser] Running JavaScript parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "javascript" / "test_pipeline.py"

    # Build command — analyzer-path now defaults to co-located file in the parser
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

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
    )

    if result.returncode != 0:
        raise RuntimeError(f"JavaScript parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  JavaScript parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="javascript",
        processing_level=processing_level,
    )


# ---------------------------------------------------------------------------
# Go parser
# ---------------------------------------------------------------------------

def _parse_go(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the Go parser.

    The Go parser is a PipelineTest class that calls a compiled Go binary.
    We invoke it via subprocess.
    """
    print("[Parser] Running Go parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "go" / "test_pipeline.py"

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

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
    )

    if result.returncode != 0:
        raise RuntimeError(f"Go parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  Go parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="go",
        processing_level=processing_level,
    )


# ---------------------------------------------------------------------------
# C/C++ parser
# ---------------------------------------------------------------------------

def _parse_c(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the C/C++ parser.

    The C parser uses tree-sitter for function extraction and call graph
    building.  Invoked via subprocess (same pattern as Go/JS parsers).

    Requires: tree-sitter, tree-sitter-c, tree-sitter-cpp
    """
    print("[Parser] Running C/C++ parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "c" / "test_pipeline.py"

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

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,  # 30 min timeout (C repos can be large)
    )

    if result.returncode != 0:
        raise RuntimeError(f"C/C++ parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  C/C++ parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="c",
        processing_level=processing_level,
    )


# ---------------------------------------------------------------------------
# Ruby parser
# ---------------------------------------------------------------------------

def _parse_ruby(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the Ruby parser.

    The Ruby parser uses tree-sitter for function extraction and call graph
    building.  Invoked via subprocess (same pattern as other parsers).

    Requires: tree-sitter, tree-sitter-ruby
    """
    print("[Parser] Running Ruby parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "ruby" / "test_pipeline.py"

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

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Ruby parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  Ruby parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="ruby",
        processing_level=processing_level,
    )


# ---------------------------------------------------------------------------
# PHP parser
# ---------------------------------------------------------------------------

def _parse_php(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the PHP parser.

    The PHP parser uses tree-sitter for function extraction and call graph
    building.  Invoked via subprocess (same pattern as other parsers).

    Requires: tree-sitter, tree-sitter-php
    """
    print("[Parser] Running PHP parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "php" / "test_pipeline.py"

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

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,
    )

    if result.returncode != 0:
        raise RuntimeError(f"PHP parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  PHP parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="php",
        processing_level=processing_level,
    )


# ---------------------------------------------------------------------------
# Zig parser
# ---------------------------------------------------------------------------

def _parse_zig(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the Zig parser.

    The Zig parser uses tree-sitter for function extraction and call graph
    building.  Invoked via subprocess (same pattern as other parsers).

    Requires: tree-sitter, tree-sitter-zig
    """
    print("[Parser] Running Zig parser...", file=sys.stderr)

    parser_script = _CORE_ROOT / "parsers" / "zig" / "test_pipeline.py"

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

    result = subprocess.run(
        cmd,
        stdout=sys.stderr,
        stderr=sys.stderr,
        cwd=str(_CORE_ROOT),
        timeout=1800,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Zig parser failed with exit code {result.returncode}")

    dataset_path = os.path.join(output_dir, "dataset.json")
    analyzer_output_path = os.path.join(output_dir, "analyzer_output.json")

    # Count units
    units_count = 0
    if os.path.exists(dataset_path):
        data = read_json(dataset_path)
        units_count = len(data.get("units", []))

    print(f"  Zig parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="zig",
        processing_level=processing_level,
    )
