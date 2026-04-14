"""
Unified parser interface.

Wraps language-specific parsers (Python, JavaScript, Go, C, Ruby, PHP) with
a single function signature that accepts a repo path and returns dataset +
analyzer output.

Each parser is invoked as a subprocess to avoid import conflicts with
sys.path hacks in the original code.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from core.schemas import ParseResult

# Root of openant-core (where parsers/ lives)
_CORE_ROOT = Path(__file__).parent.parent


def detect_language(repo_path: str) -> str:
    """Auto-detect the primary language of a repository.

    Counts source files by extension and returns the dominant language.

    Returns:
        "python", "javascript", or "go"
    """
    repo = Path(repo_path)
    counts = {"python": 0, "javascript": 0, "go": 0, "c": 0, "ruby": 0, "php": 0, "zig": 0}

    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        # Skip common non-source dirs
        parts = f.parts
        if any(p in parts for p in (
            "node_modules", "__pycache__", "venv", ".venv",
            "dist", "build", ".git", "vendor",
        )):
            continue

        suffix = f.suffix.lower()
        if suffix == ".py":
            counts["python"] += 1
        elif suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            counts["javascript"] += 1
        elif suffix == ".go":
            counts["go"] += 1
        elif suffix in (".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hxx", ".hh"):
            counts["c"] += 1
        elif suffix in (".rb", ".rake"):
            counts["ruby"] += 1
        elif suffix == ".php":
            counts["php"] += 1
        elif suffix == ".zig":
            counts["zig"] += 1

    if not any(counts.values()):
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

    Returns:
        ParseResult with paths to generated files and stats.

    Raises:
        ValueError: If language can't be detected or is unsupported.
        RuntimeError: If the parser subprocess fails.
    """
    repo_path = os.path.abspath(repo_path)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # Detect language if auto
    if language == "auto":
        language = detect_language(repo_path)
        print(f"  Auto-detected language: {language}", file=sys.stderr)

    # Dispatch to the right parser
    if language == "python":
        return _parse_python(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "javascript":
        return _parse_javascript(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "go":
        return _parse_go(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "c":
        return _parse_c(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "ruby":
        return _parse_ruby(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "php":
        return _parse_php(repo_path, output_dir, processing_level, skip_tests, name)
    elif language == "zig":
        return _parse_zig(repo_path, output_dir, processing_level, skip_tests, name)
    else:
        raise ValueError(f"Unsupported language: {language}")


# ---------------------------------------------------------------------------
# Reachability filter (shared by Python path; JS/Go handle it internally)
# ---------------------------------------------------------------------------

def _apply_reachability_filter(
    dataset: dict,
    output_dir: str,
    processing_level: str,
) -> dict:
    """Filter dataset units to only those reachable from entry points.

    Reads the call_graph.json intermediate file produced by the parser,
    detects entry points, computes reachability via BFS, and removes
    unreachable units from the dataset.

    For ``codeql`` and ``exploitable`` levels the reachability filter is
    still applied (it is a prerequisite), but the additional CodeQL /
    LLM-classification filters are not yet wired into the Python path
    and a warning is printed.

    Args:
        dataset: The full, unfiltered dataset dict (mutated in place).
        output_dir: Directory containing call_graph.json from the parser.
        processing_level: One of "reachable", "codeql", "exploitable".

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

    with open(call_graph_path, "r") as f:
        call_graph_data = json.load(f)

    functions = call_graph_data.get("functions", {})
    call_graph = call_graph_data.get("call_graph", {})
    reverse_call_graph = call_graph_data.get("reverse_call_graph", {})

    # Detect entry points
    detector = EntryPointDetector(functions, call_graph)
    entry_points = detector.detect_entry_points()

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
            u["is_entry_point"] = unit_id in entry_points
            if unit_id in entry_points:
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
    with open(dataset_path, "w") as f:
        json.dump(dataset, f, indent=2)

    with open(analyzer_output_path, "w") as f:
        json.dump(analyzer_output, f, indent=2)

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

def _parse_javascript(repo_path: str, output_dir: str, processing_level: str, skip_tests: bool = True, name: str = None) -> ParseResult:
    """Invoke the JavaScript/TypeScript parser.

    The JS parser is a PipelineTest class that runs Node.js subprocesses.
    We invoke it via subprocess to avoid the sys.path hacks.
    """
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
        with open(dataset_path) as f:
            data = json.load(f)
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
        with open(dataset_path) as f:
            data = json.load(f)
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
        with open(dataset_path) as f:
            data = json.load(f)
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
        with open(dataset_path) as f:
            data = json.load(f)
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
        with open(dataset_path) as f:
            data = json.load(f)
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
        with open(dataset_path) as f:
            data = json.load(f)
        units_count = len(data.get("units", []))

    print(f"  Zig parser complete: {units_count} units", file=sys.stderr)

    return ParseResult(
        dataset_path=dataset_path,
        analyzer_output_path=analyzer_output_path if os.path.exists(analyzer_output_path) else None,
        units_count=units_count,
        language="zig",
        processing_level=processing_level,
    )
