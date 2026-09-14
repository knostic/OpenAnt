"""#600: the discovery-stage exclusion counters reach the artifacts operators
read — the excluded directories are NAMED, not a bare count.

Three layers, one doctrine (absence ≠ zero, #307/#606):

* the PRODUCERS: every scanner that prunes directories records a
  name-keyed histogram (``excluded_dir_names``) with entry-relative
  examples — retention is RESERVED for the scanner's effective exclusion
  set (``build``, ``env``, ``migrations`` … — the literal names; a
  first-seen cap would fill with ``__pycache__`` before reaching the one
  example the issue exists for), dynamic names bounded separately with
  the overflow DISCLOSED as an occurrence count.
* the AGGREGATOR: a per-language ``discovery`` block (language → name →
  count — the cross-language sum is prune observations, never unique
  directories), per-FIELD missing-data disclosure (a language carrying
  ``directories_excluded`` does not imply it instruments the histogram),
  and the failed-language rule (a failed parse's stale artifact is never
  mistaken for another language's data).
* the CONSUMERS: the scan path's parse step summary, the STANDALONE
  ``parse`` path (both construct ``parse.report.json`` — fixing only the
  scan leaves the CLI blind), the pipeline-output bridge, and the
  generated summary's Discovery line.

The honest RED is the artifact assertion: pristine code writes no
discovery anywhere; the producers' histograms do not exist.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parsers.python.repository_scanner import RepositoryScanner  # noqa: E402


# ---------------------------------------------------------------------------
# the producer: the Python scanner names its excluded directories
# ---------------------------------------------------------------------------

def _scan_repo(tmp_path, dirs, files=("m.py",)):
    repo = tmp_path / "repo"
    repo.mkdir()
    for name in dirs:
        (repo / name).mkdir()
        for f in files:
            (repo / name / f).write_text("x = 1\n")
    (repo / "root.py").write_text("y = 2\n")
    return RepositoryScanner(str(repo)).scan()


def test_excluded_names_histogram_names_the_first_party_dirs(tmp_path):
    """build/, env/, migrations/ — the issue's own examples — appear BY NAME
    with exact counts, alongside the high-frequency noise."""
    out = _scan_repo(tmp_path, ["build", "env", "migrations", "__pycache__"])
    stats = out["statistics"]
    hist = stats["excluded_dir_names"]
    assert hist["build"] == 1
    assert hist["env"] == 1
    assert hist["migrations"] == 1
    assert hist["__pycache__"] == 1
    # the bare count still counts every prune
    assert stats["directories_excluded"] == 4


def test_entry_relative_examples_per_reserved_name(tmp_path):
    """Each retained name carries 1-2 ENTRY-RELATIVE example paths (never
    absolute — the username leak the coverage examples once had)."""
    (tmp_path / "pkg").mkdir()
    repo = tmp_path / "pkg" / "repo"
    repo.mkdir()
    (repo / "build").mkdir()
    (repo / "build" / "m.py").write_text("x = 1\n")
    out = RepositoryScanner(str(repo)).scan()
    ex = out["statistics"]["excluded_dir_examples"]["build"]
    assert len(ex) >= 1
    assert not ex[0].startswith("/")
    assert "repo" not in ex[0]  # relative to the REPO, not the host
    assert ex[0] == "build"


def test_repeated_scans_reset_and_recount(tmp_path):
    """The histogram lives in scan()'s reset (not __init__): a second scan
    of the same tree reports the same counts, not doubled ones."""
    first = _scan_repo(tmp_path, ["build"])
    second = RepositoryScanner(str(tmp_path / "repo")).scan()
    assert first["statistics"]["excluded_dir_names"] == \
        second["statistics"]["excluded_dir_names"]
    assert second["statistics"]["excluded_dir_names"]["build"] == 1


def test_dynamic_name_saturation_discloses_overflow(tmp_path):
    """Dynamic names (not in the scanner's effective exclusion set) are
    bounded: the first D distinct names retained, later occurrences summed
    into the overflow count — the exact total preserved, truncation
    disclosed. The exact total is never claimed as the retained-count."""
    # 30 distinct dynamic names (pattern-excluded: the .egg-info suffix)
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(30):
        d = repo / f"pkg{i}-1.0-py3-none-any.egg-info"
        d.mkdir()
        (d / "m.py").write_text("x = 1\n")
    out = RepositoryScanner(str(repo)).scan()
    stats = out["statistics"]
    hist = stats["excluded_dir_names"]
    dynamic = {k: v for k, v in hist.items() if k.endswith(".egg-info")}
    assert len(dynamic) <= 12  # the dynamic bound
    assert stats["excluded_dir_names_overflow"] >= 30 - len(dynamic)
    assert stats["directories_excluded"] == 30  # the exact total


def test_attacker_hostile_names_never_reach_the_artifact(tmp_path):
    """Names with control characters / newlines / absurd length are
    producer-side sanitized: they count, but never become JSON keys or
    prompt tokens."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # PORTABLE hostile names only on the FILESYSTEM (control characters
    # are illegal on NTFS — the control-char class is covered by the
    # recorder-unit test below). A 120-char name is legal on every
    # supported filesystem and over the 100-char artifact bound.
    for name in ("y" * 120 + "-1.0.egg-info", "a" * 99 + "b-1.0.egg-info"):
        d = repo / name
        d.mkdir()
        (d / "m.py").write_text("x = 1\n")
    out = RepositoryScanner(str(repo)).scan()
    hist = out["statistics"]["excluded_dir_names"]
    for k in hist:
        assert all(32 <= ord(c) <= 126 for c in k), repr(k)
        assert len(k) <= 100, repr(k)


def test_hostile_control_names_at_the_recorder_unit():
    """The control-character class — recorder-UNIT (no filesystem: control
    chars in names are illegal on NTFS, so the FS fixture cannot cover
    them on every platform)."""
    from core.repo_walk import ExcludedDirRecorder
    r = ExcludedDirRecorder({"build"})
    r.note("evil\nname", "evil\nname")
    r.note("evil\u001b[31m", "x")
    r.note("", "empty")
    r.note("build", "build")  # the clean one still works
    assert r.names == {"build": 1}
    assert r.overflow == 3
    assert r.examples == {"build": ["build"]}


# ---------------------------------------------------------------------------
# the walker-delegating producers: the histogram survives their
# hand-rebuilt statistics projections (rust/zig reconstruct their dicts)
# ---------------------------------------------------------------------------

def test_walker_scanners_project_the_histogram(tmp_path):
    """Every walker-delegating scanner's RETURNED statistics carry the
    histogram — the walker instrumentation survives the projection."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "build").mkdir()
    (repo / "build" / "lib.rs").write_text("pub fn f() {}\n")
    (repo / "root.rs").write_text("pub fn g() {}\n")
    from parsers.rust.repository_scanner import (
        RepositoryScanner as RustScanner,
    )
    out = RustScanner(str(repo)).scan()
    stats = out["statistics"]
    assert stats["excluded_dir_names"].get("build") == 1
    assert stats["directories_excluded"] >= 1
    ex = stats["excluded_dir_examples"].get("build", [])
    assert ex and ex[0] == "build"

# ---------------------------------------------------------------------------
# the aggregator: per-language, per-field, failed-language-aware
# ---------------------------------------------------------------------------

def _write_scan_result(dir_path, statistics):
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "scan_result.json").write_text(
        json.dumps({"statistics": statistics}))
    return str(dir_path)


def _discovery_result(**per_language):
    from core.scanner import ScanResult, _collect_discovery
    langs = list(per_language)
    r = ScanResult(output_dir="/unused", language=langs[0] if langs else "python",
                   languages=langs or ["python"])
    r.per_language = {k: {"output_dir": v} for k, v in per_language.items()}
    return _collect_discovery(r), r


def test_aggregator_attributes_by_language(tmp_path):
    py = _write_scan_result(tmp_path / "py-out", {
        "directories_excluded": 3, "shebang_files_detected": 2,
        "excluded_dir_names": {"build": 2, "env": 1},
        "excluded_dir_examples": {"build": ["build"]},
        "excluded_dir_names_overflow": 0,
    })
    block, _ = _discovery_result(python=py)
    assert block["per_language"]["python"]["excluded_dir_names"]["build"] == 2
    assert "languages_without_discovery_data" not in block
    assert "fields_missing_by_language" not in block


def test_per_field_disclosure_never_sums_partial_as_complete(tmp_path):
    """A language carrying the flat count but NOT the histogram is partially
    instrumented: disclosed per field, never summed as if complete."""
    partial = _write_scan_result(tmp_path / "partial-out", {
        "directories_excluded": 5,  # the flat count only — pre-#600 shape
    })
    block, _ = _discovery_result(c=partial)
    assert block["per_language"]["c"]["directories_excluded"] == 5
    assert "excluded_dir_names" in \
        block["fields_missing_by_language"]["c"]


def test_the_js_camelcase_alias_supplies_the_count_only(tmp_path):
    js = _write_scan_result(tmp_path / "js-out", {
        "directoriesExcluded": 7,  # the camelCase alias
    })
    block, _ = _discovery_result(javascript=js)
    assert block["per_language"]["javascript"]["directories_excluded"] == 7
    # the histogram stays UNKNOWN for that language (disclosed, not zero)
    assert "excluded_dir_names" in \
        block["fields_missing_by_language"]["javascript"]


def test_failed_language_disclosed_never_fell_back(tmp_path):
    """A failed parse's stale artifact is never read; it is disclosed."""
    ok_dir = _write_scan_result(tmp_path / "py-out", {
        "directories_excluded": 1,
    })
    from core.scanner import ScanResult, _collect_discovery
    r = ScanResult(output_dir="/unused", language="python", languages=["python", "go"])
    r.per_language = {
        "python": {"output_dir": ok_dir},
        "go": {"output_dir": str(tmp_path / "go-out"), "ok": False},
    }
    (tmp_path / "go-out").mkdir()
    _write_scan_result(tmp_path / "go-out", {"directories_excluded": 99})
    block = _collect_discovery(r)
    assert block["failed_languages"] == ["go"]
    assert "go" not in block["per_language"]  # the stale 99 never read
    assert block["per_language"]["python"]["directories_excluded"] == 1


# ---------------------------------------------------------------------------
# the consumers: both entry points construct parse.report.json
# ---------------------------------------------------------------------------

def test_scan_path_parse_report_carries_discovery(monkeypatch, tmp_path):
    """The plumbing proof: the REAL scan path's parse.report.json carries
    the discovery block (read off disk; the offline scaffold)."""
    from core import scanner as scanner_mod
    from tests.test_pr69_report_llmconfig_forwarding import (
        _install_minimal_pipeline, _offline_registry,  # noqa: F401
    )
    from core import parser_adapter
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "build").mkdir()
    (tmp_path / "repo" / "build" / "m.py").write_text("x = 1\n")
    (tmp_path / "repo" / "root.py").write_text("y = 2\n")
    _install_minimal_pipeline(monkeypatch)
    # Self-sufficient offline guarantees (the shared plugin fixture is a
    # belt; this is the braces): the probe neutered MODULE-LOCALLY (the
    # call-time import resolves utilities.llm at scan time — patching the
    # module attribute takes effect), and the dummy key for any adapter
    # construction. NO request can go out: the probe is a no-op and every
    # LLM stage is off/stubbed.
    import utilities.llm as _llm_mod
    monkeypatch.setattr(_llm_mod, "probe_registry_or_raise",
                        lambda *a, **k: None, raising=True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-offline-000")
    # The shared scaffold's parse stub does not write scan_result.json (the
    # aggregator's input artifact) — wrap it to write a REAL one so this
    # test exercises the reader end to end.
    _orig_stub = parser_adapter.parse_repository
    def _stub_with_scan_result(*, output_dir, **kwargs):
        pr = _orig_stub(output_dir=output_dir, **kwargs)
        from pathlib import Path as _P
        _sr = _P(output_dir) / "scan_result.json"
        _sr.write_text(json.dumps({"statistics": {
            "directories_excluded": 1,
            "excluded_dir_names": {"build": 1},
            "excluded_dir_examples": {"build": ["build"]},
            "excluded_dir_names_overflow": 0,
            "shebang_files_detected": 0,
        }}))
        return pr
    monkeypatch.setattr(parser_adapter, "parse_repository",
                         _stub_with_scan_result)
    monkeypatch.chdir(tmp_path)
    scanner_mod.scan_repository(
        repo_path="repo", output_dir="out",
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False, llm_reachability=False,
    )
    report = json.loads((tmp_path / "out" / "parse.report.json").read_text())
    disc = report["summary"]["discovery"]
    assert disc["per_language"]["python"]["excluded_dir_names"]["build"] == 1


def test_standalone_parse_report_carries_discovery(monkeypatch, tmp_path):
    """The STANDALONE parse entry point (`parse` without the scan pipeline)
    constructs the same parse.report.json — the discovery block reaches it
    too, or the CLI path stays blind."""
    import subprocess, sys as _sys
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "build").mkdir()
    (tmp_path / "repo" / "build" / "m.py").write_text("x = 1\n")
    (tmp_path / "repo" / "root.py").write_text("y = 2\n")
    out = tmp_path / "out"
    proc = subprocess.run(
        [_sys.executable, "-m", "openant.cli", "parse",
         str(tmp_path / "repo"), "--output", str(out)],
        capture_output=True, text=True, timeout=120,
        cwd=str(PROJECT_ROOT))  # THIS worktree's openant resolves first
    assert proc.returncode == 0, proc.stderr[-2000:]
    report = json.loads((out / "parse.report.json").read_text())
    disc = report["summary"]["discovery"]
    assert disc["per_language"]["python"]["excluded_dir_names"]["build"] == 1


def test_summary_template_states_the_discovery_line():
    """The generated summary's prompt instructs the Discovery rendering —
    a disclosure nobody sees is the failure mode this fix targets."""
    src = (PROJECT_ROOT / "report" / "prompts" / "summary.txt").read_text()
    assert "Discovery section" in src
    assert "unknown (not zero)" in src
    assert "excluded_dir_names" in src
    assert "directories_excluded" in src  # the flat count renders too
    assert "fields_missing_by_language" in src  # the per-field qualification


# ---------------------------------------------------------------------------
# the producer census: ALL SEVEN Python-family scanners (the hunt's R05 fix —
# a single-scanner test let swift's false-zero and ruby's absence slip)
# ---------------------------------------------------------------------------

_SCANNERS = [
    ("python", "parsers.python.repository_scanner", "RepositoryScanner", ".py"),
    ("rust", "parsers.rust.repository_scanner", "RepositoryScanner", ".rs"),
    ("zig", "parsers.zig.repository_scanner", "RepositoryScanner", ".zig"),
    ("swift", "parsers.swift.repository_scanner", "RepositoryScanner", ".swift"),
    ("c", "parsers.c.repository_scanner", "RepositoryScanner", ".c"),
    ("php", "parsers.php.repository_scanner", "RepositoryScanner", ".php"),
    ("ruby", "parsers.ruby.repository_scanner", "RepositoryScanner", ".rb"),
]


def test_all_scanners_name_their_excluded_dirs(tmp_path, request):
    """The parametrized census: every Python-family scanner names build/ with
    the exact count and an entry-relative example — the test that would have
    caught swift's false-zero projection and ruby's missing instrumentation."""
    import importlib
    for lang, mod_name, cls_name, ext in _SCANNERS:
        repo = tmp_path / f"repo-{lang}"
        repo.mkdir()
        (repo / "build").mkdir()
        (repo / "build" / f"lib{ext}").write_text("x = 1\n")
        (repo / f"root{ext}").write_text("y = 2\n")
        mod = importlib.import_module(mod_name)
        scanner = getattr(mod, cls_name)(str(repo))
        stats = scanner.scan()["statistics"]
        assert stats.get("excluded_dir_names", {}).get("build") == 1, (
            f"{lang}: the histogram must name build/ (got "
            f"{stats.get('excluded_dir_names')})")
        assert stats["directories_excluded"] >= 1, lang
        ex = stats.get("excluded_dir_examples", {}).get("build", [])
        assert ex and ex[0] == "build", f"{lang}: entry-relative example (got {ex})"


def test_second_scan_same_instance_does_not_double(tmp_path):
    """The c/php reset hazard: ONE scanner instance, TWO scan() calls — the
    histogram must not double while the flat count resets."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "build").mkdir()
    (repo / "build" / "lib.c").write_text("int x;\n")
    (repo / "root.c").write_text("int y;\n")
    from parsers.c.repository_scanner import RepositoryScanner as CScanner
    sc = CScanner(str(repo))
    first = sc.scan()["statistics"]
    second = sc.scan()["statistics"]
    assert first["excluded_dir_names"] == second["excluded_dir_names"]
    assert second["excluded_dir_names"]["build"] == 1


def test_stale_artifact_not_misattributed(tmp_path):
    """A REUSED output dir carries the prior language's scan_result.json
    beside the current language's scan_results.json — the reader takes the
    NEWEST by mtime, never the stale one (the hunt's P2)."""
    import os
    from core.scanner import _read_stats_fields
    d = tmp_path / "out"
    d.mkdir()
    (d / "scan_result.json").write_text(json.dumps({"statistics": {
        "directories_excluded": 44, "excluded_dir_names": {"stale": 44}}}))
    (d / "scan_results.json").write_text(json.dumps({"statistics": {
        "directories_excluded": 7}}))
    # explicit mtimes (no sleep-tie on coarse-mtime filesystems)
    os.utime(d / "scan_result.json", (1000000, 1000000))
    os.utime(d / "scan_results.json", (2000000, 2000000))
    out = _read_stats_fields(str(d), ("directories_excluded",
                                     "excluded_dir_names"))
    assert out["directories_excluded"] == 7
    assert "excluded_dir_names" not in out  # the stale 44 never read


def test_hostile_names_that_are_actually_excluded(tmp_path):
    """The sanitization exercised FOR REAL: names that TRIGGER exclusion
    (the egg-info suffix predicate) while bearing control characters —
    counted into overflow, never keyed, never exemplified (the hunt's
    vacuous-test P3)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # hostile names that match the .egg-info exclusion pattern — PORTABLE
    # hostility only (oversized-but-legal; the control-char class is at
    # the recorder-unit level — NTFS cannot create those names)
    (repo / ("y" * 120 + "-1.0.egg-info")).mkdir()
    (repo / ("z" * 105 + "-2.0.egg-info")).mkdir()
    (repo / "build").mkdir()
    (repo / "build" / "m.py").write_text("x = 1\n")
    out = RepositoryScanner(str(repo)).scan()["statistics"]
    hist = out["excluded_dir_names"]
    for k in hist:
        assert all(32 <= ord(c) <= 126 for c in k), repr(k)
    assert "build" in hist
    assert out["excluded_dir_names_overflow"] >= 2
    assert out["directories_excluded"] == 3  # the exact total


def test_mtime_tie_disclosed_not_guessed(tmp_path):
    """Both artifacts, ONE coarse tick: ambiguous — read neither (the tie
    is disclosed as without-data, never guessed by filename order)."""
    import os
    from core.scanner import _read_stats_fields
    d = tmp_path / "out"
    d.mkdir()
    (d / "scan_result.json").write_text(json.dumps({"statistics": {
        "directories_excluded": 44}}))
    (d / "scan_results.json").write_text(json.dumps({"statistics": {
        "directories_excluded": 7}}))
    os.utime(d / "scan_result.json", (1000000, 1000000))
    os.utime(d / "scan_results.json", (1000000, 1000000))  # the TIE
    assert _read_stats_fields(str(d), ("directories_excluded",)) == {}


def test_clean_name_under_nonascii_ancestor_counts_example_withheld(tmp_path):
    """The count/example gate split (the hunt round-3 shape): a clean ASCII
    name under a legitimate non-ASCII ancestor COUNTS (the exact-total
    contract) and is retained — only its example path is withheld."""
    repo = tmp_path / "repo"
    repo.mkdir()
    anc = repo / "données"  # a legitimate non-ASCII directory
    anc.mkdir()
    (anc / "build").mkdir()
    (anc / "build" / "m.py").write_text("x = 1\n")
    (repo / "root.py").write_text("y = 2\n")
    out = RepositoryScanner(str(repo)).scan()["statistics"]
    hist = out["excluded_dir_names"]
    assert hist.get("build") == 1  # counted + retained despite the ancestor
    assert out["directories_excluded"] == 1
    assert out["excluded_dir_names_overflow"] == 0  # not treated as hostile
    assert "build" not in out["excluded_dir_examples"]  # example withheld
