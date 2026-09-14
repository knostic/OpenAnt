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

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parsers.python.repository_scanner import RepositoryScanner  # noqa: E402
from parsers.rust.repository_scanner import (  # noqa: E402
    RepositoryScanner as RustScanner,
)
from parsers.swift.repository_scanner import (  # noqa: E402
    RepositoryScanner as SwiftScanner,
)
from parsers.zig.repository_scanner import (  # noqa: E402
    RepositoryScanner as ZigScanner,
)
from parsers.c.repository_scanner import (  # noqa: E402
    RepositoryScanner as CScanner,
)
from parsers.php.repository_scanner import (  # noqa: E402
    RepositoryScanner as PhpScanner,
)
from parsers.ruby.repository_scanner import (  # noqa: E402
    RepositoryScanner as RubyScanner,
)


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
    of the same tree — the SAME instance — reports the same counts, not
    doubled ones (an __init__-only histogram must not satisfy this)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "build").mkdir()
    (repo / "build" / "m.py").write_text("x = 1\n")
    (repo / "root.py").write_text("y = 2\n")
    scanner = RepositoryScanner(str(repo))
    first = scanner.scan()
    second = scanner.scan()
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


def test_nonascii_name_counts_into_overflow_never_keys():
    """A legitimate non-ASCII NAME ('données') counts toward the overflow
    and never keys the artifact — the documented bound (the name-gate half
    of the count/example split; the non-ASCII-ancestor test covers the
    path half)."""
    from core.repo_walk import ExcludedDirRecorder
    r = ExcludedDirRecorder({"build"})
    r.note("données", "x")
    r.note("build", "build")
    assert r.names == {"build": 1}
    assert r.overflow == 1
    assert list(r.examples) == ["build"]


def test_oversized_example_path_withheld_count_kept():
    """A retained name whose example path exceeds the path bound still
    counts and stays retained — only its example is withheld (the path
    gate's length half; the name gate caps names, the path gate caps the
    ancestor chain — repo content is attacker-controlled up to PATH_MAX)."""
    from core.repo_walk import ExcludedDirRecorder
    r = ExcludedDirRecorder({"build"})
    r.note("build", "d/" * 150 + "build")  # ~300 chars — over the bound
    r.note("build", "build")
    assert r.names == {"build": 2}
    assert r.examples == {"build": ["build"]}  # the oversized one withheld


# ---------------------------------------------------------------------------
# the walker-delegating producers: the histogram survives their
# hand-rebuilt statistics projections (rust/zig reconstruct their dicts)
# ---------------------------------------------------------------------------

def test_walker_scanners_project_the_histogram(tmp_path):
    """A walker-delegating scanner's hand-rebuilt RETURNED statistics carry
    the histogram (rust here — the parametrized census below covers every
    scanner; this pins the projection shape at the recorder unit's site)."""
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


def test_single_language_camelcase_alias_folds_identically(tmp_path):
    """The PASSTROUGH branch folds the camelCase alias identically to the
    per-language branch (one shared helper — the two must not drift): the
    canonical spelling always wins, the alias is always removed."""
    from core.scanner import ScanResult, _collect_discovery
    _write_scan_result(tmp_path, {"directoriesExcluded": 5,
                                  "directories_excluded": 3})
    r = ScanResult(output_dir=str(tmp_path), language="javascript",
                   languages=["javascript"])  # per_language stays {}
    block = _collect_discovery(r)
    stats = block["per_language"]["javascript"]
    assert stats["directories_excluded"] == 3  # canonical wins
    assert "directoriesExcluded" not in stats  # the alias always removed
    assert "excluded_dir_names" in block["fields_missing_by_language"]["javascript"]


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


def test_language_without_any_artifact_is_disclosed_not_zeroed(tmp_path):
    """A language whose output dir carries NO scan artifact (the Go
    pipeline-mode runtime contract: `go_parser all` writes neither probed
    filename) lands in languages_without_discovery_data — disclosed,
    never zeroed, never a failed-language entry."""
    empty = tmp_path / "go-out"
    empty.mkdir()
    block, _ = _discovery_result(go=str(empty))
    assert block["per_language"] == {}
    assert block["languages_without_discovery_data"] == ["go"]
    assert "failed_languages" not in block


# ---------------------------------------------------------------------------
# the consumers: both entry points construct parse.report.json
# ---------------------------------------------------------------------------

def test_scan_path_parse_report_carries_discovery(monkeypatch, tmp_path):
    """The plumbing proof: the REAL scan path's parse.report.json carries
    the discovery block (read off disk; the offline scaffold)."""
    from core import scanner as scanner_mod
    from tests.test_pr69_report_llmconfig_forwarding import (
        _install_minimal_pipeline,
    )
    from core import parser_adapter
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "build").mkdir()
    (tmp_path / "repo" / "build" / "m.py").write_text("x = 1\n")
    (tmp_path / "repo" / "root.py").write_text("y = 2\n")
    _install_minimal_pipeline(monkeypatch)
    # Self-sufficient offline guarantees — THE ONLY guard (the pr69
    # module's _offline_registry autouse fixture never engages for THIS
    # module — a fixture declared in another test module is not inherited;
    # the function-local import of it is inert): the probe neutered
    # MODULE-LOCALLY (the call-time import resolves utilities.llm at scan
    # time — patching the module attribute takes effect), and the dummy
    # key for any adapter construction. NO request can go out: the probe
    # is a no-op and every LLM stage is off/stubbed. Do not drop these.
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
    # #600: wrap the scaffold's fake build_pipeline_output to CAPTURE the
    # Step-6 kwargs — the bridge's discovery kwarg is the pin; the fake
    # (which writes "{}") stays the writer.
    import core.reporter as _reporter_mod
    _captured = {}
    _scaffold_fake = _reporter_mod.build_pipeline_output

    def _capturing_build_output(*args, **kwargs):
        _captured.update(kwargs)
        return _scaffold_fake(*args, **kwargs)

    monkeypatch.setattr(_reporter_mod, "build_pipeline_output",
                        _capturing_build_output)
    monkeypatch.chdir(tmp_path)
    scanner_mod.scan_repository(
        repo_path="repo", output_dir="out",
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False, llm_reachability=False,
    )
    report = json.loads((tmp_path / "out" / "parse.report.json").read_text())
    disc = report["summary"]["discovery"]
    assert disc["per_language"]["python"]["excluded_dir_names"]["build"] == 1
    # The Step-6 bridge forwards the same block to build_pipeline_output
    # (captured past the scaffold's fake — the real call site), and the
    # operator's aggregate report carries it beside coverage.
    assert _captured["discovery"]["per_language"]["python"][
        "excluded_dir_names"]["build"] == 1
    sr = json.loads((tmp_path / "out" / "scan.report.json").read_text())
    assert sr["summary"]["discovery"]["per_language"]["python"][
        "excluded_dir_names"]["build"] == 1


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


def test_step_report_forwarder_is_best_effort():
    """#600: _discovery_from_step_reports forwards the parse report's
    block; a parse output elsewhere drops it (present-only downstream)."""
    from openant.cli import _discovery_from_step_reports
    block = {"per_language": {"python": {"directories_excluded": 1}}}
    assert _discovery_from_step_reports(
        [{"step": "parse", "summary": {"discovery": block}}]) == block
    # a non-parse step's block is never forwarded
    assert _discovery_from_step_reports(
        [{"step": "analyze", "summary": {"discovery": block}}]) is None
    # an empty summary, and no step reports at all
    assert _discovery_from_step_reports(
        [{"step": "parse", "summary": {}}]) is None
    assert _discovery_from_step_reports(None) is None


def test_pipeline_output_discovery_is_present_only(tmp_path):
    """#600: build_pipeline_output emits the discovery key only when
    supplied — present-only beside coverage (absent upstream stays absent
    downstream; the standalone build-output/report lanes depend on it)."""
    from core.reporter import build_pipeline_output
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"results": [], "metrics": {}}))
    out1 = tmp_path / "po-none.json"
    build_pipeline_output(str(results), str(out1), repo_name="fixture")
    assert "discovery" not in json.loads(out1.read_text())
    out2 = tmp_path / "po-with.json"
    block = {"per_language": {"python": {"directories_excluded": 1}}}
    build_pipeline_output(str(results), str(out2), repo_name="fixture",
                          discovery=block)
    assert json.loads(out2.read_text())["discovery"] == block


# ---------------------------------------------------------------------------
# the producer census: ALL SEVEN Python-family scanners (the hunt's R05 fix —
# a single-scanner test let swift's false-zero and ruby's absence slip)
# ---------------------------------------------------------------------------

_SCANNERS = [
    ("python", RepositoryScanner, ".py"),
    ("rust", RustScanner, ".rs"),
    ("zig", ZigScanner, ".zig"),
    ("swift", SwiftScanner, ".swift"),
    ("c", CScanner, ".c"),
    ("php", PhpScanner, ".php"),
    ("ruby", RubyScanner, ".rb"),
]


@pytest.mark.parametrize("lang,scanner_cls,ext", _SCANNERS)
def test_all_scanners_name_their_excluded_dirs(tmp_path, lang, scanner_cls,
                                               ext):
    """The parametrized census: every Python-family scanner names build/ with
    the exact count and an entry-relative example — the test that would have
    caught swift's false-zero projection and ruby's missing instrumentation
    (parametrized so one scanner's failure never masks another's; the
    scanners statically imported — no dynamic import surface)."""
    repo = tmp_path / f"repo-{lang}"
    repo.mkdir()
    (repo / "build").mkdir()
    (repo / "build" / f"lib{ext}").write_text("x = 1\n")
    (repo / f"root{ext}").write_text("y = 2\n")
    scanner = scanner_cls(str(repo))
    stats = scanner.scan()["statistics"]
    assert stats.get("excluded_dir_names", {}).get("build") == 1, (
        f"{lang}: the histogram must name build/ (got "
        f"{stats.get('excluded_dir_names')})")
    assert stats["directories_excluded"] >= 1, lang
    ex = stats.get("excluded_dir_examples", {}).get("build", [])
    assert ex and ex[0] == "build", f"{lang}: entry-relative example (got {ex})"


@pytest.mark.parametrize("lang,scanner_cls,ext", [
    ("c", CScanner, ".c"),
    ("php", PhpScanner, ".php"),
    ("ruby", RubyScanner, ".rb"),
])
def test_second_scan_same_instance_does_not_double(tmp_path, lang,
                                                   scanner_cls, ext):
    """The c/php/ruby reset hazard: ONE scanner instance, TWO scan() calls —
    the histogram must not double while the flat count resets (python's
    reset is pinned by the same-instance recount test; rust/swift/zig are
    structurally immune — their recorder is scan()-local)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "build").mkdir()
    (repo / "build" / f"lib{ext}").write_text("x = 1\n")
    (repo / f"root{ext}").write_text("y = 2\n")
    scanner = scanner_cls(str(repo))
    first = scanner.scan()["statistics"]
    second = scanner.scan()["statistics"]
    assert first["excluded_dir_names"] == second["excluded_dir_names"]
    assert second["excluded_dir_names"]["build"] == 1, lang


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
