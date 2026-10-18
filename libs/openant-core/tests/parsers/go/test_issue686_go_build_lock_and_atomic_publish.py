"""#686: the go_parser rebuild is serialized, and its result is published atomically.

`GoPipelineTest.setup()` checked whether the `go_parser` binary was stale and, if
it was, ran `go build -o go_parser .` straight onto the one path every scan
execs, inside the installed package tree, with nothing on the Python side
excluding a second scan. Two consequences, and the issue is explicit that
neither substitutes for the other:

1. **no mutual exclusion** -- two concurrent scans both read "stale", so both
   run the whole build onto the same destination;
2. **the publish is not atomic** -- the toolchain publishes with a rename that
   falls back to a byte copy (``shell.go:174-183``: rename first, then
   remove -> ``O_TRUNC`` -> ``io.Copy``), and the copy writes the destination in
   place, so a scan that execs the path inside that window can see a partially
   written binary.

The issue's own ruling fixes the shape: "stage-then-rename ... plus an
``fcntl.flock`` around check+build", and "the lock is needed independently of
atomicity".

**What these tests observe, and what they simulate.** The issue's verification
note is binding here: without a reproduction "the fix would be picked by
preference, not evidence". So every test below drives the REAL
``GoPipelineTest.setup()`` and asserts on OBSERVED artifacts -- a build journal,
the bytes on the destination path, what ``git check-ignore`` answers -- never on
the shape of the source. What is
simulated is only the toolchain: a stub `go` on ``PATH`` replays the documented
copy fallback (remove -> truncate -> chunked write) deterministically, instead
of forcing the real toolchain onto that branch with a cross-device ``GOTMPDIR``
on a RAM disk. That forcing is what the issue's third comment already MEASURED
on the real `go build` -- ~336,000 partial-binary samples on the destination
across 4 builds, against zero for the same-filesystem control -- and it is not
portable to three CI runners. The stub makes the same window deterministic; the
real-toolchain magnitude lives in the issue. ``test_the_real_toolchain_still_
builds_and_publishes`` closes the loop with the actual `go build`.

Nothing here builds into the package tree: the Go SOURCES are copied into
``tmp_path`` first, which is the same discipline
``tests/parsers/go/test_issue746_method_value_composite_literal.py`` adopted
citing this issue. Sources ALONE -- see ``_parser_tree``: copying the whole
directory also copied whatever `go_parser` BINARY a previous test had left in the
real tree, and that made every test here order-dependent.
"""

import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

_CORE = Path(__file__).resolve().parents[3]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

# The orchestrator under test, imported by its FULLY QUALIFIED name. The
# sibling tests reach these files through importlib under a synthetic module
# name because the bare basename `test_pipeline` collides across the six parser
# packages -- `parsers.go.test_pipeline` does not collide, and
# tests/test_entrypoint_bindings.py already imports it this way. Importing the
# class rather than the module is deliberate: each test below then NAMES the
# production class it drives, so no assertion here can be satisfied by a
# re-implementation living in this file.
from parsers.go.test_pipeline import GoPipelineTest  # noqa: E402

_TP = _CORE / "parsers" / "go" / "test_pipeline.py"
_GO_PARSER_SRC = _CORE / "parsers" / "go" / "go_parser"

# The stub writes this many bytes in CHUNK_COUNT chunks. "Partial" means a size
# strictly between 0 and FINAL_SIZE: a reader that sees one has seen a binary
# that is neither the old one nor the new one.
_CHUNK = b"N" * 4096
_CHUNK_COUNT = 4
_FINAL_SIZE = len(_CHUNK) * _CHUNK_COUNT
_OLD_BINARY = b"O" * 128

_SHIM = r'''
import os, sys, time
mode = os.environ["ISSUE686_SHIM_MODE"]
work = os.environ["ISSUE686_SHIM_WORK"]
argv = sys.argv[1:]
out = argv[argv.index("-o") + 1] if "-o" in argv else "go_parser"
if not os.path.isabs(out):
    out = os.path.join(os.getcwd(), out)
stamp = f"{os.getpid()}"

def journal(event):
    with open(os.path.join(work, "journal.txt"), "a", encoding="utf-8") as fh:
        fh.write(f"{event} {stamp} {time.time():.6f} {out}\n")

journal("start")
if mode == "serialize":
    # Hold the build window open long enough that two unsynchronized builders
    # must overlap. No sampling, no timing luck: the journal records the
    # interval and the assertion reads it back.
    time.sleep(0.8)
    with open(out, "wb") as fh:
        fh.write(_FINAL)
elif mode == "nonatomic":
    # The toolchain's copy fallback, replayed: unlink the destination, create it
    # truncated, then stream. After the first chunk, wait (bounded) for a reader
    # to say it saw the partial state -- so the RED is deterministic rather than
    # a won race, and the GREEN pays one bounded wait and nothing else.
    try:
        os.unlink(out)
    except OSError:
        pass
    with open(out, "wb") as fh:
        fh.write(_CHUNKBYTES)
        fh.flush()
        os.fsync(fh.fileno())
        deadline = time.time() + 3.0
        while time.time() < deadline and not os.path.exists(
                os.path.join(work, "observed")):
            time.sleep(0.005)
        for _ in range(_CHUNKS - 1):
            fh.write(_CHUNKBYTES)
            fh.flush()
elif mode == "truncate_then_fail":
    # A build that destroys the destination and THEN fails. The toolchain does
    # this on the copy path whenever the copy cannot finish (full disk, a killed
    # compile): remove + truncate happen before any bytes land.
    try:
        os.unlink(out)
    except OSError:
        pass
    with open(out, "wb") as fh:
        fh.write(_CHUNKBYTES)
    journal("fail")
    sys.stderr.write("stub go: deliberate build failure after truncating the output\n")
    sys.exit(1)
else:
    raise SystemExit(f"unknown shim mode {mode!r}")
journal("end")
'''


def _install_go_stub(tmp_path: Path, mode: str, monkeypatch) -> Path:
    """Put a stub `go` first on PATH and return its work directory."""
    bindir = tmp_path / "stubbin"
    bindir.mkdir()
    work = tmp_path / "shimwork"
    work.mkdir()
    shim = bindir / "_go_shim.py"
    shim.write_text(
        _SHIM.replace("_FINAL", repr(_CHUNK * _CHUNK_COUNT))
             .replace("_CHUNKBYTES", repr(_CHUNK))
             .replace("_CHUNKS", str(_CHUNK_COUNT)),
        encoding="utf-8",
    )
    if os.name == "nt":
        # PATHEXT resolution finds go.bat for a bare `go` from a SHELL -- but
        # the CI-red root cause (PR #783, run 38144408072) is that Python's
        # subprocess -> CreateProcess appends ONLY `.exe` in its PATH search,
        # so a bare ['go', ...] can never resolve a .bat stub: it silently
        # found the runner's REAL go.exe, which built the fixture for real
        # (codes [0,0], an EMPTY journal, "the build ran 0 times"). The
        # stub therefore ALSO runs via the direct route on Windows --
        # _win_stub_run_utf8 wraps the loaded module's run_utf8 to invoke
        # the shim script with the interpreter directly (a separate process
        # per build, the same argv, the same returncode semantics; only the
        # EXECUTABLE RESOLUTION is stubbed, which is harness plumbing, not
        # the lock/publish behavior under test).
        (bindir / "go.bat").write_text(
            f'@"{sys.executable}" "{shim}" %*\r\n', encoding="utf-8")
        monkeypatch.setenv("ISSUE686_GO_SHIM", str(shim))
    else:
        launcher = bindir / "go"
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{shim}" "$@"\n',
                            encoding="utf-8")
        launcher.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("ISSUE686_SHIM_MODE", mode)
    monkeypatch.setenv("ISSUE686_SHIM_WORK", str(work))
    return work


# SOURCES ONLY. Copying everything in the directory also copied any `go_parser`
# BINARY a previous test had left in the real package tree -- shutil.copy2
# preserves its mtime, so the staleness check read "fresh", setup() built
# nothing, and every test here failed in a directory batch while passing alone.
# (The leftover is real: tests/parsers/go/test_go_schema_completeness.py runs
# the orchestrator as a subprocess, which builds in place -- which is this
# issue's own point.)
_TREE_SOURCES = ("*.go", "go.mod", "go.sum")


def _parser_tree(tmp_path: Path) -> Path:
    """A private copy of parsers/go/go_parser, so no test ever builds in-tree."""
    root = tmp_path / "parsers_go"
    (root / "go_parser").mkdir(parents=True)
    copied = 0
    for pattern in _TREE_SOURCES:
        for src in sorted(_GO_PARSER_SRC.glob(pattern)):
            if src.is_file():
                shutil.copy2(src, root / "go_parser" / src.name)
                copied += 1
    assert copied, f"copied no Go sources out of {_GO_PARSER_SRC}"
    return root


def _win_stub_run_utf8(mod):
    """On Windows, route the module's run_utf8 straight to the shim script.

    CreateProcess appends only `.exe` when resolving a bare command name, so
    a `.bat` stub on PATH is unreachable from Python's subprocess -- the
    runner's real go.exe silently won instead (the observed CI-red). The
    wrapper preserves every semantic the tests read: a separate process per
    build, the same argv (the shim parses argv exactly as before), the same
    returncode, and the same journal. POSIX keeps the proven PATH-stub route.
    """
    if os.name != "nt":
        return
    # fable delta-round F6: the wrapper must be IDEMPOTENT (a per-call stack
    # of wrappers leaked across tests and broke the real-toolchain test --
    # a stale shim route rerouted the real ['go','build'] and KeyErrored),
    # and it must read the shim env AT CALL TIME so monkeypatch teardown
    # restores a clean pass-through when the next test runs unstubbed.
    if getattr(mod.run_utf8, "_issue686_wrapped", False):
        return
    orig = mod.run_utf8

    def _stub(cmd, **kw):
        shim = os.environ.get("ISSUE686_GO_SHIM")
        if shim and cmd and cmd[0] == "go":
            import subprocess as _sp
            return _sp.run([sys.executable, shim] + list(cmd[1:]),
                           capture_output=True, text=True,
                           cwd=kw.get("cwd"), encoding="utf-8",
                           errors="replace")
        return orig(cmd, **kw)

    _stub._issue686_wrapped = True
    mod.run_utf8 = _stub


def _pipeline_on(cls, tmp_path: Path, tree: Path, tag: str):
    # On Windows the in-process tests share the imported module: apply the
    # direct shim route there too (the same wrapper the child uses).
    import sys as _sys
    _win_stub_run_utf8(_sys.modules["parsers.go.test_pipeline"])
    repo = tmp_path / f"repo_{tag}"
    repo.mkdir(exist_ok=True)
    (repo / "go.mod").write_text("module probe686\n\ngo 1.21\n", encoding="utf-8")
    (repo / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    p = cls(repo_path=str(repo), output_dir=str(tmp_path / f"out_{tag}"))
    # parser_dir is derived from __file__, so redirect the INSTANCE rather than
    # patching the build command -- which stays `go build -o go_parser .`.
    p.parser_dir = str(tree)
    p.go_parser = str(tree / "go_parser" / "go_parser")
    return p


def _journal(work: Path):
    text = (work / "journal.txt").read_text(encoding="utf-8") if (
        work / "journal.txt").exists() else ""
    rows = []
    for line in text.splitlines():
        event, pid, ts, out = line.split(" ", 3)
        rows.append({"event": event, "pid": pid, "t": float(ts), "out": out})
    return rows


_CHILD = r'''
import importlib.util, os, sys, time
tp, tree, tag, ready_dir, n = sys.argv[1:6]
core = str(os.path.dirname(os.path.dirname(os.path.dirname(tp))))
for p in (os.path.dirname(tp), core):
    if p not in sys.path:
        sys.path.insert(0, p)
spec = importlib.util.spec_from_file_location("isolated_go_pipeline_686_child", tp)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
repo = os.path.join(ready_dir, "repo" + n)
os.makedirs(repo, exist_ok=True)
open(os.path.join(repo, "go.mod"), "w").write("module probe686\n\ngo 1.21\n")
open(os.path.join(repo, "main.go"), "w").write("package main\n\nfunc main() {}\n")
if os.name == "nt":
    # PR #783's CI-red root cause: CreateProcess appends only `.exe` in its
    # bare-name PATH search, so a .bat stub is unreachable and the runner's
    # real go.exe silently won (codes [0,0], an empty journal). Route the
    # module's run_utf8 straight to the shim script on Windows -- the same
    # separate process, argv, returncode and journal; only the executable
    # resolution (harness plumbing) is stubbed. The shim env is read AT
    # CALL TIME (fable F6: the pass-through must survive teardown).
    _orig_run = mod.run_utf8

    def _stub(cmd, **kw):
        _shim = os.environ.get("ISSUE686_GO_SHIM")
        if _shim and cmd and cmd[0] == "go":
            import subprocess as _sp
            return _sp.run([sys.executable, _shim] + list(cmd[1:]),
                           capture_output=True, text=True,
                           cwd=kw.get("cwd"), encoding="utf-8",
                           errors="replace")
        return _orig_run(cmd, **kw)

    mod.run_utf8 = _stub
p = mod.GoPipelineTest(repo_path=repo, output_dir=os.path.join(ready_dir, "out" + n))
p.parser_dir = tree
p.go_parser = os.path.join(tree, "go_parser", "go_parser")
# Handshake: both children are inside setup() before either can build, so the
# overlap at base is a certainty rather than a race we have to win.
open(os.path.join(ready_dir, "ready" + n), "w").close()
deadline = time.time() + 30.0
while time.time() < deadline:
    if all(os.path.exists(os.path.join(ready_dir, "ready" + k)) for k in ("0", "1")):
        break
    time.sleep(0.01)
ok = p.setup()
sys.exit(0 if ok else 3)
'''


def _run_two_concurrent_setups(tmp_path: Path, tree: Path, env: dict):
    child = tmp_path / "child686.py"
    child.write_text(_CHILD, encoding="utf-8")
    ready = tmp_path / "handshake"
    ready.mkdir()
    procs = [
        subprocess.Popen(
            [sys.executable, str(child), str(_TP), str(tree), f"c{n}", str(ready), str(n)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for n in (0, 1)
    ]
    out = [pr.communicate(timeout=180) for pr in procs]
    return [pr.returncode for pr in procs], [o[0] for o in out]


# --------------------------------------------------------------------------
# 1. mutual exclusion -- observed in a build journal, no timing race to win
# --------------------------------------------------------------------------

def test_two_concurrent_scans_run_the_build_once(tmp_path, monkeypatch):
    """The re-check-under-the-lock, observed: two scan PROCESSES that both find
    the binary missing produce exactly ONE build.

    At base both ran it: two full builds onto one destination, which is the
    issue's "two stale checks -> two builds -> double work".
    """
    work = _install_go_stub(tmp_path, "serialize", monkeypatch)
    tree = _parser_tree(tmp_path)
    codes, outputs = _run_two_concurrent_setups(tmp_path, tree, dict(os.environ))
    assert codes == [0, 0], f"a child setup() failed: {codes}\n{outputs}"
    starts = [r for r in _journal(work) if r["event"] == "start"]
    assert len(starts) == 1, (
        f"the build ran {len(starts)} times for two concurrent scans -- the "
        f"staleness check is not re-evaluated under a lock.\n{_journal(work)}")


def test_two_concurrent_builds_do_not_overlap(tmp_path, monkeypatch):
    """Serialization itself, observed: no two build windows intersect.

    Independent of the count assertion above -- a fix that deduplicated builds
    by some sentinel but let two real builds run concurrently would pass that
    one and fail this one. The stub holds its window open for 0.8s, far longer
    than the process-start skew the handshake already removes, so an unlocked
    pair overlaps deterministically.
    """
    work = _install_go_stub(tmp_path, "serialize", monkeypatch)
    tree = _parser_tree(tmp_path)
    # Force two real builds even under the lock, by making the first one's
    # product stale again: see the second scan's own staleness check. Instead of
    # faking that, drive the two scans against a tree whose source is newer than
    # anything either produces -- the stub writes a file but never touches the
    # .go mtimes, so the second builder under the lock still sees "stale".
    for go_file in (tree / "go_parser").glob("*.go"):
        os.utime(go_file, (time.time() + 5, time.time() + 5))
    codes, outputs = _run_two_concurrent_setups(tmp_path, tree, dict(os.environ))
    assert codes == [0, 0], f"a child setup() failed: {codes}\n{outputs}"
    rows = _journal(work)
    spans = {}
    for r in rows:
        spans.setdefault(r["pid"], {})[r["event"]] = r["t"]
    windows = sorted((v["start"], v["end"]) for v in spans.values()
                     if "start" in v and "end" in v)
    assert len(windows) == 2, (
        f"expected two completed builds with the sources kept newer than the "
        f"product; journal was:\n{rows}")
    (a_start, a_end), (b_start, b_end) = windows
    assert b_start >= a_end, (
        f"the two builds overlapped by {a_end - b_start:.3f}s -- they ran "
        f"concurrently onto the same destination. windows={windows}")


def test_a_fresh_binary_skips_the_build_entirely(tmp_path, monkeypatch):
    """Guard the guard. If the staleness check ever stopped firing, every test
    above would pass vacuously. Green on both sides by design.
    """
    work = _install_go_stub(tmp_path, "serialize", monkeypatch)
    tree = _parser_tree(tmp_path)
    p = _pipeline_on(GoPipelineTest, tmp_path, tree, "fresh")
    assert p.setup() is True
    assert len([r for r in _journal(work) if r["event"] == "start"]) == 1, \
        "the first setup() did not build -- the staleness precondition is broken"
    again = _pipeline_on(GoPipelineTest, tmp_path, tree, "fresh2")
    assert again.setup() is True
    assert len([r for r in _journal(work) if r["event"] == "start"]) == 1, \
        "a fresh binary was rebuilt -- setup() no longer trusts the mtime check"


# --------------------------------------------------------------------------
# 2. atomic publication -- observed in the bytes on the destination path
# --------------------------------------------------------------------------

def test_the_destination_is_never_observed_partially_written(tmp_path, monkeypatch):
    """The issue's own RED/GREEN gate: a sampler on the destination path sees
    only {absent, final} -- never a size in between.

    This is the publication window, not the exec consequence; the issue is
    explicit that a probabilistic exec hammer is not viable (25 trials / 1,365
    execs found nothing). The stub replays the copy fallback and blocks after
    its first chunk until the sampler says it saw the partial state, so at base
    the partial is certain and at head the wait simply expires.
    """
    work = _install_go_stub(tmp_path, "nonatomic", monkeypatch)
    tree = _parser_tree(tmp_path)
    destination = tree / "go_parser" / "go_parser"
    samples = []
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            try:
                size = destination.stat().st_size
            except OSError:
                samples.append(None)
            else:
                samples.append(size)
                if 0 < size < _FINAL_SIZE:
                    (work / "observed").touch()
            time.sleep(0.001)

    t = threading.Thread(target=sampler, daemon=True)
    t.start()
    try:
        p = _pipeline_on(GoPipelineTest, tmp_path, tree, "atomic")
        assert p.setup() is True
    finally:
        stop.set()
        t.join(timeout=5)

    partial = sorted({s for s in samples if s is not None and 0 < s < _FINAL_SIZE})
    assert partial == [], (
        f"the destination was observed partially written at sizes {partial} "
        f"(final is {_FINAL_SIZE}) -- the publish is not atomic. "
        f"{len(samples)} samples, {sum(1 for s in samples if s is None)} absent")
    assert destination.stat().st_size == _FINAL_SIZE, \
        "the build did not publish a complete binary at all"


def test_a_failed_build_leaves_the_previous_binary_standing(tmp_path, monkeypatch):
    """A build that truncates its output and then fails must not take the
    working binary with it.

    No sampler and no timing at all: the assertion is the bytes on disk after
    setup() returns. At base the destination WAS the build's output path, so the
    truncation destroyed the only copy -- the same loss PR #96 removed from
    write_json.
    """
    work = _install_go_stub(tmp_path, "truncate_then_fail", monkeypatch)
    tree = _parser_tree(tmp_path)
    destination = tree / "go_parser" / "go_parser"
    destination.write_bytes(_OLD_BINARY)
    # Make it stale so setup() is obliged to try a rebuild.
    for go_file in (tree / "go_parser").glob("*.go"):
        os.utime(go_file, (time.time() + 5, time.time() + 5))

    p = _pipeline_on(GoPipelineTest, tmp_path, tree, "failed")
    assert p.setup() is False, "a failing `go build` must make setup() fail"
    assert [r["event"] for r in _journal(work)].count("fail") == 1, \
        "the stub did not reach its failure path -- the fixture is broken"
    assert destination.exists(), \
        "the failed build deleted the previous good binary"
    assert destination.read_bytes() == _OLD_BINARY, (
        f"the failed build corrupted the previous good binary: "
        f"{destination.stat().st_size} bytes, expected {len(_OLD_BINARY)}")


def test_the_lock_sits_on_the_same_filesystem_as_the_binary(tmp_path, monkeypatch):
    """PR #43's clause, as an artifact property rather than a source grep: the
    lockfile the build creates lives in the destination's own directory, so the
    staging rename cannot become a cross-volume copy+delete.
    """
    work = _install_go_stub(tmp_path, "serialize", monkeypatch)
    tree = _parser_tree(tmp_path)
    p = _pipeline_on(GoPipelineTest, tmp_path, tree, "lockloc")
    assert p.setup() is True
    assert len([r for r in _journal(work) if r["event"] == "start"]) == 1, \
        "no build ran -- nothing would have created a lock"
    locks = sorted(q.name for q in (tree / "go_parser").iterdir()
                   if q.name.endswith(".lock"))
    assert locks, (
        "the build created no lockfile beside the binary -- there is nothing "
        f"excluding a second scan. directory held: "
        f"{sorted(q.name for q in (tree / 'go_parser').iterdir())}")
    assert len(locks) == 1, f"more than one lockfile appeared: {locks}"


def test_the_staging_directory_is_inside_the_destination_directory(tmp_path, monkeypatch):
    """Fable r1 F1 (the M6 gap): the SAME-FILESYSTEM property of the staged
    publish is pinned as an artifact fact, not a source grep. PR #43's
    clause: os.replace is atomic only within one volume; across volumes it
    degrades to copy+delete and loses the never-partially-written property.
    The staging directory must appear INSIDE the binary's own directory
    (created with dir=go_parser_dir), never in the system temp -- a staging
    in tmpdir() would be on another volume wherever TMPDIR is a different
    mount (the CI containers' case).
    """
    work = _install_go_stub(tmp_path, "serialize", monkeypatch)
    tree = _parser_tree(tmp_path)
    p = _pipeline_on(GoPipelineTest, tmp_path, tree, "stagingloc")
    assert p.setup() is True
    builds = [r for r in _journal(work) if r["event"] == "start"]
    assert len(builds) == 1, "no build ran -- nothing would have created staging"
    staging_dir = Path(builds[0]["out"]).parent
    # fable r2 F5: parent EQUALITY, not a startswith prefix -- a sibling
    # directory (os.path.dirname(go_parser_dir)) would pass a prefix check
    # while living outside the gitignore pattern's directory; the same-
    # filesystem property holds either way, but "INSIDE the destination's
    # own directory" is the pinned fact.
    assert staging_dir.resolve().parent == (tree / "go_parser").resolve(), (
        f"the staging directory is NOT inside the destination's own directory: "
        f"{staging_dir} -- a cross-volume os.replace would degrade to "
        "copy+delete and lose the never-partially-written property (PR #43's "
        "finding; the fable-r1 M6 mutant moved it to the system temp and "
        "survived every other test)")


def test_the_staged_build_leaves_no_residue(tmp_path, monkeypatch):
    """The staging directory is removed, so a scan does not litter the package
    tree it had to build in. Also pins that the published name is the one the
    scan execs -- a publish to the wrong basename would read as 'no binary'.
    """
    work = _install_go_stub(tmp_path, "serialize", monkeypatch)
    tree = _parser_tree(tmp_path)
    before = {q.name for q in (tree / "go_parser").iterdir()}
    p = _pipeline_on(GoPipelineTest, tmp_path, tree, "residue")
    assert p.setup() is True
    assert len([r for r in _journal(work) if r["event"] == "start"]) == 1
    after = {q.name for q in (tree / "go_parser").iterdir()}
    added = sorted(n for n in after - before if not n.endswith(".lock"))
    assert added == ["go_parser"], (
        f"the build left {added} in the package directory; only the published "
        "binary should appear")
    assert not [q for q in (tree / "go_parser").iterdir() if q.is_dir()], \
        "a staging directory survived the build"


# --------------------------------------------------------------------------
# 3. the real toolchain -- green on both sides, so the stub cannot hide a break
# --------------------------------------------------------------------------

def test_the_real_toolchain_still_builds_and_publishes(tmp_path):
    """No stub: the real `go build` through the real setup(), into a copy of the
    parser tree. Proves the staged publish produces a runnable binary at the
    path the pipeline then execs, which is the one thing a stub cannot show.
    """
    if shutil.which("go") is None:
        pytest.skip("Go toolchain unavailable")
    tree = _parser_tree(tmp_path)
    p = _pipeline_on(GoPipelineTest, tmp_path, tree, "realgo")
    assert p.setup() is True, "the real build failed through setup()"
    published = Path(p.go_parser)
    if not published.exists() and published.with_suffix(".exe").exists():
        published = published.with_suffix(".exe")
    assert published.exists(), (
        f"`go build` succeeded but nothing was published at {p.go_parser} -- "
        "the staged rename lost the artifact")
    assert published.stat().st_size > 0
    proc = subprocess.run([str(published)], capture_output=True, text=True, timeout=120)
    assert proc.returncode != 0 or proc.stdout or proc.stderr, \
        "the published file did not behave like the parser binary"


def test_the_build_artifacts_are_ignored_by_the_repo():
    """The build now leaves a lockfile beside the binary, and (after a hard
    kill) possibly a staging directory. Both must be ignored, or every Go scan
    dirties the developer's checkout -- the defect #666 removed from the
    generate-context report, in a new place. The line already in `.gitignore`
    for `parsers/javascript/.openant-npm-install.lock` is the same provision
    for the JS tree.

    Asked of git rather than of the file's text, and asked about the names the
    ORCHESTRATOR itself uses (`_GO_BUILD_LOCK_NAME` and
    `_GO_BUILD_STAGING_PREFIX`), so renaming one without the other fails here
    instead of in someone's `git status`.
    """
    # Imported HERE, not at module scope. These two constants do not exist at
    # the pre-fix base, and a module-level import of a name that is absent
    # there turns the whole FILE into a collection error -- which would erase
    # the behavioural base-red of every other test in it and leave nothing but
    # "the constant is new". The names that the other tests need
    # (`GoPipelineTest`) exist on both sides and stay at module scope.
    from parsers.go.test_pipeline import (
        _GO_BUILD_LOCK_NAME,
        _GO_BUILD_STAGING_PREFIX,
    )

    if shutil.which("git") is None:
        pytest.skip("git unavailable")
    repo_root = _CORE.parents[1]
    if not (repo_root / ".gitignore").is_file() or not (repo_root / ".git").exists():
        pytest.skip("not a source checkout")
    go_dir = (_CORE / "parsers" / "go" / "go_parser").relative_to(repo_root).as_posix()
    # Both names come from the orchestrator's own constants, never retyped. A
    # directory is asked about with the trailing slash git needs, plus a file
    # inside it, which is the form `git status` actually reports.
    staged = f"{go_dir}/{_GO_BUILD_STAGING_PREFIX}probe686"
    for rel in (f"{go_dir}/{_GO_BUILD_LOCK_NAME}", staged + "/", staged + "/go_parser"):
        proc = subprocess.run(["git", "check-ignore", "-q", rel],
                              cwd=str(repo_root), capture_output=True, text=True)
        assert proc.returncode == 0, (
            f"`git check-ignore` says {rel} is NOT ignored (rc={proc.returncode}) "
            "-- a scan that builds the parser would leave it untracked in the "
            "checkout")
