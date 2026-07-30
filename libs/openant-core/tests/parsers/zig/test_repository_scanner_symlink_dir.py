"""Symlink policy for the Zig RepositoryScanner: refuse, and record the gap.

The scanner used ``os.walk(repo)`` which defaults to ``followlinks=False``, so a
``.zig`` file reachable only through a symlinked directory was silently dropped
(the other four language scanners use ``Path.iterdir()`` + ``is_dir()`` which
follow symlinks). Following symlinks must be paired with a cycle guard so a
self-referential symlink loop does not hang the walk.
"""
import importlib.util
import os
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_scanner():
    path = _CORE_ROOT / "parsers" / "zig" / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location("rs_zig_symlink_dir", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


SCANNER = _load_scanner()


def test_symlinked_directory_is_refused_and_the_gap_is_recorded(tmp_path):
    """POLICY CHANGE: symlinked directories are no longer followed.

    This test previously asserted the opposite, and it was right to at the time:
    a ``.zig`` file reachable only through a symlink was being silently dropped,
    and for a SAST tool a false negative is the worse failure direction.

    It was inverted deliberately, by operator decision, after a demonstrated
    exfiltration: because traversal takes an entry's mode from a call that
    FOLLOWS links, an untrusted repository could ship ``leak.py -> /etc/passwd``
    (or a directory link to anywhere) and have host-file contents read into
    ``dataset.json``, which is sent to the model provider. An intermediate policy
    allowed links resolving inside the repository or its parent; the stricter
    rule was chosen because it needs no containment arithmetic and cannot be
    defeated by a target resolving somewhere unexpected.

    The original concern is NOT dismissed — it is converted from a silent loss
    into a counted one. Symlinked source is still unscanned code; the scanner now
    records it so the gap is visible rather than invisible.
    """
    external = tmp_path / "external_pkg"
    external.mkdir()
    (external / "util.zig").write_text("pub fn f() void {}\n")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked_pkg").symlink_to(external, target_is_directory=True)

    results = SCANNER(str(repo)).scan()
    found = {f["path"] for f in results["files"]}
    assert "linked_pkg/util.zig" not in found, (
        f"symlinked directory was followed; policy is to refuse. found={found}"
    )
    stats = results.get("statistics", {})
    assert stats.get("symlinks_skipped"), (
        "the symlink was refused but NOT counted — an unscanned path that leaves "
        f"no trace is a silent false negative. statistics={stats}"
    )


def test_symlink_cycle_is_bounded_and_emits_target_once(tmp_path):
    # Self-referential symlink loop (sub/loop -> repo). The walk must terminate
    # AND must not re-emit the target file once per loop iteration. Asserting
    # mere membership ("sub/a.zig" in found) is FALSE-GREEN: os.walk terminates
    # on its own via ELOOP/ENAMETOOLONG, so membership holds even with no guard.
    # We assert the result set is BOUNDED and that the target appears EXACTLY
    # ONCE, so the test FAILS if the cycle guard is removed.
    repo = tmp_path / "repo"
    sub = repo / "sub"
    sub.mkdir(parents=True)
    (sub / "a.zig").write_text("pub fn g() void {}\n")
    (sub / "loop").symlink_to(repo, target_is_directory=True)

    results = SCANNER(str(repo)).scan()
    paths = [f["path"] for f in results["files"]]

    # Bounded: without a guard the loop yields a.zig under sub/, sub/loop/sub/,
    # sub/loop/sub/loop/sub/ ... (dozens of aliases before ELOOP).
    assert len(paths) <= 2, f"unbounded/duplicated walk; paths={paths}"
    # Exactly once, under the canonical (loop-free) path.
    zig_paths = [p for p in paths if p.endswith("a.zig")]
    assert zig_paths.count("sub/a.zig") == 1, f"expected sub/a.zig exactly once; got {zig_paths}"
    assert len(zig_paths) == 1, f"target emitted more than once; got {zig_paths}"


def _force_scandir_order(monkeypatch, os_module, reverse):
    """Force a deterministic os.scandir order so the alias-vs-canonical race is
    testable regardless of the underlying filesystem's natural ordering."""
    orig = os_module.scandir

    class _Ordered:
        def __init__(self, entries):
            self._it = iter(entries)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def __iter__(self):
            return self._it

        def __next__(self):
            return next(self._it)

        def close(self):
            pass

    def fake_scandir(path=".", *args, **kwargs):
        with orig(path, *args, **kwargs) as it:
            entries = sorted(it, key=lambda e: e.name, reverse=reverse)
        return _Ordered(entries)

    monkeypatch.setattr(os_module, "scandir", fake_scandir)


def test_in_repo_symlink_emits_canonical_path_not_alias(tmp_path, monkeypatch):
    # Regression: a real dir aaa/ (aaa/x.zig) and an in-repo symlink zzz -> aaa.
    # An inode-dedup guard that keys on the FIRST visited path emits x.zig under
    # whichever of {aaa, zzz} os.walk sees first -- if zzz wins, the canonical
    # aaa/x.zig is inode-suppressed and NEVER emitted (a non-deterministic
    # regression vs HEAD, which never followed the symlink at all). The scanner
    # must emit x.zig EXACTLY ONCE under the canonical aaa/ path, regardless of
    # directory-scan order. We force the adversarial order (zzz before aaa) so
    # the failure is deterministic.
    repo = tmp_path / "repo"
    aaa = repo / "aaa"
    aaa.mkdir(parents=True)
    (aaa / "x.zig").write_text("pub fn h() void {}\n")
    (repo / "zzz").symlink_to(aaa, target_is_directory=True)

    # reverse=True => 'zzz' is yielded before 'aaa' (worst case for the alias).
    _force_scandir_order(monkeypatch, os, reverse=True)

    results = SCANNER(str(repo)).scan()
    paths = [f["path"] for f in results["files"]]
    zig_paths = [p for p in paths if p.endswith("x.zig")]

    assert zig_paths == ["aaa/x.zig"], (
        f"expected x.zig exactly once under canonical aaa/; got {zig_paths}"
    )
