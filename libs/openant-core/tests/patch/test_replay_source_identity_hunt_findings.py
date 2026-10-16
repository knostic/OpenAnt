"""PR #763 HUNT N13: a traced run made on a DIRTY working tree recorded only the
target's HEAD SHA, and replay accepted a clean checkout of that SHA as the
state the run analyzed, although its source differs.

run_traced now records whether the analyzed working tree was clean; replay
refuses a source recorded dirty, and one whose state was never recorded (a
trace written before this was recorded), and carries the recorded state into
its own manifest so a replay of a replay is checked the same way.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from utilities.autopatcher import stage_replay as sr
from utilities.autopatcher.tools import run_traced as rt

_GIT = ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"]


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def f(x):\n    return eval(x)\n")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run([*_GIT, "add", "-A"], cwd=root, check=True)
    subprocess.run([*_GIT, "commit", "-qm", "init"], cwd=root, check=True)
    return root


def _make_dirty(root: Path) -> None:
    (root / "app.py").write_text("def f(x):\n    if not x.isdigit():\n        raise ValueError\n    return eval(x)\n")


def _restore(root: Path) -> None:
    (root / "app.py").write_text("def f(x):\n    return eval(x)\n")


class TestRecording:
    def test_clean_source_is_recorded_clean(self, tmp_path):
        root = _repo(tmp_path)
        assert rt._replay_provenance(str(root), executions=[])["target_repository"]["worktree_clean"] is True

    def test_dirty_source_is_recorded_dirty(self, tmp_path):
        root = _repo(tmp_path)
        _make_dirty(root)
        assert rt._replay_provenance(str(root), executions=[])["target_repository"]["worktree_clean"] is False


class TestReplayGate:
    def test_dirty_source_is_refused_on_a_clean_checkout_of_the_same_head(self, tmp_path):
        """The HUNT reproduction: dirty source run, then the checkout is
        restored to HEAD; the bytes differ from what the run analyzed."""
        root = _repo(tmp_path)
        _make_dirty(root)
        manifest = rt._replay_provenance(str(root), executions=[])
        _restore(root)
        provenance = sr.resolve_source_provenance(root, manifest)
        with pytest.raises(sr.StageReplayError, match="had uncommitted changes"):
            sr.validate_target_repository(None, provenance, stage="report_generation")

    def test_clean_source_is_accepted(self, tmp_path):
        root = _repo(tmp_path)
        manifest = rt._replay_provenance(str(root), executions=[])
        provenance = sr.resolve_source_provenance(root, manifest)
        assert sr.validate_target_repository(None, provenance, stage="report_generation") == root

    def test_unrecorded_source_state_is_refused(self, tmp_path):
        """A trace written before the field existed: nothing shows the
        source was clean, so no equivalence is claimed."""
        root = _repo(tmp_path)
        manifest = rt._replay_provenance(str(root), executions=[])
        del manifest["target_repository"]["worktree_clean"]
        provenance = sr.resolve_source_provenance(root, manifest)
        with pytest.raises(sr.StageReplayError, match="was not recorded"):
            sr.validate_target_repository(None, provenance, stage="report_generation")

    def test_clean_source_with_a_dirty_replay_checkout_is_still_refused(self, tmp_path):
        root = _repo(tmp_path)
        manifest = rt._replay_provenance(str(root), executions=[])
        _make_dirty(root)
        provenance = sr.resolve_source_provenance(root, manifest)
        with pytest.raises(sr.StageReplayError, match="uncommitted changes"):
            sr.validate_target_repository(None, provenance, stage="report_generation")

    def test_different_head_is_still_refused(self, tmp_path):
        root = _repo(tmp_path)
        manifest = rt._replay_provenance(str(root), executions=[])
        (root / "b.py").write_text("x = 1\n")
        subprocess.run([*_GIT, "add", "-A"], cwd=root, check=True)
        subprocess.run([*_GIT, "commit", "-qm", "2"], cwd=root, check=True)
        provenance = sr.resolve_source_provenance(root, manifest)
        with pytest.raises(sr.StageReplayError, match="HEAD does not match"):
            sr.validate_target_repository(None, provenance, stage="report_generation")


def test_replay_manifests_carry_the_recorded_state():
    """Both replay writers keep the source state for a replay of a replay."""
    for module in ("stage_replay.py", "replay_engine.py"):
        source = (Path(sr.__file__).parent / module).read_text()
        assert '"worktree_clean": provenance.repo_worktree_clean' in source, module
