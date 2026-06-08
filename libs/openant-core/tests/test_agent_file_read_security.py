"""The agent's ``read_file_section`` tool must not escape the repo root.

Pre-existing finding (surfaced during the PR #69 round-2 review): the
model-controlled ``file_path`` was joined onto the repo root with no
containment check, so ``..`` / absolute / symlink paths could read
arbitrary host files. The fix confines the resolved path to the repo root.
"""

from __future__ import annotations

from utilities.agentic_enhancer.repository_index import RepositoryIndex


def test_read_file_section_blocks_traversal(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("l1\nl2\nl3\n")
    (tmp_path.parent / "secret.txt").write_text("TOPSECRET\n")

    idx = RepositoryIndex({}, repo_path=str(tmp_path))

    # Legit in-repo read works.
    assert idx.read_file_section("src/a.py", 1, 2) == "l1\nl2\n"
    # Escapes are refused (None, same as a missing file) — never read.
    assert idx.read_file_section("../secret.txt", 1, 1) is None
    assert idx.read_file_section("/etc/hosts", 1, 1) is None
    assert idx.read_file_section("src/../../secret.txt", 1, 1) is None
