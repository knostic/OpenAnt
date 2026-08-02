"""Isolated repository copy primitive.

Creates a disposable copy of a repository in a temp directory and
guarantees cleanup. This is a generic repository-mutation primitive with
no knowledge of patches, investigations, or any specific downstream use —
future capabilities (patch application via ``patch_applicability.apply_patch``,
test execution, static analysis, OpenAnt re-analysis) compose on top of it
by treating the yielded root as an ordinary writable repo checkout.

The source repository is only ever read (via ``shutil.copytree``) — this
module contains no code path that can write to the caller's repo_root.
"""

from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_IGNORE_PATTERNS = shutil.ignore_patterns("__pycache__", "*.pyc", "node_modules")


@contextmanager
def temporary_repo_copy(repo_root: "Path | str") -> Iterator[Path]:
    """Copy repo_root into a new temp directory; guarantees cleanup.

    Yields the copy's root path (including .git, so git-based tooling like
    apply_patch works against it unmodified). Always removes the temp
    directory on exit, even if the caller raises inside the `with` block.
    Never writes to repo_root — it is only ever a copytree source.
    """
    tmp_dir = tempfile.mkdtemp(prefix="openant-workspace-")
    try:
        dest = Path(tmp_dir) / "repo"
        shutil.copytree(Path(repo_root), dest, ignore=_IGNORE_PATTERNS)
        yield dest
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
