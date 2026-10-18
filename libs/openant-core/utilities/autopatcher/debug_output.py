"""Where AUTOPATCHER_DEBUG artifacts are written.

Every debug writer (patch_generator, pipeline, repo_locator) calls
`debug_dir()`. The established default is `./reports/debug` relative to the
working directory, and an explicit AUTOPATCHER_DEBUG_DIR always wins. The
`openant patch` entry (core/patch.py) sets AUTOPATCHER_DEBUG_DIR for one
run only when that default would land inside the analyzed repository: debug
prompts carry repository source and must not be written into the working
copy being analyzed (`resolve_debug_dir`).
"""

from __future__ import annotations

import os
from pathlib import Path

DEBUG_DIR_ENV = "AUTOPATCHER_DEBUG_DIR"
_DEFAULT_DEBUG_DIR = Path("reports") / "debug"


def debug_dir() -> Path:
    """The directory AUTOPATCHER_DEBUG artifacts go to right now."""
    explicit = os.environ.get(DEBUG_DIR_ENV)
    return Path(explicit) if explicit else _DEFAULT_DEBUG_DIR


def resolve_debug_dir(repo_root: "str | Path | None", output_dir: "str | Path") -> Path:
    """`debug_dir()`, except that when it is the working-directory default
    and that resolves inside `repo_root` (the analyzed repository), the
    run's own output directory (`<output_dir>/debug`) instead."""
    current = debug_dir()
    if os.environ.get(DEBUG_DIR_ENV) or not repo_root:
        return current
    try:
        inside = current.resolve().is_relative_to(Path(repo_root).resolve())
    except OSError:
        inside = True  # cannot tell: keep the debug output out of the repository
    return Path(output_dir) / "debug" if inside else current
