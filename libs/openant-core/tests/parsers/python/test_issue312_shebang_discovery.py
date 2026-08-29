"""Regression tests for issue #312 — extension-only discovery silently
drops first-party source: a byte-identical shebang'd executable without a
.py extension is never scanned, and the skip is uncounted.

Because discovery precedes seeding and reachability, anything lost here is
lost from every downstream stage — and nothing in the artifact records
WHAT was dropped. The issue's fixture: two byte-identical Python files,
one extensionless with a shebang and mode 0755, one with a .py extension —
only the twin produces units.

Contract locked here (the issue's suggestions 1+2; defect (2) was
RETRACTED by the reporter — the build/ exclusion is the specified
registry-level behaviour):
- an extensionless file whose first line is a `#!...python` shebang IS a
  source file (the cheap, precise fallback);
- extensionless files WITHOUT a python shebang are still skipped (a
  binary, a shell script, a data file — no false positives);
- the shebang discovery is COUNTED in the shape _note_symlink
  established: its own stats key (`shebang_files_detected`) plus up to
  5 example paths, so the coverage gain stays visible;
- the .py twin behavior is unchanged (the control).
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import importlib.util

_RS_PATH = PROJECT_ROOT / "parsers" / "python" / "repository_scanner.py"
_RS_SPEC = importlib.util.spec_from_file_location("rs_python_issue312", _RS_PATH)
_RS_MOD = importlib.util.module_from_spec(_RS_SPEC)
_RS_SPEC.loader.exec_module(_RS_MOD)
RepositoryScanner = _RS_MOD.RepositoryScanner


def _scan(files: dict):
    repo = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        if rel == "tool_shebang":
            # The EXECUTABLE bit is LOAD-BEARING (shebang discovery keys on
            # it); the group/other bits are not. 0o700 keeps the test honest
            # (a real tool's exec bit) without tripping CodeQL's
            # py/overly-permissive-file — same discovery, quieter mode.
            os.chmod(p, 0o700)
    scanner = RepositoryScanner(str(repo))
    result = scanner.scan()
    found = sorted(f["path"] for f in result["files"])
    return found, result["statistics"]


SHEBANG = "#!/usr/bin/env python3\nprint('tool')\n"


def test_shebang_file_is_discovered():
    found, stats = _scan({"tool_shebang": SHEBANG})
    assert found == ["tool_shebang"], found
    assert stats["shebang_files_detected"] == 1
    assert stats["shebang_examples"][0].endswith("tool_shebang")


def test_py_twin_control_unchanged():
    found, stats = _scan({"tool.py": SHEBANG})
    assert found == ["tool.py"]
    assert stats.get("shebang_files_detected", 0) == 0


def test_both_twins_discovered():
    """The issue's fixture: both byte-identical files produce units."""
    found, stats = _scan({"tool_shebang": SHEBANG, "tool.py": SHEBANG})
    assert found == ["tool.py", "tool_shebang"]
    assert stats["shebang_files_detected"] == 1


def test_extensionless_without_python_shebang_still_skipped():
    found, _ = _scan({
        "shell_tool": "#!/bin/sh\necho hi\n",
        "binaryish": "\x7fELF binary",
        "data": "plain text, no shebang",
    })
    assert found == []


def test_shebang_counts_capped_at_5_examples():
    files = {f"tool{i}": SHEBANG for i in range(7)}
    found, stats = _scan(files)
    assert len(found) == 7
    assert stats["shebang_files_detected"] == 7
    assert len(stats["shebang_examples"]) == 5


def test_first_line_only_no_magic_deeper_in_file():
    """A python shebang must be on the FIRST line — a mention deeper in
    the file (a comment, a string) does not make a data file source."""
    found, _ = _scan({
        "notes": "#!/usr/bin/env cat\nsome text\n#!/usr/bin/env python3\n",
    })
    assert found == []
