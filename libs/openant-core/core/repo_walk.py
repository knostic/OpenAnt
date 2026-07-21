"""One repository walker, shared by every Python language scanner.

There were four: ``parsers/{python,c,php,ruby}/repository_scanner.py`` each
implemented recursion, symlink handling, stat-error behaviour and unreadable-entry
accounting independently. That is the mechanical cause of this codebase's most
persistent defect shape — a fix lands at the site a report names, and the other
three keep the hole. Traversal has now been fixed three separate times in this
subsystem (symlink guard, deep nesting, FIFO handling) and each time it reached a
different subset of the four.

Worse, the divergence hides from grep-style parity tests. Before this module,
``ruby`` recorded unreadable directories as ``directories_read_failed`` while
``python`` used ``directories_unreadable`` — a token-matching test that accepted
either would report both compliant, while ruby still recursed and still classified
entries with ``Path.is_dir()``. The property a reader cares about ("deeply nested
code is either scanned or reported missing") was false in a scanner the test called
green.

So: one walker. Language scanners supply *classification* (is this a source file? a
test file?) and *record-building* (what goes in the output row). They do not get to
re-implement traversal.

The three properties this walker guarantees, none of which were universal before:

1. **Iterative.** No recursion limit, so a deeply nested tree cannot blow the stack
   and get swallowed by a caller's ``except``. An explicit stack of *iterators*
   (not paths) preserves depth-first, name-sorted order, so output ordering is
   unchanged from the recursive form.
2. **Symlink-refusing.** Directory symlinks are never followed: ``vendor -> /``
   walks the host filesystem into ``dataset.json`` and on to the model provider,
   and ``loop -> ..`` does not terminate.
3. **Gap-recording.** Anything that cannot be classified or read is *counted*, not
   skipped. ``Path.is_dir()`` converts ``OSError`` into a silent ``False``, so a
   path past ``PATH_MAX`` reads as "neither file nor directory" and vanishes from a
   scan that still reports success. For a SAST tool that is a false-negative
   primitive and strictly worse than a crash, because it manufactures assurance.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Callable

from utilities.file_io import safe_to_descend, safe_to_read

# Keys this walker maintains on the caller's stats dict. Callers should seed them,
# but the walker tolerates absence so an existing scanner can adopt it incrementally.
STAT_KEYS = (
    "directories_scanned",
    "directories_excluded",
    "directories_unreadable",
)


def walk_repository(
    root: Path,
    *,
    should_exclude_directory: Callable[[str], bool],
    on_file: Callable[[Path, str], None],
    stats: dict,
    unreadable_examples_limit: int = 5,
) -> None:
    """Walk ``root``, calling ``on_file`` for every regular file.

    Args:
        root: Repository root to walk.
        should_exclude_directory: Given a bare directory name, return True to prune.
            Language-specific (``node_modules``, ``vendor``, ``__pycache__``, ...).
        on_file: Called as ``on_file(entry, relative_path)`` for each regular file.
            The scanner decides whether it is a source file and what to record —
            this walker deliberately knows nothing about extensions.
        stats: Mutated in place. ``directories_scanned`` / ``directories_excluded``
            / ``directories_unreadable`` are maintained here, plus an
            ``unreadable_examples`` list for diagnosis.
        unreadable_examples_limit: Cap on retained example paths, so a pathological
            tree cannot balloon the result.

    Note:
        Unreadable entries are counted into ``stats`` rather than raised. A single
        unreadable directory should not abort a whole scan — but it must not be
        invisible either, which is why the count lands in the structured result and
        not only on stderr, where CI discards it.
    """
    repo_real = os.path.realpath(root)
    # Bounds cycles among *internal* symlinks, which are followed (see
    # safe_to_descend: the property is "never leave the repository", not "never
    # follow a link" — a repo may legitimately organise code behind an alias).
    seen_dirs: set = set()
    for key in STAT_KEYS:
        stats.setdefault(key, 0)

    def _record_unreadable(path, reason: str) -> None:
        stats["directories_unreadable"] = stats.get("directories_unreadable", 0) + 1
        # Ruby's scanner shipped this figure as `directories_read_failed` before the
        # walkers were unified. Emitting both keeps its existing consumers and
        # regression test working rather than silently renaming a field someone
        # depends on — the canonical name is `directories_unreadable`.
        stats["directories_read_failed"] = stats.get("directories_read_failed", 0) + 1
        stats.setdefault("unreadable_examples", [])
        if len(stats["unreadable_examples"]) < unreadable_examples_limit:
            stats["unreadable_examples"].append(f"{path}: {reason}")
        print(f"Warning: Cannot read {path}: {reason} (coverage gap recorded)",
              file=sys.stderr)

    def _open_dir(path: Path):
        stats["directories_scanned"] = stats.get("directories_scanned", 0) + 1
        try:
            return iter(sorted(path.iterdir(), key=lambda e: e.name))
        except PermissionError:
            _record_unreadable(path, "permission denied")
        except OSError as exc:
            _record_unreadable(path, str(exc))
        return None

    root_entries = _open_dir(Path(root))
    if root_entries is None:
        return
    stack = [(root_entries, "")]

    while stack:
        entries, relative = stack[-1]
        entry = next(entries, None)
        if entry is None:
            stack.pop()
            continue

        entry_relative = os.path.join(relative, entry.name) if relative else entry.name

        # Explicit stat rather than is_dir()/is_file(): both swallow OSError and
        # answer False, which silently drops anything the OS refuses to stat.
        try:
            mode = entry.stat().st_mode
        except OSError as exc:
            _record_unreadable(entry, str(exc))
            continue

        if stat.S_ISDIR(mode):
            if should_exclude_directory(entry.name):
                stats["directories_excluded"] = stats.get("directories_excluded", 0) + 1
                continue
            if not safe_to_descend(entry, repo_real, seen_dirs):
                stats["directories_excluded"] = stats.get("directories_excluded", 0) + 1
                continue
            child = _open_dir(entry)
            if child is not None:
                stack.append((child, entry_relative))
        elif stat.S_ISREG(mode):
            # Files get the SAME containment check as directories. They did not,
            # and that was an exfiltration hole: `mode` above comes from
            # `entry.stat()`, which FOLLOWS symlinks, so `leak.py -> /etc/passwd`
            # reports S_ISREG and was handed straight to `on_file`. The scanner
            # then read through the link and put host-file contents into
            # dataset.json, which is sent to the model provider — reachable with
            # one committed symlink in an untrusted repository.
            #
            # Every guard in the tree was directory-only, and the test asserting
            # "does not ingest files outside the repository" built only a
            # DIRECTORY symlink, so it certified one shape of the attack while
            # the other was wide open.
            if not safe_to_read(entry, repo_real):
                stats["files_excluded"] = stats.get("files_excluded", 0) + 1
                continue
            on_file(entry, entry_relative)
