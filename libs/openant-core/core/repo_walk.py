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
    # Symlinks are refused outright (see utilities.file_io.safe_to_descend). That
    # is unscanned code, so it is COUNTED. A scanner that silently analyses less
    # than it claims manufactures assurance, which is worse than a visible gap.
    "symlinks_skipped",
)


# ---------------------------------------------------------------------------
# #600: the excluded-directory recorder — ONE policy home for every scanner.
# The walker knows only that a directory was pruned; the SCANNER knows its
# effective exclusion set. The recorder splits retention accordingly:
# RESERVED names (the scanner's effective exclusion set — build/, env/,
# migrations/ ... the first-party examples the issue is about) are always
# retained (their counts keep increasing after any dynamic saturation);
# DYNAMIC names (pattern-excluded: .egg-info suffixes, test dirs) are
# bounded with the overflow DISCLOSED as an occurrence count. Hostile
# names (control characters, non-printable, absurd length) count toward
# the overflow but NEVER key the artifact — the histogram's keys land in
# reports and the LLM summary prompt (producer-side sanitization).
# ---------------------------------------------------------------------------

_EXCLUDED_NAME_DYNAMIC_BOUND = 12
_EXCLUDED_NAME_MAX_LEN = 100
_EXCLUDED_NAME_EXAMPLES_PER_NAME = 2
_EXCLUDED_EXAMPLE_PATH_MAX_LEN = 200


class ExcludedDirRecorder:
    """Records pruned directories by name, with per-name entry-relative
    examples and disclosed truncation.

    The statistics projection shape (each scanner merges this after its
    walk): ``excluded_dir_names`` (name -> exact prune count, retained
    names only), ``excluded_dir_examples`` (name -> up to 2 relative
    paths), ``excluded_dir_names_overflow`` (the occurrence count of
    unretained names — hostile or beyond the dynamic bound). The bare
    ``directories_excluded`` count stays authoritative for the TOTAL.
    """

    def __init__(self, effective_exclusion_names):
        self._reserved = {str(n) for n in (effective_exclusion_names or ())}
        self.names = {}
        self.examples = {}
        self.overflow = 0
        self._dynamic = 0

    def note(self, name, relative_path):
        # The NAME gate decides COUNTING (hostile/oversized names overflow,
        # never key the artifact); the PATH gate decides EXAMPLES only —
        # a legitimate name under a non-ASCII ancestor still COUNTS and is
        # retained (the exact-total contract), its example path merely
        # withheld (hostile bytes never reach the artifact).
        if (
            not name
            or len(name) > _EXCLUDED_NAME_MAX_LEN
            or any(ord(c) < 32 or ord(c) > 126 for c in name)
        ):
            # Hostile, oversized, OR NON-ASCII: counted, never keyed — the
            # histogram's keys land in reports and LLM prompts, and a
            # non-ASCII name routes to overflow deliberately (a documented
            # bound, not a sanitization claim).
            self.overflow += 1
            return
        if name in self._reserved or name in self.names:
            self.names[name] = self.names.get(name, 0) + 1
        elif self._dynamic < _EXCLUDED_NAME_DYNAMIC_BOUND:
            self.names[name] = 1
            self._dynamic += 1
        else:
            # A dynamic name beyond the bound: its OCCURRENCE is disclosed
            # without fabricating a retained-name count we stopped tracking.
            self.overflow += 1
            return
        # The path gate bounds LENGTH too: names are capped at 100 chars,
        # and an unbounded ancestor chain (attacker-controlled repo content
        # up to PATH_MAX) would reach the reports and the LLM prompt
        # uncapped — the same withheld-example disclosure as non-ASCII.
        _path_ok = (
            len(str(relative_path)) <= _EXCLUDED_EXAMPLE_PATH_MAX_LEN
            and all(32 <= ord(c) <= 126 for c in str(relative_path))
        )
        if _path_ok:
            ex = self.examples.setdefault(name, [])
            if len(ex) < _EXCLUDED_NAME_EXAMPLES_PER_NAME:
                ex.append(str(relative_path))

    def merge_into(self, stats):
        stats["excluded_dir_names"] = dict(self.names)
        stats["excluded_dir_examples"] = {
            k: list(v) for k, v in self.examples.items()
        }
        stats["excluded_dir_names_overflow"] = self.overflow

def walk_repository(
    root: Path,
    *,
    should_exclude_directory: Callable[[str], bool],
    on_file: Callable[[Path, str], None],
    stats: dict,
    unreadable_examples_limit: int = 5,
    note_excluded=None,
) -> None:
    """Walk ``root``, calling ``on_file`` for every regular file.

    #600: ``note_excluded(name, relative_path)`` is the optional
    excluded-directory callback — the SCANNER owns the retention policy
    (via ExcludedDirRecorder below); the walker reports only the name and
    its entry-relative path. The histogram lives in the CALLER's stats
    (never this walker's STAT_KEYS — those are 0-seeded numerics).

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

    def _note_symlink(path) -> None:
        """Record a refused symlink so the coverage gap is inspectable.

        Policy is to refuse every symlink, which means code reachable only that
        way is not scanned. Recording it in the structured result — not just on
        stderr, which CI discards — is what keeps that a visible gap rather than
        a silent false negative.
        """
        stats.setdefault("symlink_examples", [])
        if len(stats["symlink_examples"]) < unreadable_examples_limit:
            stats["symlink_examples"].append(str(path))

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

        entry_relative = f"{relative}/{entry.name}" if relative else entry.name

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
                if note_excluded is not None:
                    # #600: the scanner's own policy decides retention — the
                    # walker reports the name and its entry-relative path only.
                    note_excluded(entry.name, entry_relative)
                continue
            if not safe_to_descend(entry, repo_real, seen_dirs):
                stats["symlinks_skipped"] = stats.get("symlinks_skipped", 0) + 1
                _note_symlink(entry)
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
                stats["symlinks_skipped"] = stats.get("symlinks_skipped", 0) + 1
                _note_symlink(entry)
                continue
            on_file(entry, entry_relative)
