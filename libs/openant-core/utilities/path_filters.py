"""Shared path-filtering helpers.

Directory exclusion must compare each *path segment* against the exclude
patterns, never a raw substring of the joined path string.  Substring
matching wrongly excludes ordinary names that merely *contain* an excluded
token (e.g. ``contest`` contains ``test``, ``rebuild`` contains ``build``,
``attempt`` contains ``tmp``).  Dropping those files silently is a
correctness hole in any parser that walks a repository.

The canonical contract mirrors ``core/parser_adapter.py`` (dominant-language
detection)::

    any(p in skip_dirs for p in f.parts)
"""

from pathlib import Path
from typing import Iterable, Union
import os

PathLike = Union[str, os.PathLike]


def should_exclude_directory(path: PathLike, patterns: Iterable[str]) -> bool:
    """Return True iff any whole path segment of ``path`` is in ``patterns``.

    Segment (whole-name) membership, not substring containment.  ``path`` may
    be a single directory name or a full path; every component is checked.

    Examples::

        should_exclude_directory("contest", {"test"})        -> False
        should_exclude_directory("test", {"test"})           -> True
        should_exclude_directory("src/rebuild/x.rb", {"build"}) -> False
        should_exclude_directory("src/build/x.rb", {"build"})   -> True
    """
    pattern_set = set(patterns)
    if not pattern_set:
        return False
    return any(part in pattern_set for part in Path(path).parts)
