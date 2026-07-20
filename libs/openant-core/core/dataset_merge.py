"""Merge per-language parse output into a single dataset.

The parse fan-out writes ``<run>/<lang>/`` directories, one per language, each
containing the same flat filenames. This module turns those into the single
``dataset.json`` / ``analyzer_output.json`` that the rest of the pipeline
consumes, so enhance/analyze/verify/report run ONCE over everything rather than
once per language. That works because the LLM stages are deliberately
language-agnostic (see DOCUMENTATION.md) — language is never used for rule or
query selection.

What is deliberately NOT merged: call graphs. There are no cross-language edges
to resolve (a Python call into a Go binary is not an edge any parser emits), so
unioning the graphs would imply a connectivity that does not exist. Instead
``write_call_graph_index`` records where each language's graph lives, which is
the single seam a future cross-language graph would attach to.
"""

import os
import sys
from dataclasses import dataclass, field

from utilities.file_io import read_json, write_json


@dataclass
class MergeStats:
    """Outcome of merging per-language datasets.

    Attributes:
        languages: Languages that contributed units, in merge order.
        units_per_language: Unit count contributed by each language.
        total_units: Units in the merged dataset.
        id_collisions: Unit ids that appeared in more than one language and
            were namespaced. Empty in normal operation — see
            ``merge_datasets`` for why a collision is possible at all.
    """

    languages: list[str] = field(default_factory=list)
    units_per_language: dict[str, int] = field(default_factory=dict)
    total_units: int = 0
    id_collisions: list[str] = field(default_factory=list)


def _successful(outcomes) -> list:
    """Outcomes that produced a dataset we can actually read."""
    return [o for o in outcomes if o.ok and o.dataset_path]


def merge_datasets(outcomes, output_path: str) -> MergeStats:
    """Union per-language datasets into one, stamping each unit's language.

    Args:
        outcomes: ``LanguageParseOutcome`` list from ``parse_repository_multi``.
            Failed languages are skipped — a degraded run still produces a
            usable dataset from the survivors.
        output_path: Where to write the merged ``dataset.json``.

    Returns:
        :class:`MergeStats` describing what was merged.

    Raises:
        ValueError: If no outcome succeeded. Callers must not silently treat a
            fully-failed parse as an empty-but-valid dataset.
    """
    usable = _successful(outcomes)
    if not usable:
        raise ValueError(
            "Cannot merge: no successful language parses among "
            f"{[o.language for o in outcomes]}"
        )

    merged_units: list[dict] = []
    seen_ids: set[str] = set()
    stats = MergeStats()

    # Carry the first language's top-level scalars (name, repository). They
    # describe the repo, not the language, so they are identical across
    # per-language datasets by construction of the fan-out.
    first = read_json(usable[0].dataset_path)
    merged: dict = {
        key: value
        for key, value in first.items()
        if key not in ("units", "statistics", "metadata")
    }

    per_language: dict[str, dict] = {}

    for outcome in usable:
        data = read_json(outcome.dataset_path)
        units = data.get("units", [])

        for unit in units:
            # setdefault, not assignment: if a parser ever starts emitting a
            # more specific language tag, it knows better than we do.
            unit.setdefault("language", outcome.language)

            unit_id = unit.get("id")
            if unit_id is not None and unit_id in seen_ids:
                # Unit ids are `relative/path.ext:name`, so a collision needs
                # the same path AND extension in two languages — impossible
                # while extension→language is a function, but possible the
                # moment a new language claims `.h` alongside C. Namespace the
                # LATER one only: rewriting ids unconditionally would break
                # core/diff_filter.py and the reporter's caller/callee dedup,
                # both of which match on id.
                stats.id_collisions.append(unit_id)
                unit["id"] = f"{outcome.language}::{unit_id}"
                print(
                    f"  [Merge] WARNING: unit id collision {unit_id!r} — "
                    f"namespaced as {unit['id']!r}",
                    file=sys.stderr,
                )
            if unit.get("id") is not None:
                seen_ids.add(unit["id"])

            merged_units.append(unit)

        stats.languages.append(outcome.language)
        stats.units_per_language[outcome.language] = len(units)

        per_language[outcome.language] = {
            "units": len(units),
            "dataset_path": outcome.dataset_path,
            "output_dir": outcome.output_dir,
        }
        # Raw per-parser statistics are preserved per-language, NOT summed into
        # the top-level aggregate. The parsers disagree on naming (Python emits
        # `total_units`, JavaScript `totalUnits`), so summing by raw key name
        # yields a dict where each convention's key holds only its own
        # language's count while reading as a whole-dataset figure. Rather than
        # inventing a canonical schema neither parser agreed to, the aggregate
        # below carries only figures the merge can compute unambiguously.
        per_language[outcome.language]["statistics"] = data.get("statistics") or {}

    merged["units"] = merged_units
    merged["statistics"] = {
        "total_units": len(merged_units),
        "units_per_language": dict(stats.units_per_language),
        "languages": list(stats.languages),
    }
    merged["metadata"] = {
        **(first.get("metadata") or {}),
        "languages": stats.languages,
        "per_language": per_language,
    }

    stats.total_units = len(merged_units)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    write_json(output_path, merged, indent=2)
    print(
        f"[Merge] {stats.total_units} units from "
        f"{len(stats.languages)} language(s): "
        + ", ".join(f"{k}={v}" for k, v in stats.units_per_language.items()),
        file=sys.stderr,
    )
    return stats


def merge_analyzer_outputs(outcomes, output_path: str) -> None:
    """Union per-language ``analyzer_output.json`` files.

    The parsers do NOT agree on this file's key set — Python emits
    ``functions``/``callGraph``/``reverseCallGraph`` while JavaScript adds
    ``repository``/``classes``/``call_graph``/``reverse_call_graph``/
    ``indirect_calls``. So the merge unions over whatever keys are present
    rather than assuming a schema, and merges each key by type: dicts are
    keyed by unit id and get updated; anything else (notably the ``repository``
    string) is taken from the first language that supplied it.

    Only ``functions`` is load-bearing in-repo — ``RepositoryIndex`` at
    ``utilities/agentic_enhancer/repository_index.py`` is the sole consumer of
    this file's contents; every other reference passes the path through. The
    remaining keys are preserved best-effort so nothing is silently dropped.
    """
    usable = [o for o in outcomes if o.ok and o.analyzer_output_path]
    if not usable:
        return

    merged: dict = {}
    for outcome in usable:
        if not os.path.exists(outcome.analyzer_output_path):
            continue
        data = read_json(outcome.analyzer_output_path)
        for key, value in data.items():
            if isinstance(value, dict):
                merged.setdefault(key, {}).update(value)
            else:
                # Scalars/lists describe the repo, not the language; first
                # writer wins rather than concatenating incomparable values.
                merged.setdefault(key, value)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    write_json(output_path, merged, indent=2)


def write_call_graph_index(outcomes, output_path: str) -> dict[str, str]:
    """Record where each language's ``call_graph.json`` lives.

    Built by PROBING THE FILESYSTEM, never from a hardcoded language list. A
    comment in core/scanner.py long claimed only Python and Zig persist a call
    graph; JavaScript does too, and which parsers do so changes over time. A
    stale list would silently skip post-LLM reachability re-filtering for a
    language that actually supports it — the exact cost regression this index
    exists to prevent.

    Args:
        outcomes: Per-language parse outcomes.
        output_path: Where to write ``call_graphs.json``.

    Returns:
        Mapping of language → path to its call graph, relative to the run dir.
    """
    run_dir = os.path.dirname(os.path.abspath(output_path))
    index: dict[str, str] = {}

    for outcome in outcomes:
        if not outcome.ok:
            # A stale call_graph.json can outlive a failed re-parse; indexing
            # it would feed the previous run's graph into this run's filter.
            continue
        candidate = os.path.join(outcome.output_dir, "call_graph.json")
        if os.path.isfile(candidate):
            index[outcome.language] = os.path.relpath(candidate, run_dir)

    os.makedirs(run_dir, exist_ok=True)
    write_json(output_path, index, indent=2)
    return index
