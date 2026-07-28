"""Locate relevant source code in a repository given a vulnerability description.

Three ranked signal sources — no AST, no embeddings:
  1. Explicit file path references in the vulnerability text  (score 3)
  2. Symbol / backtick-term grep                              (score 2)
  3. CWE-specific keyword fallback                            (score 1)

Pass 2 combines two extractors:
  - Unfiltered backtick terms: ``Cookie``, ``Authorization``, etc. — advisory
    authors use backticks to highlight specific technical terms; these are
    meaningful grep signals even when the raw word looks generic.
  - Filtered symbols: snake_case / PascalCase identifiers that survive the
    generic-token filter.

Candidates are collected across all passes, deduped by path, and ranked.
Returns a code context string (≤ 4 000 chars) ready to inject into the
patch generator prompt.

Class-definition supplement (full-file mode only):
  After ranking, files that *define* a PascalCase class named in the advisory
  are prepended to the secondary context queue.  This ensures implementation
  files (e.g. a provider or handler class) reach the model even when generic
  signal words (e.g. "stac") inflate the occurrence counts of routing/API
  files and push the defining file below the ranked[1:3] window.
  The supplement does not modify scoring, ranking, or existing pass behaviour.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from pathlib import Path
from typing import List, NamedTuple, Tuple

from .repository_grounding_models import (
    DiscoveryEvidence,
    GroundingDecision,
    RepositoryCandidate,
    RepositoryGroundingResult,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GENERIC_TOKENS = frozenset({
    "header", "cookie", "redirect", "request", "response", "error", "file",
    "path", "data", "input", "output", "value", "test", "config", "handler",
    "params", "args", "kwargs", "result", "context", "message", "user",
    "type", "name", "id", "key", "code", "info", "log", "debug", "level",
    "mode", "options", "settings", "status", "default", "base", "util",
    "utils", "helper", "manager", "service", "client", "server", "read",
    "write", "send", "load", "save", "parse", "check", "get", "set",
})

_CWE_KEYWORDS: dict[str, list[str]] = {
    "CWE-89":  ["execute", "cursor", "query", "fetchone", "fetchall"],
    "CWE-79":  ["innerHTML", "dangerouslySetInnerHTML", "render", "template"],
    "CWE-22":  ["abspath", "realpath", "normpath", "join"],
    "CWE-78":  ["subprocess", "popen", "system"],
    "CWE-798": ["password", "secret", "hardcoded", "credential"],
    "CWE-287": ["authenticate", "login", "session", "verify", "jwt"],
    "CWE-502": ["loads", "pickle", "unmarshal", "yaml"],
}

# Minimal, general-purpose English stopword list for cwe_name_tokens() —
# articles/prepositions/conjunctions/copula only, deliberately NOT a
# security-vocabulary list (see design_token_extraction_2026-07-14.md: a
# hand-curated "this sounds generic" list is the same category of mistake
# as _CWE_KEYWORDS itself). Words like "expression", "regular", "prototype",
# "credentials" must never be added here.
_CWE_NAME_STOPWORDS = frozenset({
    "the", "a", "an",
    "of", "to", "in", "on", "for", "and", "or", "nor", "but", "with", "by",
    "from", "as", "at", "into", "via", "not", "no", "when", "which", "who",
    "whom", "that", "this", "these", "those", "is", "are", "was", "were",
    "be", "been", "being",
})

_IGNORED_DIRS = frozenset({".venv", "__pycache__", ".git", "node_modules", ".tox", "dist", "build"})
_SOURCE_EXTENSIONS = frozenset({".py", ".js", ".ts", ".rb", ".go", ".java", ".c", ".cpp", ".h", ".php", ".cs"})

_MAX_CONTEXT_CHARS = 4_000
_CONTEXT_WINDOW_LINES = 30   # lines above/below a match for large files
_SMALL_FILE_THRESHOLD = 150  # lines — include whole file if at or below this

# If the top matched file is at or below this size, send it in full so the LLM
# can produce accurate hunk line numbers. Files above this threshold fall back
# to the window + code-anchor snippet approach.
_FULL_FILE_THRESHOLD_CHARS = 20_000
_SECONDARY_CONTEXT_BUDGET = 4_000  # chars for snippets appended after the full-file primary
_MIN_CLASS_NAME_LENGTH = 5  # PascalCase names shorter than this are too generic for class-def search

# Per-pass candidate limits passed to _grep_repo. Both currently 3 (the
# value hardcoded before this constant existed) — kept as two separate
# names, not one shared constant, specifically so either pass's limit can
# be changed independently in the future without silently changing the
# other's behavior too (2026-07-16 experiment: a single shared limit was
# confirmed to widen Pass 2's own candidate return exactly as much as
# Pass 3's, which cannot help Pass 3 since Pass 2 always outranks Pass 3
# by tier regardless of candidate count).
_PASS2_CANDIDATE_LIMIT = 3
_PASS3_CANDIDATE_LIMIT = 3


# ---------------------------------------------------------------------------
# Debug instrumentation (observational only — see _write_debug_artifact)
#
# Everything in this section only *records* what find_code_context() already
# decided; nothing here feeds back into scoring, ranking, or the returned
# context string. Gated behind AUTOPATCHER_DEBUG, mirroring the existing
# reports/debug/ convention in patch_generator.py.
# ---------------------------------------------------------------------------

def _rel(p: Path, repo_root: Path) -> str:
    try:
        return p.relative_to(repo_root).as_posix()
    except ValueError:
        return p.name


def _derive_selected_pass(passes: list[dict], final_score) -> "str | None":
    """Return the pass name whose score equals final_score — the pass that
    actually determined this candidate's ranking.

    Purely derived from already-computed data (never stored or updated
    independently): every candidate's passes list always contains an entry
    whose score matches final_score, since final_score is itself the max of
    those same scores (or, for a class-definition-supplement-only entry,
    both final_score and the sole pass's score are None, which also
    matches). The None fallback is defensive only; this function has no
    known input for which it is reached.
    """
    for p in passes:
        if p["score"] == final_score:
            return p["pass"]
    return None


def _build_debug_record(
    repo_root: Path,
    extraction_signals: dict,
    debug_by_file: dict[str, dict],
    result: str,
    budget_model: str,
    budget_cap: int,
    budget_used: int,
) -> dict:
    """Assemble the final debug JSON structure. Pure — reads already-computed
    values only, never re-derives context selection itself."""
    candidates = list(debug_by_file.values())
    for c in candidates:
        # Single source of truth: both fields are derived here, at
        # serialization time, directly from selection_outcome/final_score —
        # neither is ever set or tracked anywhere else in this module.
        c["selected_pass"] = _derive_selected_pass(c["passes"], c["final_score"])
        c["selected"] = c["selection_outcome"] != "rejected"
    selected = [c["file"] for c in candidates if c["selection_outcome"] != "rejected"]
    rejected = sum(1 for c in candidates if c["selection_outcome"] == "rejected")
    return {
        "repo_root": str(repo_root),
        "extraction_signals": extraction_signals,
        "candidates": candidates,
        "summary": {
            "total_candidates": len(candidates),
            "selected_files": selected,
            "context_size": len(result),
            "remaining_budget": {
                "model": budget_model,
                "cap": budget_cap,
                "used": budget_used,
                "remaining": budget_cap - budget_used,
            },
            "rejected_candidates": rejected,
            "extraction_signals": extraction_signals,
        },
    }


def _write_debug_artifact(record: dict) -> None:
    """Write a context-selection debug artifact to reports/debug/.

    Gated behind AUTOPATCHER_DEBUG (same env var patch_generator.py already
    uses for its own reports/debug/ prompt dumps). Called only after the
    real return value of find_code_context() has already been computed —
    this function never influences it, and any failure here is swallowed
    so instrumentation can never break the pipeline.
    """
    if not os.environ.get("AUTOPATCHER_DEBUG"):
        return
    try:
        debug_dir = Path("reports") / "debug"
        debug_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        path = debug_dir / f"context_selection_{ts}.json"
        suffix = 0
        while path.exists():
            suffix += 1
            path = debug_dir / f"context_selection_{ts}_{suffix}.json"
        path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Path resolution (Pass 1 helper)
# ---------------------------------------------------------------------------

class PathResolution(NamedTuple):
    path: "Path | None"
    strategy: str  # "exact" | "suffix" | "ambiguous" | "unresolved"


class RepositoryPathResolver:
    """Resolves an advisory-named relative path to a file under repo_root.

    Strategies, tried in order:
      1. Exact repo-root-relative join.
      2. Unique suffix match — only attempted when `rel` has more than one
         path segment (e.g. ``_internal/download.py``), so this never
         degrades into basename-only matching for a bare filename like
         ``download.py``. Basename fallback is deliberately out of scope
         until a real case shows it's needed.

    More than one suffix match is ambiguous and is never resolved to a
    guess — callers should treat "ambiguous" the same as "not found".
    """

    def __init__(self, repo_root: Path) -> None:
        self._repo_root = repo_root
        self._files: list[Path] | None = None

    def resolve(self, rel: str) -> PathResolution:
        exact = self._resolve_exact(rel)
        if exact is not None:
            return PathResolution(exact, "exact")

        rel_parts = Path(rel).parts
        if len(rel_parts) < 2:
            return PathResolution(None, "unresolved")

        n = len(rel_parts)
        matches = [p for p in self._iter_files() if self._rel_parts(p)[-n:] == rel_parts]
        if len(matches) == 1:
            return PathResolution(matches[0], "suffix")
        if len(matches) > 1:
            return PathResolution(None, "ambiguous")
        return PathResolution(None, "unresolved")

    def _resolve_exact(self, rel: str) -> "Path | None":
        p = (self._repo_root / rel).resolve()
        if _safe_under(p, self._repo_root) and p.is_file():
            return p
        return None

    def _iter_files(self) -> list[Path]:
        if self._files is None:
            self._files = [
                p for p in sorted(self._repo_root.rglob("*"))
                if p.is_file() and not any(part in _IGNORED_DIRS for part in p.parts)
            ]
        return self._files

    def _rel_parts(self, p: Path) -> tuple:
        try:
            return p.relative_to(self._repo_root).parts
        except ValueError:
            return p.parts


# ---------------------------------------------------------------------------
# Domain objects (Repository Grounding)
#
# The dataclasses themselves live in repository_grounding_models.py (pure
# data, no logic). Populated directly from find_code_context()'s own
# canonical algorithm state — the same `candidates`/`best`/`ranked`
# structures, the same real per-pass loop variables (score, hit_line, the
# Pass-1 resolution result), and the same real selection/rendering
# variables (rel_label, n_lines, parts, ranges, sec_header, entry) that
# already determine `_result`. This is deliberately independent of the
# debug-only `_debug_raw_candidates`/`_debug_by_file` structures below,
# which exist solely to feed `_build_debug_record()`/the AUTOPATCHER_DEBUG
# artifact — the two are separate projections of the same underlying
# computation, not one derived from the other.
# ---------------------------------------------------------------------------

def _build_grounding_result(
    grounding_candidates: dict,
    grounding_decisions: dict,
    extraction_signals: dict,
    rendered_context: str,
    budget_model: "str | None",
    budget_cap: "int | None",
    budget_used: "int | None",
) -> RepositoryGroundingResult:
    """Assemble the final result from the RepositoryCandidate/GroundingDecision
    objects find_code_context() already built directly from its own
    canonical state (see the module comment above). Pure — makes no
    discovery, ranking, selection, budget, or rendering decisions of its
    own; this function only wraps already-built objects."""
    budget = None
    if budget_model is not None:
        budget = {
            "model": budget_model, "cap": budget_cap, "used": budget_used,
            "remaining": budget_cap - budget_used,
        }
    return RepositoryGroundingResult(
        rendered_context=rendered_context,
        candidates=list(grounding_candidates.values()),
        decisions=list(grounding_decisions.values()),
        extraction_signals=extraction_signals,
        budget=budget,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_code_context(
    vulnerability_text: str, repo_root: Path, *, _grounding_result_out: "list | None" = None
) -> str:
    """Return a ranked code context string extracted from repo_root.

    Returns an empty string if no relevant code is found.
    """
    # (score, path, content, first_hit_line)
    candidates: list[tuple[int, Path, str, int]] = []

    # --- canonical Repository Grounding evidence (NOT debug bookkeeping) ---
    # One entry per (pass, file) match, appended at the same point and from
    # the same real loop variables as `candidates.append(...)` below —
    # independent of _debug_raw_candidates.
    _evidence_by_path: dict[Path, list[DiscoveryEvidence]] = {}

    # --- debug bookkeeping (observational only, see _write_debug_artifact) ---
    _debug_raw_candidates: list[dict] = []
    _debug_unresolved_paths: list[str] = []
    _debug_ambiguous_paths: list[str] = []
    _debug_path_resolutions: list[dict] = []
    _debug_pass2_scanned: list[dict] = []
    _debug_pass3_scanned: list[dict] = []

    # Pass 1: explicit file paths (highest priority)
    _explicit_paths = _extract_file_paths(vulnerability_text)
    _path_resolver = RepositoryPathResolver(repo_root)
    for rel in _explicit_paths:
        resolution = _path_resolver.resolve(rel)
        # Recorded from the same `resolution` value the branches below read,
        # in the same iteration — explicit_path_resolutions can never
        # diverge from explicit_paths_unresolved/explicit_paths_ambiguous,
        # by construction, not by coincidence. Additive alongside those
        # existing fields; neither they nor their population logic changes.
        _debug_path_resolutions.append({
            "raw_path": rel,
            "strategy": resolution.strategy,
            "resolved_file": _rel(resolution.path, repo_root) if resolution.path is not None else None,
        })
        if resolution.path is not None:
            p = resolution.path
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                candidates.append((3, p, content, 0))
                _evidence_by_path.setdefault(p, []).append(DiscoveryEvidence(
                    pass_name="explicit_path", tier=3,
                    matched_tokens=[rel], total_occurrences=None,
                    hit_line=0, resolution_strategy=resolution.strategy,
                ))
                _debug_raw_candidates.append({
                    "file": _rel(p, repo_root), "pass": "explicit_path",
                    "score": 3, "matched_tokens": [rel],
                    "occurrence_counts": None, "hit_line_0indexed": 0,
                    "resolution_strategy": resolution.strategy,
                })
            except Exception:
                pass
        elif resolution.strategy == "ambiguous":
            _debug_ambiguous_paths.append(rel)
        else:
            _debug_unresolved_paths.append(rel)

    # Pass 2: symbol name grep — unfiltered backtick terms merged with filtered symbols
    backtick_terms = _extract_backtick_terms(vulnerability_text)
    symbols = _extract_symbols(vulnerability_text)
    all_signals = list(dict.fromkeys(backtick_terms + symbols))[:15]
    if all_signals:
        for p, content, hit_line in _grep_repo(
            repo_root, all_signals,
            _debug_sink=_debug_pass2_scanned, limit=_PASS2_CANDIDATE_LIMIT,
        ):
            candidates.append((2, p, content, hit_line))
            _evidence_by_path.setdefault(p, []).append(DiscoveryEvidence(
                pass_name="symbol_search", tier=2,
                matched_tokens=None, total_occurrences=None,
                hit_line=hit_line, resolution_strategy=None,
            ))
            _debug_raw_candidates.append({
                "file": _rel(p, repo_root), "pass": "symbol_search",
                "score": 2,
                "matched_tokens": next(
                    (e["matched_tokens"] for e in _debug_pass2_scanned if e["file"] == p), {}
                ),
                "occurrence_counts": next(
                    (e["total_occurrences"] for e in _debug_pass2_scanned if e["file"] == p), None
                ),
                "hit_line_0indexed": hit_line,
            })

    # Pass 3: CWE keyword fallback — dict-based keywords unioned with tokens
    # derived from the advisory's own CWE name (cwe_name_tokens), so a CWE
    # missing from _CWE_KEYWORDS still contributes Pass-3 signal. Union, not
    # replacement: zero regression risk to the dict's existing coverage.
    kws: list[str] = []
    for cwe in _extract_cwes(vulnerability_text):
        kws.extend(_CWE_KEYWORDS.get(cwe, []))
    kws.extend(cwe_name_tokens(vulnerability_text))
    kws = list(dict.fromkeys(kws))
    if kws:
        for p, content, hit_line in _grep_repo(
            repo_root, kws,
            _debug_sink=_debug_pass3_scanned, limit=_PASS3_CANDIDATE_LIMIT,
        ):
            candidates.append((1, p, content, hit_line))
            _evidence_by_path.setdefault(p, []).append(DiscoveryEvidence(
                pass_name="cwe_keywords", tier=1,
                matched_tokens=None, total_occurrences=None,
                hit_line=hit_line, resolution_strategy=None,
            ))
            _debug_raw_candidates.append({
                "file": _rel(p, repo_root), "pass": "cwe_keywords",
                "score": 1,
                "matched_tokens": next(
                    (e["matched_tokens"] for e in _debug_pass3_scanned if e["file"] == p), {}
                ),
                "occurrence_counts": next(
                    (e["total_occurrences"] for e in _debug_pass3_scanned if e["file"] == p), None
                ),
                "hit_line_0indexed": hit_line,
            })

    # --- debug: extraction signals, always recorded regardless of outcome ---
    _debug_signals = {
        "explicit_paths": _explicit_paths,
        "explicit_paths_unresolved": _debug_unresolved_paths,
        "explicit_paths_ambiguous": _debug_ambiguous_paths,
        "explicit_path_resolutions": _debug_path_resolutions,
        "cwes": _extract_cwes(vulnerability_text),
        "backtick_terms": backtick_terms,
        "symbols": symbols,
        "grep_tokens_pass2": all_signals,
        "grep_tokens_pass3": kws,
    }

    if not candidates:
        _write_debug_artifact({
            "repo_root": str(repo_root),
            "extraction_signals": _debug_signals,
            "candidates": [],
            "summary": {
                "total_candidates": 0,
                "selected_files": [],
                "context_size": 0,
                "remaining_budget": None,
                "rejected_candidates": 0,
                "extraction_signals": _debug_signals,
            },
        })
        if _grounding_result_out is not None:
            _grounding_result_out.append(_build_grounding_result(
                {}, {}, _debug_signals, "",
                budget_model=None, budget_cap=None, budget_used=None,
            ))
        return ""

    # Deduplicate by path, keep highest score per path
    best: dict[Path, tuple[int, str, int]] = {}
    for score, p, content, hit_line in candidates:
        if p not in best or score > best[p][0]:
            best[p] = (score, content, hit_line)

    ranked = sorted(best.items(), key=lambda kv: -kv[1][0])  # descending score

    # Canonical RepositoryCandidate/GroundingDecision seed — built directly
    # from `best` (not from _debug_raw_candidates/_debug_by_file). Every
    # decision defaults to "rejected"; the real selection/rendering code
    # below flips it for whichever files it actually renders.
    _grounding_candidates: dict[str, RepositoryCandidate] = {}
    _grounding_decisions: dict[str, GroundingDecision] = {}
    for p, (score, _content, _hit) in best.items():
        _label = _rel(p, repo_root)
        _grounding_candidates[_label] = RepositoryCandidate(
            path=_label, evidence=_evidence_by_path.get(p, []), best_tier=score,
        )
        _grounding_decisions[_label] = GroundingDecision(
            path=_label, outcome="rejected", snippet_ranges=None,
            bytes_contributed=0, truncated=False,
        )

    # --- debug: consolidate raw per-pass records by file, attach final score.
    # Every candidate defaults to "rejected" here; the branches below flip
    # that to primary/secondary for whichever files the real algorithm (the
    # code immediately following, unchanged) actually selects. ---
    _best_by_rel = {_rel(p, repo_root): score for p, (score, _c, _h) in best.items()}
    _debug_by_file: dict[str, dict] = {}
    for rc in _debug_raw_candidates:
        rec = _debug_by_file.setdefault(rc["file"], {
            "file": rc["file"], "passes": [],
            "final_score": _best_by_rel.get(rc["file"]),
            "selection_outcome": "rejected", "snippet_range_1indexed": None,
            "bytes_contributed": 0, "truncated": False,
        })
        rec["passes"].append({
            "pass": rc["pass"], "score": rc["score"],
            "matched_tokens": rc["matched_tokens"],
            "occurrence_counts": rc["occurrence_counts"],
            "hit_line_0indexed": rc["hit_line_0indexed"],
            # Only ever set for Pass 1 ("explicit_path") entries; None for
            # symbol_search/cwe_keywords, which have no resolution strategy.
            "resolution_strategy": rc.get("resolution_strategy"),
        })

    # Full-file mode: if the top candidate fits within the threshold, include it
    # entirely so the LLM can produce accurate hunk line numbers.
    # Hybrid context budget: also inject snippets from ranked[1] and ranked[2]
    # within a bounded secondary budget so the model can see implementation files
    # that score below the primary (e.g. provider layer when API layer ranks #1).
    if ranked:
        top_p, (_, top_content, _) = ranked[0]
        if len(top_content) <= _FULL_FILE_THRESHOLD_CHARS:
            try:
                rel_label = top_p.relative_to(repo_root).as_posix()
            except ValueError:
                rel_label = top_p.name
            n_lines = len(top_content.splitlines())
            parts = [f"# {rel_label} (full file, {n_lines} lines)\n" + top_content]

            if rel_label in _debug_by_file:
                _debug_by_file[rel_label]["selection_outcome"] = "primary_full_file"
                _debug_by_file[rel_label]["snippet_range_1indexed"] = [1, n_lines]
                _debug_by_file[rel_label]["bytes_contributed"] = len(parts[0])
                _debug_by_file[rel_label]["truncated"] = False
            if rel_label in _grounding_decisions:
                _dec = _grounding_decisions[rel_label]
                _dec.outcome = "primary_full_file"
                _dec.snippet_ranges = [1, n_lines]
                _dec.bytes_contributed = len(parts[0])
                _dec.truncated = False

            # Build the secondary queue.
            # Class-definition supplements come first: files that define a
            # PascalCase class named in the advisory are injected before ranked
            # secondary files so they appear even when occurrence-count ranking
            # pushes them below the ranked[1:3] window.
            # The primary file (top_p) is always excluded from supplementation.
            _seen_secondary: set[Path] = {top_p}
            _secondary_queue: list[tuple[Path, str, int]] = []
            for _sup_p, _sup_content, _sup_hit in _find_class_definitions(
                vulnerability_text, repo_root
            ):
                _sup_rel = _rel(_sup_p, repo_root)
                if _sup_rel not in _debug_by_file:
                    _debug_by_file[_sup_rel] = {
                        "file": _sup_rel,
                        "passes": [{
                            "pass": "class_definition_supplement", "score": None,
                            "matched_tokens": None, "occurrence_counts": None,
                            "hit_line_0indexed": _sup_hit,
                        }],
                        "final_score": None, "selection_outcome": "rejected",
                        "snippet_range_1indexed": None, "bytes_contributed": 0,
                        "truncated": False,
                    }
                if _sup_rel not in _grounding_candidates:
                    _grounding_candidates[_sup_rel] = RepositoryCandidate(
                        path=_sup_rel,
                        evidence=[DiscoveryEvidence(
                            pass_name="class_definition_supplement", tier=None,
                            matched_tokens=None, total_occurrences=None,
                            hit_line=_sup_hit, resolution_strategy=None,
                        )],
                        best_tier=None,
                    )
                    _grounding_decisions[_sup_rel] = GroundingDecision(
                        path=_sup_rel, outcome="rejected", snippet_ranges=None,
                        bytes_contributed=0, truncated=False,
                    )
                if _sup_p not in _seen_secondary:
                    _secondary_queue.append((_sup_p, _sup_content, _sup_hit))
                    _seen_secondary.add(_sup_p)
            for _rank_p, (_, _rank_content, _rank_hit) in ranked[1:]:
                if _rank_p not in _seen_secondary:
                    _secondary_queue.append((_rank_p, _rank_content, _rank_hit))
                    _seen_secondary.add(_rank_p)

            sec_total = 0
            for sec_p, sec_content, sec_hit in _secondary_queue[:2]:
                try:
                    sec_label = sec_p.relative_to(repo_root).as_posix()
                except ValueError:
                    sec_label = sec_p.name
                budget = _SECONDARY_CONTEXT_BUDGET - sec_total - len(sec_label) - 60
                if budget <= 0:
                    break
                snippet, ranges = _extract_snippet(sec_content, sec_hit, budget)
                if not snippet:
                    continue
                if ranges:
                    range_str = ", ".join(f"{s}-{e}" for s, e in ranges)
                    sec_header = f"# {sec_label} (lines {range_str})\n"
                else:
                    sec_header = f"# {sec_label}\n"
                parts.append(sec_header + snippet)
                sec_total += len(sec_header) + len(snippet)
                if sec_label in _debug_by_file:
                    _debug_by_file[sec_label]["selection_outcome"] = "secondary_snippet"
                    _debug_by_file[sec_label]["snippet_range_1indexed"] = ranges
                    _debug_by_file[sec_label]["bytes_contributed"] = len(sec_header) + len(snippet)
                    _debug_by_file[sec_label]["truncated"] = "[truncated]" in snippet
                if sec_label in _grounding_decisions:
                    _dec = _grounding_decisions[sec_label]
                    _dec.outcome = "secondary_snippet"
                    _dec.snippet_ranges = ranges
                    _dec.bytes_contributed = len(sec_header) + len(snippet)
                    _dec.truncated = "[truncated]" in snippet
                if sec_total >= _SECONDARY_CONTEXT_BUDGET:
                    break

            _result = "\n\n".join(parts)
            _write_debug_artifact(_build_debug_record(
                repo_root, _debug_signals, _debug_by_file, _result,
                budget_model="secondary_snippet_budget",
                budget_cap=_SECONDARY_CONTEXT_BUDGET, budget_used=sec_total,
            ))
            if _grounding_result_out is not None:
                _grounding_result_out.append(_build_grounding_result(
                    _grounding_candidates, _grounding_decisions, _debug_signals, _result,
                    budget_model="secondary_snippet_budget",
                    budget_cap=_SECONDARY_CONTEXT_BUDGET, budget_used=sec_total,
                ))
            return _result

    # Snippet mode: top file exceeds threshold — use window + code-anchor approach.
    _HEADER_OVERHEAD = 60  # budget reserve for " (lines NNN-MMM, NNN-MMM)"
    parts: list[str] = []
    total = 0
    for _idx, (p, (_, content, hit_line)) in enumerate(ranked[:2]):
        try:
            rel_label = p.relative_to(repo_root).as_posix()
        except ValueError:
            rel_label = p.name  # defensive fallback

        budget = _MAX_CONTEXT_CHARS - total - len(rel_label) - _HEADER_OVERHEAD
        if budget <= 0:
            break
        snippet, ranges = _extract_snippet(content, hit_line, budget)
        if snippet:
            if ranges:
                range_str = ", ".join(f"{s}-{e}" for s, e in ranges)
                header = f"# {rel_label} (lines {range_str})\n"
            else:
                header = f"# {rel_label}\n"
            entry = header + snippet
            parts.append(entry)
            total += len(entry)
            if rel_label in _debug_by_file:
                _debug_by_file[rel_label]["selection_outcome"] = (
                    "primary_snippet" if _idx == 0 else "secondary_snippet"
                )
                _debug_by_file[rel_label]["snippet_range_1indexed"] = ranges
                _debug_by_file[rel_label]["bytes_contributed"] = len(entry)
                _debug_by_file[rel_label]["truncated"] = "[truncated]" in snippet
            if rel_label in _grounding_decisions:
                _dec = _grounding_decisions[rel_label]
                _dec.outcome = "primary_snippet" if _idx == 0 else "secondary_snippet"
                _dec.snippet_ranges = ranges
                _dec.bytes_contributed = len(entry)
                _dec.truncated = "[truncated]" in snippet
        if total >= _MAX_CONTEXT_CHARS:
            break

    _result = "\n\n".join(parts)
    _write_debug_artifact(_build_debug_record(
        repo_root, _debug_signals, _debug_by_file, _result,
        budget_model="snippet_mode_budget",
        budget_cap=_MAX_CONTEXT_CHARS, budget_used=total,
    ))
    if _grounding_result_out is not None:
        _grounding_result_out.append(_build_grounding_result(
            _grounding_candidates, _grounding_decisions, _debug_signals, _result,
            budget_model="snippet_mode_budget",
            budget_cap=_MAX_CONTEXT_CHARS, budget_used=total,
        ))
    return _result


def ground_repository(vulnerability_text: str, repo_root: Path) -> RepositoryGroundingResult:
    """Run find_code_context()'s scan exactly once and return the full
    domain-object result alongside the same rendered_context string it
    returns. The only intended caller of find_code_context()'s private
    _grounding_result_out parameter."""
    _out: list[RepositoryGroundingResult] = []
    find_code_context(vulnerability_text, repo_root, _grounding_result_out=_out)
    return _out[0]


# ---------------------------------------------------------------------------
# Signal extractors
# ---------------------------------------------------------------------------

def _extract_file_paths(text: str) -> list[str]:
    """Extract plausible relative file paths (e.g. app/auth.py) from text."""
    pattern = re.compile(
        r'\b([\w][\w/\-]*\.(?:py|js|ts|rb|go|java|c|cpp|h|php|cs))\b'
    )
    return list(dict.fromkeys(m.group(1) for m in pattern.finditer(text)))


def _extract_symbols(text: str) -> list[str]:
    """Extract specific function/class symbol names from vulnerability text.

    Priority:
      1. Backtick-quoted identifiers  (`authenticate`, `UserManager`)
      2. snake_case tokens with at least one underscore
      3. PascalCase class names
    """
    seen: dict[str, None] = {}

    def _add(token: str) -> None:
        if len(token) >= 4 and token.lower() not in _GENERIC_TOKENS:
            seen.setdefault(token, None)

    # Backtick-quoted — most specific
    for m in re.finditer(r'`([A-Za-z_][A-Za-z0-9_]*)\s*\(?', text):
        _add(m.group(1))

    # snake_case with at least one underscore
    for m in re.finditer(r'\b([a-z][a-z0-9]+(?:_[a-z][a-z0-9]+)+)\b', text):
        _add(m.group(1))

    # PascalCase (class names)
    for m in re.finditer(r'\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b', text):
        _add(m.group(1))

    return list(seen)[:10]


def _extract_backtick_terms(text: str) -> list[str]:
    """Extract backtick-quoted identifiers without the generic-token filter.

    Advisory authors use backticks to call out specific technical terms —
    header names (``Cookie``, ``Authorization``), parameter names
    (``redirects=False``), symbol names — that are meaningful grep signals
    even when the bare word looks generic.

    Minimum length 2 to exclude single-character noise.
    """
    seen: dict[str, None] = {}
    for m in re.finditer(r'`([A-Za-z_][A-Za-z0-9_]*)', text):
        token = m.group(1)
        if len(token) >= 2:
            seen[token] = None
    return list(seen)[:15]


def _extract_cwes(text: str) -> list[str]:
    return re.findall(r'CWE-\d+', text)


_TYPE_LINE_RE = re.compile(r'\*\*Type:\*\*\s*(.+)')
_CWE_ID_TOKEN_RE = re.compile(r'CWE-\d+')
_NAME_WORD_RE = re.compile(r"[A-Za-z]+(?:['-][A-Za-z]+)*")


def cwe_name_tokens(vulnerability_text: str) -> list[str]:
    """Derive keyword tokens from the advisory's own CWE name.

    Reads the **Type:** line (present in 100% of the advisory corpus via
    advisory_converter.ghsa_to_vuln_text and this project's file-mode
    convention) without assuming which side of the line the bare CWE-NNN
    id appears on, or what punctuation separates it from the name — the
    corpus contains three different shapes (CWE-id-first with parens,
    name-first with parens, name-first with an em-dash and a nested
    parenthetical abbreviation). The bare CWE-NNN token(s) are stripped by
    substitution, never by a positional/structural split, so all three
    shapes are handled without special-casing any of them.

    Parenthetical abbreviations (e.g. "(ReDoS)") are kept, not discarded —
    see reports/implementation_plan_stage2_token_expansion_2026-07-14.md
    §0.3: distinguishing them would require new heuristic logic, and they
    are structurally coined terms-of-art, not generic nouns.

    Returns lowercase tokens: _grep_repo has no case-insensitive matching,
    and lowercase is measurably better recall in real code (verified:
    curl's `credentials` hits 69 files as lowercase vs 2 as `Credentials`).

    Filter: length >= 4 and not in the minimal grammatical _CWE_NAME_STOPWORDS
    set only — no security-vocabulary list, no _GENERIC_TOKENS reuse (see
    the design report's §0.1/§0.2: neither is needed for CWE names the two
    proven benchmark failures actually use, and _GENERIC_TOKENS would strip
    a real token, "service", from node-semver's own CWE-1333 name for no
    corresponding benefit).
    """
    m = _TYPE_LINE_RE.search(vulnerability_text)
    if not m:
        return []
    line = _CWE_ID_TOKEN_RE.sub(' ', m.group(1))
    seen: dict[str, None] = {}
    for word in _NAME_WORD_RE.findall(line):
        token = word.lower()
        if len(token) >= 4 and token not in _CWE_NAME_STOPWORDS:
            seen.setdefault(token, None)
    return list(seen)


# ---------------------------------------------------------------------------
# Repo grep
# ---------------------------------------------------------------------------

def _is_test_file(p: Path) -> bool:
    """Return True if the path looks like a test file."""
    name = p.name.lower()
    rel = str(p).replace("\\", "/").lower()
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or "/tests/" in rel
        or "/test/" in rel
        or "/spec/" in rel
    )


def _grep_repo(
    repo_root: Path,
    tokens: list[str],
    _debug_sink: list | None = None,
    limit: int = 3,
) -> list[tuple[Path, str, int]]:
    """Grep repo_root for token occurrences.

    Returns a list of (path, content, first_hit_line_0indexed) sorted by
    total occurrence count descending, truncated to `limit`. Test files are
    excluded.

    `limit` defaults to 3 — the value every caller used before this
    parameter existed — so any call site that doesn't pass it explicitly is
    unaffected. Pass 2 and Pass 3 each pass their own named constant
    (`_PASS2_CANDIDATE_LIMIT`, `_PASS3_CANDIDATE_LIMIT`) so the two can be
    tuned independently; this function itself stays pass-agnostic.

    _debug_sink, when provided, is appended with one entry per *every*
    matched file (not just the returned top `limit`) — file, per-token
    occurrence counts, total count, and hit line — for observability only.
    It has no effect on the ranking or the returned value.
    """
    patterns = [re.compile(rf'\b{re.escape(t)}\b') for t in tokens]
    hits: list[tuple[int, Path, str, int]] = []  # (count, path, content, hit_line)

    for p in sorted(repo_root.rglob("*")):
        if p.is_dir():
            continue
        if any(part in _IGNORED_DIRS for part in p.parts):
            continue
        if p.suffix not in _SOURCE_EXTENSIONS:
            continue
        if _is_test_file(p):
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Count total occurrences across all patterns (not just unique pattern hits).
        count = sum(len(pat.findall(content)) for pat in patterns)
        if count == 0:
            continue

        # Find first matching line index
        first_hit = 0
        for i, line in enumerate(content.splitlines()):
            if any(pat.search(line) for pat in patterns):
                first_hit = i
                break

        hits.append((count, p, content, first_hit))

        if _debug_sink is not None:
            _debug_sink.append({
                "file": p,
                "matched_tokens": {
                    t: len(pat.findall(content))
                    for t, pat in zip(tokens, patterns)
                    if pat.findall(content)
                },
                "total_occurrences": count,
                "hit_line_0indexed": first_hit,
            })

    hits.sort(key=lambda x: -x[0])
    return [(p, content, hit_line) for _, p, content, hit_line in hits[:limit]]


# ---------------------------------------------------------------------------
# Class-definition supplement
# ---------------------------------------------------------------------------

def _find_class_definitions(
    vulnerability_text: str, repo_root: Path
) -> list[tuple[Path, str, int]]:
    """Return (path, content, hit_line) for Python files that define a class
    named in the advisory text.

    Only PascalCase names of length >= _MIN_CLASS_NAME_LENGTH are considered;
    shorter names are too generic (e.g. "Foo", "Base") and produce false
    positives.  Results are sorted by definition count descending so the
    canonical implementation floats above re-export shims.

    hit_line is the 0-indexed line of the first class definition match,
    so that _extract_snippet centres the secondary snippet on the class body
    rather than the top of the file.

    Python-only.  Test files are excluded.  Returns [] when no qualifying
    class names are present in the advisory.
    """
    class_names = [
        s for s in _extract_symbols(vulnerability_text)
        if re.match(r'^[A-Z][a-z]', s) and len(s) >= _MIN_CLASS_NAME_LENGTH
    ]
    if not class_names:
        return []

    pattern = re.compile(
        r'(?m)^\s*class\s+(' + '|'.join(re.escape(c) for c in class_names) + r')\b'
    )
    hits: list[tuple[int, Path, str, int]] = []
    for p in sorted(repo_root.rglob("*.py")):
        if any(part in _IGNORED_DIRS for part in p.parts):
            continue
        if _is_test_file(p):
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        matches = list(pattern.finditer(content))
        if not matches:
            continue
        first_hit_line = content[: matches[0].start()].count("\n")
        hits.append((len(matches), p, content, first_hit_line))

    hits.sort(key=lambda x: -x[0])
    return [(p, c, line) for _, p, c, line in hits]


# ---------------------------------------------------------------------------
# Docstring / implementation detection
# ---------------------------------------------------------------------------

# Matches lines that open a code block: class/function definitions, ALL_CAPS
# class-level constants, and RST attribute docstrings (#: …) that precede them.
_CODE_ANCHOR_RE = re.compile(
    r"^\s*(def |class |[A-Z][A-Z0-9_]{2,}\s*=|#:\s*\w)"
)


def _is_docstring_line(line: str) -> bool:
    """Return True if `line` looks like prose inside a docstring rather than code.

    Heuristic (no AST):
    - RST directives  (:param, :type, :returns …)
    - Docstring delimiters (triple-quote openers/closers)
    - Lines with no code operators (=  (  {  [  <  >  !) and no keyword starts
    """
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith(":") and len(stripped) > 1 and stripped[1].isalpha():
        return True  # RST directive
    if stripped.startswith(('"""', "'''")):
        return True  # docstring delimiter
    if re.search(r"[=\(\{\[<>!]", stripped):
        return False  # code operator present
    if re.match(
        r"(def|class|return|import|from|if|for|while|raise|with|try|except|yield|async)\b",
        stripped,
    ):
        return False  # keyword
    return True  # likely prose


def _find_code_block_after(
    lines: list[str], after: int, max_lines: int = 40
) -> tuple[str, int] | None:
    """Scan forward from `after` for the first code anchor line.

    A code anchor is a class/function definition, an ALL_CAPS constant
    assignment, or an RST attribute docstring marker (#: …).

    When the anchor is a constant or #: marker, collects lines until the
    first method or class definition (structural boundary) rather than
    stopping at a fixed line count.  This captures the complete
    class-level constant/configuration block regardless of how many
    constants the class contains.

    When the anchor is itself a def/class, falls back to a fixed window
    (max_lines) because structural collection of a method body is not
    useful in this context.

    The caller (_extract_snippet) enforces the character budget; this
    function returns the full structural block and trusts the caller to
    truncate when necessary.

    Returns (text, start_line_0indexed) or None if no anchor found within
    200 lines.
    """
    _SCAN_LIMIT = 200
    for i in range(after, min(len(lines), after + _SCAN_LIMIT)):
        if _CODE_ANCHOR_RE.match(lines[i]):
            # If the first anchor is already a method or class definition we
            # are past the constants block.  Fall back to a fixed window so we
            # do not collect an entire method body.
            if re.match(r"\s*(def|class)\s+", lines[i]):
                end = min(len(lines), i + max_lines)
                return "\n".join(lines[i:end]), i

            # Anchor is a constant or #: marker — collect the entire
            # constant/configuration section by scanning until the first
            # method or class definition.  Terminating at this structural
            # boundary is invariant to the number of constants in the class.
            result: list[str] = []
            for k in range(i, min(len(lines), i + _SCAN_LIMIT)):
                if k > i and re.match(r"\s*(def|class)\s+", lines[k]):
                    break
                result.append(lines[k])
            return "\n".join(result), i
    return None


# ---------------------------------------------------------------------------
# Snippet extraction
# ---------------------------------------------------------------------------

def _extract_snippet(
    content: str, hit_line: int, max_chars: int
) -> tuple[str, list[tuple[int, int]]]:
    """Return (snippet_text, line_ranges) where ranges are 1-indexed inclusive.

    For large files where the hit appears to be inside a docstring, appends
    the nearest downstream code block (class constants, function definitions).
    The code anchor is preserved over the docstring window when budget is tight.

    Non-contiguous snippets (window + anchor) produce two range tuples.
    """
    if max_chars <= 0:
        return "", []
    lines = content.splitlines()

    if len(lines) <= _SMALL_FILE_THRESHOLD:
        raw = content[:max_chars]
        if len(content) > max_chars:
            raw = raw.rsplit("\n", 1)[0] + "\n[truncated]"
        n = len(raw.splitlines())
        return raw, [(1, n)]

    # Hit window (0-indexed [start, end))
    start = max(0, hit_line - _CONTEXT_WINDOW_LINES)
    end = min(len(lines), hit_line + _CONTEXT_WINDOW_LINES + 1)
    window = "\n".join(lines[start:end])
    window_range = (start + 1, end)  # 1-indexed inclusive

    # If the hit is inside a docstring, find the nearest downstream code block.
    hit_text = lines[hit_line] if hit_line < len(lines) else ""
    anchor_result = (
        _find_code_block_after(lines, end) if _is_docstring_line(hit_text) else None
    )

    if anchor_result:
        code_block, anchor_start_0 = anchor_result
        anchor_end_0 = anchor_start_0 + len(code_block.splitlines())
        anchor_range = (anchor_start_0 + 1, anchor_end_0)  # 1-indexed inclusive
        sep = "\n\n"
        anchor_len = len(code_block)

        if anchor_len >= max_chars:
            raw = code_block[:max_chars]
            if "\n" in raw:
                raw = raw.rsplit("\n", 1)[0]
            return raw + "\n[truncated]", [anchor_range]

        window_budget = max_chars - anchor_len - len(sep)
        if window_budget >= 80:
            window_clip = window[:window_budget]
            if len(window) > window_budget:
                window_clip = window_clip.rsplit("\n", 1)[0] + "\n[truncated]"
            return window_clip + sep + code_block, [window_range, anchor_range]
        else:
            return code_block, [anchor_range]

    # No code anchor: standard window
    raw = window[:max_chars]
    if len(window) > max_chars:
        raw = raw.rsplit("\n", 1)[0] + "\n[truncated]"
    return raw, [window_range]


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def _safe_under(p: Path, root: Path) -> bool:
    """Return True if p is under root (no path traversal)."""
    try:
        p.relative_to(root.resolve())
        return True
    except ValueError:
        return False
