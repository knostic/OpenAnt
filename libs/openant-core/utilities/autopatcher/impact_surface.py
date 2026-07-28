"""Impact surface analyzer (lightweight, deterministic).

Single-file analyzer that parses a unified diff, extracts changed
Python function symbols, searches the repo for usages, classifies
impact as low/medium/high, and returns a minimal ImpactReport.

This module is intentionally self-contained and dependency-free so it
can be safely executed inside the pipeline without external tools.

Symbol resolution deliberately never trusts a diff hunk header's declared
line number as ground truth for where its content lives in the current
file — LLM-generated patches can anchor a hunk at a drifted line number
even when the actual changed content is byte-identical (observed directly:
the same one-line urllib3 constant change reported at hunk header @@-189
in one run and @@-196 in another). Trusting that number caused symbol
resolution to read the wrong slice of the real file, fail to recognize a
constant assignment, and fall back to whatever unrelated `def` happened to
be nearby — `__init__` in that case — which then drove a false HIGH impact
classification purely from where the LLM happened to anchor its hunk.

Instead: the hunk's own context/removed lines are relocated in the current
file by content (difflib.SequenceMatcher), never by trusting the header,
and the enclosing symbol is then resolved structurally via `ast` (so
comments and whitespace can never be mistaken for code, and nested
scopes/class-level constants resolve correctly) rather than by a regex
"nearest `def` above" text scan.
"""
from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Tuple, Optional

from .diff_parsing import DiffHunk, parse_diff


@dataclass
class UsageMatch:
    symbol: str
    file: str
    line: int
    snippet: str


@dataclass
class ImpactReport:
    changed_files: List[str]
    changed_symbols: List[str]
    usage_matches: List[UsageMatch]
    affected_files: List[str]
    impact_level: str  # low | medium | high
    impact_summary: str
    recommendations: List[str]

    def to_dict(self) -> Dict:
        return {
            "changed_files": self.changed_files,
            "changed_symbols": self.changed_symbols,
            "usage_matches": [asdict(u) for u in self.usage_matches],
            "affected_files": self.affected_files,
            "impact_level": self.impact_level,
            "impact_summary": self.impact_summary,
            "recommendations": self.recommendations,
        }


class ImpactAnalyzer:
    """Abstract interface for impact analyzers."""

    def analyze(self, repo_root: Path, patch_diff: str, adversarial_findings: List[Dict] | None = None) -> ImpactReport:
        raise NotImplementedError()


class LightweightImpactAnalyzer(ImpactAnalyzer):
    """Deterministic, dependency-free lightweight analyzer.

    Behavior:
    - parse unified diff to find changed files and hunks (keeping each
      hunk's own body text, not just its claimed line range)
    - relocate each hunk's content in the CURRENT file by text match
      (never by trusting the hunk header's line number)
    - resolve the enclosing Python symbol structurally via `ast`
    - grep repository for usages of those symbols (simple token heuristics)
    - classify impact as low/medium/high using deterministic thresholds
    """

    IGNORED_DIRS = {".venv", "__pycache__", ".git", "node_modules"}
    TEST_PATH_PATTERNS = ("/tests/", "/test_", "/spec/")
    ENTRYPOINT_HINTS = ("routes", "handlers", "views", "api", "auth", "server", "app", "main")

    SENSITIVE_KEYWORDS = {
        "auth",
        "login",
        "password",
        "token",
        "validate",
        "sanitize",
        "input",
        "security",
        "permission",
        "access",
    }

    def analyze(
        self,
        patch_diff: str,
        adversarial_findings: List[Dict] | None = None,
        repo_context=None,
        repo_language: str = "python",
    ) -> ImpactReport:
        """Analyze the provided unified diff and return an ImpactReport.

        Backwards-compatible: callers may omit `repo_context`, in which case
        this function will use Path-based filesystem access (current behavior).
        When `repo_context` is provided, file reads will be routed through it.

        Symbol extraction and usage search only understand Python syntax and
        only scan `.py`/`.pyi` files. When `repo_language` is not "python",
        this analysis is not meaningful for the target repository — return an
        explicit "not_applicable" report (keeping only the language-agnostic
        changed-files list from the diff) rather than a "low impact" verdict
        manufactured by finding zero Python symbols to extract.
        """
        changed_files, file_hunks = parse_diff(patch_diff)

        if repo_language != "python":
            return ImpactReport(
                changed_files=changed_files,
                changed_symbols=[],
                usage_matches=[],
                affected_files=[],
                impact_level="not_applicable",
                impact_summary=(
                    "Not Applicable — language not supported by this signal yet "
                    f"(detected: {repo_language}). Changed-symbol and usage-impact "
                    "analysis only supports Python source."
                ),
                recommendations=[],
            )

        changed_symbols: List[str] = []
        for f in changed_files:
            if f.endswith(".py"):
                hunks = file_hunks.get(f, [])
                syms = self._extract_symbols(f, hunks, repo_context=repo_context)
                changed_symbols.extend(syms)

        # Unique symbols
        changed_symbols = list(dict.fromkeys(changed_symbols))

        usage_matches = self._search_usages(changed_symbols, repo_context=repo_context)

        # Exclude test files and also exclude the changed files themselves
        affected_files = sorted({m.file for m in usage_matches if not self._is_test_path(m.file) and m.file not in changed_files})

        impact_level = self._classify(affected_files, changed_files)

        # Sensitive context detection: bump low->medium and adapt summary
        context_type = self._detect_sensitive(changed_symbols, changed_files, affected_files)
        if context_type and impact_level == "low":
            impact_level = "medium"

        impact_summary = self._build_summary(changed_symbols, affected_files, changed_files, impact_level, context_type)

        recommendations = self._recommendations_for_level(impact_level)

        return ImpactReport(
            changed_files=changed_files,
            changed_symbols=changed_symbols,
            usage_matches=usage_matches,
            affected_files=affected_files,
            impact_level=impact_level,
            impact_summary=impact_summary,
            recommendations=recommendations,
        )

    # ---- content-based relocation (never trusts the hunk header's line number) ----
    def _normalize(self, raw_line: str) -> str:
        """Strip a leading diff marker if present, then strip surrounding
        whitespace — makes matching and comparison whitespace-tolerant."""
        if raw_line[:1] in (" ", "+", "-"):
            raw_line = raw_line[1:]
        return raw_line.strip()

    def _anchor_lines(self, hunk_lines: List[str]) -> Tuple[List[str], List[bool]]:
        """Return (anchors, changed_flags): the lines expected to already
        exist in the CURRENT (pre-patch) file — context (' ') and removed
        ('-') lines — normalized, plus a parallel flag marking which of
        those positions are the actual edit (removed lines) versus
        surrounding context.

        Falls back to added ('+') lines, all flagged as "changed", only when
        a hunk has no context/removed lines at all — a pure-insertion hunk
        has nothing pre-existing to anchor on.
        """
        pairs = [(self._normalize(l), l[:1] == "-") for l in hunk_lines if l[:1] in (" ", "-")]
        if pairs:
            return [p[0] for p in pairs], [p[1] for p in pairs]
        added = [self._normalize(l) for l in hunk_lines if l[:1] == "+"]
        return added, [True for _ in added]

    def _is_whitespace_only_hunk(self, hunk_lines: List[str]) -> bool:
        """True when a hunk's removed and added lines are identical once
        each is whitespace-normalized — a purely cosmetic change that must
        not be attributed to any symbol."""
        removed = [self._normalize(l) for l in hunk_lines if l[:1] == "-"]
        added = [self._normalize(l) for l in hunk_lines if l[:1] == "+"]
        if not removed or not added:
            return False
        return removed == added

    def _locate_hunk(self, anchors: List[str], file_lines: List[str]) -> Optional[int]:
        """Find the 0-indexed start line in file_lines where `anchors` best
        matches, using difflib.SequenceMatcher over whitespace-normalized
        text. The hunk header's claimed line number is never consulted here
        — only content match. Returns None when no sufficiently confident
        match exists (e.g. the anchor text appears nowhere in the file),
        rather than guessing.
        """
        if not anchors:
            return None
        normalized_file = [self._normalize(l) for l in file_lines]
        matcher = difflib.SequenceMatcher(None, normalized_file, anchors, autojunk=False)
        match = matcher.find_longest_match(0, len(normalized_file), 0, len(anchors))
        if match.size == 0:
            return None
        # Require most of the anchor to align, not just one coincidental
        # shared line, before trusting the location.
        if match.size < min(len(anchors), 2):
            return None
        return max(0, match.a - match.b)

    # ---- structural symbol resolution via ast (never a text/regex scan) ----
    def _build_symbol_index(self, file_text: str) -> Optional[List[Tuple[int, int, str]]]:
        """Parse file_text and return [(lineno, end_lineno, name), ...] for
        every module-level or class-level function/class/simple assignment,
        1-indexed and inclusive, matching ast's own line numbering.

        Returns None when the file does not parse as valid Python — callers
        must treat that as "structural analysis unavailable" and skip symbol
        attribution for this file, never fall back to a guess.
        """
        try:
            tree = ast.parse(file_text)
        except (SyntaxError, ValueError):
            return None

        index: List[Tuple[int, int, str]] = []

        def walk(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    end = getattr(child, "end_lineno", None) or child.lineno
                    index.append((child.lineno, end, child.name))
                    walk(child)
                elif isinstance(child, (ast.Assign, ast.AnnAssign)) and isinstance(node, (ast.Module, ast.ClassDef)):
                    # Only direct module-level/class-level assignments count
                    # as symbols — local variables inside function bodies
                    # aren't something a repo-wide usage search makes sense
                    # for, and indexing them would blur "changed symbol"
                    # beyond what this analyzer is meant to answer.
                    targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                    for t in targets:
                        if isinstance(t, ast.Name):
                            end = getattr(child, "end_lineno", None) or child.lineno
                            index.append((child.lineno, end, t.id))
                else:
                    walk(child)

        walk(tree)
        return index

    def _resolve_symbol_at_line(self, index: List[Tuple[int, int, str]], line: int) -> Optional[str]:
        """Return the name of the smallest span in `index` containing
        `line` — i.e. the innermost enclosing symbol. Nested scopes always
        have strictly smaller spans than their containers, so this
        naturally prefers a directly-changed function/assignment over its
        enclosing class/module without any separate special case."""
        candidates = [(end - lineno, name) for lineno, end, name in index if lineno <= line <= end]
        if not candidates:
            return None
        candidates.sort(key=lambda c: c[0])
        return candidates[0][1]

    def _extract_symbols(self, file_path: Path | str, hunks: List[DiffHunk], repo_context=None) -> List[str]:
        """Extract changed Python symbol names for a file's hunks.

        For each hunk: skip it entirely if it's whitespace-only (cosmetic,
        no symbol attribution); otherwise relocate its actual edit by
        content in the current file (never by the hunk header's line
        number) and resolve the innermost enclosing symbol there via ast.
        Silently produces no symbol for a hunk that can't be confidently
        relocated or a file that doesn't parse — never guesses.
        """
        symbols: List[str] = []
        try:
            if repo_context is not None:
                rel = file_path if isinstance(file_path, str) else str(file_path)
                text = repo_context.read_file(rel)
            else:
                text = Path(file_path).read_text(encoding="utf-8")
        except Exception:
            return symbols

        file_lines = text.splitlines()
        symbol_index = self._build_symbol_index(text)
        if symbol_index is None:
            return symbols

        for hunk in hunks:
            if self._is_whitespace_only_hunk(hunk.lines):
                continue

            anchors, changed_flags = self._anchor_lines(hunk.lines)
            start_idx = self._locate_hunk(anchors, file_lines)
            if start_idx is None:
                continue

            changed_positions = [start_idx + i for i, is_changed in enumerate(changed_flags) if is_changed]
            if not changed_positions:
                changed_positions = [start_idx + i for i in range(len(anchors))]
            true_start = min(changed_positions) + 1  # 1-indexed
            true_end = max(changed_positions) + 1

            resolved = self._resolve_symbol_at_line(symbol_index, true_start)
            if resolved is None and true_end != true_start:
                resolved = self._resolve_symbol_at_line(symbol_index, true_end)
            if resolved:
                symbols.append(resolved)

        return symbols

    def _search_usages(self, symbols: List[str], repo_context=None) -> List[UsageMatch]:
        """Greedy repo scan for symbol usage. Returns UsageMatch list.

        This keeps the existing traversal logic (Path.rglob) when no
        `repo_context` is provided. When `repo_context` is present, file
        contents are read via `repo_context.read_file(rel)` where `rel` is a
        repo-relative path string; the traversal still uses Path.rglob so the
        set of files examined is unchanged.
        """
        matches: List[UsageMatch] = []
        if not symbols:
            return matches
        # prepare patterns
        token_patterns = []
        for s in symbols:
            token_patterns.append(re.compile(rf"\b{re.escape(s)}\s*\("))
            token_patterns.append(re.compile(rf"\b{re.escape(s)}\b"))

        # Determine traversal root: when repo_context is available it still
        # follows the current working directory semantics unless the caller
        # uses pipeline to pass a different cwd. We preserve the existing
        # behavior by using Path.cwd() as the traversal root when no explicit
        # repo_root is supplied at the pipeline level.
        repo_root = repo_context.repo_root if repo_context is not None else Path.cwd()

        for p in repo_root.rglob("**/*"):
            try:
                if p.is_dir():
                    continue
                # skip ignored dirs
                parts = [part for part in p.parts]
                if any(ign in parts for ign in self.IGNORED_DIRS):
                    continue
                rel = str(p.relative_to(repo_root))
                # skip tests
                if self._is_test_path(rel):
                    continue
                # only scan Python source files for symbol usages
                if p.suffix not in {".py", ".pyi"}:
                    continue
                # read file text
                if repo_context is not None:
                    text = repo_context.read_file(rel)
                else:
                    text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for i, line in enumerate(text.splitlines(), start=1):
                for si, pat in enumerate(token_patterns):
                    if pat.search(line):
                        sym_idx = si // 2
                        matches.append(UsageMatch(symbols[sym_idx], rel, i, line.strip()))
        return matches

    def _is_test_path(self, relpath: str) -> bool:
        lp = relpath.replace("\\", "/")
        lower = lp.lower()
        if any(p in lower for p in self.TEST_PATH_PATTERNS):
            return True
        return False

    def _classify(self, affected_files: List[str], changed_files: List[str]) -> str:
        # Exclude changed files when counting external impact
        external_files = [f for f in affected_files if f not in changed_files and not self._is_test_path(f)]
        non_test_count = len(external_files)
        # Entry point heuristic: consider both affected files and changed files
        entrypoint_hit = any(
            any(h in f.lower() for h in self.ENTRYPOINT_HINTS)
            for f in list(affected_files) + list(changed_files)
        )

        if non_test_count == 0:
            return "low"
        if non_test_count >= 3 or entrypoint_hit:
            return "high"
        # 1-2 external files
        return "medium"

    def _build_summary(self, symbols: List[str], affected_files: List[str], changed_files: List[str], level: str, context_type: str | None = None) -> str:
        # Prefer an explicit symbol name, then changed file path for low-impact summaries
        sym = symbols[0] if symbols else None
        changed_file = changed_files[0] if changed_files else None
        if context_type:
            # Sensitive-context phrasing
            if context_type == "auth":
                ex = f"This change touches authentication-related logic ({sym or changed_file or '(unknown)'} ) — even localized changes may impact access control and should be carefully reviewed."
            elif context_type == "validation":
                ex = f"The modified code is part of input validation/sanitization ({sym or changed_file or '(unknown)'} ) — potential security boundary risk."
            else:
                ex = f"This change touches security-sensitive code ({sym or changed_file or '(unknown)'} ) — review recommended."
            # If level is high, also mention breadth
            if level == "high":
                ex = ex + f" Also referenced by {len(affected_files)} modules; potential system-wide impact."
            return ex

        if level == "high":
            ex = f"This change affects {sym or changed_file or '(unknown)'} used by {len(affected_files)} production modules including {', '.join(affected_files[:2])} — potential system-wide impact; review recommended."
        elif level == "medium":
            ex = f"This change affects {sym or changed_file or '(unknown)'} used by a few components ({len(affected_files)}) — validate across flows and add tests."
        else:
            # low: mention changed symbol or file explicitly when available
            target = None
            if sym:
                target = f"`{sym}()`"
            elif changed_file:
                target = f"`{changed_file}`"
            else:
                target = "(local)"
            ex = f"Change appears localized to {target} — low operational risk."
        return ex

    def _detect_sensitive(self, symbols: List[str], changed_files: List[str], affected_files: List[str]) -> str | None:
        """Detect sensitive context; return a context_type string or None.

        Context types: 'auth' for authentication-related, 'validation' for input
        validation/sanitization, or 'security' for generic security keywords.
        """
        keywords = self.SENSITIVE_KEYWORDS
        def check_text(t: str) -> bool:
            tl = t.lower()
            return any(k in tl for k in keywords)

        # Check symbols first
        for s in symbols:
            if not s:
                continue
            if any(k in s.lower() for k in ("auth", "login", "password", "token", "access", "permission")):
                return "auth"
            if any(k in s.lower() for k in ("validate", "sanitize", "input")):
                return "validation"
            if check_text(s):
                return "security"

        # Check changed_files paths
        for f in changed_files:
            if check_text(f):
                # pick auth vs validation heuristics
                if any(k in f.lower() for k in ("auth", "login", "password", "token", "access", "permission")):
                    return "auth"
                if any(k in f.lower() for k in ("validate", "sanitize", "input")):
                    return "validation"
                return "security"

        # Check affected files as fallback
        for f in affected_files:
            if check_text(f):
                if any(k in f.lower() for k in ("auth", "login", "password", "token", "access", "permission")):
                    return "auth"
                if any(k in f.lower() for k in ("validate", "sanitize", "input")):
                    return "validation"
                return "security"

        return None

    def _recommendations_for_level(self, level: str) -> List[str]:
        if level == "high":
            return ["review", "add_test"]
        if level == "medium":
            return ["add_test"]
        return ["no_action"]
