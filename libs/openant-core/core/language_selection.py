"""Deciding WHICH detected languages a scan should actually parse.

Detection (``core.parser_adapter.detect_languages``) answers "what is in this
repo". This module answers "what is worth parsing", which is a separate
judgement: spawning a full Go parse for one stray ``tools/gen.go`` in a
5,000-file Python repo costs real time and, downstream, real tokens.

The policy is deliberately conservative in one specific way — the dominant
language is ALWAYS selected, whatever the thresholds say. That guarantees the
selection is never empty for a repo with any supported source, which in turn
guarantees multi-language scanning can never be *less* capable than the
single-language behaviour it replaces.
"""

import math
import sys
from dataclasses import dataclass, field

from core.language_registry import supported_languages

# A language must clear BOTH an absolute floor and a share of the repo. The
# absolute floor stops a handful of files pulling in a whole toolchain; the
# share stops a large-but-proportionally-tiny slice of a monorepo doing the
# same. Tuned to be permissive: the cost of a missed language is a silent
# coverage gap, which is worse than a slightly slow scan.
DEFAULT_MIN_FILES = 5
DEFAULT_MIN_SHARE = 0.02  # 2% of counted source files


class UnknownLanguageError(ValueError):
    """Raised when an explicitly requested language is not supported."""

    def __init__(self, unknown: list[str]):
        self.unknown = unknown
        supported = ", ".join(supported_languages())
        super().__init__(
            f"Unknown language(s): {', '.join(unknown)}. Supported: {supported}"
        )


@dataclass
class LanguageSelection:
    """The outcome of applying selection policy to a detection result.

    Attributes:
        selected: Languages to parse, ordered by descending file count.
        counts: The full detection result, including excluded languages.
        excluded: Language → human-readable reason it was dropped.
            NOT currently surfaced anywhere: callers flatten this object to
            ``selected`` before it reaches the scanner, so exclusion reasons are
            computed and discarded. The coverage gap this field exists to make
            visible is therefore still silent.
        primary: The dominant language. Populates every scalar ``language``
            field downstream, preserving back-compat.
    """

    selected: list[str]
    counts: dict[str, int] = field(default_factory=dict)
    excluded: dict[str, str] = field(default_factory=dict)
    primary: str = ""

    @property
    def is_multi(self) -> bool:
        return len(self.selected) > 1


def select_languages(
    counts: dict[str, int],
    *,
    include: list[str] | None = None,
    all_languages: bool = False,
    min_files: int = DEFAULT_MIN_FILES,
    min_share: float = DEFAULT_MIN_SHARE,
) -> LanguageSelection:
    """Choose which detected languages to parse.

    Rules are applied in this order:

    1. An explicit ``include`` list wins outright — no thresholds. The user
       asked for these languages by name; second-guessing them would be
       surprising. Unknown names raise rather than being silently dropped.
    2. ``all_languages`` disables thresholds but still requires detection.
    3. Otherwise a language is selected iff its count clears
       ``max(min_files, ceil(min_share * total))``.
    4. The dominant language is always selected regardless of the above.

    Args:
        counts: Detection result from ``detect_languages``.
        include: Explicit language list (from ``--languages``).
        all_languages: Select everything detected (from ``--all-languages``).
        min_files: Absolute file-count floor.
        min_share: Fractional share floor, 0.0-1.0.

    Returns:
        A :class:`LanguageSelection`.

    Raises:
        ValueError: If ``counts`` is empty, or ``include`` names an unsupported
            language.
    """
    if not counts:
        raise ValueError("No languages detected; nothing to select from.")

    # counts arrives ordered by (-count, name) from detect_languages, but do
    # not depend on the caller having preserved that.
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    primary = ordered[0][0]

    if include:
        requested = [lang.strip().lower() for lang in include if lang.strip()]
        unknown = [lang for lang in requested if lang not in supported_languages()]
        if unknown:
            raise UnknownLanguageError(unknown)

        # Preserve detection order, and keep requested-but-absent languages out
        # of `selected` — parsing a language with zero files is pure overhead.
        selected = [lang for lang, _ in ordered if lang in requested]
        excluded = {
            lang: "not requested via --languages"
            for lang, _ in ordered
            if lang not in requested
        }
        for lang in requested:
            if lang not in counts:
                excluded[lang] = "explicitly requested but no source files found"

        if not selected:
            # Falling through with an empty selection let callers treat it as
            # "no multi-language request" and re-detect the dominant language —
            # inverting an explicit user instruction and, under `scan`, billing
            # LLM analysis of a language the user had scoped out.
            raise ValueError(
                f"None of the requested language(s) {requested} have source "
                f"files in this repository (detected: {sorted(counts)}). "
                "Nothing to parse."
            )

        return LanguageSelection(
            selected=selected,
            counts=dict(ordered),
            excluded=excluded,
            # `primary` must stay a language we actually parse, otherwise the
            # scalar `language` field downstream would name an unscanned one.
            primary=selected[0] if selected else primary,
        )

    if all_languages:
        return LanguageSelection(
            selected=[lang for lang, _ in ordered],
            counts=dict(ordered),
            excluded={},
            primary=primary,
        )

    total = sum(counts.values())
    threshold = max(min_files, math.ceil(min_share * total))

    selected: list[str] = []
    excluded: dict[str, str] = {}
    for lang, count in ordered:
        if lang == primary:
            # Rule 4: never let thresholds empty the selection.
            selected.append(lang)
            continue
        if count >= threshold:
            selected.append(lang)
        else:
            share = (count / total) * 100 if total else 0.0
            excluded[lang] = (
                f"{count} file(s) ({share:.2f}%) below threshold of {threshold}"
            )

    return LanguageSelection(
        selected=selected,
        counts=dict(ordered),
        excluded=excluded,
        primary=primary,
    )


def report_exclusions(excluded: dict[str, str]) -> None:
    """Print excluded languages to stderr as an explicit coverage gap.

    Thresholds are allowed to skip work; they are not allowed to do it
    quietly. For a security scanner a silently-skipped language is a silently
    missed vulnerability class — a 4-file PHP upload handler in a JS monorepo
    is precisely what the tool exists to find, and the parse it saves costs
    ~0.1s. So the exclusion is reported wherever a human or a CI log will see
    it, with the reason verbatim.
    """
    if not excluded:
        return
    print("\n  COVERAGE GAP — languages detected but NOT scanned:", file=sys.stderr)
    for language, reason in sorted(excluded.items()):
        print(f"    {language}: {reason}", file=sys.stderr)
    print(
        "  Use --all-languages to scan everything, or --languages to name a set.",
        file=sys.stderr,
    )
