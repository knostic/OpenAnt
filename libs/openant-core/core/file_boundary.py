"""Single source of truth for the multi-file unit boundary marker.

When a unit inlines its dependencies, the parser concatenates several files'
source into one ``primary_code`` blob and separates them with a marker. That
marker must be a COMMENT in the language being parsed — a ``//`` line inside
Python source is a syntax error — so producers emit it with their own comment
prefix:

    python, ruby              ->  # ========== File Boundary ==========
    javascript, go, c, php,   -> // ========== File Boundary ==========
    zig

Consumers, however, historically matched the ``//`` form literally
(``prompts/vulnerability_analysis.py``, ``prompts/verification_prompts.py``,
``validate_dataset_schema.py``, ``utilities/agentic_enhancer/agent.py``). For
Python and Ruby the split therefore never fired, and the fallback branch
handed the model the ENTIRE concatenation as the target function while
silently dropping the "Context (do NOT analyze these)" section — so dependency
code was analysed as if it were the unit under test.

The fix is to agree on the part that does not vary: the text between the
comment prefix and the end of the line. Match on that, emit with the right
prefix.
"""

import re

# The invariant substring every producer emits, whatever its comment syntax.
BOUNDARY_TEXT = "========== File Boundary =========="

# Comment prefix per language. Anything not listed uses the C-style default,
# matching the pre-existing behaviour of the agentic enhancer.
_COMMENT_PREFIX = {
    "python": "#",
    "ruby": "#",
    "javascript": "//",
    "typescript": "//",
    "go": "//",
    "c": "//",
    "cpp": "//",
    "php": "//",
    "zig": "//",
}

_DEFAULT_PREFIX = "//"

# A whole boundary line: optional leading comment prefix, then the invariant
# text. Anchored to line starts so the marker cannot be matched inside a
# string literal that merely contains the words.
_BOUNDARY_LINE = re.compile(
    rf"^[ \t]*(?:#|//)?[ \t]*{re.escape(BOUNDARY_TEXT)}[ \t]*$",
    re.MULTILINE,
)


def neutralize_boundaries(source: str) -> str:
    """Defang boundary-shaped lines in untrusted source before concatenation.

    This is the security half of the boundary contract, and it belongs to the
    *producer*. A consumer cannot defend itself: once several files are joined into
    one blob, a marker the attacker wrote and a marker the parser wrote are the same
    bytes, and no amount of pattern-tightening distinguishes them.

    The attack it prevents: scanned source contains a line that looks like a
    boundary. ``split_on_boundary`` then cuts the unit there, and everything after
    the forged line is relabelled "Context (do NOT analyze these)" in the prompt —
    so a repository hides a vulnerability from both analysis stages with one comment.

    This was not exploitable before multi-language support, by accident rather than
    design: the matcher required ``//``, which is a syntax error in Python, so the
    marker could not appear in real Python source. Teaching the matcher to accept
    ``#`` fixed a genuine bug (Python and Ruby units never split at all, so
    dependency code was analysed as the target) and simultaneously made the marker
    forgeable in exactly the languages that had just been fixed. Hence a
    neutralizer rather than a tighter pattern: the previous attempt to fix this by
    adjusting the regex is what created the hole.

    The replacement is deliberately visible rather than silent. The model still sees
    that a suspicious line was present, which is itself signal, and a reviewer
    reading the prompt can tell defanging happened.
    """
    if not source:
        return source
    return _BOUNDARY_LINE.sub(
        "# [openant] boundary-shaped line from scanned source, neutralized", source
    )


def has_boundary(code: str) -> bool:
    """Whether *code* contains at least one file-boundary marker."""
    if not code:
        return False
    return _BOUNDARY_LINE.search(code) is not None


def split_on_boundary(code: str) -> list[str]:
    """Split concatenated multi-file code into its constituent parts.

    Comment-syntax-agnostic: a Python unit separated by ``#`` markers and a
    JavaScript unit separated by ``//`` markers both split correctly, as does a
    blob carrying both (possible once units from several languages share a
    merged dataset).

    Args:
        code: The unit's ``primary_code``.

    Returns:
        The parts, in order. Index 0 is the target function; the rest are
        inlined dependencies. A single-file unit yields a one-element list, so
        callers can branch on ``len(parts) > 1`` exactly as before.
    """
    if not code:
        return [code]
    return _BOUNDARY_LINE.split(code)


def boundary_in_code(code: str, default_language: str | None = None) -> str:
    """The boundary marker as it actually appears in *code*.

    Used when re-joining split parts: echoing back the producer's own marker
    keeps the output byte-faithful to the input, and means callers that have no
    language parameter (``get_verification_prompt``) need not grow one just to
    pick a comment prefix.

    Falls back to ``default_language``'s marker, then to the C-style default,
    when *code* carries no boundary.
    """
    if code:
        match = _BOUNDARY_LINE.search(code)
        if match is not None:
            return f"\n\n{match.group(0).strip()}\n\n"
    return boundary_for_language(default_language)


def boundary_for_language(language: str | None) -> str:
    """The boundary marker to EMIT for *language*, with surrounding blank lines.

    Matches the producers' formatting so round-tripping is exact.
    """
    prefix = _COMMENT_PREFIX.get((language or "").lower(), _DEFAULT_PREFIX)
    return f"\n\n{prefix} {BOUNDARY_TEXT}\n\n"
