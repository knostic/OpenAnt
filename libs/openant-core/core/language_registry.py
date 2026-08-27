"""Single source of truth for the supported-language set.

Before this module, four places independently described which languages
OpenAnt supports, and they drifted:

  1. ``config/languages.json`` — the extension→language map used for detection.
  2. The ``if/elif`` dispatch chain in ``core/parser_adapter.py``.
  3. ``argparse`` ``choices=[...]``, duplicated in two places in ``openant/cli.py``.
  4. Go flag help strings in ``cmd/init.go``, ``cmd/scan.go``, ``cmd/parse.go``.

The drift was not hypothetical: ``scan.go`` and ``parse.go`` omitted Zig from
their help text, and so did ``README.md``. Adding a language meant remembering
seven files.

``config/languages.json`` is now authoritative and everything else derives from
it. The legacy top-level ``extensions`` and ``skip_dirs`` maps are preserved
byte-for-byte, because the Go detector (``cmd/init.go``) reads the same file and
must keep working without a coordinated cross-language change; a consistency
test asserts the legacy flat map stays exactly the union of the per-language
lists, so the two representations cannot silently diverge.

Adding a language is now a config edit plus a ``parsers/<lang>/`` directory.
"""

import os
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from utilities.file_io import read_json

# Where config/languages.json may live, in priority order:
#   1. $OPENANT_LANGUAGES_CONFIG (explicit operator override)
#   2. upward from this module   (monorepo checkout, and an installed layout
#                                 that ships the config as package data)
#   3. upward from the CWD       (running against a checkout from elsewhere)
#
# A bare `parent.parent.parent.parent` resolves correctly ONLY in the monorepo
# checkout; under an installed layout it points outside the distribution. That
# was not a graceful degradation: `supported_languages()` runs during argparse
# construction, so a missing config raised FileNotFoundError before the CLI
# parsed a single flag — `openant --help` died. The Go side already searched
# upward from both the executable and the CWD and degraded rather than failing
# at flag-registration time; this brings Python to the same contract.
_CONFIG_REL = Path("config") / "languages.json"
_SEARCH_LEVELS = 6


def _search_upward(start: Path) -> Path | None:
    current = start.resolve()
    for _ in range(_SEARCH_LEVELS):
        candidate = current / _CONFIG_REL
        if candidate.is_file():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def find_languages_config() -> Path | None:
    """Locate config/languages.json, or None if it cannot be found.

    Returning None rather than raising is deliberate: callers on the CLI's
    startup path must degrade, not die.
    """
    override = os.environ.get("OPENANT_LANGUAGES_CONFIG")
    if override:
        candidate = Path(override)
        if candidate.is_file():
            return candidate
        # A stale override must not be more destructive than no override.
        print(
            f"[languages] OPENANT_LANGUAGES_CONFIG={override!r} not found; "
            "falling back to search",
            file=sys.stderr,
        )

    found = _search_upward(Path(__file__).parent)
    if found is not None:
        return found
    found = _search_upward(Path.cwd())
    if found is not None:
        # #273 visibility: the CWD leg can find a config in the working
        # directory — including a scanned repo's own config when run from
        # inside it. skip_dirs/extensions from it are data-only (parser
        # scripts are hard-guarded in parser_script_path); this note makes
        # the source loud instead of silent.
        print(
            f"[languages] note: config/languages.json located via the "
            f"working directory ({found}); if this is the scanned "
            f"repository, its settings are being trusted for "
            f"skip_dirs/extensions",
            file=sys.stderr,
        )
    return found

# Root of openant-core, used to resolve parser script paths.
_CORE_ROOT = Path(__file__).parent.parent

# Key used inside a per-extension ``fence`` mapping for "everything else".
_FENCE_DEFAULT_KEY = "*"


@dataclass(frozen=True)
class LanguageSpec:
    """Everything OpenAnt knows about one supported language.

    Attributes:
        name: Canonical language name (the value used everywhere as the key).
        extensions: File extensions claimed by this language, lowercase, with
            the leading dot.
        parser_mode: ``"inprocess"`` or ``"subprocess"``. Python is parsed
            in-process; every other parser is a subprocess with a shared argv
            contract. This asymmetry is data rather than control flow so the
            dispatch chain can be a lookup.
        parser_script: Repo-relative path to the subprocess entry point, or
            ``None`` for in-process parsers.
        bootstrap: Optional pre-parse hook name (``"npm"`` for JavaScript,
            whose parser carries its own ``package.json``).
        fence: Markdown code-fence tag. Either a plain string, or a mapping of
            extension → tag with a ``"*"`` fallback for languages where one
            parser covers several fence tags (``.ts`` must fence as
            ``typescript``, ``.cpp`` as ``cpp``).
        docker_template: Template name for dynamic exploit testing, or ``None``
            when no template exists. ``None`` means "skip", never "guess".
        enabled: Whether this language participates in detection and dispatch.
    """

    name: str
    extensions: tuple[str, ...]
    parser_mode: str
    parser_script: str | None
    bootstrap: str | None
    fence: str | dict[str, str]
    docker_template: str | None
    enabled: bool


@lru_cache(maxsize=1)
def _load_config() -> dict:
    """Read and cache ``config/languages.json``.

    Cached because detection walks large trees and would otherwise re-read the
    file per call. Tests that mutate the config must call
    ``load_registry.cache_clear()`` / ``_load_config.cache_clear()``.
    """
    path = find_languages_config()
    if path is None:
        # Degrade to an empty registry. Consumers that merely DESCRIBE the
        # language set (help text, choices) then show nothing rather than
        # crashing; consumers that need to actually parse still fail loudly
        # because detection finds no extensions and raises.
        return {}
    return read_json(path)


@lru_cache(maxsize=1)
def load_registry() -> dict[str, LanguageSpec]:
    """Build the language registry from config.

    Returns:
        Mapping of language name → :class:`LanguageSpec`, insertion-ordered by
        language name so downstream iteration is deterministic.
    """
    config = _load_config()
    raw = config.get("languages", {})

    registry: dict[str, LanguageSpec] = {}
    for name in sorted(raw):
        entry = raw[name]
        parser = entry.get("parser", {})
        registry[name] = LanguageSpec(
            name=name,
            extensions=tuple(ext.lower() for ext in entry.get("extensions", [])),
            parser_mode=parser.get("mode", "subprocess"),
            parser_script=parser.get("script"),
            bootstrap=parser.get("bootstrap"),
            fence=entry.get("fence", name),
            docker_template=entry.get("docker_template"),
            enabled=entry.get("enabled", True),
        )
    return registry


def supported_languages() -> list[str]:
    """Enabled language names, sorted — the canonical list for CLI choices."""
    return [name for name, spec in load_registry().items() if spec.enabled]


def require_registry() -> dict[str, LanguageSpec]:
    """The registry, or a loud failure explaining that the install is broken.

    ``load_registry()`` degrades to ``{}`` when the config is missing, which is
    right for callers that merely DESCRIBE the language set — ``--help`` must not
    die because a data file moved. It is wrong for callers that need to actually
    do work: with an empty registry, detection finds zero source files and reports
    "repository has no supported source files", which sends the operator to look at
    their repository when the fault is in the installation.

    That misattribution is worse than the original crash it replaced. Go already
    fails loudly on the identical condition (``registry.go`` returns an error), so
    the two runtimes disagreed about the same missing file. This restores the loud
    contract for the paths that need it, without putting ``--help`` back at risk.
    """
    registry = load_registry()
    if not registry:
        searched = os.environ.get("OPENANT_LANGUAGES_CONFIG") or "$OPENANT_LANGUAGES_CONFIG (unset)"
        raise RuntimeError(
            "config/languages.json could not be found, so no languages are known. "
            "This is an installation problem, not a problem with the repository "
            "being scanned. Searched: "
            f"{searched}, then upward from {Path(__file__).parent} and {Path.cwd()}."
        )
    return registry


def extension_map() -> dict[str, str]:
    """Extension → language name, derived from the per-language lists.

    This is the same content as the legacy top-level ``extensions`` map; a
    consistency test asserts they match so the Go reader and the Python reader
    cannot drift.

    Raises:
        RuntimeError: If no config could be located. Detection cannot do anything
            useful with an empty map, and failing here names the real cause.
    """
    return {
        ext: spec.name
        for spec in require_registry().values()
        if spec.enabled
        for ext in spec.extensions
    }


def skip_dirs() -> frozenset[str]:
    """Directory names pruned during detection and scanning."""
    return frozenset(_load_config().get("skip_dirs", []))


def language_for_path(path: str | os.PathLike) -> str | None:
    """Language owning this file, by extension, or ``None`` if unsupported."""
    suffix = Path(path).suffix.lower()
    return extension_map().get(suffix)


def fence_for_path(path: str | os.PathLike, fallback: str | None = None) -> str:
    """Markdown code-fence tag for a file, resolved by EXTENSION.

    Resolving per file rather than per scan is a correctness fix, not just
    multi-language plumbing: a ``.ts`` file in a JavaScript scan is currently
    fenced as ``javascript`` because the caller passes the scan-wide language.

    Args:
        path: File path whose extension decides the fence.
        fallback: Language name to fall back on when the path has no
            recognized extension (e.g. the literal ``"unknown"`` the reporter
            synthesizes for a route key with no colon).

    Returns:
        The fence tag, or ``""`` when nothing matches — an empty tag is a valid
        unhighlighted Markdown fence, so this degrades rather than breaking.
    """
    suffix = Path(path).suffix.lower()
    registry = load_registry()

    language = extension_map().get(suffix)
    if language is not None:
        fence = registry[language].fence
        if isinstance(fence, dict):
            return fence.get(suffix, fence.get(_FENCE_DEFAULT_KEY, ""))
        return fence

    # No usable extension — fall back to the caller's scan-wide language.
    if fallback:
        spec = registry.get(fallback.lower())
        if spec is not None:
            fence = spec.fence
            if isinstance(fence, dict):
                return fence.get(_FENCE_DEFAULT_KEY, "")
            return fence

    return ""


def docker_template_for(language: str) -> str | None:
    """Dynamic-test Docker template for a language, or ``None`` if none exists.

    ``None`` is meaningful and must be honoured by callers: generating a Python
    Dockerfile for a C finding burns tokens on a guaranteed failure. Callers
    should skip with an explicit reason instead.
    """
    spec = load_registry().get(language)
    return spec.docker_template if spec else None


def parser_script_path(language: str) -> Path | None:
    """Absolute path to a language's subprocess parser entry point.

    #273 hard guard: the config file may come from an untrusted source
    (the resolver's CWD-upward leg can find a scanned repo's own
    config/languages.json), and ``Path('/root') / '/abs'`` is ``'/abs'``
    in pathlib — an absolute ``parser.script`` value previously resolved
    to ITSELF and was executed via ``sys.executable``. Resolve and require
    the result to stay under ``_CORE_ROOT`` (rejects absolute values,
    ``..`` escapes, and symlink escapes alike); anything else returns None
    (the caller degrades to a typed error, never executes).
    """
    spec = load_registry().get(language)
    if spec is None or not spec.parser_script:
        return None
    root = _CORE_ROOT.resolve()
    try:
        candidate = (root / spec.parser_script).resolve()
    except (OSError, ValueError):
        # Hostile script values (e.g. embedded NULs, absurd length) can
        # make resolve itself raise — total guard, never executes.
        return None
    if not candidate.is_relative_to(root) or candidate == root:
        # == root: "." and friends resolve to the root DIRECTORY — not a
        # script; reject alongside out-of-root escapes.
        return None
    return candidate
