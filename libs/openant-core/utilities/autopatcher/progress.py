"""
Small, dependency-free terminal-progress presentation layer for the Auto
Patcher's human-facing output (``openant patch`` and
``tools/run_traced.py`` -- both funnel through the same
``utilities.autopatcher`` call graph, so this one module is the single
place either path's progress narration goes through).

This is NOT a logging framework: no handlers, no formatters, no log
levels beyond the three verbosity states below, no third-party
dependency. Every call is a synchronous ``print`` to stderr (or a no-op),
gated by module-level state configured once per process by whichever CLI
entry point owns this run (``openant/cli.py``'s ``cmd_patch``, or
``tools/run_traced.py``'s ``main()``).

Design
------
- Three verbosity states: "default", "verbose", "quiet". A caller that
  wants JSON-clean output (``--json``) simply configures ``quiet=True``
  (see ``configure()``) -- from this module's point of view, "suppress
  human progress so stdout/the final answer stays clean" is the same
  request whether it's spelled ``--quiet`` or ``--json``.
- Status symbols encode MEANING, not merely "a step executed": a stage
  that completed but found something concerning gets a warning, not a
  checkmark (see ``success``/``warning``/``recovery``/``failure``/
  ``skipped``/``info`` below).
- ``fatal()`` is NOT suppressed by quiet -- quiet means "don't narrate
  progress," not "hide why the run failed." Its detail (traceback) is
  still gated by verbose.
- Module-global state, mirroring this codebase's existing
  ``llm_client._cached_provider``/``_cached_model`` pattern: configured
  once at process start, read everywhere else. Each ``openant patch``/
  ``run_traced.py`` invocation is a fresh process, so this never leaks
  between real runs. Tests that flip verbosity directly must call
  ``reset_for_tests()`` in a fixture/finally so state never leaks into an
  unrelated test in the same pytest process.
"""

from __future__ import annotations

import sys

_DEFAULT = "default"
_VERBOSE = "verbose"
_QUIET = "quiet"

_mode = _DEFAULT

# Status vocabulary -- meaning, not mere execution. See module docstring.
SUCCESS = "✓"   # ✓ completed / passed
RECOVERY = "↻"  # ↻ retry / fallback / recovery
WARNING = "⚠"   # ⚠ unresolved / warning / concern
FAILURE = "✗"   # ✗ failure
SKIPPED = "–"   # – skipped
INFO = "ℹ"      # ℹ informational

_DIVIDER = "─" * 60
_INDENT = "  "
_DETAIL_INDENT = "      "


def configure(verbose: bool = False, quiet: bool = False) -> None:
    """Set this process's progress verbosity once, at CLI entry.

    `quiet` wins if both are set -- see module docstring and the CLI's
    own `--quiet`/`--verbose` precedence rule.
    """
    global _mode
    if quiet:
        _mode = _QUIET
    elif verbose:
        _mode = _VERBOSE
    else:
        _mode = _DEFAULT


def reset_for_tests() -> None:
    """Restore default (non-verbose, non-quiet) state and forget any
    claimed model announcement. Call this in a fixture/finally after any
    test that calls `configure()`/`claim_model_announcement()` directly,
    so verbosity never leaks into an unrelated test in the same process.
    """
    global _mode, _announced_model
    _mode = _DEFAULT
    _announced_model = None


def is_verbose() -> bool:
    return _mode == _VERBOSE


def is_quiet() -> bool:
    return _mode == _QUIET


def _emit(line: str) -> None:
    if _mode == _QUIET:
        return
    print(line, file=sys.stderr)


def header(title: str, fields: "list[tuple[str, str]]") -> None:
    """Run header: title, a divider, then aligned key/value lines.

    Suppressed under quiet, like the rest of the progress stream --
    Go's own `--quiet` already drops this CLI's entire stderr stream
    today; this keeps direct-Python callers (run_traced.py) consistent
    with that.
    """
    if _mode == _QUIET:
        return
    lines = [title, _DIVIDER]
    if fields:
        width = max(len(k) for k, _ in fields)
        lines += [f"{k.ljust(width)}  {v}" for k, v in fields]
    _emit("\n".join(lines))


def stage(n: int, total: int, name: str) -> None:
    """Begin a numbered stage group, e.g. "[1/5] Analyze"."""
    _emit(f"\n[{n}/{total}] {name}")


def success(text: str, detail: "str | None" = None) -> None:
    _emit(f"{_INDENT}{SUCCESS} {text}")
    if detail:
        _emit(f"{_DETAIL_INDENT}{detail}")


def recovery(text: str, detail: "str | None" = None) -> None:
    _emit(f"{_INDENT}{RECOVERY} {text}")
    if detail:
        _emit(f"{_DETAIL_INDENT}{detail}")


def warning(text: str, detail: "str | None" = None) -> None:
    _emit(f"{_INDENT}{WARNING} {text}")
    if detail:
        _emit(f"{_DETAIL_INDENT}{detail}")


def failure(text: str, detail: "str | None" = None) -> None:
    _emit(f"{_INDENT}{FAILURE} {text}")
    if detail:
        _emit(f"{_DETAIL_INDENT}{detail}")


def skipped(text: str, reason: "str | None" = None) -> None:
    if reason:
        _emit(f"{_INDENT}{SKIPPED} {text}: {reason}")
    else:
        _emit(f"{_INDENT}{SKIPPED} {text}")


def info(text: str, detail: "str | None" = None) -> None:
    _emit(f"{_INDENT}{INFO} {text}")
    if detail:
        _emit(f"{_DETAIL_INDENT}{detail}")


def verbose(text: str) -> None:
    """Detailed diagnostic output (the pre-existing `[pipeline] ...`-style
    lines) -- printed only in verbose mode. Text is passed through
    unchanged; callers keep the exact wording the old unconditional
    `print(..., file=sys.stderr)` call used."""
    if _mode != _VERBOSE:
        return
    _emit(text)


def banner(lines: "list[str]") -> None:
    """A bordered block for the run's final decision -- top/bottom
    dividers around the given lines. Respects quiet like the rest of the
    progress stream (see header()'s docstring for why)."""
    if _mode == _QUIET:
        return
    _emit(_DIVIDER)
    for line in lines:
        _emit(line)
    _emit(_DIVIDER)


def fatal(text: str, detail: "str | None" = None) -> None:
    """A concise, always-visible failure line -- NOT suppressed by quiet.

    Quiet means "don't narrate progress," never "hide why the run
    stopped." `detail` (e.g. a traceback) is still gated by verbose --
    pass it only when `is_verbose()`; this function does not check that
    itself so callers can decide whether they even have a detail to show.
    """
    print(f"{FAILURE} {text}", file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)


_announced_model: "tuple[str, str] | None" = None


def claim_model_announcement(provider: str, model: str) -> bool:
    """Returns True the first time (provider, model) is claimed this run,
    False every time after -- the "announce once" primitive used to
    replace the old per-LLM-call "Using {provider} (model: {model})"
    line. Whichever caller gets here first (the run header built by
    core/patch.py, or llm_client.call_llm() itself for a caller that
    skips the header, e.g. tests/replay calling pipeline.run() directly)
    wins; every later call this run becomes a no-op. There is no real
    provider/model fallback in this codebase today (llm_client never
    silently substitutes), so in practice this claims exactly once; if
    that ever changes, a genuine (provider, model) change would return
    True again, keeping a real transition visible.
    """
    global _announced_model
    key = (provider, model)
    if _announced_model == key:
        return False
    _announced_model = key
    return True


def format_provider_model(provider: str, model: str) -> str:
    """Display formatting for a resolved provider/model pair, e.g.
    "Anthropic · claude-opus-4-8", or just "Mock" for the test/
    research mock provider. `provider` is expected to already be the
    human-facing display name (see llm_client.display_provider_name) --
    this function only composes, it never maps provider keys itself."""
    if provider.lower() == "mock":
        return "Mock"
    return f"{provider} · {model}"
