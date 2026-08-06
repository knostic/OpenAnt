"""ContextBudgetController -- user-approved, fixed-size context-budget
window extensions for Auto Patcher's repository source/context
acquisition stages.

Background: Auto Patcher's Final-Target Slicing / Deterministic Pre-Patch
Acquisition (Slice 2) / Guided Pre-Patch Acquisition (Slice 3) / Post-Patch
Recovery (Slice 4) all share ONE soft character ceiling --
remediation_planner.FINAL_TARGET_SLICE_MAX_CHARS -- plus Slice 4's own
additional per-round total (MAX_POST_PATCH_SOURCE_CHARS). A real research
run can be stopped before Patch Generation purely because that character
capacity, not any safety/verification concern, ran out. This module lets a
caller (the CLI, or another library caller) opt in to additional, FIXED-
SIZE windows of that same budget -- never exponential growth, never a
silent reset, never a bypass of any non-budget gate (unsafe paths,
ambiguous/unresolved symbols, cross-file mismatches, request/round/target
caps, applicability, source verification, Recommendation Policy).

Policies (exactly these three):
  "never"  -- never extend; identical to the pre-existing fixed-budget,
              fail-closed behavior. The default for any caller that
              doesn't pass a controller at all (see effective_budget()/
              request_extension() below) -- library use never prompts.
  "always" -- automatically approve another window, up to max_windows,
              without asking. For local research, batch validation, CI.
  "ask"    -- ask the user interactively whenever another window is
              needed; the default answer is No; converted to "never"
              (recorded, not silently guessed) whenever the run is not
              interactive (stdin is not a TTY).

Deep acquisition helpers (remediation_planner.py) only ever call
effective_budget()/request_extension() on a controller instance -- never
input()/sys.stdin/isatty() themselves. That keeps unit tests deterministic
and this module free of any hard coupling between repository logic and
terminal I/O; a caller that wants "ask" supplies (or accepts the built-in
default for) a `confirm` callback instead of this module reading stdin
directly from inside deep helpers.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable, Optional


CONTEXT_BUDGET_POLICIES = ("ask", "always", "never")
"""The only three supported policies -- see the module docstring for
exactly what each means."""

DEFAULT_MAX_CONTEXT_BUDGET_WINDOWS = 10
"""Hard cap on total windows (initial + approved) per stage, applied
regardless of policy -- even "always" stops here. Configurable via
ContextBudgetController(max_windows=...) / the CLI's
--max-context-budget-windows; never an unbounded sentinel (validated to
be a positive int by the constructor)."""


@dataclass
class _StageBudgetState:
    """One acquisition stage's own fixed-size, additive budget-window
    state. `window_size` must be that stage's PRE-EXISTING base
    character budget (e.g. remediation_planner.FINAL_TARGET_SLICE_MAX_CHARS)
    -- never a new, independently-sized constant -- so every extension
    window this stage grants is exactly one more of the SAME size, never
    exponential growth (10K -> 20K -> 30K, never 10K -> 20K -> 40K)."""

    stage: str
    window_size: int
    initial_windows: int
    max_windows: int
    approved_windows: int = 0
    used_chars: int = 0
    extension_requests: "list" = field(default_factory=list)

    @property
    def total_windows(self) -> int:
        return self.initial_windows + self.approved_windows

    @property
    def effective_budget(self) -> int:
        return self.window_size * self.total_windows

    @property
    def remaining_chars(self) -> int:
        return max(0, self.effective_budget - self.used_chars)

    def as_dict(self) -> dict:
        return {
            "window_size": self.window_size,
            "initial_windows": self.initial_windows,
            "approved_windows": self.approved_windows,
            "max_windows": self.max_windows,
            "effective_budget": self.effective_budget,
            "used_chars": self.used_chars,
            "remaining_chars": self.remaining_chars,
            "extension_requests": list(self.extension_requests),
        }


def _default_confirm(prompt_text: str) -> bool:
    """The built-in interactive confirmation for policy="ask" -- mirrors
    openant/cli.py's existing cmd_report Y/n gate (a stderr prompt +
    sys.stdin.readline()), except the default on empty input/EOF/Ctrl-C
    is explicitly No, never Yes -- a context-budget extension is opt-in,
    never an accidental default. Only ever called by
    ContextBudgetController.request_extension() when policy="ask" AND
    the controller has already confirmed the run is interactive -- never
    called on a non-interactive stdin."""
    try:
        sys.stderr.write(prompt_text)
        sys.stderr.flush()
        answer = sys.stdin.readline().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def format_extension_prompt(
    stage: str, state: "_StageBudgetState", reason: str, affected_targets: "list | None",
) -> str:
    """Concise, concrete prompt text for a policy="ask" extension
    request: stage, reason, affected target paths, window size, windows
    already active, and the effective budget approval would produce --
    deliberately never the rendered slice text or any other large
    internal detail."""
    targets = list(affected_targets or [])
    lines = [f"Context budget exhausted during {stage} ({reason})."]
    if targets:
        noun = "target" if len(targets) == 1 else "targets"
        lines.append("")
        lines.append(f"{len(targets)} {noun} still lack{'s' if len(targets) == 1 else ''} verified source:")
        for t in targets:
            lines.append(f"- {t}")
    lines.append("")
    lines.append(
        f"Allow another {state.window_size:,}-character context window? "
        f"({state.total_windows}/{state.max_windows} windows active -- "
        f"effective budget would become {state.effective_budget + state.window_size:,} chars) [y/N] "
    )
    return "\n".join(lines)


class ContextBudgetController:
    """Owns fixed-size, additive budget-window state for one pipeline
    run's soft character budgets that gate repository source/context
    acquisition (see the module docstring). A caller constructs one
    controller per pipeline run and passes it into
    utilities.autopatcher.pipeline.run(budget_controller=...); no
    controller supplied behaves exactly like policy="never" everywhere
    it is consulted (see effective_budget()) -- a library caller that
    never builds one gets the pre-existing fixed-budget behavior
    unchanged, with zero interactive prompts.

    max_windows: hard cap on TOTAL windows (initial + approved) per
      stage, validated to be a positive int -- no unbounded sentinel.
      Even policy="always" stops here (see request_extension()).
    interactive: whether an "ask" prompt may run at all. Defaults to
      sys.stdin.isatty() -- a non-interactive process (CI, a pipe) never
      blocks on input regardless of policy; "ask" degrades to "never"
      (recorded as decision_source="non_interactive_fallback", not a
      silent guess) whenever this is False.
    confirm: optional callable(prompt_text: str) -> bool, used only for
      policy="ask" while interactive. Defaults to a Y/N stdin prompt
      matching the existing CLI convention (see _default_confirm).
    """

    def __init__(
        self,
        policy: str = "never",
        max_windows: int = DEFAULT_MAX_CONTEXT_BUDGET_WINDOWS,
        interactive: "Optional[bool]" = None,
        confirm: "Optional[Callable[[str], bool]]" = None,
    ) -> None:
        if policy not in CONTEXT_BUDGET_POLICIES:
            raise ValueError(
                f"Unknown context budget policy: {policy!r} (expected one of {CONTEXT_BUDGET_POLICIES})"
            )
        if isinstance(max_windows, bool) or not isinstance(max_windows, int) or max_windows < 1:
            raise ValueError(f"max_windows must be a positive integer, got {max_windows!r}")
        self.policy = policy
        self.max_windows = max_windows
        self.interactive = sys.stdin.isatty() if interactive is None else bool(interactive)
        self._confirm = confirm or _default_confirm
        self._stages: "dict" = {}

    def _stage(self, stage: str, window_size: int, initial_windows: int) -> _StageBudgetState:
        state = self._stages.get(stage)
        if state is None:
            state = _StageBudgetState(
                stage=stage, window_size=window_size, initial_windows=initial_windows,
                max_windows=self.max_windows,
            )
            self._stages[stage] = state
        return state

    def effective_budget(self, stage: str, base_chars: int, initial_windows: int = 1) -> int:
        """The stage's current effective ceiling -- `base_chars` unless
        at least one extension has already been approved for this stage
        this run. Auto-registers the stage on first call (callers never
        need a separate registration step). `base_chars` must be that
        stage's own pre-existing budget constant, read live by the
        caller every time (never cached) -- so a test that monkeypatches
        the underlying constant keeps working unchanged whether or not a
        controller is given."""
        return self._stage(stage, base_chars, initial_windows).effective_budget

    def record_used(self, stage: str, used_chars: int) -> None:
        """Best-effort observability only, for the structured trace --
        records the largest `used_chars` seen for `stage` this run.
        Never consulted by request_extension()'s own decision, and a
        stage that was never registered (effective_budget()/
        request_extension() not yet called for it) is simply a no-op."""
        state = self._stages.get(stage)
        if state is not None:
            state.used_chars = max(state.used_chars, used_chars)

    def request_extension(
        self,
        stage: str,
        window_size: int,
        *,
        reason: str,
        affected_targets: "list | None" = None,
        initial_windows: int = 1,
    ) -> bool:
        """Ask for exactly one more window for `stage`. Returns True
        only if the effective budget actually increased by one window as
        a direct result of THIS call -- the caller re-reads
        effective_budget() (or recomputes its own remaining-chars)
        immediately afterward; this never mutates anything else (no
        rollback of already-committed source, no round/request counter).

        Never blocks a non-interactive process, never asks more than
        once per call, never exceeds max_windows. Every call -- approved
        or not -- is recorded on the stage's own `extension_requests`
        (see _StageBudgetState.as_dict()), including the specific reason
        it was or wasn't granted (`decision_source`): "policy_never",
        "policy_always", "non_interactive_fallback", "interactive_user",
        or "hard_budget_window_limit_reached"."""
        state = self._stage(stage, window_size, initial_windows)
        record = {
            "reason": reason,
            "affected_targets": list(affected_targets or []),
            "approved": False,
            "decision_source": None,
        }

        if state.total_windows >= state.max_windows:
            record["decision_source"] = "hard_budget_window_limit_reached"
            state.extension_requests.append(record)
            self._announce(stage, state, approved=False, note="hard_budget_window_limit_reached")
            return False

        if self.policy == "never":
            record["decision_source"] = "policy_never"
            state.extension_requests.append(record)
            return False

        if self.policy == "always":
            state.approved_windows += 1
            record["approved"] = True
            record["decision_source"] = "policy_always"
            state.extension_requests.append(record)
            self._announce(stage, state, approved=True)
            return True

        # policy == "ask"
        if not self.interactive:
            record["decision_source"] = "non_interactive_fallback"
            state.extension_requests.append(record)
            return False

        prompt_text = format_extension_prompt(stage, state, reason, affected_targets)
        try:
            approved = bool(self._confirm(prompt_text))
        except Exception:
            approved = False
        if approved:
            state.approved_windows += 1
        record["approved"] = approved
        record["decision_source"] = "interactive_user"
        state.extension_requests.append(record)
        if approved:
            self._announce(stage, state, approved=True)
        return approved

    @staticmethod
    def _announce(stage: str, state: "_StageBudgetState", approved: bool, note: "str | None" = None) -> None:
        """A single concise stderr line on a granted extension (or on
        hitting the hard cap) -- matches pipeline.py's own existing
        `print(..., file=sys.stderr)` progress convention, so a
        policy="always" run stays observable without requiring
        AUTOPATCHER_DEBUG. Never raises: this is pure observability, no
        different from every other "[pipeline] ..." line already
        written elsewhere in this engine."""
        try:
            if approved:
                sys.stderr.write(
                    f"[context_budget] {stage}: window #{state.total_windows}/{state.max_windows} "
                    f"approved -- effective budget now {state.effective_budget:,} chars.\n"
                )
            elif note == "hard_budget_window_limit_reached":
                sys.stderr.write(
                    f"[context_budget] {stage}: hard_budget_window_limit_reached "
                    f"({state.max_windows} windows) -- failing closed.\n"
                )
            sys.stderr.flush()
        except Exception:
            pass

    def to_trace_dict(self) -> dict:
        """The full structured trace for this run's budget-window
        activity -- safe to embed verbatim into an existing debug
        artifact (see pipeline.py's reports/debug/*.json writers).
        Never raises: a stage's own as_dict() is pure attribute access
        over plain ints/dicts."""
        return {
            "policy": self.policy,
            "interactive": self.interactive,
            "max_windows": self.max_windows,
            "stages": {name: state.as_dict() for name, state in self._stages.items()},
        }
