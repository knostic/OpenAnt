"""Regression tests for issue #290 — the verify/enhance agent loops bypass
`simple_text` and pinned their own output budget.

`finding_verifier` and `agentic_enhancer/agent` call
`binding.adapter.complete(...)` directly (they need raw content blocks for
the multi-turn tool conversation), so PR #242's raise of `simple_text`'s
default 8192→20000 — whose comment names the exact failure mode (a
thinking-era model spends the output budget on hidden reasoning and returns
a reasoning-only completion) — never reached them: both loops kept a private
`MAX_TOKENS_PER_RESPONSE = 4096`, HALF the pre-#242 default, on the largest
units in the scan. A truncated finish call is deliberately downgraded to
verification-incomplete (FN-safe), so the undersized cap silently converted
adjudications into needs_review (31 self-declared max_tokens truncations on
the run that filed this).

Contract locked here (the issue's "so the two cannot drift again"):
- both agent-loop constants ARE `llm.helpers.DEFAULT_MAX_TOKENS` — same
  object by construction, not coincidentally equal numbers;
- `simple_text`'s signature default is that same constant;
- neither agent-loop source pins a private numeric budget anymore.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.agentic_enhancer import agent as enhancer_agent  # noqa: E402
from utilities import finding_verifier  # noqa: E402
from utilities.llm.helpers import DEFAULT_MAX_TOKENS, simple_text  # noqa: E402


def test_agent_loops_share_the_simple_text_budget_constant():
    """#290: both agent-loop budgets ARE the shared constant (no private
    4096 pins) — the two budget paths cannot drift apart again."""
    assert finding_verifier.MAX_TOKENS_PER_RESPONSE is DEFAULT_MAX_TOKENS
    assert enhancer_agent.MAX_TOKENS_PER_RESPONSE is DEFAULT_MAX_TOKENS


def test_simple_text_default_is_the_shared_constant():
    sig = inspect.signature(simple_text)
    assert sig.parameters["max_tokens"].default is DEFAULT_MAX_TOKENS
    # and the number is the thinking-era budget PR #242 established
    assert DEFAULT_MAX_TOKENS == 20000


def test_no_private_numeric_budget_pins_in_agent_loops():
    """Neither agent-loop source pins a numeric max_tokens anymore: the
    constants must be defined by reference to the shared default, so a
    future edit to one site that re-pins a number is visible in review."""
    core = PROJECT_ROOT / "utilities"
    for rel in ("finding_verifier.py", "agentic_enhancer/agent.py"):
        src = (core / rel).read_text()
        for line in src.splitlines():
            if "MAX_TOKENS_PER_RESPONSE =" in line and "=" in line:
                rhs = line.split("=", 1)[1].strip()
                assert rhs in ("DEFAULT_MAX_TOKENS",), (
                    f"{rel}: budget must reference DEFAULT_MAX_TOKENS, "
                    f"got {rhs!r}")
