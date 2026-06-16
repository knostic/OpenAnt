"""L3 (round-5): ``safe_code_fence`` must tolerate a None/empty body.

Before the guard, ``re.findall(r"`+", None)`` raised ``TypeError`` mid
prompt-build. An absent context block / empty unit has no backtick runs, so
the minimum 3-backtick fence applies.
"""

from prompts._fence import safe_code_fence


def test_none_body_returns_minimum_fence():
    assert safe_code_fence(None) == "```"


def test_empty_body_returns_minimum_fence():
    assert safe_code_fence("") == "```"


def test_backtick_runs_still_grow_the_fence():
    # Regression guard: the None tolerance must not weaken the core behaviour.
    assert safe_code_fence("a ``` b") == "````"
