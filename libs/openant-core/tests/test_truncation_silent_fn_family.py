"""Truncation silent-FN family — cross-provider adapter invariants (R2-A, R2-C).

Family invariant (adapter side): every adapter must emit stop_reason="max_tokens"
for a TRUNCATED response and must not mask it (as tool_use) or launder an
unknown/abnormal termination into a clean end_turn — otherwise a downstream
consumer (verifier / enhancer) accepts a truncated reply as a complete verdict.
Offline stubs; no network.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utilities.llm.providers.google import _response_to_unified as _google_unify


def _gemini_resp(*, finish_reason, with_tool=False, text=None):
    parts = []
    if with_tool:
        parts.append(SimpleNamespace(
            function_call=SimpleNamespace(name="finish", args={"agree": False}, id=None), text=None))
    if text is not None:
        parts.append(SimpleNamespace(function_call=None, text=text))
    return SimpleNamespace(
        candidates=[SimpleNamespace(finish_reason=finish_reason,
                                    content=SimpleNamespace(parts=parts))],
        usage_metadata=SimpleNamespace(prompt_token_count=1, candidates_token_count=1),
    )


def test_gemini_truncation_wins_over_tool_use():
    # R2-A: a MAX_TOKENS candidate carrying a function_call must surface as
    # max_tokens (truncation), NOT tool_use — else the consumer accepts a
    # truncated finish as a complete verdict.
    r = _google_unify(_gemini_resp(finish_reason="MAX_TOKENS", with_tool=True))
    assert r.stop_reason == "max_tokens"


def test_gemini_normal_tool_call_still_tool_use():
    # regression guard: a normal (STOP) tool call is still tool_use.
    r = _google_unify(_gemini_resp(finish_reason="STOP", with_tool=True, text=None))
    assert r.stop_reason == "tool_use"


def test_gemini_unknown_finish_is_max_tokens_not_end_turn():
    # R2-C: an unknown/abnormal finish_reason (SAFETY/RECITATION/proxy) is not a
    # clean end_turn.
    r = _google_unify(_gemini_resp(finish_reason="ZZ_FUTURE_REASON", text="partial"))
    assert r.stop_reason == "max_tokens"


def test_gemini_unknown_finish_with_tool_call_is_max_tokens_not_tool_use():
    # round-5: an UNKNOWN/abnormal finish_reason carrying a function_call must surface
    # as max_tokens, not tool_use — an abnormal termination wins over the tool-call
    # signal (so a consumer's max_tokens gate can fire), consistent with unknown->max_tokens.
    r = _google_unify(_gemini_resp(finish_reason="ZZ_FUTURE_REASON", with_tool=True))
    assert r.stop_reason == "max_tokens"


def test_gemini_known_stop_unchanged():
    r = _google_unify(_gemini_resp(finish_reason="STOP", text="hi"))
    assert r.stop_reason == "end_turn"
