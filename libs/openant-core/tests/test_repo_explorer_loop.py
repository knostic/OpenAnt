"""The explore_repository multi-turn loop had NO test (HANDOFF §4 #5), so its
'model called no tool' branch — which previously sent ToolResultBlock(tool_use_id="nudge"),
a guaranteed Messages-API 400 — never fired in a test. These pin that branch and the
loop's finish / exhaustion paths, with a fake adapter (no network, free).

RED on the pre-fix code: the nudge branch sent a ToolResultBlock with an id matching no
tool_use in the preceding turn -> test_chatty_turn_is_answered_with_plain_text would fail
(it asserts the fed-back turn carries NO ToolResultBlock).
"""
from __future__ import annotations

import pytest

from context.repo_explorer import explore_repository, MAX_TURNS
from utilities.llm.adapter import Message, TextBlock, ToolDef, ToolResultBlock, ToolUseBlock


class _Resp:
    def __init__(self, content, stop_reason=None):
        self.content = content
        self.stop_reason = stop_reason


class _FakeAdapter:
    supports_tools = True

    def __init__(self, scripted):
        self._scripted = list(scripted)
        self.seen_messages = []  # messages passed on each complete() call

    def complete(self, *, model, system, messages, max_tokens, tools):
        self.seen_messages.append(list(messages))
        return self._scripted.pop(0)


class _PairingFakeAdapter(_FakeAdapter):
    """Enforces the Messages-API rule real providers enforce: every assistant
    tool_use must be answered by a tool_result in the immediately following user
    turn. Catches an unanswered/dangling tool_use (which real APIs 400 on)."""

    def complete(self, *, model, system, messages, max_tokens, tools):
        for i, m in enumerate(messages):
            if m.role != "assistant":
                continue
            tu_ids = [b.id for b in m.content if isinstance(b, ToolUseBlock)]
            if not tu_ids:
                continue
            nxt = messages[i + 1] if i + 1 < len(messages) else None
            tr_ids = [b.tool_use_id for b in (nxt.content if nxt else ())
                      if isinstance(b, ToolResultBlock)]
            for tid in tu_ids:
                if tid not in tr_ids:
                    raise RuntimeError(
                        f"400: assistant tool_use {tid!r} has no matching tool_result "
                        f"in the next user turn")
        return super().complete(model=model, system=system, messages=messages,
                                max_tokens=max_tokens, tools=tools)


class _FakeBinding:
    def __init__(self, adapter):
        self.adapter = adapter
        self.model = "fake-model"
        self.provider_name = "fake"


_FINISH = ToolDef(name="finish", description="deliver result",
                  input_schema={"type": "object", "properties": {}})


def _repo(tmp_path):
    r = tmp_path / "repo"
    (r / "src").mkdir(parents=True)
    (r / "src" / "app.py").write_text("def handler(req):\n    return req\n")
    return r


def test_finish_returns_payload_and_counts_turns(tmp_path):
    adapter = _FakeAdapter([
        _Resp((ToolUseBlock(id="tu1", name="finish", input={"ok": True}),)),
    ])
    payload, budget = explore_repository(_repo(tmp_path), _FakeBinding(adapter),
                                         "sys", "task", _FINISH)
    assert payload == {"ok": True}
    assert budget.turns == 1


def test_truncated_finish_at_max_tokens_is_not_accepted(tmp_path):
    # R3-A: a finish call on a turn truncated at max_tokens must NOT be accepted as
    # a complete survey (it under-scopes the threat model every later scan trusts).
    # R4-1: and the skipped finish's tool_use must be ANSWERED (pairing-validating
    # adapter enforces the real Messages-API rule) so the retry turn isn't a 400.
    # The loop nudges and uses a later COMPLETE finish instead.
    adapter = _PairingFakeAdapter([
        _Resp((ToolUseBlock(id="tu1", name="finish", input={"partial": True}),),
              stop_reason="max_tokens"),
        _Resp((ToolUseBlock(id="tu2", name="finish", input={"complete": True}),),
              stop_reason="tool_use"),
    ])
    payload, budget = explore_repository(_repo(tmp_path), _FakeBinding(adapter),
                                         "sys", "task", _FINISH)
    assert payload == {"complete": True}   # the truncated finish was skipped
    assert budget.turns == 2


def test_chatty_turn_is_answered_with_plain_text_not_toolresult(tmp_path):
    # Turn 1: model returns prose, calls no tool -> the nudge branch.
    # Turn 2: model calls finish.
    adapter = _FakeAdapter([
        _Resp((TextBlock(text="let me think about this repo..."),)),
        _Resp((ToolUseBlock(id="tu2", name="finish", input={"done": 1}),)),
    ])
    payload, budget = explore_repository(_repo(tmp_path), _FakeBinding(adapter),
                                         "sys", "task", _FINISH)
    assert payload == {"done": 1}
    assert budget.turns == 2
    # THE FIX: the turn fed back after the chatty response must be a plain user
    # TextBlock, never a ToolResultBlock (whose id would match no tool_use -> 400).
    fed_back = adapter.seen_messages[1][-1]  # last message the model saw on turn 2
    assert all(not isinstance(b, ToolResultBlock) for b in fed_back.content), \
        "nudge must be plain text, not a ToolResultBlock"
    assert any(isinstance(b, TextBlock) for b in fed_back.content)


def test_tool_call_result_is_fed_back_as_toolresult(tmp_path):
    # A real tool call (list_dir) must come back as a ToolResultBlock with the
    # matching tool_use id, then finish.
    adapter = _FakeAdapter([
        _Resp((ToolUseBlock(id="tu-ld", name="list_dir", input={"path": "."}),)),
        _Resp((ToolUseBlock(id="tu-fin", name="finish", input={"ok": 1}),)),
    ])
    payload, _ = explore_repository(_repo(tmp_path), _FakeBinding(adapter),
                                    "sys", "task", _FINISH)
    assert payload == {"ok": 1}
    fed_back = adapter.seen_messages[1][-1]
    trs = [b for b in fed_back.content if isinstance(b, ToolResultBlock)]
    assert len(trs) == 1 and trs[0].tool_use_id == "tu-ld"


def test_never_finishing_raises_after_max_turns(tmp_path):
    adapter = _FakeAdapter([_Resp((TextBlock(text="thinking"),)) for _ in range(MAX_TURNS)])
    with pytest.raises(RuntimeError):
        explore_repository(_repo(tmp_path), _FakeBinding(adapter), "sys", "task", _FINISH)


class _ScriptedRaisingAdapter(_FakeAdapter):
    """Scripted entries may be exceptions: a completion that RAISES (an empty/
    malformed turn -- every adapter raises LLMResponseError on empty content).
    """
    def complete(self, *, model, system, messages, max_tokens, tools):
        self.seen_messages.append(list(messages))
        item = self._scripted.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def test_empty_turn_is_recovered_not_fatal(tmp_path):
    # An empty/malformed turn (adapter raises LLMResponseError) mid-survey must NOT
    # abort a survey that may already have read useful context. The loop consumes
    # the turn and retries; a later valid finish still succeeds.
    # Raise the exact class repo_explorer's `except` is bound to (its own module
    # binding) so the test is stable even if another test purged utilities.* from
    # sys.modules and re-minted a second LLMResponseError identity.
    from context.repo_explorer import LLMResponseError
    adapter = _ScriptedRaisingAdapter([
        LLMResponseError("OpenAI returned an empty completion"),
        _Resp((ToolUseBlock(id="tu-fin", name="finish", input={"ok": 1}),)),
    ])
    payload, budget = explore_repository(_repo(tmp_path), _FakeBinding(adapter),
                                         "sys", "task", _FINISH)
    assert payload == {"ok": 1}
    assert budget.turns == 2  # the empty turn was consumed, then finish


def test_persistent_empty_turns_fail_loud_and_bounded(tmp_path):
    # A model that returns nothing on EVERY turn must still fail loudly (never a
    # silent partial) and bounded (not burn the entire MAX_TURNS budget).
    from context.repo_explorer import LLMResponseError
    adapter = _ScriptedRaisingAdapter(
        [LLMResponseError("empty") for _ in range(MAX_TURNS + 2)])
    with pytest.raises(LLMResponseError):
        explore_repository(_repo(tmp_path), _FakeBinding(adapter), "sys", "task", _FINISH)
    # Bailed early on consecutive empties -- did NOT consume the whole budget.
    assert len(adapter.seen_messages) < MAX_TURNS


def test_refusal_is_not_retried_propagates(tmp_path):
    # A refusal/content-filter (LLMRefusalError, subclass of LLMResponseError) is
    # NOT a transient blank: it must propagate immediately, never be churned past.
    from context.repo_explorer import LLMRefusalError
    adapter = _ScriptedRaisingAdapter([
        LLMRefusalError("model refused"),
        _Resp((ToolUseBlock(id="tu-fin", name="finish", input={"ok": 1}),)),
    ])
    with pytest.raises(LLMRefusalError):
        explore_repository(_repo(tmp_path), _FakeBinding(adapter), "sys", "task", _FINISH)
    assert len(adapter.seen_messages) == 1  # bailed on the refusal, did not retry
