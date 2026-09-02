"""Regression test for: single-shot enhance failed-context path sets no 'error' key.

Bug (enhancer-failed-context-no-error-key):
    ``core/enhancer.py`` counts enhancement failures with ``if ctx.get("error")``
    (line ~151), mirroring the agentic path which sets a structured
    ``agent_context["error"]`` on failure. But the single-shot failure path in
    ``ContextEnhancer.enhance_unit`` writes ``_get_default_context()`` with NO
    ``error`` key, so single-shot failures are never counted — they fall through
    to the classification branch and are reported as if successfully enhanced
    (error_count == 0, units_enhanced == all units).

No network: ``simple_text`` is monkeypatched to raise / return junk.
"""


class _FakeAdapter:
    name = "anthropic"
    supports_tools = True

    def complete(self, *, model, system, messages, max_tokens, tools=None):  # pragma: no cover
        raise AssertionError("adapter must not be called")

    def validate(self, model):  # pragma: no cover
        pass


def _fake_binding():
    from utilities.llm import PhaseBinding

    return PhaseBinding(
        phase="enhance",
        adapter=_FakeAdapter(),
        model="claude-test",
        provider_name="anthropic",
    )


def _make_enhancer():
    from utilities.context_enhancer import ContextEnhancer

    return ContextEnhancer(binding=_fake_binding(), tracker=None)


def _unit():
    return {"id": "u0", "code": {"primary_code": "def f(): pass"}, "unit_type": "function"}


def test_exception_failure_sets_error_key(monkeypatch):
    """When the LLM call raises, the failed llm_context must carry an 'error'
    dict so enhancer.py's ``if ctx.get('error')`` counts the failure."""
    import utilities.context_enhancer as ce

    def boom(*a, **k):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(ce, "simple_text", boom)

    enh = _make_enhancer()
    unit = enh.enhance_unit(_unit(), {})
    ctx = unit["llm_context"]

    err = ctx.get("error")
    assert err, "failed single-shot llm_context must set an 'error' key (enhancer.py counts on it)"
    # enhancer.py does err.get("type") when err is a dict.
    assert isinstance(err, dict) and err.get("type"), "error must be a structured dict with a 'type'"


def test_parse_failure_sets_error_key(monkeypatch):
    """When the response can't be parsed to JSON, the failed context is likewise
    a failure and must carry an 'error' key."""
    import utilities.context_enhancer as ce

    monkeypatch.setattr(ce, "simple_text", lambda *a, **k: "not-json-at-all")

    enh = _make_enhancer()
    unit = enh.enhance_unit(_unit(), {})
    ctx = unit["llm_context"]
    assert ctx.get("error"), "unparseable-response failed context must set an 'error' key"


def test_enhancer_counts_singleshot_failure_as_error(monkeypatch):
    """End-to-end at the counting layer: a failed single-shot unit must be
    tallied by enhancer.py's error loop, not reported as an enhanced unit."""
    import utilities.context_enhancer as ce

    monkeypatch.setattr(ce, "simple_text", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))

    enh = _make_enhancer()
    unit = enh.enhance_unit(_unit(), {})

    # Reproduce enhancer.py's aggregation loop (mode != agentic -> llm_context).
    ctx = unit.get("llm_context", {})
    error_count = 1 if ctx.get("error") else 0
    assert error_count == 1, "single-shot failure must be counted as an error by enhancer.py"
