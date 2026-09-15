"""Tests for issue #569 (choice c) — a budget-exhausted empty completion
retries ONCE at a raised cap; every other retryable keeps the #292
same-cap re-roll.

The #561 cause-clause split named the deterministic class (finish_reason
'length' / stop_reason 'max_tokens' → "the output budget was consumed");
the #292 classifier still retried it at the SAME cap — a coin flip against
a deterministic cause. Choice (c): the retry attacks the cause (the cap).
"""
from __future__ import annotations

from utilities.rate_limiter import (
    is_budget_exhausted_error,
    is_retryable_error,
)


MSG_LENGTH = ("OpenAIAdapter returned an empty completion (no text or tool "
              "calls; finish_reason='length'); the output budget was consumed "
              "before any visible content (reasoning models spend it on "
              "hidden reasoning)")
MSG_STOP = ("OpenAIAdapter returned an empty completion (no text or tool "
            "calls; finish_reason='stop'); the request may have been "
            "filtered or the response was malformed")


class TestBudgetDiscriminator:
    def test_length_empty_is_budget_exhausted(self):
        assert is_budget_exhausted_error(MSG_LENGTH)

    def test_stop_empty_is_not_budget(self):
        """The filtered/malformed class keeps the #292 same-cap retry."""
        assert not is_budget_exhausted_error(MSG_STOP)

    def test_both_still_retryable(self):
        """The split does NOT declassify anything — both empty classes
        stay retryable (the caller just raises the cap for one)."""
        assert is_retryable_error(MSG_LENGTH)
        assert is_retryable_error(MSG_STOP)

    def test_dict_shape_via_message(self):
        d = {"error": MSG_LENGTH}
        assert is_budget_exhausted_error(d)

    def test_transient_not_budget(self):
        assert not is_budget_exhausted_error("connection reset by peer")


class TestCapThreaded:
    def test_analyze_unit_accepts_max_tokens(self):
        """The cap parameter exists on the full chain (the plumbing)."""
        import inspect
        from core.analysis_core import analyze_unit
        sig = inspect.signature(analyze_unit)
        assert "max_tokens" in sig.parameters

    def test_budget_retry_cap_under_sdk_ceiling(self):
        """The refutation round's blocker: the raised cap MUST stay under
        the Anthropic non-streaming ceiling (~21,333; helpers.py:29-31)
        or the retry is a guaranteed SDK ValueError on that adapter."""
        from core.analyzer import BUDGET_RETRY_MAX_TOKENS
        from utilities.llm.helpers import DEFAULT_MAX_TOKENS
        assert DEFAULT_MAX_TOKENS < BUDGET_RETRY_MAX_TOKENS <= 21000, (
            f"the raised cap {BUDGET_RETRY_MAX_TOKENS} must be above the "
            f"default and at/below the SDK-safe ceiling")

    def test_retry_cap_decision_production_helper(self):
        """THE production decision, pinned on the real helper: the budget
        class gets the raised cap, every other retryable gets None."""
        from core.analyzer import budget_retry_cap, BUDGET_RETRY_MAX_TOKENS
        assert budget_retry_cap(0, {0, 2}) == BUDGET_RETRY_MAX_TOKENS
        assert budget_retry_cap(1, {0, 2}) is None  # the #292 same-cap path
        assert budget_retry_cap(2, {0, 2}) == BUDGET_RETRY_MAX_TOKENS

    def test_retry_loop_drives_the_split(self, tmp_path, monkeypatch):
        """End-to-end through the REAL run_analysis retry pass: a
        length-empty unit's retry call carries the raised cap; a
        stop-empty unit's carries None. Drives the production wiring
        (analyzer's retry loop) — the #569 review round replaced this
        test's prior shape, which re-implemented the loop's computation
        and never invoked it."""
        import json as _json
        from core import analyzer
        from utilities.llm_client import reset_warning_state

        reset_warning_state()
        dataset_path = tmp_path / "dataset.json"
        dataset_path.write_text(_json.dumps({"units": [
            {"id": "a:f1", "code": "x=1"},
            {"id": "b:f2", "code": "x=1"},
        ]}))
        output_dir = tmp_path / "out"

        def fake_run_detection(units, binding, json_corrector, app_context,
                               workers, checkpoint=None,
                               summary_callback=None):
            # Two failed units: one budget-class, one stop-class.
            return ([{"unit_id": "a:f1", "error": MSG_LENGTH},
                     {"unit_id": "b:f2", "error": MSG_STOP}],
                    {u["id"]: "" for u in units})

        calls = []

        def fake_process(binding, unit, i, jc, ac, max_tokens=None):
            calls.append((unit["id"], max_tokens))
            return {"result": {"unit_id": unit["id"], "finding": "safe",
                               "verdict": "SAFE", "confidence": 90,
                               "vulnerabilities": [], "reasoning": "r"},
                    "route_key": unit["id"], "code_for_route": "",
                    "finding": "safe", "usage": {}}

        monkeypatch.setattr(analyzer, "_run_detection", fake_run_detection)
        monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                            lambda binding, ctx_sha=None: {
                                "key_digest": "sha256:test"})
        monkeypatch.setattr(analyzer, "_process_unit", fake_process)

        from utilities.llm import PhaseBinding

        class _Adapter:
            name = "anthropic"
            supports_tools = True
            pricing = {}

        class _FakeRegistry:
            def get(self, phase):
                return PhaseBinding(phase=phase, adapter=_Adapter(),
                                    model="m", provider_name="anthropic")

        analyzer.run_analysis(
            str(dataset_path), str(output_dir),
            registry=_FakeRegistry(), workers=1)
        reset_warning_state()

        assert calls == [("a:f1", analyzer.BUDGET_RETRY_MAX_TOKENS),
                         ("b:f2", None)], (
            "the retry pass must thread the raised cap ONLY into the "
            "budget-class unit's call")


class TestRegistryCeilingInvariants:
    """The registry discipline the per-model cap depends on (the review
    round's conformance asks): the anthropic/bedrock exclusion is enforced
    by TEST, not prose — a future max_output_tokens >= ~21,334 on those
    records would push the retry past the SDK non-streaming ceiling (the
    exact class the 21000 default exists to prevent); and same-family
    records agree on their ceilings (the #344 price precedent, extended)."""

    def test_anthropic_and_bedrock_carry_no_ceiling(self):
        from core import model_registry
        for rec in model_registry.load_models():
            if rec.get("provider") in ("anthropic", "bedrock"):
                assert not rec.get("max_output_tokens"), (
                    f"{rec['provider']}/{rec['id']} carries max_output_tokens "
                    f"{rec['max_output_tokens']!r} — the retry cap would "
                    f"exceed the SDK non-streaming ~21,333 ceiling; the "
                    f"exclusion is load-bearing (see analyzer.py)")

    def test_same_family_agrees_on_ceiling(self):
        from core import model_registry
        import re
        fam = {}
        for rec in model_registry.load_models():
            cap = rec.get("max_output_tokens")
            if not cap:
                continue
            # family = the base model id (strip vendor prefix + date stamps)
            base = rec["id"].split("/")[-1]
            base = re.sub(r"-\d{8}.*$", "", base)
            fam.setdefault(base, set()).add(cap)
        for base, caps in fam.items():
            assert len(caps) == 1, (
                f"family {base!r} disagrees on max_output_tokens: {caps} — "
                f"an alias landing on a sibling record must be ceiling-safe "
                f"(the #344 same-family price precedent)")


class TestPerModelCeiling:
    """#569 follow-up (2b): the retry cap honors the model's documented
    max-output ceiling (config/models.json max_output_tokens) — a listed
    model gets min(2x default, ceiling); an unlisted model keeps the
    default-derived cap; a ceiling that admits no raise gets None (a
    same-cap retry beats a guaranteed 400)."""

    class _Binding:
        def __init__(self, provider, model):
            self.provider_name = provider
            self.model = model

    def test_listed_model_gets_ceiling_capped_raise(self):
        from core.analyzer import budget_retry_cap
        from utilities.llm.helpers import DEFAULT_MAX_TOKENS
        # gpt-4.1 carries max_output_tokens 32768: min(40000, 32768).
        assert budget_retry_cap(0, {0}, self._Binding("openai", "gpt-4.1")) == 32768
        # gemini-2.5-pro carries 65536: the 2x-default term binds.
        assert budget_retry_cap(0, {0}, self._Binding("google", "gemini-2.5-pro")) == DEFAULT_MAX_TOKENS * 2

    def test_alias_spelling_resolves_to_the_record(self):
        from core.analyzer import budget_retry_cap
        # The openrouter mirror spells it bare; the alias pass resolves it.
        assert budget_retry_cap(0, {0}, self._Binding("openrouter", "gpt-4.1")) == 32768

    def test_unlisted_model_keeps_default_cap(self):
        from core.analyzer import budget_retry_cap, BUDGET_RETRY_MAX_TOKENS
        assert budget_retry_cap(0, {0}, self._Binding("openai", "gpt-4o")) == BUDGET_RETRY_MAX_TOKENS
        assert budget_retry_cap(0, {0}, self._Binding("anthropic", "claude-opus-4-8")) == BUDGET_RETRY_MAX_TOKENS

    def test_ceiling_admitting_no_raise_returns_none(self):
        from core.analyzer import budget_retry_cap
        # A hypothetical ceiling at/below the default: no raise is possible;
        # None (same-cap) beats a guaranteed 400 on the retry.
        from unittest.mock import patch
        with patch("core.model_registry.max_output_tokens", return_value=16000):
            assert budget_retry_cap(0, {0}, self._Binding("openai", "x")) is None

    def test_registry_accessor_shapes(self):
        from core import model_registry
        assert model_registry.max_output_tokens("openai", "gpt-4.1") == 32768
        assert model_registry.max_output_tokens("openrouter", "gpt-4.1") == 32768
        assert model_registry.max_output_tokens("openai", "gpt-4o") is None
        assert model_registry.max_output_tokens("openai", "not-a-model") is None


class TestParityMarkers:
    """The #569 refutation's parity extension: the discriminator reaches
    EVERY adapter's budget wording — which the #569 review round made
    DETERMINISTIC-CLASS-ONLY (the truncated wordings carry the marker; the
    filtered wordings must NOT — gemini/Responses producers branch on the
    finish signal, mirroring the openai-chat #561 pattern)."""

    def test_gemini_budget_wording(self):
        assert is_budget_exhausted_error(
            "Gemini returned a candidate with no usable content (empty "
            "completion); the response was truncated — a thinking "
            "model consumed the token budget before emitting output")

    def test_gemini_filtered_not_budget(self):
        assert not is_budget_exhausted_error(
            "Gemini returned a candidate with no usable content (empty "
            "completion); the response may have been filtered or malformed")

    def test_openai_responses_budget_wording(self):
        assert is_budget_exhausted_error(
            "OpenAI Responses returned no usable content "
            "(status='incomplete'); the request was truncated — "
            "reasoning consumed the budget")

    def test_openai_responses_filtered_not_budget(self):
        assert not is_budget_exhausted_error(
            "OpenAI Responses returned no usable content "
            "(status='completed'); the request may have been filtered")

    def test_filtered_still_not_budget(self):
        assert not is_budget_exhausted_error(
            "may have been filtered or the response was malformed")
