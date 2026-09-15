"""#209: the summary producer must not bless an empty completion as success.

`report.generator.generate_summary_report` returned `_context_provenance_header
(pipeline_data) + text` and its callers wrote the result unconditionally and
recorded `status: success` with `summary_path` in outputs — so an empty/
whitespace LLM completion produced a summary-free SUMMARY_REPORT.md asserted as
a delivered artifact (#209). The Claude-5 thinking/empty-completion path is a
known live producer of exactly that empty payload.

The guard lives on the RAW LLM output, BEFORE the provenance banner is prepended:
on a threat-model scan the banner is non-empty, so a guard on the banner+text
combination would miss precisely that case (and it is the case a repo-supplied
`OPENANT.THREATMODEL.md` triggers). These tests drive the real generator with
only the adapter stubbed, so the banner-prepend path is exercised, not stubbed
over. Fully offline ($0).
"""

import pytest

import report.generator as gen


class _Result:
    def __init__(self, block, has_text):
        # REAL TextBlock — the generator joins only `isinstance(b, TextBlock)`
        # blocks, so a fake block would be skipped and every case would look
        # empty (a vacuous pass).
        self.content = (block,)
        self.input_tokens = 10
        self.output_tokens = 5 if has_text else 0
        self.stop_reason = "end_turn"
        self.usage_details = None  # matches CompletionResult (#211 capture)


class _Adapter:
    def __init__(self, text):
        self._text = text

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        # Match the real keyword-only adapter signature so a wrong call fails
        # loudly, and resolve TextBlock at CALL TIME exactly as the generator
        # does (its `from utilities.llm import TextBlock` is inside the function).
        # A module-top import would bind a stale class if another test reimports
        # utilities.llm.adapter (several stub sys.modules["anthropic"]), and the
        # generator's isinstance(b, TextBlock) filter would then reject our block
        # and read the summary as empty.
        from utilities.llm import TextBlock

        return _Result(TextBlock(self._text), bool(self._text))


class _Binding:
    def __init__(self, text):
        self.adapter = _Adapter(text)
        self.model = "fake-model"
        self.provider_name = "fake"


_BUILTIN = {"findings": [], "pipeline_stats": {}}
_THREATMODEL = {
    "findings": [],
    "pipeline_stats": {},
    "context_source": "threat_model",
    "threat_model_sha256": "deadbeef",
    "threat_model_warnings": [],
}


class TestEmptySummaryGuard:
    def test_empty_completion_raises_builtin_context(self, monkeypatch):
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        with pytest.raises(Exception):
            gen.generate_summary_report(_BUILTIN, _Binding(""))

    def test_whitespace_completion_raises(self, monkeypatch):
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        with pytest.raises(Exception):
            gen.generate_summary_report(_BUILTIN, _Binding("  \n\t \n"))

    def test_empty_completion_raises_even_with_nonempty_threatmodel_banner(
        self, monkeypatch
    ):
        """The header hole: a threat-model scan prepends a non-empty banner, so a
        guard on banner+text would pass. The guard must fire on the raw output.
        """
        # sanity: the banner really is non-empty for this context
        assert gen._context_provenance_header(_THREATMODEL).strip(), (
            "threat_model context should produce a non-empty provenance banner"
        )
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        with pytest.raises(Exception):
            gen.generate_summary_report(_THREATMODEL, _Binding(""))

    def test_real_summary_still_succeeds(self, monkeypatch):
        """The guard must not break a normal, non-empty summary."""
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        text, usage = gen.generate_summary_report(
            _BUILTIN, _Binding("# Security Summary\n\nAll good.\n")
        )
        assert "Security Summary" in text
        assert text.strip()
