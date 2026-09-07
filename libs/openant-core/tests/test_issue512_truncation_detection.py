"""#512: truncation is never silent — the warn-once helper, the named
parse-failure, and the in-deliverable banners.

Reasoning models spend output budget on hidden reasoning and return a
fence fragment or an empty completion at exactly max_tokens; pre-#512
this surfaced as a bare JSON-parse failure (app-context) or a quietly
short summary/disclosure (report) with no signal of the cause.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utilities.llm import adapter as llm_adapter  # noqa: E402
from utilities.llm.helpers import (  # noqa: E402
    reset_truncation_warnings,
    simple_completion,
    simple_text,
)


class _FakeAdapter:
    def __init__(self, text, stop_reason):
        self._text = text
        self.stop_reason = stop_reason

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return llm_adapter.CompletionResult(
            content=(llm_adapter.TextBlock(self._text),),
            input_tokens=10,
            output_tokens=max_tokens if self.stop_reason == "max_tokens" else 5,
            stop_reason=self.stop_reason,
        )


class _Binding:
    def __init__(self, text, stop_reason="end_turn", phase="test_phase"):
        self.adapter = _FakeAdapter(text, stop_reason)
        self.model = "fake-model"
        self.phase = phase
        self.provider_name = "fake"


# --- the helper pair --------------------------------------------------------

def test_simple_completion_returns_the_result():
    b = _Binding("hello")
    result = simple_completion(b, "hi")
    assert isinstance(result, llm_adapter.CompletionResult)
    assert result.stop_reason == "end_turn"
    assert simple_text(b, "hi") == "hello"


def test_truncated_reply_warns_once_per_phase_model_cap(capsys):
    reset_truncation_warnings()
    b = _Binding("frag", stop_reason="max_tokens")
    simple_text(b, "x")
    simple_text(b, "x")
    out = capsys.readouterr().err
    assert out.count("hit max_tokens=") == 1, f"warned {out.count('hit max_tokens=')}x for the same key"
    # a different cap is a different signal
    simple_text(b, "x", max_tokens=777)
    out2 = capsys.readouterr().err
    assert out2.count("hit max_tokens=777") == 1
    reset_truncation_warnings()


def test_end_turn_at_cap_emits_nothing(capsys):
    """Locks the detector to stop_reason, NOT output_tokens==cap (the
    overturned heuristic: a normal reply that happens to be exactly the
    cap is not truncation)."""
    reset_truncation_warnings()
    b = _Binding("full reply exactly at cap", stop_reason="end_turn")
    simple_text(b, "x", max_tokens=10)
    out = capsys.readouterr().err
    assert "hit max_tokens" not in out
    reset_truncation_warnings()


# --- the app-context named failure ------------------------------------------

def test_appcontext_parse_error_names_the_truncation(monkeypatch, tmp_path):
    import context.application_context as appctx
    (tmp_path / "README.md").write_text("# Demo\nA CLI.\n")
    monkeypatch.setattr(appctx, "gather_context_sources", lambda p: {"README.md": "# Demo"})

    def _truncated(binding, prompt, **kw):
        return llm_adapter.CompletionResult(
            content=(llm_adapter.TextBlock("```json {\"trunc"),),
            input_tokens=1, output_tokens=2000, stop_reason="max_tokens")

    monkeypatch.setattr(appctx, "simple_completion", _truncated)
    import types
    binding = types.SimpleNamespace(provider_name="fake", model="fake-model")
    try:
        appctx.generate_application_context(tmp_path, binding=binding, force_regenerate=True)
        assert False, "should have raised"
    except ValueError as e:
        assert "stop_reason=max_tokens" in str(e)
        assert "TRUNCATED" in str(e)


# --- the generator banners ---------------------------------------------------

def _gen_binding(text, stop_reason):
    class _B:
        provider_name = "fake"
        model = "fake-model"
        adapter = _FakeAdapter(text, stop_reason)
    return _B()


def test_summary_truncation_banner_in_deliverable(monkeypatch):
    import report.generator as gen
    monkeypatch.setattr(gen, "load_prompt", lambda name: "PROMPT" if name in ("system", "summary") else "")
    b = _gen_binding("partial summary text", "max_tokens")
    text, _ = gen.generate_summary_report({"results": [], "metadata": {}}, b)
    assert "TRUNCATED at the model's output budget" in text
    assert text.index("TRUNCATED") < text.index("partial summary text")


def test_summary_untruncated_has_no_banner(monkeypatch):
    import report.generator as gen
    monkeypatch.setattr(gen, "load_prompt", lambda name: "PROMPT" if name in ("system", "summary") else "")
    b = _gen_binding("a complete summary", "end_turn")
    text, _ = gen.generate_summary_report({"results": [], "metadata": {}}, b)
    assert "TRUNCATED" not in text


def test_summary_empty_and_truncated_names_the_cause(monkeypatch):
    import report.generator as gen
    monkeypatch.setattr(gen, "load_prompt", lambda name: "PROMPT" if name in ("system", "summary") else "")
    b = _gen_binding("", "max_tokens")  # reasoning-only: empty text at cap
    try:
        gen.generate_summary_report({"results": [], "metadata": {}}, b)
        assert False, "the #209 guard should have raised"
    except RuntimeError as e:
        assert "stop_reason=max_tokens" in str(e)


def test_disclosure_truncation_banner(monkeypatch):
    import report.generator as gen
    monkeypatch.setattr(gen, "load_prompt", lambda name: "SYS" if name == "system" else "DISC {vulnerability_data}")
    b = _gen_binding("partial disclosure", "max_tokens")
    vuln = {"id": "f1", "name": "n", "cwe_id": 22, "cwe_name": "x",
            "location": {"file": "a.py", "line": 1},
            "finding": "vulnerable", "verdict": "vulnerable",
            "explanation": "e"}
    text, _ = gen.generate_disclosure(vuln, "vuln", b)
    assert "TRUNCATED at the model's output budget" in text


# --- the budget-drift pin ----------------------------------------------------

def test_generator_has_no_numeric_output_cap():
    """#290's mirror for the report generator: the two direct adapter calls
    must use DEFAULT_MAX_TOKENS, not private numeric pins."""
    src = (Path(__file__).resolve().parent.parent
           / "report" / "generator.py").read_text(encoding="utf-8")
    bad = re.findall(r"max_tokens\s*=\s*(\d+)", src)
    assert not bad, f"numeric max_tokens pins found in report/generator.py: {bad}"


def test_appcontext_has_no_numeric_output_cap():
    src = (Path(__file__).resolve().parent.parent
           / "context" / "application_context.py").read_text(encoding="utf-8")
    bad = re.findall(r"max_tokens\s*=\s*(\d+)", src)
    assert not bad, f"numeric max_tokens pins found in context/application_context.py: {bad}"

def test_empty_completion_guards_name_the_stop_reason():
    """The gate round's fold: the adapter empty-content guards (the only
    layer that sees an EMPTY reasoning-only truncation) name the stop
    reason — anthropic.py/openai.py carry it in the raise message; google
    names the truncation class in prose. Source-scan pin (no live call).
    """
    from pathlib import Path

    from utilities.llm.providers import anthropic as ap, openai as op
    ap_src = Path(ap.__file__).read_text(encoding="utf-8")
    assert "stop_reason={raw_stop!r}" in ap_src, (
        "anthropic's empty-completion guard no longer names the stop reason")
    op_src = Path(op.__file__).read_text(encoding="utf-8")
    assert "finish_reason={raw_finish!r}" in op_src, (
        "openai's empty-completion guard no longer names the finish reason")
