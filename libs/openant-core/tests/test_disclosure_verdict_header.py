"""#210: disclosures must distinguish verified from unverified findings.

The disclosure phase generated one document per DISCLOSURE_ELIGIBLE finding —
including Stage-1 candidates Stage-2 never adjudicated (`unverified`/`error`) —
with the verification status left to an LLM-rendered "Verified via ..." line
that the model dropped in most documents, and an `{affected_versions}` field the
payload never carries (rendered "[NOT PROVIDED]"). So an unadjudicated candidate
read identically to an attacker-simulation-confirmed vulnerability.

The producer now stamps a deterministic verification banner (and the real
file/function location) from the server-truth `stage2_verdict`, the same way the
vulnerable code is spliced in. These tests drive the real generator with only
the adapter stubbed (the LLM output carries NO verification prose), so the marker
must come from the deterministic header, not the model. Fully offline ($0).
"""

import pytest

import report.generator as gen


class _Result:
    def __init__(self, block):
        self.content = (block,)
        self.input_tokens = 10
        self.output_tokens = 5
        self.stop_reason = "end_turn"


class _Adapter:
    def __init__(self, text):
        self._text = text

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        # Match the real keyword-only adapter signature, and resolve TextBlock at
        # CALL TIME as the generator does — a module-top import would bind a stale
        # class if another test reimports utilities.llm.adapter, and the
        # generator's isinstance(b, TextBlock) filter would then read empty.
        from utilities.llm import TextBlock

        return _Result(TextBlock(self._text))


class _Binding:
    def __init__(self, text):
        self.adapter = _Adapter(text)
        self.model = "fake-model"
        self.provider_name = "fake"


# an LLM disclosure body with NO verification prose at all — the marker must
# come from the server-stamped header, not this text.
_LLM_BODY = "## Summary\n\nA plausible issue in the handler.\n"


def _finding(verdict):
    return {
        "stage2_verdict": verdict,
        "location": {"file": "app/routes.py", "function": "handler"},
        "short_name": "test-finding",
        "vulnerable_code_section": "",
    }


class TestDisclosureVerdictHeader:
    def test_unverified_finding_is_marked_unverified(self, monkeypatch):
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        out, _ = gen.generate_disclosure(
            _finding("unverified"), "prod", _Binding(_LLM_BODY)
        )
        assert "UNVERIFIED" in out, "an unverified Stage-1 candidate is not marked"
        assert "app/routes.py:handler" in out, "the location is not stamped"

    def test_confirmed_finding_is_marked_confirmed(self, monkeypatch):
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        out, _ = gen.generate_disclosure(
            _finding("confirmed"), "prod", _Binding(_LLM_BODY)
        )
        assert "CONFIRMED" in out
        assert "UNVERIFIED" not in out

    def test_error_verdict_is_unverified_not_confirmed(self, monkeypatch):
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        out, _ = gen.generate_disclosure(
            _finding("error"), "prod", _Binding(_LLM_BODY)
        )
        assert "UNVERIFIED" in out
        assert "CONFIRMED" not in out

    def test_bypassable_is_unverified_not_confirmed(self, monkeypatch):
        """`bypassable` is a Stage-1 verdict (no Stage-2 adjudication), so it must
        NOT be stamped confirmed — the same false-confirmation this banner kills.
        """
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        out, _ = gen.generate_disclosure(
            _finding("bypassable"), "prod", _Binding(_LLM_BODY)
        )
        assert "UNVERIFIED" in out
        assert "CONFIRMED" not in out

    def test_vulnerable_is_unverified_not_confirmed(self, monkeypatch):
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        out, _ = gen.generate_disclosure(
            _finding("vulnerable"), "prod", _Binding(_LLM_BODY)
        )
        assert "UNVERIFIED" in out
        assert "CONFIRMED" not in out

    def test_marker_is_deterministic_not_llm_dependent(self, monkeypatch):
        """The LLM body carries no verification text, so the marker is proof the
        header is server-stamped, not model-rendered."""
        monkeypatch.setattr(gen, "lookup_pricing", lambda b: None)
        assert "verif" not in _LLM_BODY.lower()  # guard the premise
        out, _ = gen.generate_disclosure(
            _finding("unverified"), "prod", _Binding(_LLM_BODY)
        )
        assert out.lstrip().startswith("> **Verification:**")
