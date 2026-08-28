"""Regression tests for issue #287 — generation parameters are excluded
from the backend fingerprint's KEY, so a budget change leaves
``key_digest`` unchanged and a resumed run adopts checkpoints produced
under the old budget.

The exclusion is a DOCUMENTED DELIBERATE decision (PR #242). #287's
narrowed ask: the rationale was CONDITIONAL on ERROR checkpoints not
adopting (#286's bug, now fixed by PR #377). The residual carry-over is
truncation-degraded SUCCESSES (stale adoption — weaker than FN).

Contract locked here:
- the verify phase's fingerprint KEY includes the phase's generation
  budget (``max_tokens``) via the existing ``extra_key`` mechanism;
- the deliberate-exclusion register in backend_identity.py documents the
  decision with its rationale AND the #286/#377 dependency;
- other phases' fingerprints are unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _verify_fingerprint(max_tokens, input_caps=None):
    """Build the verify-phase fingerprint exactly as verifier.py:182 does
    (the extra_key mechanism), with the given max_tokens and input caps."""
    from core.backend_identity import fingerprint_for_binding

    class _Binding:
        phase = "verify"
        model = "claude-5-opus"
        provider_name = "anthropic"
        base_url = None

        class adapter:
            name = "anthropic"

    class _Template(str):
        pass

    extra_key = {"analyze_fingerprint": "sha256:abc",
                 "gen_params": {"max_tokens": max_tokens}}
    if input_caps is not None:
        extra_key["input_caps"] = input_caps
    return fingerprint_for_binding(
        _Binding(), [_Template("template")], extra_key=extra_key)


def test_different_max_tokens_different_digest():
    """The #287 core: two verify fingerprints with identical identity but
    different max_tokens must have different key_digest values."""
    a = _verify_fingerprint(4096)
    b = _verify_fingerprint(20000)
    assert a["key_digest"] != b["key_digest"], (
        "a budget change must invalidate the verify checkpoint identity "
        "(stale adoption of truncation-degraded successes otherwise)"
    )


def test_same_max_tokens_same_digest():
    a = _verify_fingerprint(4096)
    b = _verify_fingerprint(4096)
    assert a["key_digest"] == b["key_digest"]


def test_exclusion_documented_in_backend_identity():
    """#287's ask (a): the deliberate exclusion is recorded in the file's
    own documented-exclusions register with its rationale and the #286
    dependency."""
    from core import backend_identity as bi
    import inspect
    src = inspect.getsource(bi)
    assert "max_tokens" in src and "generation param" in src.lower(), (
        "the deliberate exclusion of generation parameters must be "
        "documented in backend_identity.py's exclusions register"
    )
    assert "#286" in src or "377" in src, (
        "the FN-safety rationale's #286/#377 dependency must be named"
    )


def test_different_input_caps_different_digest():
    """Union-diff checkpoint (20 submitted, 2026-08-29): #291's input caps
    change what the model saw on every turn — they are part of the verify
    conversation's identity exactly like max_tokens. A cap change must
    invalidate the checkpoint identity (stale adoption of checkpoints
    produced under uncapped-input semantics otherwise)."""
    caps_a = {"max_prompt_chars": 60_000, "max_tool_result_chars": 24_000}
    caps_b = {"max_prompt_chars": 30_000, "max_tool_result_chars": 24_000}
    a = _verify_fingerprint(20000, caps_a)
    b = _verify_fingerprint(20000, caps_b)
    assert a["key_digest"] != b["key_digest"], (
        "an input-cap change must invalidate the verify checkpoint identity"
    )
