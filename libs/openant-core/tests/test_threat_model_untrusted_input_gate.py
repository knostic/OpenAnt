"""Fix A — threat-model gate: don't suppress untrusted-input bugs for data libraries.

`format_app_context_for_prompt` (Stage 1) and `format_app_context_for_verification`
(Stage 2) historically emitted a "this is a CLI tool/library, only flag REMOTE
attackers, not local users" suppression block whenever `requires_remote_trigger`
was False — which the generator sets for EVERY library. That discards exactly the
bug class of a parser/deserializer/codec, whose untrusted INPUT DATA is the attack
surface even with no network listener (the tree-sitter case).

Fix: gate the suppression on `ApplicationContext.suppress_local_only()`, which keeps
the clause only when NO trust boundary is `untrusted`. A library that ingests
untrusted data (`source_code_being_parsed: untrusted`) is therefore analysed, while
a genuine no-attack-surface library (all-trusted) is unchanged — no new field, reuses
the already-captured `trust_boundaries`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from context.application_context import ApplicationContext  # noqa: E402
from prompts.vulnerability_analysis import format_app_context_for_prompt  # noqa: E402
from prompts.verification_prompts import format_app_context_for_verification  # noqa: E402

# Sentinels that appear ONLY inside the suppression block of each formatter.
_STAGE1_SUPPRESSION = "have local access"        # vulnerability_analysis.py
_STAGE2_SUPPRESSION = "local filesystem access"  # verification_prompts.py


def _lib(trust_boundaries, *, remote=False):
    return ApplicationContext(
        application_type="library",
        purpose="x",
        trust_boundaries=trust_boundaries,
        requires_remote_trigger=remote,
    )


# --- the method itself --------------------------------------------------------
def test_suppress_when_all_trusted():
    assert _lib({"cli_args": "trusted", "config": "trusted"}).suppress_local_only() is True


def test_do_not_suppress_when_any_untrusted():
    assert _lib({"source_code_being_parsed": "untrusted", "config": "trusted"}).suppress_local_only() is False


def test_untrusted_match_is_case_insensitive():
    # trust_boundaries values are LLM-generated; tolerate case deviation.
    assert _lib({"input": "Untrusted"}).suppress_local_only() is False
    assert _lib({"input": "UNTRUSTED"}).suppress_local_only() is False


def test_do_not_suppress_when_remote():
    # web_app-style: remote trigger always means no local-only suppression.
    assert _lib({"cli_args": "trusted"}, remote=True).suppress_local_only() is False


def test_empty_boundaries_still_suppress():
    # No declared boundaries + local-only library -> keep the conservative suppression.
    assert _lib({}).suppress_local_only() is True


# --- Stage 1 formatter --------------------------------------------------------
def test_stage1_all_trusted_keeps_suppression():
    out = format_app_context_for_prompt(_lib({"cli_args": "trusted"}))
    assert _STAGE1_SUPPRESSION in out


def test_stage1_untrusted_input_drops_suppression():
    out = format_app_context_for_prompt(_lib({"source_code_being_parsed": "untrusted"}))
    assert _STAGE1_SUPPRESSION not in out


# --- Stage 2 formatter --------------------------------------------------------
def test_stage2_all_trusted_keeps_suppression():
    out = format_app_context_for_verification(_lib({"cli_args": "trusted"}))
    assert _STAGE2_SUPPRESSION in out


def test_stage2_untrusted_input_drops_suppression():
    out = format_app_context_for_verification(_lib({"source_code_being_parsed": "untrusted"}))
    assert _STAGE2_SUPPRESSION not in out
