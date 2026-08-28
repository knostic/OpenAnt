"""Regression tests for issue #286 — errored verify checkpoints are
restored as completed on resume, so failed units are never retried.

The resume classifier ``_cp_is_error`` returned True only when the
checkpoint had no ``verification`` dict or when
``verification["correct_finding"] == "error"`` — a value the normal verify
error path never writes. The error path writes ``verification =
{"incomplete": True}``. Every errored unit therefore looked like finished
work on resume and was adopted, never retried — #286's measured 223/223
adoption with 48 hard errors.

Contract locked here: a checkpoint whose verification carries
``incomplete: True`` IS an errored checkpoint (retryable) — the exact
signal the error path writes. A genuine completed verification
(agree + correct_finding, incomplete absent/False) is NOT errored.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.finding_verifier import FindingVerifier  # noqa: E402


def _classifier_from_source():
    """Extract the REAL _cp_is_error from the live source (no copy-paste
    predicate: the assertion reads the shipped code's semantics)."""
    import inspect
    src = inspect.getsource(FindingVerifier)
    m = re.search(r"def _cp_is_error\(cp_data\):\n(.*?)(?=\n        # Separate)", src, re.S)
    assert m, "the resume classifier must exist in the live source"
    body = m.group(0)
    ns = {}
    exec(body, ns)
    return ns["_cp_is_error"]


def test_errored_checkpoint_classifies_as_retry():
    """The #286 core: the verify-ERROR shape (the adapter-raise error
    string, now copied into the checkpoint by the writer) must classify
    as ERRORED (retryable), not completed."""
    cp = {"verification": {"agree": False, "incomplete": True},
          "finding": "vulnerable",
          "error": "LLMRefusalError: refused"}
    assert _classifier_from_source()(cp) is True, (
        "a checkpoint carrying the adapter-raise error string IS "
        "errored — treating it as completed adopts a failed unit and "
        "never retries it (#286)"
    )


def test_deterministic_incomplete_does_not_retry():
    """Wave catch (glm F1/F2, kimi F2): incomplete=True alone is NOT a
    retry signal — five non-error fail-safe writers set it (max
    iterations, truncated finish, no tool calls, degenerate finish);
    those are deterministic outcomes, and retrying them on every resume
    is unbounded waste (Opus 5 refusals are deterministic per #212)."""
    cp = {"verification": {"agree": False, "incomplete": True,
                           "explanation": "Verification incomplete"},
          "finding": "vulnerable"}
    assert _classifier_from_source()(cp) is False, (
        "incomplete WITHOUT an error string is a deterministic "
        "fail-safe outcome, not a retryable error"
    )


def test_completed_checkpoint_not_errored():
    cp = {"verification": {"agree": True, "correct_finding": "vulnerable",
                           "incomplete": False},
          "finding": "vulnerable"}
    assert _classifier_from_source()(cp) is False


def test_missing_verification_errored():
    assert _classifier_from_source()({}) is True
    assert _classifier_from_source()({"verification": {}}) is True


def test_correct_finding_error_still_errored():
    """The legacy correct_finding='error' path (written by the Stage-1
    consistency path) still classifies as errored."""
    cp = {"verification": {"correct_finding": "error", "incomplete": True},
          "finding": "vulnerable"}
    assert _classifier_from_source()(cp) is True
