"""Utility modules for OpenAnt vulnerability analysis."""

from .llm_client import (
    TokenTracker,
    get_global_tracker,
    reset_global_tracker,
)
from .json_corrector import JSONCorrector
from .context_corrector import ContextCorrector
from .context_reviewer import ContextReviewer
from .context_enhancer import ContextEnhancer
from .ground_truth_challenger import GroundTruthChallenger
from .finding_verifier import FindingVerifier, VerificationResult

__all__ = [
    'TokenTracker',
    'get_global_tracker',
    'reset_global_tracker',
    'MODEL_PRICING',
    'JSONCorrector',
    'ContextCorrector',
    'ContextReviewer',
    'ContextEnhancer',
    'GroundTruthChallenger',
    'FindingVerifier',
    'VerificationResult',
]


def __getattr__(name: str):
    # MODEL_PRICING is registry-backed and served lazily by llm_client's own
    # PEP 562 hook. Re-export it lazily too, so importing the ``utilities``
    # package (e.g. on ``--help``) does not force a config/models.json read at
    # import time — the wrinkle a naive eager re-export would reintroduce.
    if name == "MODEL_PRICING":
        from .llm_client import MODEL_PRICING

        return MODEL_PRICING
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
