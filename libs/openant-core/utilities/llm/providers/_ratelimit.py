"""Shared rate-limiter glue for provider adapters.

Every adapter cooperates with the process-global :class:`GlobalRateLimiter`
so a 429/529 on any worker thread backs the *other* workers off — the
whole reason the limiter is a process-level singleton. Centralised here
so a new adapter can't silently skip the dance.

That omission is exactly the H1 defect from PR #69: only the Anthropic
adapter called the limiter, so with 8 workers on a shared OpenAI/Google
quota, one worker's 429 left the other seven stampeding. Wiring goes
through these two helpers in every adapter's ``complete()``:

    wait_for_rate_limit()                     # before issuing the request
    ...
    except <provider 429>:
        report_rate_limit(retry_after)        # on the rate-limit branch
"""

from __future__ import annotations

from typing import Optional

from ...rate_limiter import get_rate_limiter


def wait_for_rate_limit() -> None:
    """Block if a sibling worker recently hit a 429/529.

    Call once at the top of ``complete()``, before the network request.
    """
    get_rate_limiter().wait_if_needed()


def report_rate_limit(retry_after: Optional[float]) -> None:
    """Trigger global backoff after a 429/529.

    Call from the adapter's rate-limit ``except`` branch. ``retry_after``
    is the provider's hint in seconds (``None`` when absent — the limiter
    falls back to its configured default backoff).
    """
    get_rate_limiter().report_rate_limit(retry_after or 0.0)
