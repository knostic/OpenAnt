"""Secret redaction for adapter error messages.

Provider SDKs put the offending request body — including, sometimes, an
echoed API key — into the ``message`` of a 400/401 exception. Every
adapter wraps that message in one of our ``LLM*Error`` classes, and the
result flows to logs and JSON reports via
``utilities/context_enhancer._build_error_info`` (which copies
``str(exc)`` into ``info["message"]``). Without scrubbing, a leaked key
ends up in a report file on disk.

:func:`redact_secrets` masks the common secret SHAPES rather than trying
to know every provider's key format. It is deliberately CONSERVATIVE:
each pattern requires a recognisable prefix or an explicit ``key=`` /
``Bearer`` lead-in, so ordinary prose ("invalid 'messages' field",
"400 Bad Request") passes through untouched. Over-redaction would hide
the actual error the user needs to act on, so we only mask things that
look unambiguously like credentials.

Patterns covered:

* ``sk-ant-...`` — Anthropic keys (checked before the generic ``sk-``
  rule so the longer match wins).
* ``sk-...`` — OpenAI / OpenAI-compatible keys (``sk-proj-...`` etc.).
* ``AIza...`` — Google API keys (fixed 39-char shape).
* ``Bearer <token>`` — any Authorization-header style bearer token.
* ``key=`` / ``api_key=`` / ``apikey=`` query- or body-param values.

The mask keeps a short, non-reversible hint of the prefix so a human can
still tell *which kind* of credential leaked (useful for "rotate the
OpenAI key") without exposing the secret itself.
"""

from __future__ import annotations

import re

_MASK = "***REDACTED***"

# Order matters: Anthropic's ``sk-ant-`` is a strict prefix of the
# generic ``sk-`` rule, so it must be applied first to win the match.
# Each pattern is anchored on a distinctive lead-in (a prefix or a
# ``key=`` / ``Bearer`` marker) so prose without those markers is never
# touched.
#
# Token character classes stay permissive on length but require a
# minimum run so a bare "sk-" mention or a two-letter "key=x" doesn't
# trip them. Keys in the wild are 20+ chars; we require >= 12 to keep a
# margin while not matching short words.

# ``key=`` / ``api_key=`` / ``apikey=`` followed by a value, in a query
# string or a JSON-ish body. Capture the marker so we can re-emit it.
#
# F1 (round-5): the separator alternation also accepts ``%3D`` — the
# URL-encoded ``=`` that shows up when a provider echoes a raw query string
# back in a 400 body (``...?key%3D<secret>...``). Without it, a value with
# NO recognisable key prefix (a custom proxy token, say) after ``key%3D``
# would only be caught if it happened to look like an sk-/AIza key. We keep
# the literal ``=``/``:`` forms too. The marker is captured and re-emitted
# verbatim so the masked message still reads ``key%3D***REDACTED***``.
_PARAM_RE = re.compile(
    r"(?P<marker>\b(?:api[_-]?key|key)\s*(?:[=:]|%3[Dd])\s*)"
    r"(?P<val>[A-Za-z0-9._\-]{8,})",
    re.IGNORECASE,
)

# ``Bearer <token>`` — Authorization-header shape.
_BEARER_RE = re.compile(
    r"(?P<marker>\bBearer\s+)(?P<val>[A-Za-z0-9._\-]{12,})",
    re.IGNORECASE,
)

# F1 (round-5): the prefix patterns previously led with ``\b``, a word
# boundary that does NOT match between two word chars. So a key abutting a
# preceding word char slipped through UNREDACTED — verified for
# ``xsk-ant-…`` (abutting ``x``) and ``key%3Dsk-ant-…`` (the URL-encoded
# ``key=`` form, where the char before ``sk-`` is the ``D`` of ``%3D``).
# We drop the leading ``\b`` entirely so the prefix matches anywhere.
#
# Dropping the anchor reopens the over-redaction question the ``\b`` was
# (wrongly) trying to answer: ordinary hyphenated words contain an ``sk-``
# run (``disk-``, ``task-``, ``risk-``, ``ask-``). A naive ``sk-<chars>{N}``
# would mask ``task-list-management-system`` once the dashed tail reached
# the length floor. The robust distinguisher is NOT length — it's DENSITY:
# a real API key always contains a long opaque alphanumeric blob, whereas a
# dashed English phrase is short segments joined by hyphens and never has a
# run of many consecutive alphanumerics. So each prefix pattern carries a
# zero-width lookahead requiring a ``_KEY_DENSE_RUN``-length run of
# consecutive ``[A-Za-z0-9]`` somewhere in the body before it will match.
# This masks every real-key shape (positives below) while leaving
# ``disk-cache-eviction-policy-manager`` and a bare ``sk-`` mention alone.

# Minimum run of CONSECUTIVE alphanumerics that marks a token as a real
# secret rather than a dashed word. 16 is comfortably below the dense blob
# in any real key (Anthropic/OpenAI keys are 40+ chars of mostly-dense
# base62; the shortest segment here is the ~20-char tail) and far above any
# hyphen-joined English phrase, which tops out at a single ~12-char word.
_KEY_DENSE_RUN = 16

# Lookahead: somewhere from the current position, within the key charset,
# there is a run of ``_KEY_DENSE_RUN`` consecutive alphanumerics. Anchored
# at the prefix end so the dense-blob requirement applies to the BODY.
_DENSE_AHEAD = rf"(?=[A-Za-z0-9._\-]*[A-Za-z0-9]{{{_KEY_DENSE_RUN}}})"
_KEY_BODY = r"[A-Za-z0-9._\-]+"

# Anthropic keys: ``sk-ant-...`` (apply before the generic sk- rule). No
# ``\b`` — matches even when abutting a word char or ``%3D``.
_ANTHROPIC_RE = re.compile(r"sk-ant-" + _DENSE_AHEAD + _KEY_BODY)

# Generic OpenAI-style keys: ``sk-...`` / ``sk-proj-...``. Same de-anchored
# + dense-run shape so ``disk-``/``task-`` prose is never touched.
_OPENAI_RE = re.compile(r"sk-" + _DENSE_AHEAD + _KEY_BODY)

# Google API keys: ``AIza`` + url-safe tail. L2 (round-5): the tail length
# is made tolerant — ``{30,}`` instead of an exact ``{35}`` — so a future
# key shape that isn't exactly 39 chars is still caught. Today's keys are
# 39 chars (35-char tail), comfortably inside ``{30,}``. No ``\b`` so the
# URL-encoded ``key%3DAIza…`` form is also masked.
_GOOGLE_RE = re.compile(r"AIza[A-Za-z0-9_\-]{30,}")


def redact_secrets(text: str) -> str:
    """Mask credential-shaped substrings in ``text``.

    Returns ``text`` unchanged when it contains no recognisable secret
    shape. Non-string inputs are coerced via ``str`` so callers can pass
    ``redact_secrets(str(exc))`` without a guard. The function is
    idempotent — running it on already-redacted text is a no-op.
    """
    if not isinstance(text, str):
        text = str(text)

    # Marker-led patterns first: they preserve the ``key=`` / ``Bearer``
    # lead-in so the message still reads sensibly after masking.
    text = _PARAM_RE.sub(lambda m: m.group("marker") + _MASK, text)
    text = _BEARER_RE.sub(lambda m: m.group("marker") + _MASK, text)

    # Prefix-led key shapes. Anthropic before generic sk- so the longer,
    # more specific match consumes ``sk-ant-...`` first.
    text = _ANTHROPIC_RE.sub(_MASK, text)
    text = _OPENAI_RE.sub(_MASK, text)
    text = _GOOGLE_RE.sub(_MASK, text)

    return text


# ---------------------------------------------------------------------------
# F2 (round-5): redacted exception cause
# ---------------------------------------------------------------------------
#
# Every adapter wraps an SDK exception as ``raise LLM*Error(redact_secrets(
# str(exc))) from exc``. The WRAPPED message is redacted, but ``from exc``
# pins the RAW SDK exception (whose ``str()`` echoes the request body —
# possibly an API key) as ``__cause__``. The LLM phases run inside
# ``core.step_report.step_context``, whose ``__exit__`` calls
# ``traceback.print_exc(file=sys.stderr)`` on any propagating error — and
# ``print_exc`` walks the WHOLE chain, printing the unredacted cause to
# stderr/logs. So the redaction at the message layer is defeated one frame
# down the chain. (Same hole for ``logging`` with ``exc_info=True`` and any
# code that calls ``traceback.format_exc()``.)
#
# Fix: don't re-raise ``from`` the raw SDK exception. Re-raise ``from`` a
# lightweight ``RedactedCause`` instead — a plain exception whose only
# message is the REDACTED text and which is NOT itself chained to the SDK
# exception (``__cause__``/``__context__`` are left unset). The chain that
# prints is therefore ``LLMError`` → ``RedactedCause``, both redacted; the
# raw SDK object is dropped on the floor once we've copied what we need.
#
# We deliberately KEEP a cause (rather than ``raise ... from None``) so the
# downstream report builder still has a ``__cause__`` to read diagnostics
# off: ``utilities.context_enhancer._build_error_info`` pulls
# ``status_code`` / ``request_id`` from ``exc.__cause__`` today. We copy
# those two fields onto the ``RedactedCause`` so that read keeps working
# with ZERO changes to the report builder — no metadata regression.


class RedactedCause(Exception):
    """A redacted stand-in for an SDK exception, used as ``__cause__``.

    Carries only the redacted message plus the two diagnostic fields the
    report builder reads (``status_code`` / ``request_id``). It is never
    chained to the raw SDK exception, so printing the traceback chain
    (``traceback.print_exc`` in ``step_context.__exit__``, ``format_exc``,
    ``logging`` with ``exc_info``) can never surface the secret the SDK
    exception's ``str()`` would have echoed.

    Attributes mirror the names the major SDKs expose so the existing
    ``getattr(cause, "status_code"/"request_id")`` read in
    ``_build_error_info`` finds them unchanged. ``None`` when the source
    exception didn't carry them.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: object = None,
        request_id: object = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.request_id = request_id


def redacted_cause_from(exc: BaseException) -> RedactedCause:
    """Build a :class:`RedactedCause` from a raw SDK exception.

    Redacts ``str(exc)`` for the message and copies the ``status_code`` /
    ``request_id`` diagnostic fields across (when the SDK set them) so the
    report builder's ``__cause__`` read is preserved. The returned object
    is meant to be used as ``raise LLM*Error(...) from redacted_cause_from(
    exc)`` — see this module's F2 note for why this replaces ``from exc``.
    """
    return RedactedCause(
        redact_secrets(str(exc)),
        status_code=getattr(exc, "status_code", None),
        request_id=getattr(exc, "request_id", None),
    )
