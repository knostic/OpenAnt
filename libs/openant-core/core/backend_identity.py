"""Minimal backend-identity fingerprints for checkpoint adopt-gating (I2).

OpenAnt caches per-phase LLM results in ``{scan_dir}/{phase}_checkpoints/``
keyed by ``unit_id`` (a PATH, e.g. ``file.py:func``). On a re-scan / resume
into a reused ``output_dir`` the phase ADOPTS those prior verdicts. That is
correct only when the SAME backend would have produced them. When the backend
identity has changed — a different model, provider, or adapter, or a different
static prompt template — adopting is a silent false-negative: the "scan" costs
$0 and re-uses answers a different backend never gave. Verify additionally
OVERWRITES the fresh Stage-1 verdict with the adopted one, corrupting the
report.

This module computes a scheme-versioned KEY that a phase stamps into its
checkpoint dir (``_fingerprint.json``) and re-checks on the next run. The KEY
is the invalidation identity: a change archives the old checkpoints aside and
re-pays.

KEY dimensions: ``scheme_version``, ``phase``, ``model``, ``provider_name``,
``adapter_type``, ``config_base_url``, a digest of the phase's STATIC prompt
template(s) (``templates_sha``), and any caller-supplied ``extra_key`` (verify
folds in the producing analyze run's fingerprint so an analyze-model swap
invalidates the dependent verify checkpoints too).

Deliberate exclusions (minimal by mandate):
  * NO endpoint DETECTION / drift_log / strict-mode — over-built, excluded.
  * NO credential-derived value (api_key). A credential-routing gateway (same
    URL + model, different key → different upstream) is a NAMED RESIDUAL.
  * app_context / threat-model is LLM-generated and regenerates
    non-deterministically every scan; callers MUST render templates with
    ``app_context=None`` so it never enters ``templates_sha`` (including it
    caused a VERIFIED ~17k-token spurious re-pay on a same-config resume).
  * Generation parameters (``max_tokens``, ``temperature``, etc.) are
    deliberately NOT global KEY members (#242: "this config-only change does
    not invalidate prior checkpoints. Rationale is FN-safe: pre-fix empty
    completions were recorded as ERROR, which never adopts on resume, so
    truncation-degraded successes are the only carry-over"). #287 re-checked
    the rationale: the FN-safety argument is CONDITIONAL on the ERROR-retry
    working — restored by #286/#377 (the adapter-raise error string is now
    copied into the checkpoint and retried on resume). The residual
    carry-over is truncation-degraded SUCCESSES (stale adoption, weaker
    than FN). The VERIFY phase opts IN its budget via ``extra_key`` (the
    existing mechanism, verifier.py:182): a ``max_tokens`` change invalidates
    verify checkpoints specifically, without a scheme bump. Other phases use
    ``simple_text`` whose default lives in helpers.py (a change there is a
    code-level behavior change, already visible in ``templates_sha``).

Bump ``FINGERPRINT_SCHEME_VERSION`` when the KEY definition changes; it is part
of the KEY, so old sidecars invalidate cleanly.

RESIDUALS (named, not closed here):
  * ``config_base_url`` IS now carried on ``PhaseBinding`` and folded into the
    KEY (sanitized: userinfo/query/fragment stripped, so no credential is
    persisted). Two gateway configs sharing model+provider but routing to
    different upstreams now discriminate; default-config users keep ``None`` →
    digest unchanged.
  * per-unit content drift — ``unit_id`` is PATH-based, not a content hash. A
    body edit under the SAME symbol adopts the stale per-unit verdict.
  * cred-routing / api_key — see above (same URL+model, different key → different
    upstream is NOT discriminated; api_key deliberately excluded from the KEY).
  * the ``enhance`` phase is NOT gated: it is default-on with PERMANENT
    checkpoints and, across a backend swap, ADOPTS the prior enhance results at
    base — restoring a stale ``agent_context`` that feeds the analyze prompt and
    gates ``--exploitable`` / ``--limit``. Deliberately deferred (gate only once
    a stale-enhance false-negative is demonstrated).
  * the ``dynamic_test`` phase is NOT gated: it likewise adopts prior execution
    facts across a backend swap at base. Deliberately deferred (same bar).
"""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit, urlunsplit

# Bump when the KEY definition below changes so pre-existing sidecars invalidate
# cleanly (they will simply mismatch and trigger an archive-and-repay).
FINGERPRINT_SCHEME_VERSION = 1

# Sidecar filename written into each checkpoint dir. Excluded from every
# checkpoint counter (see core/checkpoint.py and the Go DetectFallback).
FINGERPRINT_FILE = "_fingerprint.json"

# Substituted for any prompt template that fails to render. It differs from any
# real template text, so a fingerprint built over it never matches a real one
# → forces re-run rather than risking a stale adoption (the 93662c7 fail-safe).
UNRENDERABLE_SENTINEL = "<<unrenderable>>"


def _sanitize_base_url(url):
    """Return ``scheme://host[:port]/path`` with **userinfo, query, and fragment**
    stripped — the three standard credential-bearing URL components
    (``user:pass@`` in the netloc, ``?api_key=...`` in the query, ``#...`` in the
    fragment). The sidecar persists the raw KEY dict via ``_write_fingerprint``,
    so these must not survive.

    Named residual (NOT stripped): the ``path`` is preserved because it is
    load-bearing for endpoint discrimination, so a credential embedded in the
    PATH (``https://gw/…/sk-SECRET/v1``) or a matrix param (``;api_key=…`` inside
    a path segment) WOULD persist. This is the same accepted-residual tier as the
    ``api_key`` cred-routing exclusion — a gateway that puts a secret in the URL
    path is not distinguished from one that does not; do not rely on this function
    to redact path-embedded secrets. IPv6 literal hosts are re-bracketed so the
    netloc stays well-formed. ``None`` passes through unchanged so default-config
    users keep ``config_base_url=None`` (digest unchanged).
    """
    if not url:
        return url
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        port = p.port  # a property that PARSES the port → may raise ValueError
    except ValueError:
        # Unparseable url / invalid port → don't risk leaking; forego
        # discrimination for this url rather than crash the scan.
        return None
    # Re-bracket an IPv6 literal (urlsplit's .hostname drops the [] netloc form).
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    # Keep scheme + sanitized netloc + path only; query and fragment dropped.
    return urlunsplit((p.scheme, netloc, p.path, "", ""))


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def templates_digest(template_texts) -> str:
    """Digest the phase's STATIC prompt template text(s).

    Callers MUST render templates with ``app_context=None`` so the
    LLM-generated, per-scan-varying threat model never enters the digest.
    """
    joined = "\x00".join(t or "" for t in (template_texts or []))
    return "sha256:" + _sha256_hex(joined)


def render_template_texts(renderers) -> list[str]:
    """Render each zero-arg template callable, substituting
    ``UNRENDERABLE_SENTINEL`` for any that raises.

    Fail-safe: an unrenderable prompt must force a re-run (a sentinel that
    differs from every real fingerprint), never a stale adoption.
    """
    texts: list[str] = []
    for r in renderers:
        try:
            texts.append(r())
        except Exception:  # noqa: BLE001 — any render failure → sentinel
            texts.append(UNRENDERABLE_SENTINEL)
    return texts


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _key_digest(key: dict) -> str:
    return "sha256:" + _sha256_hex(_canonical(key))


def build_fingerprint(phase: str, model: str, provider_name: str,
                      adapter_type: str, config_base_url,
                      template_texts, extra_key: dict | None = None) -> dict:
    """Assemble the KEY fingerprint for a phase.

    Returns the KEY dict (``scheme_version``, ``phase``, ``model``,
    ``provider_name``, ``adapter_type``, ``config_base_url``, ``templates_sha``,
    optional ``extra``) plus ``key_digest`` = sha256 over the KEY. That digest
    is what the adopt gate compares. NO credential-derived value is included.
    ``extra_key`` folds caller-supplied, deterministic identity into the KEY
    (e.g. verify's producing-analyze fingerprint); its members are namespaced
    under ``extra`` so a caller dimension can never collide with a core one.
    """
    key = {
        "scheme_version": FINGERPRINT_SCHEME_VERSION,
        "phase": phase,
        "model": model,
        "provider_name": provider_name,
        "adapter_type": adapter_type,
        "config_base_url": config_base_url,
        "templates_sha": templates_digest(template_texts),
    }
    if extra_key:
        key["extra"] = {k: extra_key[k] for k in sorted(extra_key)}
    fingerprint = dict(key)
    fingerprint["key_digest"] = _key_digest(key)
    return fingerprint


def fingerprint_for_binding(binding, template_texts, *,
                            extra_key: dict | None = None) -> dict:
    """Build a phase fingerprint from a ``PhaseBinding`` + its static template(s).

    ``adapter_type`` comes from the adapter's class-level ``name``;
    ``config_base_url`` from ``binding.base_url`` (the provider's configured
    gateway endpoint), SANITIZED via :func:`_sanitize_base_url` so userinfo /
    query / fragment (which can carry ``user:pass`` or ``?api_key=``) never enter
    the KEY or the persisted sidecar. ``None`` (default-config users) passes
    through → digest unchanged, zero re-pay. No api_key / credential material is
    read. ``template_texts`` MUST be rendered with ``app_context=None``.
    """
    adapter = getattr(binding, "adapter", None)
    adapter_type = getattr(adapter, "name", None) or (
        type(adapter).__name__ if adapter is not None else "unknown")
    return build_fingerprint(
        phase=binding.phase,
        model=binding.model,
        provider_name=binding.provider_name,
        adapter_type=adapter_type,
        config_base_url=_sanitize_base_url(getattr(binding, "base_url", None)),
        template_texts=template_texts,
        extra_key=extra_key,
    )
