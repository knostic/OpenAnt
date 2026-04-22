"""TLS configuration for Anthropic API calls.

TLS inspection (for example Zscaler) terminates HTTPS with a corporate root
that is not in the default trust store. Node and Claude Code honor
``NODE_EXTRA_CA_CERTS`` (a PEM file of extra CA certificates). The Anthropic
Python SDK uses httpx; this module applies the same PEM when the variable is
set so verification succeeds behind those proxies.

Python 3.13+ enables ``VERIFY_X509_STRICT`` on default contexts, which rejects
many corporate intercept CAs (e.g. Zscaler) whose Basic Constraints extension
is not marked critical. When using ``NODE_EXTRA_CA_CERTS``, that strict bit is
cleared so TLS still verifies the chain while matching typical Node behavior.
"""

from __future__ import annotations

import os
import ssl
from typing import Any

import httpx

try:
    from anthropic import DefaultHttpxClient
except ImportError:  # pragma: no cover - extremely old anthropic
    DefaultHttpxClient = httpx.Client  # type: ignore[misc, assignment]

try:
    import certifi
except ImportError:  # pragma: no cover - pulled in by httpx
    certifi = None  # type: ignore[assignment]


def _relax_x509_strict_for_corporate_cas(ctx: ssl.SSLContext) -> None:
    """Turn off VERIFY_X509_STRICT so Zscaler-like CAs validate (Python 3.13+)."""
    strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
    if strict:
        ctx.verify_flags &= ~strict


def _ssl_context_from_node_extra_ca_certs() -> ssl.SSLContext | None:
    """Build TLS context: public CA bundle plus PEM from ``NODE_EXTRA_CA_CERTS``.

    Node appends ``NODE_EXTRA_CA_CERTS`` to its built-in store. On some platforms
    ``ssl.create_default_context()`` then ``load_verify_locations(file)`` does not
    stack the way we need; anchoring with certifi's bundle then loading the extra
    file matches the Node / Claude Code behavior more reliably (e.g. macOS +
    Zscaler).
    """
    path = (os.environ.get("NODE_EXTRA_CA_CERTS") or "").strip()
    if not path or not os.path.isfile(path):
        return None
    try:
        if certifi is not None:
            ctx = ssl.create_default_context(cafile=certifi.where())
        else:
            ctx = ssl.create_default_context()
        ctx.load_verify_locations(path)
        _relax_x509_strict_for_corporate_cas(ctx)
    except OSError:
        return None
    return ctx


def anthropic_http_client_from_env() -> httpx.Client | None:
    """Return an httpx client with extra CAs, or None if not configured."""
    ctx = _ssl_context_from_node_extra_ca_certs()
    if ctx is None:
        return None
    return DefaultHttpxClient(verify=ctx)


def create_anthropic_client(**kwargs: Any):
    """Construct ``anthropic.Anthropic`` honoring ``NODE_EXTRA_CA_CERTS``.

    If the caller passes ``http_client``, it is left unchanged.
    """
    import anthropic

    if kwargs.get("http_client") is None:
        http_client = anthropic_http_client_from_env()
        if http_client is not None:
            kwargs["http_client"] = http_client
    return anthropic.Anthropic(**kwargs)
