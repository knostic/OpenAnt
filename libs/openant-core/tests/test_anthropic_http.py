"""Tests for utilities.anthropic_http (corporate TLS / NODE_EXTRA_CA_CERTS)."""

from __future__ import annotations

import os
import ssl
import tempfile
from typing import Any

import certifi
import pytest

from utilities.anthropic_http import _ssl_context_from_node_extra_ca_certs, create_anthropic_client

# Self-signed test CA (generated for this test module only; not a production trust anchor).
_TEST_CA_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIUb/55TWJ6Dq5Md9inc2PMh795YUkwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRVGVzdCBDb3Jwb3JhdGUgQ0EwHhcNMjYwNTE1MDgzMzM4
WhcNMjcwNTE1MDgzMzM4WjAcMRowGAYDVQQDDBFUZXN0IENvcnBvcmF0ZSBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANT6B1N+UkVlx4u4MWA/NKmJ
XVHULjJiOqdgEAQpJ0a1LMWHBmabthkdxVtzXOvbvZMeV2MmoMtN0fUKRvY4TRvF
ktPKzyuopz7T2KdVF062wLsq6+T0essOJ5DcUJSsyWlfX9myfGYqAq+XA6lufh6E
S6nroeYxbXvmIt7yMOG/TTHFghXHNPvnwOk7iy1QpPJt5dFlvXuANsgfJ5nBDyLS
P3kU+/P/Q3TQ3Qe6aEwF5MdvVnGhDQ7waKj3HHdhAabwkAzzAxoHxkzbm+GT5y/G
rmd9i7xOdztpmNxQ1xE2kk/7qDqmgQumNDsUOPpGnUfRh4lbsXmp9YoqRB1EYlMC
AwEAAaNTMFEwHQYDVR0OBBYEFEm8vvB1B2V/Jsctb6P+eMxM4sbqMB8GA1UdIwQY
MBaAFEm8vvB1B2V/Jsctb6P+eMxM4sbqMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAIbcE0Pcb7+azH9acQhsuRy3EEHaZYgBFmpfcnRqtgNHAfF3
hyevLhjCr+auiQ9NtAMEHeoRFGdqxqXG4BzqqIuoFrBc+cCwBxbeNVyWN0+6qqFi
ObYmZQu+wB3lPYdwlShNIGu+rRBNCsqymLtKIuLEqW1Rk1D5B4HiJCYDqBa0VXgY
IpGQR7qvDcgvH/AfYdfY3GSCMgAWDjAt28o6NV3lZC9gcfKmo3Vt1ID+W0DdE4TZ
8XqADeHTYAnJUQs4r81vbemLE8vbwuQR+/lSWyJ18jCAmoAjHl+VlHyaFdoFBCD+
bbc7He5nRua65XEUMIbTgpvT83E9KhHsJz+K96A=
-----END CERTIFICATE-----
"""


@pytest.fixture
def corporate_ca_pem_path() -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(_TEST_CA_PEM)
        path = f.name
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


def test_ssl_context_loads_extra_ca_into_trust_store(monkeypatch: pytest.MonkeyPatch, corporate_ca_pem_path: str):
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", corporate_ca_pem_path)
    base = ssl.create_default_context(cafile=certifi.where()).cert_store_stats()["x509"]
    ctx = _ssl_context_from_node_extra_ca_certs()
    assert ctx is not None
    assert ctx.cert_store_stats()["x509"] >= base + 1


def test_create_anthropic_client_injects_http_client_when_env_set(
    monkeypatch: pytest.MonkeyPatch, corporate_ca_pem_path: str,
):
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", corporate_ca_pem_path)
    captured: dict[str, Any] = {}

    class _StubAnthropic:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", _StubAnthropic)
    create_anthropic_client(api_key="test-key")
    assert "http_client" in captured
    assert captured["http_client"] is not None


def test_create_anthropic_client_skips_http_client_without_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
    captured: dict[str, Any] = {}

    class _StubAnthropic:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", _StubAnthropic)
    create_anthropic_client(api_key="test-key")
    assert "http_client" not in captured
