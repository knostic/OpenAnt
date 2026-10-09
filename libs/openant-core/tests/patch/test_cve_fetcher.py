"""Unit tests for cve_fetcher. All tests use mocked HTTP -- no network required.

Ported from the standalone Auto Patcher project's test_cve_fetcher.py, adapted
to assert on the split CVENotFoundError/CVEFetchError exception types instead
of a single bare ValueError. Re-adapted again when cve_fetcher switched its
transport from ``urllib.request`` to ``requests`` -- these tests mock
``requests.get`` and a ``requests.Response``-shaped object instead of
``urllib.request.urlopen`` and a context-manager, but assert on the exact
same product behavior (exception types, messages, and parsed CVE data) as
before.
"""

from __future__ import annotations

from unittest import mock

import pytest
import requests

from utilities.autopatcher.cve_fetcher import CVEFetchError, CVENotFoundError, fetch_cve

FIXTURE_CVE = {
    "id": "CVE-2021-12345",
    "descriptions": [
        {"lang": "en", "value": "A SQL injection vulnerability exists in the authenticate() function."}
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
            }
        ]
    },
    "weaknesses": [
        {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-89"}]}
    ],
    "references": [{"url": "https://example.com/advisory", "source": "nvd@nist.gov"}],
}

FIXTURE_ENVELOPE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [{"cve": FIXTURE_CVE}],
}

_PATCH_TARGET = "utilities.autopatcher.cve_fetcher.requests.get"


def _make_response(data: dict, status_code: int = 200):
    """Build a mock object standing in for a ``requests.Response``.

    ``status_code``/``ok``/``reason`` mirror how cve_fetcher branches on a
    non-transport-exception HTTP response (2xx/4xx/5xx all arrive here --
    unlike urllib, `requests` does not raise for a non-2xx status). ``.json``
    mirrors the body access cve_fetcher actually calls.
    """
    resp = mock.MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 400
    resp.reason = "OK" if status_code == 200 else "Error"
    resp.json = mock.Mock(return_value=data)
    return resp


def _make_json_error_response(exc: Exception):
    """A 200 response whose body isn't valid JSON -- `.json()` raises."""
    resp = mock.MagicMock(spec=requests.Response)
    resp.status_code = 200
    resp.ok = True
    resp.reason = "OK"
    resp.json = mock.Mock(side_effect=exc)
    return resp


class TestFetchCveSuccess:
    def test_returns_the_unwrapped_cve_object(self):
        with mock.patch(_PATCH_TARGET, return_value=_make_response(FIXTURE_ENVELOPE)):
            result = fetch_cve("CVE-2021-12345")
        assert isinstance(result, dict)
        assert result == FIXTURE_CVE
        assert result["id"] == "CVE-2021-12345"

    def test_passes_timeout_through_to_requests_get(self):
        captured_kwargs = {}

        def fake_get(url, **kwargs):
            captured_kwargs.update(kwargs)
            return _make_response(FIXTURE_ENVELOPE)

        with mock.patch(_PATCH_TARGET, fake_get):
            fetch_cve("CVE-2021-12345", timeout=42)

        assert captured_kwargs.get("timeout") == 42


class TestFetchCveNotFound:
    def test_http_404_raises_cve_not_found_error(self):
        with mock.patch(_PATCH_TARGET, return_value=_make_response({}, status_code=404)):
            with pytest.raises(CVENotFoundError, match="HTTP 404"):
                fetch_cve("CVE-bad")

    def test_empty_vulnerabilities_list_raises_cve_not_found_error(self):
        empty_envelope = {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
        with mock.patch(_PATCH_TARGET, return_value=_make_response(empty_envelope)):
            with pytest.raises(CVENotFoundError, match="no matching record"):
                fetch_cve("CVE-9999-99999")

    def test_missing_vulnerabilities_key_raises_cve_not_found_error(self):
        with mock.patch(_PATCH_TARGET, return_value=_make_response({"resultsPerPage": 0})):
            with pytest.raises(CVENotFoundError):
                fetch_cve("CVE-9999-99999")

    def test_cve_not_found_error_is_a_value_error(self):
        with mock.patch(_PATCH_TARGET, return_value=_make_response({}, status_code=404)):
            with pytest.raises(ValueError):
                fetch_cve("CVE-bad")


class TestFetchCveFetchFailures:
    def test_other_http_status_raises_cve_fetch_error(self):
        with mock.patch(_PATCH_TARGET, return_value=_make_response({}, status_code=503)):
            with pytest.raises(CVEFetchError, match="HTTP 503"):
                fetch_cve("CVE-2021-12345")

    def test_connection_error_raises_cve_fetch_error(self):
        with mock.patch(
            _PATCH_TARGET,
            side_effect=requests.exceptions.ConnectionError("name resolution failed"),
        ):
            with pytest.raises(CVEFetchError, match="name resolution failed"):
                fetch_cve("CVE-2021-12345")

    def test_timeout_raises_cve_fetch_error(self):
        with mock.patch(_PATCH_TARGET, side_effect=requests.exceptions.Timeout("timed out")):
            with pytest.raises(CVEFetchError, match="timed out"):
                fetch_cve("CVE-2021-12345")

    def test_malformed_json_raises_cve_fetch_error(self):
        bad_response = _make_json_error_response(ValueError("not json{{"))
        with mock.patch(_PATCH_TARGET, return_value=bad_response):
            with pytest.raises(CVEFetchError, match="unparseable"):
                fetch_cve("CVE-2021-12345")

    def test_vulnerabilities_entry_missing_cve_key_raises_cve_fetch_error(self):
        envelope = {"vulnerabilities": [{"not_cve": {}}]}
        with mock.patch(_PATCH_TARGET, return_value=_make_response(envelope)):
            with pytest.raises(CVEFetchError, match="malformed"):
                fetch_cve("CVE-2021-12345")

    def test_cve_fetch_error_is_a_value_error(self):
        with mock.patch(_PATCH_TARGET, side_effect=requests.exceptions.ConnectionError("boom")):
            with pytest.raises(ValueError):
                fetch_cve("CVE-2021-12345")


class TestApiKeyHeader:
    def test_includes_api_key_header_when_set(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "nvd_test_key")
        captured = []

        def fake_get(url, headers=None, timeout=None):
            captured.append(headers or {})
            return _make_response(FIXTURE_ENVELOPE)

        with mock.patch(_PATCH_TARGET, fake_get):
            fetch_cve("CVE-2021-12345")

        assert captured, "requests.get was not called"
        assert captured[0].get("apiKey") == "nvd_test_key"

    def test_no_api_key_header_without_env_var(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        captured = []

        def fake_get(url, headers=None, timeout=None):
            captured.append(headers or {})
            return _make_response(FIXTURE_ENVELOPE)

        with mock.patch(_PATCH_TARGET, fake_get):
            fetch_cve("CVE-2021-12345")

        assert "apiKey" not in captured[0]

    def test_api_key_value_never_appears_in_a_raised_error_message(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "super-secret-key-value")
        with mock.patch(_PATCH_TARGET, return_value=_make_response({}, status_code=500)):
            with pytest.raises(CVEFetchError) as exc_info:
                fetch_cve("CVE-2021-12345")
        assert "super-secret-key-value" not in str(exc_info.value)
