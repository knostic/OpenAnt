"""Unit tests for cve_fetcher. All tests use mocked HTTP -- no network required.

Ported from the standalone Auto Patcher project's test_cve_fetcher.py, adapted
to assert on the split CVENotFoundError/CVEFetchError exception types instead
of a single bare ValueError.
"""

from __future__ import annotations

import json
import urllib.error
from unittest import mock

import pytest

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


def _make_response(data: dict):
    """Build a mock context-manager response for urlopen."""
    body = json.dumps(data).encode("utf-8")
    cm = mock.MagicMock()
    cm.__enter__ = mock.Mock(return_value=cm)
    cm.__exit__ = mock.Mock(return_value=False)
    cm.read = mock.Mock(return_value=body)
    return cm


class TestFetchCveSuccess:
    def test_returns_the_unwrapped_cve_object(self):
        with mock.patch("urllib.request.urlopen", return_value=_make_response(FIXTURE_ENVELOPE)):
            result = fetch_cve("CVE-2021-12345")
        assert isinstance(result, dict)
        assert result == FIXTURE_CVE
        assert result["id"] == "CVE-2021-12345"

    def test_passes_timeout_through_to_urlopen(self):
        captured_kwargs = {}

        def fake_urlopen(req, **kwargs):
            captured_kwargs.update(kwargs)
            return _make_response(FIXTURE_ENVELOPE)

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            fetch_cve("CVE-2021-12345", timeout=42)

        assert captured_kwargs.get("timeout") == 42


class TestFetchCveNotFound:
    def test_http_404_raises_cve_not_found_error(self):
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                code=404,
                msg="Not Found",
                hdrs=None,
                fp=None,
            ),
        ):
            with pytest.raises(CVENotFoundError, match="HTTP 404"):
                fetch_cve("CVE-bad")

    def test_empty_vulnerabilities_list_raises_cve_not_found_error(self):
        empty_envelope = {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
        with mock.patch("urllib.request.urlopen", return_value=_make_response(empty_envelope)):
            with pytest.raises(CVENotFoundError, match="no matching record"):
                fetch_cve("CVE-9999-99999")

    def test_missing_vulnerabilities_key_raises_cve_not_found_error(self):
        with mock.patch("urllib.request.urlopen", return_value=_make_response({"resultsPerPage": 0})):
            with pytest.raises(CVENotFoundError):
                fetch_cve("CVE-9999-99999")

    def test_cve_not_found_error_is_a_value_error(self):
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                url="x", code=404, msg="Not Found", hdrs=None, fp=None
            ),
        ):
            with pytest.raises(ValueError):
                fetch_cve("CVE-bad")


class TestFetchCveFetchFailures:
    def test_other_http_errors_raise_cve_fetch_error(self):
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                code=503,
                msg="Service Unavailable",
                hdrs=None,
                fp=None,
            ),
        ):
            with pytest.raises(CVEFetchError, match="HTTP 503"):
                fetch_cve("CVE-2021-12345")

    def test_url_error_raises_cve_fetch_error(self):
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("name resolution failed"),
        ):
            with pytest.raises(CVEFetchError, match="name resolution failed"):
                fetch_cve("CVE-2021-12345")

    def test_timeout_raises_cve_fetch_error(self):
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with pytest.raises(CVEFetchError, match="timed out"):
                fetch_cve("CVE-2021-12345")

    def test_malformed_json_raises_cve_fetch_error(self):
        cm = mock.MagicMock()
        cm.__enter__ = mock.Mock(return_value=cm)
        cm.__exit__ = mock.Mock(return_value=False)
        cm.read = mock.Mock(return_value=b"not json{{")
        with mock.patch("urllib.request.urlopen", return_value=cm):
            with pytest.raises(CVEFetchError, match="unparseable"):
                fetch_cve("CVE-2021-12345")

    def test_vulnerabilities_entry_missing_cve_key_raises_cve_fetch_error(self):
        envelope = {"vulnerabilities": [{"not_cve": {}}]}
        with mock.patch("urllib.request.urlopen", return_value=_make_response(envelope)):
            with pytest.raises(CVEFetchError, match="malformed"):
                fetch_cve("CVE-2021-12345")

    def test_cve_fetch_error_is_a_value_error(self):
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
            with pytest.raises(ValueError):
                fetch_cve("CVE-2021-12345")


class TestApiKeyHeader:
    def test_includes_api_key_header_when_set(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "nvd_test_key")
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return _make_response(FIXTURE_ENVELOPE)

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            fetch_cve("CVE-2021-12345")

        assert captured, "urlopen was not called"
        assert captured[0].get_header("Apikey") == "nvd_test_key"

    def test_no_api_key_header_without_env_var(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return _make_response(FIXTURE_ENVELOPE)

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            fetch_cve("CVE-2021-12345")

        assert captured[0].get_header("Apikey") is None

    def test_api_key_value_never_appears_in_a_raised_error_message(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "super-secret-key-value")
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(url="x", code=500, msg="err", hdrs=None, fp=None),
        ):
            with pytest.raises(CVEFetchError) as exc_info:
                fetch_cve("CVE-2021-12345")
        assert "super-secret-key-value" not in str(exc_info.value)
