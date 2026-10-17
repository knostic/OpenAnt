"""Fetch a CVE record by ID from the NVD REST API (v2.0).

Ported from the standalone Auto Patcher project's ``cve_fetcher.py``, which
used only stdlib. This version uses ``requests`` instead of
``urllib.request`` -- ``requests`` is already a direct OpenAnt dependency and
already the established client for plain REST API calls elsewhere in this
codebase (see ``github_scanner/github_repo_filter.py``). It also verifies
TLS certificates against ``certifi``'s bundled CA roots by default, rather
than the selected Python interpreter's own OpenSSL default trust store --
which stdlib ``urllib``/``ssl`` fall back to, and which is not guaranteed to
be populated on every interpreter this CLI might run under. Set
``NVD_API_KEY`` in the environment to raise NVD's rate limits; the key is
only ever placed in an outgoing request header, never logged or included in
any exception message.

Unlike the original, "not found" and "fetch failure" are distinct exception
types (``CVENotFoundError`` / ``CVEFetchError``) rather than a single bare
``ValueError``, so callers -- and the eventual CLI error messages -- can tell
a typo'd or unknown CVE id apart from a network/parsing problem. Both
subclass ``ValueError`` so existing ``except ValueError`` handling still
catches either.

No retries here by design: a caller that wants retry behavior adds it at a
higher layer, where it can also decide whether a retry is worthwhile for a
given failure kind (retrying a CVENotFoundError is never useful).
"""

from __future__ import annotations

import os

import requests

_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVENotFoundError(ValueError):
    """NVD has no record matching the given CVE id."""


class CVEFetchError(ValueError):
    """Network, HTTP, or parsing failure while contacting NVD."""


def fetch_cve(cve_id: str, timeout: int = 15) -> dict:
    """Fetch a CVE record from the NVD API.

    Parameters
    ----------
    cve_id:
        Full CVE identifier, e.g. "CVE-2021-12345".
    timeout:
        Socket timeout in seconds for the NVD request.

    Returns
    -------
    dict
        The single CVE object (NVD's ``vulnerabilities[0]["cve"]``), not the
        NVD response envelope.

    Raises
    ------
    CVENotFoundError
        NVD returned HTTP 404, or a 200 response with no matching record.
    CVEFetchError
        Any other HTTP error, a network/timeout failure, or an unparseable
        or malformed response body.
    """
    url = f"{_API_URL}?cveId={cve_id}"
    headers = {}
    api_key = os.environ.get("NVD_API_KEY", "")
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        # Covers connection failures, timeouts, and TLS errors alike -- all
        # of them mean "we couldn't talk to NVD", not a parseable response.
        raise CVEFetchError(f"Failed to fetch {cve_id} from NVD: {exc}") from exc

    if resp.status_code == 404:
        raise CVENotFoundError(f"CVE {cve_id} not found in NVD (HTTP 404)") from None
    if not resp.ok:
        raise CVEFetchError(
            f"Failed to fetch {cve_id} from NVD: HTTP {resp.status_code} {resp.reason}"
        )

    try:
        payload = resp.json()
    except ValueError as exc:
        raise CVEFetchError(f"NVD returned an unparseable response for {cve_id}") from exc

    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        raise CVENotFoundError(f"NVD returned no matching record for {cve_id}")

    cve = vulnerabilities[0].get("cve")
    if not cve:
        raise CVEFetchError(
            f"NVD returned a malformed response for {cve_id} (missing cve object)"
        )
    return cve
