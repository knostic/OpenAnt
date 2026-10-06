"""Tests for utilities/autopatcher/tools/blind_evaluation.py and
run_traced.py --blind-evaluation (evaluation-only blind input mode).

Hermetic: LLM_PROVIDER=mock, fetch_cve mocked at its source module (same
patch target as test_run_traced_wrapper.py / test_run_patch_cve.py), no
network, no real repository beyond tmp_path. The two historical-benchmark
fixtures below are NVD-shaped dicts reconstructed so that the REAL
cve_to_vuln_text reproduces the exact previously-captured renderings
(asserted by hash) -- they live only here, in tests, never in the
implementation.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path
from unittest import mock

import pytest

import utilities.autopatcher.cve_converter as cve_converter_module
import utilities.autopatcher.investigation_adapters as adapters_module
import utilities.autopatcher.pipeline as pipeline_module
from utilities.autopatcher.cve_converter import cve_to_vuln_text as REAL_CVE_TO_VULN_TEXT
from utilities.autopatcher.investigation_adapters import case_from_vulnerability_text
from utilities.autopatcher.tools.blind_evaluation import (
    DIRECT_REMEDIATION_COMMIT,
    DIRECT_REMEDIATION_COMPARE,
    ORDINARY,
    RULE_ID,
    UNSUPPORTED_CODE_CHANGE,
    BlindEvaluationError,
    BlindEvaluationSession,
    blind_vulnerability_text,
    classify_reference_url,
    path_resolves_inside,
    sha256_text,
)

REAL_PIPELINE_RUN = pipeline_module.run

SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "utilities" / "autopatcher" / "tools" / "run_traced.py"
)
MODULE_PATH = SCRIPT_PATH.parent / "blind_evaluation.py"

CVE_ID = "CVE-2021-12345"


def _cve(refs, description="A path traversal in the archive extractor allows writing outside the target directory."):
    return {
        "id": CVE_ID,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
        "references": [{"url": u} for u in refs],
    }


COMMIT_URL = "https://github.com/acme/widget/commit/0123456789abcdef0123456789abcdef01234567"
COMPARE_URL = "https://github.com/acme/widget/compare/1.0.0...1.0.1"
ISSUE_URL = "https://github.com/acme/widget/issues/42"
ADVISORY_URL = "https://github.com/acme/widget/security/advisories/GHSA-aaaa-bbbb-cccc"
MAILING_URL = "https://lists.example.org/archives/security/2021/msg00001.html"

MIXED_CVE = _cve([MAILING_URL, COMMIT_URL, COMPARE_URL, ISSUE_URL, ADVISORY_URL])
ORDINARY_CVE = _cve([MAILING_URL, ISSUE_URL, ADVISORY_URL])


# --- historical fixtures (tests only) --------------------------------------

URLLIB3_FIXTURE = {
    "id": "CVE-2023-43804",
    "descriptions": [{"lang": "en", "value": (
        "urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` "
        "HTTP header special or provide any helpers for managing cookies over HTTP, that is the "
        "responsibility of the user. However, it is possible for a user to specify a `Cookie` header and "
        "unknowingly leak information via HTTP redirects to a different origin if that user doesn't "
        "disable redirects explicitly. This issue has been patched in urllib3 version 1.26.17 or 2.0.5."
    )}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.9, "baseSeverity": "MEDIUM"}}]},
    "weaknesses": [{"description": [
        {"lang": "en", "value": "CWE-200"}, {"lang": "en", "value": "NVD-CWE-noinfo"},
    ]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": c} for c in (
            "cpe:2.3:a:python:urllib3:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
            "cpe:2.3:o:fedoraproject:fedora:37:*:*:*:*:*:*:*",
            "cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*",
            "cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*",
        )
    ]}]}],
    "references": [{"url": u} for u in (
        "https://github.com/urllib3/urllib3/commit/01220354d389cd05474713f8c982d05c9b17aafb",
        "https://github.com/urllib3/urllib3/commit/644124ecd0b6e417c527191f866daa05a5a2056d",
        "https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f",
        "https://lists.debian.org/debian-lts-announce/2023/10/msg00012.html",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5F5CUBAN5XMEBVBZPHFITBLMJV5FIJJ5/",
    )],
}
URLLIB3_ORIGINAL_SHA = "c84983ba116d05cfe8bbbd802b2ae05928977c156e32ee94f73633cc5610e5dd"
URLLIB3_BLIND_SHA = "637ed26c167d15da9ff824f1783f08e0f1cb16b9f8548f644a819a8dc2477aac"

_PIP_REFS = (
    "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00005.html",
    "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00010.html",
    "https://github.com/gzpan123/pip/commit/a4c735b14a62f9cb864533808ac63936704f2ace",
    "https://github.com/pypa/pip/compare/19.1.1...19.2",
    "https://github.com/pypa/pip/issues/6413",
    "https://lists.debian.org/debian-lts-announce/2020/09/msg00010.html",
    "https://www.oracle.com/security-alerts/cpuapr2022.html",
    "https://www.oracle.com/security-alerts/cpujul2022.html",
)
PIP_FIXTURE = {
    "id": "CVE-2019-20916",
    "descriptions": [{"lang": "en", "value": (
        "The pip package before 19.2 for Python allows Directory Traversal when a URL is given in an "
        "install command, because a Content-Disposition header can have ../ in a filename, as "
        "demonstrated by overwriting the /root/.ssh/authorized_keys file. This occurs in "
        "_download_http_url in _internal/download.py."
    )}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": c} for c in (
            "cpe:2.3:a:pypa:pip:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:opensuse:leap:15.1:*:*:*:*:*:*:*",
            "cpe:2.3:o:opensuse:leap:15.2:*:*:*:*:*:*:*",
            "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:oracle:communications_cloud_native_core_network_function_cloud_native_environment:1.10.0:*:*:*:*:*:*:*",
        )
    ]}]}],
    # NVD lists each URL once per source -- 16 entries; the converter keeps the first five.
    "references": [{"url": u} for u in _PIP_REFS + _PIP_REFS],
}
PIP_ORIGINAL_SHA = "e0e2421c2357effe44fb5bc7364c210351b6c13b31b25b1a4f3108ceba596206"


# --- helpers ---------------------------------------------------------------


@pytest.fixture(scope="module")
def run_traced():
    spec = importlib.util.spec_from_file_location("run_traced_blind_tests", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _assert_globals_restored():
    yield
    assert cve_converter_module.cve_to_vuln_text is REAL_CVE_TO_VULN_TEXT
    assert pipeline_module.run is REAL_PIPELINE_RUN


def _references_body(text: str) -> list[str]:
    section = text.split("## References\n", 1)[1].split("\n## ", 1)[0]
    return [line for line in section.splitlines() if line]


def _outside_references(text: str) -> tuple[str, str]:
    head, rest = text.split("## References\n", 1)
    return head, "## " + rest.split("\n## ", 1)[1]


def _main(run_traced, tmp_path, monkeypatch, cve, extra_args=(), name="run"):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo = tmp_path / f"{name}-repo"
    repo.mkdir(exist_ok=True)
    out = tmp_path / f"{name}-out"
    argv = ["--cve", CVE_ID, "--repo-root", str(repo), "--output", str(out), "--quiet", *extra_args]
    with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve):
        rc = run_traced.main(argv)
    manifest_path = out / "trace" / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else None
    return rc, out, manifest


class _PipelineSpy:
    """Installed as pipeline.run BEFORE main() so a BlindEvaluationSession,
    if any, wraps it -- i.e. it observes what passes the guard."""

    def __init__(self, sidecar_dir: "Path | None" = None):
        self.texts = []
        self.sidecar_existed_at_entry = None
        self.sidecar_dir = sidecar_dir
        self.converter_was_real = None

    def __call__(self, **kwargs):
        self.texts.append(kwargs["vulnerability_text"])
        if self.sidecar_dir is not None:
            self.sidecar_existed_at_entry = self.sidecar_dir.exists()
        self.converter_was_real = cve_converter_module.cve_to_vuln_text is REAL_CVE_TO_VULN_TEXT
        return REAL_PIPELINE_RUN(**kwargs)


# --- 3-8: the pure filter --------------------------------------------------


class TestFilterContract:
    def test_github_commit_reference_removed(self):
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(MIXED_CVE))
        assert f"- {COMMIT_URL}" in r.removed_reference_lines
        assert COMMIT_URL not in r.blinded_text

    def test_github_compare_reference_removed(self):
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(MIXED_CVE))
        assert f"- {COMPARE_URL}" in r.removed_reference_lines
        assert COMPARE_URL not in r.blinded_text

    def test_issue_reference_preserved(self):
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(MIXED_CVE))
        assert f"- {ISSUE_URL}" in _references_body(r.blinded_text)

    def test_advisory_and_mailing_list_preserved(self):
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(MIXED_CVE))
        body = _references_body(r.blinded_text)
        assert body == [f"- {MAILING_URL}", f"- {ISSUE_URL}", f"- {ADVISORY_URL}"]

    def test_exact_removed_lines_and_order(self):
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(MIXED_CVE))
        assert r.removed_reference_lines == (f"- {COMMIT_URL}", f"- {COMPARE_URL}")
        assert r.removed_references == (COMMIT_URL, COMPARE_URL)
        assert r.rule_id == RULE_ID

    def test_output_is_input_minus_exact_lines(self):
        original = REAL_CVE_TO_VULN_TEXT(MIXED_CVE)
        r = blind_vulnerability_text(original)
        assert r.blinded_text == original.replace(f"- {COMMIT_URL}\n", "").replace(f"- {COMPARE_URL}\n", "")
        assert r.original_sha256 == sha256_text(original)
        assert r.blinded_sha256 == sha256_text(r.blinded_text)

    def test_prose_byte_identical(self):
        original = REAL_CVE_TO_VULN_TEXT(MIXED_CVE)
        r = blind_vulnerability_text(original)
        assert _outside_references(r.blinded_text) == _outside_references(original)

    def test_filtering_only_inside_references(self):
        # An ordinary URL in prose stays; an identical-looking bullet outside
        # References is never filtered -- here a commit URL in prose aborts
        # instead of being silently removed (it would require rewriting prose).
        prose_issue = _cve([COMMIT_URL], description=f"Reported at {ISSUE_URL} by a researcher.")
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(prose_issue))
        assert ISSUE_URL in r.blinded_text and COMMIT_URL not in r.blinded_text

        prose_commit = _cve([MAILING_URL], description=f"Fixed upstream by {COMMIT_URL}.")
        with pytest.raises(BlindEvaluationError) as ei:
            blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(prose_commit))
        assert ei.value.unsupported_references[0]["url"] == COMMIT_URL
        assert ei.value.unsupported_references[0]["line"] is None

    def test_no_insertion_when_everything_removed(self):
        original = REAL_CVE_TO_VULN_TEXT(_cve([COMMIT_URL, COMPARE_URL]))
        r = blind_vulnerability_text(original)
        assert _references_body(r.blinded_text) == []
        assert "(none)" not in r.blinded_text
        assert len(r.blinded_text) == len(original) - len(f"- {COMMIT_URL}\n") - len(f"- {COMPARE_URL}\n")

    def test_none_placeholder_kept_and_unchanged(self):
        original = REAL_CVE_TO_VULN_TEXT(_cve([]))
        r = blind_vulnerability_text(original)
        assert r.blinded_text == original and "- (none)" in r.blinded_text

    @pytest.mark.parametrize("url,category", [
        (COMMIT_URL, DIRECT_REMEDIATION_COMMIT),
        ("https://github.com/acme/widget/commit/0123abc", DIRECT_REMEDIATION_COMMIT),
        ("https://github.com/fork-owner/widget/commit/abcdef0123", DIRECT_REMEDIATION_COMMIT),
        (COMPARE_URL, DIRECT_REMEDIATION_COMPARE),
        ("https://github.com/acme/widget/compare/v1.2...v1.3", DIRECT_REMEDIATION_COMPARE),
        (ISSUE_URL, ORDINARY),
        (ADVISORY_URL, ORDINARY),
        ("https://github.com/advisories/GHSA-aaaa-bbbb-cccc", ORDINARY),
        ("https://github.com/acme/widget/releases/tag/1.0.1", ORDINARY),
        ("https://github.com/acme/widget", ORDINARY),
        (MAILING_URL, ORDINARY),
        ("https://nvd.nist.gov/vuln/detail/CVE-2021-12345", ORDINARY),
        ("https://www.vendor.example/security-alerts/2022.html", ORDINARY),
        # recognizable code-change forms V1 does not support -> fail closed
        ("https://github.com/acme/widget/pull/7", UNSUPPORTED_CODE_CHANGE),
        ("https://github.com/acme/widget/pull/7/files", UNSUPPORTED_CODE_CHANGE),
        ("https://github.com/acme/widget/commits/main", UNSUPPORTED_CODE_CHANGE),
        ("https://github.com/acme/widget/commit/not-a-hex-ref", UNSUPPORTED_CODE_CHANGE),
        ("https://github.com/acme/widget/commit/0123456789abcdef.patch", UNSUPPORTED_CODE_CHANGE),
        ("https://github.com/acme/widget/commit/0123456789abcdef#diff-1", UNSUPPORTED_CODE_CHANGE),
        ("https://github.com/acme/widget/compare/1.0..1.1", UNSUPPORTED_CODE_CHANGE),
        ("https://gitlab.com/acme/widget/-/commit/0123456789abcdef", UNSUPPORTED_CODE_CHANGE),
        ("https://gitlab.com/acme/widget/-/merge_requests/3", UNSUPPORTED_CODE_CHANGE),
        ("https://bitbucket.org/acme/widget/commits/0123456789abcdef", UNSUPPORTED_CODE_CHANGE),
        ("https://bitbucket.org/acme/widget/pull-requests/5", UNSUPPORTED_CODE_CHANGE),
        ("https://git.example.org/widget.git/commit/?id=0123456789abcdef", UNSUPPORTED_CODE_CHANGE),
        ("https://patches.example.org/fix-traversal.diff", UNSUPPORTED_CODE_CHANGE),
        ("https://git.example.org/?p=widget.git;a=commitdiff;h=0123456", UNSUPPORTED_CODE_CHANGE),
    ])
    def test_url_classification(self, url, category):
        assert classify_reference_url(url).category == category

    @pytest.mark.parametrize("url", [
        "https://github.com/acme/widget/pull/7",
        "https://gitlab.com/acme/widget/-/merge_requests/3",
        "https://bitbucket.org/acme/widget/commits/0123456789abcdef",
    ])
    def test_unsupported_reference_raises_and_is_reported_not_removed(self, url):
        with pytest.raises(BlindEvaluationError) as ei:
            blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(_cve([MAILING_URL, COMMIT_URL, url])))
        assert [u["url"] for u in ei.value.unsupported_references] == [url]
        assert ei.value.unsupported_references[0]["line"] == f"- {url}"
        assert url in str(ei.value)

    @pytest.mark.parametrize("text", [
        "# T\n\n## Vulnerability description\n\nx\n",                                  # no References
        "# T\n\n## References\n\n- https://a.example/x\n\n## References\n\n## Note\n",  # duplicate
        "# T\n\n## References\n\n- https://a.example/x\n",                             # no following H2
        "# T\n\n## References\n\nsee https://a.example/x\n\n## Note\n",                # malformed line
        "# T\n\n## References\n\n- https://a.example/x trailing\n\n## Note\n",        # malformed line
        "# T\n\n## References\n\n- not-a-url\n\n## Note\n",                           # malformed line
    ])
    def test_unrecognized_structure_fails_closed(self, text):
        with pytest.raises(BlindEvaluationError):
            blind_vulnerability_text(text)

    def test_non_string_rejected(self):
        with pytest.raises(BlindEvaluationError):
            blind_vulnerability_text(None)


# --- 9, 10, 20, 21: rendering-level behavior -------------------------------


class TestRenderedFixtures:
    def test_no_refill_after_five_reference_cap(self):
        refs = [COMMIT_URL, COMPARE_URL, MAILING_URL, ISSUE_URL, ADVISORY_URL,
                "https://sixth.example/never-rendered"]
        original = REAL_CVE_TO_VULN_TEXT(_cve(refs))
        assert "sixth.example" not in original  # converter's own cap
        r = blind_vulnerability_text(original)
        assert _references_body(r.blinded_text) == [f"- {MAILING_URL}", f"- {ISSUE_URL}", f"- {ADVISORY_URL}"]
        assert "sixth.example" not in r.blinded_text

    def test_zero_removable_references_identical_hashes(self):
        original = REAL_CVE_TO_VULN_TEXT(ORDINARY_CVE)
        r = blind_vulnerability_text(original)
        assert r.blinded_text == original
        assert r.original_sha256 == r.blinded_sha256
        assert r.removed_reference_lines == ()

    def test_urllib3_fixture_reproduces_validated_blind_transformation(self):
        original = REAL_CVE_TO_VULN_TEXT(URLLIB3_FIXTURE)
        assert sha256_text(original) == URLLIB3_ORIGINAL_SHA  # fixture fidelity
        r = blind_vulnerability_text(original)
        assert r.original_sha256 == URLLIB3_ORIGINAL_SHA
        assert r.blinded_sha256 == URLLIB3_BLIND_SHA
        assert r.removed_references == (
            "https://github.com/urllib3/urllib3/commit/01220354d389cd05474713f8c982d05c9b17aafb",
            "https://github.com/urllib3/urllib3/commit/644124ecd0b6e417c527191f866daa05a5a2056d",
        )

    def test_pip_fixture_removes_fork_commit_and_compare(self):
        original = REAL_CVE_TO_VULN_TEXT(PIP_FIXTURE)
        assert sha256_text(original) == PIP_ORIGINAL_SHA  # fixture fidelity (live render)
        r = blind_vulnerability_text(original)
        assert r.removed_references == (
            "https://github.com/gzpan123/pip/commit/a4c735b14a62f9cb864533808ac63936704f2ace",
            "https://github.com/pypa/pip/compare/19.1.1...19.2",
        )
        assert _references_body(r.blinded_text) == [
            "- http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00005.html",
            "- http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00010.html",
            "- https://github.com/pypa/pip/issues/6413",
        ]
        assert "debian-lts-announce" not in r.blinded_text  # no refill past the cap
        assert _outside_references(r.blinded_text) == _outside_references(original)


# --- 1, 2: run_traced argument surface and default path --------------------


class TestRunTracedDefaultAndValidation:
    def test_flag_defaults_off(self, run_traced):
        assert run_traced.build_parser().parse_args(["--cve", "X", "--repo-root", "/r"]).blind_evaluation is False

    def test_default_run_unchanged(self, run_traced, tmp_path, monkeypatch):
        spy = _PipelineSpy()
        with mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, out, manifest = _main(run_traced, tmp_path, monkeypatch, MIXED_CVE)
        assert rc == 0
        expected = REAL_CVE_TO_VULN_TEXT(MIXED_CVE)
        assert spy.texts == [expected]                       # references NOT filtered
        assert spy.converter_was_real is True                 # no interception installed
        assert (out / "patch" / f"{CVE_ID}-vulnerability.md").read_text() == expected
        assert "blind_evaluation" not in manifest
        assert not (out / "trace" / "blind_evaluation").exists()
        assert manifest["status"] == "success"

    def test_rejected_outside_cve_mode(self, run_traced, tmp_path, capsys):
        po = tmp_path / "pipeline_output.json"
        po.write_text("{}")
        with mock.patch("core.patch.run_patch") as m_run:
            rc = run_traced.main([str(po), "--finding-id", "VULN-001", "--output", str(tmp_path / "o"),
                                  "--blind-evaluation"])
        assert rc == 2
        m_run.assert_not_called()
        assert "--blind-evaluation is supported only with --cve" in capsys.readouterr().err

    @pytest.mark.parametrize("which", ["output", "trace-dir"])
    def test_rejected_when_artifacts_inside_repo(self, run_traced, tmp_path, which):
        repo = tmp_path / "repo"
        repo.mkdir()
        argv = ["--cve", CVE_ID, "--repo-root", str(repo), "--blind-evaluation"]
        argv += (["--output", str(repo / "out")] if which == "output"
                 else ["--output", str(tmp_path / "out"), "--trace-dir", str(repo / "trace")])
        with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve") as m_fetch:
            assert run_traced.main(argv) == 2
        m_fetch.assert_not_called()
        assert not (repo / "out").exists() and not (repo / "trace").exists()


# --- 10, 11, 15, 17, 18: end-to-end opt-in runs ----------------------------


class TestBlindRunEndToEnd:
    def test_consistency_metadata_and_sidecar(self, run_traced, tmp_path, monkeypatch):
        out_dir = tmp_path / "run-out"
        spy = _PipelineSpy(sidecar_dir=out_dir / "trace" / "blind_evaluation")
        with mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, out, manifest = _main(run_traced, tmp_path, monkeypatch, MIXED_CVE, ["--blind-evaluation"])
        assert rc == 0 and manifest["status"] == "success"

        original = REAL_CVE_TO_VULN_TEXT(MIXED_CVE)
        expected = blind_vulnerability_text(original)
        sidecar = out / "trace" / "blind_evaluation"
        vuln_md = (out / "patch" / f"{CVE_ID}-vulnerability.md").read_text()
        s1 = json.loads(Path(manifest["executions"][0]["artifact_path"]).read_text())

        # 18: original / blinded / S1 / pipeline-input consistency
        assert (sidecar / "original_vulnerability.md").read_text() == original
        assert spy.texts == [expected.blinded_text]
        assert vuln_md == expected.blinded_text
        assert s1["vulnerability_text"] == expected.blinded_text
        assert (sidecar / "blinded_vulnerability.md").read_text() == expected.blinded_text
        assert spy.sidecar_existed_at_entry is False  # never readable by the system under test

        # 17: manifest/sidecar metadata accuracy
        b = manifest["blind_evaluation"]
        assert b["enabled"] is True and b["rule_id"] == RULE_ID and b["status"] == "verified"
        assert b["original_sha256"] == sha256_text(original)
        assert b["blinded_sha256"] == sha256_text(expected.blinded_text) == b["pipeline_input_sha256"]
        assert b["removed_reference_lines"] == [f"- {COMMIT_URL}", f"- {COMPARE_URL}"]
        assert b["removed_references"] == [COMMIT_URL, COMPARE_URL]
        assert b["removed_count"] == 2
        assert b["unsupported_references"] == []
        assert b["converter_interception_count"] == 1
        assert b["pipeline_entry_count"] == 1
        assert b["pipeline_input_verified"] is True
        assert b["vulnerability_artifact_verified"] is True
        assert b["error"] is None and b["run_error"] is None
        assert (sidecar / "removed_reference_lines.txt").read_text() == f"- {COMMIT_URL}\n- {COMPARE_URL}\n"
        side_meta = json.loads((sidecar / "blind_evaluation.json").read_text())
        assert side_meta["blinded_sha256"] == b["blinded_sha256"]
        assert set(b["sidecar_files"].values()) == {p.name for p in sidecar.iterdir()}

    def test_zero_removable_is_valid_blind_run(self, run_traced, tmp_path, monkeypatch):
        rc, out, manifest = _main(run_traced, tmp_path, monkeypatch, ORDINARY_CVE, ["--blind-evaluation"])
        b = manifest["blind_evaluation"]
        assert rc == 0 and b["status"] == "verified"
        assert b["removed_count"] == 0 and b["original_sha256"] == b["blinded_sha256"]
        assert (out / "patch" / f"{CVE_ID}-vulnerability.md").read_text() == REAL_CVE_TO_VULN_TEXT(ORDINARY_CVE)

    def test_unsupported_reference_aborts_before_pipeline(self, run_traced, tmp_path, monkeypatch, capsys):
        pr_url = "https://github.com/acme/widget/pull/7"
        spy = _PipelineSpy()
        with mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, out, manifest = _main(run_traced, tmp_path, monkeypatch,
                                      _cve([COMMIT_URL, pr_url, ISSUE_URL]), ["--blind-evaluation"])
        assert rc == 2
        assert spy.texts == []
        assert manifest["status"] == "failed" and manifest["error_type"] == "BlindEvaluationError"
        assert manifest["llm_call_count"] == 0
        b = manifest["blind_evaluation"]
        assert b["status"] == "aborted"
        assert [u["url"] for u in b["unsupported_references"]] == [pr_url]
        assert b["blinded_sha256"] is None and b["pipeline_entry_count"] == 0
        assert not (out / "patch" / f"{CVE_ID}-trust-report.md").exists()
        assert pr_url in capsys.readouterr().err


# --- 12-16: fail-closed interception/verification paths --------------------


def _bypassing_case_from_cve(cve, repo_root=None):
    """Builds the same case WITHOUT going through the (wrapped) converter."""
    return case_from_vulnerability_text(REAL_CVE_TO_VULN_TEXT(cve), repo_root=repo_root)


def _double_render_case_from_cve(cve, repo_root=None):
    cve_converter_module.cve_to_vuln_text(cve)
    return case_from_vulnerability_text(cve_converter_module.cve_to_vuln_text(cve), repo_root=repo_root)


def _tampering_case_from_cve(cve, repo_root=None):
    text = cve_converter_module.cve_to_vuln_text(cve) + "tampered\n"
    return case_from_vulnerability_text(text, repo_root=repo_root)


class TestFailClosed:
    @pytest.mark.parametrize("replacement,expected_fragment", [
        (_bypassing_case_from_cve, "interception count is 0"),        # 12: interception did not occur
        (_double_render_case_from_cve, "more than once"),            # 13: intercepted twice
        (_tampering_case_from_cve, "pipeline input SHA256"),          # 14: wrong hash at pipeline entry
    ])
    def test_aborts_before_pipeline(self, run_traced, tmp_path, monkeypatch, replacement, expected_fragment):
        spy = _PipelineSpy()
        with mock.patch.object(adapters_module, "case_from_cve", side_effect=replacement), \
             mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, out, manifest = _main(run_traced, tmp_path, monkeypatch, MIXED_CVE, ["--blind-evaluation"])
        assert rc == 2
        assert spy.texts == []                       # real pipeline never entered
        assert manifest["llm_call_count"] == 0
        assert manifest["status"] == "failed"
        b = manifest["blind_evaluation"]
        assert b["status"] == "aborted" and expected_fragment in b["error"]
        assert b["pipeline_input_verified"] in (False, None)

    def test_verify_completed_fails_when_nothing_happened(self):
        session = BlindEvaluationSession()
        with session:
            pass
        with pytest.raises(BlindEvaluationError, match="interception count is 0"):
            session.verify_completed(None)

    def test_verify_completed_fails_when_pipeline_guard_bypassed(self, tmp_path):
        session = BlindEvaluationSession()
        with session:
            text = cve_converter_module.cve_to_vuln_text(MIXED_CVE)  # interception happens
        artifact = tmp_path / "v.md"
        artifact.write_text(text)
        with pytest.raises(BlindEvaluationError, match="pipeline.run guard entered 0"):
            session.verify_completed(str(artifact))

    def test_wrappers_restored_after_success(self, run_traced, tmp_path, monkeypatch):
        rc, _, _ = _main(run_traced, tmp_path, monkeypatch, MIXED_CVE, ["--blind-evaluation"])
        assert rc == 0
        assert cve_converter_module.cve_to_vuln_text is REAL_CVE_TO_VULN_TEXT
        assert pipeline_module.run is REAL_PIPELINE_RUN

    def test_wrappers_restored_after_blind_abort(self, run_traced, tmp_path, monkeypatch):
        rc, _, _ = _main(run_traced, tmp_path, monkeypatch,
                         _cve(["https://gitlab.com/acme/widget/-/commit/0123456789abcdef"]),
                         ["--blind-evaluation"])
        assert rc == 2
        assert cve_converter_module.cve_to_vuln_text is REAL_CVE_TO_VULN_TEXT
        assert pipeline_module.run is REAL_PIPELINE_RUN

    def test_wrappers_restored_after_pipeline_failure(self, run_traced, tmp_path, monkeypatch):
        failing = mock.Mock(side_effect=RuntimeError("pipeline exploded"))
        with mock.patch.object(pipeline_module, "run", failing):
            with pytest.raises(RuntimeError, match="pipeline exploded"):
                _main(run_traced, tmp_path, monkeypatch, MIXED_CVE, ["--blind-evaluation"])
            assert pipeline_module.run is failing  # session restored exactly what it found
        assert cve_converter_module.cve_to_vuln_text is REAL_CVE_TO_VULN_TEXT
        manifest = json.loads((tmp_path / "run-out" / "trace" / "run_manifest.json").read_text())
        b = manifest["blind_evaluation"]
        assert manifest["status"] == "failed"
        assert b["status"] == "run_failed" and b["pipeline_input_verified"] is True
        assert "pipeline exploded" in b["run_error"]


# --- 19: benchmark-agnostic implementation ---------------------------------


class TestBenchmarkAgnostic:
    def test_no_benchmark_identifiers_in_implementation(self):
        source = MODULE_PATH.read_text()
        assert not re.search(r"CVE-\d{4}-\d+", source)
        assert not re.search(r"GHSA-[0-9a-z]{4}-", source, re.I)
        assert not re.search(r"\b[0-9a-f]{40}\b", source)
        for name in ("urllib3", "minimist", "gzpan123", "pypa"):
            assert name not in source
        assert not re.search(r"\bpip\b", source)
        for outcome in ("non_blocking", "blocked_or_review", "Deploy After Validation", "Do Not Apply"):
            assert outcome not in source

    def test_no_nvd_tag_based_filtering(self):
        source = MODULE_PATH.read_text()
        assert "tags" not in source and '"Patch"' not in source

    def test_production_modules_do_not_import_blind_evaluation(self):
        root = SCRIPT_PATH.parent.parent
        for rel in ("pipeline.py", "cve_converter.py", "cve_fetcher.py", "investigation_adapters.py"):
            assert "blind_evaluation" not in (root / rel).read_text()
        core_patch = SCRIPT_PATH.parents[3] / "core" / "patch.py"
        assert "blind_evaluation" not in core_patch.read_text()


# --- corrective pass: exact V1 grammar --------------------------------------


class TestExactV1Grammar:
    HEX7 = "0123abc"
    HEX40 = "0123456789abcdef0123456789abcdef01234567"

    @pytest.mark.parametrize("url,category", [
        (f"https://github.com/acme/widget/commit/{HEX7}", DIRECT_REMEDIATION_COMMIT),
        (f"https://github.com/acme/widget/commit/{HEX40}", DIRECT_REMEDIATION_COMMIT),
        (f"https://github.com/my-org/my.repo_name-2/commit/{HEX40}", DIRECT_REMEDIATION_COMMIT),
        ("https://github.com/acme/widget/compare/1.0.0...1.0.1", DIRECT_REMEDIATION_COMPARE),
        ("https://github.com/acme/widget/compare/v1.2...main", DIRECT_REMEDIATION_COMPARE),
        ("https://github.com/acme/widget/compare/main...fork-owner:main", DIRECT_REMEDIATION_COMPARE),
        # exact V1 under owner/repo names that collide with route words
        (f"https://github.com/pull/compare/commit/{HEX7}", DIRECT_REMEDIATION_COMMIT),
    ])
    def test_exact_forms_removable(self, url, category):
        assert classify_reference_url(url).category == category

    @pytest.mark.parametrize("url", [
        # query / fragment / empty query or fragment
        f"https://github.com/acme/widget/commit/{HEX40}?w=1",
        f"https://github.com/acme/widget/commit/{HEX40}?",
        f"https://github.com/acme/widget/commit/{HEX40}#diff-abc",
        f"https://github.com/acme/widget/commit/{HEX40}#",
        "https://github.com/acme/widget/compare/1.0...1.1?expand=1",
        "https://github.com/acme/widget/compare/1.0...1.1#files",
        # suffixes and trailing syntax
        f"https://github.com/acme/widget/commit/{HEX40}.patch",
        f"https://github.com/acme/widget/commit/{HEX40}.diff",
        f"https://github.com/acme/widget/commit/{HEX40}/",
        "https://github.com/acme/widget/compare/1.0...1.1.diff",
        "https://github.com/acme/widget/compare/1.0...1.1.patch",
        "https://github.com/acme/widget/compare/1.0...1.1/",
        # revision grammar
        "https://github.com/acme/widget/commit/0123ab",
        "https://github.com/acme/widget/commit/" + "a" * 41,
        "https://github.com/acme/widget/commit/ABCDEF0123",
        "https://github.com/acme/widget/commit/v1.2.3",
        # route case
        f"https://github.com/acme/widget/COMMIT/{HEX40}",
        "https://github.com/acme/widget/Compare/1.0...1.1",
        # malformed compare ranges
        "https://github.com/acme/widget/compare/1.0..1.1",
        "https://github.com/acme/widget/compare/a....b",
        "https://github.com/acme/widget/compare/a...b...c",
        "https://github.com/acme/widget/compare/...b",
        "https://github.com/acme/widget/compare/a...",
        "https://github.com/acme/widget/compare/.a...b",
        "https://github.com/acme/widget/compare/1..0...2",
        "https://github.com/acme/widget/compare/1.0...2..1",
        "https://github.com/acme/widget/compare/feature/x...main",
        "https://github.com/acme/widget/compare/v1.0",
        # host / scheme variants
        f"http://github.com/acme/widget/commit/{HEX40}",
        f"https://www.github.com/acme/widget/commit/{HEX40}",
        f"https://GitHub.com/acme/widget/commit/{HEX40}",
        f"https://github.com:443/acme/widget/commit/{HEX40}",
        f"https://user@github.com/acme/widget/commit/{HEX40}",
        f"HTTPS://github.com/acme/widget/commit/{HEX40}",
        # malformed owner / repo
        f"https://github.com//widget/commit/{HEX40}",
        f"https://github.com/-acme/widget/commit/{HEX40}",
        f"https://github.com/acme-/widget/commit/{HEX40}",
        f"https://github.com/ac--me/widget/commit/{HEX40}",
        f"https://github.com/acme/../commit/{HEX40}",
        f"https://github.com/acme/w%20x/commit/{HEX40}",
        # other GitHub code-change routes
        "https://github.com/acme/widget/pull/7",
        "https://github.com/acme/widget/pull/7/files",
        "https://github.com/acme/widget/pulls",
        "https://github.com/acme/widget/commits/main",
        f"https://github.com/acme/widget/commit/{HEX40}/extra",
        "https://github.com/acme/widget/blob/main/fix.patch",
    ])
    def test_non_exact_code_change_forms_abort_not_removed(self, url):
        assert classify_reference_url(url).category == UNSUPPORTED_CODE_CHANGE
        text = REAL_CVE_TO_VULN_TEXT(_cve([MAILING_URL, url]))
        with pytest.raises(BlindEvaluationError) as ei:
            blind_vulnerability_text(text)
        assert [u["url"] for u in ei.value.unsupported_references] == [url]

    def test_query_string_commit_url_aborts_end_to_end(self, run_traced, tmp_path, monkeypatch):
        url = f"https://github.com/acme/widget/commit/{self.HEX40}?w=1"
        spy = _PipelineSpy()
        with mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, _, manifest = _main(run_traced, tmp_path, monkeypatch, _cve([url, ISSUE_URL]), ["--blind-evaluation"])
        assert rc == 2 and spy.texts == [] and manifest["llm_call_count"] == 0
        assert [u["url"] for u in manifest["blind_evaluation"]["unsupported_references"]] == [url]
        assert manifest["blind_evaluation"]["removed_count"] == 0


class TestGitHubDetectorAccuracy:
    @pytest.mark.parametrize("url", [
        "https://github.com/diff/widget/issues/1",
        "https://github.com/acme/pull/issues/1",
        "https://github.com/compare/commit/security/advisories/GHSA-aaaa-bbbb-cccc",
        "https://github.com/commit/diff",
        "https://github.com/pull",
        "https://github.com/acme/widget/wiki/diff",
        "https://github.com/acme/widget/blob/main/docs/commit-policy.md",
        "https://github.com/acme/widget/issues/7",
        "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "https://github.com/acme/widget/releases/tag/1.0.1",
    ])
    def test_route_names_in_owner_repo_or_ordinary_routes_are_kept(self, url):
        assert classify_reference_url(url).category == ORDINARY

    def test_owner_named_diff_issue_preserved_end_to_end(self):
        issue = "https://github.com/diff/widget/issues/1"
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(_cve([issue, COMMIT_URL])))
        assert _references_body(r.blinded_text) == [f"- {issue}"]

    def test_non_github_limitation_is_documented_not_claimed(self):
        # V1 deliberately does NOT recognize these families (documented
        # known limitation); this pins the documented behavior so a future
        # extension is an explicit, reviewed change.
        for url in (
            "https://chromium.googlesource.com/chromium/src/+/0123456789abcdef",
            "https://review.opendev.org/c/openstack/nova/+/12345",
            "https://hg.mozilla.org/mozilla-central/rev/0123456789ab",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=0123abc",
        ):
            assert classify_reference_url(url).category == ORDINARY
        doc = MODULE_PATH.read_text()
        tracing = (SCRIPT_PATH.parent / "TRACING_AND_DEBUGGING.md").read_text()
        for text in (doc, tracing):
            assert "Gerrit" in text and "Mercurial" in text and "cgit" in text
        assert "not a universal forge detector" in doc and "not a universal forge detector" in tracing


# --- corrective pass: artifact byte fidelity --------------------------------


class TestArtifactByteFidelity:
    def test_crlf_input_is_verified_end_to_end(self, run_traced, tmp_path, monkeypatch):
        cve = _cve([COMMIT_URL, ISSUE_URL], description="First line.\r\nSecond line with a traversal bug.")
        rc, out, manifest = _main(run_traced, tmp_path, monkeypatch, cve, ["--blind-evaluation"])
        b = manifest["blind_evaluation"]
        assert rc == 0 and b["status"] == "verified"
        assert b["vulnerability_artifact_verified"] is True
        raw = (out / "patch" / f"{CVE_ID}-vulnerability.md").read_bytes()
        assert b"\r\n" in raw
        assert sha256_text(raw.decode("utf-8")) == b["blinded_sha256"] == b["pipeline_input_sha256"]


def _session_through_guard(stub_run):
    """Enter a session over a stubbed pipeline.run, intercept once, pass the
    guard once. Returns (session, blinded_text)."""
    session = BlindEvaluationSession()
    session.__enter__()
    text = cve_converter_module.cve_to_vuln_text(MIXED_CVE)
    pipeline_module.run(vulnerability_text=text)
    return session, text


class TestGuardGaps:
    def test_second_pipeline_entry_rejected_and_not_delegated(self):
        stub = mock.Mock(return_value="report")
        with mock.patch.object(pipeline_module, "run", stub):
            session, text = _session_through_guard(stub)
            try:
                with pytest.raises(BlindEvaluationError, match="entered more than once"):
                    pipeline_module.run(vulnerability_text=text)
            finally:
                session.__exit__(None, None, None)
            assert stub.call_count == 1
            assert pipeline_module.run is stub

    def test_mismatched_artifact_fails_verification(self, tmp_path):
        stub = mock.Mock(return_value="report")
        with mock.patch.object(pipeline_module, "run", stub):
            session, text = _session_through_guard(stub)
            session.__exit__(None, None, None)
        good = tmp_path / "good.md"
        good.write_bytes(text.encode("utf-8"))
        bad = tmp_path / "bad.md"
        bad.write_bytes((text + "x").encode("utf-8"))
        with pytest.raises(BlindEvaluationError, match="vulnerability artifact does not match"):
            session.verify_completed(str(bad))
        assert session.vulnerability_artifact_verified is False
        assert session.status() == "aborted"

    def test_matching_crlf_artifact_passes_verification(self, tmp_path):
        stub = mock.Mock(return_value="report")
        crlf_cve = _cve([COMMIT_URL], description="a.\r\nb.")
        with mock.patch.object(pipeline_module, "run", stub):
            session = BlindEvaluationSession()
            with session:
                text = cve_converter_module.cve_to_vuln_text(crlf_cve)
                pipeline_module.run(vulnerability_text=text)
        artifact = tmp_path / "v.md"
        artifact.write_bytes(text.encode("utf-8"))
        assert "\r\n" in text
        session.verify_completed(str(artifact))
        assert session.status() == "verified"

    def test_keyboard_interrupt_restores_wrappers(self):
        with pytest.raises(KeyboardInterrupt):
            with BlindEvaluationSession():
                assert cve_converter_module.cve_to_vuln_text is not REAL_CVE_TO_VULN_TEXT
                raise KeyboardInterrupt
        assert cve_converter_module.cve_to_vuln_text is REAL_CVE_TO_VULN_TEXT
        assert pipeline_module.run is REAL_PIPELINE_RUN

    def test_keyboard_interrupt_during_run_restores_wrappers(self, run_traced, tmp_path, monkeypatch):
        interrupting = mock.Mock(side_effect=KeyboardInterrupt)
        with mock.patch.object(pipeline_module, "run", interrupting):
            with pytest.raises(KeyboardInterrupt):
                _main(run_traced, tmp_path, monkeypatch, MIXED_CVE, ["--blind-evaluation"])
            assert pipeline_module.run is interrupting
            assert interrupting.call_count == 1
        assert cve_converter_module.cve_to_vuln_text is REAL_CVE_TO_VULN_TEXT


# --- corrective pass: output path containment -------------------------------


class TestOutputPathContainment:
    @pytest.fixture
    def layout(self, tmp_path):
        repo = tmp_path / "realrepo"
        (repo / "sub").mkdir(parents=True)
        (tmp_path / "outside").mkdir()
        (tmp_path / "repolink").symlink_to(repo)
        (tmp_path / "linkintorepo").symlink_to(repo / "sub")
        return tmp_path, repo

    def test_inside_cases_rejected(self, layout):
        base, repo = layout
        for planned, root in (
            (repo, repo),
            (repo / "out", repo),
            (repo / "a" / "b" / "c", repo),
            (base / "outside" / ".." / "realrepo" / "out", repo),
            (base / "linkintorepo" / "out", repo),
            (base / "linkintorepo" / "x" / "y", repo),
            (repo / "out", base / "repolink"),
            (base / "repolink" / "out", repo),
        ):
            assert path_resolves_inside(planned, root), (planned, root)

    def test_outside_cases_allowed(self, layout):
        base, repo = layout
        for planned in (base / "outside" / "out", repo.parent / "realrepo2" / "out",
                        repo / "sub" / ".." / ".." / "outside" / "out"):
            assert not path_resolves_inside(planned, repo), planned

    def test_nonexistent_repo_root_still_contains_children_lexically(self, tmp_path):
        missing = tmp_path / "not-yet-cloned"
        assert path_resolves_inside(missing / "out", missing)
        assert not path_resolves_inside(tmp_path / "elsewhere", missing)

    def test_case_variant_alias_rejected_when_filesystem_is_case_insensitive(self, layout):
        base, repo = layout
        variant = base / "REALREPO"
        if not variant.exists():
            pytest.skip("filesystem is case-sensitive; case-variant alias cannot exist")
        assert not (base / "REALREPO" / "out").resolve().is_relative_to(repo.resolve())  # lexical check alone misses it
        assert path_resolves_inside(variant / "out", repo)

    def test_macos_data_volume_alias_rejected_when_present(self, layout):
        _, repo = layout
        alias = Path("/System/Volumes/Data" + str(repo.resolve()))
        if not alias.exists() or not os.path.samefile(alias, repo):
            pytest.skip("no /System/Volumes/Data alias on this platform")
        assert path_resolves_inside(alias / "out", repo)

    def test_run_traced_rejects_symlinked_output_into_repo(self, run_traced, layout):
        base, repo = layout
        argv = ["--cve", CVE_ID, "--repo-root", str(repo), "--output", str(base / "linkintorepo" / "out"),
                "--blind-evaluation"]
        with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve") as m_fetch:
            assert run_traced.main(argv) == 2
        m_fetch.assert_not_called()
        assert not (repo / "sub" / "out").exists()

    def test_containment_check_is_blind_only(self, run_traced, tmp_path, monkeypatch):
        # Without --blind-evaluation an output inside the repo keeps the
        # previous (unchecked) run_traced semantics.
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo = tmp_path / "repo"
        repo.mkdir()
        with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=ORDINARY_CVE):
            rc = run_traced.main(["--cve", CVE_ID, "--repo-root", str(repo), "--output", str(repo / "out"), "--quiet"])
        assert rc == 0
