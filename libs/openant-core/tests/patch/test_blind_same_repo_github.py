"""Tests for the opt-in same-repository GitHub reference policy of blind
evaluation (run_traced.py --blind-evaluation
--blind-strip-same-repo-github-references).

Hermetic: LLM_PROVIDER=mock, fetch_cve mocked, no network. Target identity
comes from a throwaway local git repository's `origin` remote (never
contacted). Generic placeholder repositories only.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from unittest import mock

import pytest

import utilities.autopatcher.pipeline as pipeline_module
from utilities.autopatcher.cve_converter import cve_to_vuln_text as REAL_CVE_TO_VULN_TEXT
from utilities.autopatcher.tools.blind_evaluation import (
    RULE_ID,
    SAME_REPO_GITHUB_POLICY_ID,
    BlindEvaluationError,
    blind_vulnerability_text,
    github_repository_identity,
    sha256_text,
)

from tests.patch.test_blind_evaluation import (  # noqa: F401 -- fixtures/helpers reused as-is
    ADVISORY_URL,
    COMMIT_URL,
    COMPARE_URL,
    CVE_ID,
    ISSUE_URL,
    MAILING_URL,
    MIXED_CVE,
    ORDINARY_CVE,
    PIP_FIXTURE,
    PIP_ORIGINAL_SHA,
    URLLIB3_BLIND_SHA,
    URLLIB3_FIXTURE,
    URLLIB3_ORIGINAL_SHA,
    _PipelineSpy,
    _assert_globals_restored,
    _cve,
    _main,
    SCRIPT_PATH,
    _references_body,
)

FLAG = "--blind-strip-same-repo-github-references"


@pytest.fixture(scope="module")
def run_traced():
    spec = importlib.util.spec_from_file_location("run_traced_same_repo_tests", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

TARGET_REMOTE = "https://github.com/acme/widget.git"
TARGET = github_repository_identity(TARGET_REMOTE)

PULL_URL = "https://github.com/acme/widget/pull/7"
OTHER_PATH_URL = "https://github.com/acme/widget/releases/tag/v1.0.1"
OTHER_REPO_PULL = "https://github.com/other/widget/pull/7"
OTHER_REPO_ISSUE = "https://github.com/other/widget/issues/3"
PREFIX_REPO_PULL = "https://github.com/acme/widget-other/pull/7"
PREFIX_REPO_ISSUE = "https://github.com/acme/widget-other/issues/3"
GITLAB_MR = "https://gitlab.com/acme/widget/-/merge_requests/9"

# The motivating shape, generically: one ordinary external reference plus
# one same-repository GitHub pull reference.
MOTIVATING_CVE = _cve([MAILING_URL, PULL_URL])


def _render(refs, description=None):
    return REAL_CVE_TO_VULN_TEXT(_cve(refs) if description is None else _cve(refs, description))


def _blind(refs, target=TARGET, description=None):
    return blind_vulnerability_text(_render(refs, description), same_repo_github=target)


# --- repository identity ----------------------------------------------------


class TestRepositoryIdentity:
    @pytest.mark.parametrize("remote", [
        "https://github.com/acme/widget.git",
        "https://github.com/acme/widget",
        "https://github.com/acme/widget/",
        "https://github.com/acme/widget.git/",
        "http://github.com/acme/widget.git",
        "https://user@github.com/acme/widget.git",
        "https://www.github.com/acme/widget.git",
        "https://GitHub.com/Acme/Widget.git",
        "git@github.com:acme/widget.git",
        "git@github.com:acme/widget",
        "ssh://git@github.com/acme/widget.git",
        "ssh://git@github.com:22/acme/widget.git",
        "  https://github.com/acme/widget.git\n",
    ])
    def test_10_target_forms_normalize_to_one_identity(self, remote):
        assert github_repository_identity(remote) == TARGET
        assert TARGET.slug == "github.com/acme/widget"

    @pytest.mark.parametrize("remote", [
        "", "not a url", "https://gitlab.com/acme/widget.git", "https://github.com/acme",
        "https://github.com/acme/widget/tree/main", "https://github.com/acme/widget.git.git",
        "git://github.com/acme/widget.git", "file:///srv/acme/widget.git", "/srv/acme/widget",
        "https://github.com.evil.example/acme/widget.git", "https://github.com/acme/./",
    ])
    def test_non_github_or_non_repository_remotes_have_no_identity(self, remote):
        assert github_repository_identity(remote) is None


# --- the pure filter ---------------------------------------------------------


class TestDefaultModeUnchanged:
    def test_1_absent_policy_is_exactly_v1(self):
        original = REAL_CVE_TO_VULN_TEXT(MIXED_CVE)
        assert blind_vulnerability_text(original) == blind_vulnerability_text(original, same_repo_github=None)

    def test_1b_same_repo_pull_still_aborts_without_policy(self):
        with pytest.raises(BlindEvaluationError) as exc:
            blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(MOTIVATING_CVE))
        assert [u["url"] for u in exc.value.unsupported_references] == [PULL_URL]

    def test_16_existing_fixtures_and_hashes_unchanged(self):
        u = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(URLLIB3_FIXTURE))
        assert (u.original_sha256, u.blinded_sha256) == (URLLIB3_ORIGINAL_SHA, URLLIB3_BLIND_SHA)
        assert u.removed_same_repo_github == () and u.removed_by_v1 == u.removed_references
        p = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(PIP_FIXTURE))
        assert p.original_sha256 == PIP_ORIGINAL_SHA
        assert p.removed_same_repo_github == () and p.same_repo_github_target is None


class TestSameRepositoryPolicy:
    def test_motivating_shape_keeps_external_removes_same_repo_pull(self):
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(MOTIVATING_CVE), same_repo_github=TARGET)
        assert _references_body(r.blinded_text) == [f"- {MAILING_URL}"]
        assert r.removed_same_repo_github == (PULL_URL,) and r.removed_by_v1 == ()

    @pytest.mark.parametrize("url", [
        PULL_URL,                                                           # 3
        ISSUE_URL,                                                          # 4
        OTHER_PATH_URL,                                                     # 7
        ADVISORY_URL,                                                       # 7
        "https://github.com/acme/widget/discussions/5",                     # 7
        "https://github.com/acme/widget/blob/main/src/x.py",                # 7
        "https://github.com/acme/widget/pull/7/files",                      # 7 (unsupported under V1)
        "https://github.com/acme/widget/commits/main",                      # 7 (unsupported under V1)
        "https://github.com/acme/widget",                                   # 7 the repository itself
        "https://www.github.com/acme/widget/pull/7",                        # host variant
        "https://github.com/Acme/Widget/pull/7",                            # GitHub names are case-insensitive
    ])
    def test_3_4_7_same_repository_references_removed(self, url):
        r = _blind([MAILING_URL, url])
        assert r.removed_same_repo_github == (url,) and r.removed_by_v1 == ()
        assert _references_body(r.blinded_text) == [f"- {MAILING_URL}"]

    @pytest.mark.parametrize("url", [COMMIT_URL, COMPARE_URL])
    def test_5_6_13_v1_removal_counted_once_under_v1_only(self, url):
        r = _blind([MAILING_URL, url])
        assert r.removed_by_v1 == (url,)
        assert r.removed_same_repo_github == ()
        assert r.removed_references == (url,) and len(r.removed_reference_lines) == 1
        assert _references_body(r.blinded_text) == [f"- {MAILING_URL}"]

    def test_8_other_repository_references_not_removed_by_policy(self):
        r = _blind([MAILING_URL, OTHER_REPO_ISSUE])
        assert r.removed_references == () and r.blinded_text == r.original_text
        with pytest.raises(BlindEvaluationError) as exc:
            _blind([MAILING_URL, OTHER_REPO_PULL])
        assert [u["url"] for u in exc.value.unsupported_references] == [OTHER_REPO_PULL]

    def test_8b_other_repository_v1_commit_still_removed_by_v1(self):
        fork_commit = COMMIT_URL.replace("/acme/", "/forker/")
        r = _blind([MAILING_URL, fork_commit])
        assert r.removed_by_v1 == (fork_commit,) and r.removed_same_repo_github == ()

    def test_9_similar_prefix_is_a_different_repository(self):
        r = _blind([MAILING_URL, PREFIX_REPO_ISSUE])
        assert r.removed_references == ()
        with pytest.raises(BlindEvaluationError):
            _blind([MAILING_URL, PREFIX_REPO_PULL])
        r = _blind([MAILING_URL, "https://github.com/acme-x/widget/issues/3"])
        assert r.removed_references == ()

    def test_11_non_github_reference_unchanged(self):
        r = _blind([MAILING_URL, "https://mirror.example.org/acme/widget/issues/7"])
        assert r.removed_references == () and r.blinded_text == r.original_text

    def test_11b_non_http_scheme_same_repository_not_matched(self):
        assert github_repository_identity("ssh://git@github.com/acme/widget.git") == TARGET
        r = _blind([MAILING_URL, "ftp://github.com/acme/widget/issues/1"])
        assert r.removed_references == ()

    def test_12_unsupported_external_reference_keeps_failing_closed(self):
        with pytest.raises(BlindEvaluationError) as exc:
            _blind([MAILING_URL, PULL_URL, GITLAB_MR])
        assert [u["url"] for u in exc.value.unsupported_references] == [GITLAB_MR]

    def test_same_repo_url_outside_references_is_never_removed(self):
        description = f"See {ISSUE_URL} for discussion."
        r = _blind([MAILING_URL, PULL_URL], description=description)
        assert ISSUE_URL in r.blinded_text and r.removed_same_repo_github == (PULL_URL,)
        with pytest.raises(BlindEvaluationError):
            _blind([MAILING_URL], description=f"Fixed in {PULL_URL} upstream.")

    def test_14_hashes_correspond_to_exact_bytes(self):
        original = _render([MAILING_URL, COMMIT_URL, PULL_URL, ISSUE_URL])
        r = blind_vulnerability_text(original, same_repo_github=TARGET)
        assert r.original_sha256 == sha256_text(original)
        expected = "".join(
            line for line in original.splitlines(keepends=True)
            if line.rstrip("\n") not in (f"- {COMMIT_URL}", f"- {PULL_URL}", f"- {ISSUE_URL}")
        )
        assert r.blinded_text == expected and r.blinded_sha256 == sha256_text(expected)

    def test_15_result_distinguishes_v1_and_same_repo_removals(self):
        r = _blind([MAILING_URL, COMMIT_URL, PULL_URL, COMPARE_URL, ISSUE_URL])
        assert r.removed_by_v1 == (COMMIT_URL, COMPARE_URL)
        assert r.removed_same_repo_github == (PULL_URL, ISSUE_URL)
        assert r.removed_references == (COMMIT_URL, PULL_URL, COMPARE_URL, ISSUE_URL)  # document order
        assert r.same_repo_github_target == TARGET


# --- run_traced CLI ----------------------------------------------------------


def _git_repo(path, remote=TARGET_REMOTE):
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    if remote is not None:
        subprocess.run(["git", "remote", "add", "origin", remote], cwd=path, check=True)
    return path


def _run(run_traced, tmp_path, monkeypatch, cve, extra_args, remote=TARGET_REMOTE):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo = _git_repo(tmp_path / "repo", remote)
    out = tmp_path / "out"
    argv = ["--cve", CVE_ID, "--repo-root", str(repo), "--output", str(out), "--quiet", *extra_args]
    with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve) as m_fetch:
        rc = run_traced.main(argv)
    manifest_path = out / "trace" / "run_manifest.json"
    return rc, out, (json.loads(manifest_path.read_text()) if manifest_path.exists() else None), m_fetch


class TestRunTracedFlag:
    def test_flag_defaults_off(self, run_traced):
        args = run_traced.build_parser().parse_args(["--cve", "X", "--repo-root", "/r", "--blind-evaluation"])
        assert args.blind_strip_same_repo_github_references is False

    def test_2_rejected_without_blind_evaluation(self, run_traced, tmp_path, monkeypatch, capsys):
        rc, out, manifest, m_fetch = _run(run_traced, tmp_path, monkeypatch, MOTIVATING_CVE, [FLAG])
        assert rc == 2 and manifest is None
        m_fetch.assert_not_called()
        assert f"{FLAG} requires --blind-evaluation" in capsys.readouterr().err

    @pytest.mark.parametrize("remote", [None, "https://gitlab.com/acme/widget.git"])
    def test_rejected_when_target_identity_unresolvable(self, run_traced, tmp_path, monkeypatch, capsys, remote):
        rc, out, manifest, m_fetch = _run(
            run_traced, tmp_path, monkeypatch, MOTIVATING_CVE, ["--blind-evaluation", FLAG], remote=remote,
        )
        assert rc == 2 and manifest is None
        m_fetch.assert_not_called()
        assert "GitHub repository" in capsys.readouterr().err

    def test_1_16_default_blind_manifest_has_no_new_keys(self, run_traced, tmp_path, monkeypatch):
        rc, out, manifest = _main(run_traced, tmp_path, monkeypatch, MIXED_CVE, ["--blind-evaluation"])
        b = manifest["blind_evaluation"]
        assert rc == 0 and b["status"] == "verified" and b["rule_id"] == RULE_ID
        for key in ("removed_by_v1", "removed_same_repo_github", "same_repo_github_policy"):
            assert key not in b

    def test_end_to_end_motivating_shape(self, run_traced, tmp_path, monkeypatch):
        spy = _PipelineSpy()
        with mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, out, manifest, _ = _run(
                run_traced, tmp_path, monkeypatch, _cve([MAILING_URL, COMMIT_URL, PULL_URL]),
                ["--blind-evaluation", FLAG],
            )
        assert rc == 0 and manifest["status"] == "success"
        original = _render([MAILING_URL, COMMIT_URL, PULL_URL])
        expected = blind_vulnerability_text(original, same_repo_github=TARGET)
        assert spy.texts == [expected.blinded_text]
        assert _references_body(expected.blinded_text) == [f"- {MAILING_URL}"]

        b = manifest["blind_evaluation"]
        assert b["status"] == "verified" and b["rule_id"] == RULE_ID
        assert b["original_sha256"] == sha256_text(original)
        assert b["blinded_sha256"] == sha256_text(expected.blinded_text) == b["pipeline_input_sha256"]
        assert b["removed_references"] == [COMMIT_URL, PULL_URL] and b["removed_count"] == 2
        assert b["removed_by_v1"] == [COMMIT_URL]
        assert b["removed_same_repo_github"] == [PULL_URL]
        assert b["same_repo_github_policy"] == {
            "enabled": True,
            "policy_id": SAME_REPO_GITHUB_POLICY_ID,
            "target_repository": "github.com/acme/widget",
            "target_source": "origin remote of --repo-root",
            "target_remote_url": TARGET_REMOTE,
        }
        sidecar = out / "trace" / "blind_evaluation"
        assert json.loads((sidecar / "blind_evaluation.json").read_text())["removed_same_repo_github"] == [PULL_URL]
        assert (sidecar / "removed_reference_lines.txt").read_text() == f"- {COMMIT_URL}\n- {PULL_URL}\n"

    def test_extended_mode_unsupported_external_still_aborts(self, run_traced, tmp_path, monkeypatch):
        rc, out, manifest, _ = _run(
            run_traced, tmp_path, monkeypatch, _cve([PULL_URL, GITLAB_MR]), ["--blind-evaluation", FLAG],
        )
        assert rc == 2
        b = manifest["blind_evaluation"]
        assert b["status"] == "aborted"
        assert [u["url"] for u in b["unsupported_references"]] == [GITLAB_MR]
        assert b["same_repo_github_policy"]["target_repository"] == "github.com/acme/widget"
        assert b["removed_by_v1"] == [] and b["removed_same_repo_github"] == []


# --- remote userinfo never exposed --------------------------------------------

USERINFO_REMOTE = "https://someuser:s3cr3t-value@github.com/acme/widget.git"
SANITIZED_REMOTE = "https://github.com/acme/widget.git"


def _assert_no_userinfo(text: str) -> None:
    assert "someuser" not in text and "s3cr3t-value" not in text
    assert "@github.com" not in text and "@gitlab.com" not in text  # no userinfo of any value


class TestRemoteUserinfoRedaction:
    @pytest.mark.parametrize("raw, exposed", [
        (USERINFO_REMOTE, SANITIZED_REMOTE),
        ("https://token@github.com:8443/acme/widget.git", "https://github.com:8443/acme/widget.git"),
        ("ssh://git:pw@github.com/acme/widget.git", "ssh://github.com/acme/widget.git"),
        ("git@github.com:acme/widget.git", "github.com:acme/widget.git"),
        (SANITIZED_REMOTE, SANITIZED_REMOTE),
    ])
    def test_sanitized_form(self, raw, exposed):
        from utilities.autopatcher.tools.blind_evaluation import sanitize_remote_url
        assert sanitize_remote_url(raw) == exposed
        # identity (matching) is unaffected by sanitization
        assert github_repository_identity(raw) == github_repository_identity(exposed) == TARGET

    def test_manifest_and_sidecar_expose_only_sanitized_remote(self, run_traced, tmp_path, monkeypatch, capsys):
        rc, out, manifest, _ = _run(
            run_traced, tmp_path, monkeypatch, MOTIVATING_CVE, ["--blind-evaluation", FLAG], remote=USERINFO_REMOTE,
        )
        assert rc == 0
        policy = manifest["blind_evaluation"]["same_repo_github_policy"]
        assert policy["target_remote_url"] == SANITIZED_REMOTE
        assert policy["target_repository"] == "github.com/acme/widget"
        assert manifest["blind_evaluation"]["removed_same_repo_github"] == [PULL_URL]
        _assert_no_userinfo((out / "trace" / "run_manifest.json").read_text())
        sidecar = out / "trace" / "blind_evaluation"
        side = json.loads((sidecar / "blind_evaluation.json").read_text())
        assert side["same_repo_github_policy"]["target_remote_url"] == SANITIZED_REMOTE
        for f in sidecar.iterdir():
            _assert_no_userinfo(f.read_text())
        captured = capsys.readouterr()
        _assert_no_userinfo(captured.out + captured.err)

    def test_diagnostic_exposes_only_sanitized_remote(self, run_traced, tmp_path, monkeypatch, capsys):
        rc, out, manifest, m_fetch = _run(
            run_traced, tmp_path, monkeypatch, MOTIVATING_CVE, ["--blind-evaluation", FLAG],
            remote="https://someuser:s3cr3t-value@gitlab.com/acme/widget.git",
        )
        assert rc == 2 and manifest is None
        m_fetch.assert_not_called()
        err = capsys.readouterr().err
        assert "'https://gitlab.com/acme/widget.git'" in err
        _assert_no_userinfo(err)

    def test_session_sanitizes_even_if_given_raw_remote(self):
        from utilities.autopatcher.tools.blind_evaluation import BlindEvaluationSession
        session = BlindEvaluationSession(same_repo_github=TARGET, same_repo_github_remote=USERINFO_REMOTE)
        d = session.to_manifest_dict()
        assert d["same_repo_github_policy"]["target_remote_url"] == SANITIZED_REMOTE
        _assert_no_userinfo(json.dumps(d))


# --- --repo-root must itself be the git top level ------------------------------


def _run_at(run_traced, tmp_path, monkeypatch, repo_root, cve=MOTIVATING_CVE):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    out = tmp_path / "out"
    argv = ["--cve", CVE_ID, "--repo-root", str(repo_root), "--output", str(out), "--quiet",
            "--blind-evaluation", FLAG]
    with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve) as m_fetch:
        rc = run_traced.main(argv)
    manifest_path = out / "trace" / "run_manifest.json"
    return rc, (json.loads(manifest_path.read_text()) if manifest_path.exists() else None), m_fetch


class TestExactRepositoryRoot:
    def test_1_repository_root_accepted(self, run_traced, tmp_path, monkeypatch):
        repo = _git_repo(tmp_path / "repo")
        rc, manifest, _ = _run_at(run_traced, tmp_path, monkeypatch, repo)
        assert rc == 0
        assert manifest["blind_evaluation"]["same_repo_github_policy"]["target_repository"] == "github.com/acme/widget"

    def test_2_subdirectory_of_repository_rejected(self, run_traced, tmp_path, monkeypatch, capsys):
        repo = _git_repo(tmp_path / "repo")
        (repo / "pkg").mkdir()
        rc, manifest, m_fetch = _run_at(run_traced, tmp_path, monkeypatch, repo / "pkg")
        assert rc == 2 and manifest is None
        m_fetch.assert_not_called()
        assert "top-level directory of the target git repository" in capsys.readouterr().err

    def test_3_plain_directory_nested_in_another_repository_rejected(self, run_traced, tmp_path, monkeypatch, capsys):
        outer = _git_repo(tmp_path / "outer", remote="https://github.com/other/enclosing.git")
        plain = outer / "vendor" / "checkout"
        plain.mkdir(parents=True)
        rc, manifest, m_fetch = _run_at(run_traced, tmp_path, monkeypatch, plain)
        assert rc == 2 and manifest is None
        m_fetch.assert_not_called()
        err = capsys.readouterr().err
        assert "top-level directory" in err and "enclosing" not in err  # identity never inherited

    def test_4_directory_outside_any_repository_rejected(self, run_traced, tmp_path, monkeypatch, capsys):
        plain = tmp_path / "plain"
        plain.mkdir()
        rc, manifest, m_fetch = _run_at(run_traced, tmp_path, monkeypatch, plain)
        assert rc == 2 and manifest is None
        m_fetch.assert_not_called()
        assert "top-level directory" in capsys.readouterr().err

    def test_5_normalized_equivalent_path_accepted(self, run_traced, tmp_path, monkeypatch):
        repo = _git_repo(tmp_path / "repo")
        (repo / "pkg").mkdir()
        rc, manifest, _ = _run_at(run_traced, tmp_path, monkeypatch, f"{repo}/pkg/..")
        assert rc == 0
        assert manifest["blind_evaluation"]["same_repo_github_policy"]["target_remote_url"] == TARGET_REMOTE
