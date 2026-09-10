"""#568: the summary channel never carries a raw remote.

``_compact_for_summary`` builds the data embedded verbatim into the summary
LLM prompt (report/generator.py) and transcribed into SUMMARY_REPORT.md. An
old ``pipeline_output.json`` — or a server job scanned with a raw
``--repo-url`` — can carry a credential-bearing or scp-form
``repository.url``. The compacted copy must drop the ``url`` key when it is
not a clean http(s) browse URL (the honest absence); the name and language
stay.
"""

import json

from report.generator import _compact_for_summary


def _pipeline(url: str) -> dict:
    return {
        "repository": {
            "name": "org/repo",
            "url": url,
            "language": "go",
            "commit_sha": "abc",
        },
        "findings": [
            {
                "id": "F1",
                "name": "demo",
                "short_name": "d",
                "location": "f.go:1",
                "cwe_id": "CWE-79",
            }
        ],
    }


def _compacted_blob(url: str) -> str:
    return json.dumps(_compact_for_summary(_pipeline(url)))


def test_credential_url_dropped_from_summary_data():
    blob = _compacted_blob("https://user:TOKEN@github.com/org/repo")
    assert "TOKEN" not in blob
    assert "user:" not in blob


def test_password_scp_url_dropped_from_summary_data():
    blob = _compacted_blob("user:pass@host:path")
    assert "pass" not in blob


def test_scp_url_dropped_from_summary_data():
    blob = _compacted_blob("git@github.com:org/repo.git")
    assert "git@" not in blob


def test_clean_url_kept_verbatim():
    blob = _compacted_blob("https://github.com/org/repo")
    assert "https://github.com/org/repo" in blob


def test_name_and_language_preserved_when_url_dropped():
    compact = _compact_for_summary(_pipeline("git@github.com:org/repo.git"))
    repo = compact["repository"]
    assert repo["name"] == "org/repo"
    assert repo["language"] == "go"


def test_caller_pipeline_data_never_mutated():
    pipeline = _pipeline("git@github.com:org/repo.git")
    _compact_for_summary(pipeline)
    # the shallow copy aliases nested objects — the caller's dict must
    # keep its own repository.url untouched.
    assert pipeline["repository"]["url"] == "git@github.com:org/repo.git"


def test_non_string_url_dropped_without_crash():
    pipeline = _pipeline("https://github.com/org/repo")
    pipeline["repository"]["url"] = 12345  # legacy/hand-edited garbage
    compact = _compact_for_summary(pipeline)
    assert "url" not in compact["repository"]


def test_query_string_secret_dropped():
    blob = _compacted_blob("https://github.com/org/repo?token=SECRET")
    assert "SECRET" not in blob
    assert "token=" not in blob


def test_fragment_dropped():
    blob = _compacted_blob("https://github.com/org/repo#anchor")
    assert "#anchor" not in blob


def test_non_dict_repository_becomes_absent():
    pipeline = _pipeline("https://github.com/org/repo")
    pipeline["repository"] = "git@name:pass@host:x"  # hand-edited garbage
    compact = _compact_for_summary(pipeline)
    assert compact["repository"] == {}
