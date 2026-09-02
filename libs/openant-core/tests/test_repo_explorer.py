"""The exploration tools hand a model read access. Confinement is the contract.

Request 2 asks for an agent that "goes over the repo". Giving a model file-read
tools over an UNTRUSTED repository is the only way to do that honestly, and also
the point at which a path argument becomes an injection sink. These tests are the
negative controls for that trade.
"""

from __future__ import annotations

import os

import pytest

from context.repo_explorer import (
    MAX_FILE_BYTES,
    ExplorationBudget,
    RepoExplorer,
)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    (r / "src").mkdir(parents=True)
    (r / "src" / "app.py").write_text("def handler(req):\n    return req\n")
    (r / "README.md").write_text("# demo\n")
    (tmp_path / "secret.txt").write_text("HOST SECRET")
    return r


def _ex(repo):
    return RepoExplorer(repo, ExplorationBudget())


@pytest.mark.parametrize("hostile", [
    "../secret.txt",
    "../../etc/passwd",
    "/etc/passwd",
    "src/../../secret.txt",
    "./../secret.txt",
])
def test_read_file_refuses_to_escape_the_repository(repo, hostile):
    """Path traversal in a tool argument is the model-facing injection sink.

    The repo's own prose is attacker-influenceable and unfenced (a documented,
    accepted gap), so an attacker has a channel to steer the model's tool
    arguments. Confinement cannot depend on the model behaving.
    """
    out = _ex(repo).execute("read_file", {"path": hostile})
    assert "error" in out, f"{hostile!r} was not refused: {out}"
    assert "HOST SECRET" not in str(out)


# "/" is not in this list: lstrip("/") maps it to the repo root, which is
# confinement working, not an escape. "/etc" becomes repo/etc and 404s.
@pytest.mark.parametrize("hostile", ["..", "../..", "/etc"])
def test_list_dir_refuses_to_escape_the_repository(repo, hostile):
    out = _ex(repo).execute("list_dir", {"path": hostile})
    assert "error" in out, f"{hostile!r} was not refused: {out}"


def test_symlinks_are_not_offered_to_the_model(repo, tmp_path):
    """Listing a symlink invites the model to read through it.

    Refusing at read time alone is not enough: a directory listing that advertises
    `escape -> /` is an instruction to try, and each attempt costs a turn.
    """
    os.symlink(tmp_path / "secret.txt", repo / "escape.txt")
    out = _ex(repo).execute("list_dir", {"path": ""})
    assert not any("escape.txt" in e for e in out["entries"])


def test_search_does_not_follow_symlinked_directories(repo, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.py").write_text("SECRET = 1\n")
    os.symlink(outside, repo / "vendor")
    out = _ex(repo).execute("search", {"name_glob": "*.py"})
    assert not any("leak" in h for h in out["hits"])


def test_reads_are_bounded_and_report_truncation(repo):
    big = "x" * (MAX_FILE_BYTES + 5_000)
    (repo / "src" / "big.py").write_text(big)
    out = _ex(repo).execute("read_file", {"path": "src/big.py"})
    assert len(out["content"]) <= MAX_FILE_BYTES
    assert out["truncated"] is True, "truncation must be visible, not silent"


def test_budget_records_what_was_actually_read(repo):
    budget = ExplorationBudget()
    ex = RepoExplorer(repo, budget)
    ex.execute("read_file", {"path": "src/app.py"})
    assert "src/app.py" in budget.files_read
    assert budget.bytes_read > 0
    assert budget.as_dict()["files_read"] == ["src/app.py"]


def test_a_normal_read_still_works(repo):
    """Negative control for the negative controls.

    Confinement that refuses everything would pass every test above while making
    the feature useless — the failure mode of a guard written only against attacks.
    """
    out = _ex(repo).execute("read_file", {"path": "src/app.py"})
    assert "def handler" in out["content"]
    listing = _ex(repo).execute("list_dir", {"path": ""})
    assert any("src" in e for e in listing["entries"])


def test_unknown_tool_is_reported_not_raised(repo):
    assert "error" in _ex(repo).execute("nope", {})
