"""Regression tests for issue #217 — oversized docs degrade the context
silently.

The context phase called ``read_repo_file(max_bytes=10_000)`` WITHOUT
``oversize="truncate"`` — the default ``"raise"`` made every doc above
10 KB raise → caught → warned → SKIPPED, while the truncation handler
three lines down (append ``[... truncated ...]``) was dead code the
author clearly intended. On the reporter's target BOTH top-level docs
(README ~3x the limit) were dropped and the context reported high
confidence from manifests alone — degradation invisible in artifacts.

Contract locked here:
- docs above the ceiling are READ as a bounded prefix with the truncation
  marker (the intended semantics; the guard itself stays — repo content
  is attacker-controlled, the read stays syscall-bounded);
- unreadable (skipped) docs are listed in a ``[skipped_sources]`` entry
  inside ``sources`` so the context generator — and the artifact — see
  the gap (the LLM prices it into confidence via its existing
  "based on how much information was available" instruction; NO
  post-hoc arithmetic on the model's number);
- truncated docs are listed in ``[truncated_sources]``;
- no new configuration: the 10_000 ceiling stays hard-coded.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from context.application_context import gather_context_sources  # noqa: E402


def _doc_repo(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Big doc\n" + ("x" * 20_000), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='t'\n", encoding="utf-8")
    return tmp_path


def test_oversize_doc_is_truncated_not_skipped(tmp_path: Path):
    """A README above the 10 KB ceiling is READ (bounded prefix + marker),
    never dropped — the issue's both-docs-dropped symptom. The prefix is
    pinned to exactly 10 000 chars + marker (not just 'some prefix')."""
    sources = gather_context_sources(_doc_repo(tmp_path))
    readme = sources.get("README.md")
    assert readme is not None, "oversize README must not be skipped"
    assert "[... truncated ...]" in readme
    assert len(readme) == 10_000 + len("\n\n[... truncated ...]")


def test_truncated_sources_listed_in_artifact_inputs(tmp_path: Path):
    sources = gather_context_sources(_doc_repo(tmp_path))
    entry = sources.get("[truncated_sources]")
    assert isinstance(entry, str) and "README.md" in entry, (
        f"entry must be a STRING (the sources dict is dict[str, str]; a list "
        f"crashes both prompt builders — 4-seat wave catch). Got {entry!r}"
    )


def test_skipped_unreadable_docs_listed(tmp_path, monkeypatch):
    """An unreadable doc (guard raises for another reason) is listed in
    [skipped_sources] so the gap is visible to the generator + artifact."""
    import context.application_context as ac

    real = ac.read_repo_file
    def _flaky(path, **kw):
        if str(path).endswith("README.md"):
            raise PermissionError("nope")
        return real(path, **kw)
    monkeypatch.setattr(ac, "read_repo_file", _flaky)
    sources = gather_context_sources(_doc_repo(tmp_path))
    entry = sources.get("[skipped_sources]")
    assert isinstance(entry, str) and "README.md" in entry
    assert "README.md" not in {k for k in sources if not k.startswith("[")}


def test_small_docs_unaffected(tmp_path: Path):
    (tmp_path / "README.md").write_text("# small\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='t'\n", encoding="utf-8")
    sources = gather_context_sources(tmp_path)
    assert sources["README.md"] == "# small\n"
    assert "[truncated_sources]" not in sources
    assert "[skipped_sources]" not in sources


def test_exactly_at_ceiling_not_marked_truncated(tmp_path: Path):
    """A doc of exactly 10 000 bytes fits whole — nothing was lost, so no
    false truncation entry (the inherited >= off-by-one, now feeding a
    visible artifact record, had to go)."""
    (tmp_path / "README.md").write_text("x" * 10_000, encoding="utf-8")
    sources = gather_context_sources(tmp_path)
    assert "[truncated_sources]" not in sources
    assert "[... truncated ...]" not in sources["README.md"]


def test_sources_survive_prompt_builder(tmp_path: Path):
    """The BLOCKER catch: drive the REAL prompt assembly (the fence loop at
    generate_application_context:689) over sources containing both new
    entries — no TypeError, entries rendered as text."""
    from prompts._fence import safe_code_fence
    sources = gather_context_sources(_doc_repo(tmp_path))
    sources_text = ""
    for name, content in sources.items():
        _sf = safe_code_fence(content)
        sources_text += f"\n### {name}\n{_sf}\n{content}\n{_sf}\n"
    assert "[truncated_sources]" in sources_text
    assert "README.md" in sources_text


def test_multibyte_file_under_char_cap_not_marked_truncated(tmp_path: Path):
    """Confirm-round MAJOR: a multi-byte file whose BYTE size exceeds 10 KB
    but whose CHAR count fits under the cap is COMPLETE — a byte-based
    check false-positives; the char basis (what the model consumes) is the
    truthful signal."""
    (tmp_path / "README.md").write_text("日" * 5_000, encoding="utf-8")  # 5,000 chars, ~15,000 bytes
    sources = gather_context_sources(tmp_path)
    assert "[truncated_sources]" not in sources
    assert "[... truncated ...]" not in sources["README.md"]
    assert len(sources["README.md"]) == 5_000


def test_one_char_over_cap_is_truncated(tmp_path: Path):
    (tmp_path / "README.md").write_text("x" * 10_001, encoding="utf-8")
    sources = gather_context_sources(tmp_path)
    assert "[truncated_sources]" in sources
    assert sources["README.md"].count("x") == 10_000
