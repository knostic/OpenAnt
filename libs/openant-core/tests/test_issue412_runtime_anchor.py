"""#412: the dynamic-test runtime anchors cannot silently drift again.

The system prompt's Go fallback tag and the docker_templates/ reference
Dockerfile are two spellings of one fact ("the current Go fallback").
They drifted three ways once (prompt 1.25 / template 1.27 / doc 1.22)
because nothing bound them. This test parses both at collection time and
fails on any mismatch — a future pin bump must touch both (and this test's
expected fallback list) in one conscious change.
"""
from __future__ import annotations

import re
from pathlib import Path

_DYNDIR = Path(__file__).resolve().parent.parent / "utilities" / "dynamic_tester"

# The fallback tag the prompt and the template must agree on. When bumping
# the fallback, update ALL of: this list, the prompt's two mentions in
# test_generator.py, and docker_templates/go.Dockerfile.
_KNOWN_FALLBACKS = {"golang:1.27-alpine"}


def _prompt_go_tags() -> set[str]:
    src = (_DYNDIR / "test_generator.py").read_text(encoding="utf-8")
    return set(re.findall(r"golang:\d+(?:\.\d+)?-alpine", src))


def _template_go_tag() -> str:
    first = (_DYNDIR / "docker_templates" / "go.Dockerfile").read_text(
        encoding="utf-8").splitlines()[0]
    m = re.search(r"golang:\d+(?:\.\d+)?-alpine", first)
    assert m, "go.Dockerfile's FROM line no longer names a golang tag"
    return m.group(0)


def test_go_fallback_tag_is_known():
    tags = _prompt_go_tags()
    assert tags <= _KNOWN_FALLBACKS, (
        f"the prompt's Go fallback tags {sorted(tags)} are not in the "
        f"known-fallback set {sorted(_KNOWN_FALLBACKS)} — a pin bump must "
        "update the prompt AND docker_templates/go.Dockerfile AND this "
        "test's set together (the #412 drift guard)")


def test_prompt_and_template_go_tags_match():
    tags = _prompt_go_tags()
    assert tags, "no golang tag found in the prompt at all"
    template = _template_go_tag()
    assert template in tags, (
        f"the prompt's Go fallback {sorted(tags)} and the template's "
        f"{template} disagree — the three-way drift #412 was filed for")


def test_runtime_anchor_guidance_present():
    """The policy itself is pinned: target-declared runtime first, stable
    fallback only when nothing is declared."""
    src = (_DYNDIR / "test_generator.py").read_text(encoding="utf-8")
    assert "BASE IMAGE RUNTIME POLICY" in src, (
        "the runtime-policy block was removed from the prompt — #412's "
        "anchor is gone; restore it or update this pin consciously")
    assert "DECLARED runtime" in src, (
        "the target-declared-runtime-first clause is gone from the prompt")
    assert "fall back to the current stable" in src, (
        "the stable-fallback clause is gone from the prompt")


def test_reference_doc_template_table_matches_the_templates():
    """The reference doc's template table is a THIRD spelling of the
    template facts — it drifted before (node:20 vs the template's 24) and
    is bound here now (the #412 audit's find)."""
    doc = (_DYNDIR / "DYNAMIC_TESTER_REFERENCE.md").read_text(encoding="utf-8")
    for name in ("python", "node", "go"):
        tmpl_first = (_DYNDIR / "docker_templates" / f"{name}.Dockerfile"
                      ).read_text(encoding="utf-8").splitlines()[0]
        import re as _re
        m = _re.search(r"FROM\s+(\S+)", tmpl_first)
        assert m, f"{name}.Dockerfile's FROM line is malformed: {tmpl_first!r}"
        image = m.group(1)
        assert f"`{image}`" in doc, (
            f"DYNAMIC_TESTER_REFERENCE.md's template table does not name "
            f"{image} (the {name}.Dockerfile base) — the table drifted "
            "from the templates it describes (the #412 class)")
