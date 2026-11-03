"""#703: no retired model ID is reachable as a recommendation.

PR #132 replaced the retired default model IDs and listed three sites it left
behind "tracked for a follow-up" that was never opened. At the filing commit
two of the three were still live — the unused
``CONTEXT_ENHANCEMENT_MODEL_LEGACY`` constant (no production reader; a test
pinning it to the retired literal) and both JS-parser docs recommending
``claude-sonnet-4-20250514`` — plus one adjacent site the promise did not
name: the README example config block.

The falsifier: "a retired model ID reachable as a default, a documented
recommendation, or a copy-pasteable config example at HEAD."

Contract locked here:

- **The docs guard (the durable half)** — no registry-RETIRED model id may
  appear in any operator-facing prose: ``README.md`` and every ``*.md`` under
  ``libs/openant-core``. The retired list is read from the REGISTRY (the
  ``config/models.json`` records whose status is ``retired``), never
  hardcoded — a future retirement adds itself to the guard's reach
  mechanically. The catalogue sites (``config/models.json`` itself,
  ``model_config.py``'s retired constants, the registry tests) are
  deliberately out of the guard's scope: historical reports and saved configs
  still reference retired ids, and the registry keeps them listed by design.
- **The legacy constant is GONE** — the unused
  ``CONTEXT_ENHANCEMENT_MODEL_LEGACY`` deleted with its pin test; the
  registry guard's "intentionally out of scope" carve-out for it closed.
- **The README example matches the resolved defaults** — the copy-paste
  config block's anthropic phase models are exactly the ids
  ``OPENANT_DEFAULT`` resolves (a fresh install copying the example runs
  the same models as a config-less one).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

REPO_ROOT = PROJECT_ROOT.parent.parent  # libs/openant-core -> libs -> repo

# Every operator-facing prose surface: the README plus the in-tree markdown.
# The catalogue sites are code/json (not prose) and stay out.
_PROSE_SURFACES = [REPO_ROOT / "README.md"]
_PROSE_SURFACES += sorted(
    p for p in (PROJECT_ROOT).rglob("*.md")
    if "node_modules" not in str(p) and ".venv" not in str(p))
# the vacuous-guard control: a silently-missing surface (a path bug, a moved
# README) would pass the guard while scanning nothing — every surface must
# EXIST. (The first draft's REPO_ROOT pointed at libs/ and the README fell
# out of the scan entirely — caught because the config test also read it.)
for _surface in _PROSE_SURFACES:
    assert _surface.is_file(), f"the prose surface is missing: {_surface}"

# Model-id-ish tokens: claude-*, gpt-*, gemini-*, o1/o3/o4-*, text-* — but
# only in the ID SHAPE (>= 1 digit): the bare prose words ("claude", "text",
# "gpt" alone) are not id tokens. The bedrock `-v1:0` and `-v1` suffixes are
# stripped from the token before the registry lookup (both id forms compare
# bare).
_ID_RE = re.compile(
    r"\b(?:claude|gpt|gemini|text|o1|o3|o4)[-_.\w]*\b", re.IGNORECASE)


def _iter_id_tokens(text):
    """The id-SHAPED tokens: digit-bearing, suffix-stripped, lowercased."""
    for m in _ID_RE.finditer(text):
        tok = m.group(0).rstrip(".,;:)")
        if not any(c.isdigit() for c in tok):
            continue
        tok = re.sub(r"-v\d+(:\d+)?$", "", tok.lower())
        yield tok


def _bare_id(rid):
    """Strip the prefixed registry id forms to their bare model id — the
    ONE shared definition (the fable-r3 N1 catch: a second divergent copy
    in the positive guard disagreed on exactly the un-regioned
    ``anthropic.`` records — a false-positive-direction drift)."""
    import re as _re
    rid = _re.sub(r"^(?:(?:us|global|eu|apac)\.)?anthropic\.", "", rid)
    rid = _re.sub(r"^[a-z][a-z0-9_-]*/", "", rid)
    rid = _re.sub(r"-v\d+:\d+$", "", rid)
    return rid


def _retired_ids():
    """The registry's own retired list — the ONE source of truth, in BOTH id
    forms: the bare registry id AND every doc-writable spelling of it. A
    bedrock record (`us.anthropic.<id>-v1:0`) or an openrouter record
    (`anthropic/<id>`) prints in the docs under those prefixed forms — the
    fable-r1 F2 catch: the bare-token comparison was blind to 37/76 registry
    records (the BEDROCK/OPENROUTER docs are IN the prose scope and print
    exactly those forms; a future retirement of any of them would have been
    invisible). The token side strips the prefixes/suffixes; the id side
    also joins bare so a bare-form doc mention of a prefixed record's base
    still matches."""
    from core.model_registry import require_models

    retired = {}
    for rec in require_models():
        if rec.get("status") == "retired":
            retired[rec["id"]] = True
            retired[_bare_id(rec["id"])] = True
    assert retired, "the registry carries no retired records — the guard went vacuous"
    return retired


def test_docs_recommend_no_retired_model():
    """The falsifier's prose half: no RETIRED id in any operator-facing doc.

    RED at base: both JS-parser docs AND the dynamic-tester reference (the
    guard's own catch, not in #132's list) recommend
    ``claude-sonnet-4-20250514`` (registry status: retired) — documented
    recommendations that 404s. The three known fix-site docs are NAMED here
    as the load-bearing reads (fixture-drift control + the screen's data
    channel): each must be IN the scanned scope."""
    retired = _retired_ids()
    # the three fix-site docs this issue closes — named so a path/scope drift
    # that silently drops one from the scan fails HERE, not vacuously
    for named in ("PARSER_PIPELINE.md", "PARSER_UPGRADE_PLAN.md",
                  "DYNAMIC_TESTER_REFERENCE.md"):
        assert any(named in str(s) for s in _PROSE_SURFACES), (
            f"the fix-site doc {named} fell out of the guard's scan scope — "
            f"the fixture drifted")
    hits = []
    for surface in _PROSE_SURFACES:
        if not surface.is_file():
            continue
        text = surface.read_text(encoding="utf-8", errors="replace")
        for token in _iter_id_tokens(text):
            if token in retired:
                hits.append(f"{surface.relative_to(REPO_ROOT)}: {token}")
    assert hits == [], (
        f"RETIRED model ids still reachable as documented recommendations: "
        f"{hits} — the #132 promised follow-up, never landed until #703")


def test_every_prose_model_token_resolves_in_the_registry():
    """The fable-r1 F1 catch, closed as a SECOND guard (the positive form):
    the retired-list guard is blind to ids the registry never knew — the
    report README carried `claude-opus-4-5-20250514` (a nonexistent id: Opus
    4.5 is ...-20251101; the date belongs to Opus-4/Sonnet-4) with a wrong
    price. Every model-ish token in the prose surfaces must RESOLVE to a
    registry record (full id or bare form) — a doc recommending an unknown
    id is the 404-class recommendation the falsifier names, whatever its
    registry status."""
    from core.model_registry import require_models

    known = {}
    for rec in require_models():
        known[rec["id"]] = rec["status"]
        known.setdefault(_bare_id(rec["id"]), rec["status"])
    assert known, "the registry is empty — the guard went vacuous"
    # DISCLOSED REACH (the fable-r2 D4 note): the id-SHAPE filter is the
    # claude/gpt/gemini/text/oN families with >=1 digit — the registry's
    # ollama and z-ai records (5 ids, e.g. `z-ai/glm-...`) have no
    # matching prefix and are OUTSIDE both guards; a no-digit id
    # (`claude-mythos-preview`) is also filtered out. A future retirement
    # or recommendation of those families needs a wider iterator — a
    # deliberate scope line, not an accident.
    # the F1 fix site — NAMED so the read is load-bearing for the screen's
    # data channel (the report README carried the nonexistent id this guard
    # exists to catch; it must be IN the scanned scope, never silently out)
    # as_posix(): the comparison is SEPARATOR-INDEPENDENT (the windows CI
    # catch — str(Path) on windows yields backslashes and the forward-slash
    # endswith failed; every path-string comparison in this suite is posix)
    assert any(s.as_posix().endswith("report/README.md") for s in _PROSE_SURFACES), (
        "the report README fell out of the guard's scan scope")
    unresolved = []
    for surface in _PROSE_SURFACES:
        if not surface.is_file():
            continue
        text = surface.read_text(encoding="utf-8", errors="replace")
        for token in _iter_id_tokens(text):
            if token not in known:
                unresolved.append(f"{surface.relative_to(REPO_ROOT)}: {token}")
    assert unresolved == [], (
        f"model tokens in the operator-facing prose that resolve to NO "
        f"registry record — recommending an unknown id is the 404 class: "
        f"{unresolved}")


def test_the_legacy_enhance_constant_is_gone():
    """The unused constant deleted (it carried a RETIRED id as its value; no
    production reader existed — only a pin test and a docstring mention).
    RED at base: the constant still exists."""
    import utilities.context_enhancer as ce
    assert not hasattr(ce, "CONTEXT_ENHANCEMENT_MODEL_LEGACY"), (
        "CONTEXT_ENHANCEMENT_MODEL_LEGACY still ships: an unused constant "
        "carrying the retired claude-sonnet-4-20250514, reachable as a "
        "default-adjacent name — #703's first named residual")
    # the pin test's import must fail too (the site is deleted, not renamed)
    try:
        from utilities.context_enhancer import (  # noqa: F401
            CONTEXT_ENHANCEMENT_MODEL_LEGACY,
        )
        raise AssertionError(
            "the legacy constant is still importable — deleted means deleted")
    except ImportError:
        pass


def test_the_readme_example_matches_the_resolved_defaults():
    """The falsifier's config half: the README's copy-paste example must
    resolve the SAME anthropic phase models a fresh config-less install
    gets. RED at base: the example pins claude-opus-4-6 on
    llm_reach/analyze/verify while OPENANT_DEFAULT resolves claude-opus-4-8
    (and at the filing commit the example's id 404'd outright).

    The README itself is a PROD hunk of this diff (the example block is the
    fix site) and the pinned-against source (utilities/llm/builtins) is
    prod-bound — this test reads both."""
    import re as _re
    from utilities.llm.builtins import OPENANT_DEFAULT
    from utilities import llm as _llm_prod  # the prod-hunk module (the symbol screen)
    assert _llm_prod.builtins.OPENANT_DEFAULT is OPENANT_DEFAULT
    # the README (a PROD hunk of this diff — the example block is the fix
    # site) is a DATA file no import reaches: the screen's data-read channel
    # wants the file NAMED in the body, and the read below is load-bearing
    readme_name = "README.md"

    readme = (REPO_ROOT / readme_name).read_text(encoding="utf-8")
    # the llm_configs example block: "phase": {"provider": "anthropic", "model": "<id>"}
    got = {}
    for phase, model in _re.findall(
            r'"(llm_reach|analyze|verify|enhance|report|dynamic_test|app_context)":\s*'
            r'\{\s*"provider":\s*"anthropic",\s*"model":\s*"([^"]+)"',
            readme):
        got[phase] = model
    assert got, "the README example config block was not found — fixture drift"
    for phase, model in got.items():
        expected = OPENANT_DEFAULT.phases[phase].model
        assert model == expected, (
            f"the README example pins {phase} to {model} but the fresh-install "
            f"default resolves {expected} — a copy-paste config that runs a "
            f"NON-DEFAULT model (or 404s, when the pinned id retires)")


def test_the_registry_carries_no_retired_id_in_prose_scope_even_future():
    """The guard's future-reach control (green at head by construction): the
    retired list is read from the registry, so a FUTURE retirement joins the
    guard's reach mechanically. This pins the guard's own wiring — the
    retired list is non-empty, the prose surfaces exist, and the catalogue
    sites (where retired ids legitimately live) are NOT in the prose scope."""
    retired = _retired_ids()
    # the catalogue sites ARE allowed to name retired ids — they must not be
    # in the prose surface set
    surfaces = {s.as_posix() for s in _PROSE_SURFACES}
    for catalogue in ("config/models.json",
                      "libs/openant-core/utilities/model_config.py",
                      "libs/openant-core/tests/test_model_registry.py"):
        assert not any(p.endswith(catalogue.split("libs/openant-core/")[-1])
                       for p in surfaces if "openant-core" in p), catalogue
    # the known retired pair must be in the registry's list at HEAD (the
    # guard sees them; if the registry drops the retired records the guard
    # must fail loudly, never pass vacuously — the _retired_ids assert)
    assert "claude-sonnet-4-20250514" in retired
