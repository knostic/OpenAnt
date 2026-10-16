"""#698: an exact-peer pair travels as ONE renovate branch, and the floors-vs-pins
guard survives the bump that branch brings.

`httpx2` pins its `httpcore2` peer EXACTLY (the published metadata for httpx2
2.13.1 requires ``httpcore2==2.13.1; sys_platform != "emscripten"``, while
`httpcore2` itself requires only `h11>=0.16` — so the constraint runs one way and
is exact). `requirements.txt` pins both. Renovate opens one branch per package by
default, so an ungrouped pair produces two branches that each break the pin
resolution the other half satisfies: `pip install -r requirements.txt` dies with
`ResolutionImpossible` on BOTH. That has now fired twice — #631/#632, then
#694/#695 (6 of 19 checks red each).

Grouping alone does not finish the job. A combined bump installs, and then the
guard in `test_issue428_floors_vs_pins.py` goes red on the very version the branch
moved, because that assertion names a literal. #478 ("the floors-vs-pins guard
survives a renovate bump") already established the follow-the-live-file shape for
the `anthropic` pin one line above; the `httpx2` line kept its literal, and #632
appended the words "the pin follows the live file" to it without changing the
assertion. Both halves are needed: the group alone leaves the branch test-red, the
assertion alone leaves the pair unresolvable.

The distinction this file rests on is observable in CI right now: #758 bumps
`anthropic`, the one package whose assertion follows the live file, and is green on
all 19 checks; #694/#695 bump this pair and are red on 6.

BOUNDARY, stated rather than papered over: `renovate.json` has no in-repo reader.
Its only consumer is the renovate app, which is out of repo, and a `packageRules`
change takes effect only AFTER merge — branch CI can never exercise it (which is
exactly why #476 hurt: a config error there halted renovate for the whole
repository). So `test_renovate_groups_the_exact_peer_pair_into_one_branch` pins the
config SHAPE the out-of-repo consumer needs; it does not and cannot assert that
consumer's behaviour. A shape guard is still what was missing — at the base
`packageRules` held exactly one entry (the tailwindcss cap) and nothing noticed.
"""
import json
import re

from packaging.version import Version

from tests.test_issue428_floors_vs_pins import CORE_ROOT

REPO_ROOT = CORE_ROOT.parent.parent

# The pair is named here because the exactness lives in httpx2's published
# metadata, not in any file this repository owns — there is no authoritative
# in-repo set to key off. If the pair ever leaves requirements.txt the first
# assertion below says so instead of passing vacuously.
EXACT_PEER_PAIR = frozenset({"httpx2", "httpcore2"})

_PIN_ROW = re.compile(
    r"^([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*==\s*([0-9][0-9A-Za-z.\-]*)\s*$")


def _bump_pin_rows(text, names, new_version):
    """Rewrite the `==` pin of every row in `names` to `new_version`.

    Returns (rewritten_text, rewritten_names) — the caller asserts on the
    second value, so a substitution that silently matched nothing cannot be
    mistaken for a bump that happened.
    """
    out, touched = [], set()
    for line in text.splitlines(keepends=True):
        row = line.split("#")[0].strip()
        m = _PIN_ROW.match(row)
        if m and m.group(1).lower() in names:
            line = line.replace(f"=={m.group(3)}", f"=={new_version}", 1)
            touched.add(m.group(1).lower())
        out.append(line)
    return "".join(out), touched


def _next_version(version):
    """The next patch release of `version` — deterministic, no network."""
    parts = list(version.release) or [0]
    parts[-1] += 1
    return ".".join(str(p) for p in parts)


def test_renovate_groups_the_exact_peer_pair_into_one_branch():
    """Half 1: a packageRules entry puts httpx2 and httpcore2 in one branch.

    Without it renovate opens two branches and each is unresolvable — the
    #631/#632 and #694/#695 pairs. `groupName` is the key that makes the
    updates share a branch; `matchPackageNames` alone would only re-describe
    them separately.
    """
    config = json.loads((REPO_ROOT / "renovate.json").read_text(encoding="utf-8"))
    rules = config.get("packageRules") or []
    covering = [
        rule for rule in rules
        if EXACT_PEER_PAIR <= {str(n).lower() for n in (rule.get("matchPackageNames") or [])}
    ]
    assert covering, (
        "renovate.json packageRules has no entry whose matchPackageNames covers "
        f"both of {sorted(EXACT_PEER_PAIR)} — httpx2 pins its httpcore2 peer "
        "exactly, so renovate's one-branch-per-package default produces two "
        "mutually-unresolvable branches (#631/#632, #694/#695). Present entries: "
        + json.dumps([rule.get("matchPackageNames") for rule in rules])
    )
    grouped = [rule for rule in covering if rule.get("groupName")]
    assert grouped, (
        "an entry covers the pair but carries no groupName, so the two updates "
        "still travel as separate branches: "
        + json.dumps(covering)
    )


def test_the_pair_is_still_pinned_together_in_requirements():
    """The pair's premise: both halves are `==`-pinned at the same version.

    This is what makes the peer requirement satisfiable inside one branch, and
    it is what a single-half renovate branch breaks. If a future bump lands
    only one half this fails loudly here rather than as an opaque
    `ResolutionImpossible` in the install step.
    """
    from tests.test_issue428_floors_vs_pins import _pins_from_requirements

    pins = _pins_from_requirements(
        (CORE_ROOT / "requirements.txt").read_text(encoding="utf-8"))
    missing = sorted(name for name in EXACT_PEER_PAIR if name not in pins)
    assert not missing, (
        f"{missing} is no longer pinned in requirements.txt — either the pair "
        "left the file (drop the renovate group and this guard together) or the "
        "row shape changed and the parser stopped seeing it"
    )
    assert pins["httpx2"] == pins["httpcore2"], (
        f"httpx2=={pins['httpx2']} but httpcore2=={pins['httpcore2']}; httpx2 "
        "pins its peer exactly, so these two must move together — this is the "
        "state a single-half renovate branch leaves behind and pip cannot "
        "resolve it"
    )


def test_the_floors_vs_pins_guard_survives_a_grouped_httpx2_bump(tmp_path, monkeypatch):
    """Half 2: the mechanised falsifier — "a renovate httpx2 update landing
    green as-authored".

    Build the tree a GROUPED renovate branch would produce (both halves of the
    pair moved to the next patch release, every other row untouched), point the
    #428 guard module at it, and run the guard's own tests against it. An
    assertion naming a literal version fails here the moment the literal and
    the live file disagree — which is what happens on every httpx2 release.
    """
    import tests.test_issue428_floors_vs_pins as guard

    live_requirements = (CORE_ROOT / "requirements.txt").read_text(encoding="utf-8")
    pins = guard._pins_from_requirements(live_requirements)
    bumped_version = _next_version(pins["httpx2"])
    assert Version(bumped_version) != pins["httpx2"], "the bump must move the version"

    bumped_requirements, touched = _bump_pin_rows(
        live_requirements, EXACT_PEER_PAIR, bumped_version)
    assert touched == set(EXACT_PEER_PAIR), (
        f"the synthetic bump rewrote {sorted(touched)}, expected "
        f"{sorted(EXACT_PEER_PAIR)} — a fixture that did not actually change "
        "the pins would make this test vacuous"
    )
    bumped_pins = guard._pins_from_requirements(bumped_requirements)
    assert bumped_pins["httpx2"] == bumped_pins["httpcore2"] == Version(bumped_version)

    branch = tmp_path / "openant-core"
    branch.mkdir()
    (branch / "requirements.txt").write_text(bumped_requirements, encoding="utf-8")
    (branch / "pyproject.toml").write_text(
        (CORE_ROOT / "pyproject.toml").read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setattr(guard, "CORE_ROOT", branch)
    monkeypatch.setattr(guard, "_PINNED_TEXT", bumped_requirements)

    # the guard's own tests, run against the grouped branch's tree
    guard.test_extras_and_names_parse()
    guard.test_pyproject_floors_never_exceed_requirements_pins()
    guard.test_every_dependency_spec_parses()
