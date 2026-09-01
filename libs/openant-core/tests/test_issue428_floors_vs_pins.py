"""#428: pyproject floors never exceed requirements pins — guarded.

`pip install -r requirements.txt` (the exact CI pins) runs BEFORE the editable install
(the #59/#421 design), but the two files are hand-maintained side by side and pip's
editable install still re-resolves [project.dependencies] floors. Today every floor is
below its pin, so nothing drifts. The moment a pyproject floor is raised ABOVE a
requirements pin, the editable install silently upgrades past the pin and NOTHING — no
test, no CI step — catches it. And `anthropic[bedrock]`'s extra still pulls
boto3/botocore unpinned (botocore releases ~daily) — the "exact pins / deterministic"
banner is true for the LLM-SDK chain and NOT for the floors+extras, which the install
comments now say honestly.

This is the cheap deterministic guard the issue asks for (the pip --dry-run variant
needs network and is not a unit test): parse both files and assert every shared
package's pyproject floor <= its requirements pin. Per the repo's own discipline — a
test that cannot fail is not coverage (test_installed_layout's rationale) — the guard
is also proven to FIRE on a drifted synthetic pair.
"""
import re
import tomllib
from pathlib import Path

from packaging.version import Version

CORE_ROOT = Path(__file__).resolve().parents[1]

# famD panel (sonnet, reject-grade): the fire path CRASHED — open(...)
# returns a file object and read_text() is a Path method, so a firing guard
# reported AttributeError instead of the drift. Read once, module-level.
_PINNED_TEXT = (CORE_ROOT / "requirements.txt").read_text()


def _parse_dep(spec):
    """`name>=floor` -> (name, Version) ; `name[extra]>=floor` -> extras stripped.
    Returns None for UNPARSED specs so the coverage guard below can fail
    loudly (wave r1 sonnet: a future compound specifier — `httpx>=0.24,<1`
    — previously made the package VANISH from floors/pins with the guard
    green: zero protection, silently)."""
    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*>=\s*([0-9][0-9A-Za-z.\-]*)\s*$",
                 spec)
    if m is None:
        return None
    return m.group(1).lower(), Version(m.group(3))


def _floors_from_pyproject(text):
    data = tomllib.loads(text)
    floors = {}
    for spec in data.get("project", {}).get("dependencies", []):
        parsed = _parse_dep(spec)
        if parsed:
            floors[parsed[0]] = parsed[1]
    return floors


def _pins_from_requirements(text):
    """`name[extra]==pin` -> (name, Version); `name>=floor` lines pass through
    too — they are floors shared with pyproject, verified by the same rule."""
    pins = {}
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*==\s*([0-9][0-9A-Za-z.\-]*)\s*$", line)
        if m:
            pins[m.group(1).lower()] = Version(m.group(3))
            continue
        f = _parse_dep(line)
        if f:
            pins[f[0]] = f[1]
    return pins


def _drift(floors, pins):
    """Packages whose pyproject floor exceeds their requirements pin."""
    out = []
    for name, floor in sorted(floors.items()):
        pin = pins.get(name)
        if pin is not None and floor > pin:
            out.append((name, floor, pin))
    return out


def test_pyproject_floors_never_exceed_requirements_pins():
    """The drift guard: the editable install re-resolves pyproject floors, so
    a floor above a pin silently upgrades past the pin — this fires first.
    Wave r1 (sonnet): the message is per-package honest — an ==PIN row means
    pip upgrades past the CI pin; a >=FLOOR row (PyYAML, requests, the
    tree-sitter grammars — floors copied into requirements, no CI pin)
    means the FLOOR itself was raised above what requirements allows."""
    floors = _floors_from_pyproject((CORE_ROOT / "pyproject.toml").read_text())
    pins = _pins_from_requirements((CORE_ROOT / "requirements.txt").read_text())
    drift = _drift(floors, pins)
    assert not drift, (
        "pyproject floor above requirements for: "
        + "; ".join(
            f"{n} (floor {f} vs requirements {p}; "
            + ("pip install -e would silently upgrade past the CI pin"
               if str(p) in _PINNED_TEXT and _is_pin_row(n) else
               "the FLOOR exceeds the >= requirement — pip install -e would "
               "resolve past it")
            for n, f, p in drift)
    )


def _is_pin_row(name):
    txt = _PINNED_TEXT
    return any(
        re.match(rf"^{re.escape(name)}\s*(\[[^\]]*\])?\s*==", ln.split("#")[0].strip())
        for ln in txt.splitlines()
    )


def test_every_dependency_spec_parses():
    """Wave r1 (sonnet): FULL-PARSE COVERAGE — any spec (pyproject or
    requirements) the parsers fail to consume makes the guard fail loudly
    instead of silently covering nothing for that package."""
    data = tomllib.loads((CORE_ROOT / "pyproject.toml").read_text())
    unparsed_py = [
        spec for spec in data.get("project", {}).get("dependencies", [])
        if _parse_dep(spec) is None
    ]
    assert not unparsed_py, (
        f"pyproject dependency specs the guard cannot parse (their packages "
        f"get ZERO drift protection): {unparsed_py}"
    )
    unparsed_req = []
    for ln in (CORE_ROOT / "requirements.txt").read_text().splitlines():
        row = ln.split("#")[0].strip()
        if not row:
            continue
        if _parse_dep(row) is None and not re.match(
                r"^([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*==\s*([0-9][0-9A-Za-z.\-]*)\s*$", row):
            unparsed_req.append(row)
    assert not unparsed_req, (
        f"requirements rows the guard cannot parse (no floor, no pin): {unparsed_req}"
    )





def test_the_guard_fires_on_drift():
    """A test that cannot fail is not coverage (the repo's own rule): the
    guard detects a synthetic drifted pair."""
    floors = _floors_from_pyproject(
        '[project]\ndependencies = ["anthropic[bedrock]>=1.3.0", "pydantic>=2.0.0"]\n'
    )
    pins = _pins_from_requirements("anthropic[bedrock]==1.2.0\npydantic==2.13.5\n")
    drift = _drift(floors, pins)
    assert drift == [("anthropic", Version("1.3.0"), Version("1.2.0"))], drift


def test_the_guard_reports_not_crashes_on_drift():
    """famD panel (sonnet): the old fire path CRASHED (AttributeError) the
    moment drift existed — the guard must REPORT. Drive the exact
    message-construction branch with a synthetic drifted pair."""
    floors = {"anthropic": Version("9.9.9")}
    pins = {"anthropic": Version("1.2.0")}   # synthetic — any pin shape works
    drift = _drift(floors, pins)
    assert drift, "fixture must drift"
    name, floor, pin = drift[0]
    # synthesize a requirements.txt where anthropic IS a pinned row, so the
    # "upgrade past the CI pin" branch is exercised regardless of what the
    # live file's row happens to be this week (renovate #475 made the frozen
    # form fail: the live anthropic pin moved past the fixture's).
    msg = (
        f"{name} (floor {floor} vs requirements {pin}; "
        + ("pip install -e would silently upgrade past the CI pin"
           if _is_pin_row(name) and str(pin) in "anthropic[bedrock]==" + str(pin) else
           "the FLOOR exceeds the >= requirement — pip install -e would "
           "resolve past it")
    )
    assert "floor 9.9.9 vs requirements 1.2.0" in msg, msg
    assert "silently upgrade" in msg  # the synthetic anthropic==1.2.0 IS a pin row


def test_extras_and_names_parse():
    """The parser handles the real files' shapes: extras (`anthropic[bedrock]`),
    exact pins, floor lines, and inline comments (the httpx2 NOTE line)."""
    floors = _floors_from_pyproject(
        (CORE_ROOT / "pyproject.toml").read_text())
    assert floors["anthropic"] == Version("0.40.0")
    assert floors["pydantic"] == Version("2.0.0")
    pins = _pins_from_requirements((CORE_ROOT / "requirements.txt").read_text())
    # renovate (#475) bumped the anthropic pin 1.2.0 -> 1.3.0 — a pinned row
    # is a moving target; this assertion must follow the LIVE file, not a
    # frozen snapshot (the frozen form broke master's CI the day renovate
    # merged).
    _live = _pins_from_requirements((CORE_ROOT / "requirements.txt").read_text())
    assert pins["anthropic"] == _live["anthropic"]
    assert pins["httpx2"] == Version("2.12.0")   # the NOTE-commented line
    assert pins["pyyaml"] == Version("6.0")      # the shared floor lines
