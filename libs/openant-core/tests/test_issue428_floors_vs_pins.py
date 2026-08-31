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


def _parse_dep(spec):
    """`name>=floor` -> (name, Version) ; `name[extra]>=floor` -> extras stripped."""
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
    a floor above a pin silently upgrades past the pin — this fires first."""
    floors = _floors_from_pyproject((CORE_ROOT / "pyproject.toml").read_text())
    pins = _pins_from_requirements((CORE_ROOT / "requirements.txt").read_text())
    drift = _drift(floors, pins)
    assert not drift, (
        "pyproject floors exceed requirements pins — pip install -e silently "
        "upgrades past the CI pin, and no CI step catches it: "
        + "; ".join(f"{n}: floor {f} > pin {p}" for n, f, p in drift)
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


def test_extras_and_names_parse():
    """The parser handles the real files' shapes: extras (`anthropic[bedrock]`),
    exact pins, floor lines, and inline comments (the httpx2 NOTE line)."""
    floors = _floors_from_pyproject(
        (CORE_ROOT / "pyproject.toml").read_text())
    assert floors["anthropic"] == Version("0.40.0")
    assert floors["pydantic"] == Version("2.0.0")
    pins = _pins_from_requirements((CORE_ROOT / "requirements.txt").read_text())
    assert pins["anthropic"] == Version("1.2.0")
    assert pins["httpx2"] == Version("2.12.0")   # the NOTE-commented line
    assert pins["pyyaml"] == Version("6.0")      # the shared floor lines
