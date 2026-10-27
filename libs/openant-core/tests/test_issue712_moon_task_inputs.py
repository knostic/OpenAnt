"""#712: the moon task graphs' input lists — completed and pinned.

The Go tasks omitted every embedded asset (the two report templates, the
vendored report.css/JS blobs, the four ui/*.html pages and their vendored
JS) and the Python test task omitted seven of the eight source directories
(the inputs were `openant/**/*` + `tests/**/*` while the tested tree is
core/, utilities/, parsers/, context/, prompts/, report/, github_scanner/
and openant/). Nothing runs moon today (no workspace root, no CI job), so
the gap was latent — but editing a template or a ui page (this repo's most
common edits on that surface) would have been a cache hit serving a stale
binary/test result for exactly the class-coverage and golden-render guards.

The falsifier (authored at filing): "a moon task graph whose build/test
inputs cover the embedded assets and the Python source tree — or a recorded
decision that the moon descriptors are unused and should be removed." This
suite pins the FIRST disjunct: the input lists now cover them, and any
regression (a dropped glob, a new embedded asset outside the globs) fires
these pins.
"""

import re
import sys
from pathlib import Path

_WT_ROOT = Path(__file__).resolve().parents[3]
_CORE_ROOT = _WT_ROOT / "libs" / "openant-core"
sys.path.insert(0, str(_CORE_ROOT))


def _load_yaml(rel: str):
    import yaml
    return yaml.safe_load((_WT_ROOT / rel).read_text())


def _glob_matches(candidate: str, pattern: str) -> bool:
    """The moon input glob semantics, WAX-FAITHFUL (moon uses
    starbase_utils::glob which is wax): `**` matches zero-or-more whole
    segments; `*` matches WITHIN one segment (never crosses '/'). The
    r1-N1 catch: fnmatch's `*` DOES cross '/', so a narrowed glob
    (ui/*.html after a file moved to ui/pages/) would false-green — this
    matcher splits on segments and matches `*` per-segment."""
    import fnmatch
    if "**" in pattern:
        # a/**/tail: the tree wildcard — zero or more segments between
        prefix, sep, rest = pattern.partition("**")
        tail = rest.lstrip("/")
        if prefix and not candidate.startswith(prefix):
            return False
        if not tail:
            return True  # a/** matches everything under a/
        rest_of = candidate[len(prefix):] if prefix else candidate
        segs = rest_of.split("/")
        tail_segs = tail.split("/")
        # try every split point (the tree wildcard consumed 0..n segments),
        # END-ANCHORED (the r2-N1 residual): the tail must consume ALL the
        # remaining segments — a zip() truncation would match mid-path
        for k in range(len(segs)):
            if len(segs) - k == len(tail_segs) and all(
                    fnmatch.fnmatch(s, p) for s, p in
                    zip(segs[k:], tail_segs)):
                return True
        return False
    # no tree wildcard: segment-wise, `*` never crosses '/'
    csegs = candidate.split("/")
    psegs = pattern.split("/")
    if len(csegs) != len(psegs):
        return False
    return all(fnmatch.fnmatch(c, p) for c, p in zip(csegs, psegs))


# --- the Go half: the embedded assets are build/test inputs ---

def _go_embed_targets(for_test=False):
    """Every //go:embed target as a repo-relative path (the targets are
    relative to the embedding .go file's package dir), derived from the
    .go sources (not declared): a new embedded asset outside the globs
    must fire the pin."""
    cli = _WT_ROOT / "apps" / "openant-cli"
    targets = []
    for go in cli.rglob("*.go"):
        if go.name.endswith("_test.go") and not for_test:
            continue
        for m in re.finditer(r"^\s*//go:embed\s+([^\n]+)", go.read_text(), re.M):
            for tok in m.group(1).split():
                tok = tok.strip().strip('"').strip("`")
                if tok.startswith("all:"):
                    tok = tok[4:]
                # the path is relative to the .go file's directory;
                # as_posix() — the moon input globs are ALWAYS
                # forward-slash (the #703 CI-catch class: on Windows
                # Path.relative_to yields backslash-separated paths that
                # match no glob)
                rel = (go.parent / tok).resolve().relative_to(cli.resolve())
                targets.append(rel.as_posix())
    return sorted(set(targets))


def test_every_embedded_asset_is_a_build_input():
    """THE Go half: every //go:embed target must be covered by the build
    task's input globs — an edit to any embedded asset must invalidate the
    build cache."""
    moon = _load_yaml("apps/openant-cli/moon.yml")
    inputs = moon["tasks"]["build"]["inputs"]
    for target in _go_embed_targets():
        covered = any(_glob_matches(target, pat) for pat in inputs)
        assert covered, (
            f"the embedded asset {target!r} is not covered by any build "
            f"input glob: {inputs}")


def test_every_embedded_asset_is_a_test_input():
    """The Go test twin: the class-coverage and golden-render suites read
    the templates and the vendored assets, so the test cache must
    invalidate on them too."""
    moon = _load_yaml("apps/openant-cli/moon.yml")
    inputs = moon["tasks"]["test"]["inputs"]
    for target in _go_embed_targets(for_test=True):
        covered = any(_glob_matches(target, pat) for pat in inputs)
        assert covered, (
            f"the embedded asset {target!r} is not covered by any test "
            f"input glob: {inputs}")


def test_the_go_source_globs_are_still_present():
    """The pre-existing inputs are kept: the .go sources + the module
    files."""
    moon = _load_yaml("apps/openant-cli/moon.yml")
    for task in ("build", "test"):
        inputs = moon["tasks"][task]["inputs"]
        assert "**/*.go" in inputs, (task, inputs)
        assert "go.mod" in inputs and "go.sum" in inputs, (task, inputs)


def test_the_go_test_task_covers_the_recipe_and_testdata():
    """The r1-F2 catch: the Go test task's inputs must cover the
    NON-embedded test-time reads — the tailwind recipe (the palette, the
    config, the input CSS — read by the CSS-freshness suites) and the
    golden-render testdata (the browser-smoke oracle)."""
    moon = _load_yaml("apps/openant-cli/moon.yml")
    inputs = moon["tasks"]["test"]["inputs"]
    cli = _WT_ROOT / "apps" / "openant-cli"
    for rel in ("internal/report/tailwind/palette.json",
                "internal/report/tailwind/tailwind.config.js",
                "internal/report/tailwind/input.css",
                "internal/server/testdata/browser-smoke/golden_input.md"):
        assert (cli / rel).exists(), rel
        covered = any(_glob_matches(rel, pat) for pat in inputs)
        assert covered, (
            f"the test-time read {rel!r} is not covered by any Go test "
            f"input glob: {inputs}")


# --- the Python half: the source tree is a test input ---

def _python_root_modules():
    """The root-level .py files (outside the package dirs) — experiment.py,
    validate_dataset_schema.py — derived from the tree: the tests import
    them, so they are test inputs."""
    core = _CORE_ROOT
    return sorted(p.name for p in core.glob("*.py"))


def test_the_root_modules_are_test_inputs():
    """The r1-F1 catch: the root-level modules the tests import
    (experiment.py — tests/test_cwe_tagging.py imports
    `from experiment import _normalize_result`; validate_dataset_schema.py)
    plus the run-shaping files (conftest.py, pytest.ini) are test inputs."""
    moon = _load_yaml("libs/openant-core/moon.yml")
    inputs = moon["tasks"]["test"]["inputs"]
    for name in _python_root_modules():
        covered = any(_glob_matches(name, pat) for pat in inputs)
        assert covered, (
            f"the root module {name!r} is not covered by any Python test "
            f"input glob: {inputs}")
    for shape in ("conftest.py", "pytest.ini", "pyproject.toml"):
        covered = any(_glob_matches(shape, pat) for pat in inputs)
        assert covered, (
            f"the run-shaping file {shape!r} is not covered: {inputs}")

def _python_source_dirs():
    """The importable source directories under libs/openant-core (the
    packages the test tree imports), derived from the tree."""
    core = _CORE_ROOT
    dirs = []
    for d in sorted(core.iterdir()):
        if d.is_dir() and not d.name.startswith((".", "__")):
            has_py = any(d.glob("*.py")) or any(d.glob("**/__init__.py"))
            if has_py and d.name != "tests":
                dirs.append(d.name)
    return dirs


def test_every_source_dir_is_a_test_input():
    """THE Python half: every source directory the tests import must be
    covered by the test task's input globs — seven of eight were outside
    the set at base, so any edit outside openant/ was a cache hit."""
    moon = _load_yaml("libs/openant-core/moon.yml")
    inputs = moon["tasks"]["test"]["inputs"]
    for d in _python_source_dirs():
        covered = any(_glob_matches(f"{d}/x.py", pat) for pat in inputs)
        assert covered, (
            f"the source directory {d!r} is not covered by any test input "
            f"glob: {inputs}")


def test_the_run_tasks_cover_the_source_tree():
    """The analyze/parse/report tasks run `python -m openant ...` — the
    whole package imports, so their inputs cover the same source tree."""
    moon = _load_yaml("libs/openant-core/moon.yml")
    for task in ("analyze", "parse", "report"):
        inputs = moon["tasks"][task]["inputs"]
        for d in _python_source_dirs():
            covered = any(_glob_matches(f"{d}/x.py", pat) for pat in inputs)
            assert covered, (
                f"the {task} task's inputs miss the source directory "
                f"{d!r}: {inputs}")


def test_the_install_task_keeps_its_input():
    """The install task's input (pyproject.toml) is unchanged."""
    moon = _load_yaml("libs/openant-core/moon.yml")
    assert moon["tasks"]["install"]["inputs"] == ["pyproject.toml"]


# --- the recorded decision (why complete, not delete) ---

def test_the_completion_decision_is_recorded():
    """The falsifier's second disjunct (delete the descriptors) was
    considered and declined: the descriptors describe the build this repo
    actually runs (go build/test, pytest) and completing them is the
    prerequisite for ANY future moon adoption; the decision is recorded in
    the Go moon.yml's first #712 comment (the option (b) analysis)."""
    src = (_WT_ROOT / "apps" / "openant-cli" / "moon.yml").read_text()
    assert "#712" in src
    # the option-(b) analysis is IN the descriptor (the r1-N2 catch: the
    # first pin only checked the issue tag)
    assert "considered and" in src and "declined" in src
    assert "workspace" in src  # the .moon/ root as the next step
