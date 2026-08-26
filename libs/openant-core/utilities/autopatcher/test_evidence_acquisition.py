"""Deterministic, bounded, generic repository-evidence gathering for Test
Plan Discovery.

This module answers "what evidence exists in this repository that's
relevant to how its tests are prepared/run." It gathers file names and
bounded file contents. It NEVER decides what those files imply -- it does
not conclude "pyproject.toml means pytest" or "package.json means npm
test," and adding a conventional filename here (e.g. requirements.txt) is
NOT a claim about what tool that file implies. That interpretation
belongs entirely to the LLM in test_plan_discovery.py. If this module
ever grows a rule like "language X implies test command Y," that is the
exact "framework provider" pattern this architecture was explicitly built
to avoid -- don't add one.

Two independent bounds are enforced, deliberately kept separate:
  - a generous RAW read cap (_MAX_RAW_READ_BYTES) on how many bytes are
    ever pulled off disk for a single file, regardless of its true size
    on disk -- this is a memory-safety bound, not a content bound.
  - small per-item PROMPT content caps (_MAX_FILE_BYTES/_MAX_CI_BYTES/
    _MAX_README_BYTES) and one overall bundle bound (_MAX_TOTAL_BYTES),
    enforced by priority-ordered greedy accumulation in
    gather_test_plan_evidence -- this is what actually bounds what is
    sent to the LLM.

Everything here is a handful of bounded reads -- no AST parsing, no
call-graph construction, nothing from the existing (and much heavier)
repository-understanding pipeline used for vulnerability grounding, which
answers a different question and is the wrong shape/cost for this one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# Config-shaped files: full (bounded) content is useful evidence.
_CONFIG_FILES = (
    "pyproject.toml", "setup.py", "setup.cfg", "pytest.ini", "tox.ini", "noxfile.py",
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "dev-requirements.txt", "test-requirements.txt", "Pipfile",
    "package.json", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
    "Makefile", "justfile", ".tool-versions", ".python-version",
)
# Lockfiles: existence alone is the useful signal (huge, low-signal content).
_LOCKFILES = (
    "poetry.lock", "uv.lock", "Pipfile.lock", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "go.sum", "Cargo.lock",
)

# Prompt-content caps -- what actually reaches the LLM, per item.
_MAX_FILE_BYTES = 4096
_MAX_CI_FILES = 2
_MAX_CI_BYTES = 3072
_MAX_TREE_ENTRIES = 200
_MAX_README_BYTES = 1500
_MAX_TOTAL_BYTES = 16384

# Raw-read safety cap -- how many bytes are ever pulled off disk for ONE
# file, independent of and much larger than the prompt-content caps
# above. Prevents ever loading an arbitrarily large file into memory
# merely to slice or parse a small piece of it afterward.
_MAX_RAW_READ_BYTES = 262_144  # 256 KiB

_CI_KEYWORD_RE = re.compile(r"test|pytest|jest|vitest|mocha|go\s+test", re.IGNORECASE)
_README_HEADING_RE = re.compile(r"^#{1,6}\s*(test|develop|contribut)", re.IGNORECASE)
_README_CANDIDATES = ("README.md", "README.rst", "README.txt", "README")

_IGNORED_DIR_NAMES = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}


@dataclass(frozen=True)
class EvidenceBundle:
    present_config_files: "tuple[tuple[str, str], ...]"    # (repo-relative path, bounded content)
    present_lockfiles: "tuple[str, ...]"                    # names only, no content
    ci_snippets: "tuple[tuple[str, str], ...]"               # (repo-relative path, bounded content)
    directory_listing: "tuple[str, ...]"                      # names only, depth <= 2
    readme_source: "str | None"                                 # e.g. "README.md" -- the exact citable id
    readme_excerpt: "str | None"
    truncated: bool                                             # True if the byte budget forced drops

    @property
    def is_empty(self) -> bool:
        return not (
            self.present_config_files or self.present_lockfiles
            or self.ci_snippets or self.directory_listing or self.readme_excerpt
        )

    @property
    def citable_identifiers(self) -> "frozenset[str]":
        """The exact set of strings Test Plan Discovery may cite in a
        plan's ``evidence`` field -- every one of these, and only these,
        was actually shown to the LLM. Used for exact (never fuzzy)
        provenance validation in test_plan_discovery.py; see
        _parse_response's evidence check there."""
        ids: set[str] = set()
        ids.update(name for name, _ in self.present_config_files)
        ids.update(self.present_lockfiles)
        ids.update(name for name, _ in self.ci_snippets)
        ids.update(self.directory_listing)
        if self.readme_source:
            ids.add(self.readme_source)
        return frozenset(ids)

    def to_prompt_text(self) -> str:
        parts: list[str] = []
        if self.present_config_files:
            parts.append("## Repository configuration/manifest files\n")
            for path, content in self.present_config_files:
                parts.append(f"### {path}\n```\n{content}\n```\n")
        if self.present_lockfiles:
            parts.append("## Lockfiles present (content omitted -- names only)\n")
            parts.append(", ".join(self.present_lockfiles) + "\n")
        if self.ci_snippets:
            parts.append("## CI workflow files mentioning tests\n")
            for path, content in self.ci_snippets:
                parts.append(f"### {path}\n```\n{content}\n```\n")
        if self.directory_listing:
            parts.append("## Repository top-level layout (names only)\n")
            parts.append(", ".join(self.directory_listing) + "\n")
        if self.readme_excerpt:
            parts.append(f"## {self.readme_source} excerpt (testing/development section)\n")
            parts.append(self.readme_excerpt + "\n")
        if self.truncated:
            parts.append("(Some lower-priority evidence was omitted to stay within budget.)\n")
        return "\n".join(parts)


def _read_bounded_text(path: Path, raw_limit: int = _MAX_RAW_READ_BYTES) -> "str | None":
    """Read at most `raw_limit` raw bytes -- NEVER the whole file,
    however large it is on disk -- and decode. Returns None for anything
    unreadable. This is the one place a file is ever opened in this
    module; every caller below bounds its own further slicing on top of
    this, but none of them can cause an unbounded read."""
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read(raw_limit)
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


def _read_bounded(path: Path, limit: int) -> "str | None":
    """Bounded read for direct-inclusion evidence files: reads at most a
    few times `limit` raw bytes (never the whole file), then truncates
    the decoded text to exactly `limit` chars."""
    text = _read_bounded_text(path, raw_limit=limit * 4)
    if text is None:
        return None
    if len(text) > limit:
        text = text[:limit] + "\n... [truncated]"
    return text


def _package_json_relevant_fields(path: Path) -> "str | None":
    """Extract only the keys relevant to deciding how this repository's
    tests should be PREPARED and RUN -- never the full manifest.

    `scripts`/`engines` answer "how do tests run." `dependencies`/
    `devDependencies`/`packageManager` answer the equally necessary "what
    does that entry point need already installed, and by which package
    manager" -- setup-command grounding (see test_plan_discovery.py) is
    impossible without them: a real minimist run accepted
    ``setup_commands=[]`` for a `npm test` entry point that fails with
    "tap: command not found" in a clean container, in part because this
    function used to omit `devDependencies` entirely (the original
    reasoning here was "dependency lists add no test-plan signal and can
    be large" -- the first half was wrong; the second half is still
    handled, unchanged, by the same _MAX_FILE_BYTES truncation every
    other package.json field already goes through). `packageManager` is
    a plain string (e.g. ``"yarn@3.2.0"``), extracted alongside the
    dict-shaped keys as the one exception -- when present it is the
    single strongest package-manager-choice signal available.

    Reads through the same raw-bytes bound as everything else; a
    package.json larger than that bound will fail to parse as JSON and
    simply contributes no evidence, rather than being read in full."""
    text = _read_bounded_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    relevant = {
        k: data[k] for k in ("scripts", "engines", "dependencies", "devDependencies")
        if k in data and isinstance(data[k], dict)
    }
    if isinstance(data.get("packageManager"), str):
        relevant["packageManager"] = data["packageManager"]
    if not relevant:
        return None
    return json.dumps(relevant, indent=2)[:_MAX_FILE_BYTES]


def _gather_config_files(root: Path) -> "tuple[tuple[str, str], ...]":
    out = []
    for name in _CONFIG_FILES:
        p = root / name
        if not p.is_file():
            continue
        if name == "package.json":
            content = _package_json_relevant_fields(p)
        else:
            content = _read_bounded(p, _MAX_FILE_BYTES)
        if content:
            out.append((name, content))
    return tuple(out)


def _gather_lockfiles(root: Path) -> "tuple[str, ...]":
    return tuple(name for name in _LOCKFILES if (root / name).is_file())


def _gather_ci_snippets(root: Path) -> "tuple[tuple[str, str], ...]":
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return ()
    out = []
    try:
        candidates = sorted(
            p for p in workflows_dir.iterdir()
            if p.is_file() and p.suffix in (".yml", ".yaml")
        )
    except OSError:
        return ()
    for p in candidates:
        if len(out) >= _MAX_CI_FILES:
            break
        text = _read_bounded_text(p)
        if text is None or not _CI_KEYWORD_RE.search(text):
            continue
        rel = f".github/workflows/{p.name}"
        snippet = text[:_MAX_CI_BYTES] + ("\n... [truncated]" if len(text) > _MAX_CI_BYTES else "")
        out.append((rel, snippet))
    return tuple(out)


def _gather_directory_listing(root: Path) -> "tuple[str, ...]":
    entries: list[str] = []
    try:
        for p in sorted(root.iterdir()):
            if p.name in _IGNORED_DIR_NAMES or p.name.startswith("."):
                continue
            entries.append(p.name + ("/" if p.is_dir() else ""))
            if p.is_dir() and len(entries) < _MAX_TREE_ENTRIES:
                try:
                    for child in sorted(p.iterdir()):
                        if child.name in _IGNORED_DIR_NAMES or child.name.startswith("."):
                            continue
                        entries.append(f"{p.name}/{child.name}")
                        if len(entries) >= _MAX_TREE_ENTRIES:
                            break
                except OSError:
                    pass
            if len(entries) >= _MAX_TREE_ENTRIES:
                break
    except OSError:
        return ()
    return tuple(entries[:_MAX_TREE_ENTRIES])


def _gather_readme_excerpt(root: Path) -> "tuple[str, str] | None":
    """Returns (source_filename, excerpt) so the exact citable identifier
    is tracked -- or None if no README with a matching heading exists."""
    for name in _README_CANDIDATES:
        p = root / name
        if not p.is_file():
            continue
        text = _read_bounded_text(p)
        if text is None:
            return None
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if _README_HEADING_RE.match(line.strip()):
                heading_level = len(line) - len(line.lstrip("#"))
                collected = [line]
                for follow in lines[i + 1:]:
                    if follow.strip().startswith("#"):
                        follow_level = len(follow) - len(follow.lstrip("#"))
                        if follow_level <= heading_level:
                            break
                    collected.append(follow)
                excerpt = "\n".join(collected).strip()
                if excerpt:
                    return name, excerpt[:_MAX_README_BYTES]
        return None
    return None


def _item_cost(name: str, content: str) -> int:
    return len(name) + len(content)


def _fit_within_budget(
    config_files: "tuple[tuple[str, str], ...]",
    directory_listing: "tuple[str, ...]",
    ci_snippets: "tuple[tuple[str, str], ...]",
    readme: "tuple[str, str] | None",
) -> "tuple[tuple[tuple[str, str], ...], tuple[str, ...], tuple[tuple[str, str], ...], tuple[str, str] | None, bool]":
    """Priority-ordered GREEDY accumulation against one shared byte
    budget -- this, not a post-hoc subtraction, is what guarantees the
    final bundle's content genuinely sums to <= _MAX_TOTAL_BYTES (plus
    the bundle's own small, fixed markdown-header formatting overhead in
    to_prompt_text, which is not counted here).

    Priority (highest first, matching the original design intent that
    config/manifest evidence is the highest-value, cheapest-to-include
    evidence, and the README excerpt is the first thing dropped under
    pressure): config files -> directory listing -> CI snippets -> README.
    Lockfile names are NOT budgeted here -- their total cost is bounded
    by construction (a fixed, short list of conventional filenames) and
    is negligible next to _MAX_TOTAL_BYTES.
    """
    budget = _MAX_TOTAL_BYTES
    truncated = False

    kept_config = []
    for name, content in config_files:
        cost = _item_cost(name, content)
        if cost <= budget:
            kept_config.append((name, content))
            budget -= cost
        else:
            truncated = True

    kept_dirs = []
    for entry in directory_listing:
        if len(entry) <= budget:
            kept_dirs.append(entry)
            budget -= len(entry)
        else:
            truncated = True
            break

    kept_ci = []
    for name, content in ci_snippets:
        cost = _item_cost(name, content)
        if cost <= budget:
            kept_ci.append((name, content))
            budget -= cost
        else:
            truncated = True

    kept_readme = None
    if readme is not None:
        name, content = readme
        if _item_cost(name, content) <= budget:
            kept_readme = readme
            budget -= _item_cost(name, content)
        else:
            truncated = True

    return tuple(kept_config), tuple(kept_dirs), tuple(kept_ci), kept_readme, truncated


def gather_test_plan_evidence(repo_root: "Path | str") -> EvidenceBundle:
    """Gather bounded, deterministic evidence for Test Plan Discovery.
    Never raises: any single unreadable file/directory is skipped, not
    fatal to the whole bundle. The returned bundle's total content is
    guaranteed to fit within _MAX_TOTAL_BYTES (see _fit_within_budget)."""
    root = Path(repo_root)
    if not root.is_dir():
        return EvidenceBundle((), (), (), (), None, None, truncated=False)

    config_files = _gather_config_files(root)
    lockfiles = _gather_lockfiles(root)
    ci_snippets = _gather_ci_snippets(root)
    directory_listing = _gather_directory_listing(root)
    readme = _gather_readme_excerpt(root)

    config_files, directory_listing, ci_snippets, readme, truncated = _fit_within_budget(
        config_files, directory_listing, ci_snippets, readme,
    )
    readme_source, readme_excerpt = readme if readme is not None else (None, None)

    return EvidenceBundle(
        present_config_files=config_files,
        present_lockfiles=lockfiles,
        ci_snippets=ci_snippets,
        directory_listing=directory_listing,
        readme_source=readme_source,
        readme_excerpt=readme_excerpt,
        truncated=truncated,
    )
