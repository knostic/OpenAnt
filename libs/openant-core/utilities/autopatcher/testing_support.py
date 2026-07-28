from pathlib import Path
from typing import List, Dict, Tuple
import re


def discover_tests(root: Path) -> List[Path]:
    """Discover test files under the repository root.

    Matches the following patterns anywhere under `root`:
      - tests/test_*.py
      - tests/*_test.py
      - any test_*.py
      - any *_test.py

    Returns a sorted list of absolute Paths for determinism.
    """
    root = Path(root)
    found = set()

    # common patterns
    excluded_parts = {".venv", "venv", "site-packages", "dist-packages", "__pycache__", "build"}

    def _is_excluded(p: Path) -> bool:
        # Check path parts for common virtualenv/site-package folders
        try:
            parts = set(p.parts)
        except Exception:
            parts = set(str(p).split("/"))
        return any(part in parts for part in excluded_parts)

    for p in root.rglob("test_*.py"):
        if p.is_file() and not _is_excluded(p):
            found.add(p.resolve())
    for p in root.rglob("*_test.py"):
        if p.is_file() and not _is_excluded(p):
            found.add(p.resolve())

    # Return sorted list for deterministic order
    return sorted(found, key=lambda p: str(p))


def _module_name_for_path(root: Path, path: Path) -> str:
    """Convert a file path to a dotted module path relative to root.

    Example: root/src/foo.py -> src.foo
    """
    try:
        rel = Path(path).with_suffix("").relative_to(root)
    except Exception:
        # fallback to path name without suffix
        rel = Path(path).with_suffix("")
    parts = rel.as_posix().split("/")
    return ".".join(parts)


def tests_for_file(root: Path, target_file: Path) -> List[Dict]:
    """Find tests relevant to `target_file` under `root`.

    Each returned dict has keys:
      - path: str (absolute path)
      - proximity: 'same-file' | 'same-module' | 'repo'
      - reason: short human-readable explanation
    """
    root = Path(root)
    target_file = Path(target_file)
    tests = discover_tests(root)
    matches = []

    target_stem = target_file.stem
    module_name = _module_name_for_path(root, target_file)

    # regex to detect import or from <module>
    import_re = re.compile(r"^\s*(from|import)\s+" + re.escape(module_name) + r"(\s|$)")

    for t in tests:
        proximity = "repo"
        reason = "generic test in repo"

        t_name = t.name.lower()
        # same-file heuristic: name matches test_{stem}.py or {stem}_test.py
        if t_name == f"test_{target_stem}.py" or t_name == f"{target_stem}_test.py":
            proximity = "same-file"
            reason = f"filename matches {t.name} -> {target_file.name}"
        else:
            # inspect file content for imports
            try:
                text = t.read_text(encoding="utf8")
            except Exception:
                text = ""
            for line in text.splitlines():
                if import_re.match(line):
                    proximity = "same-module"
                    reason = f"imports module {module_name}"
                    break

        matches.append({
            "path": str(t.resolve()),
            "proximity": proximity,
            "reason": reason,
        })

    # deterministic ordering: proximity rank then path
    rank = {"same-file": 0, "same-module": 1, "repo": 2}
    matches.sort(key=lambda m: (rank.get(m["proximity"], 9), m["path"]))
    return matches


def score_test_support(matches: List[Dict], language: str = "python") -> Tuple[str, float, Dict]:
    """Score test support given a list of match dicts.

    Returns (rating, delta, metadata) where metadata includes:
      - rating
      - delta
      - total_matches
      - matches (the list passed in)

    Rules:
      - Good: same-file exists OR at least 2 same-module matches -> delta +0.05
      - Some: at least one same-module OR at least one repo match -> delta 0.0
      - None: no matches -> delta -0.15

    `discover_tests`/`tests_for_file` only recognize Python's `test_*.py` /
    `*_test.py` naming convention. When `language` is not "python", an empty
    or sparse `matches` list reflects a coverage gap in this signal, not a
    real absence of tests — so this returns "Not Applicable" with a neutral
    delta instead of "None" with a confidence penalty.
    """
    if language != "python":
        metadata = {
            "rating": "Not Applicable",
            "delta": 0.0,
            "total_matches": len(matches),
            "matches": matches,
            "reason": (
                "Test discovery only recognizes Python's test_*.py / *_test.py "
                f"convention; detected language: {language}."
            ),
        }
        return "Not Applicable", 0.0, metadata

    same_file = sum(1 for m in matches if m.get("proximity") == "same-file")
    same_module = sum(1 for m in matches if m.get("proximity") == "same-module")
    repo = sum(1 for m in matches if m.get("proximity") == "repo")

    total = len(matches)

    # New semantics: generic repo tests do not count towards support.
    # Good: same-file exists OR at least 2 same-module matches
    # Some: at least 1 same-module match
    # None: no same-file or same-module matches
    if same_file >= 1 or same_module >= 2:
        rating = "Good"
        delta = 0.05
    elif same_module >= 1:
        rating = "Some"
        delta = 0.0
    else:
        rating = "None"
        delta = -0.15

    metadata = {
        "rating": rating,
        "delta": delta,
        "total_matches": total,
        "matches": matches,
    }
    return rating, delta, metadata
