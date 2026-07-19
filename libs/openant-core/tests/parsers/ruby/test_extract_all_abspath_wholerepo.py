"""Regression: extract_all must exclude by REPO-RELATIVE segments, not the
absolute path.

Defect (PR164-ruby-abspath-wholerepo-drop): ``extract_all`` walked
``self.repo_path.rglob(...)`` and passed the ABSOLUTE ``file_path`` to
``should_exclude_directory(file_path, [... 'tmp' ...])``. That helper tests
every path *segment*, so a repository located under an ancestor named like an
excluded token (``/private/tmp/repo``, ``.../vendor/checkout``) had EVERY file
excluded -> zero functions extracted. The sibling Python extractor already
guards on ``file_path.relative_to(self.repo_path).parts``.

The module-basename ``function_extractor.py`` recurs across parsers, so the
import is package-qualified to load the Ruby one unambiguously.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))

from parsers.ruby.function_extractor import FunctionExtractor

_SOURCE = "def greet\n  puts 'hi'\nend\n"


def test_extract_all_walks_repo_under_excluded_ancestor(tmp_path: Path) -> None:
    """A repo whose ANCESTOR dir is named 'tmp' must still be scanned.

    The excluded token ('tmp') appears only ABOVE repo_path, so no file inside
    the repo is genuinely in an excluded directory. With the abspath bug every
    file is dropped; with the fix (relative-path exclusion) the method extracts.
    """
    repo = tmp_path / "tmp" / "repo"
    repo.mkdir(parents=True)
    (repo / "app.rb").write_text(_SOURCE)

    extractor = FunctionExtractor(str(repo))
    result = extractor.extract_all()  # no explicit file list -> rglob branch

    names = {fd["name"] for fd in result["functions"].values()}
    assert "greet" in names, (
        "extract_all dropped every file because an ancestor segment matched an "
        f"exclude token; extracted names={names}"
    )
