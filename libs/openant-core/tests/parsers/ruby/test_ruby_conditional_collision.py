"""Bug 1 (Ruby): same-name defs in mutually-exclusive conditional branches must
NOT collapse to the last-in-source one.

Verified harmful (independent + judge, real `ruby` interpreter): for
  if COND then def k; A end else def k; B end end
only the taken branch's `def` executes — and it may be the EARLIER (if) branch,
but the extractor kept only the later (else) one. Both branches are
env-dependently reachable, so the fix keeps BOTH via the `#L<line>`
disambiguation the Python extractor already uses. Collision-only: a unique name
keeps its clean id. (Unconditional reopening stays correct — last-wins — and is
simply also kept-both, the same tradeoff Python accepts.)
"""
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.ruby.function_extractor import FunctionExtractor


def _extract(tmp_path: Path, filename: str, source: str) -> dict:
    (tmp_path / filename).write_text(source)
    return FunctionExtractor(str(tmp_path)).extract_all([filename])


def _named(out: dict, name: str):
    return [fid for fid, d in out["functions"].items() if d.get("name") == name]


def test_conditional_ifelse_keeps_both_branches(tmp_path):
    src = (
        "if ENV['X']\n"
        "  def k; if_branch; end\n"
        "else\n"
        "  def k; else_branch; end\n"
        "end\n"
    )
    out = _extract(tmp_path, "cond.rb", src)
    ks = _named(out, "k")
    assert len(ks) == 2, f"both conditional branches of k must be kept; got {ks}"
    bodies = " ".join(out["functions"][f]["code"] for f in ks)
    assert "if_branch" in bodies and "else_branch" in bodies, f"a branch was dropped: {bodies}"


def test_unique_name_id_unchanged(tmp_path):
    out = _extract(tmp_path, "u.rb", "def solo; 1; end\n")
    ids = _named(out, "solo")
    assert ids == ["u.rb:solo"], f"unique-name id must stay byte-identical; got {ids}"
