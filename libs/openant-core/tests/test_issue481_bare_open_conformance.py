"""#481: the bare-open class stays retired — a structural conformance scan.

The review-corpus sweep (the 11-comment not-always-closed class) was retired
by converting every inline bare open to the pathlib idiom. This test is the
lock: it re-parses the tests tree and fails if a bare ``open()`` ever comes
back.

Policy points, so a future reader knows the intent:

1. **AST, not regex.** The tests tree embeds ``open(`` inside string
   literals as parser fixture data (e.g. the C-parser tests), so a regex
   scan needs a hand-rolled scrubber to avoid false positives. AST sees
   string data as Constant nodes, never as calls — the false-positive
   class is gone by construction.
2. **with-management is the property — for the object the with receives.**
   Managed calls are the OUTERMOST call of each ``with`` item's context
   expression (a plain Call; a parenthesized ``with (a as x, b as y):``
   parses as separate items, and a walrus or await in the header is
   unwrapped). An open nested as an ARGUMENT (``with tarfile.open(fileobj=
   open(p)) as t:``) is NOT managed — the with closes the tarfile, not the
   handle passed to it — and is flagged. Likewise ``with pytest.raises(...):
   open(missing)`` in the body is flagged although no handle survives, and
   ``fh = open(p)`` + ``with fh:`` is flagged even though it does close at
   runtime — for test code, never holding an unmanaged handle (not even
   to hand it back, not even in a raise-path) is the policy, and the open
   belongs IN the with-header. Wrapper idioms that DO close
   their argument (``contextlib.closing(open(p))``, ``ExitStack.
   enter_context``) are not recognized — no test uses them today; if one
   ever needs one, extend the managed set here, in one place.
   ``os.open`` is exempt (fd-based, not a handle; the low-level idiom in
   test_hostile_repo.py is correct). Everything else with an ``.open``
   attribute is flagged — including ``Path.open``/``tmp_path.open()``, which
   ruff's SIM115 cannot see on a Name or BinOp receiver.
3. **What ruff covers vs this scan.** SIM115 flags unmanaged open-family
   calls EXCEPT in a ``with``/``return`` statement, behind ExitStack/
   unittest ``enterContext``, immediately ``.close()``d, or inside
   ``__enter__`` — its blind spot is the return statement (that is exactly
   how the six shared ``_graph()`` helpers escaped it), plus non-Call
   ``.open`` receivers, plus anything outside its stdlib opener list —
   notably the project's own ``open_utf8`` wrapper, invisible to SIM115 in
   every shape. This scan closes those gaps for the open family. Among
   constructor-style openers, ruff's list reaches the tempfile family,
   ``lzma.LZMAFile`` and ``fileinput.FileInput`` (subject to the same
   with/return/ExitStack/immediate-close exemptions above); the
   CONSTRUCTORS ``zipfile.ZipFile(...)``, ``tarfile.TarFile(...)``,
   ``bz2.BZ2File(...)``, ``io.FileIO``, ``gzip.GzipFile`` and ``os.fdopen``
   are invisible to BOTH arms — though the ``.open()`` MEMBER on a
   ``ZipFile(...)``/``LZMAFile(...)``/``TarFile(...)`` receiver IS visible
   to both (zero unmanaged constructor sites today; if one appears, add
   the constructor names here). Known limits of any name-based detector
   apply to it too: an ``import os as o`` alias would false-positive, an opener
   imported under a different name would be a silent miss, and ANY
   non-``os`` ``.open`` flags — including non-handle openers
   (``webbrowser.open``) and an ``IfExp`` with-header (both arms of a
   ``with open(a) if c else open(b):`` flag although one is managed at
   runtime) — the tests tree uses none of these (if one appears, extend
   the name sets here in one place). The two arms together are the guard,
   which is why the config pin below asserts SIM115 cannot silently
   disappear from the ruff select.
4. **The exemption list is derived, not duplicated.** Paths exempt from
   this scan are the pyproject per-file-ignores entries that list SIM115
   — the efficacy fixtures and the sample-repo fixtures are parser
   input/benchmark data, not test logic (a deliberate bare open lives at
   tests/efficacy/fixtures/webapp/src/app_a.py:15), and the two gates
   move together — EXCEPT that pytest-collected logic (test_*.py /
   *_test.py / conftest.py) is scanned even under an exempt glob: a
   planted test file under fixture data is logic, not data. (fnmatch's
   ``*`` crosses directory separators and ruff additionally matches a
   slash-less pattern against basenames; only exact ``SIM115`` mentions
   are honored — keep both in mind when adding entries.)
"""
from __future__ import annotations

import ast
import fnmatch
import tomllib
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
CORE_ROOT = TESTS_DIR.parent
PYPROJECT = CORE_ROOT / "pyproject.toml"

# Name-form openers that return a file handle: the builtin, and the
# project's own utf-8 wrapper (utilities/file_io.py — the with-target).
_OPENER_NAMES = {"open", "open_utf8"}


def _bare_open_sites(source: str, filename: str = "<source>") -> list[int]:
    """Line numbers of every open-family call not managed by a ``with``.

    Managed = the outermost call of a with-item's context expression
    (walrus in the header is unwrapped); argument-nested opens are NOT
    managed (the with closes its own object, not the arguments handed to
    it). A parenthesized ``with (open(a), open(b)) as (fa, fb):`` never
    reaches the managed arm — a bare tuple has no ``__enter__``, the code
    itself raises at runtime — so both opens flag.
    """
    tree = ast.parse(source, filename=filename)
    managed: set[int] = set()

    def _outer_calls(expr) -> list[ast.Call]:
        # A walrus or await in the with-header is genuinely managed;
        # unwrap to the call underneath.
        if isinstance(expr, (ast.NamedExpr, ast.Await)):
            return _outer_calls(expr.value)
        if isinstance(expr, ast.Call):
            return [expr]
        return []

    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                for call in _outer_calls(item.context_expr):
                    managed.add(id(call))
    sites: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or id(node) in managed:
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in _OPENER_NAMES:
            sites.append(node.lineno)
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "open"
            and not (isinstance(func.value, ast.Name) and func.value.id == "os")
        ):
            sites.append(node.lineno)
    return sites


@pytest.mark.parametrize("source,expected", [
    # Must trip: the retired class, every face of it.
    pytest.param("import json\ndef f(p):\n    return json.load(open(p))\n", 1,
                 id="return-json-load-open"),
    pytest.param("def f(p):\n    return open(p).read()\n", 1,
                 id="return-open-read"),
    pytest.param("def f(p):\n    fh = open(p)\n    return fh.read()\n", 1,
                 id="assigned-open"),
    pytest.param("def f(p):\n    return open(p)\n", 1,
                 id="return-open-bare"),
    pytest.param("import io\ndef f(p):\n    return io.open(p)\n", 1,
                 id="io-open-unmanaged"),
    pytest.param("def f(p):\n    return open_utf8(p)\n", 1,
                 id="wrapper-unmanaged"),
    pytest.param("def f(x):\n    return x.open()\n", 1,
                 id="attribute-open-name-receiver"),  # Path.open too
    pytest.param("def f(d):\n    return (d / 'x.json').open()\n", 1,
                 id="attribute-open-binop-receiver"),
    # Argument-nested opens: the with closes its object, not its arguments.
    pytest.param(
        "import tarfile\ndef f(p):\n"
        "    with tarfile.open(fileobj=open(p, 'rb')) as t:\n        return t\n",
        1, id="argument-nested-open"),
    pytest.param(
        "import contextlib\ndef f(p):\n"
        "    with contextlib.suppress(open(p)):\n        return t\n",
        1, id="suppress-argument-open"),
    # The documented policy: a raise-path holds no handle either.
    pytest.param(
        "import pytest\ndef f(p):\n"
        "    with pytest.raises(FileNotFoundError):\n        open(p)\n",
        1, id="raise-path-open"),
    # Must NOT trip: managed or exempt.
    pytest.param("def f(p):\n    with open(p) as fh:\n        return fh.read()\n", 0,
                 id="with-open-managed"),
    pytest.param(
        "def f(a, b):\n    with (open(a) as fa, open(b) as fb):\n"
        "        return fa.read() + fb.read()\n",
        0, id="parenthesized-with-items-managed"),
    # A bare tuple has no __enter__ — the code raises at runtime and both
    # handles leak; the scan must NOT bless this shape as managed.
    pytest.param(
        "def f(a, b):\n    with (open(a), open(b)) as (fa, fb):\n"
        "        return fa.read() + fb.read()\n",
        2, id="bare-tuple-with-flags-both"),
    pytest.param("def f(p):\n    with (fh := open(p)):\n        return fh.read()\n", 0,
                 id="walrus-header-managed"),
    # An await in the header unwraps to the managed call.
    pytest.param(
        "async def f(p):\n    async with (await open(p)) as fh:\n"
        "        return fh.read()\n",
        0, id="await-header-managed"),
    pytest.param("import os\ndef f(p):\n    return os.open(p, os.O_RDONLY)\n", 0,
                 id="os-open-exempt"),
    pytest.param(
        "import tarfile\nimport gzip\n"
        "def f(p):\n    with tarfile.open(p) as t, gzip.open(p) as g:\n"
        "        return t, g\n",
        0, id="multi-item-with-managed"),
    pytest.param("def f(p):\n    with open_utf8(p) as fh:\n        return fh.read()\n", 0,
                 id="wrapper-with-managed"),
])
def test_scanner_semantics(source, expected):
    assert len(_bare_open_sites(source)) == expected


def _load_ruff_config() -> dict:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh).get("tool", {}).get("ruff", {})


def _sim115_exempt_globs() -> list[str]:
    ruff = _load_ruff_config()
    lint = ruff.get("lint", {})
    # ruff UNIONS per-file-ignores with extend-per-file-ignores per glob —
    # mirror that (a replace-merge would drop a base-table SIM115 entry).
    merged: dict[str, set] = {}
    for table in ("per-file-ignores", "extend-per-file-ignores"):
        for glob, rules in lint.get(table, {}).items():
            merged.setdefault(glob, set()).update(rules)
    return [glob for glob, rules in merged.items() if "SIM115" in rules]


def test_sim115_config_is_pinned():
    """The ruff backstop must not silently appear, disappear, or widen.

    SIM115 is one of the two arms (it misses return-statement opens and
    Name/BinOp ``.open`` receivers; this scan closes those). The pin is
    tamper-evident in BOTH directions: dropping SIM115 disarms one arm,
    and ADDING a SIM115 exemption silently blinds both arms for that
    path (the sweep derives its exemptions from the same pyproject
    keys). The exemption set is pinned exactly — a new entry must be a
    conscious decision recorded here.
    """
    ruff = _load_ruff_config()
    lint = ruff.get("lint", {})
    # WHOLE-TABLE ALLOWLIST, not a per-key blocklist: a blocklist always
    # trails ruff's growing options surface (ignore/exclude/include/
    # force-exclude/fix-only/extend-inheritance/deprecated top-level
    # forms each disarm SIM115 somewhere). The allowlist pins the exact
    # ruff config shape: ANY new top-level or lint key — whatever ruff
    # names it next — trips this pin and becomes a conscious decision.
    assert set(ruff) == {"target-version", "lint"}, (
        f"unexpected top-level ruff keys: {sorted(set(ruff) - {'target-version', 'lint'})} "
        "— any scope/fix/ignore key disarms the ruff arm somewhere; "
        "if deliberate, update this pin consciously")
    assert set(lint) == {"select", "per-file-ignores"}, (
        f"unexpected ruff.lint keys: {sorted(set(lint) - {'select', 'per-file-ignores'})} "
        "— same reason; if deliberate, update this pin consciously")
    assert "SIM115" in lint["select"], (
        "SIM115 is no longer exactly in ruff select (dropped, or renamed/"
        "broadened?) — one arm of the bare-open guard is gone (see this "
        "file's docstring for the two-arm design)")
    expected_ignores = {
        "tests/efficacy/fixtures/**": {"F401", "F841", "SIM115"},
        "tests/fixtures/**": {"SIM115"},
    }
    actual_ignores = {glob: sorted(rules)
                      for glob, rules in lint["per-file-ignores"].items()}
    assert actual_ignores == {g: sorted(r) for g, r in expected_ignores.items()}, (
        f"the ruff per-file-ignores map changed — expected exactly "
        f"{ {g: sorted(r) for g, r in expected_ignores.items()} }, found {actual_ignores}. "
        "An entry or a prefix selector (SIM/ALL) blinds BOTH gates for "
        "that path (sweep + ruff); if deliberate, update this pin "
        "consciously")
    # Named residuals this pin cannot reach: any noqa form in prod
    # (``# noqa: SIM115``, bare ``# noqa``, file-level ``# ruff: noqa``),
    # CI workflow flags (--config/--ignore/--exit-zero), sibling/nested
    # ruff.toml/.ruff.toml files, and .gitignore-driven exclusion
    # (respect-gitignore). None exist today; each would be a visible
    # repo change on review.


def test_no_bare_opens_in_the_test_tree():
    """The sweep: every test file parses clean of unmanaged opens.

    Pytest-collected logic (test_*.py / *_test.py / conftest.py) is NEVER
    exempt — a planted test file under a fixture glob is test logic,
    not data.
    """
    exempt = _sim115_exempt_globs()
    offenders: list[str] = []
    for path in sorted(TESTS_DIR.rglob("*.py")):
        rel = path.relative_to(CORE_ROOT).as_posix()
        is_collected_logic = (
            path.name.startswith("test_")
            or path.name.endswith("_test.py")
            or path.name == "conftest.py")
        if not is_collected_logic and any(fnmatch.fnmatch(rel, glob) for glob in exempt):
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            offenders.append(f"{rel}: unreadable as utf-8 — fixture data? "
                             "add a SIM115 per-file-ignore")
            continue
        try:
            sites = _bare_open_sites(source, filename=str(path))
        except SyntaxError as exc:
            offenders.append(f"{rel}:{exc.lineno}: does not parse — "
                             "fixture data? add a SIM115 per-file-ignore")
            continue
        offenders.extend(f"{rel}:{lineno}" for lineno in sites)
    assert not offenders, (
        "Unmanaged open() calls in the tests tree (the #481 class is "
        f"back): {offenders}\n"
        "Fix idiom: ``with open(p) as fh:`` for handles, "
        "``Path(p).read_text(encoding='utf-8')`` for one-line reads, "
        "``Path(p).write_text(..., encoding='utf-8')`` for one-line "
        "writes — the open belongs IN the with-header")
