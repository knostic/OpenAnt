"""PR #763 independent HUNT review, findings N6-N8: Impact Surface rated a
behavior-changing patch Low Risk because it attributed the change to no
symbol (an indentation change, an import rebinding), to a nested function's
local name, or to an earlier function with identical text.

The analyzer is driven exactly as S9 drives it (LightweightImpactAnalyzer over
the patch, file reads through TargetRepoContext), and its level is fed through
the production trust-signal computation, so a wrong level shows up as a wrong
deployment-safety signal."""

from pathlib import Path

import pytest

from utilities.autopatcher.impact_surface import LightweightImpactAnalyzer
from utilities.autopatcher.pipeline import TargetRepoContext, _compute_trust_signals


def _repo(tmp_path: Path, files: dict) -> Path:
    root = tmp_path / "repo"
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def _callers(module: str, fn: str, n: int = 4) -> dict:
    return {f"caller{i}.py": f"from {module} import {fn}\n\ndef job{i}(x):\n    return {fn}(x)\n" for i in range(n)}


def _analyze(root: Path, diff: str):
    report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(root), repo_language="python")
    safety = _compute_trust_signals([], {"applicable": True}, {"still_vulnerable": False}, "Good", report.impact_level)
    return report, safety["deployment_safety"]["value"]


def _not_low(report, safety):
    assert report.impact_level not in ("low", "medium"), (report.impact_level, report.changed_symbols)
    assert safety != "Low Risk"


# ---------------------------------------------------------------------------
# N6 -- indentation and import rebinding are behavior changes.
# ---------------------------------------------------------------------------

FETCH = "def fetch(user, key):\n    if user.is_admin:\n        audit(key)\n    return STORE[key]\n"


class TestN6IndentationAndImports:
    def test_reindented_statement_is_attributed(self, tmp_path):
        root = _repo(tmp_path, {"core.py": FETCH, **_callers("core", "fetch")})
        diff = ("--- a/core.py\n+++ b/core.py\n@@ -1,4 +1,4 @@\n def fetch(user, key):\n"
                "     if user.is_admin:\n         audit(key)\n-    return STORE[key]\n+        return STORE[key]\n")
        report, safety = _analyze(root, diff)
        assert report.changed_symbols == ["fetch"]
        _not_low(report, safety)

    def test_dedented_statement_is_attributed(self, tmp_path):
        """The opposite direction: a guarded statement moved out of its block."""
        src = "def fetch(user, key):\n    if user.is_admin:\n        return STORE[key]\n    return None\n"
        root = _repo(tmp_path, {"core.py": src, **_callers("core", "fetch")})
        diff = ("--- a/core.py\n+++ b/core.py\n@@ -1,4 +1,4 @@\n def fetch(user, key):\n"
                "     if user.is_admin:\n-        return STORE[key]\n+    return STORE[key]\n     return None\n")
        report, safety = _analyze(root, diff)
        assert report.changed_symbols == ["fetch"]
        _not_low(report, safety)

    @pytest.mark.parametrize("old,new", [
        ("from json import loads", "from pickle import loads"),
        ("from json import loads", "from pickle import loads as loads"),
        ("import json as codec", "import pickle as codec"),
        ("from json import loads", "from pickle import *"),
    ], ids=["from-import", "aliased", "module-alias", "star"])
    def test_import_rebinding_is_not_low(self, tmp_path, old, new):
        src = f"{old}\n\ndef parse(b):\n    return loads(b)\n".replace("loads(b)", "codec.loads(b)" if "codec" in old else "loads(b)")
        root = _repo(tmp_path, {"ser.py": src, **_callers("ser", "parse")})
        diff = f"--- a/ser.py\n+++ b/ser.py\n@@ -1,3 +1,3 @@\n-{old}\n+{new}\n \n def parse(b):\n"
        report, safety = _analyze(root, diff)
        assert report.impact_level == "unavailable"
        _not_low(report, safety)

    def test_removed_import_is_not_low(self, tmp_path):
        src = "import json\nimport os\n\ndef parse(b):\n    return json.loads(b)\n"
        root = _repo(tmp_path, {"ser.py": src, **_callers("ser", "parse")})
        diff = "--- a/ser.py\n+++ b/ser.py\n@@ -1,3 +1,2 @@\n-import json\n import os\n \n"
        _not_low(*_analyze(root, diff))

    def test_added_import_shadowing_a_function_is_not_low(self, tmp_path):
        src = "import os\n\n\ndef loads(b):\n    return b\n\n\ndef parse(b):\n    return loads(b)\n"
        root = _repo(tmp_path, {"ser.py": src, **_callers("ser", "parse")})
        diff = "--- a/ser.py\n+++ b/ser.py\n@@ -1,1 +1,2 @@\n import os\n+from pickle import loads\n"
        _not_low(*_analyze(root, diff))

    # -- genuinely narrow changes keep their low rating --
    def test_trailing_whitespace_is_still_cosmetic(self, tmp_path):
        root = _repo(tmp_path, {"core.py": FETCH, **_callers("core", "fetch")})
        diff = ("--- a/core.py\n+++ b/core.py\n@@ -1,4 +1,4 @@\n def fetch(user, key):\n"
                "     if user.is_admin:\n         audit(key)\n-    return STORE[key]\n+    return STORE[key]   \n")
        report, _ = _analyze(root, diff)
        assert report.changed_symbols == [] and report.impact_level == "low"

    @pytest.mark.parametrize("diff", [
        "--- a/ser.py\n+++ b/ser.py\n@@ -1,1 +1,2 @@\n import os\n+import html\n",
        "--- a/ser.py\n+++ b/ser.py\n@@ -1,2 +1,2 @@\n-import os\n-import json\n+import json\n+import os\n",
        "--- a/ser.py\n+++ b/ser.py\n@@ -1,1 +1,2 @@\n import os\n+# an explanatory comment\n",
    ], ids=["new-import", "reordered-imports", "comment"])
    def test_narrow_module_level_changes_stay_low(self, tmp_path, diff):
        src = "import os\nimport json\n\ndef parse(b):\n    return json.loads(b)\n"
        root = _repo(tmp_path, {"ser.py": src, **_callers("ser", "parse")})
        report, safety = _analyze(root, diff)
        assert report.impact_level == "low" and safety == "Low Risk", report.impact_summary

    def test_indented_import_is_the_enclosing_functions_change(self, tmp_path):
        src = "def parse(b):\n    import json\n    return json.loads(b)\n"
        root = _repo(tmp_path, {"ser.py": src, **_callers("ser", "parse")})
        diff = ("--- a/ser.py\n+++ b/ser.py\n@@ -1,3 +1,3 @@\n def parse(b):\n"
                "-    import json\n+    import pickle as json\n     return json.loads(b)\n")
        report, safety = _analyze(root, diff)
        assert report.changed_symbols == ["parse"]
        _not_low(report, safety)


# ---------------------------------------------------------------------------
# N7 -- a nested function's change reaches its enclosing function's callers.
# ---------------------------------------------------------------------------

RENDER = ('def render_page(name):\n    def _escape(value):\n        return value.replace("<", "&lt;")\n'
          '    return "<p>" + _escape(name) + "</p>"\n')
NESTED_EDIT = ('--- a/core.py\n+++ b/core.py\n@@ -1,4 +1,4 @@\n def render_page(name):\n     def _escape(value):\n'
               '-        return value.replace("<", "&lt;")\n+        return value.replace("&", "&amp;").replace("<", "&lt;")\n'
               '     return "<p>" + _escape(name) + "</p>"\n')


class TestN7NestedFunctionAttribution:
    def test_nested_function_edit_is_charged_to_the_enclosing_function(self, tmp_path):
        root = _repo(tmp_path, {"core.py": RENDER, **_callers("core", "render_page")})
        report, safety = _analyze(root, NESTED_EDIT)
        assert report.changed_symbols == ["render_page"]
        _not_low(report, safety)

    def test_doubly_nested_and_inner_class(self, tmp_path):
        src = ("def outer(x):\n    class Helper:\n        def run(self, y):\n            def leaf(z):\n"
               "                return z * 2\n            return leaf(y)\n    return Helper().run(x)\n")
        root = _repo(tmp_path, {"core.py": src, **_callers("core", "outer")})
        diff = ("--- a/core.py\n+++ b/core.py\n@@ -4,3 +4,3 @@\n             def leaf(z):\n"
                "-                return z * 2\n+                return z * 3\n             return leaf(y)\n")
        report, safety = _analyze(root, diff)
        assert report.changed_symbols == ["outer"]
        _not_low(report, safety)

    def test_method_helper_is_charged_to_the_method(self, tmp_path):
        src = ("class Service:\n    def handle(self, x):\n        def check(y):\n            return y > 0\n"
               "        return check(x)\n")
        root = _repo(tmp_path, {"svc.py": src, **{f"c{i}.py": "from svc import Service\nService().handle(1)\n"
                                                  for i in range(4)}})
        diff = ("--- a/svc.py\n+++ b/svc.py\n@@ -3,2 +3,2 @@\n         def check(y):\n"
                "-            return y > 0\n+            return y >= 0\n")
        report, _ = _analyze(root, diff)
        assert report.changed_symbols == ["handle"]

    # -- ordinary attribution is unchanged --
    def test_plain_method_keeps_its_own_name(self, tmp_path):
        src = "class Service:\n    LIMIT = 3\n\n    def handle(self, x):\n        return x + 1\n"
        root = _repo(tmp_path, {"svc.py": src})
        diff = ("--- a/svc.py\n+++ b/svc.py\n@@ -4,2 +4,2 @@\n     def handle(self, x):\n"
                "-        return x + 1\n+        return x + 2\n")
        report, _ = _analyze(root, diff)
        assert report.changed_symbols == ["handle"]

    def test_class_level_assignment_keeps_its_own_name(self, tmp_path):
        src = "class Service:\n    LIMIT = 3\n\n    def handle(self, x):\n        return x + 1\n"
        root = _repo(tmp_path, {"svc.py": src})
        diff = "--- a/svc.py\n+++ b/svc.py\n@@ -1,2 +1,2 @@\n class Service:\n-    LIMIT = 3\n+    LIMIT = 4\n"
        report, _ = _analyze(root, diff)
        assert report.changed_symbols == ["LIMIT"]

    def test_nested_edit_in_an_uncalled_function_stays_low(self, tmp_path):
        """Not inflated: the enclosing function itself has no callers."""
        root = _repo(tmp_path, {"core.py": RENDER})
        report, safety = _analyze(root, NESTED_EDIT)
        assert report.changed_symbols == ["render_page"]
        assert report.impact_level == "low" and safety == "Low Risk"


# ---------------------------------------------------------------------------
# N8 -- a hunk is placed where git applies it, never at the first identical
# text.
# ---------------------------------------------------------------------------

BODY = "    first = x + 1\n    second = first * 2\n    result = second + 5\n    return result\n"
DUPLICATED = "def unused(x):\n" + BODY + "\n\ndef calculate(x):\n" + BODY
# `calculate` starts at line 8; its body lines are 9-12.


def _body_edit(old_start: int) -> str:
    return (f"--- a/item.py\n+++ b/item.py\n@@ -{old_start},3 +{old_start},3 @@\n     second = first * 2\n"
            "-    result = second + 5\n+    result = second + 6\n     return result\n")


class TestN8DuplicateHunkLocation:
    def test_header_picks_the_later_identical_copy(self, tmp_path):
        root = _repo(tmp_path, {"item.py": DUPLICATED, **_callers("item", "calculate")})
        report, safety = _analyze(root, _body_edit(10))
        assert report.changed_symbols == ["calculate"]
        _not_low(report, safety)

    def test_header_picks_the_earlier_identical_copy(self, tmp_path):
        root = _repo(tmp_path, {"item.py": DUPLICATED, **_callers("item", "calculate")})
        report, _ = _analyze(root, _body_edit(3))
        assert report.changed_symbols == ["unused"]

    @pytest.mark.parametrize("old_start", [6, 40], ids=["between-copies", "past-end"])
    def test_header_naming_no_copy_abstains(self, tmp_path, old_start):
        root = _repo(tmp_path, {"item.py": DUPLICATED, **_callers("item", "calculate")})
        report, safety = _analyze(root, _body_edit(old_start))
        assert report.impact_level == "unavailable"
        _not_low(report, safety)

    def test_duplicated_partial_match_abstains_without_a_header_match(self, tmp_path):
        """The hunk's full context matches nowhere; its longest matching run
        occurs in both functions."""
        root = _repo(tmp_path, {"item.py": DUPLICATED, **_callers("item", "calculate")})
        diff = ("--- a/item.py\n+++ b/item.py\n@@ -30,4 +30,4 @@\n     second = first * 2\n"
                "-    result = second + 5\n+    result = second + 6\n     return result\n     # gone\n")
        _not_low(*_analyze(root, diff))

    def test_unique_hunk_with_a_drifted_header_is_still_located(self, tmp_path):
        """Content still decides a unique match (the module's original
        guarantee against drifted LLM headers)."""
        src = "def unused(x):\n    return x\n\n\ndef calculate(x):\n" + BODY
        root = _repo(tmp_path, {"item.py": src, **_callers("item", "calculate")})
        report, safety = _analyze(root, _body_edit(40))
        assert report.changed_symbols == ["calculate"]
        _not_low(report, safety)
