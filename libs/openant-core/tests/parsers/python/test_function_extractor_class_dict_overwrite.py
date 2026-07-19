"""Regression lock: a class re-declared under the same name in one file must not be
overwritten (last-write-wins) in `self.classes`, which would drop the first declaration's
bases and methods and sever its inheritance edges.

Pattern: a conditional / platform-branch / redefined class shares its `path:ClassName`
key with the other declaration. The extractor keyed both on `f"{path}:{name}"` and did
`self.classes[class_id] = class_data`, so the second declaration clobbered the first --
its bases (used by super()/inheritance resolution in call_graph_builder) vanished.
The fix merges same-key declarations (union of bases/methods/decorators).
"""
import tempfile
from pathlib import Path

from parsers.python.function_extractor import FunctionExtractor


def _repo(files: dict) -> str:
    d = Path(tempfile.mkdtemp())
    for name, src in files.items():
        (d / name).write_text(src)
    return str(d)


def test_redefined_class_does_not_drop_bases_and_methods():
    repo = _repo({
        "mod.py": (
            "class Foo(BaseA):\n"
            "    def a(self):\n"
            "        return 1\n"
            "\n"
            "class Foo(BaseB):\n"
            "    def b(self):\n"
            "        return 2\n"
        ),
    })
    res = FunctionExtractor(repo).extract_all(["mod.py"])
    cls = res["classes"]["mod.py:Foo"]
    # Both declarations' bases survive -- neither inheritance edge is severed.
    assert "BaseA" in cls["bases"], f"BaseA dropped by overwrite: {cls['bases']}"
    assert "BaseB" in cls["bases"], f"BaseB dropped: {cls['bases']}"
    # Both declarations' methods survive.
    assert "a" in cls["methods"], f"method a dropped by overwrite: {cls['methods']}"
    assert "b" in cls["methods"], f"method b dropped: {cls['methods']}"


def test_conditional_class_branches_merge():
    repo = _repo({
        "plat.py": (
            "import sys\n"
            "if sys.platform == 'win32':\n"
            "    class Widget(WinBase):\n"
            "        def win_only(self):\n"
            "            return 1\n"
            "else:\n"
            "    class Widget(PosixBase):\n"
            "        def posix_only(self):\n"
            "            return 2\n"
        ),
    })
    res = FunctionExtractor(repo).extract_all(["plat.py"])
    cls = res["classes"]["plat.py:Widget"]
    assert {"WinBase", "PosixBase"} <= set(cls["bases"]), cls["bases"]
    assert {"win_only", "posix_only"} <= set(cls["methods"]), cls["methods"]
