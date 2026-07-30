"""Swift repository-scanner tests: anchored test detection, case-insensitive
extension, generated-dir exclusion (the recurring 'anchoring beats substring'
family from the OpenAnt PR history)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import RepositoryScanner  # noqa: E402


def _scan(tmp_path, files, skip_tests=True):
    for name, src in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    res = RepositoryScanner(str(tmp_path), skip_tests=skip_tests).scan()
    return {f["path"] for f in res["files"]}


def test_case_insensitive_extension(tmp_path):
    found = _scan(tmp_path, {"A.SWIFT": "func a(){}", "B.Swift": "func b(){}"})
    assert {"A.SWIFT", "B.Swift"} <= found


def test_test_file_and_dir_anchoring(tmp_path):
    found = _scan(tmp_path, {
        "Sources/Server.swift": "func s(){}",
        "Sources/latest.swift": "func l(){}",        # 'latest' is NOT a test
        "Sources/ServerTests.swift": "func t(){}",   # anchored suffix -> test
        "Tests/AppTests/FooTests.swift": "func f(){}",  # test dir
    }, skip_tests=True)
    assert "Sources/Server.swift" in found
    assert "Sources/latest.swift" in found, "'latest.swift' must not be treated as a test"
    assert "Sources/ServerTests.swift" not in found
    assert "Tests/AppTests/FooTests.swift" not in found


def test_test_files_included_when_not_skipping(tmp_path):
    found = _scan(tmp_path, {
        "Sources/Server.swift": "func s(){}",
        "Tests/AppTests/FooTests.swift": "func f(){}",
    }, skip_tests=False)
    assert "Tests/AppTests/FooTests.swift" in found


def test_generated_dirs_excluded(tmp_path):
    found = _scan(tmp_path, {
        "Sources/App.swift": "func a(){}",
        ".build/gen.swift": "func g(){}",
        "Pods/Dep/Dep.swift": "func d(){}",
        "DerivedData/x.swift": "func x(){}",
    })
    assert found == {"Sources/App.swift"}
