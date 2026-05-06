"""Tests for the Python parser phases (scanner, extractor, call graph, unit generator)."""
import sys
from pathlib import Path

import pytest

# The parser modules use relative imports, so we need to add the parsers/python dir
PARSERS_DIR = Path(__file__).parent.parent / "parsers" / "python"
if str(PARSERS_DIR) not in sys.path:
    sys.path.insert(0, str(PARSERS_DIR))

from repository_scanner import RepositoryScanner
from function_extractor import FunctionExtractor
from call_graph_builder import CallGraphBuilder
from unit_generator import UnitGenerator


class TestRepositoryScanner:
    def test_finds_python_files(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        result = scanner.scan()
        assert result["statistics"]["total_files"] == 3
        paths = [f["path"] for f in result["files"]]
        assert any("app.py" in p for p in paths)
        assert any("db.py" in p for p in paths)
        assert any("utils.py" in p for p in paths)

    def test_skip_tests_option(self, tmp_path):
        (tmp_path / "main.py").write_text("pass")
        (tmp_path / "test_main.py").write_text("pass")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text("pass")

        scanner = RepositoryScanner(str(tmp_path), {"skip_tests": True})
        result = scanner.scan()
        paths = [f["path"] for f in result["files"]]
        assert any("main.py" in p for p in paths)
        assert not any("test_main.py" in p for p in paths)
        assert not any("test_foo.py" in p for p in paths)

    def test_records_file_sizes(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        result = scanner.scan()
        for f in result["files"]:
            assert "size" in f
            assert f["size"] > 0

    def test_empty_repo(self, tmp_path):
        scanner = RepositoryScanner(str(tmp_path))
        result = scanner.scan()
        assert result["statistics"]["total_files"] == 0
        assert result["files"] == []


class TestFunctionExtractor:
    def test_extracts_functions(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        scan_result = scanner.scan()
        extractor = FunctionExtractor(sample_python_repo)
        result = extractor.extract_from_scan(scan_result)

        assert "functions" in result
        assert len(result["functions"]) > 0

    def test_finds_known_functions(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        scan_result = scanner.scan()
        extractor = FunctionExtractor(sample_python_repo)
        result = extractor.extract_from_scan(scan_result)

        func_names = [f["name"] for f in result["functions"].values()]
        assert "get_user" in func_names
        assert "create_user" in func_names
        assert "get_connection" in func_names
        assert "sanitize_input" in func_names
        assert "validate_email" in func_names

    def test_extracts_route_handlers(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        scan_result = scanner.scan()
        extractor = FunctionExtractor(sample_python_repo)
        result = extractor.extract_from_scan(scan_result)

        func_names = [f["name"] for f in result["functions"].values()]
        assert "get_user_endpoint" in func_names
        assert "create_user_endpoint" in func_names

    def test_captures_decorators(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        scan_result = scanner.scan()
        extractor = FunctionExtractor(sample_python_repo)
        result = extractor.extract_from_scan(scan_result)

        # Find the get_user_endpoint function
        endpoint_funcs = [
            f for f in result["functions"].values()
            if f["name"] == "get_user_endpoint"
        ]
        assert len(endpoint_funcs) == 1
        assert len(endpoint_funcs[0]["decorators"]) > 0

    def test_statistics(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        scan_result = scanner.scan()
        extractor = FunctionExtractor(sample_python_repo)
        result = extractor.extract_from_scan(scan_result)

        stats = result["statistics"]
        assert stats["total_functions"] > 0
        assert stats["files_processed"] == 3

    def test_function_has_code(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        scan_result = scanner.scan()
        extractor = FunctionExtractor(sample_python_repo)
        result = extractor.extract_from_scan(scan_result)

        for func in result["functions"].values():
            assert "code" in func
            assert len(func["code"]) > 0


class TestCallGraphBuilder:
    @pytest.fixture
    def extractor_result(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        scan_result = scanner.scan()
        extractor = FunctionExtractor(sample_python_repo)
        return extractor.extract_from_scan(scan_result)

    def test_builds_call_graph(self, extractor_result):
        builder = CallGraphBuilder(extractor_result)
        builder.build_call_graph()
        result = builder.export()

        assert "call_graph" in result
        assert "reverse_call_graph" in result

    def test_detects_calls(self, extractor_result):
        builder = CallGraphBuilder(extractor_result)
        builder.build_call_graph()
        result = builder.export()

        # get_user_endpoint calls get_user
        endpoint_key = [k for k in result["call_graph"] if "get_user_endpoint" in k]
        assert len(endpoint_key) > 0
        callees = result["call_graph"][endpoint_key[0]]
        callee_names = [c.split(":")[-1] for c in callees]
        assert "get_user" in callee_names

    def test_reverse_graph(self, extractor_result):
        builder = CallGraphBuilder(extractor_result)
        builder.build_call_graph()
        result = builder.export()

        # get_user should be called by get_user_endpoint
        get_user_key = [k for k in result["reverse_call_graph"] if k.endswith(":get_user")]
        assert len(get_user_key) > 0

    def test_statistics(self, extractor_result):
        builder = CallGraphBuilder(extractor_result)
        builder.build_call_graph()
        result = builder.export()

        stats = result["statistics"]
        assert stats["total_edges"] > 0
        assert "avg_out_degree" in stats


class TestUnitGenerator:
    @pytest.fixture
    def call_graph_result(self, sample_python_repo):
        scanner = RepositoryScanner(sample_python_repo)
        scan_result = scanner.scan()
        extractor = FunctionExtractor(sample_python_repo)
        extractor_result = extractor.extract_from_scan(scan_result)
        builder = CallGraphBuilder(extractor_result)
        builder.build_call_graph()
        return builder.export()

    def test_generates_units(self, call_graph_result):
        generator = UnitGenerator(call_graph_result)
        dataset = generator.generate_units()

        assert "units" in dataset
        assert len(dataset["units"]) > 0

    def test_units_have_id_and_code(self, call_graph_result):
        generator = UnitGenerator(call_graph_result)
        dataset = generator.generate_units()

        for unit in dataset["units"]:
            assert "id" in unit
            assert "code" in unit
            assert "primary_code" in unit["code"]

    def test_units_have_metadata(self, call_graph_result):
        generator = UnitGenerator(call_graph_result)
        dataset = generator.generate_units()

        for unit in dataset["units"]:
            assert "metadata" in unit
            assert "unit_type" in unit

    def test_enhanced_code_includes_dependencies(self, call_graph_result):
        generator = UnitGenerator(call_graph_result)
        dataset = generator.generate_units()

        # get_user_endpoint should have get_user's code included
        endpoint_units = [u for u in dataset["units"] if "get_user_endpoint" in u["id"]]
        assert len(endpoint_units) == 1
        code = endpoint_units[0]["code"]["primary_code"]
        assert "get_user" in code

    def test_statistics(self, call_graph_result):
        generator = UnitGenerator(call_graph_result)
        dataset = generator.generate_units()

        assert "statistics" in dataset
        assert dataset["statistics"]["total_units"] == len(dataset["units"])
