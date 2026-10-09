"""Tests for deterministic pytest command discovery."""

from __future__ import annotations

from pathlib import Path

from utilities.autopatcher.pytest_discovery import PYTEST_ARGV, discover_pytest_command


class TestDiscoverPytestCommand:
    def test_pytest_ini_present(self, tmp_path: Path):
        (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        cmd = discover_pytest_command(tmp_path)
        assert cmd is not None
        assert cmd.argv == PYTEST_ARGV
        assert "pytest.ini" in cmd.discovery_reason

    def test_pyproject_tool_pytest_ini_options(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n", encoding="utf-8"
        )
        cmd = discover_pytest_command(tmp_path)
        assert cmd is not None
        assert cmd.argv == PYTEST_ARGV
        assert "pyproject.toml" in cmd.discovery_reason

    def test_pyproject_without_pytest_section_is_no_evidence(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\nname = \"demo\"\n", encoding="utf-8"
        )
        assert discover_pytest_command(tmp_path) is None

    def test_setup_cfg_tool_pytest_section(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text("[tool:pytest]\ntestpaths = tests\n", encoding="utf-8")
        cmd = discover_pytest_command(tmp_path)
        assert cmd is not None
        assert cmd.argv == PYTEST_ARGV
        assert "setup.cfg" in cmd.discovery_reason

    def test_setup_cfg_without_pytest_section_is_no_evidence(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text("[metadata]\nname = demo\n", encoding="utf-8")
        assert discover_pytest_command(tmp_path) is None

    def test_bare_tests_directory_is_not_sufficient(self, tmp_path: Path):
        """MVP deliberately requires explicit pytest configuration -- a
        bare tests/ directory alone is NOT evidence in this slice (see
        pytest_discovery.py's module docstring)."""
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_x.py").write_text("def test_x(): pass\n", encoding="utf-8")
        assert discover_pytest_command(tmp_path) is None

    def test_no_evidence_at_all(self, tmp_path: Path):
        assert discover_pytest_command(tmp_path) is None

    def test_malformed_pyproject_toml_does_not_raise(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("this is not [valid toml", encoding="utf-8")
        assert discover_pytest_command(tmp_path) is None

    def test_malformed_setup_cfg_does_not_raise(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_bytes(b"\x00\x01\x02not an ini file")
        assert discover_pytest_command(tmp_path) is None

    def test_nonexistent_repo_root_does_not_raise(self, tmp_path: Path):
        assert discover_pytest_command(tmp_path / "does-not-exist") is None

    def test_pytest_ini_takes_precedence_order_is_stable(self, tmp_path: Path):
        """All three forms of evidence are equally valid; when more than
        one is present, discovery is still deterministic (pytest.ini
        checked first) and always returns the identical command."""
        (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            "[tool.pytest.ini_options]\n", encoding="utf-8"
        )
        cmd = discover_pytest_command(tmp_path)
        assert cmd is not None
        assert cmd.argv == PYTEST_ARGV

    def test_command_contains_only_junitxml_addition(self):
        """Do not add markers, paths, filters, or xdist -- the only
        addition beyond a bare invocation is --junitxml."""
        assert PYTEST_ARGV[:3] == ("python", "-m", "pytest")
        assert len(PYTEST_ARGV) == 4
        assert PYTEST_ARGV[3].startswith("--junitxml=")
