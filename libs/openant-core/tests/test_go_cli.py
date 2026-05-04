"""Integration tests for the Go CLI wrapper (openant.exe).

These tests invoke the real compiled binary and verify it correctly
delegates to the Python core. They test the wrapper, not the LLM pipeline —
so they use parse-only commands that don't require an API key.
"""
import json
import os
import subprocess
import shutil
import sys
from pathlib import Path

import pytest

CLI_DIR = Path(__file__).parent.parent.parent.parent / "apps" / "openant-cli"
BINARY_NAME = "openant.exe" if sys.platform == "win32" else "openant"
BINARY = CLI_DIR / BINARY_NAME

pytestmark = pytest.mark.skipif(
    not BINARY.exists(),
    reason=f"Go binary not built at {BINARY}. Run: cd apps/openant-cli && go build -o {BINARY_NAME} .",
)


def run_cli(*args, env_override=None):
    """Run the openant CLI binary and return the CompletedProcess."""
    env = os.environ.copy()
    # Don't let the test hit any real API
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("OPENANT_LOCAL_CLAUDE", None)
    # Pin the Go CLI to the exact interpreter running pytest. This:
    #   - blocks a developer's shell-exported OPENANT_PYTHON from changing
    #     which interpreter the Go CLI resolves under test;
    #   - guarantees the Go CLI uses the same Python that the test setup
    #     pip-installed `openant` into, instead of whatever `python3` happens
    #     to resolve to on the runner's PATH (which is not the same Python
    #     on macOS/Windows GitHub runners).
    env["OPENANT_PYTHON"] = sys.executable
    if env_override:
        env.update(env_override)
    return subprocess.run(
        [str(BINARY)] + list(args),
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


class TestVersion:
    def test_version_runs(self):
        result = run_cli("version")
        assert result.returncode == 0
        assert "openant" in result.stderr.lower() or "openant" in result.stdout.lower()

    def test_version_subcommand(self):
        result = run_cli("version")
        assert result.returncode == 0


class TestHelp:
    def test_help(self):
        result = run_cli("--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "scan" in output
        assert "parse" in output

    def test_parse_help(self):
        result = run_cli("parse", "--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "repository" in output.lower()

    def test_scan_help(self):
        result = run_cli("scan", "--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "pipeline" in output.lower()


class TestParse:
    def test_parse_python_repo(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
            "--json",
        )
        assert result.returncode == 0

        envelope = json.loads(result.stdout)
        assert envelope["status"] == "success"

    def test_parse_produces_dataset(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
        )
        dataset = Path(output_dir) / "dataset.json"
        assert dataset.exists()
        data = json.loads(dataset.read_text())
        assert "units" in data
        assert len(data["units"]) > 0

    def test_parse_auto_detect(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--json",
        )
        assert result.returncode == 0
        envelope = json.loads(result.stdout)
        assert envelope["status"] == "success"

    def test_parse_js_repo(self, sample_js_repo, tmp_path):
        """JS parsing via Go CLI. May fail if the Go CLI finds system Python
        instead of the venv (missing anthropic package).
        """
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_js_repo,
            "--output", output_dir,
            "--language", "javascript",
            "--json",
        )
        if result.returncode != 0 and "No module named" in result.stderr:
            if sys.platform == "win32":
                pytest.skip("Go CLI using system Python without required packages (Windows)")
            else:
                pytest.fail("Go CLI resolved wrong Python (missing required packages)")
        if result.returncode != 0 and "UnicodeEncodeError" in result.stderr:
            pytest.fail("UnicodeEncodeError from JS parser (unexpected regression)")
        assert result.returncode == 0
        envelope = json.loads(result.stdout)
        assert envelope["status"] == "success"

    def test_parse_missing_repo(self, tmp_path):
        result = run_cli(
            "parse", str(tmp_path / "nonexistent"),
            "--output", str(tmp_path / "out"),
        )
        assert result.returncode != 0

    def test_parse_json_output_is_valid(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--json",
        )
        # Should always produce valid JSON on stdout when --json is used
        envelope = json.loads(result.stdout)
        assert "status" in envelope


class TestApiKeyHandling:
    def test_scan_requires_api_key(self, sample_python_repo):
        """Scan should fail without an API key."""
        result = run_cli("scan", sample_python_repo, "--skip-dynamic-test")
        output = result.stderr + result.stdout
        assert result.returncode != 0
        assert "api key" in output.lower()
