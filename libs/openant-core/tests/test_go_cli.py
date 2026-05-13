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

    def test_scan_help_advertises_llm_reachability(self):
        """The opt-in --llm-reachability flag (issue #17) should be discoverable
        from `openant scan --help`."""
        result = run_cli("scan", "--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "llm-reachability" in output.lower()


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


class TestInit:
    """Integration tests for ``openant init`` covering item 13 of #16:
    auto-detect language and tolerate non-git directories.
    """

    @pytest.fixture
    def isolated_home(self, tmp_path):
        """Override home so init writes into a tmp ~/.openant/."""
        home = str(tmp_path / "fakehome")
        os.makedirs(home)
        # USERPROFILE for Windows, HOME for Unix.
        return {"USERPROFILE": home, "HOME": home}

    def _read_project_json(self, home_dir, project_name):
        project_json = (
            Path(home_dir)
            / ".openant"
            / "projects"
            / project_name
            / "project.json"
        )
        assert project_json.exists(), (
            f"project.json not found at {project_json}"
        )
        return json.loads(project_json.read_text())

    @staticmethod
    def _make_repo(tmp_path, name, files):
        repo = tmp_path / name
        repo.mkdir()
        for rel, content in files.items():
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        return repo

    def test_auto_detect_python_from_fixture(
        self, sample_python_repo, isolated_home
    ):
        """Init with -l auto on a Python fixture detects ``python``."""
        result = run_cli(
            "init", sample_python_repo,
            "--name", "test/python-repo",
            "-l", "auto",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "Detected language: python" in result.stderr

        project = self._read_project_json(
            isolated_home["HOME"], "test/python-repo",
        )
        assert project["language"] == "python"

    def test_auto_detect_javascript_from_fixture(
        self, sample_js_repo, isolated_home
    ):
        """Init with -l auto on a JS fixture detects ``javascript``."""
        result = run_cli(
            "init", sample_js_repo,
            "--name", "test/js-repo",
            "-l", "auto",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "Detected language: javascript" in result.stderr

        project = self._read_project_json(
            isolated_home["HOME"], "test/js-repo",
        )
        assert project["language"] == "javascript"

    def test_auto_detect_typescript_synthetic(self, tmp_path, isolated_home):
        """A TS-only tree (no .git) is detected as ``javascript``."""
        repo = self._make_repo(
            tmp_path, "ts_repo",
            {
                "src/app.ts": "export const x = 1;\n",
                "src/comp.tsx": "export default () => null;\n",
                "src/util.ts": "export const y = 2;\n",
            },
        )
        result = run_cli(
            "init", str(repo),
            "--name", "test/ts-synth",
            "-l", "auto",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "Detected language: javascript" in result.stderr

        project = self._read_project_json(
            isolated_home["HOME"], "test/ts-synth",
        )
        assert project["language"] == "javascript"

    def test_auto_detect_go_synthetic(self, tmp_path, isolated_home):
        """A Go-only tree (no .git) is detected as ``go``."""
        repo = self._make_repo(
            tmp_path, "go_repo",
            {
                "main.go": "package main\nfunc main() {}\n",
                "internal/svc.go": "package internal\n",
                "cmd/cli.go": "package cmd\n",
            },
        )
        result = run_cli(
            "init", str(repo),
            "--name", "test/go-synth",
            "-l", "auto",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "Detected language: go" in result.stderr

        project = self._read_project_json(
            isolated_home["HOME"], "test/go-synth",
        )
        assert project["language"] == "go"

    def test_explicit_language_overrides_auto_detect(
        self, sample_python_repo, isolated_home
    ):
        """An explicit ``-l`` flag wins over auto-detection."""
        result = run_cli(
            "init", sample_python_repo,
            "--name", "test/explicit-lang",
            "-l", "go",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        # Auto-detect path must not run when -l is supplied.
        assert "Auto-detecting" not in result.stderr

        project = self._read_project_json(
            isolated_home["HOME"], "test/explicit-lang",
        )
        assert project["language"] == "go"

    def test_non_git_directory_uses_nogit_sha(self, tmp_path, isolated_home):
        """Init on a plain (non-.git) dir succeeds with ``nogit`` placeholder."""
        repo = self._make_repo(
            tmp_path, "plain_repo",
            {"main.py": "print('hello')\n"},
        )
        # Sanity: not a git repo.
        assert not (repo / ".git").exists()

        result = run_cli(
            "init", str(repo),
            "--name", "test/no-git",
            "-l", "auto",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"

        project = self._read_project_json(
            isolated_home["HOME"], "test/no-git",
        )
        assert project["language"] == "python"
        assert project["commit_sha"] == "nogit"
        assert project["commit_sha_short"] == "nogit"

    def test_non_git_directory_warns_on_commit_flag(
        self, tmp_path, isolated_home
    ):
        """``--commit`` on a non-git directory warns and falls back to ``nogit``."""
        repo = self._make_repo(
            tmp_path, "plain_repo",
            {"main.py": "print('hello')\n"},
        )
        result = run_cli(
            "init", str(repo),
            "--name", "test/no-git-commit",
            "--commit", "abc123",
            "-l", "auto",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "ignored" in result.stderr.lower()

        project = self._read_project_json(
            isolated_home["HOME"], "test/no-git-commit",
        )
        assert project["commit_sha"] == "nogit"

    def test_empty_dir_fails_with_clear_error(self, tmp_path, isolated_home):
        """Init on a directory with no source files fails cleanly."""
        empty = tmp_path / "empty_repo"
        empty.mkdir()

        result = run_cli(
            "init", str(empty),
            "--name", "test/empty",
            "-l", "auto",
            env_override=isolated_home,
        )
        assert result.returncode != 0
        combined = (result.stderr + result.stdout).lower()
        assert "no supported source files" in combined
