"""Shared fixtures for OpenAnt tests."""
import sys
from pathlib import Path

import pytest

# Ensure the project root is on sys.path so imports like `from utilities...` work
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_PYTHON_REPO = FIXTURES_DIR / "sample_python_repo"
SAMPLE_JS_REPO = FIXTURES_DIR / "sample_js_repo"


@pytest.fixture
def sample_python_repo():
    """Path to the sample Python repository fixture."""
    return str(SAMPLE_PYTHON_REPO)


@pytest.fixture
def sample_js_repo():
    """Path to the sample JavaScript repository fixture."""
    return str(SAMPLE_JS_REPO)


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Temporary output directory for parser results."""
    return str(tmp_path / "output")
