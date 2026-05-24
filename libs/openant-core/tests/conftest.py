"""Shared fixtures for OpenAnt tests."""
import sys
from pathlib import Path

import pytest

# Ensure the project root is on sys.path so imports like `from utilities...` work
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Several test files defensively stub ``sys.modules["anthropic"]`` if the
# real SDK isn't loaded yet (a legacy guard from before anthropic became a
# hard dep). Now that core modules no longer eagerly import the SDK at
# module load (issue #65 moved provider IO behind the adapter layer), the
# first-loaded test that runs the guard would install the stub — and then
# the Anthropic adapter contract tests fail with ``Cannot spec a Mock
# object``. Claim the slot here with the real module so the guards become
# no-ops. The SDK is in requirements.txt so the import is guaranteed to
# succeed in any environment that runs the test suite.
import anthropic  # noqa: F401,E402 — see comment above

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
