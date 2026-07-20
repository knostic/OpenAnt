"""The language registry must survive being installed, not just checked out.

``config/languages.json`` is the single source of truth for the language set. It
lives at the *monorepo* root, while the Python package root is ``libs/openant-core``,
so the wheel shipped without it: the registry resolved to ``{}``, ``-l python`` became
"invalid choice", and detection found zero source files in every repository.

That defect was invisible to the existing tests for a structural reason worth naming.
``test_language_registry_resolution.py`` exercises the search from inside the
checkout, where walking upward always finds the real config — so it passes whether or
not the file is packaged. A test that cannot fail is not coverage. These tests
deliberately leave the checkout.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = CORE_ROOT.parent.parent


def test_wheel_declares_the_config_as_force_include():
    """The packaging declaration itself, so silent removal is caught cheaply.

    Building a wheel per test run is too slow for CI, but losing this stanza is
    exactly how the bug happened, and it is a one-line accident to repeat.
    """
    pyproject = (CORE_ROOT / "pyproject.toml").read_text()
    assert "force-include" in pyproject, (
        "pyproject.toml has no force-include stanza; config/languages.json lives "
        "above the package root and cannot ship without one"
    )
    assert "config/languages.json" in pyproject


def test_the_monorepo_config_exists_where_packaging_expects_it():
    """Guard on the force-include source path.

    This asserts only that the file the wheel stanza points at is really there —
    the real installed-layout proof is ``test_a_built_wheel_carries_the_config``.
    Kept separate and named for what it does, because a moved config would
    otherwise surface as a confusing wheel-build failure rather than a missing file.
    """
    assert (REPO_ROOT / "config" / "languages.json").is_file(), (
        f"expected the language config at {REPO_ROOT / 'config' / 'languages.json'}; "
        "the wheel's force-include stanza points there and will break if it moves"
    )


def test_missing_config_fails_loudly_rather_than_reporting_an_empty_repository(
    tmp_path: Path, monkeypatch
):
    """A broken install must not look like an empty repository.

    ``load_registry()`` degrades to ``{}`` so ``--help`` survives a missing config.
    But detection built on an empty extension map reports "no supported source
    files", which sends the operator to inspect *their repository* when the fault is
    in the installation — a worse outcome than the crash that degradation replaced,
    because it misattributes the cause.

    Go fails loudly on this identical condition, so before this the two runtimes
    disagreed about the same missing file. ``require_registry`` restores the loud
    contract for the paths that need it.
    """
    from core import language_registry as lr

    monkeypatch.setattr(lr, "find_languages_config", lambda: None)
    lr._load_config.cache_clear()
    lr.load_registry.cache_clear()
    try:
        # Describing the language set still degrades quietly: --help must not die.
        assert lr.supported_languages() == []

        # Doing real work must not.
        with pytest.raises(RuntimeError) as exc:
            lr.extension_map()
        message = str(exc.value)
        assert "installation problem" in message, (
            "the error must name the installation as the cause; blaming the scanned "
            "repository is the misattribution this exists to prevent"
        )
    finally:
        lr._load_config.cache_clear()
        lr.load_registry.cache_clear()


@pytest.mark.slow
def test_a_built_wheel_carries_the_config(tmp_path: Path):
    """End-to-end: build a wheel and confirm the config is inside it.

    Marked slow because it shells out to `build`. This is the only assertion here
    that would have caught the original defect on its own — the rest are proxies.
    """
    # sys.executable, not `which python3`: the system interpreter has no `build`
    # module, and picking it turned this into a permanent skip — a test that never
    # runs is indistinguishable from one that passes.
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path),
         str(CORE_ROOT)],
        capture_output=True, text=True, timeout=600,
        env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
    )
    if result.returncode != 0:
        pytest.skip(f"wheel build unavailable here: {result.stderr[-300:]}")

    import zipfile

    wheels = list(tmp_path.glob("*.whl"))
    assert wheels, "no wheel produced"
    names = zipfile.ZipFile(wheels[0]).namelist()
    assert any("languages.json" in n for n in names), (
        f"wheel ships no language config; installed users get zero languages. "
        f"Entries: {[n for n in names if 'config' in n]}"
    )
