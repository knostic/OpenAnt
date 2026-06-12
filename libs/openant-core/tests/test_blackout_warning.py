"""Fix B — reachability blackout warning (advisory; never changes filtering).

The #75 zero-seed net only fires at EXACTLY 0 entry points. A library like
tree-sitter trips a handful of INCIDENTAL seeds (code that merely contains an
input-reading pattern), yielding a 96.6% reduction that looks like a successful
filter while the real public-API core was dropped. `blackout_warning` catches
both the total blackout and this partial-blackout-with-only-incidental-seeds case,
and stays silent for a normal app (real route/main/CLI seeds, moderate reduction).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from utilities.agentic_enhancer import blackout_warning  # noqa: E402


def _details(*reason_lists):
    """Build an entry_point_details-shaped dict from per-seed reason lists."""
    return {f"f{i}": {"reasons": rs} for i, rs in enumerate(reason_lists)}


def test_total_blackout_warns():
    assert blackout_warning(_details(), original_count=500, reachable_count=0) is not None


def test_partial_blackout_incidental_seeds_warns():
    # tree-sitter shape: 4 incidental input_pattern seeds, 712 -> 24 (96.6% pruned).
    details = _details(["input_pattern:fopen"], ["input_pattern:read"],
                       ["input_pattern:getenv"], ["input_pattern:scanf"])
    assert blackout_warning(details, original_count=712, reachable_count=24) is not None


def test_structural_seed_suppresses_even_high_reduction():
    # A real CLI/main seed means the high reduction is legitimate, not a blackout.
    details = _details(["unit_type:main"], ["input_pattern:read"])
    assert blackout_warning(details, original_count=712, reachable_count=24) is None


def test_normal_app_reduction_is_silent():
    # Arkime C shape: route/main seeds, 1655 -> 608 (63% pruned). No warning.
    details = _details(["unit_type:cli_handler"], ["unit_type:main"], ["unit_type:http_handler"])
    assert blackout_warning(details, original_count=1655, reachable_count=608) is None


def test_decorator_and_name_seeds_are_structural():
    assert blackout_warning(_details(["decorator:@app.route"]),
                            original_count=712, reachable_count=24) is None
    assert blackout_warning(_details(["name:main"]),
                            original_count=712, reachable_count=24) is None


def test_library_mode_suppresses_warning():
    # With library-mode on, a high reduction is the intended precise result.
    details = _details(["input_pattern:read"])
    assert blackout_warning(details, original_count=712, reachable_count=24,
                            library_mode=True) is None


def test_empty_dataset_no_warning():
    assert blackout_warning(_details(), original_count=0, reachable_count=0) is None
