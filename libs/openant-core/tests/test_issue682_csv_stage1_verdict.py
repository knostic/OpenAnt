"""#682: the CSV's stage1_verdict exports the STAGE-1 verdict, not the
current finding — after a consistency rewrite.

The consistency apply loop records the original in `consistency_update`
({from, to, ...}) but writes no verification_note, so the CSV's
get_stage1_verdict fell to the agree branch and exported the REWRITTEN
finding as the Stage-1 verdict. The fix: the CSV reads the provenance the
verifier already records (consistency_update.from) — the same
"the original survives" convention the disagreement path's
"Changed from X to Y" note already carries.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from report.csv_export import get_stage1_verdict  # noqa: E402


def test_consistency_rewritten_row_exports_the_stage1_verdict():
    """THE #682 SHAPE: agreed + consistency-rewritten — the column must
    read the ORIGINAL (vulnerable), never the rewritten finding."""
    result = {
        "route_key": "test:f",
        "finding": "protected",
        "verdict": "vulnerable",
        "verification": {"agree": True, "correct_finding": "protected"},
        "consistency_update": {"from": "vulnerable", "to": "protected",
                               "reason": "wave catch", "pattern": "p"},
    }
    got = get_stage1_verdict(result)
    assert got == "vulnerable", (
        f"stage1_verdict must export the Stage-1 verdict, got {got!r} — "
        "the #682 provenance hole (the column promised 'Initial Stage 1 "
        "detection verdict')"
    )


def test_the_no_rewrite_control_unchanged():
    """The control: agree=True, no rewrite — the current finding IS the
    Stage-1 verdict (the pre-existing correct path)."""
    result = {
        "finding": "vulnerable",
        "verdict": "vulnerable",
        "verification": {"agree": True},
    }
    assert get_stage1_verdict(result) == "vulnerable"


def test_the_disagreement_note_path_unchanged():
    """The control: the #623 'Changed from' parse still owns the
    disagreement path (the CSV exports the stored note verbatim)."""
    result = {
        "finding": "protected",
        "verification": {"agree": False},
        "verification_note": "Changed from vulnerable to protected",
    }
    assert get_stage1_verdict(result) == "vulnerable"


def test_the_legacy_insufficient_context_spelling_survives():
    """The #623 BY-DESIGN guard: the provenance export does not fold the
    legacy spelling — the consistency path must not change that either."""
    result = {
        "finding": "insufficient_context",
        "verification": {"agree": True},
        "consistency_update": {"from": "vulnerable", "to": "insufficient_context"},
    }
    got = get_stage1_verdict(result)
    assert got == "vulnerable", (
        f"the consistency_from record is the Stage-1 verdict regardless of "
        f"the destination's spelling — got {got!r}"
    )

def test_the_disagreed_then_rewritten_row_exports_the_stage1_verdict():
    """The T1's F1 shape: a row the verifier DISAGREED (the note carries the
    Stage-1 original) that the consistency pass then rewrote — the record's
    `from` holds Stage-2's correction (raw_old = correct_finding or finding),
    so the NOTE must win; reading the record first would export 'safe' — a
    value that cannot be a Stage-1 verdict (only positives enter Stage 2).
    """
    result = {
        "finding": "protected",
        "verification": {"agree": False},
        "verification_note": "Changed from vulnerable to safe",
        "consistency_update": {"from": "safe", "to": "protected",
                               "reason": "wave catch", "pattern": "p"},
    }
    got = get_stage1_verdict(result)
    assert got == "vulnerable", (
        f"the note (the Stage-1 original) must win over the record's `from` "
        f"(Stage-2's correction on this shape) — got {got!r}"
    )
