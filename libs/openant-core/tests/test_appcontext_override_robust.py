import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from context.application_context import check_manual_override


def test_numeric_key_ok(tmp_path):
    (tmp_path / "OPENANT.md").write_text(
        "---\napplication_type: cli_tool\npurpose: p\n123: x\n---\n"
    )
    c = check_manual_override(tmp_path)
    assert c and c.application_type == "cli_tool"


def test_empty_yaml_single_file_no_crash(tmp_path):
    (tmp_path / "OPENANT.md").write_text("---\n\n---\nbody\n")
    # raise caught by the loop's except, no other override file -> None
    assert check_manual_override(tmp_path) is None


def test_list_yaml_single_file_no_crash(tmp_path):
    (tmp_path / "OPENANT.md").write_text("---\n- a\n- b\n---\nbody\n")
    assert check_manual_override(tmp_path) is None


def test_precedence_malformed_high_priority_falls_through(tmp_path):
    # OPENANT.md (highest priority) is malformed; OPENANT.json (lower) is valid.
    # Regression: the helper must NOT short-circuit the loop -> the valid json wins.
    (tmp_path / "OPENANT.md").write_text("---\n- not\n- a\n- map\n---\nbody\n")
    (tmp_path / "OPENANT.json").write_text(
        '{"application_type": "web_app", "purpose": "valid override"}'
    )
    c = check_manual_override(tmp_path)
    assert c is not None, "malformed OPENANT.md short-circuited the precedence loop"
    assert c.application_type == "web_app"


def test_unknown_key_override_honored_not_dropped(tmp_path):
    # the primary finding: an unknown key must not discard the whole override
    (tmp_path / "OPENANT.json").write_text(
        '{"application_type":"cli_tool","purpose":"p","bogus":1}'
    )
    c = check_manual_override(tmp_path)
    assert c and c.application_type == "cli_tool"
