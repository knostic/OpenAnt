def load_module():
    import utilities.autopatcher.test_suggester as mod
    return mod


def test_extract_findings_from_bullets_and_sections():
    mod = load_module()
    text = """
Edge cases:
- Database drivers that use `%s` placeholders (driver mismatch)
- Unicode and binary username encodings

Potential issues:
- Missing unit tests for edge-case payloads
- Assumes `db.execute` accepts parameterized args as shown
"""
    findings = mod.extract_findings(text)
    # headings/status labels should not be included
    assert not any(f.lower().startswith("still vulnerable") for f in findings)
    assert not any(f.lower().startswith("edge cases") for f in findings)
    assert not any(f.lower().startswith("potential issues") for f in findings)

    # actionable findings should be present
    assert any("unicode and binary" in f.lower() for f in findings)
    assert any("database drivers" in f.lower() or "%s" in f for f in findings)
    assert len(findings) <= 6
    # ensure deterministic ordering: first finding should be the database driver mismatch
    assert findings[0] == "Database drivers that use `%s` placeholders (driver mismatch)"


def test_suggest_tests_creates_valid_skeletons():
    mod = load_module()
    findings = [
        "Unicode and binary username encodings",
        "Database drivers that use %s placeholders",
    ]
    suggestions = mod.suggest_tests(findings)
    assert isinstance(suggestions, list)
    assert len(suggestions) == 2
    for s, f in zip(suggestions, findings):
        assert s["reason"] == f
        assert s["name"].startswith("test_")
        assert "pytest.mark.skip" in s["code"]


def test_limit_findings_to_six():
    mod = load_module()
    # create many bullet lines
    text = "\n".join(f"- finding {i}" for i in range(10))
    findings = mod.extract_findings(text)
    assert len(findings) == 6


def test_suggest_tests_with_behavior_generates_skeletons_and_dedupe():
    mod = load_module()
    # Behavior with function name and two primary behaviors
    behavior = {
        "function": "authenticate",
        "file": "app/auth.py",
        "summary": "Does authentication",
        "primary_behaviors": ["valid login", "invalid login"],
    }

    # No initial findings -> behavior-derived tests should appear
    suggestions = mod.suggest_tests([], behavior=behavior)
    names = [s["name"] for s in suggestions]
    assert "test_authenticate_valid_login" in names
    assert "test_authenticate_invalid_login" in names

    # Dedupe: if findings already produce same name, behaviour test not duplicated
    findings = ["valid login"]
    suggestions2 = mod.suggest_tests(findings, behavior=behavior)
    names2 = [s["name"] for s in suggestions2]
    # only one test for valid_login should exist
    assert names2.count("test_valid_login") + names2.count("test_authenticate_valid_login") >= 1
    # ensure behavior marker in code for at least one suggestion
    assert any("# Behavior-focused validation" in s["code"] for s in suggestions2)
