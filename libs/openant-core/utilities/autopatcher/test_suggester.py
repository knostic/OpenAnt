from typing import List, Dict
import re


def extract_findings(adversarial_text: str) -> List[str]:
    """Extract up to 6 discrete findings from adversarial text.

    Heuristics:
    - Collect bullet lines (starting with '-' or '*') anywhere.
    - Collect lines under headings 'Edge cases' or 'Potential issues' (case-insensitive).
    - Return cleaned strings, deduplicated, up to 6 items.
    """
    if not adversarial_text:
        return []

    lines = adversarial_text.splitlines()
    findings: List[str] = []

    # Helper to clean a bullet/line
    def _clean(s: str) -> str:
        s = s.strip()
        # remove leading bullet markers
        s = re.sub(r"^[\-*\u2022\s]+", "", s)
        # collapse internal whitespace
        s = re.sub(r"\s+", " ", s)
        return s.strip(" .")

    # Helper to detect non-actionable headings/status labels
    heading_re = re.compile(r"^(still vulnerable|edge cases|potential issues|potential issue|edge case|summary)\b", re.IGNORECASE)

    # 1) Global bullets — collect actionable bullets only
    for ln in lines:
        if re.match(r"^\s*[-\*\u2022]\s+", ln):
            txt = _clean(ln)
            if not txt:
                continue
            # skip heading/status labels that are non-actionable
            if heading_re.match(txt):
                continue
            if txt and txt not in findings:
                findings.append(txt)
                if len(findings) >= 6:
                    return findings

    # 2) Sections: Edge cases / Potential issues
    section_re = re.compile(r"^(?:\*\*?)?\s*(Edge cases|Potential issues|Potential issue|Edge case)\s*[:\*]*$", re.IGNORECASE)
    in_section = False
    for ln in lines:
        if section_re.match(ln.strip()):
            in_section = True
            continue
        if in_section:
            if not ln.strip():
                # blank line ends the section
                in_section = False
                continue
            # accept bullet or plain lines within the section
            if re.match(r"^\s*[-\*\u2022]\s+", ln):
                txt = _clean(ln)
            else:
                txt = _clean(ln)
            if not txt:
                continue
            # skip headings/status labels inside sections
            if heading_re.match(txt):
                continue
            if txt and txt not in findings:
                findings.append(txt)
                if len(findings) >= 6:
                    return findings

    # 3) Fallback: any non-empty lines that look like short findings (avoid long paragraphs)
    if not findings:
        for ln in lines:
            txt = ln.strip()
            if not txt:
                continue
            # ignore headings
            if re.match(r"^#{1,6}\s+", txt):
                continue
            if heading_re.match(txt):
                continue
            # prefer short lines < 120 chars
            if len(txt) <= 120:
                cleaned = _clean(txt)
                if cleaned and cleaned not in findings:
                    findings.append(cleaned)
                    if len(findings) >= 6:
                        break

    return findings[:6]


def _safe_name(s: str) -> str:
    # create a short pythonic test name from the finding
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "suggested"
    # build a body capped to ~40 chars at word boundaries to avoid ugly truncation
    max_body = 40
    parts = [p for p in s.split("_") if p]
    body_parts: list[str] = []
    total = 0
    for p in parts:
        add_len = len(p) + (1 if body_parts else 0)
        if total + add_len > max_body:
            break
        body_parts.append(p)
        total += add_len
    body = "_".join(body_parts) if body_parts else s[:max_body]
    body = body.rstrip("_")
    if not body:
        body = s[:max_body]
    return f"test_{body[:45]}"


def suggest_tests(findings: List[str], behavior: dict | None = None) -> List[Dict]:
    """Generate pytest skeletons for each finding.

    Returns a list of dicts with keys: name, code, reason
    If `behavior` is provided, also generate up to 2 conservative
    behavior-derived test skeletons and dedupe by test name.
    """
    out: List[Dict] = []
    for f in findings:
        name = _safe_name(f)
        reason = f
        code = (
            f"# Based on adversarial finding:\n# \"{f}\"\n\n"
            "import pytest\n\n"
            "@pytest.mark.skip(reason=\"Generated from adversarial finding\")\n\n"
            f"def {name}():\n"
            "    # Arrange: create inputs that exercise this finding\n"
            "    # Act: call the patched function or affected flow\n"
            "    # Assert: verify the expected safe behavior\n"
        )
        out.append({"name": name, "code": code, "reason": reason})

    # Behavior-derived suggestions: generate up to 2 tests from
    # behavior['primary_behaviors'] but do so conservatively and
    # dedupe against existing names.
    if behavior:
        func_name = (behavior.get("function") or "").strip()
        # sanitize func_name to pythonic token
        func_token = re.sub(r"[^a-zA-Z0-9]+", "_", func_name).strip("_").lower()
        pbs = (behavior.get("primary_behaviors") or [])[:2]
        existing_names = {s["name"] for s in out}
        for b in pbs:
            # build a safe body name using existing helper
            base = _safe_name(b)  # yields test_<body>
            safe_body = base[len("test_") :] if base.startswith("test_") else base
            if func_token:
                name = f"test_{func_token}_{safe_body}"
            else:
                name = f"test_{safe_body}"

            if name in existing_names:
                continue

            reason = b
            code = (
                "# Behavior-focused validation\n"
                "import pytest\n\n"
                "@pytest.mark.skip(reason=\"Behavior-derived test\")\n"
                f"def {name}():\n"
                "    \"\"\"Behavior-focused validation\"\"\"\n"
                "    assert False\n"
            )
            out.insert(0, {"name": name, "code": code, "reason": reason})
            existing_names.add(name)

    return out
