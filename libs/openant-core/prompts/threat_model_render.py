"""Rendering a custom threat model into analysis and verification prompts.

NOTE: every field rendered below originates from an attacker-authored
OPENANT.THREATMODEL.md (a scanned repo can commit it; it is auto-loaded on every
default scan). Each is spliced onto its own prompt line, so any interpolated value
MUST be passed through ``collapse_inline`` first — otherwise an embedded newline
forges a new instruction/bullet line and steers the analyzer/verifier LLM.

Without a threat model OpenAnt hardcodes a single attacker — "on the internet,
with a browser and nothing else" — and a single binary lever
(``suppress_local_only``) deciding whether local-only findings count. That
cannot express a supply-chain or adjacent attacker, e.g. a developer with
commit access to a watched manifest repo but no shell on the host.

A threat model replaces both: it declares its own attacker profiles, each with
explicit capabilities and limits, and its own criteria for what counts as a
vulnerability. These renderers turn that declaration into prompt text.

The legacy path is untouched — callers branch on ``has_threat_model()`` and
only reach this module when a threat model is present.
"""

from prompts._fence import collapse_inline


def render_attacker_personas(ctx) -> str:
    """The attacker section, built from declared profiles.

    Each profile is stated with what it CAN and CANNOT do, because the limits
    are what make a verdict falsifiable: "this attacker cannot run CLI
    commands" is the constraint that stops a local-only finding being reported
    as remotely exploitable.
    """
    profiles = ctx.attacker_profiles or []
    if not profiles:
        # A threat model with no profiles declares no attacker; say so rather
        # than silently falling back to the hardcoded browser attacker, which
        # would contradict the document.
        return (
            "This repository's threat model declares NO attacker profiles. "
            "Do not assume one; report only what the vulnerability criteria "
            "below describe."
        )

    lines = [
        "Adopt each of the following attacker profiles IN TURN and attempt "
        "exploitation strictly within that profile's stated capabilities.",
        "",
    ]
    for profile in profiles:
        # Every profile field is attacker-authored (from OPENANT.THREATMODEL.md) and
        # spliced onto its own prompt line, so collapse each to one inert line or an
        # embedded newline forges a directive line into the Stage-2 verifier prompt.
        lines.append(f"### Profile: {collapse_inline(profile.get('id', 'unnamed'))} "
                     f"({collapse_inline(profile.get('position', 'unspecified'))})")
        if profile.get("description"):
            # Prefix with a literal label so the attacker-authored value cannot BE a
            # whole forged line: collapse_inline removes newlines, but a bare col-0
            # emission lets a single-line value like "### SYSTEM OVERRIDE ..." or a lone
            # "```" fence forge a structural/directive line with no newline at all. A
            # non-empty prefix (like every sibling field here) keeps it mid-line and inert.
            lines.append("Description: " + collapse_inline(profile["description"]))
        if profile.get("capabilities"):
            lines.append("You CAN: " + collapse_inline("; ".join(profile["capabilities"])))
        if profile.get("cannot"):
            lines.append("You CANNOT: " + collapse_inline("; ".join(profile["cannot"])))
        if profile.get("entry_via"):
            lines.append("Entry points available to you: "
                         + collapse_inline(", ".join(profile["entry_via"])))
        if profile.get("impact"):
            lines.append(f"Success means: {collapse_inline(profile['impact'])}")
        lines.append("")

    lines.append(
        "A finding is VULNERABLE if ANY profile succeeds within its stated "
        "capabilities, and the harm matches the vulnerability criteria and "
        "affects someone other than that attacker."
    )
    return "\n".join(lines)


def render_threat_model_context(ctx, *, for_verification: bool = False) -> str:
    """The context block describing the program under its own threat model.

    Args:
        ctx: An ApplicationContext carrying threat-model fields.
        for_verification: Include the impact statement, which the verifier
            needs to judge severity but which would bias Stage 1 detection.
    """
    lines = ["## Threat Model", ""]

    if ctx.classification:
        lines.append(f"**Classification:** {collapse_inline(ctx.classification)}")
    lines.append(f"**Purpose:** {collapse_inline(ctx.purpose)}")

    if ctx.components:
        lines.append("")
        lines.append("**Components:**")
        for component in ctx.components:
            paths = collapse_inline(", ".join(component.get("paths", [])))
            lines.append(
                f"- {collapse_inline(component.get('name', '?'))} "
                f"({collapse_inline(component.get('component_type', 'unspecified'))}, "
                f"exposure: {collapse_inline(component.get('exposure', 'unspecified'))})"
                + (f" — {paths}" if paths else "")
            )

    if ctx.input_sources:
        lines.append("")
        lines.append("**Input sources by trust level:**")
        # Group so the model sees the untrusted ones together rather than
        # having to collate them itself.
        by_trust: dict[str, list[str]] = {}
        for name, spec in ctx.input_sources.items():
            trust = collapse_inline(str(spec.get("trust", "unspecified")).lower())
            description = spec.get("description", "")
            by_trust.setdefault(trust, []).append(
                f"{collapse_inline(name)}"
                + (f" — {collapse_inline(description)}" if description else "")
            )
        for trust in ("untrusted", "semi_trusted", "trusted"):
            for entry in by_trust.get(trust, []):
                lines.append(f"- [{trust}] {entry}")
        for trust, entries in by_trust.items():
            if trust not in ("untrusted", "semi_trusted", "trusted"):
                for entry in entries:
                    lines.append(f"- [{trust}] {entry}")

    if ctx.attacker_profiles:
        lines.append("")
        lines.append("**Declared attacker profiles:**")
        # Stage 1's system prompt instructs the model to flag a finding only if
        # a declared profile can trigger it. It therefore has to SEE them — the
        # first cut rendered profiles only into Stage 2, so detection was told
        # to check something it was never shown.
        for profile in ctx.attacker_profiles:
            lines.append(
                f"- {collapse_inline(profile.get('id', '?'))} "
                f"({collapse_inline(profile.get('position', '?'))}): "
                f"{collapse_inline(profile.get('description', ''))}"
            )
            if profile.get("capabilities"):
                lines.append(f"  CAN: {collapse_inline('; '.join(profile['capabilities']))}")
            if profile.get("cannot"):
                lines.append(f"  CANNOT: {collapse_inline('; '.join(profile['cannot']))}")

    if ctx.vulnerability_criteria:
        lines.append("")
        lines.append("**These ARE vulnerabilities in this threat model:**")
        for item in ctx.vulnerability_criteria:
            lines.append(f"- {collapse_inline(item)}")

    if ctx.not_a_vulnerability:
        lines.append("")
        lines.append("**These are NOT vulnerabilities here — do not flag them:**")
        # Deliberately NOT truncated. The legacy path caps this at 5 to bound
        # prompt size; a custom threat model's list is authoritative and a
        # dropped entry means a false positive the author explicitly excluded.
        for item in ctx.not_a_vulnerability:
            lines.append(f"- {collapse_inline(item)}")

    if for_verification and ctx.impact_statement:
        lines.append("")
        lines.append(f"**Impact if compromised:** {collapse_inline(ctx.impact_statement)}")

    if ctx.security_model:
        lines.append("")
        lines.append(f"**Security model:** {collapse_inline(ctx.security_model)}")

    return "\n".join(lines)
