"""Custom threat models: schema v1, loud validation, and legacy-field derivation.

OpenAnt's built-in security context collapses an entire attacker model into one of
four ``ApplicationType`` values plus a single boolean (``suppress_local_only``). That
cannot express, say, a deployment orchestrator whose real adversary is "a developer
with commit access to a watched manifest repo and no shell on the orchestrator" —
neither the "remote attacker with a browser" nor the "local user with shell access"
persona fits, and picking either one produces systematically wrong verdicts.

A *threat model* replaces the four-value enum with a structured description the repo
author writes: free-form classification, components with free-form component types,
named attacker profiles with explicit CAN/CANNOT capabilities, per-input-source trust
levels, and explicit statements of what is and is not a vulnerability *for this
repository*.

Storage format
--------------
``OPENANT.THREATMODEL.md`` in the scanned repository's root: human-readable markdown
headings for reviewers and PR diffs, plus **one authoritative fenced ```json block**
that is the machine truth. Markdown-with-embedded-JSON is chosen over YAML
frontmatter because ``check_manual_override`` already proves the seam works with the
same regex, LLMs emit fenced JSON far more reliably than nested YAML, and the
frontmatter path depends on an optional PyYAML import that degrades to a *warning* —
precisely the silent failure this module exists to eliminate.

``parse_threat_model_md`` scans **every** json block and selects the one whose parsed
object carries ``"schema": "openant-threat-model"``, so a document whose prose
contains illustrative json blocks (a template, a diff, a worked example) still parses.

Loud failure
------------
``load_threat_model`` returns ``None`` **only** when the file is absent. If the file
exists but is malformed it **raises**. This is a deliberate inversion of
``check_manual_override``'s catch-all ``except Exception: print(warning); continue``.
The rationale is asymmetric blast radius: a broken ``OPENANT.md`` degrades to
LLM-generated context, which is merely worse; a broken ``OPENANT.THREATMODEL.md``
degrades to the default ``"web_app"`` assumption, which silently inverts the entire
security model of a scan that the operator explicitly asked to be threat-model driven
— and the resulting report looks completely successful. A typo must not be able to
produce a confident, wrong answer.

For the same reason ``ThreatModelValidationError`` collects **all** violations rather
than failing fast on the first: a human fixing a hand-written threat model should see
the whole list in one pass, not play whack-a-mole across N scan invocations.

Known gap: this file originates in the scanned repository and is therefore
attacker-influenceable, and it is NOT prompt-injection-fenced (scanned source code is,
via ``prompts/_fence.py``). See the KNOWN GAP section of
``context/OPENANT_THREATMODEL_TEMPLATE.md``. Accepted, documented risk.
"""

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from context.application_context import ApplicationContext
from utilities.file_io import open_utf8

# --- Schema v1 constants ------------------------------------------------------

#: Discriminator that identifies the authoritative json block inside the markdown.
# Cap the file size. The document is attacker-authored, and an unbounded read
# is both a memory-exhaustion vector and a way to flood the analysis prompt so
# that real source code falls out of the model's context window.
MAX_THREAT_MODEL_BYTES = 1024 * 1024

SCHEMA_NAME = "openant-threat-model"

#: Current schema version emitted by ``render_threat_model_md``.
SCHEMA_VERSION = 1

#: Every schema version this module can ingest. A future v2 that is a superset of
#: v1 would be added here; an incompatible v2 would not be.
SUPPORTED_SCHEMA_VERSIONS = (1,)

#: Filename looked for in the scanned repository's root.
#:
#: Deliberately NOT added to ``application_context.MANUAL_OVERRIDE_FILES``. If it
#: were, ``check_manual_override`` would consume it on the *built-in* arm too, so
#: both A/B arms would receive threat-model-derived context and the comparison
#: between them would measure nothing.
THREAT_MODEL_FILENAME = "OPENANT.THREATMODEL.md"

#: Where a component sits relative to the outside world.
EXPOSURE_LEVELS = ("remote", "local", "internal")

#: Where an attacker stands. Superset of the two personas the built-in path can
#: express ("remote" and "local_user"); the other three are the whole point.
ATTACKER_POSITIONS = ("remote", "adjacent", "local_user", "supply_chain", "insider")

#: Trust levels for input sources. Matches the vocabulary already used by
#: ``ApplicationContext.trust_boundaries`` so derivation is a straight map.
TRUST_LEVELS = ("untrusted", "semi_trusted", "trusted")

#: Heading skeleton of the markdown document. Presence of these is advisory — the
#: json block is the machine truth and is what gets strictly validated — but
#: ``render_threat_model_md`` always emits them and reviewers rely on them.
REQUIRED_HEADINGS = (
    "Purpose",
    "Architecture & Components",
    "Attacker Profiles",
    "Input Sources & Trust Levels",
    "What IS a Vulnerability",
    "What is NOT a Vulnerability",
    "Impact",
    "Machine-Readable Threat Model",
)

#: Top-level keys that must be present. ``not_a_vulnerability`` may be an empty
#: list, but the key itself must exist — an author who has genuinely decided that
#: nothing is out of scope should have to say so, not omit it by accident.
REQUIRED_TOP_LEVEL = (
    "schema",
    "schema_version",
    "classification",
    "purpose",
    "components",
    "attacker_profiles",
    "input_sources",
    "vulnerability_criteria",
    "not_a_vulnerability",
    "impact_statement",
)

#: Recognised-but-optional keys. Listed for documentation and for
#: ``render_threat_model_md``'s ordering; unknown keys are not an error.
OPTIONAL_TOP_LEVEL = (
    "architecture",
    "intended_behaviors",
    "security_model",
    "confidence",
    "evidence",
    "generated_by",
)

_JSON_BLOCK_RE = re.compile(r"```json\s*(.*?)\s*```", re.DOTALL)


class ThreatModelValidationError(Exception):
    """Raised when a threat model is present but unusable.

    Carries the **full** list of violations rather than the first one, plus the
    path it came from when known. Collecting everything is not a nicety: the
    expected authoring loop is a human editing markdown by hand, and fail-fast
    validation turns a five-mistake document into five edit/scan round trips.
    """

    def __init__(self, violations: list[str], path: Path | str | None = None):
        self.violations = list(violations)
        self.path = Path(path) if path is not None else None
        where = f" in {self.path}" if self.path is not None else ""
        body = "\n".join(f"  - {v}" for v in self.violations)
        super().__init__(
            f"Invalid threat model{where} ({len(self.violations)} violation(s)):\n{body}"
        )


# --- Parsing ------------------------------------------------------------------


def parse_threat_model_md(text: str) -> dict:
    """Extract the authoritative threat-model object from markdown text.

    Scans **all** ```json fenced blocks and returns the first whose parsed value is
    an object carrying ``"schema": "openant-threat-model"``. Blocks that fail to
    parse, or that parse to something else, are skipped rather than fatal — the
    document is expected to contain prose examples, and a template's own decoy
    blocks must not shadow the real one.

    Args:
        text: Full markdown source of an ``OPENANT.THREATMODEL.md``.

    Returns:
        The parsed threat-model object. Not validated — call
        ``validate_threat_model`` on the result.

    Raises:
        ThreatModelValidationError: If no block carries the schema discriminator.
            Any json decode errors seen along the way are reported too, since a
            typo inside the *real* block is by far the likeliest cause.
    """
    blocks = _JSON_BLOCK_RE.findall(text or "")
    if not blocks:
        raise ThreatModelValidationError(
            ["no ```json block found; the machine-readable threat model is required"]
        )

    decode_errors: list[str] = []
    for index, block in enumerate(blocks):
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            decode_errors.append(f"json block #{index + 1} is not valid JSON: {exc}")
            continue
        if isinstance(parsed, dict) and parsed.get("schema") == SCHEMA_NAME:
            return parsed

    violations = [
        f"no ```json block declares \"schema\": \"{SCHEMA_NAME}\" "
        f"({len(blocks)} json block(s) examined)"
    ]
    violations.extend(decode_errors)
    raise ThreatModelValidationError(violations)


def missing_headings(text: str) -> list[str]:
    """Headings from ``REQUIRED_HEADINGS`` that do not appear in the document.

    Advisory only — callers surface these as warnings. The json block is the
    machine truth, so a document with perfect json and no prose still scans; it is
    just useless to the humans who have to review it.
    """
    return [h for h in REQUIRED_HEADINGS if h.lower() not in (text or "").lower()]


# --- Validation ---------------------------------------------------------------


def _require_nonempty_str(value: Any, label: str, violations: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        violations.append(f"{label} must be a non-empty string (got {_describe(value)})")


def _describe(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, str) and not value.strip():
        return "empty string"
    return type(value).__name__


def _require_str_list(value: Any, label: str, violations: list[str], *, allow_empty: bool = True) -> None:
    if not isinstance(value, list):
        violations.append(f"{label} must be a list (got {_describe(value)})")
        return
    if not allow_empty and not value:
        violations.append(f"{label} must not be empty")
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            violations.append(f"{label}[{i}] must be a non-empty string (got {_describe(item)})")


def _require_enum(value: Any, allowed: tuple[str, ...], label: str, violations: list[str],
                  *, case_insensitive: bool = False) -> None:
    candidate = value.lower() if (case_insensitive and isinstance(value, str)) else value
    if candidate not in allowed:
        violations.append(
            f"{label} must be one of {', '.join(allowed)} (got {value!r})"
        )


def validate_threat_model(data: Any) -> None:
    """Validate a parsed threat model against schema v1, collecting every violation.

    Args:
        data: Object returned by ``parse_threat_model_md`` (or hand-built).

    Raises:
        ThreatModelValidationError: With ``.violations`` listing **all** problems
            found. Every missing required field is named individually, so a
            document missing three fields reports three violations, not one.
    """
    violations: list[str] = []

    if not isinstance(data, dict):
        raise ThreatModelValidationError(
            [f"threat model must be a JSON object (got {_describe(data)})"]
        )

    # Missing-key pass first, so the per-field checks below can assume presence
    # and every absent field is named in its own violation.
    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            violations.append(f"missing required field: {key}")

    if "schema" in data and data["schema"] != SCHEMA_NAME:
        violations.append(
            f'schema must be "{SCHEMA_NAME}" (got {data["schema"]!r})'
        )

    if "schema_version" in data:
        version = data["schema_version"]
        if version not in SUPPORTED_SCHEMA_VERSIONS:
            supported = ", ".join(str(v) for v in SUPPORTED_SCHEMA_VERSIONS)
            violations.append(
                f"unsupported schema_version {version!r}; supported versions: {supported}"
            )

    if "classification" in data:
        # Free-form on purpose: the whole point is that the four-value enum was
        # too small. Only non-emptiness is enforced.
        _require_nonempty_str(data["classification"], "classification", violations)
    if "purpose" in data:
        _require_nonempty_str(data["purpose"], "purpose", violations)
    if "impact_statement" in data:
        _require_nonempty_str(data["impact_statement"], "impact_statement", violations)

    if "vulnerability_criteria" in data:
        _require_str_list(
            data["vulnerability_criteria"], "vulnerability_criteria", violations,
            allow_empty=False,
        )
    if "not_a_vulnerability" in data:
        # May legitimately be empty; the key's presence is what is required.
        _require_str_list(data["not_a_vulnerability"], "not_a_vulnerability", violations)

    component_names = _validate_components(data.get("components"), violations) \
        if "components" in data else set()
    input_source_names = _validate_input_sources(data.get("input_sources"), violations, component_names) \
        if "input_sources" in data else set()
    if "attacker_profiles" in data:
        _validate_attacker_profiles(data["attacker_profiles"], violations, input_source_names)

    # Optional fields, validated only for type when present.
    if data.get("architecture") is not None:
        _require_nonempty_str(data["architecture"], "architecture", violations)
    if data.get("security_model") is not None:
        _require_nonempty_str(data["security_model"], "security_model", violations)
    if "intended_behaviors" in data:
        _require_str_list(data["intended_behaviors"], "intended_behaviors", violations)
    if "evidence" in data:
        _require_str_list(data["evidence"], "evidence", violations)
    if "confidence" in data:
        confidence = data["confidence"]
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) \
                or not 0.0 <= float(confidence) <= 1.0:
            violations.append(f"confidence must be a number in [0.0, 1.0] (got {confidence!r})")

    if violations:
        raise ThreatModelValidationError(violations)


def _validate_components(components: Any, violations: list[str]) -> set[str]:
    """Validate ``components[]``; return the set of declared component names."""
    names: set[str] = set()
    if not isinstance(components, list):
        violations.append(f"components must be a list (got {_describe(components)})")
        return names
    if not components:
        violations.append("components must not be empty")
    for i, comp in enumerate(components):
        label = f"components[{i}]"
        if not isinstance(comp, dict):
            violations.append(f"{label} must be an object (got {_describe(comp)})")
            continue
        for key in ("name", "component_type"):
            if key not in comp:
                violations.append(f"{label} missing required field: {key}")
            else:
                # component_type is FREE-FORM by design ("manifest watcher",
                # "reconciliation loop", ...). Constraining it here would
                # recreate the four-value enum this schema exists to escape.
                _require_nonempty_str(comp[key], f"{label}.{key}", violations)
        if "paths" not in comp:
            violations.append(f"{label} missing required field: paths")
        else:
            _require_str_list(comp["paths"], f"{label}.paths", violations, allow_empty=False)
        if "exposure" not in comp:
            violations.append(f"{label} missing required field: exposure")
        else:
            _require_enum(comp["exposure"], EXPOSURE_LEVELS, f"{label}.exposure", violations)
        if isinstance(comp.get("name"), str) and comp["name"].strip():
            names.add(comp["name"])
    return names


def _validate_input_sources(input_sources: Any, violations: list[str],
                            component_names: set[str]) -> set[str]:
    """Validate ``input_sources{}``; return the set of declared source names.

    Also cross-validates ``handled_by[]`` against the declared component names: a
    handler that names a component which does not exist is a dangling reference,
    and dangling references in a security document are exactly the kind of drift
    that makes it quietly stop describing the code.
    """
    names: set[str] = set()
    if not isinstance(input_sources, dict):
        violations.append(f"input_sources must be an object (got {_describe(input_sources)})")
        return names
    if not input_sources:
        violations.append("input_sources must not be empty")
    for name, spec in input_sources.items():
        label = f"input_sources[{name!r}]"
        names.add(name)
        if not isinstance(spec, dict):
            violations.append(f"{label} must be an object (got {_describe(spec)})")
            continue
        if "trust" not in spec:
            violations.append(f"{label} missing required field: trust")
        else:
            # Accepted case-insensitively: these documents are hand-written and
            # LLM-written, and "Untrusted" meaning something different from
            # "untrusted" would be a hostile piece of API design.
            _require_enum(spec["trust"], TRUST_LEVELS, f"{label}.trust", violations,
                          case_insensitive=True)
        if "description" not in spec:
            violations.append(f"{label} missing required field: description")
        else:
            _require_nonempty_str(spec["description"], f"{label}.description", violations)
        if "handled_by" in spec:
            _require_str_list(spec["handled_by"], f"{label}.handled_by", violations)
            if isinstance(spec["handled_by"], list):
                for handler in spec["handled_by"]:
                    if isinstance(handler, str) and handler not in component_names:
                        violations.append(
                            f"{label}.handled_by references unknown component {handler!r}; "
                            f"declared components: {', '.join(sorted(component_names)) or '(none)'}"
                        )
    return names


def _validate_attacker_profiles(profiles: Any, violations: list[str],
                                input_source_names: set[str]) -> None:
    """Validate ``attacker_profiles[]`` and cross-check ``entry_via[]``.

    ``entry_via`` must name a key of ``input_sources``. This is the single most
    load-bearing cross-reference in the schema: it is what connects "who the
    attacker is" to "what bytes they control", and a dangling entry means a
    persona is claiming reach into a channel the document never described.
    """
    if not isinstance(profiles, list):
        violations.append(f"attacker_profiles must be a list (got {_describe(profiles)})")
        return
    if not profiles:
        violations.append("attacker_profiles must not be empty")
    for i, profile in enumerate(profiles):
        label = f"attacker_profiles[{i}]"
        if not isinstance(profile, dict):
            violations.append(f"{label} must be an object (got {_describe(profile)})")
            continue
        for key in ("id", "description", "impact"):
            if key not in profile:
                violations.append(f"{label} missing required field: {key}")
            else:
                _require_nonempty_str(profile[key], f"{label}.{key}", violations)
        if "position" not in profile:
            violations.append(f"{label} missing required field: position")
        else:
            _require_enum(profile["position"], ATTACKER_POSITIONS, f"{label}.position", violations)
        for key in ("capabilities", "cannot"):
            if key not in profile:
                violations.append(f"{label} missing required field: {key}")
            else:
                _require_str_list(profile[key], f"{label}.{key}", violations, allow_empty=False)
        if "entry_via" not in profile:
            violations.append(f"{label} missing required field: entry_via")
        else:
            _require_str_list(profile["entry_via"], f"{label}.entry_via", violations,
                              allow_empty=False)
            if isinstance(profile["entry_via"], list):
                for entry in profile["entry_via"]:
                    if isinstance(entry, str) and entry not in input_source_names:
                        violations.append(
                            f"{label}.entry_via references unknown input source {entry!r}; "
                            f"declared input sources: "
                            f"{', '.join(sorted(input_source_names)) or '(none)'}"
                        )


# --- Derivation ---------------------------------------------------------------


def slug(text: str) -> str:
    """Lowercase, hyphenated slug of a free-form classification.

    Used only to build ``application_type = "custom:" + slug(classification)``.
    """
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", (text or "").lower())).strip("-")


def threat_model_to_context(data: dict) -> ApplicationContext:
    """Build an ``ApplicationContext`` from a validated threat model.

    The new schema fields are carried **verbatim** onto the dataclass, and the
    legacy fields are **derived** from them so that every pre-existing consumer
    (``format_context_for_prompt``, ``suppress_local_only``, the analyzer and
    verifier context threading, ``core/llm_reachability``'s raw-JSON dump) keeps
    working without a branch. Threat-model-aware renderers then override the
    legacy rendering where it matters; anything not yet converted degrades to a
    reasonable approximation rather than to nothing.

    Derivations:

    * ``application_type`` — ``"custom:" + slug(classification)``. Namespaced so it
      can never collide with an ``ApplicationType`` value, and so any code that
      compares against the enum simply sees "not one of mine" instead of a
      plausible-looking wrong match.
    * ``trust_boundaries`` — ``{source name: trust level}``, i.e. exactly the legacy
      shape, lowercased. This is what keeps ``suppress_local_only`` semantically
      sane for residual callers.
    * ``requires_remote_trigger`` — true if any attacker profile stands at
      ``position == "remote"`` **or** any input source is ``untrusted``. The second
      disjunct matters: a supply-chain attacker who controls an untrusted manifest
      is not "remote", but suppressing everything they can reach would be wrong.

    Args:
        data: A threat model that has already passed ``validate_threat_model``.

    Returns:
        ApplicationContext with ``has_threat_model()`` true.
    """
    input_sources = data.get("input_sources") or {}
    trust_boundaries = {
        name: str((spec or {}).get("trust", "")).lower()
        for name, spec in input_sources.items()
        if isinstance(spec, dict)
    }
    attacker_profiles = data.get("attacker_profiles") or []
    requires_remote_trigger = any(
        isinstance(p, dict) and p.get("position") == "remote" for p in attacker_profiles
    ) or any(level == "untrusted" for level in trust_boundaries.values())

    return ApplicationContext(
        application_type="custom:" + slug(data.get("classification", "")),
        purpose=data.get("purpose", ""),
        intended_behaviors=list(data.get("intended_behaviors") or []),
        trust_boundaries=trust_boundaries,
        security_model=data.get("security_model"),
        not_a_vulnerability=list(data.get("not_a_vulnerability") or []),
        requires_remote_trigger=requires_remote_trigger,
        confidence=float(data.get("confidence", 0.0) or 0.0),
        evidence=list(data.get("evidence") or []),
        source="threat_model",
        # Carried verbatim.
        threat_model_version=data.get("schema_version", SCHEMA_VERSION),
        classification=data.get("classification"),
        components=list(data.get("components") or []),
        attacker_profiles=list(attacker_profiles),
        input_sources=dict(input_sources),
        vulnerability_criteria=list(data.get("vulnerability_criteria") or []),
        impact_statement=data.get("impact_statement"),
    )


# --- Rendering ----------------------------------------------------------------


def _bullets(items: Any, empty: str = "_(none)_") -> str:
    items = [str(i) for i in (items or [])]
    return "\n".join(f"- {i}" for i in items) if items else empty


def render_threat_model_md(data: dict) -> str:
    """Render a threat model back to ``OPENANT.THREATMODEL.md`` markdown.

    The inverse of ``parse_threat_model_md``: emits the full heading skeleton for
    human reviewers followed by the authoritative json block. Round-tripping is
    exact for the json (the prose is a projection of it, not an additional source
    of truth), which is what lets a generator and a human edit the same file.
    """
    lines: list[str] = [
        f"# Threat Model: {data.get('classification', 'unclassified')}",
        "",
        # NB: no literal triple-backtick-json sequence in this comment. It would open
        # a fence that swallows the whole document up to the real block's opener.
        "<!-- OpenAnt threat model. The JSON fenced block at the bottom is the machine",
        "     truth; the prose above it is a rendering of that block for reviewers. -->",
        "",
        "## Purpose",
        "",
        str(data.get("purpose", "")),
        "",
        "## Architecture & Components",
        "",
    ]
    if data.get("architecture"):
        lines += [str(data["architecture"]), ""]
    for comp in data.get("components") or []:
        if not isinstance(comp, dict):
            continue
        lines.append(
            f"- **{comp.get('name', '?')}** ({comp.get('component_type', '?')}, "
            f"exposure: {comp.get('exposure', '?')}) — "
            f"`{'`, `'.join(str(p) for p in comp.get('paths') or [])}`"
        )
        if comp.get("description"):
            lines.append(f"  - {comp['description']}")
    lines += ["", "## Attacker Profiles", ""]
    for profile in data.get("attacker_profiles") or []:
        if not isinstance(profile, dict):
            continue
        lines += [
            f"### `{profile.get('id', '?')}` — {profile.get('description', '')}",
            "",
            f"**Position:** {profile.get('position', '?')}",
            "",
            "**CAN:**",
            _bullets(profile.get("capabilities")),
            "",
            "**CANNOT:**",
            _bullets(profile.get("cannot")),
            "",
            f"**Enters via:** {', '.join(str(e) for e in profile.get('entry_via') or []) or '_(none)_'}",
            "",
            f"**Impact if successful:** {profile.get('impact', '')}",
            "",
        ]
    lines += ["## Input Sources & Trust Levels", ""]
    for name, spec in (data.get("input_sources") or {}).items():
        if not isinstance(spec, dict):
            continue
        handled = ", ".join(str(h) for h in spec.get("handled_by") or [])
        lines.append(
            f"- **{name}** — `{spec.get('trust', '?')}` — {spec.get('description', '')}"
            + (f" (handled by: {handled})" if handled else "")
        )
    lines += [
        "",
        "## What IS a Vulnerability",
        "",
        _bullets(data.get("vulnerability_criteria")),
        "",
        "## What is NOT a Vulnerability",
        "",
        _bullets(data.get("not_a_vulnerability")),
        "",
        "## Impact",
        "",
        str(data.get("impact_statement", "")),
        "",
        "## Machine-Readable Threat Model",
        "",
        "```json",
        json.dumps(data, indent=2, ensure_ascii=False),
        "```",
        "",
    ]
    return "\n".join(lines)


# --- Loading ------------------------------------------------------------------


def threat_model_path(repo_path: Path | str) -> Path:
    """Path at which ``load_threat_model`` looks for the threat model."""
    return Path(repo_path) / THREAT_MODEL_FILENAME


def load_threat_model(repo_path: Path | str) -> ApplicationContext | None:
    """Load ``OPENANT.THREATMODEL.md`` from a repository root, if present.

    Returns:
        ``None`` **only** when the file does not exist — the repository simply has
        no threat model, and the caller should fall back to the built-in path.

    Raises:
        ThreatModelValidationError: When the file exists but cannot be parsed or
            fails schema validation. This is the deliberate inversion of
            ``check_manual_override``'s catch-all: absence is a choice, but a
            *present and broken* threat model is an error the operator must see.
            Silently continuing would produce a scan that looks entirely
            successful while analysing the repository under the default
            ``"web_app"`` attacker model — the exact opposite of what was asked
            for, with no signal anywhere in the output that it happened.
        OSError: Propagated if the file exists but cannot be read (permissions,
            unreadable encoding). Same reasoning: not silently swallowed.

    Note:
        The returned context is derived from a file that lives in the *scanned*
        repository and is therefore attacker-influenceable, and its contents are
        not prompt-injection-fenced. See the KNOWN GAP section of
        ``context/OPENANT_THREATMODEL_TEMPLATE.md``. Accepted, documented risk.
    """
    path = threat_model_path(repo_path)
    if not path.exists():
        return None

    # Guard BEFORE opening. The scanned repository authors this path, so it can
    # ship a symlink to a host file, or a FIFO/device that blocks the scanner
    # forever. `exists()` and `open()` both follow symlinks, so the check must
    # use lstat and must precede the open, not follow it.
    link_stat = os.lstat(path)
    if stat.S_ISLNK(link_stat.st_mode):
        raise ThreatModelValidationError(
            [f"{path.name} is a symlink; refusing to follow it out of the "
             "scanned repository"], path)
    if not stat.S_ISREG(link_stat.st_mode):
        raise ThreatModelValidationError(
            [f"{path.name} is not a regular file (mode {link_stat.st_mode:o}); "
             "a FIFO or device would block the scan indefinitely"], path)
    if link_stat.st_size > MAX_THREAT_MODEL_BYTES:
        raise ThreatModelValidationError(
            [f"{path.name} is too large ({link_stat.st_size} bytes > "
             f"{MAX_THREAT_MODEL_BYTES}); refusing to load"], path)

    with open_utf8(path) as handle:
        text = handle.read()

    try:
        data = parse_threat_model_md(text)
        validate_threat_model(data)
    except ThreatModelValidationError as exc:
        # Re-raise with the path attached so the operator is told *which* file.
        raise ThreatModelValidationError(exc.violations, path) from None

    return threat_model_to_context(data)
