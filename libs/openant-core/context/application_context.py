"""Generate rich application context for security analysis.

This module analyzes a repository and generates structured security context
that informs all subsequent vulnerability analysis stages. The context helps
the LLM understand:
- What the application IS and what it's SUPPOSED to do
- What behaviors are INTENTIONAL features (not vulnerabilities)
- What trust boundaries exist
- Whether vulnerabilities require remote exploitation

Supported Application Types:
- web_app: Web applications and API servers (HTTP-based, remote attackers)
- cli_tool: Command-line tools (local user has shell access)
- library: Reusable code packages (no direct attack surface)
- agent_framework: AI agent/LLM frameworks (code execution is intentional)

Usage:
    from context import generate_application_context, save_context

    # ``binding`` is the app_context-phase binding from a PhaseRegistry
    # (registry.get("app_context")); it is required.
    context = generate_application_context(Path("/path/to/repo"), binding)
    save_context(context, Path("application_context.json"))
"""

import json
import re
import sys
from dataclasses import dataclass, asdict, field, fields
from enum import Enum
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from utilities.file_io import open_utf8, read_json, read_repo_file, write_json
from utilities.llm import PhaseBinding, simple_text

load_dotenv()


class ApplicationType(Enum):
    """Supported application types for security analysis.

    Each type has a specific security model and attack surface.
    """
    WEB_APP = "web_app"
    CLI_TOOL = "cli_tool"
    LIBRARY = "library"
    AGENT_FRAMEWORK = "agent_framework"

    @classmethod
    def is_supported(cls, value: str) -> bool:
        """Check if a string value is a supported application type."""
        return value in [t.value for t in cls]

    @classmethod
    def supported_values(cls) -> list[str]:
        """Get list of supported type values."""
        return [t.value for t in cls]


# Type descriptions for prompts and documentation
APPLICATION_TYPE_INFO = {
    "web_app": {
        "description": "Web applications and API servers",
        "attack_model": "Remote attacker with browser/HTTP client",
        "examples": "Flask, Django, Express, FastAPI, REST APIs, GraphQL servers",
        "requires_remote_trigger": True,
        "trust_model": "HTTP requests are untrusted, config files are trusted",
    },
    "cli_tool": {
        "description": "Command-line tools and utilities",
        "attack_model": "Local user with shell access (already has filesystem access)",
        "examples": "git, npm, pip, langchain-cli, terraform",
        "requires_remote_trigger": False,
        "trust_model": "CLI arguments are trusted (user runs the command)",
    },
    "library": {
        "description": "Reusable code packages and SDKs",
        "attack_model": "No direct attack surface; security depends on how caller uses it",
        "examples": "requests, pandas, lodash, axios",
        "requires_remote_trigger": False,
        "trust_model": "Function parameters controlled by calling code, not end users",
    },
    "agent_framework": {
        "description": "AI agent and LLM orchestration frameworks",
        "attack_model": "Code execution is intentional; focus on sandbox escapes",
        "examples": "LangChain, AutoGen, CrewAI, semantic-kernel",
        "requires_remote_trigger": False,
        "trust_model": "Agent code execution is a feature, not a vulnerability",
    },
}


class UnsupportedApplicationTypeError(Exception):
    """Raised when the detected application type is not supported."""

    def __init__(self, detected_type: str, evidence: list[str] = None):
        self.detected_type = detected_type
        self.evidence = evidence or []
        supported = ", ".join(ApplicationType.supported_values())
        message = (
            f"Unsupported application type: '{detected_type}'\n"
            f"Supported types: {supported}\n"
            f"OpenAnt currently only supports security analysis for these application types.\n"
            f"To analyze this repository, create a manual OPENANT.md override file."
        )
        super().__init__(message)


@dataclass
class ApplicationContext:
    """Structured security context for an application."""

    # Core classification
    application_type: str  # Must be one of ApplicationType values
    purpose: str  # 1-2 sentence description

    # Security-relevant understanding
    intended_behaviors: list[str] = field(default_factory=list)
    trust_boundaries: dict[str, str] = field(default_factory=dict)
    security_model: str | None = None

    # Guidance for vulnerability analysis
    not_a_vulnerability: list[str] = field(default_factory=list)
    requires_remote_trigger: bool = True

    # Metadata
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    source: str = "llm"  # "llm", "manual", "merged", or "threat_model"

    # --- Custom threat-model extension (schema v1, see context/threat_model.py) ---
    #
    # These are ALL optional with defaults, deliberately. The two deserialization
    # sites in the codebase (core/analyzer.py, core/verifier.py) both go through
    # ``load_context``, which is ``ApplicationContext(**data)``; ``save_context`` is
    # a plain ``asdict``. Because every new field is defaulted, a pre-existing
    # ``application_context.json`` written before this extension existed still loads
    # unchanged, and the richer schema round-trips through save/load with no changes
    # to either function. That is what lets the built-in "app type" arm and the
    # custom threat-model arm be the *same* dataclass differing only in which JSON
    # file is handed to the pipeline — the precondition for comparing them.
    # Provenance of a repo-supplied threat model, for scan-artifact visibility.
    # Both are additive/defaulted so save_context(asdict)/load_context(**data)
    # round-trip unchanged. sha256 is over the raw file bytes; permissive_warnings
    # is warn_permissive_threat_model's output, which was previously discarded.
    source_sha256: str | None = None
    permissive_warnings: list = None
    threat_model_version: int | None = None
    classification: str | None = None
    components: list = field(default_factory=list)
    attacker_profiles: list = field(default_factory=list)
    input_sources: dict = field(default_factory=dict)
    vulnerability_criteria: list = field(default_factory=list)
    impact_statement: str | None = None

    def __post_init__(self):
        if self.permissive_warnings is None:
            self.permissive_warnings = []
        """Validate application_type after initialization."""
        # A hallucinated non-dict ``trust_boundaries`` (e.g. an LLM emitting a list)
        # would crash suppress_local_only() / format_app_context_for_prompt's ``.items()``
        # at analyze-phase prompt build, which is not wrapped in try/except.
        # Coerce to a dict for every construction path (manual, LLM, threat-model).
        if not isinstance(self.trust_boundaries, dict):
            self.trust_boundaries = {}
        # Skip validation for manual overrides (they may use custom types intentionally)
        if self.source == "manual":
            return

        # Skip validation for threat-model contexts. This is an EXPLICIT second
        # branch rather than a widening of the ``source == "manual"`` bypass above,
        # and the duplication is intentional. The two bypasses exist for unrelated
        # reasons and must be able to change independently:
        #
        #   * the manual bypass exists because an operator hand-writing OPENANT.md
        #     is trusted to name any type they like;
        #   * this bypass exists because a threat model's ``application_type`` is
        #     *derived*, not chosen — ``threat_model_to_context`` synthesizes
        #     ``"custom:" + slug(classification)`` from a free-form classification,
        #     which by construction can never be one of the four enum values.
        #
        # Folding them together would mean a future tightening of one silently
        # loosens the other, and would also make a threat-model context
        # indistinguishable from an operator override at the ``source`` field.
        if self.threat_model_version is not None:
            return

        if not ApplicationType.is_supported(self.application_type):
            raise UnsupportedApplicationTypeError(
                self.application_type,
                self.evidence
            )

    def has_threat_model(self) -> bool:
        """Whether this context was built from a custom threat model (schema v1+).

        The single branch predicate at every consumption site: prompt renderers,
        the scanner's context step, and the A/B arm labelling. ``threat_model_version``
        is the marker because it is the one field that is meaningless to set by hand
        on a legacy context and is written by exactly one producer
        (``context.threat_model.threat_model_to_context``).
        """
        return self.threat_model_version is not None

    def get_type_info(self) -> dict:
        """Get detailed information about this application type."""
        return APPLICATION_TYPE_INFO.get(self.application_type, {})

    def suppress_local_only(self) -> bool:
        """Whether to tell the analyzer to flag only REMOTE-attacker vulnerabilities.

        The "local users have access, only flag remote" framing is correct for a
        CLI/library whose inputs are all operator-controlled. But a data-processing
        library (parser, deserializer, codec) takes UNTRUSTED INPUT DATA — and that
        data crossing into the code IS the attack surface, even with no network
        listener. ``requires_remote_trigger`` alone (False for every library) would
        suppress exactly those bugs. Gate on the already-captured ``trust_boundaries``:
        if any input source is ``untrusted``, do NOT suppress, regardless of type.
        """
        if self.requires_remote_trigger:
            return False
        # A boundary counts as untrusted if its (LLM-generated, free-form) level
        # CONTAINS the 'untrusted' token — tolerating case AND qualifiers such as
        # 'untrusted (attacker-controlled)' / 'untrusted - HTTP body'. An exact
        # '== untrusted' match let a qualified level slip past and re-enable suppression
        # of the untrusted-input bug class the gate exists to protect.
        # 'trusted'/'semi-trusted' do not contain the substring 'untrusted'.
        boundaries = self.trust_boundaries if isinstance(self.trust_boundaries, dict) else {}
        return not any(
            "untrusted" in str(level).lower()
            for level in boundaries.values()
        )


def _context_kwargs_from_dict(data: dict) -> dict:
    """Allowlist-filter an untrusted dict to ApplicationContext dataclass fields.

    LLM output and hand-edited JSON files can carry unknown/hallucinated keys;
    passing them straight to ``ApplicationContext(**data)`` raises an uncaught
    TypeError. Keep only keys that name a real dataclass field so construction
    is robust to extra keys.
    """
    allowed = {f.name for f in fields(ApplicationContext)}
    return {k: v for k, v in data.items() if k in allowed}


# Files to check for manual override (in order of priority)
MANUAL_OVERRIDE_FILES = [
    "OPENANT.md",
    "OPENANT.json",
    ".openant.md",
    ".openant.json",
]

# Priority files to read for context generation
CONTEXT_FILES = [
    "README.md",
    "CLAUDE.md",
    "AGENTS.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "setup.py",
]

# Patterns that indicate application type
ENTRY_POINT_PATTERNS = {
    "cli": [
        (r"import typer|from typer", "typer CLI framework"),
        (r"import click|from click", "click CLI framework"),
        (r"import argparse|from argparse", "argparse CLI"),
        (r"import fire|from fire", "fire CLI framework"),
        (r"@.*\.command\(\)", "CLI command decorator"),
    ],
    "web": [
        (r"from fastapi|import fastapi|FastAPI\(\)", "FastAPI web framework"),
        (r"from flask|import flask|Flask\(\)", "Flask web framework"),
        (r"from django|import django", "Django web framework"),
        (r"@app\.route|@router\.", "Web route decorator"),
        (r"from starlette|import starlette", "Starlette web framework"),
    ],
    "agent": [
        (r"langchain|LangChain", "LangChain agent framework"),
        (r"autogen|AutoGen", "AutoGen agent framework"),
        (r"crewai|CrewAI", "CrewAI agent framework"),
        (r"agent.*execute|execute.*agent", "Agent execution pattern"),
    ],
}


def gather_context_sources(repo_path: Path) -> dict[str, str]:
    """Gather relevant files for context generation.

    Args:
        repo_path: Path to the repository root.

    Returns:
        Dictionary mapping filename to content.
    """
    sources = {}

    # Read priority files
    for filename in CONTEXT_FILES:
        filepath = repo_path / filename
        try:
            # Guarded, and bounded at the syscall rather than after the fact: the
            # old form read the whole file and *then* truncated to 10 000 chars, so
            # a README symlinked to /dev/zero or a multi-GB file was fully resident
            # before the cap ever applied.
            content = read_repo_file(filepath, max_bytes=10_000)
            if content is None:
                continue
            if len(content) >= 10_000:
                content = content + "\n\n[... truncated ...]"
            sources[filename] = content
        except Exception as e:  # noqa: BLE001 - context gathering is best-effort
            print(f"Warning: Could not read {filename}: {e}", file=sys.stderr)

    # Get directory structure (top 2 levels)
    dir_structure = get_directory_structure(repo_path, max_depth=2)
    if dir_structure:
        sources["[directory_structure]"] = dir_structure

    # Detect entry points
    entry_points = detect_entry_points(repo_path)
    if entry_points:
        sources["[detected_patterns]"] = entry_points

    return sources


def get_directory_structure(repo_path: Path, max_depth: int = 2) -> str:
    """Get directory tree for pattern recognition.

    Args:
        repo_path: Path to repository root.
        max_depth: Maximum depth to traverse.

    Returns:
        String representation of directory structure.
    """
    lines = []

    try:
        for path in sorted(repo_path.iterdir()):
            # Skip hidden directories and common non-essential dirs
            if path.name.startswith('.') or path.name in ('node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build'):
                continue

            if path.is_dir():
                lines.append(f"{path.name}/")
                if max_depth > 1:
                    try:
                        for subpath in sorted(path.iterdir()):
                            if subpath.name.startswith('.'):
                                continue
                            if subpath.is_dir():
                                lines.append(f"  {subpath.name}/")
                            else:
                                lines.append(f"  {subpath.name}")
                    except PermissionError:
                        pass
            else:
                lines.append(path.name)
    except PermissionError:
        pass

    return "\n".join(lines[:100])  # Limit output


# Directory names (exact path SEGMENTS, not substrings) to skip when scanning for entry points.
_PY_EXCLUDE_DIRS = {'node_modules', '__pycache__', 'venv', '.venv', 'test', 'tests'}
_JS_EXCLUDE_DIRS = {'node_modules', 'dist', 'build'}


def _path_excluded(file_path: Path, repo_path: Path, exclude_dirs: set, anchored_test: bool = False) -> bool:
    """Whether file_path should be skipped, matching on relative-path COMPONENTS.

    Anchors on path *segments* relative to repo_path rather than a substring of the absolute
    path, so a parent directory or a partial token ('protest_api.py', 'latest/', 'redistribute.js')
    no longer wrongly excludes a real entry point — and a token in some ancestor of repo_path
    (e.g. a CI checkout under '/build/' or '/latest/') can no longer suppress every file.
    """
    try:
        parts = file_path.relative_to(repo_path).parts
    except ValueError:
        parts = file_path.parts
    if exclude_dirs.intersection(parts):
        return True
    if anchored_test:
        name = file_path.name
        if name.startswith("test_") or name.endswith("_test.py"):
            return True
    return False


def detect_entry_points(repo_path: Path) -> str:
    """Detect entry point patterns in the codebase.

    Args:
        repo_path: Path to repository root.

    Returns:
        String describing detected patterns.
    """
    findings = []
    files_checked = 0
    max_files = 100  # Limit files to check

    # Check Python files
    for py_file in repo_path.rglob("*.py"):
        if files_checked >= max_files:
            break
        if _path_excluded(py_file, repo_path, _PY_EXCLUDE_DIRS, anchored_test=True):
            continue

        try:
            with open_utf8(py_file, errors="ignore") as _f:
                content = _f.read()
            rel_path = py_file.relative_to(repo_path)

            for category, patterns in ENTRY_POINT_PATTERNS.items():
                for pattern, description in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(f"[{category}] {rel_path}: {description}")
                        break  # One finding per file per category

            files_checked += 1
        except Exception:
            pass

    # Check JavaScript/TypeScript files
    for js_file in list(repo_path.rglob("*.js"))[:20] + list(repo_path.rglob("*.ts"))[:20]:
        if _path_excluded(js_file, repo_path, _JS_EXCLUDE_DIRS):
            continue

        try:
            with open_utf8(js_file, errors="ignore") as _f:
                content = _f.read()
            rel_path = js_file.relative_to(repo_path)

            if re.search(r"express\(\)|require\(['\"]express['\"]\)", content):
                findings.append(f"[web] {rel_path}: Express.js web framework")
            if re.search(r"@Controller|@Get|@Post|NestFactory", content):
                findings.append(f"[web] {rel_path}: NestJS web framework")
        except Exception:
            pass

    return "\n".join(findings[:30])  # Limit output


def _application_context_from_override(data: Any, filename: str) -> ApplicationContext:
    """Build an ApplicationContext from operator override data, tolerating unknown keys.

    An unknown/extra key makes ``ApplicationContext(**data)`` raise TypeError, which
    the caller's broad ``except`` swallows -- silently dropping the whole override.
    Filter to the dataclass's known fields (allowlist) and warn on the rest so the
    known keys are still honored.

    Raises ValueError when ``data`` is not a mapping (empty/list/scalar frontmatter),
    so the caller's existing ``except`` handles it exactly like any other parse
    failure -- falling through to the next MANUAL_OVERRIDE_FILES entry rather than
    short-circuiting the precedence loop.
    """
    if not isinstance(data, dict):
        raise ValueError(f"manual override is not a mapping (got {type(data).__name__})")
    data = {**data, "source": "manual"}
    known = {f.name for f in fields(ApplicationContext)}
    unknown = [k for k in data if k not in known]
    if unknown:
        print(
            f"Warning: ignoring unknown key(s) in {filename}: {', '.join(sorted(str(k) for k in unknown))}",
            file=sys.stderr,
        )
    return ApplicationContext(**{k: v for k, v in data.items() if k in known})


def check_manual_override(repo_path: Path) -> ApplicationContext | None:
    """Check for manual override file in the repository.

    Supports both Markdown and JSON formats:
    - OPENANT.md: Markdown with YAML/JSON frontmatter or structured sections
    - OPENANT.json: Direct JSON configuration

    Args:
        repo_path: Path to repository root.

    Returns:
        ApplicationContext if manual override found, None otherwise.
    """
    for filename in MANUAL_OVERRIDE_FILES:
        filepath = repo_path / filename

        try:
            # Guarded read: this path is authored by the scanned repository, so it
            # may be a symlink out of the tree, a FIFO that blocks forever, or
            # unbounded. read_repo_file lstats before opening and returns None for
            # genuine absence. Previously this was `exists()` + bare `open()`, which
            # hung the scanner on a FIFO named OPENANT.md.
            content = read_repo_file(filepath)
            if content is None:
                continue

            if filename.endswith('.json'):
                data = json.loads(content)
                return _application_context_from_override(data, filename)

            if filename.endswith('.md'):
                # Markdown format - check for JSON code block. No `\s*` around the
                # lazy group: that form backtracks cubically on an unclosed fence,
                # which is an unbounded hang on eight bytes of repo-authored input.
                json_match = re.search(r'```json(.*?)```', content, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(1).strip())
                    return _application_context_from_override(data, filename)

                # Check for YAML frontmatter
                yaml_match = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
                if yaml_match:
                    try:
                        import yaml
                        data = yaml.safe_load(yaml_match.group(1))
                        return _application_context_from_override(data, filename)
                    except ImportError:
                        print("Warning: PyYAML not installed, cannot parse YAML frontmatter", file=sys.stderr)

        except Exception as e:
            print(f"Warning: Could not parse {filename}: {e}", file=sys.stderr)

    return None


def _build_type_descriptions() -> str:
    """Build formatted type descriptions for the prompt."""
    lines = []
    for type_value, info in APPLICATION_TYPE_INFO.items():
        lines.append(f"- **{type_value}**: {info['description']}")
        lines.append(f"  - Attack model: {info['attack_model']}")
        lines.append(f"  - Examples: {info['examples']}")
    return "\n".join(lines)


CONTEXT_GENERATION_PROMPT = """Analyze this software repository and generate a security analysis context.

## Repository Information

{sources}

---

## Task

You are preparing context for a security vulnerability scanner. The scanner will analyze individual code units (functions/methods) for vulnerabilities. Your job is to provide application-level context so the scanner understands:

1. What this application IS and what it's SUPPOSED to do
2. What behaviors are INTENTIONAL features (not vulnerabilities)
3. What trust boundaries exist
4. Whether vulnerabilities require remote exploitation or if local-only issues should be flagged

## Supported Application Types

You MUST classify this repository as ONE of these four types:

""" + _build_type_descriptions() + """

If the repository doesn't fit any of these types (e.g., desktop app, mobile app, game, embedded system), use `application_type: "unsupported"` and explain why in the evidence field.

## Security Model by Type

- **web_app**: Remote attackers via HTTP. SSRF, XSS, SQLi, path traversal are real concerns.
- **cli_tool**: Local user has shell access. Path traversal, file operations are NOT vulnerabilities.
- **library**: No direct attack surface. Vulnerabilities depend on how the caller uses the library.
- **agent_framework**: Code execution is the CORE FEATURE. Focus on sandbox escapes, not code execution itself.

## Output Format

Respond with a JSON object (no other text):

```json
{{
  "application_type": "web_app|cli_tool|library|agent_framework|unsupported",
  "purpose": "1-2 sentence description of what this application does",
  "intended_behaviors": [
    "List of behaviors that are BY DESIGN, not vulnerabilities",
    "Be specific - e.g., 'Executes user-provided code in sandboxed environment'",
    "e.g., 'Clones git repositories from user-specified URLs'",
    "e.g., 'Makes HTTP requests to user-provided endpoints'"
  ],
  "trust_boundaries": {{
    "description of input source": "untrusted|semi_trusted|trusted",
    "http_request_body": "untrusted",
    "cli_arguments": "trusted",
    "config_files": "trusted"
  }},
  "security_model": "Description of any documented security approach (allowlists, sandboxing, etc.), or null if none documented",
  "not_a_vulnerability": [
    "Specific patterns that should NOT be flagged as vulnerabilities",
    "e.g., 'Path traversal in CLI commands - user has filesystem access'",
    "e.g., 'Subprocess execution in agent tools - this is the core feature'"
  ],
  "requires_remote_trigger": true,
  "confidence": 0.85,
  "evidence": [
    "List of files/patterns that led to these conclusions",
    "e.g., 'README.md describes this as an AI agent framework'",
    "e.g., 'Detected typer CLI framework in cli/ directory'"
  ]
}}
```

**Guidelines:**
- `application_type`: MUST be one of: web_app, cli_tool, library, agent_framework, unsupported
- `requires_remote_trigger`: Set to `true` for web_app, AND for any cli_tool/library/agent_framework that PROCESSES UNTRUSTED INPUT DATA (a parser, deserializer, codec, file/format reader, or anything where `trust_boundaries` marks an input source `untrusted` — the untrusted data crossing into the code is the attack surface even with no network listener). Set to `false` only when every input source is operator-controlled/trusted.
- `confidence`: 0.0-1.0 based on how much information was available.
- Be specific in `not_a_vulnerability` - these will directly prevent false positives.
"""


def generate_application_context(
    repo_path: Path,
    binding: PhaseBinding,
    force_regenerate: bool = False,
) -> ApplicationContext | None:
    """Generate application context using LLM analysis.

    Checks for manual override first, then falls back to LLM generation.

    Args:
        repo_path: Path to the repository root.
        binding: Phase binding for the ``app_context`` phase, obtained
            from ``PhaseRegistry.get("app_context")``. The model and
            adapter embedded in it are what the call actually uses —
            no caller-side model selection.
        force_regenerate: If True, skip manual override check.

    Returns:
        ApplicationContext with security-relevant information.

    Raises:
        UnsupportedApplicationTypeError: If detected type is not supported.
    """
    repo_path = Path(repo_path)

    # Check for manual override first
    if not force_regenerate:
        manual_context = check_manual_override(repo_path)
        if manual_context:
            print(f"Using manual override from repository", file=sys.stderr)
            return manual_context

    # Gather sources
    print(f"Gathering context sources from {repo_path}...", file=sys.stderr)
    sources = gather_context_sources(repo_path)

    if not sources:
        raise ValueError(f"No context sources found in {repo_path}")

    # Format sources for prompt. `content` is a repo file (README, package
    # manifest, ...) read from the SCANNED repo — untrusted. A bare ``` fence is
    # escapable: a source file containing its own ``` line would break out and
    # the remainder would be read as prompt-level instructions, steering the
    # generated app-context (which then seeds every Stage-1 analysis prompt).
    # Use a length-adaptive fence per source so the content stays inert data.
    from prompts._fence import safe_code_fence
    sources_text = ""
    for name, content in sources.items():
        _sf = safe_code_fence(content)
        sources_text += f"\n### {name}\n{_sf}\n{content}\n{_sf}\n"

    # Call LLM via the adapter — provider+model are dictated by the
    # llm-config's ``app_context`` phase, not hardcoded here.
    print(
        f"Generating context with {binding.provider_name}/{binding.model}...",
        file=sys.stderr,
    )
    response_text = simple_text(
        binding,
        CONTEXT_GENERATION_PROMPT.format(sources=sources_text),
        max_tokens=2000,
    )

    # Extract JSON from response
    # No `\s*` around the lazy group: that form is ambiguous and backtracks
    # cubically on an unclosed fence. Third copy of this pattern to be fixed — the
    # other two were context/threat_model.py and check_manual_override above. This
    # one parses *model* output rather than repo files, so it is bounded by
    # max_tokens and was a multi-minute hang rather than an unbounded one, but the
    # input is still attacker-influenceable via the accepted prompt-injection gap.
    json_match = re.search(r'```json(.*?)```', response_text, re.DOTALL)
    if json_match:
        json_str = json_match.group(1).strip()
    else:
        # Try to parse the whole response as JSON
        json_str = response_text.strip()

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse LLM response as JSON: {e}\nResponse: {response_text}")

    data['source'] = 'llm'

    # Allowlist-filter to dataclass fields: the LLM can hallucinate unknown/extra
    # keys, and a raw ApplicationContext(**data) would raise an uncaught TypeError
    # ("unexpected keyword argument") that crashes context generation. Drop unknown
    # keys so only recognized fields reach the constructor.
    data = _context_kwargs_from_dict(data)

    # Validate and create context (will raise UnsupportedApplicationTypeError if invalid).
    # The allowlist filter above closes the UNKNOWN-key crash, but the LLM can also
    # OMIT a required field (application_type / purpose); ApplicationContext(**data)
    # then raises an uncaught TypeError ("missing required positional argument") that
    # crashes generation — the exact class this hardening set out to kill. Untrusted
    # LLM output: warn to stderr and fall back gracefully (return None; both callers —
    # context/generate_context.py and core/scanner.py — wrap this call in a broad
    # try/except and continue without a context).
    try:
        return ApplicationContext(**data)
    except TypeError as e:
        print(
            f"WARNING: LLM returned an incomplete application context "
            f"(missing required field): {e}. Skipping app context.",
            file=sys.stderr,
        )
        return None


def save_context(context: ApplicationContext, output_path: Path) -> None:
    """Save context to JSON file.

    Args:
        context: ApplicationContext to save.
        output_path: Path to output JSON file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    write_json(output_path, asdict(context))

    print(f"Context saved to {output_path}", file=sys.stderr)


def load_context(input_path: Path) -> ApplicationContext:
    """Load context from JSON file.

    Args:
        input_path: Path to JSON file.

    Returns:
        ApplicationContext loaded from file.
    """
    data = read_json(input_path)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {input_path}, got {type(data).__name__}")
    # Mark as manual to skip validation (already validated when saved)
    original_source = data.get('source', 'llm')
    data['source'] = 'manual'  # Temporarily bypass validation
    # Sibling of the LLM path: a hand-edited JSON file may carry unknown keys;
    # allowlist-filter to dataclass fields so **data cannot raise TypeError.
    data = _context_kwargs_from_dict(data)
    # The filter drops unknown keys, but a saved/edited file can also be MISSING a
    # required field (application_type / purpose); ApplicationContext(**data) then
    # raises a raw, uninformative TypeError. This is a trusted-ish on-disk file, so
    # surface a clear, actionable error naming the offending path instead of crashing.
    try:
        context = ApplicationContext(**data)
    except TypeError as e:
        raise ValueError(f"Invalid context in {input_path}: {e}")
    context.source = original_source  # Restore original source
    return context


def format_context_for_prompt(context: ApplicationContext) -> str:
    """Format context for inclusion in vulnerability analysis prompts.

    Args:
        context: ApplicationContext to format.

    Returns:
        Formatted string for prompt injection.
    """
    # The free-text fields below (purpose, intended_behaviors, not_a_vulnerability,
    # security_model, trust_boundaries) are attacker-authored: a scanned repo can
    # commit OPENANT.json / OPENANT.THREATMODEL.md, which is auto-loaded on every
    # default scan. Each is spliced onto its own prompt line, so an embedded newline
    # would forge a NEW instruction line (a fake "## SYSTEM DIRECTIVE" / extra
    # "Do NOT flag" bullet) that steers this tool's own analyzer/verifier LLM into
    # false negatives. Collapse every such value to a single inert line — the same
    # discipline safe_code_fence/neutralize_boundaries already apply to source and
    # file-boundary markers. application_type is collapsed too: __post_init__ skips the
    # ApplicationType enum check when source=="manual" (a repo-committed OPENANT.json
    # override), so it is attacker-controllable despite looking validated. type_info comes
    # from the built-in registry (a dict lookup on application_type), so it is left raw.
    from prompts._fence import collapse_inline

    type_info = context.get_type_info()

    lines = [
        "## Application Context",
        "",
        f"**Application Type:** {collapse_inline(context.application_type)}",
    ]

    if type_info:
        lines.append(f"**Type Description:** {type_info.get('description', '')}")
        lines.append(f"**Attack Model:** {type_info.get('attack_model', '')}")

    lines.append(f"**Purpose:** {collapse_inline(context.purpose)}")
    lines.append("")

    if context.intended_behaviors:
        lines.append("**Intended Behaviors (these are FEATURES, not vulnerabilities):**")
        for behavior in context.intended_behaviors:
            lines.append(f"- {collapse_inline(behavior)}")
        lines.append("")

    if context.trust_boundaries:
        lines.append("**Trust Boundaries:**")
        for source, level in context.trust_boundaries.items():
            lines.append(f"- {collapse_inline(source)}: {collapse_inline(level)}")
        lines.append("")

    if context.not_a_vulnerability:
        lines.append("**Do NOT flag as vulnerable:**")
        for item in context.not_a_vulnerability:
            lines.append(f"- {collapse_inline(item)}")
        lines.append("")

    if context.suppress_local_only():
        lines.append("**IMPORTANT:** This is a CLI tool/library. Users running this code have local access.")
        lines.append("Only flag vulnerabilities that could be exploited by a REMOTE attacker, not by local users.")
        lines.append("")

    if context.security_model:
        lines.append(f"**Security Model:** {collapse_inline(context.security_model)}")
        lines.append("")

    return "\n".join(lines)
