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

    context = generate_application_context(Path("/path/to/repo"))
    save_context(context, Path("application_context.json"))
"""

import json
import re
import sys
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
from typing import Any

from anthropic import Anthropic
from dotenv import load_dotenv
from utilities.file_io import open_utf8, read_json, write_json

# Load environment variables
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
    source: str = "llm"  # "llm", "manual", or "merged"

    def __post_init__(self):
        """Validate application_type after initialization."""
        # Skip validation for manual overrides (they may use custom types intentionally)
        if self.source == "manual":
            return

        if not ApplicationType.is_supported(self.application_type):
            raise UnsupportedApplicationTypeError(
                self.application_type,
                self.evidence
            )

    def get_type_info(self) -> dict:
        """Get detailed information about this application type."""
        return APPLICATION_TYPE_INFO.get(self.application_type, {})


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
        if filepath.exists():
            try:
                with open_utf8(filepath, errors="ignore") as _f:
                    content = _f.read()
                # Limit size to avoid token overflow
                if len(content) > 10000:
                    content = content[:10000] + "\n\n[... truncated ...]"
                sources[filename] = content
            except Exception as e:
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
        if any(p in str(py_file) for p in ['node_modules', '__pycache__', 'venv', '.venv', 'test', 'tests']):
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
        if any(p in str(js_file) for p in ['node_modules', 'dist', 'build']):
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
        if not filepath.exists():
            continue

        try:
            if filename.endswith('.json'):
                # Direct JSON format
                data = read_json(filepath)
                data['source'] = 'manual'
                return ApplicationContext(**data)

            # .md files need raw text so regex can extract the embedded JSON block.
            with open_utf8(filepath) as _f:
                content = _f.read()

            if filename.endswith('.md'):
                # Markdown format - check for JSON code block
                json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(1))
                    data['source'] = 'manual'
                    return ApplicationContext(**data)

                # Check for YAML frontmatter
                yaml_match = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
                if yaml_match:
                    try:
                        import yaml
                        data = yaml.safe_load(yaml_match.group(1))
                        data['source'] = 'manual'
                        return ApplicationContext(**data)
                    except ImportError:
                        print("Warning: PyYAML not installed, cannot parse YAML frontmatter", file=sys.stderr)

        except Exception as e:
            print(f"Warning: Could not parse {filename}: {e}", file=sys.stderr)

    return None


# Build the type descriptions for the prompt
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
- `requires_remote_trigger`: Set to `false` for cli_tool, library, agent_framework. Set to `true` for web_app.
- `confidence`: 0.0-1.0 based on how much information was available.
- Be specific in `not_a_vulnerability` - these will directly prevent false positives.
"""


def generate_application_context(
    repo_path: Path,
    model: str = "claude-sonnet-4-20250514",
    force_regenerate: bool = False,
) -> ApplicationContext:
    """Generate application context using LLM analysis.

    Checks for manual override first, then falls back to LLM generation.

    Args:
        repo_path: Path to the repository root.
        model: Anthropic model to use for generation.
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

    # Format sources for prompt
    sources_text = ""
    for name, content in sources.items():
        sources_text += f"\n### {name}\n```\n{content}\n```\n"

    # Call LLM
    print(f"Generating context with {model}...", file=sys.stderr)
    client = Anthropic()
    response = client.messages.create(
        model=model,
        max_tokens=2000,
        messages=[{
            "role": "user",
            "content": CONTEXT_GENERATION_PROMPT.format(sources=sources_text)
        }]
    )

    # Parse response
    response_text = response.content[0].text

    # Extract JSON from response
    json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
    if json_match:
        json_str = json_match.group(1)
    else:
        # Try to parse the whole response as JSON
        json_str = response_text.strip()

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse LLM response as JSON: {e}\nResponse: {response_text}")

    data['source'] = 'llm'

    # Validate and create context (will raise UnsupportedApplicationTypeError if invalid)
    return ApplicationContext(**data)


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
    # Mark as manual to skip validation (already validated when saved)
    original_source = data.get('source', 'llm')
    data['source'] = 'manual'  # Temporarily bypass validation
    context = ApplicationContext(**data)
    context.source = original_source  # Restore original source
    return context


def format_context_for_prompt(context: ApplicationContext) -> str:
    """Format context for inclusion in vulnerability analysis prompts.

    Args:
        context: ApplicationContext to format.

    Returns:
        Formatted string for prompt injection.
    """
    type_info = context.get_type_info()

    lines = [
        "## Application Context",
        "",
        f"**Application Type:** {context.application_type}",
    ]

    if type_info:
        lines.append(f"**Type Description:** {type_info.get('description', '')}")
        lines.append(f"**Attack Model:** {type_info.get('attack_model', '')}")

    lines.append(f"**Purpose:** {context.purpose}")
    lines.append("")

    if context.intended_behaviors:
        lines.append("**Intended Behaviors (these are FEATURES, not vulnerabilities):**")
        for behavior in context.intended_behaviors:
            lines.append(f"- {behavior}")
        lines.append("")

    if context.trust_boundaries:
        lines.append("**Trust Boundaries:**")
        for source, level in context.trust_boundaries.items():
            lines.append(f"- {source}: {level}")
        lines.append("")

    if context.not_a_vulnerability:
        lines.append("**Do NOT flag as vulnerable:**")
        for item in context.not_a_vulnerability:
            lines.append(f"- {item}")
        lines.append("")

    if not context.requires_remote_trigger:
        lines.append("**IMPORTANT:** This is a CLI tool/library. Users running this code have local access.")
        lines.append("Only flag vulnerabilities that could be exploited by a REMOTE attacker, not by local users.")
        lines.append("")

    if context.security_model:
        lines.append(f"**Security Model:** {context.security_model}")
        lines.append("")

    return "\n".join(lines)
