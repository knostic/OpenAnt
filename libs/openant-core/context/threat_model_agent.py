"""Generate an OPENANT.THREATMODEL.md for a repository.

Until this module existed, a custom threat model had to be hand-authored. The
generator surveys the repository — its README and manifests, its directory
shape, and its detected entry points — and produces the document, which is then
committed to the repo root and consumed on subsequent scans.

Two design choices worth stating:

**It reuses the ``app_context`` phase rather than adding one.** The phase set in
``utilities/llm/config.py`` is closed, and user configs must list every phase
explicitly — adding a phase would be a breaking config change for every existing
user. Generating a threat model is the same semantic job as generating an
application context, so it rides the same phase.

**The agent's own output is validated exactly like a human's.** It goes through
``validate_threat_model`` before anything is written. A model that fails
validation is an error, not a file — writing an invalid document would poison
every later scan, and the loader is deliberately strict about malformed input.
"""

import json
from pathlib import Path

from context.threat_model import (
    THREAT_MODEL_FILENAME,
    ThreatModelValidationError,
    render_threat_model_md,
    validate_threat_model,
)

# Kept well above the built-in app-context budget (2000): a full threat model
# carries a component inventory, several attacker profiles and two criteria
# lists, and truncation mid-JSON produces an unparseable document.
MAX_TOKENS = 6000


class ThreatModelGenerationError(Exception):
    """Raised when a threat model could not be generated or is unusable."""


GENERATION_PROMPT = """You are a security architect. Study this repository and \
produce a threat model for it.

Do NOT assume a generic web application. Classify what this program actually is,
in your own words — the classification is free-form, not drawn from a fixed list.

Return ONLY a JSON object with exactly these keys:

  schema                 "openant-threat-model"
  schema_version         1
  classification         free-form description of what this program is
  purpose                what it does, for whom
  components             [{{name, paths[], component_type (FREE-FORM), \
exposure: remote|local|internal, description?}}]
  architecture           prose data-flow summary (optional)
  attacker_profiles      [{{id, description, position: \
remote|adjacent|local_user|supply_chain|insider, capabilities[], cannot[], \
entry_via[], impact}}]
  input_sources          {{name: {{trust: untrusted|semi_trusted|trusted, \
description, handled_by?[]}}}}
  vulnerability_criteria [] what IS a vulnerability in THIS threat model
  not_a_vulnerability    [] what is NOT — intended behaviour that looks alarming
  impact_statement       overall worst-case impact

Rules that matter:
- `entry_via` entries MUST name keys of `input_sources`.
- `cannot` is load-bearing: state what each attacker genuinely cannot do. It is
  what makes a later verdict falsifiable.
- Prefer several specific attacker profiles over one generic one. A supply-chain
  or adjacent attacker is often the realistic threat, not an anonymous remote user.
- `not_a_vulnerability` should name behaviour that IS intentional here. Do not
  use it to wave away whole classes of real risk.

REPOSITORY: {name}

--- Context files ---
{sources}

--- Entry points detected ---
{entry_points}
"""


def threat_model_exists(repo_path: Path) -> bool:
    """Whether the repository already ships a threat model."""
    return (Path(repo_path) / THREAT_MODEL_FILENAME).exists()


def _build_prompt(repo_path: Path) -> str:
    """Assemble the survey prompt from the repo's own signals."""
    from context.application_context import detect_entry_points, gather_context_sources

    sources = gather_context_sources(repo_path)
    rendered = "\n\n".join(
        f"### {name}\n{content[:4000]}" for name, content in sources.items()
    ) or "(no context files found)"

    try:
        entry_points = detect_entry_points(repo_path) or "(none detected)"
    except Exception:  # noqa: BLE001 - survey signal only; never fail generation
        entry_points = "(entry-point detection unavailable)"

    return GENERATION_PROMPT.format(
        name=Path(repo_path).name, sources=rendered, entry_points=entry_points
    )


def _extract_json(text: str) -> dict:
    """Pull the JSON object out of a model response."""
    stripped = text.strip()
    if stripped.startswith("```"):
        # Strip a fenced block, tolerating a ```json info-string.
        lines = [ln for ln in stripped.splitlines() if not ln.startswith("```")]
        stripped = "\n".join(lines)
    start, end = stripped.find("{"), stripped.rfind("}")
    if start == -1 or end == -1:
        raise ThreatModelGenerationError(
            f"model response contained no JSON object: {text[:200]!r}"
        )
    try:
        return json.loads(stripped[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ThreatModelGenerationError(
            f"model response was not valid JSON: {exc}"
        ) from exc


def generate_threat_model(
    repo_path: Path,
    binding,
    *,
    force: bool = False,
    output_path: Path | None = None,
) -> Path:
    """Generate a threat model and write it to the repository root.

    Args:
        repo_path: Repository to survey.
        binding: Phase binding supplying the adapter and model. The
            ``app_context`` phase is reused deliberately (see module docstring).
        force: Overwrite an existing threat model. The previous file is backed
            up to ``<name>.bak`` first — it may be hand-curated, and losing a
            human's threat model to a regeneration would be a poor trade.
        output_path: Write here instead of the repo root. Used when the repo is
            read-only.

    Returns:
        Path to the written file.

    Raises:
        ThreatModelGenerationError: If a model already exists without ``force``,
            the LLM call fails, or the produced model fails validation.
    """
    repo_path = Path(repo_path)
    target = Path(output_path) if output_path else repo_path / THREAT_MODEL_FILENAME

    if target.exists() and not force:
        raise ThreatModelGenerationError(
            f"{target} already exists. It may be hand-curated; pass force=True "
            "to regenerate (the existing file is backed up first)."
        )

    prompt = _build_prompt(repo_path)

    try:
        # Single-shot rather than a tool loop. The survey inputs (README,
        # manifests, entry points) are already assembled above, so the agentic
        # exploration the enhancer needs per-unit buys little here — and it
        # keeps the generator usable on adapters without tool support.
        response = binding.adapter.complete(prompt=prompt, max_tokens=MAX_TOKENS)
    except ThreatModelGenerationError:
        raise
    except Exception as exc:  # noqa: BLE001 - adapter errors vary by provider
        raise ThreatModelGenerationError(
            f"threat-model generation call failed: {exc}"
        ) from exc

    data = _extract_json(response if isinstance(response, str) else str(response))

    data.setdefault("generated_by", {}).update({
        "model": getattr(binding, "model", "unknown"),
        "provider": getattr(binding, "provider_name", "unknown"),
    })

    # Validate BEFORE writing. An invalid document on disk would fail every
    # subsequent scan at load time, which is a worse failure than not writing.
    try:
        validate_threat_model(data)
    except ThreatModelValidationError as exc:
        raise ThreatModelGenerationError(
            "generated threat model failed validation: "
            + "; ".join(getattr(exc, "violations", [str(exc)]))
        ) from exc

    if target.exists() and force:
        backup = target.with_suffix(target.suffix + ".bak")
        backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_threat_model_md(data), encoding="utf-8")
    return target
