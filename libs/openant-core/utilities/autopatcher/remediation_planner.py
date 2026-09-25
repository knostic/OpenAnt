"""
Remediation planner (experimental).

Planning is split into two bounded, distinctly-labeled LLM calls around one
deterministic bridge:

    initial repository evidence
    -> generate_remediation_plan()        ("target_discovery" role)
    -> build_planner_evidence()           (deterministic verification + enrichment)
    -> generate_remediation_strategy()    ("remediation_strategy" stage)
    -> Patch Generator

`generate_remediation_plan(vulnerability_text, llm, code_context)`: one
bounded LLM call (stage "remediation_planning") that identifies files,
symbols, and open questions worth investigating -- exploratory, not
authoritative. Returns a `RemediationPlanResult` (rendered Markdown plus the
parsed, unverified `target_files`/`target_symbols`) -- never a patch, never
code. On any call/parsing failure this degrades to an all-empty result,
never raises.

`build_planner_evidence(...)`: a deterministic bridge from that (unverified)
Planner proposal to a separately-labeled evidence block, built entirely from
existing OpenAnt analysis (RepositoryIndex, call graph, reachability,
constants, candidate enrichment/fusion/rendering). Every proposed
file/symbol is verified against the real repository before it is allowed
anywhere near enrichment -- an unverifiable proposal is dropped, never
presented as evidence. No new LLM call, no new analysis, no repository-wide
reparsing: this only ever reuses the InvestigationContext already built for
this run.

`generate_remediation_strategy(...)`: a second, distinct LLM call (stage
"remediation_strategy") that runs only once verified Planner evidence
exists, and receives that verified evidence in addition to everything the
first call saw. It selects the smallest evidence-backed remediation
mechanism -- still never a diff, never code. Its `target_files`/
`target_symbols` are deterministically re-verified against the same
repository before anything from it reaches Patch Generation; anything that
doesn't verify is dropped with an explicit warning, never silently promoted.
On any call/parsing failure, or when there is no verified evidence to give
it, this degrades to an all-empty result and the pipeline continues with
whatever evidence already existed -- never raises, never a third LLM call.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import NamedTuple

from .content_relocation import find_unique_occurrence, old_side_anchors
from .context_budget import ContextBudgetController
from .diff_parsing import parse_diff
from .llm_client import ModelUnavailableError
from .repository_grounding_models import DiscoveryEvidence, RepositoryCandidate

_PROMPT_PATH = Path(__file__).parent / "prompts" / "remediation_planner.md"
_STRATEGY_PROMPT_PATH = Path(__file__).parent / "prompts" / "remediation_strategy.md"

_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```$", re.DOTALL)

_SECTIONS = [
    ("security_invariant", "Security invariant", False),
    ("narrower_alternative_decision", "Narrower alternative decision", False),
    ("narrower_alternative_considered", "Narrower alternative considered", False),
    ("remediation_mechanism", "Likely remediation mechanism", False),
    ("target_files", "Likely remediation files", True),
    ("target_symbols", "Relevant symbols", True),
    ("required_edits", "Required edits", True),
    ("approaches_to_avoid", "Approaches to avoid", True),
    ("explicit_unknowns", "Explicit unknowns", True),
]
"""`narrower_alternative_decision`/`narrower_alternative_considered` sit
between `security_invariant` and `remediation_mechanism` deliberately: they
are the recorded decision and comparison that produced the final mechanism,
not an independent finding -- rendering them between "the condition that
must be restored" and "the mechanism chosen to restore it" mirrors the
reasoning order the Planner prompt now requires. Additive only: an
absent/null value renders nothing (see `_render_plan`'s existing
scalar-field handling below), so a response from before either field
existed, or one that omits them, is unaffected."""

_VALID_NARROWER_DECISIONS = frozenset({"SELECTED", "REJECTED", "NONE_IDENTIFIED"})
"""The only values `narrower_alternative_decision` is trusted to carry --
see `RemediationPlanResult.narrower_alternative_decision`'s own docstring
for why an unrecognized or missing value is normalized to `None` here
rather than passed through: this module never guesses a decision from
`narrower_alternative_considered`'s prose, and callers (pipeline.py's
Planner Claim Verifier dispatch) must never see a value outside this set."""


class RemediationPlanResult(NamedTuple):
    """The Planner's output, kept in one minimal shape rather than a model
    hierarchy: the rendered Markdown (unchanged from before), plus the
    parsed-but-UNVERIFIED target_files/target_symbols lists the pipeline
    needs to build the deterministic evidence bridge. Never claims these
    paths/symbols are real -- that's `build_planner_candidates`'s job.

    `security_invariant`/`remediation_mechanism`/`narrower_alternative_
    considered`/`required_edits`/`approaches_to_avoid`/`explicit_unknowns`
    are the SAME already-parsed JSON values `_render_plan` already renders
    into `rendered` -- ALSO kept here structurally, mirroring exactly the
    pattern `RemediationStrategyResult` already uses for its own analogous
    free-text fields (see that class's docstring). No prompt or JSON schema
    change: every one of these fields already existed in the parsed
    response; this only stops discarding them after rendering. Additive --
    every existing caller that only ever read `.rendered`/`.target_files`/
    `.target_symbols` is unaffected.

    `narrower_alternative_decision`: the Planner's explicit, structured
    decision about `narrower_alternative_considered` -- `"SELECTED"`,
    `"REJECTED"`, or `"NONE_IDENTIFIED"` (see
    prompts/remediation_planner.md's own field description), or `None` when
    the response omitted it or supplied a value outside that set. This is
    the ONLY thing the Planner Claim Verifier orchestration (pipeline.py)
    reads to decide WHICH question to ask the verifier -- it is never
    inferred from `narrower_alternative_considered`'s prose. `None` is
    handled entirely by the orchestration's own fail-closed default, not by
    this module guessing a value.

    Read by the Planner Claim Verifier orchestration (pipeline.py) to
    decide whether verification is even triggered at all, and in which
    mode, and (when triggered) to give the verifier the exact claim to
    check -- never by Strategy or Patch Generation, which continue to read
    only the rendered Markdown.

    `additional_evidence_required` is the Planner's own structured,
    load-bearing evidence-sufficiency gate -- see
    `run_planning_evidence_acquisition`'s own docstring for how it drives
    the bounded acquisition loop. Unlike `target_authority_unresolved`
    (Strategy's own asymmetric bool, where an absent/malformed key
    defaults PERMISSIVELY to `False`), this field cannot be a plain bool:
    the governing invariant (see `_planning_gate_outcome`) requires telling
    "the model explicitly certified sufficiency" apart from "the model
    said nothing trustworthy at all" -- a two-valued bool cannot represent
    that distinction, so this is a small closed string enum instead, one
    of `"explicit_false"` (the model wrote a real JSON `false` -- the ONLY
    state that can ever certify a plan grounded), `"explicit_true"` (a
    real JSON `true` -- more evidence is being requested),
    `"missing"` (the key was absent from the response), or `"malformed"`
    (the key was present but not a real JSON boolean -- `null` or a wrong
    type). `"missing"` and `"malformed"` both fail closed identically for
    gating purposes (see `_planning_gate_outcome`) but are kept distinct
    here so the trace can record which one actually happened. Parsed by
    `_parse_additional_evidence_required`, below.

    `evidence_requests` is the Planner's own structured request for
    additional repository evidence -- every already-parsed
    `PlanningEvidenceRequest` from the response's `evidence_requests`
    list, valid or not (schema validity is decided later, by
    `_validate_planning_request_schema`, only for whichever requests the
    gate actually needs to act on -- this field itself never drops or
    filters anything at parse time, mirroring `GuidedContextRequest`'s own
    parse-then-validate-later split). Never itself authoritative: only
    `run_planning_evidence_acquisition`'s own gate/resolution logic reads
    it as anything other than an observability record."""

    rendered: str
    target_files: "list[str]"
    target_symbols: "list[str]"
    security_invariant: "str | None" = None
    remediation_mechanism: "str | None" = None
    narrower_alternative_decision: "str | None" = None
    narrower_alternative_considered: "str | None" = None
    required_edits: "list[str]" = []
    approaches_to_avoid: "list[str]" = []
    explicit_unknowns: "list[str]" = []
    additional_evidence_required: str = "missing"
    evidence_requests: "list[PlanningEvidenceRequest]" = []


_EMPTY_PLAN_RESULT = RemediationPlanResult(rendered="", target_files=[], target_symbols=[])


def _find_balanced_json_objects(text: str) -> "list[str]":
    """Find every top-level, brace-balanced ``{...}`` substring in `text`,
    respecting JSON string-literal syntax (a ``{``/``}`` inside a quoted
    string value never confuses the depth count) -- but NOT respecting
    intent: a bare, code-formatted ``{}`` sitting in the model's own
    explanatory prose (never inside a JSON string at all) is, syntactically,
    an equally valid top-level balanced object, and this scanner has no way
    to tell it apart from that. Purely syntactic bracket-matching -- no
    JSON parsing, no semantic interpretation, no repair -- so a returned
    substring is only a CANDIDATE; the caller still runs it through
    `json.loads`, and (for this module) a Planner-specific shape check
    (`_has_plan_shape`), before trusting it.

    Duplicated, byte-for-byte, from remediation_verifier.py's own
    `_find_balanced_json_objects` (itself duplicated from
    test_plan_discovery.py) -- proven there against real urllib3 and
    minimist incidents with this exact failure shape, now separately
    reproduced against a real minimist Planner revision response that
    prefixed a fully valid Planner object with explanatory prose containing
    several bare `{}` snippets. Kept as a local duplicate rather than a
    cross-module import: this is a small (~25-line), fully self-contained,
    dependency-free primitive, and this module family already duplicates
    its other small parsing primitives per stage (`_FENCE_RE`/
    `_parse_json_response` are themselves already duplicated between this
    module and remediation_verifier.py) rather than sharing them across
    otherwise-unrelated canonical stages -- a new shared module for one
    ~25-line function would be more invasive than this duplication, not
    less."""
    objects: "list[str]" = []
    depth = 0
    start = None
    in_string = False
    escaped = False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                objects.append(text[start:i + 1])
                start = None
    return objects


_PLAN_SHAPE_FIELDS = (
    "remediation_mechanism", "target_files", "target_symbols",
    "security_invariant", "narrower_alternative_decision",
)
"""The Planner-specific structural fingerprint `_has_plan_shape` requires
ALL of, together -- deliberately a combination, not "any one known field":
a single shared field name (e.g. just `target_files`) is common enough in
ordinary prose-adjacent JSON-like fragments that it would not reliably
distinguish a genuine Planner object from incidental noise, whereas this
exact 5-field combination -- the finding's own root condition
(`security_invariant`), its proposed fix (`remediation_mechanism`), its
scope (`target_files`/`target_symbols`), and its structured narrowing
decision (`narrower_alternative_decision`, unique to this schema) -- is
specific to a genuine Planner response. `required_edits`/
`approaches_to_avoid`/`explicit_unknowns` are deliberately excluded from
the fingerprint: the 5 required here are already sufficient to be specific,
and every field actually read downstream already tolerates a missing key
(see RemediationPlanResult's own construction) -- this is a shape check on
KEY PRESENCE only, never a value/type check, so it stays a pure
disambiguator and never becomes a second schema validator."""


def _has_plan_shape(parsed) -> bool:
    """The Planner-specific structural discriminator used to disambiguate a
    real candidate from prose-embedded brace noise: a dict declaring ALL of
    `_PLAN_SHAPE_FIELDS` as keys (any value, including `null`/empty-list --
    this checks key PRESENCE, not field validity). Nothing more -- this is
    NOT schema validation (that remains generate_remediation_plan's own
    job, run afterward, unchanged, on whatever this accepts); it exists
    only to tell "this looks like it could be our response at all" apart
    from a bare `{}` or some other object shape the model's own prose
    happened to contain. A candidate that passes this check can still end
    up with every field normalized to `None`/`[]` by the existing
    downstream logic exactly as before -- this function narrows AMBIGUITY,
    it does not narrow validity. Mirrors remediation_verifier.py's own
    `_has_verifier_shape` in role and placement, adapted to a
    multi-field fingerprint since the Planner schema has no single field
    as distinctively load-bearing as the verifier's own `status`."""
    if not isinstance(parsed, dict):
        return False
    return all(field in parsed for field in _PLAN_SHAPE_FIELDS)


def _parse_json_response(raw: str) -> "dict | None":
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip()
    m = _FENCE_RE.match(text)
    if m:
        text = m.group(1).strip()

    # Fast path -- UNCHANGED: the whole (fence-stripped) response parses as
    # JSON on its own. This is the only path taken for a well-formed
    # response, and the only path that existed before this fix.
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        return parsed

    # Fallback -- only reached when the whole response did NOT parse as
    # JSON on its own (e.g. explanatory prose before the JSON object, the
    # exact shape a real minimist Planner revision response took). Scan for
    # every top-level, brace-balanced substring and keep only the ones that
    # look like a Planner response at all (_has_plan_shape) -- this is what
    # tells the real object apart from bare `{}` snippets (or other
    # incidental JSON-shaped fragments) the model's own prose can otherwise
    # contain. Exactly one surviving candidate is accepted; zero or more
    # than one both fail closed exactly like the pre-fix behavior already
    # did for an unparseable response -- this never selects, merges, or
    # guesses among competing candidates, and never prefers the first one
    # found over another.
    candidates = []
    for substring in _find_balanced_json_objects(text):
        try:
            candidate = json.loads(substring)
        except (json.JSONDecodeError, ValueError):
            continue  # not valid JSON on its own -- e.g. a stray "{" in prose
        if _has_plan_shape(candidate):
            candidates.append(candidate)

    if len(candidates) == 1:
        return candidates[0]
    return None  # zero or ambiguous (>1) candidates -- fail closed, same as before


def _render_plan(plan: dict) -> str:
    # "Target Discovery" (not "Remediation Plan") is deliberate: this is the
    # exploratory first call's output. It is never authoritative for Patch
    # Generation once a Final Strategy exists -- that distinction is carried
    # by this label and by context ordering (Final Strategy always renders
    # last), not by removing or hiding any field here.
    lines = ["## Target Discovery Plan (exploratory — not authoritative for Patch Generation)"]

    for key, label, is_list in _SECTIONS:
        value = plan.get(key)
        if is_list:
            if not value:
                continue
            lines.append(f"\n**{label}:**")
            lines.extend(f"- {item}" for item in value)
        else:
            if not value:
                continue
            lines.append(f"\n**{label}:** {value}")

    if len(lines) == 1:
        return ""  # nothing but the heading -- no usable content
    return "\n".join(lines) + "\n"


def _string_list(value) -> "list[str]":
    """Best-effort coercion for a JSON field that is *supposed* to be a list
    of strings: a non-list value degrades to [], and non-string items are
    dropped rather than crashing anything downstream."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _parse_additional_evidence_required(plan: dict) -> str:
    """Parse the Planner's `additional_evidence_required` field into one of
    the four states `RemediationPlanResult.additional_evidence_required`'s
    own docstring documents. Unlike `_parse_target_authority_unresolved`,
    there is no permissive default: a genuinely absent key is `"missing"`,
    never silently `"explicit_false"` -- see `_planning_gate_outcome` for
    why absence can never certify a plan grounded. A present-but-not-a-
    real-JSON-boolean value (an explicit `null`, a string, a number) is
    `"malformed"`, kept distinct from `"missing"` purely for trace
    forensics (see PlanningAttemptRecord.gate_state) -- both states are
    treated identically by the gate itself."""
    if "additional_evidence_required" not in plan:
        return "missing"
    value = plan.get("additional_evidence_required")
    if isinstance(value, bool):
        return "explicit_true" if value else "explicit_false"
    return "malformed"


def _parse_one_planning_request(item) -> "PlanningEvidenceRequest | None":
    """Extract only the four allowed fields from one raw JSON
    `evidence_requests` item -- anything else present is never read.
    Returns None only when `item` isn't even a dict (mirrors
    `_parse_one_guided_request`'s own convention)."""
    if not isinstance(item, dict):
        return None

    def _s(key: str) -> "str | None":
        v = item.get(key)
        return v.strip() if isinstance(v, str) and v.strip() else None

    return PlanningEvidenceRequest(
        request_type=_s("request_type"),
        file_hint=_s("file_hint"),
        symbol=_s("symbol"),
        reason=_s("reason"),
    )


def _parse_planning_evidence_requests(plan: dict) -> "list[PlanningEvidenceRequest]":
    """Parse the Planner's `evidence_requests` list -- a non-list value
    (missing key, wrong type) coerces to `[]` (the "malformed request-list
    container" case), and individual non-dict entries are silently
    dropped, mirroring `_string_list`'s own defensive-coercion convention.
    Schema validity of each SURVIVING entry (does it have the fields its
    own `request_type` requires) is decided later, only when the gate
    actually needs it -- see `_validate_planning_request_schema`."""
    raw = plan.get("evidence_requests")
    if not isinstance(raw, list):
        return []
    requests: "list[PlanningEvidenceRequest]" = []
    for item in raw:
        parsed = _parse_one_planning_request(item)
        if parsed is not None:
            requests.append(parsed)
    return requests


def generate_remediation_plan(
    vulnerability_text: str, llm, code_context: str = "", retry_hint: str = "",
    stage: str = "remediation_planning",
) -> RemediationPlanResult:
    """
    Ask the model to commit to a remediation strategy before Patch
    Generation runs. Never generates code or a diff. Best-effort: any
    ordinary call or parsing failure (network, timeout, malformed
    response) returns an all-empty RemediationPlanResult so the pipeline
    degrades exactly like every other optional context section -- no
    rendered plan, and no Planner candidates for the enrichment bridge.

    ModelUnavailableError is the one exception NOT treated as best-effort:
    it means the requested model was rejected and either the run is
    non-interactive or the user declined to pick a working alternative --
    an explicit execution/configuration decision, not ordinary evidence
    acquisition failure. It must abort the run, not degrade to "no plan".

    `retry_hint`, when given, is appended as a "## Retry instruction"
    section -- the exact same idiom `generate_patch()`/`generate_patch_raw()`
    already use for their own bounded retry callers. Empty by default (the
    default preserves this function's exact prior behavior byte-for-byte):
    this is what the Planner Claim Verifier orchestration (pipeline.py)
    uses for its own ONE bounded revision call when the verifier finds a
    concrete contradiction -- never a general retry/agent loop, and this
    function itself still makes exactly one LLM call regardless of whether
    a hint is given.

    `stage`, like `generate_patch_raw`'s own parameter of the same name, is
    purely an observability tag for the LLM call tracer -- it never
    affects the request or the returned text. Defaults to
    "remediation_planning" (identical to this function's prior hardcoded
    value, so every pre-existing caller is unaffected); a revision call
    should pass a distinct value (e.g. "remediation_plan_revision") so the
    two calls remain distinguishable in a trace.
    """
    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    user_message = "## Vulnerability report\n\n" + vulnerability_text
    if code_context:
        user_message += "\n\n## Repository evidence\n\n" + code_context
    if retry_hint:
        user_message += "\n\n## Retry instruction\n\n" + retry_hint

    try:
        raw = llm.complete(system_prompt, user_message, stage=stage)
    except ModelUnavailableError:
        raise
    except Exception:
        return _EMPTY_PLAN_RESULT

    plan = _parse_json_response(raw)
    if plan is None:
        return _EMPTY_PLAN_RESULT

    try:
        rendered = _render_plan(plan)
    except Exception:
        rendered = ""

    def _opt_str(value) -> "str | None":
        return value if isinstance(value, str) and value.strip() else None

    def _opt_decision(value) -> "str | None":
        # Fail-closed normalization, not inference: a missing field, a
        # non-string value, or any string outside _VALID_NARROWER_DECISIONS
        # all collapse to the SAME `None` -- this never guesses a decision
        # from wording (e.g. treating "I select it" as SELECTED); it only
        # recognizes the exact enum value the schema asked for. Case/
        # whitespace-tolerant only ("selected", " SELECTED ") since that is
        # ordinary response normalization, not semantic interpretation.
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized in _VALID_NARROWER_DECISIONS:
                return normalized
        return None

    return RemediationPlanResult(
        rendered=rendered,
        target_files=_string_list(plan.get("target_files")),
        target_symbols=_string_list(plan.get("target_symbols")),
        security_invariant=_opt_str(plan.get("security_invariant")),
        remediation_mechanism=_opt_str(plan.get("remediation_mechanism")),
        narrower_alternative_decision=_opt_decision(plan.get("narrower_alternative_decision")),
        narrower_alternative_considered=_opt_str(plan.get("narrower_alternative_considered")),
        required_edits=_string_list(plan.get("required_edits")),
        approaches_to_avoid=_string_list(plan.get("approaches_to_avoid")),
        explicit_unknowns=_string_list(plan.get("explicit_unknowns")),
        additional_evidence_required=_parse_additional_evidence_required(plan),
        evidence_requests=_parse_planning_evidence_requests(plan),
    )


# ---------------------------------------------------------------------------
# Planner -> deterministic enrichment bridge
#
# Everything below treats the Planner's target_files/target_symbols as
# hypotheses, never as facts. Nothing here adds a new LLM call, a new
# repository parse, a new index, or a new call graph -- it only verifies
# Planner proposals against data structures (RepositoryIndex, constants,
# the call graph) that InvestigationContext already built for this run,
# then reuses the existing enrich_candidates/fuse_evidence/
# render_repository_understanding chain unmodified.
# ---------------------------------------------------------------------------

_PLANNER_HEADING = "## Planner-Proposed Candidate Evidence"
_PLANNER_DISCLAIMER = (
    "*The file and symbol locations below were proposed by the experimental "
    "Remediation Planner -- an LLM hypothesis, not deterministic Repository "
    "Grounding. Every path and symbol shown here was independently verified "
    "to exist in this repository before any enrichment ran. The structural "
    "facts below (call graph, constants, tests, etc.) are deterministic. "
    "None of this confirms that these locations are vulnerable, or that "
    "they are the correct remediation target.*"
)


def _verify_file(raw_path, repo_root: Path) -> "str | None":
    """A Planner-proposed path survives only if it is a non-empty string,
    not absolute, contains no `..` traversal segment, resolves to a real
    regular file *inside* repo_root, and is returned as the canonical
    repo-relative path (never the raw string the model happened to use)."""
    if not isinstance(raw_path, str):
        return None
    raw_path = raw_path.strip()
    if not raw_path:
        return None
    if raw_path.startswith("/") or raw_path.startswith("\\"):
        return None
    if len(raw_path) > 1 and raw_path[1] == ":" and raw_path[0].isalpha():
        return None  # Windows drive-letter absolute path, e.g. "C:\..."
    if ".." in Path(raw_path).parts:
        return None

    try:
        resolved_root = repo_root.resolve()
        candidate = (resolved_root / raw_path).resolve()
        rel = candidate.relative_to(resolved_root)
    except (ValueError, OSError):
        return None

    if not candidate.is_file():
        return None
    return str(rel)


def _split_symbol_entry(raw: str) -> "tuple[str | None, str]":
    """Supports `path/to/file.py:Class.method`, `path/to/file.py:Class`,
    and a bare symbol name with no file hint at all."""
    raw = raw.strip()
    if ":" in raw:
        maybe_file, _, maybe_symbol = raw.rpartition(":")
        if maybe_file.strip() and maybe_symbol.strip():
            return maybe_file.strip(), maybe_symbol.strip()
    return None, raw


def _file_part(func_id: str) -> str:
    colon_idx = func_id.rfind(":")
    return func_id[:colon_idx] if colon_idx > 0 else func_id


class _SymbolMatch(NamedTuple):
    """The richer result of resolving one Planner-proposed symbol string --
    everything the source-excerpt bridge needs (kind/end_line/func_id) in
    addition to the (file, label, line) shape `_resolve_symbol` has always
    returned. Built once per symbol; never re-derived by a second lookup
    implementation."""

    file: str
    label: str
    kind: str  # "function" | "constant"
    line: int
    end_line: "int | None"
    func_id: "str | None"  # set only when kind == "function"


# ---------------------------------------------------------------------------
# Deterministic identifier fallback -- final-target readiness only.
#
# The structured lookups above (RepositoryIndex.search_by_name, the
# constants table) are only as complete as the upstream repository
# analyzer's own function/constant index. A construct that analyzer
# doesn't index at all (observed: a JavaScript function declared inside
# another function's body, e.g. `module.exports = function (...) {
# function setKey (...) { ... } }`) can have exact, real source sitting in
# an already-verified file while still resolving to nothing through
# either lookup -- indistinguishable, from this module's point of view,
# from a genuinely-hallucinated symbol name unless something else steps
# in. This fallback is that something else: given the exact identifier
# name and the small set of files the CALLER has already independently
# verified (never a wider search), it looks for the identifier directly
# in that verified file text -- no LLM call, no new language grammar, no
# fuzzy matching, and it fails closed (returns None) the moment the
# result would be ambiguous rather than ever guessing.
# ---------------------------------------------------------------------------

_FALLBACK_FIXED_WINDOW_LINES = 40
"""Half-window (lines) around a fallback-recovered identifier when no
balanced block could be found -- generous enough to usually still contain
a short-to-medium function, but bounded, never the whole file."""

_FALLBACK_MAX_BLOCK_SCAN = 400
"""Safety cap on how many lines _bounded_declaration_block will scan
forward counting brace depth -- bounds the cost of a pathological or
unbalanced input; the fixed-window fallback below takes over past this."""

_FALLBACK_VARIABLE_DECL_RE_PART = r"^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+{name}\b"
"""Isolated separately (rather than inlined only in
_FALLBACK_DECLARATION_RE_PARTS below) so _deterministic_identifier_fallback
can re-test a chosen hit against this ONE shape specifically -- see its own
`class_qualifier` handling: a plain variable declaration is never a valid
match for a class-qualified request, no matter how it was found."""

_FALLBACK_DECLARATION_RE_PARTS = (
    r"^[ \t]*(?:export[ \t]+)?function[ \t]+{name}[ \t]*\(",
    r"^[ \t]*def[ \t]+{name}[ \t]*\(",
    r"^[ \t]*class[ \t]+{name}\b",
    _FALLBACK_VARIABLE_DECL_RE_PART,
)
"""A small, fixed set of already-common declaration shapes -- deliberately
not a language grammar. Matched literally against real file text, never
against a fabricated one."""


def _bounded_declaration_block(lines: "list[str]", decl_line0: int) -> int:
    """Best-effort 0-indexed end line for the declaration starting at
    `decl_line0`, found by counting brace depth from that line forward
    (never a real parser -- no tokenizing of strings/comments, so a brace
    inside one can occasionally mis-count; bounded by
    _FALLBACK_MAX_BLOCK_SCAN so a mis-count can never scan past a small,
    fixed limit). Returns `decl_line0` unchanged if no `{` is ever seen or
    the depth never returns to zero within the scan limit -- the caller
    then falls back to a fixed-size window instead of trusting an
    unresolved brace count."""
    limit = min(len(lines), decl_line0 + _FALLBACK_MAX_BLOCK_SCAN)
    depth = 0
    opened = False
    for i in range(decl_line0, limit):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
        if opened and depth <= 0:
            return i
    return decl_line0


_DECLARATION_FORM_SCAN_LINES = 5
"""Bounded lookahead (lines), used only to classify a declaration's OWN
signature as brace-scoped or indentation-scoped BEFORE deciding whether
_bounded_declaration_block's brace-depth scan even applies -- large enough
for a realistic multi-line function/method signature, far smaller than
_FALLBACK_MAX_BLOCK_SCAN (which scans the whole body, not just the
signature)."""


def _declaration_is_brace_scoped(lines: "list[str]", decl_line0: int) -> bool:
    """Best-effort, syntax-only classification of the declaration starting
    at `decl_line0`: does its OWN signature open a brace-delimited block
    (a `{` at the top level of the signature, outside any `(...)`/`[...]`
    the signature itself contains -- e.g. `function foo() {`, `class Foo
    {`), or does it terminate in a bare trailing `:` with no such brace
    first -- the indentation-scoped shape every `def`/`class` declaration
    in Python (and any similarly indentation-scoped language) always uses?

    This exists because `_bounded_declaration_block`'s brace-depth counter
    was written for brace-delimited languages and has no notion of
    indentation-scoped ones at all: a Python declaration whose docstring
    or a nearby comment happens to contain a BALANCED pair of literal `{`
    `}` characters (e.g. a format-string example like `{backoff factor}`)
    makes that counter's depth return to zero right there, long before the
    declaration's real body -- silently mis-truncating the block. This
    check runs first and skips the brace counter entirely for a
    declaration whose own signature is unambiguously indentation-scoped,
    so a docstring or comment appearing later can never be mistaken for
    the declaration's own closing brace.

    Scans forward at most `_DECLARATION_FORM_SCAN_LINES` lines (the
    signature only, never the body), tracking `(`/`[` nesting so a `{`
    used as a default-argument value (e.g. `def f(x: dict = {}):`) is not
    mistaken for the signature's own block-opening brace. Returns True
    (brace-scoped) the moment a top-level `{` is seen; False
    (indentation-scoped) the moment a line, with top-level nesting closed,
    ends in a bare `:`. Defaults to True -- preserving
    `_bounded_declaration_block`'s existing behavior completely unchanged
    -- if neither is found within the bounded window; this function only
    ever ADDS one new, narrow early-exit, it never removes or weakens the
    existing brace-scan path for anything it can't confidently classify."""
    limit = min(len(lines), decl_line0 + _DECLARATION_FORM_SCAN_LINES)
    nesting = 0
    for i in range(decl_line0, limit):
        line = lines[i]
        for ch in line:
            if ch in "([":
                nesting += 1
            elif ch in ")]":
                nesting = max(0, nesting - 1)
            elif ch == "{" and nesting == 0:
                return True
        if nesting == 0 and line.rstrip().endswith(":"):
            return False
    return True


def _deterministic_identifier_fallback(
    name: str, candidate_files: "list[str]", repo_root: Path,
    class_qualifier: "str | None" = None,
) -> "_SymbolMatch | None":
    """Deterministic, file-scoped recovery for a target identifier whose
    exact name is known but the structured lookups in
    _resolve_symbol_details could not resolve it. Searches ONLY
    `candidate_files` -- every one of which the caller has already
    independently verified against the real repository -- never a wider
    repository scan, and never a location proposed only by an LLM.

    Two tiers, in that order, each accepted only when it is unambiguous
    across every candidate file combined:
      1. An exact declaration-like match (_FALLBACK_DECLARATION_RE_PARTS).
      2. Only if NO declaration-like match exists anywhere: an exact
         token-boundary occurrence of `name` (this tier is intentionally
         weaker, so it never runs when a real declaration was found).
    More than one match at whichever tier is checked -- or none at all --
    fails closed (returns None); this never picks an arbitrary first hit.

    `class_qualifier` is _resolve_symbol_details' own already-computed
    signal that the caller proposed this identifier in qualified form
    ("ClassName.member") -- i.e. it is asking for a class member, never a
    plain module/function-local variable, and never a bare, unowned token
    reference. When given (not None):
      - A would-be tier-1 declaration match is rejected -- fails closed
        (returns None) -- if that match is ITSELF shaped like a plain
        variable declaration (_FALLBACK_VARIABLE_DECL_RE_PART): a
        same-named `const`/`let`/`var` in some unrelated function is not
        the requested class member, no matter how unambiguous its own
        match was.
      - Tier 2 (the token-only fallback) is never used at all: it has no
        declaration shape and therefore no way to establish that a bare
        token belongs to the requested class member rather than some
        unrelated reference, so it can never be the sole basis for
        satisfying a class-qualified request.
    In both cases this fails closed rather than presenting misleading
    source under the member's label. `class_qualifier=None` (the default,
    and every existing caller before this fix) preserves the exact prior
    behavior for a bare, unqualified name -- neither check runs for one,
    since a bare request carries no such signal to check against.

    Returns a bounded source window (the balanced-brace block itself when
    one can be found, otherwise a fixed-size padded window around the
    declaration line), never the whole file -- kind="constant" so the
    existing bounded line-range reader (_read_symbol_source's constant
    branch) can render it without needing a func_id the upstream analyzer
    never assigned. Deliberately returns the block's OWN exact bounds
    with no extra padding baked in here: every existing caller that
    reads a "constant"-kind match's source already applies its own
    _DEFINITION_CONTEXT_LINES padding on top (see _read_symbol_source) --
    adding a second, independent pad here would stack, needlessly
    widening the window (and, in a tightly-packed file, risk reaching a
    neighboring declaration this fallback was never asked to include)."""
    if not name or not candidate_files:
        return None

    escaped = re.escape(name)
    declaration_pattern = re.compile(
        "|".join(part.format(name=escaped) for part in _FALLBACK_DECLARATION_RE_PARTS),
        re.MULTILINE,
    )
    token_pattern = re.compile(r"\b" + escaped + r"\b")

    file_texts: "dict[str, str]" = {}
    declaration_hits: "list[tuple[str, int]]" = []  # (file, 0-indexed line)
    token_hits: "list[tuple[str, int]]" = []
    for f in candidate_files:
        try:
            text = (Path(repo_root) / f).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        file_texts[f] = text
        for m in declaration_pattern.finditer(text):
            declaration_hits.append((f, text.count("\n", 0, m.start())))
        for m in token_pattern.finditer(text):
            token_hits.append((f, text.count("\n", 0, m.start())))

    if len(declaration_hits) > 1:
        return None  # ambiguous declaration -- fail closed, never guess
    if declaration_hits:
        chosen = declaration_hits[0]
        if class_qualifier is not None:
            chosen_file, chosen_line0 = chosen
            chosen_line_text = file_texts[chosen_file].splitlines()[chosen_line0]
            variable_only_pattern = re.compile(_FALLBACK_VARIABLE_DECL_RE_PART.format(name=escaped))
            if variable_only_pattern.match(chosen_line_text):
                return None  # a plain variable can't satisfy a class-qualified request
    elif len(token_hits) == 1 and class_qualifier is None:
        chosen = token_hits[0]
    else:
        return None  # zero/ambiguous token occurrences, or a class-qualified
        # request with no declaration match at all -- Tier 2 has no
        # declaration or ownership information capable of establishing that
        # a bare token belongs to the requested class member, so it must
        # never be the sole basis for satisfying one; fail closed.

    file, line0 = chosen
    text = file_texts[file]
    lines = text.splitlines()
    n_lines = len(lines)
    if n_lines == 0:
        return None

    # Only run the brace-depth scanner for a declaration whose own
    # signature actually opens a brace-delimited block -- an
    # indentation-scoped declaration (Python's `def`/`class`, and any
    # similarly-scoped language) never does, and a brace appearing later
    # (e.g. inside its docstring) must never be mistaken for its closing
    # brace. See _declaration_is_brace_scoped's own docstring.
    if _declaration_is_brace_scoped(lines, line0):
        block_end0 = _bounded_declaration_block(lines, line0)
    else:
        block_end0 = line0  # indentation-scoped -- go straight to the fixed window below
    if block_end0 > line0:
        start_line = line0 + 1
        end_line = min(n_lines, block_end0 + 1)
    else:
        start_line = max(1, line0 + 1 - _FALLBACK_FIXED_WINDOW_LINES)
        end_line = min(n_lines, line0 + 1 + _FALLBACK_FIXED_WINDOW_LINES)

    return _SymbolMatch(file=file, label=name, kind="constant", line=start_line, end_line=end_line, func_id=None)


def _resolve_symbol_details(
    raw: str, repo_root: Path, context, verified_files: "list[str] | None" = None,
) -> "_SymbolMatch | None":
    """Resolve one Planner-proposed symbol string using only existing
    lookups -- RepositoryIndex.search_by_name for functions, the
    already-built constants table for module/class-level constants.
    Returns None (never a fabricated line) if the symbol can't be
    confirmed, or if a stated file hint doesn't itself verify, or if the
    only match found belongs to a different file than the one proposed.

    A qualified proposal (``"ClassName.method"``) additionally requires the
    matched function's own class to equal that qualifier -- bare-name
    search alone is not enough, since a repository can legitimately contain
    the same method name on more than one class (e.g. urllib3's
    ``PoolManager.urlopen`` and ``HTTPConnectionPool.urlopen``). Without
    this check, the first same-named match anywhere in the repo would be
    accepted silently, under the ORIGINALLY PROPOSED label, even when it
    belongs to a different class entirely. A proposal with no class
    qualifier (a bare function name) is unaffected -- bare-name matching
    behaves exactly as before.

    `verified_files`, when given by the caller, is that caller's OWN
    already-independently-verified file set (e.g. a Final Strategy's own
    re-verified target_files) -- used ONLY by the deterministic fallback
    below, after both structured lookups above have already been tried
    and found nothing. Omitted (the default) preserves every existing
    caller's exact prior behavior, including returning None for a symbol
    the structured lookups can't resolve."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    if context is None:
        return None

    file_hint, name = _split_symbol_entry(raw)
    bare_name = name.rsplit(".", 1)[-1]
    class_qualifier = name.rsplit(".", 1)[0] if "." in name else None

    verified_file = None
    if file_hint:
        verified_file = _verify_file(file_hint, repo_root)
        if verified_file is None:
            return None  # a stated file that doesn't verify invalidates the whole pairing

    index = getattr(context, "index", None)
    if index is not None and bare_name:
        for match in index.search_by_name(bare_name, exact=True):
            func_id = match.get("id", "")
            candidate_file = _file_part(func_id)
            if verified_file is not None and candidate_file != verified_file:
                continue
            if class_qualifier is not None and match.get("className") != class_qualifier:
                continue
            line = match.get("startLine")
            if line is not None:
                return _SymbolMatch(
                    file=candidate_file, label=name, kind="function",
                    line=line, end_line=match.get("endLine"), func_id=func_id,
                )

    constants = getattr(context, "constants", None) or {}
    files_to_check = [verified_file] if verified_file else list(constants.keys())
    for f in files_to_check:
        for qualified_name, record in constants.get(f, {}).items():
            if qualified_name == name or qualified_name.rsplit(".", 1)[-1] == bare_name:
                line = record.get("line")
                if line is not None:
                    return _SymbolMatch(
                        file=f, label=name, kind="constant",
                        line=line, end_line=record.get("end_line"), func_id=None,
                    )

    # Neither structured lookup resolved it. If an explicit file hint was
    # given and verified, the fallback is scoped to exactly that one file
    # (an explicit, already-confirmed hint always wins over the caller's
    # broader verified set); otherwise it's scoped to the caller's own
    # verified_files, if any -- never a wider repository search, and never
    # run at all when the caller didn't independently verify anything.
    fallback_files = [verified_file] if verified_file else list(verified_files or ())
    if fallback_files:
        return _deterministic_identifier_fallback(
            bare_name, fallback_files, repo_root, class_qualifier=class_qualifier,
        )

    return None


def _resolve_symbol(raw: str, repo_root: Path, context) -> "tuple[str, str, int] | None":
    """Original (file, label, line) shape, kept as-is for existing callers
    and tests. See `_resolve_symbol_details` for the richer shape the
    source-excerpt bridge needs -- this is a thin wrapper over it, not a
    second implementation."""
    match = _resolve_symbol_details(raw, repo_root, context)
    if match is None:
        return None
    return match.file, match.label, match.line


def _resolve_planner_symbols(
    plan: RemediationPlanResult, repo_root: Path, context,
    verified_files: "list[str] | None" = None,
) -> "dict[str, _SymbolMatch]":
    """Resolve every Planner-proposed symbol exactly once, keyed by its
    resolved file (first-occurrence wins per file, matching the Planner's
    own target_symbols order). Shared by build_planner_candidates (which
    only reads .label/.line) and build_planner_source_excerpts (which also
    needs .kind/.end_line/.func_id) so this resolution never runs twice.

    `verified_files`, when given by the caller, is that caller's OWN
    already-verified Planner target_files -- passed straight through to
    _resolve_symbol_details as its own `verified_files` so a symbol the
    structured lookup can't resolve (e.g. a nested function the upstream
    analyzer never indexed) still gets the same deterministic, file-scoped
    identifier fallback _verify_strategy_targets and
    _build_final_target_slice_inner already use, scoped to exactly those
    already-verified files -- never a wider search. Omitted (the default)
    preserves every existing caller's exact prior behavior."""
    resolved: "dict[str, _SymbolMatch]" = {}
    for raw_symbol in plan.target_symbols:
        match = _resolve_symbol_details(raw_symbol, repo_root, context, verified_files=verified_files)
        if match is None:
            continue
        if match.file not in resolved:
            resolved[match.file] = match
    return resolved


def build_planner_candidates(
    plan: RemediationPlanResult,
    repo_root: Path,
    context,
    symbol_locations: "dict[str, _SymbolMatch] | None" = None,
) -> "list[RepositoryCandidate]":
    """
    Verify every Planner-proposed file against the real repository first;
    only verified files ever become candidates. Symbols are then used only
    to pick a hit_line for a file that already verified -- an unresolved
    symbol never suppresses its file's candidate, and a symbol resolving to
    a file the Planner did not also name as a target_file is never used to
    invent a new candidate. Order matches the Planner's own target_files
    order (first-occurrence deduplicated); the result is capped at the same
    small constant candidate_selection.py already uses for ordinary
    grounding, reused here rather than re-derived.

    `symbol_locations`, when given, must be `_resolve_planner_symbols`'s
    own output -- passed in by build_planner_evidence so symbol resolution
    runs exactly once per Planner proposal, shared with the source-excerpt
    bridge, rather than being recomputed here. Computed internally when
    omitted (using this same already-verified `verified_files`, so a
    3-argument caller gets the identical deterministic-fallback-eligible
    resolution build_planner_evidence's own call already gets), so
    existing 3-argument callers are unaffected in shape, only in that a
    symbol only the deterministic fallback can find now also resolves here.
    """
    if not plan.target_files:
        return []

    verified_files: "list[str]" = []
    seen: set = set()
    for raw in plan.target_files:
        vf = _verify_file(raw, repo_root)
        if vf and vf not in seen:
            seen.add(vf)
            verified_files.append(vf)

    if not verified_files:
        return []

    from .candidate_selection import DEFAULT_MAX_CANDIDATES

    if symbol_locations is None:
        symbol_locations = _resolve_planner_symbols(plan, repo_root, context, verified_files=verified_files)

    candidates = []
    for path in verified_files[:DEFAULT_MAX_CANDIDATES]:
        match = symbol_locations.get(path) if path in seen else None
        label, line = (match.label, match.line) if match else (None, None)
        evidence = DiscoveryEvidence(
            pass_name="planner_proposed",
            # 0, not None: _resolve_containing_function only reads hit_line
            # from evidence entries that carry SOME tier (its "no evidence
            # carries a tier" guard), so a real int is needed for a verified
            # symbol's hit_line to actually be used. 0 is deliberately below
            # every real repo_locator tier (1-4, see candidate_selection.py's
            # docstring) so it can never be mistaken for one. The CANDIDATE's
            # own best_tier stays None (below) -- that is what render_
            # repository_understanding's "best tier" line actually reads, so
            # the rendered text never claims an ordinary Repository Grounding
            # tier for a Planner-origin candidate.
            tier=0,
            matched_tokens=[label] if label else None,
            total_occurrences=None,
            hit_line=line if line is not None else 0,
            resolution_strategy="planner_symbol_verified" if line is not None else "planner_file_only",
        )
        candidates.append(RepositoryCandidate(path=path, evidence=[evidence], best_tier=None))
    return candidates


_SOURCE_SUBHEADING = "### Verified source from Planner-proposed candidates"
_SOURCE_DISCLAIMER = (
    "*The source below was loaded from the target repository. Each path or "
    "symbol was proposed by the Remediation Planner and then independently "
    "verified to exist before its source was read -- inclusion here does "
    "not prove that it is the correct remediation target.*"
)


_DEFINITION_CONTEXT_LINES = 3
"""Lines of exact repository text to include on each side of a rendered
"Target definition" block in the Final-Target Remediation Slice (see
build_final_target_slice below), so Patch Generation has enough real,
repository-verbatim surrounding lines to construct a unified diff hunk
without inventing them from memory.

3, not an arbitrary guess: it matches the number of context lines a
unified diff conventionally carries on each side of a change (git's own
default context is 3 lines) -- the exact quantity this system's own
output format already assumes, tied to what a patch actually needs rather
than picked freehand.

Applies only where a bounded line-range read already happens (the
constant branch of _read_symbol_source, and the two other line-range
reads inside _build_final_target_slice_inner) -- never to a
whole-function-body read (get_function_code) or a whole-file read,
neither of which needs it: both already contain ample internal context by
construction. This is a structural distinction (bounded line-range read
vs. whole-body/whole-file read), not a policy keyed on "is this a
constant" -- the same widening would apply identically to any other
short, line-range-shaped definition (a class attribute, a type alias, an
enum member, in any language) that this codebase resolves the same way.
"""


def _padded_line_range(line: int, end_line: int, pad: int) -> "tuple[int, int]":
    """Expand a (line, end_line) span by `pad` lines on each side, clamped
    to a minimum start of 1. Pure arithmetic -- no new repository read: the
    upper bound needs no file-length lookup because
    RepositoryIndex.read_file_section already clamps its own end_line to
    min(len(lines), end_line) (repository_index.py), so passing an
    end_line past EOF is always safe. pad <= 0 returns the input unchanged,
    so this is a strict no-op for every caller that doesn't opt in."""
    if pad <= 0:
        return line, end_line
    return max(1, line - pad), end_line + pad


def _rendered_end_line(start: int, source: str) -> int:
    """The end line a rendered block's header must claim, given the text
    actually returned for it starting at `start`.

    Not simply `start + pad`: read_file_section clamps its own end_line to
    min(len(lines), end_line) (repository_index.py) when a padded request
    runs past EOF, silently returning fewer lines than requested -- using
    the unclamped requested end here would make the header claim lines
    that were never actually shown. Derived from `source`'s own line
    count, which is already in hand -- no new repository read."""
    return start + max(0, len(source.splitlines()) - 1)


def _read_symbol_source(match: "_SymbolMatch", context, pad_lines: int = 0) -> "str | None":
    """Real source text for one verified symbol, using only existing
    RepositoryIndex accessors -- get_function_code for a resolved function,
    read_file_section for a resolved constant's exact defining line(s).
    Never reconstructs source by hand; returns None (never fabricated
    text) if the index/context can't produce it.

    `pad_lines` (default 0, so every existing caller is unaffected) widens
    the constant branch's read by that many lines on each side -- see
    _padded_line_range and FINAL_TARGET_SLICE_MAX_CHARS' docstring for why.
    Never applies to the function branch: a rendered whole-function body
    already contains its own internal context by construction, so this
    isn't "constants get padding, functions don't" as a policy choice --
    it only widens the one branch that performs a bounded line-range read
    at all; the function branch uses a different accessor entirely."""
    index = getattr(context, "index", None) if context is not None else None
    if index is None:
        return None
    if match.kind == "function" and match.func_id:
        return index.get_function_code(match.func_id) or None
    if match.kind == "constant" and match.end_line is not None:
        start, end = _padded_line_range(match.line, match.end_line, pad_lines)
        return index.read_file_section(match.file, start, end) or None
    return None


def _render_source_excerpt(path: str, label: "str | None", start: int, end: int, source: str) -> str:
    if label:
        header = f"#### Verified source: `{path}:{label}` (lines {start}–{end})"
    else:
        header = f"#### Verified source: `{path}` (full file, {end} lines)"
    return f"{header}\n\n```python\n{source.rstrip()}\n```\n"


class _SourceExcerptPlan(NamedTuple):
    """The complete, structural result of the Pass 1 / Pass 2 source-
    fitting decision -- the ONE place that decision is ever computed.
    `build_planner_source_excerpts` renders its string return value from
    this and only this; `_included_source_labels` (and, through it,
    `resolved_source_coverage`) reads only `.included_labels` from it.
    There is deliberately no second implementation of Pass 1/Pass 2
    ordering, budget arithmetic, source-reading, or included/omitted
    classification anywhere else -- see EVIDENCE-01, where a caller that
    instead compared two RENDERED strings was fooled by a budget numeral
    embedded in an omission notice even though this same structural result
    was byte-for-byte unchanged between the two calls being compared.

    `omitted_sizes` maps every `symbol_omitted`/`fallback_omitted` label to
    the exact character length of the rendered block that didn't fit --
    already computed in the same moment the candidate is omitted below,
    just not previously retained. This is what lets a deterministic budget-
    expansion loop (see build_planner_evidence_with_budget) decide, WITHOUT
    re-rendering, whether any currently-omitted resolved candidate could
    ever fit within the remaining legal context-budget windows -- so a
    window is never requested (and, under policy="ask", a user is never
    prompted) when it provably cannot help."""

    blocks: "tuple[str, ...]"
    included_labels: "frozenset[str]"
    symbol_omitted: "tuple[str, ...]"
    fallback_omitted: "tuple[str, ...]"
    read_failed: "tuple[str, ...]"
    budget: int
    # No default: a NamedTuple field default is a single shared object
    # reused by every instance that omits it, which would be an
    # accidentally-shared mutable dict here -- every construction site
    # (below, and _EMPTY_SOURCE_EXCERPT_PLAN) passes its own fresh dict
    # explicitly instead.
    omitted_sizes: "dict[str, int]"


def _compute_source_excerpt_plan(
    candidates: "list[RepositoryCandidate]",
    symbol_locations: "dict[str, _SymbolMatch]",
    repo_root: Path,
    context,
    max_chars: "int | None" = None,
) -> _SourceExcerptPlan:
    """
    Deterministic passes over the already-verified Planner candidates (same
    order build_planner_candidates produced) -- no scoring, no ranking
    weights, no source truncation; every admission decision is still
    whole-block-or-omit, exactly as before this function's Pass 1 gained a
    fairness sub-split (1a/1b, below).

    Pass 1 -- verified symbol excerpts, fairly admitted:

      1a (fair-share admission): every candidate with a verified Planner
      symbol gets ONE turn, in candidate order, against an equal share of
      the shared budget (`budget // count of symbol-resolved candidates`).
      A candidate whose own excerpt fits inside that share is admitted
      immediately. One that doesn't is deferred -- NOT consumed from the
      shared budget yet -- so a single oversized symbol can never be read
      before, and so starve, an otherwise-admissible sibling merely
      because of candidate order (see FIX 3 / the forensic report's Run-3
      analysis: a coarse class-level target consuming the whole window
      before two narrower sibling targets ever got a turn).

      1b (grow pass): whatever was deferred in 1a gets a second look, in
      the SAME original order, against whatever budget genuinely remains
      after every candidate already had its fair-share turn -- so a large
      candidate can still be included in full if enough was left over,
      but never ahead of a smaller sibling's own admission above.

      Never the enrichment pipeline's own containing-function guess (for a
      file-only candidate that is the whole-module catch-all, not a real
      symbol) -- only `symbol_locations.get(path)`, which holds nothing
      unless a Planner symbol was independently verified for that path. If
      the symbol's source can't be read, or its excerpt doesn't fit in
      either 1a or 1b, it is omitted explicitly -- never truncated, and
      never silently replaced by that file's full content.

    Pass 2: full-file fallback, and ONLY for candidates whose Planner
    symbol never resolved at all (not for one whose excerpt merely failed
    to fit in Pass 1 -- that stays omitted, per above). Runs strictly
    after every Pass-1 excerpt (1a AND 1b) has already had first claim on
    the shared budget, so a lower-priority fallback can never consume
    budget a higher-priority verified symbol still needed. Unaffected by
    the 1a/1b fairness split -- still first-come/whole-block-or-omit
    within its own, strictly lower-priority tier.

    The rendered block ORDER is always restored to match `candidates`'
    own original order before this returns, regardless of which sub-pass
    (1a, 1b, or 2) actually admitted a given candidate -- the fairness
    split changes WHEN a candidate's admission is decided, never WHERE it
    appears in the output once admitted.

    Never raises -- any failure is reflected as an empty/partial plan so
    callers fall back to their own existing degradation.

    `max_chars=None` (the default, and every existing caller) preserves
    the exact prior behavior byte-for-byte: the shared budget is
    `evidence_fusion.DEFAULT_MAX_CHARS`, exactly as before this parameter
    existed. Passing an explicit `max_chars` overrides that budget for
    this call only -- used by the evidence-gap Strategy fallback (see
    pipeline.py) to re-run this SAME deterministic, no-LLM-call selection
    at the larger, already-existing Final-Target Slice ceiling instead of
    a new, separate budget constant. Every other candidate-selection rule
    above (priority order, whole-block-or-omit, Pass 1 before Pass 2) is
    completely unaffected by which budget value is in force.
    """
    if max_chars is None:
        from .evidence_fusion import DEFAULT_MAX_CHARS as _budget
    else:
        _budget = max_chars

    included_labels: "set[str]" = set()
    symbol_omitted: "list[str]" = []
    fallback_omitted: "list[str]" = []
    read_failed: "list[str]" = []
    omitted_sizes: "dict[str, int]" = {}
    running = 0
    seen: set = set()
    ordered_blocks: "list[tuple[int, str]]" = []  # (original candidate index, rendered block)

    # Pre-pass: split into the Pass-1 (symbol-resolved) tier and the
    # Pass-2 (fallback-eligible) tier, preserving each candidate's
    # original index so the final output order can be restored below --
    # uses only the already-available symbol_locations dict, no I/O.
    resolved: "list[tuple[int, str, _SymbolMatch]]" = []
    fallback_eligible: "list[tuple[int, str]]" = []
    for index, candidate in enumerate(candidates):
        path = candidate.path
        if path in seen:
            continue  # defensive: build_planner_candidates already dedupes by path
        seen.add(path)
        match = symbol_locations.get(path)
        if match is None:
            fallback_eligible.append((index, path))
        else:
            resolved.append((index, path, match))

    # Pass 1a -- fair-share admission.
    fair_share = _budget // len(resolved) if resolved else _budget
    deferred: "list[tuple[int, str, str]]" = []  # (index, label, block)
    for index, _path, match in resolved:
        label = f"{match.file}:{match.label}"
        source = _read_symbol_source(match, context)
        if source is None:
            read_failed.append(label)
            continue
        block = _render_source_excerpt(match.file, match.label, match.line, match.end_line, source)
        if len(block) <= fair_share and running + len(block) <= _budget:
            ordered_blocks.append((index, block))
            included_labels.add(label)
            running += len(block)
        else:
            deferred.append((index, label, block))

    # Pass 1b -- grow pass, same original order, against whatever budget
    # genuinely remains after every candidate's Pass 1a turn.
    for index, label, block in deferred:
        if running + len(block) <= _budget:
            ordered_blocks.append((index, block))
            included_labels.add(label)
            running += len(block)
        else:
            symbol_omitted.append(label)
            omitted_sizes[label] = len(block)

    # Pass 2 -- full-file fallback, only for candidates with no resolved
    # symbol at all (never for one whose symbol excerpt was itself omitted
    # above -- that stays omitted, it is not "upgraded" to a full file).
    for index, path in fallback_eligible:
        try:
            full_text = (repo_root / path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            read_failed.append(path)
            continue
        n_lines = len(full_text.splitlines())
        block = _render_source_excerpt(path, None, 1, n_lines, full_text)
        if running + len(block) <= _budget:
            ordered_blocks.append((index, block))
            included_labels.add(path)
            running += len(block)
        else:
            fallback_omitted.append(path)
            omitted_sizes[path] = len(block)

    # Restore original candidate order for the final rendered sequence --
    # see the docstring's own note on this above.
    ordered_blocks.sort(key=lambda pair: pair[0])
    blocks = tuple(block for _, block in ordered_blocks)

    return _SourceExcerptPlan(
        blocks=blocks, included_labels=frozenset(included_labels),
        symbol_omitted=tuple(symbol_omitted), fallback_omitted=tuple(fallback_omitted),
        read_failed=tuple(read_failed), budget=_budget, omitted_sizes=omitted_sizes,
    )


def _render_source_excerpt_plan(plan: "_SourceExcerptPlan") -> str:
    """The ONLY renderer of a `_SourceExcerptPlan` into the Markdown block
    Patch Generation/Strategy prompts embed -- both
    `build_planner_source_excerpts` (existing public API) and
    `_build_planner_evidence_result` (the shared primitive behind
    `build_planner_evidence`/`build_planner_evidence_with_budget`) call
    this and only this, so there is exactly one rendering implementation
    regardless of caller."""
    if not plan.blocks and not plan.symbol_omitted and not plan.fallback_omitted and not plan.read_failed:
        return ""

    lines = [_SOURCE_SUBHEADING, "", _SOURCE_DISCLAIMER]
    if plan.blocks:
        lines.append("")
        lines.append("\n".join(plan.blocks).rstrip())

    notes = []
    if plan.symbol_omitted:
        notes.append(f"symbol excerpt(s) omitted to stay within the {plan.budget}-character budget: {', '.join(plan.symbol_omitted)}")
    if plan.fallback_omitted:
        notes.append(f"full-file fallback(s) omitted to stay within the {plan.budget}-character budget: {', '.join(plan.fallback_omitted)}")
    if plan.read_failed:
        notes.append(f"source could not be read: {', '.join(plan.read_failed)}")
    if notes:
        lines.append("")
        lines.extend(f"*{n}.*" for n in notes)

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Baseline-evidence preservation for the named-target authority-gap
# reacquisition (scope-v4/authority-v1 forensic finding): the reacquisition
# seeds `build_planner_evidence_with_budget` from Strategy #1's OWN selected
# target only (see pipeline.py's evidence-gap fallback call site) -- correct
# for FOCUSING the reacquisition on the specific dependency Strategy #1 named
# as unresolved, but this means the freshly-rebuilt PlannerEvidenceResult has
# no memory of whatever OTHER candidates Strategy #1's own (broader) evidence
# construction already resolved and rendered. Passing that fresh result alone
# as Strategy #2's `planner_evidence_ctx` silently drops it. The two
# functions below combine Strategy #1's own already-rendered evidence with
# the fresh reacquisition's own evidence -- a pure, deterministic text
# operation over already-computed results: no new repository read, no new
# LLM call, no new context-budget window request, and no keyword/prose
# inspection of anything either result's evidence actually says.
# ---------------------------------------------------------------------------

_VERIFIED_SOURCE_LABEL_RE = re.compile(r"^#### Verified source: `([^`]+)`")


def _dedupe_source_excerpt_blocks(
    blocks: "tuple[str, ...]", already_included_labels: "frozenset[str]",
) -> "tuple[str, ...]":
    """Drop any rendered source-excerpt block whose own label -- parsed
    from its first line, the exact, fixed header `_render_source_excerpt`
    itself writes ("#### Verified source: `path[:label]` (...)") --
    already appears in `already_included_labels`. This is the SAME label
    string `_compute_source_excerpt_plan` uses to populate
    `_SourceExcerptPlan.included_labels`, so this is a structural-identity
    comparison, never prose/keyword matching, and never re-derives or
    re-reads anything: the block is already-rendered text, only its own
    already-computed header is inspected.

    A block whose first line does not match this exact, code-generated
    format (should never happen for a real `_SourceExcerptPlan.blocks`
    entry -- every block is produced by `_render_source_excerpt`, which
    always writes this header first) is conservatively KEPT, never
    dropped on an unrecognized shape -- fail closed toward preserving
    evidence, never toward silently discarding it."""
    kept: "list[str]" = []
    for block in blocks:
        first_line = block.splitlines()[0] if block else ""
        match = _VERIFIED_SOURCE_LABEL_RE.match(first_line)
        label = match.group(1) if match else None
        if label is not None and label in already_included_labels:
            continue
        kept.append(block)
    return tuple(kept)


def merge_baseline_and_reacquired_planner_evidence(
    baseline: "PlannerEvidenceResult", fresh: "PlannerEvidenceResult",
) -> str:
    """Combine `baseline` (Strategy #1's own already-rendered Planner
    evidence, computed once before Strategy #1 ever ran) with `fresh`
    (the named-target authority-gap reacquisition's own newly-built
    evidence) into ONE rendered string for the one allowed Strategy
    rerun -- UNION, never replacement.

    `baseline.rendered` is preserved completely unchanged -- never
    re-derived, never re-fetched, never re-rendered, never truncated.
    Only `fresh`'s own source-excerpt blocks are deduplicated (via
    `_dedupe_source_excerpt_blocks`, structural-identity only) against
    `baseline.excerpt_plan.included_labels` before being appended under a
    clearly separate heading -- a label baseline already fully rendered
    (whole-block-or-omit, so "already included" always means "already
    complete") is never duplicated. Fresh's own structural-facts prose
    (everything before `_SOURCE_SUBHEADING` in `fresh.rendered`) and its
    own omission notes (`symbol_omitted`/`fallback_omitted`/`read_failed`,
    preserved via `_replace` on `fresh.excerpt_plan`) survive unchanged
    regardless of whether any block was deduplicated -- reuses
    `_render_source_excerpt_plan`, the ONE existing renderer, rather than
    a second rendering implementation.

    Pure text combination: no new repository read, no new LLM call, no
    new context-budget window request beyond whatever `baseline` and
    `fresh` already separately, legitimately consumed to reach their own
    (already-bounded) rendered form. The caller is responsible for also
    recording the combined length via the shared `ContextBudgetController`
    (observability only -- see `record_used`'s own docstring: it never
    gates anything) so the run's own trace accurately reflects what was
    actually sent, even though nothing here requests additional budget.

    Degenerate inputs: returns `fresh.rendered` unchanged if `baseline` is
    empty (nothing to preserve), `baseline.rendered` unchanged if `fresh`
    is empty (nothing new to add) or if deduplication leaves fresh with
    no surviving contribution at all.
    """
    if not baseline.rendered.strip():
        return fresh.rendered
    if not fresh.rendered.strip():
        return baseline.rendered

    deduped_blocks = _dedupe_source_excerpt_blocks(
        fresh.excerpt_plan.blocks, baseline.excerpt_plan.included_labels,
    )
    if deduped_blocks == fresh.excerpt_plan.blocks:
        fresh_contribution = fresh.rendered
    else:
        # Some of fresh's own blocks were already fully present in
        # baseline -- split fresh's own rendered text at the same fixed
        # subheading _render_source_excerpt_plan always starts with, so
        # fresh's structural-facts portion survives untouched and only
        # its source-excerpt portion is rebuilt from the deduped blocks.
        structural_part = fresh.rendered.split(_SOURCE_SUBHEADING, 1)[0].rstrip()
        deduped_plan = fresh.excerpt_plan._replace(blocks=deduped_blocks)
        rebuilt_source_part = _render_source_excerpt_plan(deduped_plan)
        fresh_contribution = (
            f"{structural_part}\n\n{rebuilt_source_part}" if rebuilt_source_part else structural_part
        )

    if not fresh_contribution.strip():
        return baseline.rendered

    return (
        f"{baseline.rendered.rstrip()}\n\n"
        "## Additional Verified Evidence (Authority-Gap Reacquisition)\n\n"
        f"{fresh_contribution.rstrip()}\n"
    )


def build_planner_source_excerpts(
    candidates: "list[RepositoryCandidate]",
    symbol_locations: "dict[str, _SymbolMatch]",
    repo_root: Path,
    context,
    max_chars: "int | None" = None,
) -> str:
    """Renders `_compute_source_excerpt_plan`'s result into the Markdown
    block Patch Generation/Strategy prompts embed -- this function owns
    ONLY rendering; the fitting decision itself lives entirely in
    `_compute_source_excerpt_plan` (see that function's own docstring for
    Pass 1/Pass 2 semantics). Signature and externally observable string
    output are unchanged from before this was split in two.

    Best-effort throughout: any failure returns "" so the caller falls
    back to structural evidence alone.
    """
    if not candidates:
        return ""

    plan = _compute_source_excerpt_plan(candidates, symbol_locations, repo_root, context, max_chars=max_chars)
    return _render_source_excerpt_plan(plan)


def _included_source_labels(
    candidates: "list[RepositoryCandidate]",
    symbol_locations: "dict[str, _SymbolMatch]",
    repo_root: Path,
    context,
    max_chars: "int | None" = None,
) -> "frozenset[str]":
    """The set of candidate/symbol labels `build_planner_source_excerpts`'s
    OWN fitting decision (`_compute_source_excerpt_plan`) actually included
    as real source -- never rendered text. Two calls with different
    `max_chars` values against the SAME candidates/symbol_locations are
    directly comparable set-for-set: an unchanged set means the larger
    budget fit nothing new, regardless of how any rendered omission notice
    happens to be worded (see EVIDENCE-01)."""
    if not candidates:
        return frozenset()
    return _compute_source_excerpt_plan(
        candidates, symbol_locations, repo_root, context, max_chars=max_chars,
    ).included_labels


def _render_planner_evidence(understanding) -> str:
    """Thin wrapper around the existing renderer: re-labels its fixed
    heading + preamble with Planner-specific provenance wording, without
    duplicating any of its actual rendering logic. render_repository_
    understanding's header is always exactly `_HEADING + "\\n\\n" +
    _PREAMBLE + "\\n"` with no blank line inside _PREAMBLE itself, so
    splitting on the first two "\\n\\n" occurrences cleanly isolates
    (heading, preamble, everything else) -- "everything else" is the only
    part reused verbatim here."""
    from .evidence_fusion import render_repository_understanding

    rendered = render_repository_understanding(understanding)
    if not rendered:
        return ""
    parts = rendered.split("\n\n", 2)
    rest = parts[2] if len(parts) > 2 else ""
    if not rest.strip():
        return ""
    return f"{_PLANNER_HEADING}\n\n{_PLANNER_DISCLAIMER}\n\n{rest}"


_EMPTY_SOURCE_EXCERPT_PLAN = _SourceExcerptPlan(
    blocks=(), included_labels=frozenset(), symbol_omitted=(), fallback_omitted=(),
    read_failed=(), budget=0, omitted_sizes={},
)


class PlannerEvidenceResult(NamedTuple):
    """Structured result of one Planner-evidence construction/rendering
    call at a given character budget -- ties the rendered Markdown block
    Strategy prompts embed to the SAME `_SourceExcerptPlan` that decided
    it (see that type's own docstring: the one place source-fitting is
    ever computed). `excerpt_plan.included_labels` IS the structural
    source-coverage signature `resolved_source_coverage` already defines
    -- no second coverage model is introduced here. Returned by both
    `build_planner_evidence` (via `.rendered`, unchanged public contract)
    and `build_planner_evidence_with_budget` (the full structured result,
    used by both Strategy #1's own construction and the evidence-gap
    Strategy fallback -- see pipeline.py)."""

    rendered: str
    excerpt_plan: "_SourceExcerptPlan"


def _build_planner_evidence_result(
    plan: RemediationPlanResult,
    repo_root,
    vulnerability_text: str,
    context,
    max_chars: "int | None" = None,
) -> PlannerEvidenceResult:
    """The one real implementation behind both `build_planner_evidence`'s
    string return and `build_planner_evidence_with_budget`'s expansion
    loop -- never a second resolve/verify/render pass. See
    `build_planner_evidence`'s own docstring for the exact bridge contract
    this reproduces; this function differs only in ALSO returning the
    `_SourceExcerptPlan` that `build_planner_evidence` itself discards
    after rendering.

    Returns `PlannerEvidenceResult("", _EMPTY_SOURCE_EXCERPT_PLAN)` -- never
    raises -- under every condition `build_planner_evidence` returns ""
    for: no repo_root, nothing proposed, no candidates survive
    verification, or any downstream step fails.
    """
    _empty = PlannerEvidenceResult(rendered="", excerpt_plan=_EMPTY_SOURCE_EXCERPT_PLAN)
    if not repo_root or not (plan.target_files or plan.target_symbols):
        return _empty
    try:
        root = Path(repo_root)
        # Same file-verification pass build_planner_candidates itself does
        # (and will redo, harmlessly, immediately below) -- computed here
        # first so _resolve_planner_symbols can pass it through to
        # _resolve_symbol_details as `verified_files`, giving a symbol the
        # structured lookup can't resolve (e.g. a nested function the
        # upstream analyzer never indexed) the same deterministic,
        # file-scoped identifier fallback _verify_strategy_targets and
        # _build_final_target_slice_inner already use -- never a wider
        # search than these already-verified target_files.
        verified_target_files: "list[str]" = []
        seen_target_files: set = set()
        for raw in plan.target_files:
            vf = _verify_file(raw, root)
            if vf and vf not in seen_target_files:
                seen_target_files.add(vf)
                verified_target_files.append(vf)

        # Resolved exactly once here, then reused for both candidate
        # construction (hit_line selection) and source-excerpt selection
        # below -- never re-derived by a second lookup pass.
        symbol_locations = _resolve_planner_symbols(plan, root, context, verified_files=verified_target_files)
        candidates = build_planner_candidates(plan, root, context, symbol_locations=symbol_locations)
        if not candidates:
            return _empty

        from .candidate_enrichment import enrich_candidates
        from .candidate_selection import CandidateSelection
        from .evidence_fusion import fuse_evidence

        selection = CandidateSelection(
            generated=list(candidates),
            excluded_by_policy=[],
            eligible=list(candidates),
            selected=list(candidates),
            excluded_by_cap=[],
            max_candidates=len(candidates),
        )
        enrich_candidates(selection, root, vulnerability_text, context)
        understanding = fuse_evidence(selection, investigation_context_available=context is not None)
        structural = _render_planner_evidence(understanding)
        if not structural:
            return _empty

        try:
            excerpt_plan = _compute_source_excerpt_plan(
                candidates, symbol_locations, root, context, max_chars=max_chars,
            )
        except Exception:
            excerpt_plan = _EMPTY_SOURCE_EXCERPT_PLAN

        source_block = _render_source_excerpt_plan(excerpt_plan)
        rendered = f"{structural.rstrip()}\n\n{source_block}" if source_block else structural
        return PlannerEvidenceResult(rendered=rendered, excerpt_plan=excerpt_plan)
    except Exception:
        return _empty


def build_planner_evidence(
    plan: RemediationPlanResult,
    repo_root,
    vulnerability_text: str,
    context,
    max_chars: "int | None" = None,
) -> str:
    """
    Best-effort bridge: verify the Planner's proposals against the target
    repository, run only the ones that verify through the existing
    deterministic enrich_candidates -> fuse_evidence -> render_repository_
    understanding chain (reusing `context`, never rebuilding it), and
    return a separately-labeled Markdown block. Returns "" -- never
    raises -- if there is no repo_root, nothing was proposed, nothing
    verified, or any downstream step fails; the caller's existing context
    is always left untouched either way.

    `max_chars=None` (the default, and every existing caller) preserves
    the exact prior behavior byte-for-byte -- passed straight through to
    build_planner_source_excerpts, which itself defaults to
    evidence_fusion.DEFAULT_MAX_CHARS unchanged. An explicit override
    widens ONLY the source-excerpt budget for this call; the structural
    (`_render_planner_evidence`) portion never depends on it and is
    identical either way, so two calls that only differ in `max_chars`
    return identical text unless the larger budget actually let more
    verified source fit.

    Signature and return type are unchanged from before
    `_build_planner_evidence_result` existed -- this is now a one-line
    delegation to it (see `build_planner_evidence_with_budget` for the
    budget-aware sibling that needs the full structured result).
    """
    return _build_planner_evidence_result(plan, repo_root, vulnerability_text, context, max_chars=max_chars).rendered


def build_planner_evidence_with_budget(
    plan: RemediationPlanResult,
    repo_root,
    vulnerability_text: str,
    context,
    *,
    budget_controller=None,
    base_max_chars: "int | None" = None,
) -> PlannerEvidenceResult:
    """Deterministic, no-LLM-call Planner-evidence construction with bounded
    context-budget expansion -- the ONE shared implementation used by both
    Strategy #1's own evidence construction and the evidence-gap Strategy
    fallback (see pipeline.py's `_run_repository_analysis_and_remediation_
    planning` and `_run_evidence_gap_strategy_fallback`). Neither caller
    implements its own budget-growth logic; both call this.

    `budget_controller=None` (the default) reproduces
    `_build_planner_evidence_result`'s exact single-render behavior at
    `base_max_chars` (or `evidence_fusion.DEFAULT_MAX_CHARS` if that is
    also None) -- byte-identical to calling `build_planner_evidence` once,
    no expansion loop entered at all. This is what makes every existing
    caller that doesn't pass a controller unaffected.

    With a real `budget_controller`, uses the stage key "planner_evidence"
    -- deliberately NOT "final_target_slice" (Slice 2/3/4's key): that
    stage's own base window size (FINAL_TARGET_SLICE_MAX_CHARS) differs
    from this one's (DEFAULT_MAX_CHARS), and ContextBudgetController locks
    a stage's window_size in on first registration (see
    ContextBudgetController._stage) -- sharing a key across two different
    base sizes would silently corrupt whichever stage registered second.
    A distinct key also keeps this evidence-construction budget from
    competing with Guided Context's own, separate acquisition budget for
    the same run.

    Expansion loop, run entirely before any LLM call:
      1. Render at the stage's current effective budget.
      2. If nothing is budget-omitted (`excerpt_plan.omitted_sizes` empty),
         stop -- there is nothing more to acquire.
      3. Deterministically check, from the exact sizes `omitted_sizes`
         already recorded (no re-render needed), whether AT LEAST ONE
         currently-omitted resolved candidate could fit within the
         remaining LEGAL window allowance (`budget_controller.max_windows`
         minus windows already used for this stage). If none could ever
         fit, stop WITHOUT requesting an extension -- a window (and, under
         policy="ask", an interactive prompt) is never spent on a
         candidate that provably cannot benefit from it.
      4. Otherwise request exactly one more window
         (`budget_controller.request_extension`). If denied (policy
         forbids it, or the hard `max_windows` cap is already reached),
         stop -- existing fail-closed behavior.
      5. Re-render deterministically at the new, larger ceiling.
      6. If `included_labels` grew relative to the previous render, STOP
         and return this improved result -- handing off to the LLM-calling
         consumer with materially new evidence is the point; this does not
         keep growing further just because some OTHER, still-omitted
         candidate remains uncovered.
      7. If `included_labels` did NOT grow, but step 3's reachability
         check still holds (a known omitted candidate remains reachable
         within what legal budget is left), loop back to step 3 and keep
         going -- this is the corrected behavior: a symbol that needs
         several successive windows before it fits must not be abandoned
         after only one non-improving attempt.
      8. If it did not grow and no omitted candidate remains reachable,
         stop (defensive backstop; the step-3 check should already have
         caught this).

    No LLM call happens anywhere in this function -- every iteration is a
    deterministic re-render of already-resolved, already-verified
    candidates. Whole-symbol-or-omit rendering is preserved unchanged
    (see `_compute_source_excerpt_plan`): this never truncates or windows
    a candidate's source, it only changes how large a ceiling the SAME
    whole-block-or-omit decision is made against.
    """
    from .evidence_fusion import DEFAULT_MAX_CHARS

    base = base_max_chars if base_max_chars is not None else DEFAULT_MAX_CHARS
    if budget_controller is None:
        return _build_planner_evidence_result(plan, repo_root, vulnerability_text, context, max_chars=base)

    _STAGE = "planner_evidence"
    ceiling = budget_controller.effective_budget(_STAGE, base)
    result = _build_planner_evidence_result(plan, repo_root, vulnerability_text, context, max_chars=ceiling)
    budget_controller.record_used(_STAGE, len(result.rendered))

    while True:
        omitted_sizes = result.excerpt_plan.omitted_sizes
        if not omitted_sizes:
            return result

        windows_used = ceiling // base
        windows_left = budget_controller.max_windows - windows_used
        max_reachable_ceiling = ceiling + windows_left * base
        if not any(size <= max_reachable_ceiling for size in omitted_sizes.values()):
            return result  # no remaining legal window allowance could ever include any omitted candidate

        before_labels = result.excerpt_plan.included_labels
        approved = budget_controller.request_extension(
            _STAGE, base,
            reason="symbol_or_fallback_omitted",
            affected_targets=sorted(omitted_sizes),
        )
        if not approved:
            return result  # policy denies expansion, or the hard max_windows cap is already reached

        ceiling = budget_controller.effective_budget(_STAGE, base)
        candidate = _build_planner_evidence_result(plan, repo_root, vulnerability_text, context, max_chars=ceiling)
        budget_controller.record_used(_STAGE, len(candidate.rendered))

        if candidate.excerpt_plan.included_labels != before_labels:
            return candidate  # new structural coverage -- stop and hand off

        result = candidate  # no new coverage yet, but still reachable -- keep expanding


# ---------------------------------------------------------------------------
# Bounded iterative Planning evidence acquisition ("Fix A")
#
# Lets the Planner explicitly request additional repository evidence before
# its plan becomes authoritative, instead of being forced to turn a
# self-reported evidence gap into a remediation hypothesis. Structural
# bounds (MAX_PLANNING_ATTEMPTS/MAX_EVIDENCE_REQUESTS_PER_ROUND) are plain
# module-level ints, independent of ContextBudgetController -- resource
# budgeting (window/character ceilings) remains entirely the job of
# build_planner_evidence_with_budget, called unmodified below; this section
# owns only (a) the structural loop bound and (b) deterministic resolution
# of a request's existence/uniqueness, never how much of it ends up
# rendered. See RemediationPlanResult.additional_evidence_required's own
# docstring for the governing authority contract.
# ---------------------------------------------------------------------------

MAX_PLANNING_ATTEMPTS = 3
"""Initial Planning attempt + at most 2 acquisition rounds. Mirrors
MAX_GUIDED_ACQUISITION_ROUNDS's own bound and rationale: one round already
resolves the overwhelming majority of genuine evidence gaps; a second
exists only to cover a gap the first round's own new evidence reveals. A
third has never been shown necessary anywhere in this codebase and would
only add cost/drift risk -- independent of any context-budget policy."""

MAX_EVIDENCE_REQUESTS_PER_ROUND = 3
"""At most this many of one attempt's own evidence_requests are even
attempted -- any beyond this are ignored this round, never queued for a
later round. Mirrors MAX_CONTEXT_REQUESTS_PER_ROUND's own convention,
sized slightly larger since Planning-time requests are coarser (whole
files) and a genuine gap often spans more than 2 related files."""

PLANNING_REQUEST_TYPES = ("file_source", "symbol_definition")
"""The only two request shapes Planning's own evidence_requests support --
deliberately narrower than GUIDED_REQUEST_TYPES (which also has
enclosing_symbol/identifier_usage): those are edit-level refinements
meaningful once concrete edits already exist (Strategy/Slice 3's job).
Planning's own gaps are earlier and coarser -- "I don't have this file at
all" or "I don't have this symbol's definition at all"."""

PLANNING_REQUEST_FAILURE_REASONS = (
    "unsupported_request_type",
    "missing_required_field",
    "unresolved_file",
    "unresolved_symbol",
    "ambiguous_symbol",
    "ambiguous_identifier",
    "cross_file_mismatch",
    "duplicate_request",
)
"""The full, closed reason vocabulary PlanningRequestResolution.failure_reason
draws from -- every rejection sets exactly one of these, never a freeform
string. Deliberately smaller than GUIDED_REQUEST_FAILURE_REASONS (no
"context_request_limit_reached"/"target_budget_exhausted"/
"missing_target_source"/"unrelated_to_unready_edit"/"unverified_file_hint":
those are Slice-3-specific gates -- e.g. edit attribution, target
character budgets -- that do not exist at Planning time)."""


class PlanningEvidenceRequest(NamedTuple):
    """One Planner-proposed evidence request, parsed from JSON but not yet
    validated or resolved -- mirrors GuidedContextRequest's own
    parse-then-validate-later split. Only ever built from
    `request_type`/`file_hint`/`symbol`/`reason`; any other key the
    model's response JSON might contain (a line number, source code, a
    shell command) is never read into this structure at all."""

    request_type: "str | None"
    file_hint: "str | None"
    symbol: "str | None"
    reason: "str | None"


class PlanningRequestResolution(NamedTuple):
    """One deterministic resolution attempt for a single
    PlanningEvidenceRequest. `resolved=True` only when the request
    deterministically resolved to a real, unambiguous repository
    file/symbol -- independent of whether that content later fits inside
    build_planner_evidence_with_budget's own (pre-existing, unmodified)
    character ceiling; see this module's own section docstring above on
    why resolution and rendering are kept as two separate concerns."""

    request: "PlanningEvidenceRequest"
    resolved: bool
    failure_reason: "str | None"
    resolved_file: "str | None"
    resolved_symbol: "str | None"


class PlanningAttemptRecord(NamedTuple):
    """One full Planning attempt's own forensic record -- what the Planner
    said, what it requested, and what happened as a result. `outcome` is
    one of "grounded", "continue", or an "ungrounded_<reason>" string (see
    `_planning_gate_outcome`/`run_planning_evidence_acquisition`)."""

    attempt: int
    llm_tag: str
    gate_state: str
    evidence_requests: "list[PlanningEvidenceRequest]"
    invalid_requests: "list[tuple]"
    resolutions: "list[PlanningRequestResolution]"
    outcome: str


class PlanningAcquisitionResult(NamedTuple):
    """run_planning_evidence_acquisition's own output. `grounded=True`
    only when the FINAL attempt's own gate state was exactly
    `additional_evidence_required=false` with zero evidence_requests --
    see `_planning_gate_outcome`'s own docstring for the full truth table.
    `terminal_state` is "grounded" or an "ungrounded_<reason>" string,
    identical to the final attempt's own `outcome`."""

    plan_result: "RemediationPlanResult"
    planner_evidence_result: "PlannerEvidenceResult"
    grounded: bool
    terminal_state: str
    attempts: "list[PlanningAttemptRecord]"


def _validate_planning_request_schema(request: "PlanningEvidenceRequest") -> "str | None":
    """Returns a PLANNING_REQUEST_FAILURE_REASONS value if `request`'s own
    shape is rejected outright, else None. Never inspects repository
    state -- purely a shape check, mirroring
    _validate_guided_request_schema exactly."""
    if request.request_type not in PLANNING_REQUEST_TYPES:
        return "unsupported_request_type"
    if request.request_type == "file_source" and not request.file_hint:
        return "missing_required_field"
    if request.request_type == "symbol_definition" and not request.symbol:
        return "missing_required_field"
    return None


def _planning_request_key(request: "PlanningEvidenceRequest") -> tuple:
    """Cross-round duplicate-detection key -- a request whose own
    (request_type, normalized file/symbol) tuple was already attempted in
    an earlier round is never re-resolved (re-running a pure function of
    the same inputs could only reproduce the same result), mirroring
    run_guided_acquisition's own duplicate-request guard."""
    if request.request_type == "file_source":
        return ("file_source", (request.file_hint or "").strip().lower())
    return (
        "symbol_definition",
        (request.symbol or "").strip().lower(),
        (request.file_hint or "").strip().lower(),
    )


def _resolve_planning_evidence_request(
    request: "PlanningEvidenceRequest", repo_root, context,
) -> "tuple[str | None, str | None, str | None]":
    """Deterministic, no-LLM-call resolution of one evidence request --
    returns (resolved_file, resolved_symbol, failure_reason); exactly one
    of (resolved_file/resolved_symbol) or failure_reason is non-None.
    "Resolved" means only "exists and is unique" -- entirely independent
    of any character budget, new or pre-existing (see this module's
    section docstring above).

    `file_source` reuses `_verify_file` unchanged -- the same primitive
    build_planner_evidence_with_budget's own candidate verification
    already uses for target_files. `symbol_definition` reuses
    `_resolve_guided_symbol` unchanged -- the same repo-wide,
    ambiguity-fail-closed search guided acquisition already uses for its
    own symbol_definition/enclosing_symbol requests. No new resolution
    logic is introduced; this function is only a thin dispatch over two
    already-existing, already-tested primitives."""
    if request.request_type == "file_source":
        vf = _verify_file(request.file_hint, Path(repo_root)) if repo_root else None
        if vf is None:
            return None, None, "unresolved_file"
        return vf, None, None

    match, reason = _resolve_guided_symbol(request.symbol, request.file_hint, repo_root, context)
    if match is None:
        return None, None, reason or "unresolved_symbol"
    return match.file, match.label, None


def _planning_gate_outcome(
    plan_result: "RemediationPlanResult",
) -> "tuple[bool, list[PlanningEvidenceRequest], str]":
    """The ONE place Planning's authority-gate invariant is decided.
    Returns (grounded, actionable_requests, reason).

    Exactly two states are authoritative:
      - `additional_evidence_required == "explicit_false"` AND zero
        evidence_requests: GROUNDED. This is the only combination that
        may certify a plan sufficiently evidenced to finalize.
      - `additional_evidence_required == "explicit_true"` AND at least
        one schema-valid evidence_request: NOT grounded, but
        `actionable_requests` (the schema-valid subset) is worth
        attempting resolution on.

    Every other combination fails closed -- never reinterpreted by giving
    one field precedence over another, and never treated as "close enough"
    to either authoritative state:
      - explicit_false + non-empty evidence_requests: contradictory --
        the model both certified sufficiency AND asked for more evidence.
        Neither field is trusted over the other.
      - explicit_true + zero schema-valid evidence_requests: nothing
        actionable was named despite declaring insufficiency.
      - "missing" (key absent): silence is never trusted as sufficiency,
        REGARDLESS of what evidence_requests happens to contain -- only
        an explicit, valid `false` may certify grounded.
      - "malformed" (null / wrong type): same treatment as missing -- an
        explicit-but-unparseable attempt is not silence, but it is also
        not a trusted `false`.

    `actionable_requests` is non-empty ONLY for the one "continue" case
    above -- every fail-closed case returns `[]`, even when
    `evidence_requests` itself is non-empty, so a caller can never
    accidentally act on requests from a contradictory or untrustworthy
    response."""
    gate = plan_result.additional_evidence_required
    valid_requests = [
        r for r in plan_result.evidence_requests
        if _validate_planning_request_schema(r) is None
    ]

    if gate == "explicit_false" and not plan_result.evidence_requests:
        return True, [], "grounded"
    if gate == "explicit_true" and valid_requests:
        return False, valid_requests, "continue"
    if gate == "explicit_false":
        return False, [], "contradictory_false_with_requests"
    if gate == "explicit_true":
        return False, [], "no_actionable_requests_declared_insufficient"
    if gate == "missing":
        return False, [], "missing_gate"
    return False, [], "malformed_gate"


def _merge_planner_evidence_results(
    baseline: "PlannerEvidenceResult", fresh: "PlannerEvidenceResult",
) -> "PlannerEvidenceResult":
    """Like `merge_baseline_and_reacquired_planner_evidence`, but also
    combines the two results' own `_SourceExcerptPlan.blocks`/
    `included_labels` (that function returns only the merged rendered
    STRING) -- needed so a downstream `.blocks` consumer (Slice 3's own
    one-hop scan input, see pipeline.py's `_run_guided_context_
    acquisition`) sees newly-acquired evidence too, not just whichever of
    baseline/fresh happened to be rendered last. Reuses the exact same
    text-merge (`merge_baseline_and_reacquired_planner_evidence`) and the
    exact same structural dedup (`_dedupe_source_excerpt_blocks`) already
    used elsewhere -- no new merge or dedup logic, and no new character
    ceiling: `.budget` is carried through from whichever side actually
    has one, never recomputed."""
    merged_rendered = merge_baseline_and_reacquired_planner_evidence(baseline, fresh)
    if not baseline.rendered.strip():
        return fresh
    if not fresh.rendered.strip():
        return baseline

    fresh_new_blocks = _dedupe_source_excerpt_blocks(
        fresh.excerpt_plan.blocks, baseline.excerpt_plan.included_labels,
    )
    merged_plan = _SourceExcerptPlan(
        blocks=baseline.excerpt_plan.blocks + fresh_new_blocks,
        included_labels=baseline.excerpt_plan.included_labels | fresh.excerpt_plan.included_labels,
        symbol_omitted=tuple(dict.fromkeys(
            baseline.excerpt_plan.symbol_omitted + fresh.excerpt_plan.symbol_omitted
        )),
        fallback_omitted=tuple(dict.fromkeys(
            baseline.excerpt_plan.fallback_omitted + fresh.excerpt_plan.fallback_omitted
        )),
        read_failed=tuple(dict.fromkeys(
            baseline.excerpt_plan.read_failed + fresh.excerpt_plan.read_failed
        )),
        budget=fresh.excerpt_plan.budget or baseline.excerpt_plan.budget,
        omitted_sizes={**baseline.excerpt_plan.omitted_sizes, **fresh.excerpt_plan.omitted_sizes},
    )
    return PlannerEvidenceResult(rendered=merged_rendered, excerpt_plan=merged_plan)


def _render_planning_acquisition_context(
    base_evidence: str, acquired_evidence: str, prior_resolutions: "list[PlanningRequestResolution]",
) -> str:
    """The `code_context` fed to each Planning attempt after the first --
    the SAME base evidence every attempt has always received, plus
    whatever evidence_requests have resolved so far, plus (only once a
    prior round exists) a compact "already attempted" list so the model
    does not simply repeat an already-failed or already-satisfied
    request. On attempt 1 (no acquired evidence, no prior resolutions)
    this returns `base_evidence` completely unchanged -- byte-identical
    to Planning's own pre-Fix-A `code_context`, so the common "grounded on
    attempt 1" case is entirely unaffected."""
    parts = [p for p in (base_evidence, acquired_evidence) if p and p.strip()]
    if prior_resolutions:
        lines = ["## Evidence requests already attempted this run -- do not repeat these", ""]
        for r in prior_resolutions:
            req = r.request
            label = req.file_hint or req.symbol or "(unnamed)"
            outcome = "resolved -- see verified evidence above" if r.resolved else (r.failure_reason or "failed")
            lines.append(f"- {req.request_type}: {label} -- {outcome}")
        parts.append("\n".join(lines) + "\n")
    return "\n\n".join(parts)


def run_planning_evidence_acquisition(
    vulnerability_text: str, llm, repo_root, context, *, base_evidence: str = "", budget_controller=None,
) -> PlanningAcquisitionResult:
    """Bounded iterative Planning: attempt #1 -> (if the Planner explicitly
    requests evidence) deterministic bounded acquisition -> attempt #2 with
    prior evidence plus newly acquired evidence -> either a sufficiently
    grounded plan or a fail-closed ungrounded result. See this module's own
    section docstring above for the governing design, and
    `_planning_gate_outcome` for the exact authority truth table.

    Every attempt calls `generate_remediation_plan` unchanged (attempt 1
    uses stage="remediation_planning"; every reattempt uses
    stage="remediation_planning_reattempt" -- a single reused tag, mirroring
    how the Evidence-Gap Strategy Fallback's own rerun reuses
    "remediation_strategy" rather than minting a new tag per attempt).

    Evidence acquired via evidence_requests is merged monotonically across
    rounds via `_merge_planner_evidence_results` (never rebuilt from
    scratch, never dropped). The FINAL plan's own `target_files`/
    `target_symbols` are ALSO verified via `build_planner_evidence_with_
    budget` -- exactly what pre-Fix-A Planning always did -- and merged in
    as the last, freshest addition: a plan that finalizes without ever
    using evidence_requests (the common, everyday case) produces evidence
    byte-identical to pre-Fix-A behavior, since merging a populated result
    against an empty baseline returns the populated side unchanged.

    Resolution (does a requested file/symbol exist) is entirely
    independent of any character budget; rendering (does it fit) is
    entirely delegated to the pre-existing, unmodified
    `build_planner_evidence_with_budget` -- this function introduces no
    new character ceiling and no new budget-related outcome. See this
    module's own section docstring above."""
    attempts: "list[PlanningAttemptRecord]" = []
    seen_keys: set = set()
    all_resolutions: "list[PlanningRequestResolution]" = []
    requested_evidence = PlannerEvidenceResult(rendered="", excerpt_plan=_EMPTY_SOURCE_EXCERPT_PLAN)
    plan_result = _EMPTY_PLAN_RESULT

    def _finalize(grounded: bool, terminal_state: str) -> PlanningAcquisitionResult:
        own_target_evidence = build_planner_evidence_with_budget(
            plan_result, repo_root, vulnerability_text, context, budget_controller=budget_controller,
        )
        final_evidence = _merge_planner_evidence_results(requested_evidence, own_target_evidence)
        return PlanningAcquisitionResult(plan_result, final_evidence, grounded, terminal_state, list(attempts))

    for attempt_num in range(1, MAX_PLANNING_ATTEMPTS + 1):
        tag = "remediation_planning" if attempt_num == 1 else "remediation_planning_reattempt"
        code_context = _render_planning_acquisition_context(
            base_evidence, requested_evidence.rendered, all_resolutions,
        )
        plan_result = generate_remediation_plan(vulnerability_text, llm, code_context=code_context, stage=tag)

        grounded, actionable, gate_reason = _planning_gate_outcome(plan_result)
        invalid_requests: "list[tuple]" = []
        for r in plan_result.evidence_requests:
            reason = _validate_planning_request_schema(r)
            if reason is not None:
                invalid_requests.append((r, reason))

        if grounded:
            attempts.append(PlanningAttemptRecord(
                attempt_num, tag, plan_result.additional_evidence_required,
                list(plan_result.evidence_requests), invalid_requests, [], "grounded",
            ))
            return _finalize(True, "grounded")

        if not actionable:
            outcome = f"ungrounded_{gate_reason}"
            attempts.append(PlanningAttemptRecord(
                attempt_num, tag, plan_result.additional_evidence_required,
                list(plan_result.evidence_requests), invalid_requests, [], outcome,
            ))
            return _finalize(False, outcome)

        capped = actionable[:MAX_EVIDENCE_REQUESTS_PER_ROUND]
        round_resolutions: "list[PlanningRequestResolution]" = []
        new_files: "list[str]" = []
        new_symbols: "list[str]" = []
        for req in capped:
            key = _planning_request_key(req)
            if key in seen_keys:
                round_resolutions.append(PlanningRequestResolution(req, False, "duplicate_request", None, None))
                continue
            seen_keys.add(key)
            rf, rs, reason = _resolve_planning_evidence_request(req, repo_root, context)
            if reason is not None:
                round_resolutions.append(PlanningRequestResolution(req, False, reason, None, None))
            else:
                round_resolutions.append(PlanningRequestResolution(req, True, None, rf, rs))
                if req.request_type == "file_source":
                    new_files.append(rf)
                else:
                    new_symbols.append(f"{rf}:{rs}" if rf else rs)

        all_resolutions.extend(round_resolutions)
        any_new = any(r.resolved for r in round_resolutions)

        if not any_new:
            attempts.append(PlanningAttemptRecord(
                attempt_num, tag, plan_result.additional_evidence_required,
                list(plan_result.evidence_requests), invalid_requests, round_resolutions, "ungrounded_unresolvable",
            ))
            return _finalize(False, "ungrounded_unresolvable")

        if attempt_num >= MAX_PLANNING_ATTEMPTS:
            attempts.append(PlanningAttemptRecord(
                attempt_num, tag, plan_result.additional_evidence_required,
                list(plan_result.evidence_requests), invalid_requests, round_resolutions, "ungrounded_max_attempts",
            ))
            return _finalize(False, "ungrounded_max_attempts")

        synthetic = RemediationPlanResult(rendered="", target_files=new_files, target_symbols=new_symbols)
        fresh = build_planner_evidence_with_budget(
            synthetic, repo_root, vulnerability_text, context, budget_controller=budget_controller,
        )
        requested_evidence = _merge_planner_evidence_results(requested_evidence, fresh)

        attempts.append(PlanningAttemptRecord(
            attempt_num, tag, plan_result.additional_evidence_required,
            list(plan_result.evidence_requests), invalid_requests, round_resolutions, "continue",
        ))

    # Defensive backstop -- unreachable in practice: the attempt_num >=
    # MAX_PLANNING_ATTEMPTS branch above always returns before the loop
    # would naturally exhaust range().
    return _finalize(False, "ungrounded_max_attempts")


def resolved_source_coverage(
    plan: RemediationPlanResult,
    repo_root,
    context,
    max_chars: "int | None" = None,
) -> "frozenset[str]":
    """The structural "how much real, usable repository source would
    build_planner_evidence's own source-excerpt selection actually
    include for this Planner proposal, at this budget" signature.

    Reuses the SAME verified-file/symbol resolution build_planner_evidence
    performs (`_verify_file`, `_resolve_planner_symbols`,
    `build_planner_candidates` -- never a second implementation of any of
    them), feeding the SAME, single fitting implementation
    `build_planner_source_excerpts` renders from
    (`_compute_source_excerpt_plan`, via `_included_source_labels`) --
    returning only its included-label set, never rendered text.

    Exists so a caller deciding "did recovery at a larger budget actually
    acquire new, usable evidence" can compare two calls' return values
    directly (frozenset equality) instead of comparing rendered Markdown,
    which embeds the budget ceiling itself inside its own omission-notice
    text and therefore always differs across two different `max_chars`
    values regardless of whether anything substantive changed (see
    EVIDENCE-01). Does not itself build the rendered evidence block --
    `build_planner_evidence` remains the only function that does, still
    needed in full whenever a caller determines (via this function) that
    real new evidence exists.

    Returns `frozenset()` -- never raises -- under every condition
    `build_planner_evidence` itself would have returned `""` for: no
    `repo_root`, nothing proposed, or zero verified candidates."""
    if not repo_root or not (plan.target_files or plan.target_symbols):
        return frozenset()
    try:
        root = Path(repo_root)
        verified_target_files: "list[str]" = []
        seen_target_files: set = set()
        for raw in plan.target_files:
            vf = _verify_file(raw, root)
            if vf and vf not in seen_target_files:
                seen_target_files.add(vf)
                verified_target_files.append(vf)

        symbol_locations = _resolve_planner_symbols(plan, root, context, verified_files=verified_target_files)
        candidates = build_planner_candidates(plan, root, context, symbol_locations=symbol_locations)
        if not candidates:
            return frozenset()

        return _included_source_labels(candidates, symbol_locations, root, context, max_chars=max_chars)
    except Exception:
        return frozenset()


# ---------------------------------------------------------------------------
# Final Strategy -- a second, distinct LLM call over materially new evidence
#
# Runs only after build_planner_evidence() has produced verified evidence.
# Selects the smallest evidence-backed remediation mechanism -- still never
# a diff, never code. Its own target_files/target_symbols are re-verified
# with the SAME _verify_file/_resolve_symbol_details helpers the bridge
# above already uses, before anything from it is rendered: no new
# repository analysis, no broader policy engine.
# ---------------------------------------------------------------------------

_STRATEGY_HEADING = "## Final Evidence-Backed Remediation Strategy"
_STRATEGY_DISCLAIMER = (
    "*This strategy is model reasoning constrained by the verified "
    "Planner-Proposed Candidate Evidence above -- every file and symbol "
    "named here was independently re-verified against the repository; "
    "anything proposed that did not verify was removed rather than "
    "presented as a target (see \"Unverified items removed\" below when "
    "present). This is the last planning section before Patch Generation.*"
)

_STRATEGY_SECTIONS = [
    ("extended_mechanism", "Extended mechanism", False),
    ("target_files", "Verified target files", True),
    ("target_symbols", "Verified target symbols", True),
    ("required_edits", "Required edits", True),
    ("rejected_targets", "Rejected discovery targets", True),
    ("security_invariant", "Security invariant", False),
    ("insufficient_evidence", "Insufficient evidence", True),
]


class RemediationStrategyResult(NamedTuple):
    """The Final Strategy call's output. `target_files`/`target_symbols`
    here are the DETERMINISTICALLY RE-VERIFIED subset of what the model
    proposed -- anything that did not verify is listed in `warnings`
    instead, never silently promoted. `rendered` (when non-empty) already
    reflects this verified subset, not the model's raw, unverified claim.

    `extended_mechanism`/`required_edits`/`security_invariant` are additive
    fields: the same already-parsed JSON values `_render_strategy` already
    renders into Markdown, ALSO kept here structurally so callers can read
    them directly without re-parsing `rendered` text. No prompt or JSON
    schema change -- all three fields already existed in the parsed
    response (see prompts/remediation_strategy.md's output schema); this
    only stops discarding them after rendering.

    `security_invariant` in particular is the model's own one-sentence
    statement of the security property this specific fix restores (e.g.
    "a cross-origin redirect must not forward Cookie"). It is LLM-derived
    remediation guidance, produced from the already-verified repository/
    Planner evidence given to this call -- NOT deterministic evidence
    itself, and it carries the same LLM-authorship caveats as this
    function's other free-text fields (`extended_mechanism`, `required_
    edits`). Reading it here adds no new LLM call (it is already computed
    by this same, already-existing Final Strategy call whenever that call
    runs at all). Report presentation (build_validation_plan) may reuse it
    to build ONE primary Validation Action when it is present and the
    coarser keyword-based Behavior Summary is too generic to be useful on
    its own; see pipeline.py's behavior-driven action block. Never read by
    Recommendation Policy, applicability, or repair.

    `insufficient_evidence` is the model's own explicit statement (per
    prompts/remediation_strategy.md's ground rules: "If the verified
    evidence is insufficient to select a concrete mechanism, say so in
    insufficient_evidence rather than guessing") of why it could not
    select a concrete target. Structural, like the three fields above --
    kept for OBSERVABILITY/reporting only. It is deliberately NOT the
    signal patch_generation gating reads (see `evaluated` below and
    pipeline._run_guided_context_acquisition) -- a real Final Strategy
    response with empty target_files/target_symbols is unsafe to build a
    patch from whether or not the model ALSO explained itself here; an
    empty list must never be misread as "nothing to worry about."

    `evaluated` is the ONE explicit signal that structurally distinguishes
    "Final Strategy actually ran and this IS its real decision" from "no
    authoritative Final Strategy decision exists" -- True only for a
    genuinely-parsed LLM response (the constructor call at the bottom of
    generate_remediation_strategy); False for _EMPTY_STRATEGY_RESULT
    (covers: no planner_evidence_ctx to reason over, an LLM-call
    exception, or a response that failed to parse as JSON -- every one of
    these means "no decision exists," not "the decision was empty").
    Never inferred from `rendered` (presentation output) or from whether
    any other field happens to be non-empty -- see pipeline.py's own gate,
    which is REQUIRED to read this field directly rather than re-derive
    it. Existing callers that never asked this question (report
    rendering, `_render_strategy`, `_verify_strategy_targets`) are
    entirely unaffected -- this field is additive.

    `rejected_targets` is an additive field mirroring the same pattern as
    `extended_mechanism`/`required_edits`/`security_invariant` above: the
    same already-parsed `rejected_targets` JSON value `_STRATEGY_SECTIONS`
    already renders into `rendered`, ALSO kept here structurally. No
    prompt or schema change -- this key already existed in the parsed
    response; this only stops discarding it after rendering. Read by the
    verified-narrower-authority Strategy target/concretization-only block
    (see `_render_strategy_target_block`) so a target Strategy explicitly
    rejected stays visible to Patch Generation without also carrying
    Strategy's mechanism-bearing prose.

    `rejected_target_symbols` is additive, mirroring the same pattern:
    the raw, model-proposed `target_symbols` strings that
    `_verify_strategy_targets` could NOT independently verify (dropped
    from `target_symbols`, recorded only as prose in `warnings` until
    now). Kept here structurally for exactly ONE narrow, downstream use
    (see `_build_final_target_slice_inner`'s `target_class_identities`
    construction): extracting a candidate CLASS QUALIFIER from a rejected
    qualified proposal (e.g. "Container" from "Container.runtime_limit")
    so that qualifier can be INDEPENDENTLY re-resolved and confirmed
    through the exact same deterministic machinery used everywhere else
    (`_resolve_symbol_details`/`_label_is_confirmed_class`), scoped to
    this same Strategy's own already-verified `target_files`. The
    rejected string itself is NEVER treated as evidence of anything -- it
    is discarded the moment its qualifier substring has been extracted;
    only independent re-verification against real repository structure
    can ever add anything to `target_class_identities`. This can never
    rehabilitate the rejected member symbol itself: it never re-enters
    `target_symbols`, `symbol_matches`, or any edit-target category, and
    it never changes `_verify_strategy_targets`'s own verification
    outcome for anything.

    `target_authority_unresolved` is a SECOND, independent structured
    signal from `insufficient_evidence` -- additive, and, unlike every
    other field on this NamedTuple, load-bearing: it is the ONE Strategy-
    level field a caller (see pipeline.py's `_evidence_gap_fallback_trigger`
    and `_run_guided_context_acquisition`) is authorized to read to decide
    whether a NAMED target/mechanism is safe to hand to Patch Generation.
    `insufficient_evidence` itself remains exactly as before -- an
    observability-only free-text list never read by any gate (see that
    field's own docstring) -- specifically because prose is not a safe
    basis for an authority decision; this field exists so the model has a
    single, explicit, structured way to say the same thing without
    requiring downstream code to parse or keyword-match that prose.

    Deliberately ASYMMETRIC, never a positive certification: `True` means
    "at least one evidence gap I reported is load-bearing for whether my
    own selected target_files/target_symbols/mechanism is the correct
    remediation location" -- a withholding claim only. `False` (the
    default, and the value for every response that predates this field's
    existence) means only "no such withholding was asserted" -- it is
    NEVER read, here or by any caller, as "the target is verified",
    "evidence-backed", "trusted", "proven", or "semantically validated".
    Repository existence/resolution verification (`_verify_strategy_
    targets`) is completely independent of this field in both directions:
    it neither sets nor reads it, and this field never widens or narrows
    which files/symbols count as existing.

    Parsed by `_parse_target_authority_unresolved` (below): a genuinely
    absent key (the old-format/backward-compatible case) and a valid
    `True`/`False` JSON boolean are the two trusted shapes; anything else
    the model writes for this key (wrong type, or an explicit JSON `null`)
    is a malformed-but-EXPLICIT attempt to say something, which must never
    be silently coerced to the permissive `False` -- see that function's
    own docstring for the exact three-way rule and why.
    """

    rendered: str
    target_files: "list[str]"
    target_symbols: "list[str]"
    warnings: "list[str]"
    extended_mechanism: "str | None"
    required_edits: "list[str]"
    security_invariant: "str | None" = None
    insufficient_evidence: "list[str]" = []
    evaluated: bool = False
    rejected_targets: "list[str]" = []
    rejected_target_symbols: "list[str]" = []
    target_authority_unresolved: bool = False


_EMPTY_STRATEGY_RESULT = RemediationStrategyResult(
    rendered="", target_files=[], target_symbols=[], warnings=[],
    extended_mechanism=None, required_edits=[], security_invariant=None,
    insufficient_evidence=[], evaluated=False, rejected_targets=[],
    rejected_target_symbols=[], target_authority_unresolved=False,
)


def _verify_strategy_targets(
    raw_files: "list[str]", raw_symbols: "list[str]", repo_root, context
) -> "tuple[list[str], list[str], list[str], list[str]]":
    """Re-verify the Final Strategy's own proposed files/symbols using the
    exact same path/symbol verification already used for the first
    Planner's proposals -- no second implementation, no broader policy
    engine. Returns (kept_files, kept_symbols, warnings, rejected_symbols);
    an item that doesn't verify is dropped and recorded in `warnings`,
    never silently lost and never allowed to abort the call.

    Symbol verification also passes `kept_files` (this call's own
    already-verified files, built above, first) into
    _resolve_symbol_details as `verified_files` -- so a symbol the
    structured lookup can't resolve (e.g. a nested function the upstream
    analyzer never indexed) still gets a deterministic, file-scoped
    identifier fallback against exactly those already-verified files
    before being dropped as unverified. Never widens which files are
    searched: kept_files is the same set _verify_file already confirmed
    real, nothing added and nothing else considered.

    `rejected_symbols` is the raw proposed strings that did NOT verify --
    additive output, never consulted by this function's own kept/dropped
    decision. Its only sanctioned downstream use is
    `_build_final_target_slice_inner` extracting a candidate class
    qualifier from a rejected QUALIFIED proposal for independent
    re-verification (see `RemediationStrategyResult.rejected_target_symbols`);
    it must never be treated as confirming the rejected symbol itself."""
    warnings: "list[str]" = []
    kept_files: "list[str]" = []
    root = Path(repo_root) if repo_root else None

    seen_files: set = set()
    for raw in raw_files:
        vf = _verify_file(raw, root) if root is not None else None
        if vf and vf not in seen_files:
            seen_files.add(vf)
            kept_files.append(vf)
        else:
            warnings.append(f"unverified target_file removed: {raw}")

    kept_symbols: "list[str]" = []
    rejected_symbols: "list[str]" = []
    seen_symbols: set = set()
    for raw in raw_symbols:
        match = (
            _resolve_symbol_details(raw, root, context, verified_files=kept_files)
            if root is not None else None
        )
        if match is not None and raw not in seen_symbols:
            seen_symbols.add(raw)
            kept_symbols.append(raw)
        else:
            warnings.append(f"unverified target_symbol removed: {raw}")
            rejected_symbols.append(raw)

    return kept_files, kept_symbols, warnings, rejected_symbols


def _parse_target_authority_unresolved(plan: dict) -> bool:
    """Parse Strategy's `target_authority_unresolved` field -- see
    RemediationStrategyResult.target_authority_unresolved's own docstring
    for the field's meaning. Three input shapes, two trusted, one not:

      1. Key genuinely ABSENT from `plan` (old-format response, or the
         model simply omitted it): backward-compatible default, `False` --
         identical to this field never having existed, so every pre-
         existing trace/response is completely unaffected by this field's
         addition.
      2. Key present with a real JSON boolean (`isinstance(value, bool)`,
         never a truthy/falsy coercion of some other type -- same strict-
         type convention already used for this codebase's other trust-
         critical model-produced booleans, see
         remediation_verifier._parse_response's `counterexample_reaches_
         unsafe_state`/`authoritative_remediation_matches_selected_
         alternative`): trusted, returned as-is.
      3. Key present but NOT a real boolean -- a non-bool string, a
         number, an explicit JSON `null`, or any other type: this is an
         EXPLICIT attempt to say something that does not parse, which is
         a materially different situation from case 1 (silence) and must
         not collapse to the same permissive `False`. Per this field's own
         asymmetric, withholding-only contract (True can only ever ADD
         scrutiny, never remove it), the conservative reading of "the
         model explicitly touched this trust-critical field but got the
         shape wrong" is `True`, not `False` -- fails closed toward more
         scrutiny (bounded re-acquisition), never toward silently granting
         authority to a target this exact field exists to gate.

    Deliberately narrow and self-contained, matching the existing
    `_opt_str`/`_opt_decision`-style small parse helpers elsewhere in this
    module: no keyword/prose inspection of `insufficient_evidence` or any
    other field happens here or anywhere this return value is consumed.
    """
    if "target_authority_unresolved" not in plan:
        return False
    value = plan.get("target_authority_unresolved")
    if isinstance(value, bool):
        return value
    return True


def _render_strategy(
    plan: dict, verified_files: "list[str]", verified_symbols: "list[str]", warnings: "list[str]"
) -> str:
    working = dict(plan)
    working["target_files"] = verified_files
    working["target_symbols"] = verified_symbols

    body: "list[str]" = []
    for key, label, is_list in _STRATEGY_SECTIONS:
        value = working.get(key)
        if is_list:
            if not value:
                continue
            body.append(f"\n**{label}:**")
            body.extend(f"- {item}" for item in value)
        else:
            if not value:
                continue
            body.append(f"\n**{label}:** {value}")

    if warnings:
        body.append("\n**Unverified items removed:**")
        body.extend(f"- {w}" for w in warnings)

    if not body:
        return ""  # nothing usable -- a complete, correct answer, not an error

    return "\n".join([_STRATEGY_HEADING, "", _STRATEGY_DISCLAIMER] + body) + "\n"


def generate_remediation_strategy(
    vulnerability_text: str,
    llm,
    repo_root,
    context,
    repo_grounding_ctx: str = "",
    repository_understanding_ctx: str = "",
    discovery_plan_ctx: str = "",
    planner_evidence_ctx: str = "",
) -> RemediationStrategyResult:
    """
    Second, distinct LLM call (stage "remediation_strategy"). Runs only when
    there is verified Planner evidence to reason over -- with no
    `planner_evidence_ctx` there is nothing materially new for this call
    versus the first, so it is skipped entirely (no LLM call at all, not
    merely an empty result). Never generates code or a diff. Best-effort
    like `generate_remediation_plan`: any call or parsing failure returns an
    all-empty result so the pipeline continues with whatever evidence
    already existed -- never raises.

    `target_files`/`target_symbols` on the result are independently
    re-verified via `_verify_strategy_targets` before rendering -- an
    invented file or symbol never reaches Patch Generation through this
    call; it is dropped and recorded in `warnings` instead.
    """
    if not planner_evidence_ctx or not planner_evidence_ctx.strip():
        return _EMPTY_STRATEGY_RESULT

    system_prompt = _STRATEGY_PROMPT_PATH.read_text(encoding="utf-8")

    sections = ["## Vulnerability report\n\n" + vulnerability_text]
    if repo_grounding_ctx and repo_grounding_ctx.strip():
        sections.append("## Original Repository Grounding context\n\n" + repo_grounding_ctx)
    if repository_understanding_ctx and repository_understanding_ctx.strip():
        sections.append("## Ordinary Repository Understanding\n\n" + repository_understanding_ctx)
    if discovery_plan_ctx and discovery_plan_ctx.strip():
        sections.append("## Initial Target Discovery output\n\n" + discovery_plan_ctx)
    sections.append("## Verified Planner-Proposed Candidate Evidence\n\n" + planner_evidence_ctx)
    user_message = "\n\n".join(sections)

    try:
        raw = llm.complete(system_prompt, user_message, stage="remediation_strategy")
    except ModelUnavailableError:
        # Explicit execution/configuration decision, not ordinary evidence
        # acquisition failure -- must abort, not degrade to "no strategy".
        raise
    except Exception:
        return _EMPTY_STRATEGY_RESULT

    plan = _parse_json_response(raw)
    if plan is None:
        return _EMPTY_STRATEGY_RESULT

    raw_files = _string_list(plan.get("target_files"))
    raw_symbols = _string_list(plan.get("target_symbols"))
    verified_files, verified_symbols, warnings, rejected_symbols = _verify_strategy_targets(
        raw_files, raw_symbols, repo_root, context
    )

    try:
        rendered = _render_strategy(plan, verified_files, verified_symbols, warnings)
    except Exception:
        rendered = ""

    return RemediationStrategyResult(
        rendered=rendered,
        target_files=verified_files,
        target_symbols=verified_symbols,
        warnings=warnings,
        extended_mechanism=plan.get("extended_mechanism") if isinstance(plan.get("extended_mechanism"), str) else None,
        required_edits=_string_list(plan.get("required_edits")),
        security_invariant=plan.get("security_invariant") if isinstance(plan.get("security_invariant"), str) else None,
        insufficient_evidence=_string_list(plan.get("insufficient_evidence")),
        # A real, successfully-parsed response was obtained -- this IS an
        # authoritative Final Strategy decision, whatever it says (even if
        # every other field above ended up empty -- see RemediationStrategyResult's
        # own docstring on why `evaluated` is never inferred from the other fields).
        evaluated=True,
        rejected_targets=_string_list(plan.get("rejected_targets")),
        rejected_target_symbols=rejected_symbols,
        target_authority_unresolved=_parse_target_authority_unresolved(plan),
    )


# ---------------------------------------------------------------------------
# Verified-narrower authority split (deterministic, no new LLM call)
#
# Activated only when pipeline.py's own `_verified_narrower_authoritative`
# gate is True: an INDEPENDENTLY VERIFIED Planner narrower-alternative
# decision (Planner `narrower_alternative_decision == "SELECTED"`, Planner
# Claim Verifier `status == "SUPPORTED"`,
# `authoritative_remediation_matches_selected_alternative is True`)
# becomes semantic authority for Patch Generation in place of Strategy's
# own mechanism-bearing prose. Both functions below are pure, deterministic
# renderers -- no LLM call, no parsing, no new schema -- mirroring exactly
# how `_render_plan`/`_render_strategy` already render already-parsed
# structured fields into Markdown. The split is enforced by WHICH text
# occupies the flat `code_context` string (see pipeline.py's `_ctx_parts`
# assembly), never by comparing Planner's and Strategy's prose against
# each other -- Strategy's mechanism-bearing fields simply never reach
# this position in the string when the gate is True, regardless of what
# they say.
# ---------------------------------------------------------------------------

_VERIFIED_AUTHORITATIVE_HEADING = "## Verified Authoritative Remediation Semantics"
_VERIFIED_AUTHORITATIVE_DISCLAIMER = (
    "*The Planner's own selected narrower alternative was independently "
    "verified by the Planner Claim Verifier against the verified "
    "repository evidence above: the verifier confirmed the authoritative "
    "remediation matches the selected alternative. This section -- not "
    "any Strategy mechanism/required-edits text below -- is the binding "
    "remediation semantics for Patch Generation. Strategy's own role "
    "below is limited to target verification/concretization: WHERE this "
    "mechanism applies, not a separate or replacement mechanism.*"
)

_VERIFIED_AUTHORITATIVE_SECTIONS = [
    ("remediation_mechanism", "Remediation mechanism", False),
    ("security_invariant", "Security invariant", False),
    ("narrower_alternative_considered", "Narrower alternative considered (verified)", False),
    ("required_edits", "Required edits", True),
    ("approaches_to_avoid", "Approaches to avoid", True),
]


def _render_verified_authoritative_semantics(plan_result: RemediationPlanResult) -> str:
    """Deterministic rendering of ONLY the 5 verified Planner semantic
    fields (`remediation_mechanism`, `security_invariant`,
    `narrower_alternative_considered`, `required_edits`,
    `approaches_to_avoid`) -- no LLM call, no parsing, no new schema.
    Deliberately does NOT reuse `_render_plan`'s "exploratory -- not
    authoritative" heading/wording: under the verified-narrower-authority
    gate this Planner result IS authoritative, and labeling it otherwise
    would misstate that. Introduces no new semantic conclusion of its
    own -- every word here already exists on `plan_result`, produced by
    the ordinary (already-existing) Planner call and Planner Claim
    Verifier, both unmodified by this function. Returns "" (a complete,
    correct answer, not an error) when none of the 5 fields have
    content, mirroring `_render_strategy`'s own empty-body convention."""
    body: "list[str]" = []
    for attr, label, is_list in _VERIFIED_AUTHORITATIVE_SECTIONS:
        value = getattr(plan_result, attr)
        if is_list:
            if not value:
                continue
            body.append(f"\n**{label}:**")
            body.extend(f"- {item}" for item in value)
        else:
            if not value:
                continue
            body.append(f"\n**{label}:** {value}")

    if not body:
        return ""

    return "\n".join([_VERIFIED_AUTHORITATIVE_HEADING, "", _VERIFIED_AUTHORITATIVE_DISCLAIMER] + body) + "\n"


_STRATEGY_TARGET_BLOCK_HEADING = "## Strategy-Verified Targets (concretization only)"
_STRATEGY_TARGET_BLOCK_DISCLAIMER = (
    "*The remediation mechanism is independently verified and "
    "authoritative -- see \"Verified Authoritative Remediation Semantics\" "
    "above. The items below are Strategy's own independently re-verified "
    "target output only: WHERE the verified mechanism applies, not a "
    "separate or replacement mechanism. Strategy's own mechanism/"
    "required-edits/security-invariant text is deliberately omitted from "
    "this section.*"
)


def _render_strategy_target_block(strategy_result: RemediationStrategyResult) -> str:
    """Deterministic rendering of ONLY Strategy's target/concretization
    fields -- `target_files`, `target_symbols`, `rejected_targets`,
    `insufficient_evidence`, `warnings` -- used in place of `.rendered`
    for the `code_context` position under the verified-narrower-authority
    gate. Deliberately, BY CONSTRUCTION, excludes `extended_mechanism`,
    `security_invariant`, and `required_edits`: this is a hard-coded field
    allowlist, not a semantic filter -- it never inspects what those
    fields say, it simply never reads them. No LLM call, no parsing, no
    new schema. Returns "" (a complete, correct answer, not an error) when
    none of the allowed fields have content."""
    body: "list[str]" = []
    if strategy_result.target_files:
        body.append("\n**Verified target files:**")
        body.extend(f"- {f}" for f in strategy_result.target_files)
    if strategy_result.target_symbols:
        body.append("\n**Verified target symbols:**")
        body.extend(f"- {s}" for s in strategy_result.target_symbols)
    if strategy_result.rejected_targets:
        body.append("\n**Rejected discovery targets:**")
        body.extend(f"- {t}" for t in strategy_result.rejected_targets)
    if strategy_result.insufficient_evidence:
        body.append("\n**Implementation evidence gap (reported by Strategy):**")
        body.extend(f"- {e}" for e in strategy_result.insufficient_evidence)
    if strategy_result.warnings:
        body.append("\n**Unverified items removed:**")
        body.extend(f"- {w}" for w in strategy_result.warnings)

    if not body:
        return ""

    return "\n".join([_STRATEGY_TARGET_BLOCK_HEADING, "", _STRATEGY_TARGET_BLOCK_DISCLAIMER] + body) + "\n"


# ---------------------------------------------------------------------------
# Final-Target Remediation Slice
#
# Built ONLY from generate_remediation_strategy()'s verified result -- never
# the earlier, exploratory Target Discovery candidates -- so source budget
# is never spent on candidates the Final Strategy later rejected. Reuses
# the existing InvestigationContext/RepositoryIndex and the existing
# _resolve_symbol_details/_read_symbol_source helpers; adds no new
# repository parse, no new index, no new LLM call, no AST framework.
#
# One proven gap in the existing capabilities (see module docstring history
# for the empirical urllib3 v2.0.5 check this was measured against):
# RepositoryIndex.search_usages() requires the target name to be followed by
# "(" -- a real constant/policy value referenced as a plain attribute
# (e.g. ``retries.remove_headers_on_redirect``, never called) is invisible
# to it. Everything below that needs to find such a reference uses its own
# plain, word-boundary substring scan over the SAME already-parsed
# ``code`` text RepositoryIndex.search_usages() itself reads -- not a new
# parser, just a less restrictive pattern over existing data.
# ---------------------------------------------------------------------------

FINAL_TARGET_SLICE_MAX_CHARS = 10_000
"""
A budget SEPARATE from evidence_fusion.DEFAULT_MAX_CHARS (never reused
implicitly). Measured, not guessed: against a real urllib3 v2.0.5 checkout,
the exact `Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT` definition alone is 70
characters; padded by _DEFINITION_CONTEXT_LINES on each side (see that
constant) it is 265 characters -- still small. A focused ~30-line consumer
window inside `PoolManager.urlopen` (clamped to its own 409-486 line range)
is 1,234 characters -- roughly 1,500 combined with the padded definition.
10,000 comfortably holds this shape for up to three final targets (a
padded exact definition + one focused consumer each, ~2,000 characters
apiece even generously) plus headings/provenance text (roughly 1,000
characters), while staying meaningfully bounded: it is deliberately NOT
sized to fit a single full 14,188-character `HTTPConnectionPool.urlopen`
or a full 18,374-character `retry.py` -- an oversized full function/file
must never be able to consume this whole budget by itself when a focused
window was available instead.
"""


def _effective_final_target_max(budget_controller: "ContextBudgetController | None") -> int:
    """The shared Final-Target Slice ceiling actually in force right now
    -- FINAL_TARGET_SLICE_MAX_CHARS unless `budget_controller` has
    already had a user-approved extension for the "final_target_slice"
    stage this run (see ContextBudgetController). `budget_controller=None`
    (every existing caller, and any library caller that never builds
    one) returns FINAL_TARGET_SLICE_MAX_CHARS unchanged -- reads it live
    at call time, never cached, so a test that monkeypatches the module
    constant keeps working identically whether or not a controller is
    given. This is the ONE mechanism Slices 2/3/4 (run_deterministic_
    acquisition/run_guided_acquisition/recover_post_patch_source) all
    reuse for the shared total -- never a separate, per-stage-sized
    ceiling for this particular budget."""
    if budget_controller is None:
        return FINAL_TARGET_SLICE_MAX_CHARS
    return budget_controller.effective_budget("final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS)


_USAGE_WINDOW_LINES = 15
"""Lines of context on each side of a discovered usage line, before
clamping to the enclosing function's own start/end line -- the middle of
the 12-20 line range a focused window should default to."""

_PER_TARGET_FULL_FUNCTION_CAP = FINAL_TARGET_SLICE_MAX_CHARS // 3
"""A directly-resolved function target with no discoverable strategy-term
anchor inside it (so no focused window is possible) renders whole only if
it fits this share of the budget -- sized so up to three such targets
could each still get a full rendering without any single one of them
dominating the whole slice. A genuinely oversized function (e.g.
HTTPConnectionPool.urlopen's 14,188 characters) will not fit and is
correctly left uncovered by exact means rather than crowding out every
other target."""

_SLICE_HEADING = "## Final-Target Remediation Slice"
_SLICE_DISCLAIMER = (
    "*Deterministic, bounded repository source built from the Final "
    "Evidence-Backed Remediation Strategy's own verified targets -- not "
    "the earlier, exploratory Target Discovery candidates. Exact "
    "definitions are repository text, verbatim. Consumer windows are "
    "deterministic discovered usage, not a claim of complete coverage.*"
)


def _remove_top_level_section(text: str, heading: str) -> str:
    """Remove one top-level ("## ") Markdown section from `text`,
    identified by an exact-line match on `heading` -- from that heading
    line up to (but not including) the next line that starts a
    DIFFERENT top-level section (a line starting with "## ", the same
    heading level every section in an assembled `code_context` uses), or
    the end of `text` if no further top-level heading follows. Sub-
    headings inside the removed section (###, ####, e.g. this module's
    own "#### Target definition:") are removed as part of the block --
    never scanned for individually.

    A pure text operation: no repository access, no re-resolution, no
    change to what was already resolved/approved -- only to which
    already-rendered copy of a section survives in `text`. No-op
    (returns `text` unchanged) if `heading` doesn't appear as an exact
    line anywhere.
    """
    lines = text.splitlines(keepends=True)
    start = None
    for i, line in enumerate(lines):
        if line.rstrip("\r\n") == heading:
            start = i
            break
    if start is None:
        return text
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].rstrip("\r\n").startswith("## "):
            end = j
            break
    return ("".join(lines[:start]) + "".join(lines[end:])).rstrip("\n")


def remove_final_target_slice_section(text: str) -> str:
    """Remove a previously-rendered "## Final-Target Remediation Slice"
    section (this module's own _SLICE_HEADING) from already-assembled
    context text.

    Used by Post-Patch Recovery (pipeline.py's Slice-4) so a stale copy
    of the slice -- built against the pre-recovery Final Strategy
    targets, before Patch Target Conformance triggered recovery -- is
    dropped before the freshly recovered slice is appended, rather than
    carried alongside it. Scoped narrowly to this one, already-known
    heading; never touches any other section, and never changes what a
    slice resolved, covered, or approved -- see _remove_top_level_section.
    """
    return _remove_top_level_section(text, _SLICE_HEADING)


# Conservative, deterministic, order-preserving identifier shapes. No
# stopword list is needed: an ordinary English word in prose has no dot,
# no underscore, and no internal capitalization hump, so it is never
# extracted by construction.
_DOTTED_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\b")
_SNAKE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")
_CAMEL_RE = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-zA-Z0-9]*)+\b")


def _extract_identifiers_from_text(text: "str | None") -> "list[str]":
    """Dotted identifiers first (widest/most specific), then snake_case /
    SCREAMING_SNAKE_CASE, then CamelCase (>=2 humps -- a single-hump
    capitalized word, e.g. a sentence-initial "Extend" or a bare class
    name, is deliberately excluded as too generic on its own; a bare
    class name of interest reaches this extraction some other way, e.g.
    as a verified target symbol's own class qualifier). Order-preserving,
    first-occurrence-deduplicated.

    A shorter token that is only a substring of an already-captured longer
    token is skipped as redundant ONLY when that longer token is itself
    plain (undotted) -- e.g. a genuinely-contained shorter SCREAMING_SNAKE_CASE
    or CamelCase token inside a longer one of the same flat shape adds no
    new search target. It is NEVER skipped merely for being contained in an
    already-captured DOTTED token: `object.attribute` (a qualified reference,
    typically occurring at a consumer/read site) and the bare `attribute`
    (typically occurring at its own definition/assignment/normalization/
    constructor site: `self.attribute = ...`, a bare parameter name, etc.)
    routinely name two DIFFERENT repository locations for the same
    underlying attribute -- demonstrated directly by a real evidence-
    acquisition gap where a constructor's own normalization of an attribute
    was never searched for because the only extracted term was a caller-
    qualified reference to that same attribute, which never occurs inside
    the constructor's own source. Both forms are therefore always kept as
    independent search targets when independently extractable.
    """
    if not text:
        return []
    found: "list[str]" = []
    seen: set = set()
    for m in _DOTTED_RE.finditer(text):
        tok = m.group(0)
        if tok not in seen:
            seen.add(tok)
            found.append(tok)
    for regex in (_SNAKE_RE, _CAMEL_RE):
        for m in regex.finditer(text):
            tok = m.group(0)
            if tok in seen:
                continue
            if any(tok != longer and "." not in longer and tok in longer for longer in found):
                continue
            seen.add(tok)
            found.append(tok)
    return found


def _extract_strategy_identifiers(strategy: RemediationStrategyResult) -> "list[str]":
    """Repository-looking identifiers from the Final Strategy's own text,
    order-preserving and first-occurrence-deduplicated: every verified
    target symbol first (already known-good -- no shape filtering, plus
    its dotted components), then shape-filtered tokens from
    `extended_mechanism`, then from each `required_edits` entry in order.
    No LLM, no free-form NLP."""
    ordered: "list[str]" = []
    seen: set = set()

    def _add(tok: "str | None") -> None:
        if tok and tok not in seen:
            seen.add(tok)
            ordered.append(tok)

    for raw_symbol in strategy.target_symbols:
        _file_hint, name = _split_symbol_entry(raw_symbol)
        _add(name)
        if "." in name:
            _add(name.rsplit(".", 1)[-1])
            _add(name.rsplit(".", 1)[0])

    for tok in _extract_identifiers_from_text(strategy.extended_mechanism):
        _add(tok)
    for edit in strategy.required_edits:
        for tok in _extract_identifiers_from_text(edit):
            _add(tok)

    return ordered


def _mechanism_derived_terms(strategy: RemediationStrategyResult) -> "set[str]":
    """The subset of `_extract_strategy_identifiers(strategy)`'s own output
    that is independently derivable from `extended_mechanism`/
    `required_edits` alone -- recomputed via the same pure, already-existing
    `_extract_identifiers_from_text`, ignoring `target_symbols` entirely.
    Provenance-based, never shape-based: a term's SOURCE decides this, not
    whether it happens to be dotted, snake_case, or CamelCase -- a bare,
    mechanism-derived CamelCase identifier (e.g. a Go-style exported
    function name mentioned in the mechanism text) belongs here exactly
    like a mechanism-derived snake_case one; a target-symbol-only bare
    CamelCase class name does not, purely because of where it came from.

    Read-only relative to `_extract_strategy_identifiers`: this never
    changes that function's own output, `RemediationStrategyResult`'s
    schema, or category 2's iteration -- it exists solely so category 3a's
    own usage scan (the only caller) can locally reorder its iteration."""
    terms: "set[str]" = set(_extract_identifiers_from_text(strategy.extended_mechanism))
    for edit in strategy.required_edits:
        terms.update(_extract_identifiers_from_text(edit))
    return terms


def _mechanism_terms_first(strategy_terms: "list[str]", strategy: RemediationStrategyResult) -> "list[str]":
    """Stable partition of an already-extracted, already-deduplicated
    `strategy_terms` list: every term independently derivable from the
    mechanism text first (original relative order preserved), then every
    remaining term whose only origin is a coarse, unconditionally-added
    verified target symbol (original relative order preserved).

    A term that happens to be BOTH a verified target symbol AND
    independently derivable from the mechanism text is classified by the
    latter -- `_extract_strategy_identifiers`'s own cross-source dedup
    already guarantees it appears in `strategy_terms` exactly once; this
    only decides which group that one occurrence lands in, never
    duplicates it.

    For category 3a's own usage-discovery loop only -- never used to
    reorder `strategy_terms` itself, category 2's iteration, or anything
    else that reads `strategy_terms` directly."""
    mechanism = _mechanism_derived_terms(strategy)
    specific = [t for t in strategy_terms if t in mechanism]
    coarse = [t for t in strategy_terms if t not in mechanism]
    return specific + coarse


def _merge_line_windows(windows: "list[tuple[int, int]]") -> "list[tuple[int, int]]":
    """Sort by start line, merge overlapping or adjacent (gap <= 1 line)
    ranges. Never drops a range, never reorders unrelated ranges, never
    produces an inverted (start > end) range."""
    if not windows:
        return []
    ordered = sorted(windows)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _find_identifier_line_offsets(code: str, identifier: str) -> "list[int]":
    """Plain, word-boundary substring scan over one function's own
    already-parsed `code` -- deliberately WITHOUT
    RepositoryIndex.search_usages()'s trailing "(" requirement (see module
    comment above for the empirical proof this misses real attribute-style
    usages). Reads only already-parsed data; never a new parse."""
    if not identifier:
        return []
    pattern = re.compile(r"\b" + re.escape(identifier) + r"\b")
    return [i for i, line in enumerate(code.split("\n")) if pattern.search(line)]


class _IdentifierMatch(NamedTuple):
    kind: str  # "constant" | "function"
    file: str
    label: str
    line: int
    end_line: "int | None"
    func_id: "str | None"


def _target_identity_by_bare_name(symbol_matches: "dict[str, object]") -> "dict[str, set]":
    """Maps each ALREADY-RESOLVED Final Strategy target symbol's own bare
    (rightmost, class-unqualified) name to the set of (file, class-qualifier)
    identities it actually resolved to -- built purely from `symbol_matches`
    (category 1's own `_resolve_symbol_details` output, the SAME
    class-qualifier-checked resolution used to build categories 1/3b/4), no
    new resolution pass.

    Used only to stop `_lookup_identifier_definition` (category 2 -- a bare,
    class-unqualified lookup by design, see its own docstring) from letting
    a same-named declaration in an UNRELATED file/class satisfy a
    strategy-derived term that is itself just the bare suffix of one of
    these already-uniquely-identified targets (see
    _extract_strategy_identifiers, which always adds a qualified target
    symbol's own bare suffix as a plain term). Without this, a term like
    "get_data_path" -- added because the real target is
    "FileSystemProvider.get_data_path" -- could resolve, via category 2's
    otherwise class-blind search, to an unrelated same-named method on a
    different class in a different file (observed directly: a real pygeoapi
    run's Final-Target Slice rendered "Target definition:
    azure_.py:get_data_path" for a Strategy that had already verified and
    scoped to "filesystem.py:FileSystemProvider.get_data_path", with
    azure_.py's own AzureBlobStorageProvider.get_data_path explicitly
    REJECTED by that same Strategy) -- even though azure_.py is present in
    `preferred_files` on purpose, for OTHER strategy-derived identifiers'
    supporting-evidence lookups.

    A bare name absent from this map (never the bare suffix of any resolved
    qualified target symbol -- e.g. a mechanism identifier like
    "os.path.realpath", or a target symbol that was itself proposed bare)
    is entirely unaffected -- category 2's pre-existing, class-blind
    behavior is preserved exactly for it."""
    identity: "dict[str, set]" = {}
    for match in symbol_matches.values():
        bare = match.label.rsplit(".", 1)[-1]
        identity.setdefault(bare, set()).add((match.file, _class_of_label(match.label)))
    return identity


def _lookup_identifier_definition(
    identifier: str, preferred_files: "list[str]", context,
    target_identity: "dict[str, set] | None" = None,
) -> "_IdentifierMatch | None":
    """Constants first (RepositoryIndex has no concept of a constant at
    all -- only InvestigationContext.constants does), then function/method
    definitions via the existing, real search_definitions() -- restricted
    to `preferred_files` only. Never a whole-repository scan for a
    strategy-derived term: an identifier that verifies nowhere within the
    Final Strategy's own target files or the files already connected via
    Planner evidence is not looked up further, by design (a repository can
    legitimately have more than one function/class sharing a name -- see
    _resolve_symbol_details' own class-qualifier check; this lookup accepts
    the SAME residual ambiguity `search_definitions()` itself has for a
    bare, class-unqualified strategy term, bounded by staying inside
    preferred_files rather than the whole repository) -- UNLESS
    `target_identity` (see _target_identity_by_bare_name) proves this exact
    bare identifier IS one of the Final Strategy's own already-resolved
    qualified target symbols: then a function candidate must match one of
    that identifier's own known (file, class) identities, never merely be
    IN preferred_files -- this is what stops a same-named method on a
    different, unrelated (possibly explicitly rejected) class/file from
    satisfying what is actually a specific target's own identity.
    `target_identity=None` (the default, and the one existing caller scoped
    to a single already-verified file) preserves this exact prior
    behavior."""
    constants = getattr(context, "constants", None) or {}
    for f in preferred_files:
        for qualified_name, record in constants.get(f, {}).items():
            if qualified_name == identifier or record.get("name") == identifier:
                line = record.get("line")
                if line is not None:
                    return _IdentifierMatch(
                        kind="constant", file=f, label=qualified_name,
                        line=line, end_line=record.get("end_line"), func_id=None,
                    )

    allowed_identities = (target_identity or {}).get(identifier)

    index = getattr(context, "index", None)
    if index is not None:
        for match in index.search_definitions(identifier):
            func_id = match.get("id", "")
            candidate_file = _file_part(func_id)
            if candidate_file not in preferred_files:
                continue
            if allowed_identities is not None and (candidate_file, match.get("className")) not in allowed_identities:
                continue  # a different target's own identity -- never a bare-name substitute
            line = match.get("startLine")
            if line is not None:
                return _IdentifierMatch(
                    kind="function", file=candidate_file, label=match.get("name") or identifier,
                    line=line, end_line=match.get("endLine"), func_id=func_id,
                )
    return None


# ---------------------------------------------------------------------------
# Method-call one-hop, repository-wide fallback (scopefix-v1 forensic
# finding): _lookup_identifier_definition's own preferred_files bound is
# intentional and correct for every OTHER caller (Strategy-term lookups,
# usage-scan seeding, target-identity-bound lookups) -- a strategy-derived
# term genuinely has no business resolving outside the files Strategy/
# Planner already connected. But the method-call one-hop path in
# _build_final_target_slice_inner is different in kind: it is not resolving
# an LLM-proposed term, it is resolving a call target the ALREADY-VERIFIED,
# ALREADY-SELECTED consumer source structurally, deterministically
# references (see _extract_source_dot_call_refs) -- e.g. PoolManager.
# urlopen's own verified source literally contains `conn.is_same_host(...)`.
# Whether that predicate's OWN definition is available to Challenger/
# Calibration should not depend on whether an earlier, low-evidence Planner
# stage happened to already guess its file into preferred_files -- see the
# forensic comparison between scopefix-v1 Run 1 (connectionpool.py never in
# Planner's own target_files -> is_same_host unresolved) and Run 3
# (connectionpool.py incidentally already there -> resolved cleanly).
#
# This function is a NARROW, single-purpose wrapper, never a parameter on
# _lookup_identifier_definition itself, precisely so no existing call site's
# behavior can silently widen: only the method-call one-hop loop below calls
# this; every other caller keeps calling _lookup_identifier_definition
# directly, unchanged.
# ---------------------------------------------------------------------------

def _lookup_identifier_definition_or_unique_repo_match(
    identifier: str, preferred_files: "list[str]", context,
) -> "_IdentifierMatch | None":
    """Tries the normal, unchanged `_lookup_identifier_definition` first --
    identical result whenever that already resolves (including its own
    constants-first, target_identity, and preferred_files behavior). Only
    when that returns None does this perform exactly one additional,
    repository-WIDE `index.search_definitions(identifier)` lookup, and
    accepts its result ONLY when it names EXACTLY ONE distinct function/
    method repository-wide.

    Uniqueness is safe to establish this way: `RepositoryIndex.search_
    definitions` -> `search_by_name(exact=True)` returns one entry per
    `self.by_name[name]` id, and `by_name` is built by iterating `self.
    functions` (itself keyed one-to-one by the analyzer's own unique
    `func_id` per physical declaration -- see RepositoryIndex._build_index)
    -- so `len(matches) == 1` genuinely means "exactly one concrete
    repository definition", never an aggregation artifact of the same
    declaration counted twice. Two or more matches, zero matches, or no
    index at all all return None -- fails closed, never guesses, exactly
    like `_lookup_identifier_definition`'s own failure mode.

    Deliberately function-only (never checks `context.constants`): a
    dot-qualified call site (`receiver.name(...)`, the only shape
    `_extract_source_dot_call_refs` ever produces) can never be a constant
    reference, so re-running the constants-first check here would be dead
    code, not an additional safety property.

    Exactly one hop, non-recursive, by construction: this function's own
    return value is never fed back into this function, into
    `_extract_source_dot_call_refs`, or into any other one-hop input --
    the caller renders and commits its source directly. Never mutates
    `preferred_files` -- the resolved definition's file is used only to
    read and render its own source for THIS candidate; it is never added to
    the shared `preferred_files` list, so it confers no broader search
    opportunity to any other lookup in this same run."""
    direct = _lookup_identifier_definition(identifier, preferred_files, context)
    if direct is not None:
        return direct

    index = getattr(context, "index", None)
    if index is None:
        return None
    matches = index.search_definitions(identifier)
    if len(matches) != 1:
        return None  # zero or ambiguous repository-wide -- fail closed
    match = matches[0]
    func_id = match.get("id", "")
    candidate_file = _file_part(func_id)
    line = match.get("startLine")
    if not candidate_file or line is None:
        return None
    return _IdentifierMatch(
        kind="function", file=candidate_file, label=match.get("name") or identifier,
        line=line, end_line=match.get("endLine"), func_id=func_id,
    )


def _lookup_identifier_usages(
    identifier: str, preferred_files: "list[str]", context
) -> "list[tuple[str, str, int, int, list[int]]]":
    """Every function within `preferred_files` whose own already-parsed
    code contains `identifier` as a plain, word-boundary substring (see
    _find_identifier_line_offsets). Returns
    (file, func_label, fn_start, fn_end, line_offsets) tuples, in
    preferred_files order, then list_functions_in_file's own stable order.
    Never a whole-repository scan."""
    index = getattr(context, "index", None)
    if index is None or not identifier:
        return []
    results = []
    for f in preferred_files:
        for entry in index.list_functions_in_file(f):
            func_id = entry.get("id")
            func = index.get_function(func_id) if func_id else None
            if not func:
                continue
            code = func.get("code", "") or ""
            offsets = _find_identifier_line_offsets(code, identifier)
            if not offsets:
                continue
            start, end = func.get("startLine"), func.get("endLine")
            if start is None or end is None:
                continue
            label = f"{func.get('className')}.{func.get('name')}" if func.get("className") else func.get("name")
            results.append((f, label, start, end, offsets))
    return results


# ---------------------------------------------------------------------------
# One-hop dependency expansion -- given source ALREADY selected for the
# slice (an exact target definition, or a focused consumer window),
# discover an exact repository-referenced CONSTANT it depends on and
# prepend its own exact definition. Deliberately bounded to exactly one
# hop: the functions below are never called again on their own output, so
# there is no recursion, no traversal, no generic data-flow analysis.
# ---------------------------------------------------------------------------

_SOURCE_CONSTANT_REF_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")


def _class_of_label(label: "str | None") -> "str | None":
    """The class-qualifier component of a "ClassName.member" label, or
    None for a bare (module-level) label -- same convention _resolve_
    symbol_details/_extract_strategy_identifiers already use."""
    if not label or "." not in label:
        return None
    return label.rsplit(".", 1)[0]


def _label_is_confirmed_class(label: str, context, func_id: "str | None" = None) -> bool:
    """True only when `label` is CONFIRMED, via already-parsed structural
    data, to be the name of a real class somewhere in this repository.
    Two independent, already-existing signals, either sufficient alone:

    1. `func_id`'s own already-parsed index record reports
       `unitType == "class"` -- the analyzer's OWN direct classification
       of the exact matched declaration (already computed by
       `RepositoryIndex.search_by_name`/`get_function`, no new parse, no
       new search). `func_id` is optional and only ever supplied by a
       caller that already resolved a match carrying one (see
       `_SymbolMatch.func_id`) -- an ordinary bare identifier proposal
       with no known func_id simply skips straight to signal 2. This
       signal is the reason an ORDINARY FUNCTION can never be
       misclassified: a real function's own index record reports
       `unitType` as "function"/"method"/"constructor"/etc. -- literally
       never "class" -- so this check is a direct read of the analyzer's
       existing, authoritative fact about what kind of declaration this
       is, not an inference from name, shape, or resolution path.

    2. InvestigationContext.constants' own already-parsed `class_name`
       field (the same field _constant_group_bounds/
       _disambiguate_constant_candidates already read -- no new parse, no
       new search): does at least one constant anywhere in the repository
       record this exact name as its enclosing class? This is the
       original, still-needed fallback for a match with no func_id at all
       (e.g. one resolved via _deterministic_identifier_fallback, which
       never assigns one) -- a real class with zero recorded class-level
       constants AND no func_id conservatively returns False (no false
       positive risk, only a missed opportunity) -- never worse than the
       pre-existing behavior.

    Never inferred merely from a bare identifier resolving at all, from
    `kind`, from capitalization, or from name/shape alone -- both signals
    above read an already-computed structural fact, never a guess."""
    index = getattr(context, "index", None)
    if index is not None and func_id:
        record = index.get_function(func_id)
        if record is not None and record.get("unitType") == "class":
            return True
    constants = getattr(context, "constants", None) or {}
    for records in constants.values():
        for record in records.values():
            if record.get("class_name") == label:
                return True
    return False


def _contains_any_strategy_identifier(text: str, terms: "list[str]") -> bool:
    """True if `text` contains at least one of `terms` verbatim, OR (for a
    dotted term like "Class.NAME") its own bare suffix after the last
    "." -- a class/module body's own definition site never repeats its
    own qualifier inline (e.g. `ALLOWED_VALUES = ...` inside `class
    Policy:` never literally contains the substring "Policy.ALLOWED_VALUES"),
    so checking only the dotted form would systematically miss the most
    common real case. Same class-qualifier/bare-suffix split
    _class_of_label and _extract_strategy_identifiers already use --
    not a new identifier-shape rule."""
    for term in terms:
        if term in text:
            return True
        if "." in term and term.rsplit(".", 1)[-1] in text:
            return True
    return False


def _extract_source_constant_refs(code: str) -> "list[str]":
    """Conservative, order-preserving, first-occurrence-deduplicated
    SCREAMING_SNAKE_CASE-shaped identifier extraction from already-
    selected Python SOURCE (not strategy-text prose -- see
    _extract_identifiers_from_text for that; this is a separate, narrower
    rule and does not reuse or modify it). Module/class-level constants in
    InvestigationContext.constants are conventionally ALL-CAPS (matching
    _extract_literal_constants' own real-world population), so
    restricting to that shape avoids speculatively looking up every
    lowercase attribute/parameter name in the constants table. Full-line
    comments are skipped outright -- a small, deterministic filter, not a
    parser; string-literal content is not otherwise excluded (an
    accepted, documented MVP limitation)."""
    if not code:
        return []
    found: "list[str]" = []
    seen: set = set()
    for line in code.split("\n"):
        if line.strip().startswith("#"):
            continue
        for m in _SOURCE_CONSTANT_REF_RE.finditer(line):
            tok = m.group(0)
            if tok not in seen:
                seen.add(tok)
                found.append(tok)
    return found


_SOURCE_DOT_CALL_REF_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)\(")


def _extract_source_dot_call_refs(code: str, connected_terms: "list[str]") -> "list[str]":
    """Sibling to `_extract_source_constant_refs`, for the one-hop
    METHOD-CALL expansion instead of the ALL-CAPS constant expansion:
    order-preserving, first-occurrence-deduplicated dot-qualified call
    names extracted from already-selected Python SOURCE, but ONLY from a
    line that already contains at least one of `connected_terms` (a term
    already tied to the Strategy -- see `_extract_strategy_identifiers`)
    verbatim. This is the exact structural relevance rule: SAME-LINE
    co-location with an already strategy-connected identifier, never
    "every call in the admitted function/block" -- a call on a different
    line of the same already-selected source gains no opportunity here,
    no matter how resolvable it might otherwise be. Not a parser: a
    single regex pass per line, same conservative-MVP shape as
    `_extract_source_constant_refs` (string-literal content not
    otherwise excluded)."""
    if not code or not connected_terms:
        return []
    found: "list[str]" = []
    seen: set = set()
    for line in code.split("\n"):
        if not any(term in line for term in connected_terms):
            continue
        for m in _SOURCE_DOT_CALL_REF_RE.finditer(line):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                found.append(name)
    return found


def _extract_fenced_code(rendered_block: "str | None") -> "str | None":
    """Recovers the raw source text from a block this module itself
    rendered via _render_definition_block/_render_usage_window_block --
    both use the exact same ```python fence convention, so this is
    deterministic (fully controlled here), not a general markdown
    parser."""
    if not rendered_block:
        return None
    start = rendered_block.find("```python\n")
    if start == -1:
        return None
    start += len("```python\n")
    end = rendered_block.rfind("```")
    if end == -1 or end <= start:
        return None
    return rendered_block[start:end]


# ---------------------------------------------------------------------------
# Class-level same-file assignment evidence -- given a verified target's
# deterministically established owning class (the SAME signal
# `target_class_identities` is built from, in _build_final_target_slice_inner
# below, just paired with the file that class was actually resolved in),
# discover an explicit module-scope `OwningClass.member = ...` rebind
# elsewhere in that SAME file, for ANY member of that class -- not only the
# specific member Strategy happened to verify. Closes a real, observed gap:
# a class attribute's own in-class declaration (e.g. `DEFAULT:
# ClassVar[Retry]`, a type annotation with no value) can be reconstructed at
# module scope hundreds of lines later in the same file (`Retry.DEFAULT =
# Retry(3)`), invisible to both the existing constants table
# (candidate_enrichment.py's _extract_literal_constants deliberately excludes
# any ast.Attribute target -- "not a single-name assignment at all") and the
# padded per-symbol definition window (too far away). This is a NEW, small,
# Auto-Patcher-owned addition -- it does not modify, wrap, or duplicate
# _extract_literal_constants; the two intentionally have disjoint LHS shapes
# (bare name vs. qualified attribute) and disjoint purposes (constant-value
# table vs. one-shot supporting evidence).
# ---------------------------------------------------------------------------

def _find_module_scope_class_attribute_assignments(
    file_text: str, class_name: str,
) -> "list[tuple[str, int, int]]":
    """Module-scope-only scan for an explicit assignment/rebinding whose LHS
    is EXACTLY `<class_name>.<member>` -- e.g. `Retry.DEFAULT = Retry(3)`.

    Returns a list of (member_name, line, end_line) tuples, in source
    (ascending line) order, one entry per qualifying statement -- never
    deduplicated by member name: multiple exact writes to the SAME member
    are each independently, structurally real and are all returned (the one
    caller renders each as its own supporting-evidence block; see its own
    docstring for why admitting all of them, rather than picking one, is the
    correct behavior here).

    Scope is deliberately narrow, and every exclusion below is a structural
    fact about the AST node, never a guess or an inference:
      - MODULE LEVEL ONLY: only direct children of the parsed Module node
        are inspected (`ast.iter_child_nodes(tree)`) -- mirrors
        candidate_enrichment.py's own `_extract_literal_constants` module-
        scope restriction exactly. A same-shaped assignment nested inside
        any function/method/if/try/class body is invisible here, not
        filtered out after the fact -- it is never visited at all.
      - EXACT CLASS MATCH: the LHS must be an `ast.Attribute` whose own
        `.value` is a bare `ast.Name` with `.id == class_name` (the class's
        own name, as literally written in this file's own `class`
        statement -- never resolved through an import alias). `Other.
        DEFAULT` (a different class), a bare `DEFAULT = ...` (an
        `ast.Name` target -- the shape `_extract_literal_constants` already
        owns, never conflated with this one), a subscript/call/dynamic
        target (`setattr(...)`, a plain `ast.Call`, never an assignment
        target at all), and a multi-target or starred assignment all fail
        this one structural check and are never specially handled.
      - `ast.Assign` (any RHS shape, never required to be a literal) and
        `ast.AnnAssign` WITH a non-None value (an annotated rebind is still
        an explicit rebind) both qualify; `ast.AnnAssign` with `value is
        None` (a bare declaration, e.g. `DEFAULT: ClassVar[Retry]` with no
        `=`) is excluded -- that is the declaration this mechanism exists
        to supplement, not a rebind. `ast.AugAssign` (`+=`, `|=`, ...) is
        excluded -- it presupposes an existing value being mutated, a
        different and more complex runtime claim than a plain rebind.

    Returns [] (never raises) when `file_text` does not parse as Python --
    the same fail-closed posture `_extract_literal_constants` already uses.
    """
    try:
        tree = ast.parse(file_text)
    except (SyntaxError, ValueError):
        return []

    found: "list[tuple[str, int, int]]" = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:
                continue  # declaration only, no rebind to admit
            targets = [node.target]
        else:
            continue
        if len(targets) != 1:
            continue  # multi-target assignment -- out of scope, not a guess
        target = targets[0]
        if not (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == class_name
        ):
            continue
        end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
        found.append((target.attr, node.lineno, end_line))
    return found


def _find_constant_candidates_by_name(
    bare_name: str, preferred_files: "list[str]", context
) -> "list[tuple[str, str, dict]]":
    """Every InvestigationContext.constants record, across
    `preferred_files` ONLY, whose own `name` field exactly equals
    `bare_name` -- a bare-NAME match, never a qualified_name match (that
    is _lookup_identifier_definition's job, for a different caller), and
    never outside preferred_files. Returns (file, qualified_name, record)
    tuples."""
    constants = getattr(context, "constants", None) or {}
    found: "list[tuple[str, str, dict]]" = []
    for f in preferred_files:
        for qualified_name, record in constants.get(f, {}).items():
            if record.get("name") == bare_name:
                found.append((f, qualified_name, record))
    return found


def _disambiguate_constant_candidates(
    candidates: "list[tuple[str, str, dict]]",
    source_file: str,
    source_class: "str | None",
    symbol_matches: dict,
    strategy_target_files: "list[str]",
) -> "tuple[tuple[str, str, dict] | None, str | None]":
    """Returns (chosen_candidate_or_None, omission_reason_or_None). Never
    guesses: a tie at any priority tier is a skip, not a choice.

    Priority (tried only when more than one candidate exists):
    1. a candidate that is already one of the Final Strategy's own
       verified (constant) target symbols;
    2. same file AND same class as the block containing the reference;
    3. same file as a Final Strategy target file;
    4. same file as the block containing the reference;
    (a single overall candidate is used directly, without needing any of
    the above -- the trivial "unique match" case.)
    """
    if not candidates:
        return None, "no constant record with that name in the preferred files"
    if len(candidates) == 1:
        return candidates[0], None

    def _is_verified_target(c):
        f, _qn, record = c
        line, end_line = record.get("line"), record.get("end_line")
        return any(
            m.kind == "constant" and m.file == f and m.line == line and m.end_line == end_line
            for m in symbol_matches.values()
        )

    def _same_file_and_class(c):
        f, qn, _record = c
        return source_class is not None and f == source_file and _class_of_label(qn) == source_class

    def _same_target_file(c):
        f, _qn, _record = c
        return f in strategy_target_files

    def _same_source_file(c):
        f, _qn, _record = c
        return f == source_file

    for tier_filter in (_is_verified_target, _same_file_and_class, _same_target_file, _same_source_file):
        narrowed = [c for c in candidates if tier_filter(c)]
        if len(narrowed) == 1:
            return narrowed[0], None

    name = candidates[0][2].get("name")
    return None, f"ambiguous: {len(candidates)} equal-priority constant candidates named {name!r}"


_CATEGORY2_HEADING_LABEL = "Related definition (context only, not an approved edit target)"
"""The heading label Category 2 (SUPPORTING-context, strategy-prose-
identifier lookup) renders under when its own resolved span does NOT
coincide with an already-verified Final Strategy target's own span -- see
_build_final_target_slice_inner's Category 2 block and
_render_definition_block's own docstring for why this must differ from
the default "Target definition" every genuine edit-target category uses.

Rendering under a different heading is presentation-only: a Category 2
block can still be exactly what makes a FILE-LEVEL intended edit "ready"
(via FinalTargetSliceResult.identifier_definition_covered -- see
check_edit_readiness), so check_patch_target_conformance must keep
recognizing it as edit-target-role source for that file, unchanged --
see _EDIT_TARGET_HEADING_PREFIXES, which _edit_target_source_for_file /
_edit_target_line_ranges_for_file match against instead of the single
literal "#### Target definition:" string, so this heading and that
parsing can never drift out of sync with each other again."""

_EDIT_TARGET_HEADING_PREFIXES = (
    "#### Target definition:",
    f"#### {_CATEGORY2_HEADING_LABEL}:",
)
"""Every heading _render_definition_block can produce for EDIT-TARGET-role
content (categories 1, 3b, 4, one-hop, Post-Patch Recovery's own
_wrap_post_patch_window -- default heading_label -- AND Category 2 --
_CATEGORY2_HEADING_LABEL) -- the complete set _edit_target_source_for_file
/ _edit_target_line_ranges_for_file must recognize so a rendering-only
heading change here can never silently change what check_patch_target_
conformance treats as approved source."""


def _render_definition_block(
    path: str, label: str, start: int, end: int, source: str,
    heading_label: str = "Target definition",
) -> str:
    """Render one resolved-symbol source block under a "#### {heading_label}:"
    heading. Defaults to "Target definition" -- byte-identical to every
    call site that existed before this parameter did (categories 1 and 4,
    the one-hop expansion step, and Post-Patch Recovery's own
    _wrap_post_patch_window -- all genuine EDIT-TARGET-role content that
    check_patch_target_conformance's _edit_target_source_for_file /
    _edit_target_line_ranges_for_file must keep recognizing). Category 2
    (_build_final_target_slice_inner's own SUPPORTING-context lookup from
    strategy-prose identifiers -- never a verified Final Strategy target)
    is the one caller that passes a different heading_label, so its
    blocks are never visually indistinguishable from an approved edit
    target in the rendered slice."""
    return (
        f"#### {heading_label}: `{path}:{label}` (lines {start}–{end})\n\n"
        f"```python\n{source.rstrip()}\n```\n"
    )


def _render_full_file_block(path: str, source: str) -> str:
    n_lines = len(source.splitlines())
    return (
        f"#### Full file (last resort): `{path}` ({n_lines} lines)\n\n"
        f"```python\n{source.rstrip()}\n```\n"
    )


def _render_usage_window_block(path: str, label: str, ranges: "list[tuple[int, int]]", context) -> "str | None":
    """Renders one or more (possibly non-contiguous) merged windows for a
    single consumer function -- reads each window's exact text via the
    existing read_file_section, never hand-reconstructed source. Two
    non-contiguous windows from the same function are separated by an
    explicit omitted-region marker rather than concatenated silently.

    `ranges=[]` (every offset's window fell outside its own enclosing
    unit's declared span -- see _windows_for's own inverted-range guard)
    renders nothing, same as "no usage found here", rather than indexing
    into an empty list."""
    if not ranges:
        return None
    index = getattr(context, "index", None)
    if index is None:
        return None
    pieces: "list[str]" = []
    prev_end = None
    for start, end in ranges:
        if prev_end is not None:
            gap = start - prev_end - 1
            pieces.append(f"# ... ({gap} line(s) omitted) ...")
        text = index.read_file_section(path, start, end)
        if text is None:
            return None
        pieces.append(text.rstrip("\n"))
        prev_end = end
    body = "\n".join(pieces)
    lo, hi = ranges[0][0], ranges[-1][1]
    return (
        f"#### Discovered consumer: `{path}:{label}` (lines {lo}–{hi}, "
        f"deterministic discovered usage)\n\n"
        f"```python\n{body}\n```\n"
    )


class FinalTargetSliceResult(NamedTuple):
    """`covered_target_files`/`covered_target_symbols` are the exact
    subset of the Final Strategy's own verified targets this slice
    actually produced usable source for -- see build_final_target_slice's
    docstring for the precise per-category coverage rule. `warning_text`
    is a separately-rendered '## Final-target source coverage warning'
    section, non-empty only when coverage is incomplete but not zero (the
    caller decides whether zero coverage should skip Patch Generation
    entirely; this result never makes that decision itself).

    The three fields below exist for check_edit_readiness (Slice 1, Edit
    Readiness Gate) -- additive; no test constructs this NamedTuple
    directly (only build_final_target_slice()'s own two construction
    sites do, both updated alongside these fields), so no defaults are
    needed and every field stays required, matching this module's other
    NamedTuples:
      resolved_target_symbols   : subset of strategy.target_symbols that
                                   resolved to a real repository location
                                   via _resolve_symbol_details, REGARDLESS
                                   of whether it made it into the budget
                                   (i.e. symbol_matches.keys()). Lets the
                                   Gate tell "never resolved" apart from
                                   "resolved but not rendered".
      full_file_fallback_covered: target FILES covered specifically by
                                   the category-5 full-file fallback AND
                                   containing a strategy-derived
                                   identifier -- the only way a file-level
                                   (no target_symbol) intended edit can be
                                   ready; an unrelated block from the same
                                   file is never enough.
      edit_target_budget_exhausted: True when the combined attempted size
                                   of every edit-target candidate (before
                                   any supporting-context block was even
                                   considered) already exceeds
                                   FINAL_TARGET_SLICE_MAX_CHARS.

    Two more fields exist for the bare-symbol fix and Slice 2 (Deterministic
    Pre-Patch Retrieval) -- both additive, both built entirely from data
    this function already computes, no new resolution pass either:
      resolved_symbol_files     : {raw target_symbol -> the real
                                   repository file it resolved to}, for
                                   every symbol in `symbol_matches`
                                   regardless of whether it made it into
                                   the budget. Lets build_intended_edits
                                   learn a bare (file-hint-less) symbol's
                                   real file without re-resolving it, so a
                                   bare symbol and its own file never
                                   produce two separate IntendedEdits for
                                   one logical target.
      identifier_definition_covered: target FILES covered specifically by
                                   an exact category-2 definition of a
                                   strategy-derived identifier (not a mere
                                   usage window, and not full_file_
                                   fallback_covered's whole-file render) --
                                   a second, more precise way a file-level
                                   (no target_symbol) intended edit can be
                                   ready (see check_edit_readiness)."""

    rendered: str
    covered_target_files: "list[str]"
    covered_target_symbols: "list[str]"
    uncovered_target_files: "list[str]"
    uncovered_target_symbols: "list[str]"
    coverage_complete: bool
    has_any_coverage: bool
    warning_text: str
    resolved_target_symbols: "list[str]"
    full_file_fallback_covered: "list[str]"
    edit_target_budget_exhausted: bool
    resolved_symbol_files: "dict[str, str]"
    identifier_definition_covered: "list[str]"


_EMPTY_SLICE_RESULT = FinalTargetSliceResult(
    rendered="", covered_target_files=[], covered_target_symbols=[],
    uncovered_target_files=[], uncovered_target_symbols=[],
    coverage_complete=True, has_any_coverage=False, warning_text="",
    resolved_target_symbols=[], full_file_fallback_covered=[],
    edit_target_budget_exhausted=False,
    resolved_symbol_files={}, identifier_definition_covered=[],
)


def build_final_target_slice(
    strategy: RemediationStrategyResult,
    repo_root,
    context,
    planner_evidence_files: "list[str] | tuple" = (),
    max_chars: "int | None" = None,
    planner_excerpt_blocks: "list[str] | tuple" = (),
) -> FinalTargetSliceResult:
    """
    Build the '## Final-Target Remediation Slice' from
    generate_remediation_strategy()'s VERIFIED result only -- never the
    earlier, exploratory Target Discovery candidates. Reuses the existing
    InvestigationContext/RepositoryIndex and the existing
    _resolve_symbol_details/_read_symbol_source helpers; no new repository
    parse, no new index, no new LLM call, no AST framework.

    Rendering order (never re-scored, never LLM-ranked): (1) exact
    definitions resolved directly from the Final Strategy's own verified
    target symbols; (2) definitions discovered from strategy-derived
    identifiers (constants/functions inside a class-only/file-only
    target's own file, or any other preferred file); (3) focused
    usage/consumer windows; (4) compact full target-symbol functions with
    no discoverable focus point; (5) full-file fallback, last resort only.
    Each category is added to a single running budget
    (FINAL_TARGET_SLICE_MAX_CHARS) strictly in that order, whole-block-or-
    omitted -- so an earlier category's block can never be displaced by a
    later one.

    `planner_excerpt_blocks` (default `()`, backward compatible): the
    already-rendered Markdown blocks from a prior
    `PlannerEvidenceResult.excerpt_plan.blocks` (see pipeline.py's own
    caller). Used ONLY as additional scan input for the method-call
    one-hop expansion below -- never re-parsed into new preferred_files,
    never re-fetched, never a second Planner-evidence acquisition.

    "Exact definition" (categories 1, 2, and the one-hop dependency
    expansion) means patch-ready repository source, not merely a
    reasoning-ready one: every such block is padded by
    _DEFINITION_CONTEXT_LINES of real, repository-verbatim lines on each
    side of the resolved symbol's own span (via _padded_line_range) --
    without this, a short definition (e.g. a one-line constant) would
    render with zero surrounding context, leaving Patch Generation nothing
    real to anchor a unified diff hunk's leading/trailing context to, and
    it would invent neighboring lines from memory instead (observed
    directly: a real urllib3 run's generated hunk against
    `DEFAULT_REMOVE_HEADERS_ON_REDIRECT` failed content-based relocation
    with relocation_reason="no_match" -- the invented context never
    existed in the file). The padding is purely arithmetic on top of the
    existing read_file_section accessor -- no new repository reader, and
    it never applies to a whole-function-body or whole-file render (both
    already self-contain ample context).

    Coverage: a target FILE is covered if the slice contains an exact
    definition, an exact target symbol, or a focused usage/consumer
    window from that file. A target SYMBOL is covered only by its own
    exact definition or its own full/windowed source (categories 1/3b/4) --
    never merely because some other identifier from the same file was
    included.

    Never raises: any internal failure returns a short, explicit failure
    note (see _EMPTY_SLICE_RESULT's caller, build_final_target_slice's
    except-branch below) -- never silently empty, never silently
    "coverage complete".

    `max_chars=None` (the default) reads the module-level
    FINAL_TARGET_SLICE_MAX_CHARS AT CALL TIME (not bound into the
    function signature), so every existing caller is unaffected AND a
    test that monkeypatches FINAL_TARGET_SLICE_MAX_CHARS still works
    exactly as before. Slice 2 (Deterministic Pre-Patch Retrieval, see
    run_deterministic_acquisition) is the only caller that passes an
    explicit smaller per-round budget, re-invoking this same function on
    a narrowly-scoped strategy naming only the targets still unready,
    rather than a second retrieval implementation.
    """
    if not strategy or not (strategy.target_files or strategy.target_symbols):
        return _EMPTY_SLICE_RESULT

    resolved_max_chars = FINAL_TARGET_SLICE_MAX_CHARS if max_chars is None else max_chars
    try:
        return _build_final_target_slice_inner(
            strategy, repo_root, context, planner_evidence_files, resolved_max_chars,
            planner_excerpt_blocks=planner_excerpt_blocks,
        )
    except Exception:
        return FinalTargetSliceResult(
            rendered=(
                f"{_SLICE_HEADING}\n\n*Slice construction failed for this run -- no additional "
                f"exact source could be deterministically extracted. Earlier context sections "
                f"are unaffected.*\n"
            ),
            covered_target_files=[], covered_target_symbols=[],
            uncovered_target_files=list(strategy.target_files),
            uncovered_target_symbols=list(strategy.target_symbols),
            coverage_complete=False, has_any_coverage=False,
            warning_text=(
                "Final-Target Remediation Slice construction failed; "
                "no verified source was added this run."
            ),
            resolved_target_symbols=[], full_file_fallback_covered=[],
            edit_target_budget_exhausted=False,
            resolved_symbol_files={}, identifier_definition_covered=[],
        )


def _render_coverage_warning(
    uncovered_files: "list[str]", uncovered_symbols: "list[str]",
    rendered_nonempty: bool, named_any_target: bool,
) -> str:
    """The '## Final-target source coverage warning' section -- extracted
    so both _build_final_target_slice_inner's own return and Slice 2's
    _merge_slice_results (which recomputes uncovered lists after
    acquisition) render it identically, never a second, divergent
    wording."""
    if rendered_nonempty and (uncovered_files or uncovered_symbols):
        parts = []
        if uncovered_files:
            parts.append("files: " + ", ".join(uncovered_files))
        if uncovered_symbols:
            parts.append("symbols: " + ", ".join(uncovered_symbols))
        return (
            "## Final-target source coverage warning\n\n"
            "*Deterministic verified source could not be produced for every "
            "Final Strategy target. Patch Generation is proceeding with "
            "partial coverage -- treat any edit to an uncovered target as "
            "unverified against real repository text.*\n\n"
            "Uncovered " + "; ".join(parts) + "\n"
        )
    if not rendered_nonempty and named_any_target:
        return (
            "## Final-target source coverage warning\n\n"
            "*No deterministic verified source could be produced for any "
            "Final Strategy target this run.*\n"
        )
    return ""


def _build_final_target_slice_inner(
    strategy: RemediationStrategyResult, repo_root, context, planner_evidence_files,
    max_chars: int = FINAL_TARGET_SLICE_MAX_CHARS,
    planner_excerpt_blocks: "list[str] | tuple" = (),
) -> FinalTargetSliceResult:
    root = Path(repo_root) if repo_root else None
    if root is None:
        return _EMPTY_SLICE_RESULT

    preferred_files: "list[str]" = []
    seen_pf: set = set()
    for f in list(strategy.target_files) + list(planner_evidence_files):
        if f not in seen_pf:
            seen_pf.add(f)
            preferred_files.append(f)

    strategy_terms = _extract_strategy_identifiers(strategy)

    budget = max_chars
    running = 0
    blocks_by_category: "dict[int, list[str]]" = {1: [], 2: [], 3: [], 4: [], 5: []}
    covered_files: set = set()
    covered_symbols: set = set()
    used_definition_keys: set = set()  # (file, line, end_line)
    used_usage_keys: set = set()       # (file, label, tuple(ranges))
    # Files covered specifically by an exact category-2 definition of a
    # strategy-derived identifier -- a second, more precise way a
    # file-level intended edit can satisfy check_edit_readiness (see
    # FinalTargetSliceResult.identifier_definition_covered), distinct from
    # full_file_fallback_covered's whole-file requirement.
    identifier_definition_covered: set = set()

    # Slice 1 -- Edit Readiness Gate bookkeeping (see check_edit_readiness
    # below). `edit_target_attempted_chars` sums every EDIT-TARGET-role
    # candidate's rendered size REGARDLESS of whether it actually fit the
    # shared budget -- purely additive bookkeeping, never consulted by any
    # commit decision above. This is what lets the Gate tell apart "the
    # edit targets themselves already exceed the whole slice budget"
    # (target_budget_exhausted) from "budget had room for edit targets but
    # this specific one still didn't make it in" (a read/resolution
    # failure -- missing_target_source). `full_file_fallback_covered`
    # records which target FILES were covered specifically by the
    # full-file fallback (category 5) and actually contain a
    # strategy-derived identifier -- the only case a file-level (no
    # target_symbol) intended edit can be "ready" (see
    # check_edit_readiness): an unrelated block from the same file must
    # never count.
    edit_target_attempted_chars = 0
    full_file_fallback_covered: set = set()

    def _try_add_to(block_list: list, text: str) -> bool:
        nonlocal running
        if running + len(text) > budget:
            return False
        block_list.append(text)
        running += len(text)
        return True

    # --- Category 1 (EDIT-TARGET role): exact verified target definitions
    # -- constants resolved directly from the Final Strategy's own
    # verified target symbols. Functions resolved here are deferred to
    # categories 3b/4 below. Committed to the budget FIRST, immediately --
    # nothing outranks this tier, and per the Edit Readiness Gate's "actual
    # edit targets first, supporting evidence second" rule, no
    # supporting-context block (one-hop / category 2 / category 3a /
    # category 5) is committed anywhere below until every edit-target
    # candidate in categories 1, 3b, and 4 has already had its turn.
    #
    # `verified_files=strategy.target_files` lets a target symbol the
    # structured lookup still can't resolve (already re-tried once in
    # _verify_strategy_targets, since a symbol string here may have been
    # proposed for a different strategy than the one that ran there --
    # e.g. Slice 2's narrowly-scoped re-invocation) fall back to the same
    # deterministic, file-scoped identifier recovery -- never a wider
    # search than the Final Strategy's own already-verified target_files.
    symbol_matches: "dict[str, object]" = {}
    for raw_symbol in strategy.target_symbols:
        match = _resolve_symbol_details(raw_symbol, root, context, verified_files=strategy.target_files)
        if match is None:
            continue
        symbol_matches[raw_symbol] = match
        if match.kind != "constant":
            continue
        key = (match.file, match.line, match.end_line)
        if key in used_definition_keys:
            covered_symbols.add(raw_symbol)
            covered_files.add(match.file)
            continue
        source = _read_symbol_source(match, context, pad_lines=_DEFINITION_CONTEXT_LINES)
        if source is None:
            continue
        render_start, _ = _padded_line_range(match.line, match.end_line, _DEFINITION_CONTEXT_LINES)
        render_end = _rendered_end_line(render_start, source)
        text = _render_definition_block(match.file, match.label, render_start, render_end, source)
        edit_target_attempted_chars += len(text)
        if _try_add_to(blocks_by_category[1], text):
            used_definition_keys.add(key)
            covered_symbols.add(raw_symbol)
            covered_files.add(match.file)

    # --- Invariant: every successfully resolved target symbol's own file
    # must be searchable by the usage/consumer scans below (categories 2 and
    # 3a). `preferred_files` was seeded above purely from the Final
    # Strategy's own `target_files` list -- a separate, independently
    # authored field from `target_symbols` (see generate_remediation_
    # strategy's two distinct `plan.get(...)` reads) with no guarantee it
    # names every verified symbol's actual file. Without this, a symbol can
    # resolve correctly here (Category 1 searches the whole repository via
    # _resolve_symbol_details, not preferred_files) while the function that
    # consumes/normalizes it -- sitting in that same file -- stays invisible
    # to every usage lookup below, which IS bounded to preferred_files by
    # design (see _lookup_identifier_usages/_lookup_identifier_definition
    # docstrings). This closes that gap deterministically, using only
    # already-resolved data -- no new lookup, no repository-wide search, no
    # new evidence category: it only widens the existing bounded scan's own
    # file set to include what Category 1 already proved is relevant.
    for match in symbol_matches.values():
        if match.file not in seen_pf:
            seen_pf.add(match.file)
            preferred_files.append(match.file)

    # --- Category 2 (SUPPORTING-context role): definitions discovered
    # from strategy identifiers, for class-only/file-only targets or any
    # other mechanism-related identifier the strategy named that isn't
    # already a verified target symbol. CANDIDATES ONLY here -- gathering
    # candidates doesn't touch the budget, so this can run in its
    # original position; the actual commit happens far below, after every
    # edit-target candidate (categories 1, 3b, 4) has already been tried.
    category2_candidates: "list[tuple[str, str]]" = []  # (rendered_text, file)
    target_identity = _target_identity_by_bare_name(symbol_matches)
    # A bare-name Category 2 lookup can resolve to the EXACT SAME (file,
    # line, end_line) span as an already-verified Final Strategy target
    # (e.g. a function target: Category 1 only resolves constants, so a
    # verified function symbol's own span is still unclaimed in
    # used_definition_keys when Category 2 runs, and Category 2 -- not
    # 3b/4 -- ends up being the block that actually satisfies it; see
    # Category 4's own "key in used_definition_keys" short-circuit below).
    # That span IS a verified edit target, just reached via this lookup
    # path -- it must keep the default "Target definition" heading, never
    # _CATEGORY2_HEADING_LABEL, which is reserved for a genuinely
    # unverified/merely-referenced identifier with no matching target span.
    _verified_target_spans = {(m.file, m.line, m.end_line) for m in symbol_matches.values()}
    for term in strategy_terms:
        found = _lookup_identifier_definition(term, preferred_files, context, target_identity=target_identity)
        if found is None:
            continue
        key = (found.file, found.line, found.end_line)
        if key in used_definition_keys:
            continue
        if found.kind == "constant":
            index = getattr(context, "index", None)
            read_start, read_end = _padded_line_range(found.line, found.end_line, _DEFINITION_CONTEXT_LINES)
            source = index.read_file_section(found.file, read_start, read_end) if index else None
            render_start = read_start
            render_end = _rendered_end_line(render_start, source) if source else found.end_line
        else:
            source = _read_symbol_source(
                _SymbolMatch(file=found.file, label=found.label, kind="function",
                             line=found.line, end_line=found.end_line, func_id=found.func_id),
                context,
            )
            render_start, render_end = found.line, found.end_line
        if source is None:
            continue
        used_definition_keys.add(key)  # decided now; committed later (key stays unpadded -- see _padded_line_range)
        _heading = "Target definition" if key in _verified_target_spans else _CATEGORY2_HEADING_LABEL
        text = _render_definition_block(
            found.file, found.label, render_start, render_end, source,
            heading_label=_heading,
        )
        category2_candidates.append((text, found.file))

    # --- Category 3 candidates (usage/consumer windows) -- CANDIDATES
    # ONLY here too. Committed in two separate passes further below: 3b
    # (a focused window into an ACTUAL verified target symbol's own body
    # -- edit-target role) ahead of every supporting block; 3a (a mere
    # consumer/usage scan, unrelated to any specific verified target --
    # supporting-context role) only with whatever budget remains.
    def _windows_for(fn_start: int, fn_end: int, offsets: "list[int]") -> "list[tuple[int, int]]":
        raw_ranges = []
        for off in offsets:
            start = max(fn_start, fn_start + off - _USAGE_WINDOW_LINES)
            end = min(fn_end, fn_start + off + _USAGE_WINDOW_LINES)
            if start > end:
                # An offset past the enclosing unit's own declared span --
                # observed directly from a real analyzer inconsistency (a
                # module-level `code` blob longer than its own startLine/
                # endLine span, e.g. "lines 51-40"). fn_end already caps
                # `end`, but nothing caps `start` against it, so a large
                # enough offset can push start past end on its own.
                # Skipping here means this fallback data shape never
                # emits an inverted range downstream, rather than
                # papering over it with a second, silent clamp.
                continue
            raw_ranges.append((start, end))
        return _merge_line_windows(raw_ranges)

    category3_candidates: "list[tuple[str, str, str, object]]" = []  # (rendered_text, file, label, raw_symbol_or_None)

    # 3a. Strategy-term usage scan, bounded to preferred_files -- covers
    # class-only/file-only targets' discovered consumers (SUPPORTING
    # role: raw_symbol stays None). Offsets from EVERY matching strategy
    # term are accumulated PER FUNCTION first (never rendered per-term) so
    # two different terms landing in the same function merge into one
    # window set and render once, in first-encountered function order --
    # where "first-encountered" is over _mechanism_terms_first's own
    # reordering of strategy_terms (mechanism-derived terms before
    # coarse, target-symbol-only ones; each group's own relative order
    # otherwise unchanged), not strategy_terms' own original order. This
    # is a LOCAL reordering for this scan only -- strategy_terms itself,
    # category 2 (above), and category 3b (below) are unaffected. Without
    # it, a single coarse, unconditionally-first target-symbol term with
    # several coincidental matches could consume this shared budget ahead
    # of a term that actually names the mechanism, discovered only later
    # in strategy_terms' own order.
    # Every term deterministically derived from an ALREADY-RESOLVED,
    # QUALIFIED target symbol's own identity (its resolved label's full
    # form and specific suffix, split the same way
    # _extract_strategy_identifiers splits a qualified target_symbol) --
    # used at commit time, below, to classify each discovered consumer
    # window as Band A (deterministically tied to a resolved target) or
    # Band B (found only via a general mechanism/context term), never by
    # file locality. A BARE, class-unqualified label (e.g. a class-only
    # target with no dot) deliberately contributes nothing here: it is
    # exactly the "coarse" case _mechanism_terms_first already exists to
    # deprioritize (see TestMechanismTermsPrioritizedOverTargetSymbol) --
    # a literal, coincidental text match on the bare class name alone
    # (e.g. inside an unrelated string literal) is not a stronger tie to
    # the target than a genuinely mechanism-derived term, and treating it
    # as one here would silently re-admit the exact starvation bug that
    # earlier fix was built to prevent. Which SPECIFIC term(s) actually
    # produced a given function's hit is recorded in `function_terms`
    # below and consulted once more at commit time, once the one-hop pass
    # further down has also had a chance to contribute (see
    # `one_hop_discovered_terms`) -- a target-connected constant that
    # one-hop discovers from the target's OWN already-selected source is
    # exactly as strong a tie as a qualified target symbol's own suffix,
    # so both must be able to earn Band A for the SAME consumer window,
    # regardless of which of the two happens to be known first. This is
    # also how a BARE target (no qualified-symbol terms at all) still
    # gets genuine Band A coverage: entirely through one-hop.
    target_derived_terms: "set[str]" = set()
    for match in symbol_matches.values():
        if "." in match.label:
            target_derived_terms.add(match.label)
            target_derived_terms.add(match.label.rsplit(".", 1)[-1])

    # Every class name a resolved target is CONFIRMED to itself BE (never
    # inferred from a bare fallback match alone -- see
    # _label_is_confirmed_class) -- lets an EXISTING category-3a candidate
    # earn Band A by target-owned-class membership: a term-relevant window
    # this scan already discovered that additionally belongs to the SAME
    # class as the resolved target is exactly as strong a tie as the
    # target's own qualified-symbol suffix above. This is deliberately not
    # a constructor concept -- ANY member of the target's own class
    # qualifies equally, __init__ included but never special-cased -- and
    # it never triggers a new search: only class-qualifiers already
    # attached to candidates this scan (or the one below) already found.
    target_class_identities: "set[str]" = set()
    for match in symbol_matches.values():
        if "." in match.label:
            target_class_identities.add(_class_of_label(match.label))
        elif _label_is_confirmed_class(match.label, context, func_id=match.func_id):
            # Deliberately NOT gated on match.kind == "constant": a bare
            # class-shaped target resolves via TWO independent paths in
            # _resolve_symbol_details -- RepositoryIndex.search_by_name
            # (the shape a real parsed repository actually produces for a
            # class, reported as kind="function" regardless of the
            # matched entry's own unitType) and, only when the index has
            # no such entry, _deterministic_identifier_fallback (always
            # kind="constant"). Gating on kind=="constant" here silently
            # excluded the first, far more common shape. _label_is_
            # confirmed_class's own independent check against parsed
            # constants' class_name field is what actually guards against
            # a false positive -- kind was never load-bearing for that.
            target_class_identities.add(match.label)

    # Evidence-continuity after a rejected QUALIFIED target-symbol
    # proposal: a member proposal like "Container.runtime_limit" can fail
    # normal target-symbol verification (correctly -- e.g. it may name an
    # instance attribute, not any real declaration) and vanish from
    # `target_symbols` entirely, taking every trace of the class it named
    # with it. `strategy.rejected_target_symbols` (additive, see
    # RemediationStrategyResult's own docstring) retains the raw rejected
    # strings for exactly this one purpose: extracting a candidate class
    # QUALIFIER and independently re-resolving it -- via the SAME
    # `_resolve_symbol_details` used for every other symbol in this
    # function, scoped to this Strategy's own already-verified
    # `target_files` (never a wider search) -- then confirming it via the
    # SAME `_label_is_confirmed_class` used just above. The rejected
    # string itself is never treated as evidence of anything: only an
    # independently, deterministically re-verified class identity can
    # ever be added here. This never re-adds the rejected member to
    # `symbol_matches`, `target_symbols`, or any edit-target category --
    # it can only ever widen `target_class_identities`, the SAME
    # supporting-evidence Band-A signal used above, nothing else.
    for raw in strategy.rejected_target_symbols:
        if "." not in raw:
            continue  # no class qualifier to extract from a bare proposal
        qualifier = raw.rsplit(".", 1)[0]
        if qualifier in target_class_identities:
            continue  # already independently confirmed above
        qualifier_match = _resolve_symbol_details(
            qualifier, root, context, verified_files=strategy.target_files,
        )
        if qualifier_match is None:
            continue  # qualifier itself does not independently resolve -- fail closed
        if "." in qualifier_match.label:
            target_class_identities.add(_class_of_label(qualifier_match.label))
        elif _label_is_confirmed_class(qualifier_match.label, context, func_id=qualifier_match.func_id):
            target_class_identities.add(qualifier_match.label)

    # --- Class-level same-file assignment evidence (SUPPORTING-context
    # role, Category 2 -- never an edit target): reuses the exact same
    # deterministic ownership signal `target_class_identities` above is
    # built from, but paired with the FILE each class was actually resolved
    # in (target_class_identities itself is a flat set of class names only
    # -- reusing it unpaired here would risk matching a same-named class in
    # a different file, which must never happen). For each such
    # (file, class) pair, scan ONLY that already-approved file (never a new
    # file, never preferred_files growth) for an explicit module-scope
    # `OwningClass.member = ...` rebind naming ANY member of that class --
    # not only whichever member Strategy happened to verify. Every match is
    # rendered as its own small, padded, Category-2-headed block and
    # committed through the EXISTING category2_candidates/_try_add_to
    # budget path below -- no new category, no new budget, no recursion
    # (the rendered text is appended only to category2_candidates, never
    # back into scan_sources/dot_call_scan_texts or any other one-hop
    # input).
    owning_class_files: "set[tuple[str, str]]" = set()
    for match in symbol_matches.values():
        if "." in match.label:
            owning_class_files.add((match.file, _class_of_label(match.label)))
        elif _label_is_confirmed_class(match.label, context, func_id=match.func_id):
            owning_class_files.add((match.file, match.label))

    index = getattr(context, "index", None)
    for (owner_file, owner_class) in sorted(owning_class_files):
        try:
            owner_file_text = (root / owner_file).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        assignments = _find_module_scope_class_attribute_assignments(owner_file_text, owner_class)
        for (member, line, end_line) in sorted(assignments, key=lambda item: item[1]):
            key = (owner_file, line, end_line)
            if key in used_definition_keys:
                continue
            if index is None:
                continue
            read_start, read_end = _padded_line_range(line, end_line, _DEFINITION_CONTEXT_LINES)
            source_text = index.read_file_section(owner_file, read_start, read_end)
            if source_text is None:
                continue
            render_end = _rendered_end_line(read_start, source_text)
            text = _render_definition_block(
                owner_file, f"{owner_class}.{member}", read_start, render_end, source_text,
                heading_label=_CATEGORY2_HEADING_LABEL,
            )
            used_definition_keys.add(key)
            category2_candidates.append((text, owner_file))

    per_function_hits: "dict[tuple[str, str], dict]" = {}
    function_order: "list[tuple[str, str]]" = []
    function_terms: "dict[tuple[str, str], set]" = {}
    for term in _mechanism_terms_first(strategy_terms, strategy):
        for (f, label, fn_start, fn_end, offsets) in _lookup_identifier_usages(term, preferred_files, context):
            fkey = (f, label)
            if fkey not in per_function_hits:
                per_function_hits[fkey] = {"fn_start": fn_start, "fn_end": fn_end, "offsets": set()}
                function_order.append(fkey)
                function_terms[fkey] = set()
            per_function_hits[fkey]["offsets"].update(offsets)
            function_terms[fkey].add(term)

    for (f, label) in function_order:
        hit = per_function_hits[(f, label)]
        ranges = _windows_for(hit["fn_start"], hit["fn_end"], sorted(hit["offsets"]))
        key = (f, label, tuple(ranges))
        if key in used_usage_keys:
            continue
        text = _render_usage_window_block(f, label, ranges, context)
        if text is None:
            continue
        used_usage_keys.add(key)
        category3_candidates.append((text, f, label, None))

    # 3b. Inside a directly-resolved FUNCTION target itself: a focused
    # window around any strategy term found in its own body, rather than
    # an immediate full-function render. EDIT-TARGET role: raw_symbol is
    # always one of strategy.target_symbols here -- this IS the target's
    # own source, just windowed rather than shown in full.
    for raw_symbol, match in symbol_matches.items():
        if match.kind != "function" or not match.func_id:
            continue
        index = getattr(context, "index", None)
        func = index.get_function(match.func_id) if index else None
        if not func:
            continue
        code = func.get("code", "") or ""
        offsets: "list[int]" = []
        for term in strategy_terms:
            offsets.extend(_find_identifier_line_offsets(code, term))
        if not offsets:
            continue
        ranges = _windows_for(match.line, match.end_line, sorted(set(offsets)))
        key = (match.file, match.label, tuple(ranges))
        if key in used_usage_keys:
            continue
        text = _render_usage_window_block(match.file, match.label, ranges, context)
        if text is None:
            continue
        used_usage_keys.add(key)
        category3_candidates.append((text, match.file, match.label, raw_symbol))

    # --- Commit category 3b's EDIT-TARGET candidates now (still ahead of
    # every supporting-context block below): these are windows into an
    # actual verified target symbol's own body, not a mere consumer, so
    # they must not be displaced by one-hop/category-2/category-3a/
    # category-5 content competing for the same budget.
    function_targets_with_window: set = set()
    for (text, f, _label, raw_symbol) in category3_candidates:
        if raw_symbol is None:
            continue  # 3a (supporting) -- committed later, below
        edit_target_attempted_chars += len(text)
        if _try_add_to(blocks_by_category[3], text):
            covered_files.add(f)
            covered_symbols.add(raw_symbol)
            function_targets_with_window.add(raw_symbol)

    # --- Category 4 (EDIT-TARGET role): compact full target symbols -- a
    # directly-resolved FUNCTION target with no strategy-term anchor
    # inside it (no focused window possible), rendered whole only if it
    # fits the per-target cap, and only if the same function wasn't
    # already rendered via its own 3b window above. Still ahead of every
    # supporting-context block -- this is the last edit-target tier.
    for raw_symbol, match in symbol_matches.items():
        if match.kind != "function" or raw_symbol in function_targets_with_window:
            continue
        key = (match.file, match.line, match.end_line)
        if key in used_definition_keys:
            covered_symbols.add(raw_symbol)
            covered_files.add(match.file)
            continue
        source = _read_symbol_source(match, context)
        if source is None or len(source) > _PER_TARGET_FULL_FUNCTION_CAP:
            continue  # too large for a "compact" full render -- left uncovered by exact means
        text = _render_definition_block(match.file, match.label, match.line, match.end_line, source)
        edit_target_attempted_chars += len(text)
        if _try_add_to(blocks_by_category[4], text):
            used_definition_keys.add(key)
            covered_symbols.add(raw_symbol)
            covered_files.add(match.file)

    # Every edit-target candidate (categories 1, 3b, 4) has now had its
    # turn, with the FULL slice budget available to it -- nothing
    # supporting-context has been committed yet. If their combined
    # attempted size alone already exceeds the budget, at least one edit
    # target could not possibly fit no matter what else is/isn't
    # rendered -- this is the one failure reason distinguishable as
    # "the budget itself is the problem", not a resolution/read failure.
    edit_target_budget_exhausted = edit_target_attempted_chars > budget

    # --- One-hop dependency expansion (SUPPORTING-context role, rendered
    # priority tier 2): scan ONLY the exact target definitions already
    # committed (category 1) and the focused consumer-window CANDIDATES
    # computed above (category 3, regardless of commit status) for exact
    # repository-referenced constants, and prepend their own exact
    # definitions ahead of every OTHER supporting block. Exactly one pass
    # -- newly added definitions below are never themselves scanned for
    # further references (no recursion). Committed here -- AFTER every
    # edit-target candidate above has already had first claim on the
    # budget, per the Edit Readiness Gate's ordering rule.
    one_hop_blocks: "list[str]" = []
    scan_sources: "list[tuple[str, str, str]]" = []  # (source_file, source_class, raw_code)

    for match in symbol_matches.values():
        if match.kind != "constant":
            continue
        if (match.file, match.line, match.end_line) not in used_definition_keys:
            continue  # category 1 did not actually include this one (budget)
        source = _read_symbol_source(match, context)
        if source is not None:
            scan_sources.append((match.file, _class_of_label(match.label), source))

    for (text, f, label, _raw_symbol) in category3_candidates:
        code = _extract_fenced_code(text)
        if code is not None:
            scan_sources.append((f, _class_of_label(label), code))

    seen_refs: set = set()
    one_hop_discovered_terms: "list[str]" = []  # bare names of every constant
    # this pass deterministically disambiguated -- see the usage-search
    # re-seed pass directly below, which is the ONLY consumer of this list.
    for (source_file, source_class, code) in scan_sources:
        for ref in _extract_source_constant_refs(code):
            if ref in seen_refs:
                continue
            seen_refs.add(ref)
            candidates = _find_constant_candidates_by_name(ref, preferred_files, context)
            chosen, _reason = _disambiguate_constant_candidates(
                candidates, source_file, source_class, symbol_matches, list(strategy.target_files)
            )
            if chosen is None:
                continue
            found_file, qualified_name, record = chosen
            # Repository-grounded the moment disambiguation succeeds --
            # independent of whether the one-hop DEFINITION block itself
            # goes on to fit the budget below. A usage-search seed costs
            # nothing to try and needs no separate budget slot, so it is
            # collected here unconditionally on a successful, unambiguous
            # match, not gated on _try_add_to's own render/budget outcome.
            bare_name = record.get("name") or qualified_name
            if bare_name:
                one_hop_discovered_terms.append(bare_name)
            line, end_line = record.get("line"), record.get("end_line")
            if line is None or end_line is None:
                continue
            key = (found_file, line, end_line)
            if key in used_definition_keys:
                continue  # already selected elsewhere -- never duplicated
            index = getattr(context, "index", None)
            read_start, read_end = _padded_line_range(line, end_line, _DEFINITION_CONTEXT_LINES)
            source_text = index.read_file_section(found_file, read_start, read_end) if index else None
            if source_text is None:
                continue
            render_end = _rendered_end_line(read_start, source_text)
            text = _render_definition_block(found_file, qualified_name, read_start, render_end, source_text)
            if _try_add_to(one_hop_blocks, text):
                used_definition_keys.add(key)  # key stays unpadded -- see _padded_line_range
                covered_files.add(found_file)

    # --- Method-call one-hop (SUPPORTING-context role, added on top of the
    # constant one-hop above -- exactly one additional bounded lookup
    # opportunity, never a second traversal mechanism). Structural
    # relevance rule: a dot-qualified call co-located, on the SAME source
    # line, with an already strategy-connected identifier (`strategy_
    # terms`) inside source ALREADY selected for the slice. A call on a
    # different line -- even in the very same already-admitted function --
    # gains no opportunity (see `_extract_source_dot_call_refs`). Scans
    # the exact same `scan_sources` the constant one-hop already built,
    # PLUS the already-computed Planner excerpt blocks
    # (`planner_excerpt_blocks`, i.e. `PlannerEvidenceResult.excerpt_plan.
    # blocks` -- see build_final_target_slice's own docstring): this is
    # what closes the stage-boundary gap where the qualifying line lives
    # in already-rendered Planner evidence rather than in this function's
    # own scan_sources. No new repository search, no Planner re-run, no
    # rendering from scratch -- `_extract_fenced_code` recovers the exact
    # same raw source text these blocks were rendered from. Resolution uses
    # `_lookup_identifier_definition_or_unique_repo_match` -- the normal
    # `preferred_files`-bound lookup first, falling back to exactly one
    # additional, uniqueness-gated repository-wide lookup ONLY for this
    # call site (see that function's own docstring for why this path, and
    # only this path, may look outside preferred_files: it resolves a call
    # target the already-verified consumer source itself references, not
    # an LLM-proposed term). Every other one-hop/usage lookup in this
    # function keeps calling `_lookup_identifier_definition` directly and
    # is completely unaffected. Every resolution is rendered under Category
    # 2's own "context only, not an approved edit target" heading and
    # merged into `category2_candidates` -- so it is committed by that
    # exact existing whole-block-or-omit loop below, against the SAME
    # shared budget, and can never become an edit target. Never recurses:
    # `dot_call_scan_texts` is fixed before this loop runs, and a
    # resolved definition's own source is never appended back to it.
    dot_call_scan_texts: "list[str]" = [code for (_f, _c, code) in scan_sources]
    for _block in planner_excerpt_blocks:
        _code = _extract_fenced_code(_block)
        if _code is not None:
            dot_call_scan_texts.append(_code)

    seen_dot_call_refs: set = set()
    for code in dot_call_scan_texts:
        for name in _extract_source_dot_call_refs(code, strategy_terms):
            if name in seen_dot_call_refs:
                continue
            seen_dot_call_refs.add(name)
            found = _lookup_identifier_definition_or_unique_repo_match(name, preferred_files, context)
            if found is None:
                continue
            key = (found.file, found.line, found.end_line)
            if key in used_definition_keys:
                continue
            if found.kind == "constant":
                dc_label = found.label
                index = getattr(context, "index", None)
                read_start, read_end = _padded_line_range(found.line, found.end_line, _DEFINITION_CONTEXT_LINES)
                dc_source = index.read_file_section(found.file, read_start, read_end) if index else None
                dc_render_start = read_start
                dc_render_end = _rendered_end_line(dc_render_start, dc_source) if dc_source else found.end_line
            else:
                dc_label = found.label
                index = getattr(context, "index", None)
                if index is not None and found.func_id:
                    func_record = index.get_function(found.func_id)
                    if func_record and func_record.get("className"):
                        dc_label = f"{func_record.get('className')}.{found.label}"
                dc_source = _read_symbol_source(
                    _SymbolMatch(file=found.file, label=found.label, kind="function",
                                 line=found.line, end_line=found.end_line, func_id=found.func_id),
                    context,
                )
                dc_render_start, dc_render_end = found.line, found.end_line
            if dc_source is None:
                continue
            used_definition_keys.add(key)  # decided now; committed later, same as category 2 above
            dc_text = _render_definition_block(
                found.file, dc_label, dc_render_start, dc_render_end, dc_source,
                heading_label=_CATEGORY2_HEADING_LABEL,
            )
            category2_candidates.append((dc_text, found.file))

    # --- Usage-search re-seed (SUPPORTING-context role, same tier as 3a
    # below -- this IS 3a, just re-run once more with additional terms):
    # once the one-hop pass above has deterministically resolved a
    # repository-grounded constant identifier that the resolved target's
    # OWN already-selected source references (e.g. a class-level default
    # threaded through __init__'s own signature), that SAME identifier is
    # eligible to seed the identical bounded usage search category 3a
    # already runs -- never a new search mechanism, never a wider file
    # scope (still `preferred_files` only), never LLM-prose-derived. This
    # is what lets a same-file constructor/normalization consumer that
    # _mechanism_terms_first(strategy_terms, ...) alone didn't happen to
    # name be found anyway, WITHOUT recursing into whatever that consumer
    # itself references (one_hop_blocks/one_hop_discovered_terms are never
    # themselves re-scanned) and WITHOUT touching edit-target authority --
    # every result lands in `category3_candidates` with raw_symbol=None,
    # the exact same SUPPORTING-context shape 3a's own hits already use.
    if one_hop_discovered_terms:
        seed_hits: "dict[tuple[str, str], dict]" = {}
        seed_order: "list[tuple[str, str]]" = []
        for term in one_hop_discovered_terms:
            for (f, label, fn_start, fn_end, offsets) in _lookup_identifier_usages(term, preferred_files, context):
                fkey = (f, label)
                if fkey not in seed_hits:
                    seed_hits[fkey] = {"fn_start": fn_start, "fn_end": fn_end, "offsets": set()}
                    seed_order.append(fkey)
                seed_hits[fkey]["offsets"].update(offsets)

        for (f, label) in seed_order:
            hit = seed_hits[(f, label)]
            ranges = _windows_for(hit["fn_start"], hit["fn_end"], sorted(hit["offsets"]))
            key = (f, label, tuple(ranges))
            if key in used_usage_keys:
                continue  # already found via strategy_terms' own scan above -- never duplicated
            text = _render_usage_window_block(f, label, ranges, context)
            if text is None:
                continue
            used_usage_keys.add(key)
            # A re-seed hit's connecting term is always a one_hop_discovered_
            # terms entry, folded into `target_derived_terms` below for band
            # classification -- so it does not need its own separate marker.
            category3_candidates.append((text, f, label, None))

    # --- Commit category 2's candidates now (SUPPORTING-context role,
    # tier 3) -- after every edit-target candidate AND the one-hop step
    # above have already had first claim on the budget.
    for (text, f) in category2_candidates:
        if _try_add_to(blocks_by_category[2], text):
            covered_files.add(f)
            identifier_definition_covered.add(f)

    # --- Commit category 3a's SUPPORTING-context candidates now (tier 4)
    # -- 3b's edit-target candidates were already committed above. Within
    # this tier, Band A (a window discovered via a term deterministically
    # tied to an already-resolved target's own identity -- either the
    # target's own resolved label, dot-split, OR a constant the one-hop
    # pass above deterministically found the target's OWN already-selected
    # source referencing) is committed ahead of Band B (discovered only via
    # a general mechanism/context term), so a focused, target-connected
    # consumer never loses this shared budget to a larger, less directly
    # connected candidate merely because the latter happened to be scanned
    # first -- an incidental side effect of prose-mention order in
    # Strategy's own free text, not a deliberate priority. `function_terms`
    # only has an entry for a window found via the ORIGINAL strategy-term
    # scan above (3a proper) -- a re-seed hit (found only via a term in
    # `one_hop_discovered_terms`, never in `strategy_terms` at all) has no
    # entry there and so is classified purely by the `in reseed_terms`
    # check, which is exactly what it needs: re-seed hits exist ONLY
    # because one-hop tied them to the target, so they are always Band A.
    # Purely a local reordering of THIS tier's own commit order -- category
    # 1/2/3b/4/one-hop/5's relative priority is unchanged, and nothing here
    # grows preferred_files, widens the search, or raises the shared budget.
    # A candidate also independently earns Band A when it is a member of
    # the SAME class as the resolved target (`target_class_identities`,
    # above) -- checked first, and purely from the candidate's own
    # already-computed label, so it applies equally to a term-scan hit and
    # a re-seed hit without needing a separate per-candidate marker.
    reseed_terms = set(one_hop_discovered_terms)
    final_target_derived_terms = target_derived_terms | reseed_terms

    def _is_band_a(f: str, label: str) -> bool:
        if _class_of_label(label) in target_class_identities:
            return True
        terms = function_terms.get((f, label))
        if terms is None:
            return True  # a re-seed-only hit -- see docstring above
        return bool(terms & final_target_derived_terms)

    for (text, f, label, raw_symbol) in category3_candidates:
        if raw_symbol is not None:
            continue  # 3b (edit-target) -- already committed above
        if not _is_band_a(f, label):
            continue
        if _try_add_to(blocks_by_category[3], text):
            covered_files.add(f)
    for (text, f, label, raw_symbol) in category3_candidates:
        if raw_symbol is not None:
            continue  # 3b (edit-target) -- already committed above
        if _is_band_a(f, label):
            continue  # already committed in the Band A pass above
        if _try_add_to(blocks_by_category[3], text):
            covered_files.add(f)

    # --- Category 5: full-file fallback -- only for a target FILE with no
    # coverage at all from categories 1-4. EDIT-TARGET role only when the
    # file has no target_symbol of its own (a file-level intended edit --
    # see check_edit_readiness) AND the fallback text actually contains a
    # strategy-derived identifier ("do not consider a file covered merely
    # because unrelated source from the same file was included" -- a
    # full-file fallback for a file that also has its own, separately
    # uncovered target_symbol is NOT treated as satisfying that symbol).
    symbol_owned_files = {m.file for m in symbol_matches.values()}
    for f in strategy.target_files:
        if f in covered_files:
            continue
        try:
            full_text = (root / f).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        text = _render_full_file_block(f, full_text)
        if _try_add_to(blocks_by_category[5], text):
            covered_files.add(f)
            if f not in symbol_owned_files and (
                not strategy_terms or _contains_any_strategy_identifier(full_text, strategy_terms)
            ):
                full_file_fallback_covered.add(f)

    lines: "list[str]" = [_SLICE_HEADING, "", _SLICE_DISCLAIMER]
    any_block = False
    for group in (
        blocks_by_category[1], one_hop_blocks, blocks_by_category[2],
        blocks_by_category[3], blocks_by_category[4], blocks_by_category[5],
    ):
        for text in group:
            lines.append("")
            lines.append(text.rstrip())
            any_block = True
    rendered = ("\n".join(lines).rstrip() + "\n") if any_block else ""

    uncovered_files = [f for f in strategy.target_files if f not in covered_files]
    uncovered_symbols = [s for s in strategy.target_symbols if s not in covered_symbols]
    coverage_complete = not uncovered_files and not uncovered_symbols
    has_any_coverage = bool(covered_files or covered_symbols)

    warning_text = _render_coverage_warning(
        uncovered_files, uncovered_symbols, rendered_nonempty=bool(rendered),
        named_any_target=bool(strategy.target_files or strategy.target_symbols),
    )

    return FinalTargetSliceResult(
        rendered=rendered,
        covered_target_files=[f for f in strategy.target_files if f in covered_files],
        covered_target_symbols=[s for s in strategy.target_symbols if s in covered_symbols],
        uncovered_target_files=uncovered_files,
        uncovered_target_symbols=uncovered_symbols,
        coverage_complete=coverage_complete,
        has_any_coverage=has_any_coverage,
        warning_text=warning_text,
        resolved_target_symbols=list(symbol_matches.keys()),
        full_file_fallback_covered=sorted(full_file_fallback_covered),
        edit_target_budget_exhausted=edit_target_budget_exhausted,
        resolved_symbol_files={raw: m.file for raw, m in symbol_matches.items()},
        identifier_definition_covered=sorted(identifier_definition_covered),
    )


# ---------------------------------------------------------------------------
# Edit Readiness Gate (Slice 1)
#
# Prevents Patch Generation from running when an intended edit does not yet
# have relevant, verified, patch-ready repository source -- replacing the
# coarse "has_any_coverage == safe to generate" assumption with a decision
# made separately for every intended edit. Reuses ONLY data
# build_final_target_slice() already computes: no new repository read, no
# new resolution pass, no new LLM call, no retrieval loop. Slices 2+
# (bounded re-retrieval, post-patch correction) are explicitly out of scope
# here -- this only detects and fails closed.
# ---------------------------------------------------------------------------


class IntendedEdit(NamedTuple):
    """One deterministic (file, symbol) pair Patch Generation is expected
    to edit -- derived only from RemediationStrategyResult's already
    independently re-verified target_files/target_symbols (see
    _verify_strategy_targets). Never a new LLM schema, never a new
    resolution pass. `symbol` is None only for a file-level intended edit
    (see build_intended_edits)."""

    file: "str | None"
    symbol: "str | None"


def build_intended_edits(
    strategy: RemediationStrategyResult, slice_result: "FinalTargetSliceResult | None" = None,
) -> "list[IntendedEdit]":
    """Derive intended edits from a verified RemediationStrategyResult.

    One IntendedEdit per verified target_symbol (deduplicated, in
    strategy.target_symbols' own order), using _split_symbol_entry -- the
    same existing helper _resolve_symbol_details already uses -- to read
    off a file hint when the symbol string carries one
    ("path/to/file.py:Class.method"). A file-level IntendedEdit
    (symbol=None) is added only for a verified target_file that has no
    target_symbol naming a location inside it, per this slice's explicit
    scope ("Add a file-level intended edit only when a verified target
    file has no corresponding verified target symbol").

    A target_symbol with NO file hint in its own string (e.g. a bare
    "Class.method") is not necessarily unrelated to one of
    strategy.target_files -- it may simply have been proposed without a
    "file.py:" prefix. `slice_result.resolved_symbol_files` (already
    computed by build_final_target_slice -- see FinalTargetSliceResult),
    when given, supplies that symbol's own real, verified file without
    any new resolution pass here. Passing it lets a bare symbol's
    IntendedEdit carry its real file (rather than file=None) and
    correctly suppresses the file-level IntendedEdit that would
    otherwise be added for the same file -- fixing a real duplication:
    without this, a bare target_symbol resolving into a file already
    named in target_files previously produced TWO IntendedEdits for one
    logical target (IntendedEdit(file=None, symbol=...) AND
    IntendedEdit(file=<that file>, symbol=None)), and the second,
    spurious one could fail readiness on its own and falsely block Patch
    Generation even though the real (symbol) edit was fully ready.
    `slice_result=None` (the default) preserves the exact prior
    behavior for any caller that doesn't have one yet.

    Pure and deterministic: no repository access, no new resolution, no
    LLM call -- everything read here (including via `slice_result`) was
    already computed and re-verified before this function is ever
    called.
    """
    resolved_symbol_files = getattr(slice_result, "resolved_symbol_files", None) or {}

    edits: "list[IntendedEdit]" = []
    seen_symbols: set = set()
    symbol_files: set = set()
    for raw_symbol in strategy.target_symbols:
        if raw_symbol in seen_symbols:
            continue
        seen_symbols.add(raw_symbol)
        file_hint, _name = _split_symbol_entry(raw_symbol)
        resolved_file = file_hint or resolved_symbol_files.get(raw_symbol)
        if resolved_file:
            symbol_files.add(resolved_file)
        edits.append(IntendedEdit(file=resolved_file, symbol=raw_symbol))

    seen_files: set = set()
    for f in strategy.target_files:
        if f in symbol_files or f in seen_files:
            continue
        seen_files.add(f)
        edits.append(IntendedEdit(file=f, symbol=None))

    return edits


class ReadyEdit(NamedTuple):
    """One intended edit the Final-Target Remediation Slice already has
    patch-ready source for. `role` is always "edit_target" -- the only
    role check_edit_readiness ever grants readiness through (a consumer,
    dependency, caller, or callee is never treated as equivalent to the
    actual edit target -- see check_edit_readiness)."""

    edit: IntendedEdit
    role: str
    file: str
    symbol: "str | None"


class UnreadyEdit(NamedTuple):
    """One intended edit the Slice does NOT yet have patch-ready source
    for, with the single most evidence-supported reason -- see
    check_edit_readiness's docstring for exactly what each reason means
    and what it deliberately does not claim."""

    edit: IntendedEdit
    reason: str


class EditReadinessResult(NamedTuple):
    """The Edit Readiness Gate's decision -- exposed at enough detail for
    later work (bounded re-retrieval, post-patch correction) without this
    slice implementing either. `failure_reasons` is `unready_edits`' own
    reasons, deduplicated, in first-seen order -- a quick top-level
    summary of why readiness failed, never a claim more precise than what
    each UnreadyEdit itself already states."""

    strategy_ready: bool
    edit_source_ready: bool
    intended_edits: "list[IntendedEdit]"
    ready_edits: "list[ReadyEdit]"
    unready_edits: "list[UnreadyEdit]"
    failure_reasons: "list[str]"


# The full reason vocabulary this Gate's schema supports. NOTE:
# "source_not_patch_ready" is deliberately never produced by
# check_edit_readiness below -- every block build_final_target_slice
# renders today (padded constants via _DEFINITION_CONTEXT_LINES, whole
# functions, focused windows, full files) is already patch-ready by
# construction, so nothing in current data can distinguish "resolved and
# rendered, but not patch-ready" from "ready". Kept in the vocabulary for
# schema completeness/forward compatibility only -- see check_edit_readiness's
# docstring, which is the actual, current, evidence-backed behavior.
EDIT_READINESS_REASONS = (
    "unresolved_symbol",
    "missing_target_source",
    "missing_identifier",
    "source_not_patch_ready",
    "target_budget_exhausted",
)


def check_edit_readiness(
    intended_edits: "list[IntendedEdit]", slice_result: FinalTargetSliceResult,
    *, allow_full_file_fallback_for_symbols: bool = False,
) -> EditReadinessResult:
    """Deterministically decide, per intended edit, whether the Final-
    Target Remediation Slice already gave Patch Generation patch-ready,
    verified repository source for it -- reusing only fields
    build_final_target_slice() already computes. No new repository read,
    no new resolution pass, no new LLM call, no retrieval.

    A symbol-having edit is ready iff its symbol is in
    slice_result.covered_target_symbols -- which already means, by
    build_final_target_slice's own coverage rule (see that function's
    docstring), "this exact symbol's own definition or full/windowed
    source was rendered", never merely "some other identifier from the
    same file was included". When not ready:
      - "unresolved_symbol" if the symbol never resolved to a real
        repository location at all (not in slice_result.resolved_target_symbols);
      - "target_budget_exhausted" if it resolved, but the combined
        attempted size of every edit-target candidate (categories 1, 3b,
        4 -- computed BEFORE any supporting-context block was even
        considered) already exceeded the whole slice budget on its own;
      - "missing_target_source" otherwise (resolved, budget had room, but
        no usable rendered source for it still made it in -- e.g. a read
        failure, or an oversized function exceeding the compact-render
        cap; current data cannot distinguish these further, so this
        function does not claim to).

    A file-only edit (no target_symbol names a location inside it) is
    ready via either of two precise, verified sources -- categories 1/3b/4
    never fire without a resolved symbol, so neither path can ever be
    satisfied by an unrelated same-file block:
      - slice_result.full_file_fallback_covered (category 5): the whole
        file was rendered AND contains a strategy-derived identifier; or
      - slice_result.identifier_definition_covered (category 2): an
        EXACT definition of a strategy-derived identifier -- constant or
        function, not a mere usage window -- was rendered from that
        file. Added for Slice 2 (Deterministic Pre-Patch Retrieval):
        without it, a file whose own exact identifier definition was
        found and rendered could still fail readiness merely because
        category 5's full-file fallback never ran for it (already
        covered, so skipped) -- an evidence-quality gap, not a
        correctness requirement, since a resolved exact definition is
        strictly stronger evidence than an unverified whole file.
    When neither is satisfied:
      - "missing_target_source" if no source at all was rendered for
        that file;
      - "missing_identifier" if source WAS rendered for that file (it's
        in covered_target_files) but not via either of the above -- i.e.
        only unrelated/supporting content (e.g. a usage window, or a
        one-hop dependency) from that file exists, which must never
        count as covering it.

    "source_not_patch_ready" is never produced -- see EDIT_READINESS_REASONS.

    `allow_full_file_fallback_for_symbols=False` (the default, and every
    existing caller) preserves this exact behavior unchanged: a
    symbol-having edit's readiness is decided purely by whether ITS OWN
    symbol resolved, never by the file-level full_file_fallback_covered/
    identifier_definition_covered signals the file-only branch already
    uses. When True (used by exactly one caller -- pipeline.run()'s
    bounded target-file fallback, applied only once, only after guided
    acquisition has already been exhausted), a symbol-having edit whose
    own symbol never resolved MAY still be marked ready if its file is
    already in full_file_fallback_covered/identifier_definition_covered --
    i.e. the SAME already-verified, already-rendered whole-file (or exact
    identifier) source a file-only edit could always use. This never reads
    a new file, never trusts an LLM-proposed location, and never widens
    which files qualify: full_file_fallback_covered/
    identifier_definition_covered are themselves fixed by
    build_final_target_slice() from the Final Strategy's own verified
    target_files, before this function ever runs.
    """
    strategy_ready = bool(intended_edits)
    ready: "list[ReadyEdit]" = []
    unready: "list[UnreadyEdit]" = []
    reasons_seen: "list[str]" = []

    def _note(reason: str) -> None:
        if reason not in reasons_seen:
            reasons_seen.append(reason)

    for edit in intended_edits:
        if edit.symbol is not None:
            if edit.symbol in slice_result.covered_target_symbols:
                ready.append(ReadyEdit(edit=edit, role="edit_target", file=edit.file or "", symbol=edit.symbol))
                continue
            if allow_full_file_fallback_for_symbols and edit.file is not None and (
                edit.file in slice_result.full_file_fallback_covered
                or edit.file in slice_result.identifier_definition_covered
            ):
                ready.append(ReadyEdit(edit=edit, role="edit_target", file=edit.file, symbol=edit.symbol))
                continue
            if edit.symbol not in slice_result.resolved_target_symbols:
                reason = "unresolved_symbol"
            elif slice_result.edit_target_budget_exhausted:
                reason = "target_budget_exhausted"
            else:
                reason = "missing_target_source"
        else:
            if (
                edit.file in slice_result.full_file_fallback_covered
                or edit.file in slice_result.identifier_definition_covered
            ):
                ready.append(ReadyEdit(edit=edit, role="edit_target", file=edit.file or "", symbol=None))
                continue
            if edit.file not in slice_result.covered_target_files:
                reason = "missing_target_source"
            else:
                reason = "missing_identifier"
        unready.append(UnreadyEdit(edit=edit, reason=reason))
        _note(reason)

    edit_source_ready = strategy_ready and not unready
    return EditReadinessResult(
        strategy_ready=strategy_ready,
        edit_source_ready=edit_source_ready,
        intended_edits=list(intended_edits),
        ready_edits=ready,
        unready_edits=unready,
        failure_reasons=reasons_seen,
    )


# ---------------------------------------------------------------------------
# Slice 2 -- Deterministic Pre-Patch Retrieval
#
# When check_edit_readiness (Slice 1) reports one or more UnreadyEdits,
# attempt to obtain additional verified repository source for exactly
# those targets -- deterministic, bounded, language-agnostic, fully
# traceable, fail-closed, and free of any new LLM call. Not a general
# agent loop: there is no exploration, no LLM-guided request, no retry of
# Patch Generation itself, and no post-patch recovery -- see
# run_deterministic_acquisition's docstring for the exact scope.
#
# Design choice: rather than a second, parallel retrieval implementation,
# this RE-INVOKES build_final_target_slice() itself, per still-unready
# edit, on a narrowly-scoped RemediationStrategyResult naming ONLY that
# edit's own file/symbol -- so every existing category (1-5), the
# existing _DEFINITION_CONTEXT_LINES padding, the existing ambiguity
# rejection (_disambiguate_constant_candidates), and the existing
# coverage rules all apply completely unchanged. check_edit_readiness
# itself (also completely unchanged) is what decides whether each
# retrieval attempt actually satisfied its edit.
# ---------------------------------------------------------------------------

MAX_ACQUISITION_ROUNDS = 2
"""How many acquisition rounds run_deterministic_acquisition will attempt
before giving up and failing closed. Conservative MVP default -- Slice 3
(LLM-guided context requests) is explicitly out of scope, so there is no
mechanism here to ever do better than "the same deterministic lookups,
tried again next round with a fresh per-round budget for whatever is
still unready"."""

MAX_UNREADY_EDITS_PER_ROUND = 2
"""How many still-unready intended edits one round will attempt, in
their existing (deterministic) order. Never all of them at once -- an
unbounded round could spend the whole remaining budget on a single
round's first few targets."""

MAX_NEW_SOURCE_CHARS_PER_ROUND = 5_000
"""Shared character budget for ONE round's acquisition, across every
edit that round processes (not per edit) -- consumed in order as each
edit in the round is attempted. Always further clamped by whatever
remains of FINAL_TARGET_SLICE_MAX_CHARS overall (see
run_deterministic_acquisition) -- this is a per-round ceiling on top of
the existing hard total, never a separate allowance that extends it."""

MAX_NEW_BLOCKS_PER_EDIT_PER_ROUND = 1
"""At most one new EDIT-TARGET block per edit per round. Enforced
STRUCTURALLY, not by truncating a rendered result after the fact: each
round's retrieval call for one edit is built from a RemediationStrategy
naming ONLY that edit's own single file-or-symbol target, so categories
1/3b/4 (the edit-target categories) can resolve at most that one target.
A one-hop supporting definition or full-file fallback may still
accompany it as SUPPORTING content, exactly like every other
build_final_target_slice call -- never a second competing edit-target
block for the same edit."""


class RetrievalAttempt(NamedTuple):
    """One deterministic acquisition attempt for a single UnreadyEdit,
    during one round of run_deterministic_acquisition. Fields are
    exactly what actually happened -- `resolved_file`/`resolved_symbol`/
    `start_line`/`end_line`/`source_kind` are None whenever nothing was
    rendered for this edit this round, never a guess.

    `failure_reason` reuses check_edit_readiness's own
    EDIT_READINESS_REASONS vocabulary verbatim (this function's own
    per-edit recheck IS a check_edit_readiness call) -- no new reason
    string is invented. In particular, an ambiguous candidate
    (_disambiguate_constant_candidates rejecting a tie) is not
    separately labeled "ambiguous" here: it is simply never rendered, so
    it surfaces as "missing_target_source"/"missing_identifier" like any
    other resolved-but-unrendered case, per this module's existing "do
    not claim a more precise reason than the underlying data supports"
    convention (see check_edit_readiness's own docstring for the same
    convention applied to "missing_target_source")."""

    intended_edit: IntendedEdit
    round: int
    retrieval_strategy: str
    resolved_file: "str | None"
    resolved_symbol: "str | None"
    start_line: "int | None"
    end_line: "int | None"
    source_kind: "str | None"
    source_chars: int
    success: bool
    failure_reason: "str | None"


class AcquisitionResult(NamedTuple):
    """run_deterministic_acquisition's own output. `slice_result` is the
    ORIGINAL slice extended additively with whatever this loop acquired
    -- nothing already present is ever removed or reordered. `attempts`
    is every RetrievalAttempt made, in round then edit order (for the
    debug artifact). `rounds_used` is 0 when the initial readiness was
    already complete (no acquisition work performed at all)."""

    slice_result: FinalTargetSliceResult
    attempts: "list[RetrievalAttempt]"
    rounds_used: int


_RENDERED_LINES_RE = re.compile(r"\(lines (\d+)[–-](\d+)\)")


def _sniff_rendered_lines(rendered_text: str) -> "tuple[int | None, int | None]":
    """Recover the (start, end) line numbers from a block's own header --
    a format this module fully controls (_render_definition_block/
    _render_usage_window_block), so this is reading back already-known
    data, never a new computation or a guess."""
    m = _RENDERED_LINES_RE.search(rendered_text)
    if not m:
        return None, None
    return int(m.group(1)), int(m.group(2))


def _sniff_rendered_kind(rendered_text: str) -> "str | None":
    """Classify which of this module's own, fully-controlled block
    headers is present -- for RetrievalAttempt.source_kind only, never
    consulted by any readiness or budget decision."""
    if any(prefix in rendered_text for prefix in _EDIT_TARGET_HEADING_PREFIXES):
        return "exact_definition"
    if "#### Discovered consumer:" in rendered_text:
        return "usage_window"
    if "#### Full file (last resort):" in rendered_text:
        return "full_file_fallback"
    return None


def _merge_slice_results(
    base: FinalTargetSliceResult,
    addition: FinalTargetSliceResult,
    strategy: RemediationStrategyResult,
) -> FinalTargetSliceResult:
    """Fold one round's single-edit Final-Target Slice into the running
    aggregate -- ADDITIVELY ONLY: every field is a union/append against
    `base`, so nothing already covered or already rendered is ever
    removed, reordered, or displaced. `addition`'s own per-round budget
    was already independently enforced by build_final_target_slice (see
    run_deterministic_acquisition) -- this performs no further size
    check of its own.

    Coverage/uncovered/coverage_complete/has_any_coverage are recomputed
    against the FULL original `strategy` (not `addition`'s narrowly-
    scoped one) so they keep meaning exactly what they meant before
    acquisition ever ran. `warning_text` is re-rendered via the same
    _render_coverage_warning helper build_final_target_slice itself
    uses, so it never goes stale after new coverage is folded in.
    """
    rendered = base.rendered
    if addition.rendered:
        rendered = (rendered.rstrip() + "\n\n" + addition.rendered) if rendered else addition.rendered

    covered_files = set(base.covered_target_files) | set(addition.covered_target_files)
    covered_symbols = set(base.covered_target_symbols) | set(addition.covered_target_symbols)
    resolved_symbols = set(base.resolved_target_symbols) | set(addition.resolved_target_symbols)
    fallback_covered = set(base.full_file_fallback_covered) | set(addition.full_file_fallback_covered)
    identifier_def_covered = set(base.identifier_definition_covered) | set(addition.identifier_definition_covered)
    resolved_symbol_files = dict(base.resolved_symbol_files)
    resolved_symbol_files.update(addition.resolved_symbol_files)

    uncovered_files = [f for f in strategy.target_files if f not in covered_files]
    uncovered_symbols = [s for s in strategy.target_symbols if s not in covered_symbols]
    coverage_complete = not uncovered_files and not uncovered_symbols

    return FinalTargetSliceResult(
        rendered=rendered,
        covered_target_files=[f for f in strategy.target_files if f in covered_files],
        covered_target_symbols=[s for s in strategy.target_symbols if s in covered_symbols],
        uncovered_target_files=uncovered_files,
        uncovered_target_symbols=uncovered_symbols,
        coverage_complete=coverage_complete,
        has_any_coverage=bool(covered_files or covered_symbols),
        warning_text=_render_coverage_warning(
            uncovered_files, uncovered_symbols, rendered_nonempty=bool(rendered),
            named_any_target=bool(strategy.target_files or strategy.target_symbols),
        ),
        resolved_target_symbols=sorted(resolved_symbols),
        full_file_fallback_covered=sorted(fallback_covered),
        edit_target_budget_exhausted=base.edit_target_budget_exhausted or addition.edit_target_budget_exhausted,
        resolved_symbol_files=resolved_symbol_files,
        identifier_definition_covered=sorted(identifier_def_covered),
    )


def _try_commit_acquisition(
    current_slice: FinalTargetSliceResult,
    addition: FinalTargetSliceResult,
    strategy: RemediationStrategyResult,
    edits_to_check: "list[IntendedEdit]",
) -> "tuple[FinalTargetSliceResult, EditReadinessResult, bool]":
    """Transactional commit/rollback for ONE acquisition candidate --
    Slice 2 (run_deterministic_acquisition) and Slice 3
    (run_guided_acquisition) both share this exact mechanism rather than
    each reimplementing it. `addition` is folded into a TEMPORARY working
    slice via the existing, unmodified _merge_slice_results (never a
    second merge implementation), so Edit Readiness for `edits_to_check`
    can be recomputed (check_edit_readiness, also unmodified) against
    what the running slice WOULD look like if this candidate were kept.

    The commit criterion is exactly, and only, "did Edit Readiness
    improve for at least one of `edits_to_check`?" -- deterministic,
    content-blind, and never a heuristic judgement of whether the
    retrieved text looks generically useful:
      - improved (at least one of `edits_to_check` is now in the
        returned readiness's `ready_edits`): the temporary merge IS the
        new running slice -- `addition` is committed, and its size is
        the caller's own signal to actually deduct from whatever budget
        it tracks.
      - not improved: `current_slice` is returned completely unchanged --
        `addition` never entered the Final-Target Slice, so a caller
        that only advances its own state (and consumes its own budget)
        when `committed` is True never lets a rolled-back candidate
        occupy either.

    Returns `(slice_to_use, readiness, committed)`. `readiness` is
    ALWAYS computed against the temporary merged slice, whether or not
    it is committed -- so a rolled-back attempt's own diagnostic
    (`RetrievalAttempt.failure_reason` / `GuidedRetrievalAttempt.
    failure_reason`) still names exactly what THIS attempt found (e.g.
    "target_budget_exhausted", "missing_identifier"), precisely as
    before this mechanism existed. It is `slice_to_use` -- never
    `readiness` -- that enforces "a rolled-back candidate leaves the
    running slice, and therefore every OTHER edit's own readiness,
    completely unchanged": callers must recompute readiness against
    `slice_to_use` (not this returned `readiness`) for anything meant to
    persist past this one attempt (e.g. the next round's starting
    readiness)."""
    merged = _merge_slice_results(current_slice, addition, strategy)
    readiness = check_edit_readiness(edits_to_check, merged)
    committed = bool(readiness.ready_edits)
    return (merged if committed else current_slice), readiness, committed


def _focused_strategy_for_edit(strategy: RemediationStrategyResult, edit: IntendedEdit) -> RemediationStrategyResult:
    """A RemediationStrategyResult naming ONLY `edit`'s own file/symbol --
    `extended_mechanism`/`required_edits` are kept unchanged, so strategy-
    derived identifier extraction (_extract_strategy_identifiers, used by
    categories 2/3a/one-hop) still benefits from the full mechanism text;
    only WHICH targets are attempted is narrowed. This is what makes one
    retrieval attempt see only its own edit target -- never an unrelated
    caller, consumer, or other still-ready target competing for the same
    round budget (see MAX_NEW_BLOCKS_PER_EDIT_PER_ROUND)."""
    target_symbols = [edit.symbol] if edit.symbol is not None else []
    target_files = [edit.file] if edit.file else []
    return strategy._replace(target_files=target_files, target_symbols=target_symbols)


def run_deterministic_acquisition(
    strategy: RemediationStrategyResult,
    repo_root,
    context,
    slice_result: FinalTargetSliceResult,
    readiness: EditReadinessResult,
    budget_controller: "ContextBudgetController | None" = None,
) -> AcquisitionResult:
    """
    Slice 2 -- Deterministic Pre-Patch Retrieval.

    Runs ONLY when `readiness` already reports at least one UnreadyEdit;
    a fully-ready (or empty) initial readiness performs zero acquisition
    work and returns `slice_result` unchanged (rounds_used=0, no
    attempts) -- see PipelineResult.edit_acquisition/pipeline.py wiring
    for where this sits between the Edit Readiness Gate and Patch
    Generation.

    Bounded: at most MAX_ACQUISITION_ROUNDS rounds; each round attempts
    at most MAX_UNREADY_EDITS_PER_ROUND still-unready intended edits (in
    their existing, deterministic order -- never re-ordered by size or
    likelihood of success); each round's newly-acquired source is capped
    at MAX_NEW_SOURCE_CHARS_PER_ROUND characters shared across that
    round's edits, and further clamped so FINAL_TARGET_SLICE_MAX_CHARS
    overall is never exceeded -- this is the SAME hard total the initial
    slice already enforces, never a separate additional allowance.

    Deterministic and language-agnostic: each attempt re-invokes
    build_final_target_slice() itself (unmodified) on a strategy naming
    only that one edit's own target (_focused_strategy_for_edit) -- so
    every existing category (1: exact definitions, 2: strategy-
    identifier definitions, 3: focused usage windows, 4: compact full
    functions, 5: full-file fallback), the existing
    _DEFINITION_CONTEXT_LINES padding, and the existing ambiguity
    rejection (_disambiguate_constant_candidates -- an ambiguous
    candidate is never promoted, exactly as in the initial pass) all
    apply completely unchanged. No fuzzy matching, no trusting an
    LLM-provided line number (nothing here reads one), no retrieval of a
    caller/consumer as a substitute for the edit target -- the focused
    strategy names only the edit target itself, so a supporting-role
    category can only ever surface content FROM that same file/symbol's
    own neighborhood, never an unrelated one.

    Readiness is recalculated (check_edit_readiness, unmodified) after
    every round, and the loop stops immediately once every intended edit
    is ready -- never running a round it doesn't need. If bounds are
    reached with readiness still incomplete, the caller's existing
    fail-closed skip path applies unchanged; this function itself makes
    no Patch Generation decision.

    Never evicts anything already in `slice_result`, and -- via
    _try_commit_acquisition (shared with Slice 3) -- never ADDS anything
    that didn't earn its place either: each attempt's `addition` is
    committed into the running slice, and only then counts against
    `round_budget_remaining`/the overall FINAL_TARGET_SLICE_MAX_CHARS
    total, if it actually made `edit` ready. An attempt that resolves and
    renders fine but never satisfies `edit`'s own readiness is rolled
    back completely -- transactional, so a candidate that never helped
    this edit can never be the reason a LATER, more precise attempt
    (this round, a later round, or Slice 3 afterward) fails with
    "target_budget_exhausted"/"context_request_limit_reached" purely
    because the earlier one silently used up shared budget. Introduces
    zero new LLM calls (build_final_target_slice/check_edit_readiness
    both take no `llm` parameter).

    `budget_controller=None` (the default, and every existing caller)
    preserves this exact fixed-budget, fail-closed behavior unchanged.
    When given, a candidate blocked ONLY by the shared
    FINAL_TARGET_SLICE_MAX_CHARS total (never by an unsafe path,
    ambiguity, or any other non-budget reason) gets exactly one
    immediate, local retry against a raised ceiling if the controller
    approves an additional window (see ContextBudgetController /
    _effective_final_target_max) -- never a second round, never a
    restart of this function, never a rerun of the Planner/Final
    Strategy.
    """
    if readiness.edit_source_ready or not readiness.unready_edits:
        return AcquisitionResult(slice_result=slice_result, attempts=[], rounds_used=0)

    attempts: "list[RetrievalAttempt]" = []
    current_slice = slice_result
    current_readiness = readiness
    rounds_used = 0

    for round_num in range(1, MAX_ACQUISITION_ROUNDS + 1):
        if current_readiness.edit_source_ready or not current_readiness.unready_edits:
            break
        rounds_used = round_num
        batch = current_readiness.unready_edits[:MAX_UNREADY_EDITS_PER_ROUND]
        round_budget_remaining = MAX_NEW_SOURCE_CHARS_PER_ROUND

        for unready in batch:
            edit = unready.edit
            _affected = [f"{edit.file or '?'}:{edit.symbol or '(file-level)'}"]
            total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
            available = min(round_budget_remaining, total_remaining)
            if budget_controller is not None:
                budget_controller.record_used("final_target_slice", len(current_slice.rendered))

            if available <= 0 or (edit.symbol is None and not edit.file):
                if available <= 0 and budget_controller is not None and budget_controller.request_extension(
                    "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                    reason="target_budget_exhausted", affected_targets=_affected,
                ):
                    total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                    available = min(round_budget_remaining, total_remaining)
                if available <= 0 or (edit.symbol is None and not edit.file):
                    attempts.append(RetrievalAttempt(
                        intended_edit=edit, round=round_num, retrieval_strategy="skipped_no_budget",
                        resolved_file=None, resolved_symbol=None, start_line=None, end_line=None,
                        source_kind=None, source_chars=0, success=False,
                        failure_reason="target_budget_exhausted" if available <= 0 else unready.reason,
                    ))
                    continue

            focused_strategy = _focused_strategy_for_edit(strategy, edit)
            addition = build_final_target_slice(
                focused_strategy, repo_root, context, planner_evidence_files=(), max_chars=available,
            )
            current_slice, single, committed = _try_commit_acquisition(current_slice, addition, strategy, [edit])
            if committed:
                round_budget_remaining = max(0, round_budget_remaining - len(addition.rendered))
            elif (
                budget_controller is not None
                and single.unready_edits
                and single.unready_edits[0].reason == "target_budget_exhausted"
                and budget_controller.request_extension(
                    "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                    reason="target_budget_exhausted", affected_targets=_affected,
                )
            ):
                # Resolved fine but didn't fit `available` -- exactly one
                # local retry against the newly-raised shared ceiling,
                # never a second round and never a Planner/Strategy rerun.
                total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                available = min(round_budget_remaining, total_remaining)
                addition = build_final_target_slice(
                    focused_strategy, repo_root, context, planner_evidence_files=(), max_chars=available,
                )
                current_slice, single, committed = _try_commit_acquisition(current_slice, addition, strategy, [edit])
                if committed:
                    round_budget_remaining = max(0, round_budget_remaining - len(addition.rendered))

            if single.ready_edits:
                r = single.ready_edits[0]
                start, end = _sniff_rendered_lines(addition.rendered)
                attempts.append(RetrievalAttempt(
                    intended_edit=edit, round=round_num, retrieval_strategy="final_target_slice_retry",
                    resolved_file=r.file or None, resolved_symbol=r.symbol,
                    start_line=start, end_line=end,
                    source_kind=_sniff_rendered_kind(addition.rendered),
                    source_chars=len(addition.rendered), success=True, failure_reason=None,
                ))
            else:
                reason = single.unready_edits[0].reason if single.unready_edits else "missing_target_source"
                attempts.append(RetrievalAttempt(
                    intended_edit=edit, round=round_num, retrieval_strategy="final_target_slice_retry",
                    resolved_file=None, resolved_symbol=None, start_line=None, end_line=None,
                    source_kind=None, source_chars=len(addition.rendered), success=False, failure_reason=reason,
                ))

        current_readiness = check_edit_readiness(readiness.intended_edits, current_slice)

    return AcquisitionResult(slice_result=current_slice, attempts=attempts, rounds_used=rounds_used)


# ---------------------------------------------------------------------------
# Slice 3 -- Bounded LLM-guided pre-patch context retrieval
#
# Runs only after Slice 2 (deterministic acquisition) still leaves at least
# one intended edit unready. The LLM may NAME repository identifiers it
# still needs (a symbol, an identifier, a file hint) -- it never provides
# repository code, a diff, or a line number, and nothing it returns is ever
# trusted directly: every request is schema-validated, attributed to a
# specific still-unready IntendedEdit, and deterministically resolved
# through the SAME helpers Slice 2 already uses
# (_resolve_symbol_details/_lookup_identifier_definition/
# build_final_target_slice) before a single character of source is
# retrieved. An unattributable, ambiguous, cross-file, or unverified
# request is rejected outright -- the model only ever improves WHICH
# target the next deterministic retrieval attempt goes after, never what
# that attempt is allowed to trust.
# ---------------------------------------------------------------------------

_GUIDED_PROMPT_PATH = Path(__file__).parent / "prompts" / "guided_context_request.md"

GUIDED_REQUEST_TYPES = (
    "symbol_definition",
    "identifier_definition",
    "enclosing_symbol",
    "identifier_usage",
)

MAX_GUIDED_ACQUISITION_ROUNDS = 2
"""At most this many guided rounds -- and therefore at most this many
guided_context_request LLM calls total (exactly one per round, never
more)."""

MAX_CONTEXT_REQUESTS_PER_ROUND = 2
"""At most this many of one round's own context_requests are even
attempted -- any beyond this are ignored, never queued for a later round."""

MAX_CONTEXT_REQUESTS_PER_EDIT = 2
"""At most this many guided requests may be attributed to the SAME
intended edit across the whole guided acquisition run (all rounds
combined) -- prevents one stubborn edit from consuming every round's
budget on repeated requests that already failed."""

MAX_NEW_SOURCE_BLOCKS_PER_REQUEST = 1
"""At most one new EDIT-TARGET block per verified request. Enforced
STRUCTURALLY, exactly like Slice 2's MAX_NEW_BLOCKS_PER_EDIT_PER_ROUND:
each request's retrieval call is built from a RemediationStrategy naming
only that ONE resolved symbol/identifier."""

MAX_GUIDED_SOURCE_CHARS_PER_ROUND = 5_000
"""Shared character budget for one round's guided retrieval, across every
request that round actually attempts -- always further clamped by
whatever remains of FINAL_TARGET_SLICE_MAX_CHARS overall (the SAME hard
total Slice 1/2 already enforce, never a separate additional allowance)."""

GUIDED_REQUEST_FAILURE_REASONS = (
    "unsupported_request_type",
    "missing_required_field",
    "unsafe_file_path",
    "unverified_file_hint",
    "ambiguous_symbol",
    "ambiguous_identifier",
    "cross_file_mismatch",
    "unresolved_symbol",
    "unresolved_identifier",
    "unrelated_to_unready_edit",
    "context_request_limit_reached",
    "target_budget_exhausted",
    "missing_target_source",
    "duplicate_request",
)
""""duplicate_request" (added alongside the loop/duplicate-request guard in
run_guided_acquisition): a request whose (request_type, symbol-or-
identifier, attributed edit) exactly repeats an earlier request already
attempted for that same edit. Recognizing this is pure bookkeeping over
already-attempted tuples -- _resolve_guided_symbol/_resolve_guided_identifier
are pure functions of their own inputs, so re-running either against the
exact same inputs could only ever reproduce the exact same failure. Skipping
that redundant resolution never changes which requests succeed."""
"""The full reason vocabulary GuidedRetrievalAttempt.failure_reason draws
from -- every rejection below sets exactly one of these, never a freeform
string, so a caller can rely on the vocabulary being closed.

NOTE: "unverified_file_hint" is deliberately never produced today -- an
identifier_definition/identifier_usage request can only ever be
attributed to an unready edit via an explicit, already-truthy file_hint,
and the same is now true of a symbol_definition/enclosing_symbol request
attributed to a file-ONLY unready edit (see _attribute_guided_request),
so by the time resolution runs that file_hint has always either already
verified (continuing past "unsafe_file_path" instead) or already caused
a "continue" on that same reason. Kept in the vocabulary for schema
completeness/forward compatibility only -- same convention as Slice 1's
own "source_not_patch_ready" (see EDIT_READINESS_REASONS)."""


class GuidedContextRequest(NamedTuple):
    """One LLM-proposed context request, parsed from JSON but NOT YET
    verified or attributed -- `intended_edit` is None until
    run_guided_acquisition successfully attributes it to a specific
    still-unready edit. Only ever built from `request_type`/`file_hint`/
    `symbol`/`identifier`/`reason` -- any other key the model's response
    JSON might contain (a line number, source code, a shell command) is
    never read into this structure at all, so it is structurally
    impossible for such a field to influence anything downstream."""

    intended_edit: "IntendedEdit | None"
    request_type: "str | None"
    file_hint: "str | None"
    symbol: "str | None"
    identifier: "str | None"
    reason: "str | None"


class GuidedRetrievalAttempt(NamedTuple):
    """One deterministic verification+retrieval attempt for a single
    GuidedContextRequest. `schema_valid` is False only for a request whose
    own shape is rejected outright (unsupported request_type, or a
    required field missing for that type) -- attribution/verification
    never even run for those. `verified` is True only once the request
    was attributed to a specific unready edit AND deterministically
    resolved to a real, unambiguous repository location.
    `readiness_improved` is True only when that specific attributed edit
    became ready as a direct result of this attempt -- retrieving a
    consumer/usage or an unrelated symbol's own supporting content never
    sets this, even when source was genuinely added (see
    run_guided_acquisition's docstring)."""

    round: int
    request: GuidedContextRequest
    schema_valid: bool
    verified: bool
    failure_reason: "str | None"
    resolved_file: "str | None"
    resolved_symbol: "str | None"
    start_line: "int | None"
    end_line: "int | None"
    source_kind: "str | None"
    source_chars: int
    readiness_improved: bool


class GuidedAcquisitionResult(NamedTuple):
    """run_guided_acquisition's own output -- mirrors AcquisitionResult's
    shape (Slice 2), plus `readiness` (the recalculated
    EditReadinessResult after guided acquisition, so a caller never has
    to re-derive it from `slice_result` a second time)."""

    slice_result: FinalTargetSliceResult
    readiness: EditReadinessResult
    attempts: "list[GuidedRetrievalAttempt]"
    rounds_used: int


def _render_guided_request_context(
    strategy: RemediationStrategyResult,
    vulnerability_text: str,
    readiness: EditReadinessResult,
    slice_result: FinalTargetSliceResult,
    deterministic_attempts: "list",
) -> str:
    """Compact, summary-only prompt context -- NEVER whole files, NEVER
    the full rendered slice text (which may itself contain a full-file
    fallback). Only what's needed to name missing context: a one-line
    vulnerability summary, the already-rendered Final Strategy (reused
    verbatim, not re-rendered), the current intended edits and WHY each
    unready one is unready, which files/symbols are already covered (so
    the model does not re-request them), a compact summary of what Slice
    2 already tried, and the identifiers already visible in verified
    evidence (_extract_strategy_identifiers, reused unchanged)."""
    first_line = ""
    for line in (vulnerability_text or "").splitlines():
        line = line.strip().lstrip("#").strip()
        if line:
            first_line = line
            break

    lines: "list[str]" = ["## Vulnerability summary", "", first_line or "(no summary available)", ""]

    if strategy.rendered:
        lines += [strategy.rendered.rstrip(), ""]

    lines += ["## Current intended edits", ""]
    for e in readiness.intended_edits:
        lines.append(f"- {e.file or '(unknown file)'}:{e.symbol or '(file-level edit)'}")

    lines += ["", "## Unready edits and their evidence-supported reason", ""]
    for u in readiness.unready_edits:
        lines.append(f"- {u.edit.file or '(unknown file)'}:{u.edit.symbol or '(file-level edit)'} -- {u.reason}")

    lines += ["", "## Already-verified evidence -- do not re-request these", ""]
    lines.append("Covered files: " + (", ".join(slice_result.covered_target_files) or "(none)"))
    lines.append("Covered symbols: " + (", ".join(slice_result.covered_target_symbols) or "(none)"))

    if deterministic_attempts:
        lines += ["", "## Deterministic acquisition already attempted (Slice 2)", ""]
        for a in deterministic_attempts:
            outcome = "succeeded" if a.success else (a.failure_reason or "failed")
            lines.append(f"- {a.intended_edit.file or '?'}:{a.intended_edit.symbol or '(file-level)'} -- {outcome}")

    identifiers = _extract_strategy_identifiers(strategy)
    if identifiers:
        lines += ["", "## Identifiers already visible in verified evidence", ""]
        lines.extend(f"- {i}" for i in identifiers)

    return "\n".join(lines) + "\n"


def _parse_one_guided_request(item) -> "GuidedContextRequest | None":
    """Extract only the five allowed fields from one raw JSON item --
    anything else present (a line number, source code, a shell command)
    is never read. Returns None only when `item` isn't even a dict (no
    request to reason about at all)."""
    if not isinstance(item, dict):
        return None

    def _s(key: str) -> "str | None":
        v = item.get(key)
        return v.strip() if isinstance(v, str) and v.strip() else None

    return GuidedContextRequest(
        intended_edit=None,
        request_type=_s("request_type"),
        file_hint=_s("file_hint"),
        symbol=_s("symbol"),
        identifier=_s("identifier"),
        reason=_s("reason"),
    )


def _validate_guided_request_schema(request: GuidedContextRequest) -> "str | None":
    """Returns a GUIDED_REQUEST_FAILURE_REASONS value if `request`'s own
    shape is rejected outright, else None. Never inspects repository
    state -- purely a shape check."""
    if request.request_type not in GUIDED_REQUEST_TYPES:
        return "unsupported_request_type"
    if request.request_type in ("symbol_definition", "enclosing_symbol") and not request.symbol:
        return "missing_required_field"
    if request.request_type in ("identifier_definition", "identifier_usage") and not request.identifier:
        return "missing_required_field"
    return None


def _guided_symbol_is_evidence_supported(
    name: str,
    strategy: "RemediationStrategyResult | None",
    slice_result: "FinalTargetSliceResult | None",
    deterministic_attempts: "list",
) -> bool:
    """True only when `name` was already visible, BEFORE this guided
    request ever ran, in evidence this run already gathered -- the Final
    Strategy's own rendered text/fields, the verified repository source
    already rendered into the current slice ("existing source capsules" /
    verified repository evidence), a prior deterministic-acquisition
    attempt's own resolved symbol or edit (Slice 2 evidence), or the
    repository-looking identifiers this module's existing shape-filtered
    extraction (_extract_strategy_identifiers) already derives from those
    same artifacts. A whole-word, case-sensitive match against the raw
    text is used (not just the shape-filtered extraction) because a
    single-hump capitalized name like "Retry" never matches
    _SNAKE_RE/_CAMEL_RE, yet can still be named explicitly in prose (e.g.
    a rationale or required_edits entry) -- this is the ONLY thing that
    lets a symbol_definition/enclosing_symbol request be attributed to a
    file-ONLY unready edit; see _attribute_guided_request."""
    if not name:
        return False
    word = re.compile(rf"\b{re.escape(name)}\b")

    if strategy is not None:
        if any(word.search(tok) for tok in _extract_strategy_identifiers(strategy)):
            return True
        if strategy.rendered and word.search(strategy.rendered):
            return True
        if strategy.extended_mechanism and word.search(strategy.extended_mechanism):
            return True
        if any(word.search(item) for item in strategy.required_edits if item):
            return True
        if any(word.search(sym) for sym in strategy.target_symbols if sym):
            return True

    if slice_result is not None and slice_result.rendered and word.search(slice_result.rendered):
        return True

    for attempt in deterministic_attempts or ():
        resolved_symbol = getattr(attempt, "resolved_symbol", None)
        if resolved_symbol and word.search(resolved_symbol):
            return True
        intended = getattr(attempt, "intended_edit", None)
        symbol = getattr(intended, "symbol", None) if intended is not None else None
        if symbol and word.search(symbol):
            return True

    return False


def _attribute_guided_request(
    request: GuidedContextRequest,
    unready_edits: "list[UnreadyEdit]",
    strategy: "RemediationStrategyResult | None" = None,
    slice_result: "FinalTargetSliceResult | None" = None,
    deterministic_attempts: "list" = (),
) -> "IntendedEdit | None":
    """A request must be attributable to a specific still-unready
    IntendedEdit -- never satisfied by "some file appears somewhere",
    always by matching against the CURRENT unready set. A
    symbol_definition/enclosing_symbol request matches an edit whose own
    `symbol` equals it exactly, or whose own bare (file-hint-stripped)
    name matches when a file_hint is either absent or consistent with
    that edit's own file. An identifier_definition/identifier_usage
    request -- which never names a specific existing target_symbol --
    can ONLY be attributed via an EXPLICIT file_hint equal to an unready
    edit's own file; a request naming no file_hint is unattributable by
    construction, and is rejected rather than guessed onto the first
    unready edit.

    A symbol_definition/enclosing_symbol request naming no matching
    target_symbol is ADDITIONALLY attributable to a file-ONLY unready
    edit (edit.symbol is None) -- but only when its own file_hint is an
    EXACT match for that edit's own file (never a partial/suffix match,
    never "absent is fine" the way the symbol-having branch above
    tolerates) AND the requested symbol's name was already named by
    evidence this run gathered before this request even existed
    (_guided_symbol_is_evidence_supported). Without the file_hint being
    both present and exact, a bare name that happens to also exist in
    more than one candidate file-only edit is never guessed onto any of
    them. Without the evidence-support check, any symbol that merely
    happens to live inside the right file would qualify -- exactly the
    unbounded behavior this function must not have. This does NOT itself
    verify the file or resolve the symbol -- exactly like the
    symbol-having branch above, that still happens afterward in
    run_guided_acquisition (_verify_file / _resolve_guided_symbol), so a
    file that fails to verify, or a symbol that resolves
    ambiguously/cross-file/not at all, is rejected there with its own
    precise reason, never masked by a coarser "attributed" here."""
    for unready in unready_edits:
        edit = unready.edit
        if request.request_type in ("symbol_definition", "enclosing_symbol"):
            if not request.symbol:
                continue
            if edit.symbol is not None and edit.symbol == request.symbol:
                return edit
            if edit.symbol is not None:
                _e_hint, e_name = _split_symbol_entry(edit.symbol)
                _r_hint, r_name = _split_symbol_entry(request.symbol)
                if e_name == r_name and (not request.file_hint or edit.file in (None, request.file_hint)):
                    return edit
            elif edit.file is not None and request.file_hint and request.file_hint == edit.file:
                _s_hint, s_name = _split_symbol_entry(request.symbol)
                candidate_names = {s_name, s_name.rsplit(".", 1)[-1]}
                if "." in s_name:
                    candidate_names.add(s_name.rsplit(".", 1)[0])
                if any(
                    _guided_symbol_is_evidence_supported(c, strategy, slice_result, deterministic_attempts)
                    for c in candidate_names
                ):
                    return edit
        else:
            if request.file_hint and edit.file == request.file_hint:
                return edit
    return None


def _resolve_guided_symbol(
    symbol: str, verified_file: "str | None", repo_root, context,
) -> "tuple[_SymbolMatch | None, str | None]":
    """Resolve a guided request's `symbol` field, explicitly REJECTING an
    ambiguous bare-name match rather than silently taking
    _resolve_symbol_details' own first-match behavior (that function
    reuses it for the actual resolution once uniqueness is confirmed, so
    there is still only one resolution mechanism -- this only adds the
    enumeration step _resolve_symbol_details itself doesn't perform).
    Returns (match, None) on success, or (None, reason) using
    GUIDED_REQUEST_FAILURE_REASONS.

    A `symbol` that already carries its own file component
    ("other.py:m") which CONTRADICTS a separately-given, already-verified
    `verified_file` (file_hint) is rejected immediately as
    "cross_file_mismatch" -- never silently resolved using one of the two
    disagreeing files while ignoring the other."""
    own_file_hint, name = _split_symbol_entry(symbol)
    if own_file_hint and verified_file and own_file_hint != verified_file:
        return None, "cross_file_mismatch"
    file_part = own_file_hint or verified_file
    qualified = f"{file_part}:{name}" if file_part else name
    bare_name = name.rsplit(".", 1)[-1]
    class_qualifier = name.rsplit(".", 1)[0] if "." in name else None

    index = getattr(context, "index", None)
    func_candidate_files: set = set()
    if index is not None:
        for m in index.search_by_name(bare_name, exact=True):
            candidate_file = _file_part(m.get("id", ""))
            if file_part is not None and candidate_file != file_part:
                continue
            if class_qualifier is not None and m.get("className") != class_qualifier:
                continue
            func_candidate_files.add(candidate_file)
    if len(func_candidate_files) > 1:
        return None, "ambiguous_symbol"

    if not func_candidate_files:
        constants = getattr(context, "constants", None) or {}
        files_to_check = [file_part] if file_part else list(constants.keys())
        const_candidate_files: set = set()
        for f in files_to_check:
            for qn, _record in constants.get(f, {}).items():
                if qn == name or qn.rsplit(".", 1)[-1] == bare_name:
                    const_candidate_files.add(f)
        if len(const_candidate_files) > 1:
            return None, "ambiguous_identifier"

    match = _resolve_symbol_details(qualified, Path(repo_root) if repo_root else None, context)
    if match is None:
        return None, "unresolved_symbol"
    if file_part is not None and match.file != file_part:
        return None, "cross_file_mismatch"
    return match, None


def _resolve_guided_identifier(
    identifier: str, verified_file: str, strategy_target_files: "list[str]", context,
) -> "tuple[_SymbolMatch | None, str | None]":
    """Resolve a guided identifier_definition/identifier_usage request's
    `identifier` field, restricted to the single verified file the
    request was attributed through (never a broader search). Reuses
    _find_constant_candidates_by_name + _disambiguate_constant_candidates
    (the exact same tie-break-then-reject-ambiguity mechanism Slice 2's
    one-hop step already uses) for constants, and
    RepositoryIndex.search_definitions for functions -- no new lookup
    mechanism, only restricted to one file and explicit about rejecting
    a same-file tie."""
    candidates = _find_constant_candidates_by_name(identifier, [verified_file], context)
    if candidates:
        chosen, _reason = _disambiguate_constant_candidates(
            candidates, source_file=verified_file, source_class=None,
            symbol_matches={}, strategy_target_files=strategy_target_files,
        )
        if chosen is None:
            return None, "ambiguous_identifier"
        f, qn, record = chosen
        line, end_line = record.get("line"), record.get("end_line")
        if line is None:
            return None, "unresolved_identifier"
        return _SymbolMatch(file=f, label=qn, kind="constant", line=line, end_line=end_line, func_id=None), None

    index = getattr(context, "index", None)
    if index is not None:
        hits = [m for m in index.search_definitions(identifier) if _file_part(m.get("id", "")) == verified_file]
        if len(hits) > 1:
            return None, "ambiguous_identifier"
        if len(hits) == 1:
            m = hits[0]
            line = m.get("startLine")
            if line is None:
                return None, "unresolved_identifier"
            return _SymbolMatch(
                file=verified_file, label=m.get("name") or identifier, kind="function",
                line=line, end_line=m.get("endLine"), func_id=m.get("id"),
            ), None

    return None, "unresolved_identifier"


def generate_guided_context_requests(
    strategy: RemediationStrategyResult,
    vulnerability_text: str,
    llm,
    readiness: EditReadinessResult,
    slice_result: FinalTargetSliceResult,
    deterministic_attempts: "list" = (),
) -> "list[GuidedContextRequest]":
    """One narrow LLM call (stage "guided_context_request") asking only
    which repository identifiers are still missing -- never a patch,
    never code, never a line number (see prompts/guided_context_request.md
    for the full contract). Returns schema-shape-parsed requests with
    `intended_edit=None` -- attribution and verification happen in
    run_guided_acquisition, never here. Best-effort: any call or parsing
    failure returns [] (never raises), which run_guided_acquisition
    treats identically to "the model had nothing further to ask" --
    failing closed, not retrying.
    """
    system_prompt = _GUIDED_PROMPT_PATH.read_text(encoding="utf-8")
    user_message = _render_guided_request_context(
        strategy, vulnerability_text, readiness, slice_result, list(deterministic_attempts),
    )
    try:
        raw = llm.complete(system_prompt, user_message, stage="guided_context_request")
    except ModelUnavailableError:
        # Explicit execution/configuration decision, not ordinary evidence
        # acquisition failure -- must abort, not degrade to "nothing to ask".
        raise
    except Exception:
        return []

    parsed = _parse_json_response(raw)
    if parsed is None:
        return []
    raw_requests = parsed.get("context_requests")
    if not isinstance(raw_requests, list):
        return []

    out: "list[GuidedContextRequest]" = []
    for item in raw_requests:
        request = _parse_one_guided_request(item)
        if request is not None:
            out.append(request)
    return out


def run_guided_acquisition(
    strategy: RemediationStrategyResult,
    vulnerability_text: str,
    llm,
    repo_root,
    context,
    slice_result: FinalTargetSliceResult,
    readiness: EditReadinessResult,
    deterministic_attempts: "list" = (),
    budget_controller: "ContextBudgetController | None" = None,
) -> GuidedAcquisitionResult:
    """
    Slice 3 -- Bounded LLM-guided pre-patch context retrieval.

    Runs ONLY when `readiness` still reports at least one UnreadyEdit
    (i.e. after Slice 2's deterministic acquisition already ran and
    still left something incomplete) -- a fully-ready or empty readiness
    performs zero guided work and returns `slice_result`/`readiness`
    unchanged (rounds_used=0, no attempts, no LLM call at all).

    Exactly one narrow LLM call per round (stage "guided_context_request",
    see generate_guided_context_requests), up to MAX_GUIDED_ACQUISITION_
    ROUNDS rounds. Never calls the Patch Generator, never reruns the
    Planner or Final Strategy, never calls the Challenger, and never adds
    a hidden retry beyond that one call per round.

    Every returned context_request is treated as untrusted: schema-
    validated (_validate_guided_request_schema), attributed to a specific
    CURRENTLY-unready IntendedEdit (_attribute_guided_request -- an
    unattributable request is rejected, never guessed onto the first
    unready edit), and deterministically resolved
    (_resolve_guided_symbol/_resolve_guided_identifier -- explicitly
    rejecting ambiguous or cross-file-mismatched candidates, never
    trusting the model's own claimed location). Only once resolution
    succeeds is build_final_target_slice() itself re-invoked (exactly
    Slice 2's own retrieval mechanism, on a strategy naming only the one
    resolved symbol/identifier) to actually retrieve verified repository
    source -- no second source-slice implementation.

    Bounded the same way as Slice 2: at most MAX_CONTEXT_REQUESTS_PER_
    ROUND requests attempted per round, at most MAX_CONTEXT_REQUESTS_
    PER_EDIT requests attributed to the same edit across the whole run,
    each round's newly-retrieved source capped at MAX_GUIDED_SOURCE_
    CHARS_PER_ROUND (shared across that round's requests) and further
    clamped so FINAL_TARGET_SLICE_MAX_CHARS overall is never exceeded --
    the SAME hard total Slice 1/2 already enforce, never a separate
    allowance. Stops immediately once every intended edit is ready.

    Loop/duplicate-request guard: a request whose (request_type, symbol-
    or-identifier, attributed edit) tuple exactly repeats one already
    attempted (in this round or an earlier one) is never re-resolved --
    recorded with failure_reason "duplicate_request" instead. And if a
    round's own attempts collectively improved NO edit's readiness at all
    (every GuidedRetrievalAttempt in that round has readiness_improved=
    False), the NEXT round's guided_context_request LLM call is skipped
    entirely -- the loop stops there rather than spending another round
    asking the model for (at best) the same or an equally unresolvable
    target again. Both checks are purely mechanical (an exact-tuple
    membership test; an already-computed boolean), never a semantic-
    similarity judgment about whether two differently-worded requests
    "mean the same thing" -- MAX_GUIDED_ACQUISITION_ROUNDS stays the same
    hard ceiling either way, this only lets the loop exit earlier when it
    already has enough evidence to know continuing is pointless.

    check_edit_readiness (itself unmodified) is what actually decides
    whether a retrieved block satisfies its attributed edit -- a
    consumer/usage window or a different symbol's own supporting content
    is folded into the slice additively (so Patch Generation still sees
    it) but never marked as satisfying a DIFFERENT edit's readiness,
    exactly like Slice 2. If the bounds are reached with readiness still
    incomplete, the caller's existing fail-closed skip path applies
    unchanged -- this function makes no Patch Generation decision itself.

    `budget_controller=None` (the default, and every existing caller)
    preserves this exact fixed-budget, fail-closed behavior unchanged.
    When given, resolution (_resolve_guided_symbol/_resolve_guided_
    identifier) always runs BEFORE the budget is even consulted, so an
    ambiguous/cross-file/unresolved candidate is rejected on its own
    non-budget reason and never triggers an extension request -- only a
    request that has ALREADY resolved to a real, unambiguous location,
    and is blocked ONLY by the shared FINAL_TARGET_SLICE_MAX_CHARS
    total, gets one immediate, local retry against a raised ceiling if
    the controller approves an additional window (see
    ContextBudgetController / _effective_final_target_max) -- never a
    second round, never a rerun of the Planner/Final Strategy/
    guided_context_request LLM call.
    """
    if readiness.edit_source_ready or not readiness.unready_edits or repo_root is None:
        return GuidedAcquisitionResult(
            slice_result=slice_result, readiness=readiness, attempts=[], rounds_used=0,
        )

    root = Path(repo_root)
    current_slice = slice_result
    current_readiness = readiness
    attempts: "list[GuidedRetrievalAttempt]" = []
    requests_per_edit: dict = {}
    rounds_used = 0
    # Loop/duplicate-request guard: every (request_type, symbol-or-
    # identifier, attributed edit) tuple already attempted, across ALL
    # rounds so far -- an exact repeat is never re-resolved (see
    # "duplicate_request" in GUIDED_REQUEST_FAILURE_REASONS). A round that
    # achieved zero readiness improvement across every one of its own
    # attempts stops the loop before the NEXT round's LLM call -- "the
    # model asked and none of it moved anything forward" is itself a
    # deterministic, already-computed signal (readiness_improved), never a
    # semantic-similarity judgment -- so this never needs to guess whether
    # two differently-worded requests "mean the same thing".
    _attempted_signatures: set = set()
    _previous_round_improved = True

    def _record(round_num, request, schema_valid, verified, failure_reason, match=None,
                start=None, end=None, kind=None, chars=0, improved=False) -> None:
        attempts.append(GuidedRetrievalAttempt(
            round=round_num, request=request, schema_valid=schema_valid, verified=verified,
            failure_reason=failure_reason,
            resolved_file=match.file if match is not None else None,
            resolved_symbol=match.label if match is not None else None,
            start_line=start, end_line=end, source_kind=kind, source_chars=chars,
            readiness_improved=improved,
        ))

    for round_num in range(1, MAX_GUIDED_ACQUISITION_ROUNDS + 1):
        if current_readiness.edit_source_ready or not current_readiness.unready_edits:
            break
        if round_num > 1 and not _previous_round_improved:
            # The previous round's own attempts improved nothing -- another
            # LLM round trip against the same still-unready edits would, at
            # best, ask for the same (or an equally unresolvable) target
            # again. Stop here rather than spend another guided_context_
            # request call; the caller's bounded target-file fallback (if
            # any) takes over from whatever this function already returns.
            break
        rounds_used = round_num
        _this_round_improved = False

        raw_requests = generate_guided_context_requests(
            strategy, vulnerability_text, llm, current_readiness, current_slice, deterministic_attempts,
        )
        round_budget_remaining = MAX_GUIDED_SOURCE_CHARS_PER_ROUND

        for request in raw_requests[:MAX_CONTEXT_REQUESTS_PER_ROUND]:
            schema_reason = _validate_guided_request_schema(request)
            if schema_reason is not None:
                _record(round_num, request, False, False, schema_reason)
                continue

            attributed_edit = _attribute_guided_request(
                request, current_readiness.unready_edits, strategy, current_slice, deterministic_attempts,
            )
            if attributed_edit is None:
                _record(round_num, request, True, False, "unrelated_to_unready_edit")
                continue
            request = request._replace(intended_edit=attributed_edit)

            if requests_per_edit.get(attributed_edit, 0) >= MAX_CONTEXT_REQUESTS_PER_EDIT:
                _record(round_num, request, True, False, "context_request_limit_reached")
                continue
            requests_per_edit[attributed_edit] = requests_per_edit.get(attributed_edit, 0) + 1

            _signature = (
                request.request_type,
                (request.symbol or request.identifier or "").strip().lower(),
                attributed_edit,
            )
            if _signature in _attempted_signatures:
                _record(round_num, request, True, False, "duplicate_request")
                continue
            _attempted_signatures.add(_signature)

            verified_file = None
            if request.file_hint:
                verified_file = _verify_file(request.file_hint, root)
                if verified_file is None:
                    _record(round_num, request, True, False, "unsafe_file_path")
                    continue

            # Resolution ALWAYS runs before the budget is even consulted
            # below -- an ambiguous/cross-file/unresolved candidate is
            # rejected on its own non-budget reason here, and never
            # reaches (or triggers) a budget-extension request.
            if request.request_type in ("symbol_definition", "enclosing_symbol"):
                match, reason = _resolve_guided_symbol(request.symbol, verified_file, root, context)
                if match is None:
                    _record(round_num, request, True, False, reason)
                    continue
                focused = strategy._replace(
                    target_files=[match.file], target_symbols=[f"{match.file}:{match.label}"],
                )
            else:
                if verified_file is None:
                    _record(round_num, request, True, False, "unverified_file_hint")
                    continue
                match, reason = _resolve_guided_identifier(
                    request.identifier, verified_file, list(strategy.target_files), context,
                )
                if match is None:
                    _record(round_num, request, True, False, reason)
                    continue
                focused = strategy._replace(
                    target_files=[match.file], target_symbols=[], extended_mechanism=request.identifier,
                )

            _affected = [f"{attributed_edit.file or verified_file or '?'}:{attributed_edit.symbol or '(file-level)'}"]
            total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
            available = min(round_budget_remaining, total_remaining)
            if budget_controller is not None:
                budget_controller.record_used("final_target_slice", len(current_slice.rendered))
            if available <= 0:
                if budget_controller is not None and budget_controller.request_extension(
                    "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                    reason="target_budget_exhausted", affected_targets=_affected,
                ):
                    total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                    available = min(round_budget_remaining, total_remaining)
                if available <= 0:
                    _record(round_num, request, True, False, "target_budget_exhausted")
                    continue

            addition = build_final_target_slice(
                focused, repo_root, context, planner_evidence_files=(), max_chars=available,
            )
            # Transactional: _try_commit_acquisition merges `addition`
            # into a TEMPORARY working slice first -- current_slice only
            # actually advances to it (and only then does this request's
            # size count against round_budget_remaining) when that merge
            # makes attributed_edit ready. A candidate that resolves and
            # renders fine but never satisfies attributed_edit's own
            # readiness (e.g. a usage window, or a block that lands but
            # isn't the exact definition) is rolled back completely --
            # current_slice reverts to exactly what it was before this
            # request, so it never occupies budget a later, more precise
            # request in this same round or a later Slice 3 round would
            # otherwise still have available. single_readiness still
            # reflects what THIS request found (reused for the
            # diagnostic below via check_edit_readiness's own
            # classification -- never a second one), whether or not it
            # was ultimately committed.
            current_slice, single_readiness, improved = _try_commit_acquisition(
                current_slice, addition, strategy, [attributed_edit],
            )
            if improved:
                round_budget_remaining = max(0, round_budget_remaining - len(addition.rendered))
            elif (
                budget_controller is not None
                and single_readiness.unready_edits
                and single_readiness.unready_edits[0].reason == "target_budget_exhausted"
                and budget_controller.request_extension(
                    "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                    reason="target_budget_exhausted", affected_targets=_affected,
                )
            ):
                # Resolved fine but didn't fit `available` -- exactly one
                # local retry against the newly-raised shared ceiling.
                total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                available = min(round_budget_remaining, total_remaining)
                addition = build_final_target_slice(
                    focused, repo_root, context, planner_evidence_files=(), max_chars=available,
                )
                current_slice, single_readiness, improved = _try_commit_acquisition(
                    current_slice, addition, strategy, [attributed_edit],
                )
                if improved:
                    round_budget_remaining = max(0, round_budget_remaining - len(addition.rendered))
            start, end = (None, None)
            kind = None
            if addition.rendered:
                start, end = _sniff_rendered_lines(addition.rendered)
                kind = _sniff_rendered_kind(addition.rendered)
            _record(
                round_num, request, True, True,
                None if improved else (single_readiness.unready_edits[0].reason if single_readiness.unready_edits else None),
                match=match, start=start, end=end, kind=kind, chars=len(addition.rendered), improved=improved,
            )
            _this_round_improved = _this_round_improved or improved

        current_readiness = check_edit_readiness(readiness.intended_edits, current_slice)
        _previous_round_improved = _this_round_improved

    return GuidedAcquisitionResult(
        slice_result=current_slice, readiness=current_readiness, attempts=attempts, rounds_used=rounds_used,
    )


# ---------------------------------------------------------------------------
# Slice 4 -- Post-Patch Target Conformance and Recovery
#
# Slices 1-3 validate and acquire source for the intended edits known
# BEFORE Patch Generation runs. Nothing before this point can catch a
# generated patch that edits a DIFFERENT repository target than the one
# Edit Readiness actually approved -- the Patch Generator is free-text
# generation over a large context, not a constrained tool call, and can
# still write a diff against a file/symbol it merely recalls rather than
# one it was given verified source for.
#
# This section adds one deterministic, bounded post-patch gate:
# check_patch_target_conformance() compares the ACTUAL edited targets of
# the generated diff (via the existing diff_parsing.parse_diff and the
# relocation records repair_hunk_headers() already computes as a side
# effect of its own repair pass -- no second diff parser, no second
# relocation mechanism) against the pre-patch ready IntendedEdits and
# verified source. recover_post_patch_source() then attempts, once and
# boundedly, to retrieve verified source for whatever is uncovered --
# reusing build_final_target_slice()/_merge_slice_results() exactly like
# Slices 2/3 do. The actual regeneration LLM call (generate_patch) is
# orchestrated by pipeline.py itself (matching where the existing
# applicability-aware retry call already lives), never here -- this
# module stays a deterministic mechanism library, same as every earlier
# slice.
# ---------------------------------------------------------------------------

MAX_POST_PATCH_RECOVERY_ROUNDS = 1
"""At most one post-patch recovery round -- if the regenerated patch
still isn't conformant, this fails closed rather than looping."""

MAX_RECOVERY_TARGETS = 3
"""At most this many distinct uncovered/unexpected/no_match files are
ever attempted for recovery in one round -- more than this fails closed
immediately (too many unexpected targets to safely recover from)."""

MAX_RECOVERY_SOURCE_BLOCKS_PER_TARGET = 1
"""At most one new EDIT-TARGET block retrieved per recovery target.
Enforced STRUCTURALLY, exactly like Slice 2/3's own per-target bounds:
each target's retrieval call is built from a RemediationStrategy naming
only that one file."""

MAX_POST_PATCH_SOURCE_CHARS = 6_000
"""Shared character budget for the whole recovery round, across every
target it attempts -- always further clamped by whatever remains of
FINAL_TARGET_SLICE_MAX_CHARS overall (the SAME hard total Slices 1-3
already enforce, never a separate additional allowance)."""

MAX_ADDITIONAL_PATCH_GENERATOR_CALLS = 1
"""Slice 4 itself calls generate_patch() at most this many times (the
one bounded regeneration attempt) -- enforced by construction (the
regeneration call site in pipeline.py runs at most once per pipeline
run), not by a counter, since there is only ever one call site."""

POST_PATCH_WINDOW_CONTEXT_LINES = 10
"""Lines of exact repository text padded on each side of a Slice 4
recovery target when no smaller enclosing unit (a sibling constant
group, or a small-enough function -- see _build_post_patch_window) can
be used whole instead. One symmetric constant, matching the existing
_padded_line_range/_DEFINITION_CONTEXT_LINES convention, deliberately
NOT reused from Slices 1-3: _DEFINITION_CONTEXT_LINES (3) is sized for
reasoning/evidence, matching a unified diff's own conventional context
width -- not for reconstructing a diff against a target an earlier,
untrusted regeneration attempt already got slightly wrong. Wider here
on purpose, and scoped to this module's post-patch recovery alone."""

_POST_PATCH_SMALL_ENCLOSING_UNIT_CHARS = _PER_TARGET_FULL_FUNCTION_CAP
"""Reuses the SAME "small enough to include whole rather than a padded
window" threshold Slice 1-3 already use for a compact full-function
render (category 4) -- no new, separate size policy for what counts as
"small" here."""

POST_PATCH_RECOVERY_FAILURE_REASONS = (
    "too_many_recovery_targets",
    "unsafe_file_path",
    "not_recovery_eligible",
    "target_budget_exhausted",
    "partial_recovery_evidence",
    "partial_hunk_coverage",
    "regeneration_call_failed",
    "malformed_or_empty_regenerated_patch",
    "regenerated_patch_still_uncovered",
    "regenerated_patch_introduces_unexpected_file",
)
"""The closed reason vocabulary PostPatchRecoveryResult.failure_reason
and the pipeline's own post-Slice-4 skip decision draw from."""


class PatchTargetConformanceResult(NamedTuple):
    """One edited hunk's conformance verdict. `target_coverage` answers
    "does this edit belong to an approved target at all" -- never merely
    "same repository file": `_edit_target_source_for_file` reads back
    ONLY this module's own EDIT-TARGET-role block headers ("Target
    definition"/"Full file (last resort)"), explicitly excluding
    "Discovered consumer" (supporting/consumer-role) text, so a mechanism
    consumer's own content can never satisfy conformance for a different
    edit target. `old_side_status` answers "does the old-side content
    this hunk claims to remove/match actually exist in the repository" --
    read back from HunkRelocationRecord, which repair_hunk_headers()
    already computed as a side effect of its own repair pass (no second
    relocation mechanism). `conformant` is the single, strict verdict:
    True only when both are satisfied (or, for a genuine new-file hunk,
    when the file is an approved target -- there is no old side to
    verify).

    `target_coverage`'s primary check (see check_patch_target_conformance)
    matches the hunk's old-side text verbatim against the rendered
    EDIT-TARGET capsule for its file. That capsule is deliberately narrow
    (a "Target definition" block is padded by only
    _DEFINITION_CONTEXT_LINES lines on each side -- sized for LLM
    reasoning, not for re-verifying an arbitrary hunk's own context
    width). A hunk whose own diff context happens to be wider than that
    padding can still be genuinely, uniquely verified against the real
    repository file (old_side_status == "old_side_verified") while its
    full old-side text no longer fits inside the narrower capsule
    verbatim. For that specific case ONLY, check_patch_target_conformance
    falls back to a position check: the hunk's own REMOVED lines (never
    its surrounding context -- see _removed_line_span) must fall, in the
    real repository file's own line numbers already resolved by
    HunkRelocationRecord, entirely inside one of the approved target's
    own rendered "Target definition" line ranges (see
    _edit_target_line_ranges_for_file). This never widens what counts as
    "approved" beyond a verified target's own real span -- it only stops
    a hunk's incidental context width from defeating a match that is
    otherwise squarely inside it."""

    file: str
    hunk_index: int
    target_coverage: str  # "approved_target" | "unexpected_file" | "uncovered_target"
    old_side_status: str  # "old_side_verified" | "old_side_no_match" | "old_side_ambiguous" | "not_verifiable" | "new_file"
    conformant: bool


class PatchConformanceReport(NamedTuple):
    """The full-patch conformance verdict -- one PatchTargetConformanceResult
    per hunk, plus the per-file groupings a caller needs to decide whether
    (and what) to recover. `all_conformant` is strict (every hunk
    conformant, including ambiguous old-side); recovery is triggered by
    the narrower `unexpected_files`/`uncovered_files`/`no_match_files`
    sets, NOT by `all_conformant` alone -- an ambiguous-but-otherwise-
    approved target must not, by itself, trigger recovery (see
    recover_post_patch_source's docstring)."""

    results: "list[PatchTargetConformanceResult]"
    all_conformant: bool
    edited_files: "list[str]"
    unexpected_files: "list[str]"
    uncovered_files: "list[str]"
    no_match_files: "list[str]"


class RecoveryTarget(NamedTuple):
    """One RECOVERY-ELIGIBILITY statement -- what Post-Patch Recovery is
    allowed to investigate after a conformance failure. Deliberately NOT
    consumed by check_patch_target_conformance (see that function's own
    docstring): recovery eligibility is a strictly BROADER set than
    "currently approved edit intent" (ReadyEdit) -- it also includes
    files with prior support from Target Discovery/Final Strategy that
    were never approved as a ReadyEdit at all (see build_recovery_targets)
    -- so it must never be mistaken for, or substituted into, the
    approved-target set conformance checks against. `kind`/`identity` are
    deliberately generic (never hardcoded to "file"-only): "symbol" for a
    ReadyEdit-derived target with a symbol, "file" otherwise (including
    every prior-supported-only target, which has no symbol at all); a
    future finer kind (function/constant/class/usage) is purely a change
    to build_recovery_targets, never to anything that consumes a
    RecoveryTarget."""

    file: str
    kind: str  # "file" | "symbol" (function | constant | class | usage reserved for future use)
    identity: "str | None"


def build_recovery_targets(ready_edits: "list", prior_supported_files: "frozenset | set" = frozenset()) -> "list[RecoveryTarget]":
    """Recovery's own eligibility set -- ReadyEdit files (Patch
    Generation's currently approved intent) UNION prior-supported files
    (Target Discovery/Final Strategy target_files that named a file
    before Patch Generation ran, whether or not it ended up approved --
    reuses the EXACT existing prior-support set the reconciliation guard
    already computes, see pipeline._prior_supported_target_files; no new
    prior-evidence source). A file absent from BOTH is not returned here
    at all -- recover_post_patch_source treats any failing file with no
    matching RecoveryTarget (when an eligibility list was supplied) as
    ineligible and fails it closed without attempting retrieval (see its
    own docstring).

    One RecoveryTarget per ReadyEdit first, in order, no filtering --
    mirrors check_patch_target_conformance's own `ready_files`
    construction exactly (every ready edit's file counts, regardless of
    symbol). Then one file-level RecoveryTarget(kind="file", identity=None)
    per prior-supported file not already covered by a ReadyEdit's own
    file -- prior support alone never implies a specific symbol. Pure and
    deterministic: no repository access, no LLM call."""
    targets = [
        RecoveryTarget(
            file=getattr(e, "file", None),
            kind="file" if getattr(e, "symbol", None) is None else "symbol",
            identity=getattr(e, "symbol", None),
        )
        for e in (ready_edits or [])
        if getattr(e, "file", None)
    ]
    covered_files = {t.file for t in targets}
    for f in sorted(set(prior_supported_files or ()) - covered_files):
        targets.append(RecoveryTarget(file=f, kind="file", identity=None))
    return targets


def _edit_target_source_for_file(rendered: str, file: str) -> str:
    """Concatenated CODE content of every EDIT-TARGET-role block for
    exactly `file` inside an already-rendered Final-Target Slice --
    reads back this module's own, fully-controlled block headers
    (_render_definition_block's headings -- see _EDIT_TARGET_HEADING_
    PREFIXES -- and _render_full_file_block's "Full file (last resort)")
    via _extract_fenced_code (reused, not re-implemented). Deliberately
    excludes _render_usage_window_block's "Discovered consumer" blocks --
    a consumer's own text must never satisfy conformance for a different
    edit target (see PatchTargetConformanceResult's docstring)."""
    if not rendered or not file:
        return ""
    blocks: "list[str]" = []
    for part in re.split(r"\n(?=#### )", rendered):
        if not part.startswith(_EDIT_TARGET_HEADING_PREFIXES) and not part.startswith("#### Full file (last resort):"):
            continue
        header_line = part.splitlines()[0] if part.splitlines() else ""
        m = re.search(r"`([^`]+)`", header_line)
        if not m:
            continue
        path_part = m.group(1).split(":")[0]
        if path_part != file:
            continue
        code = _extract_fenced_code(part)
        if code:
            blocks.append(code)
    return "\n".join(blocks)


def _edit_target_line_ranges_for_file(rendered: str, file: str) -> "list[tuple[int, int]]":
    """The real repository (start, end) line range of every "Target
    definition" EDIT-TARGET-role block already rendered for exactly
    `file` -- read back from the SAME block headers
    `_edit_target_source_for_file` already parses (this module's own
    _render_definition_block, which always renders a "(lines
    start-end)" annotation via _RENDERED_LINES_RE -- the identical
    regex _sniff_rendered_lines already uses, reused here rather than a
    second one). Deliberately excludes "Full file (last resort)" blocks:
    those already contain the whole file as CODE text, so the existing
    verbatim text match in check_patch_target_conformance already
    succeeds for them regardless of a hunk's context width -- no
    position fallback is needed, or computed, for that case.

    Used only for the narrow fallback described in
    PatchTargetConformanceResult's docstring: never a new resolution
    pass, never a new repository read -- purely re-parsing text this
    module itself already rendered."""
    if not rendered or not file:
        return []
    ranges: "list[tuple[int, int]]" = []
    for part in re.split(r"\n(?=#### )", rendered):
        if not part.startswith(_EDIT_TARGET_HEADING_PREFIXES):
            continue
        header_line = part.splitlines()[0] if part.splitlines() else ""
        m = re.search(r"`([^`]+)`", header_line)
        if not m or m.group(1).split(":")[0] != file:
            continue
        start, end = _sniff_rendered_lines(header_line)
        if start is not None and end is not None:
            ranges.append((start, end))
    return ranges


def _removed_line_span(relocated_start: "int | None", hunk_lines: "list[str]") -> "tuple[int, int] | None":
    """The real (1-indexed) repository file line range spanned by this
    hunk's own REMOVED ('-') lines ONLY -- context lines never count
    towards this span, so a hunk whose surrounding context is wider
    than a verified target's own rendered capsule cannot, merely by
    padding its own context, expand what counts as "inside" the
    approved target (see PatchTargetConformanceResult's docstring).

    `relocated_start` is the real file line HunkRelocationRecord already
    resolved for this hunk's first old-side (context or removed) line --
    reused verbatim, never re-derived by a second relocation pass. Every
    old-side line (context ' ' or removed '-') advances the running
    real-file line counter by exactly one, in hunk order, exactly
    mirroring how a unified diff's OLD side maps onto real file lines;
    only removed lines are recorded into the returned span. Returns None
    for a hunk with no removed line (a pure addition -- has no old-side
    position to check) or when `relocated_start` itself is unknown (no
    unique real-file match was ever found for this hunk)."""
    if relocated_start is None:
        return None
    offset = 0
    first: "int | None" = None
    last: "int | None" = None
    for line in hunk_lines:
        marker = line[:1]
        if marker not in (" ", "-"):
            continue
        if marker == "-":
            if first is None:
                first = relocated_start + offset
            last = relocated_start + offset
        offset += 1
    if first is None or last is None:
        return None
    return (first, last)


def _insertion_only_covers_target(
    relocated_start: "int | None", hunk_lines: "list[str]", target_ranges: "list[tuple[int, int]]",
) -> bool:
    """True iff every maximal '+' run in a hunk that has NO removed ('-')
    lines at all (a pure insertion) is covered by the SAME single approved
    range in `target_ranges` -- used ONLY by check_patch_target_
    conformance's own insertion-only branch (see its docstring), for a
    hunk whose old side is already independently, uniquely verified
    against the real repository file (`relocated_start` is only ever
    passed non-None for such a hunk). Caller-restricted to zero-removed-
    line hunks; this function does not re-check that itself, exactly as
    _removed_line_span does not re-check "is this hunk a removal" either.

    For each '+' run, `before`/`after` are the real-file positions of the
    nearest surrounding ' ' (context) line within the hunk (searching
    outward past any adjacent run, never assumed to be the immediate
    neighbor). Because `relocated_start` is only ever non-None for a hunk
    whose own old-side sequence was already uniquely, verbatim matched
    against the real file, consecutive old-side lines are -- by
    construction of that match, not by assumption here -- consecutive
    real file lines. A run missing one side's neighbor (it starts/ends at
    the hunk's own boundary) is judged using ONLY the side that IS real --
    never a synthesized guess about the unknown side (see `_run_covered`
    below): a run whose only real neighbor is far from every approved
    range must never be treated as "covered" merely because its unknown
    side would arithmetically land nearby. A run with NEITHER neighbor
    (the entire hunk is '+' lines with no old-side line at all) makes this
    return False -- fails closed rather than inventing a position; see
    check_patch_target_conformance's own gating, which never reaches this
    function without a verified `relocated_start` in hand anyway.

    A run is covered by one candidate range `(start, end)` when its real
    position is either strictly inside `(start, end)`, or in one of the
    two unit-width gaps immediately touching that range's own edges --
    immediately before `start`, or immediately after `end` (PIP-BOUNDARY-
    01: a helper inserted immediately adjacent to an already-approved
    function is, by construction, still an edit AT that approved
    location, not an unrelated one). No tolerance beyond that exact
    boundary is ever granted: a run whose nearest real neighbor lands one
    line further out is not covered by this range.

    EVERY run in the hunk must be covered by ONE SAME range, checked per
    range, per run -- never a combined multi-run span, exactly so that one
    run's own legitimate boundary touch can never let a second, unrelated
    run elsewhere in the same hunk ride along on it (a hazard the
    predecessor combined-span check was structurally immune to only by
    being strict everywhere, including at a target's own boundary -- see
    this module's own PIP-BOUNDARY-01 regression tests for the exact
    multi-run scenario this per-run check guards against).

    Never consults target_source or any concatenated/rendered text --
    position against `target_ranges` only, exactly preserving TARGET-01:
    a rendered-block concatenation artifact has no bearing on this
    check."""
    if relocated_start is None or not target_ranges:
        return False
    offset = 0
    positions: "list[int | None]" = []
    for line in hunk_lines:
        if line[:1] == " ":
            positions.append(relocated_start + offset)
            offset += 1
        else:
            positions.append(None)

    runs: "list[tuple[int | None, int | None]]" = []
    n = len(hunk_lines)
    i = 0
    while i < n:
        if hunk_lines[i][:1] != "+":
            i += 1
            continue
        run_start = i
        while i < n and hunk_lines[i][:1] == "+":
            i += 1
        run_end = i - 1

        before = next((positions[j] for j in range(run_start - 1, -1, -1) if positions[j] is not None), None)
        after = next((positions[j] for j in range(run_end + 1, n) if positions[j] is not None), None)
        if before is None and after is None:
            return False
        runs.append((before, after))

    if not runs:
        return False

    def _run_covered(before: "int | None", after: "int | None", start: int, end: int) -> bool:
        if before is not None:
            return start - 1 <= before <= end
        # before is None here, so the earlier "both None" check guarantees
        # after is real -- never a synthesized before is compared instead.
        return start <= after <= end + 1

    return any(
        all(_run_covered(before, after, start, end) for before, after in runs)
        for start, end in target_ranges
    )


def check_patch_target_conformance(
    patch: str,
    relocations: "list",
    ready_edits: "list",
    slice_result: "FinalTargetSliceResult | None",
) -> PatchConformanceReport:
    """Compare the ACTUAL edited targets of a generated patch against the
    pre-patch Edit Readiness Gate's own ready edits and verified source.
    This is deliberately the ONLY target model Patch Target Conformance
    ever consumes -- never RecoveryTarget/build_recovery_targets (see
    RecoveryTarget's own docstring), so "did the generated patch stay
    within the currently APPROVED edit intent" never gets silently
    widened by whatever Post-Patch Recovery is separately allowed to
    investigate.

    Reuses diff_parsing.parse_diff (the existing, generic unified-diff
    parser -- no second diff parser) for every edited file/hunk, and
    `relocations` (diff_hunk_repair.RepairResult.relocations, already
    computed by repair_hunk_headers() as a side effect of its OWN repair
    pass over this same `patch` -- no second relocation mechanism, no new
    git call, no new repository read) for old-side verification.

    A hunk is "approved_target" only when its own file is one of
    `ready_edits`' own files AND (for a non-new-file hunk) its old-side
    content is found, via the same content-matching primitive
    diff_hunk_repair.py itself uses (content_relocation.
    find_unique_occurrence), inside the EDIT-TARGET-role source already
    rendered for that file (_edit_target_source_for_file) -- never merely
    "this file happens to be a ready target" (see
    PatchTargetConformanceResult's docstring): an edit to an unrelated
    part of a ready-edit's own file, or to a mechanism consumer, is
    "uncovered_target", not "approved_target". When that verbatim-text
    match fails but the hunk's old side was independently, uniquely
    verified against the real repository file (old_side_status ==
    "old_side_verified"), one narrow fallback applies: the hunk's own
    REMOVED lines' real position (see _removed_line_span) is checked
    against the approved target's own rendered line range (see
    _edit_target_line_ranges_for_file) -- this is what keeps a hunk whose
    own diff context is simply wider than the rendered capsule's fixed
    padding from being misclassified "uncovered_target" despite editing
    exactly, and only, verified target content (see
    PatchTargetConformanceResult's docstring for why this is still
    strict: it is never satisfied by "same file", only by a position
    inside a specific approved target's own verified span).

    A hunk whose declared old_start is 0 (repair_hunk_headers' own
    new-file sentinel) is a genuine new-file creation -- there is no old
    side to verify, so it is never classified "old_side_no_match" merely
    for having none; it is "new_file", and conformant whenever its own
    file is an approved target.

    A hunk with NO removed ('-') lines at all (a pure insertion) never
    reaches the verbatim-text-anywhere-in-target_source primary check
    above: that check is blind to WHICH rendered block it matched inside
    of, so it can be satisfied by an artifact spanning the tail of one
    rendered block immediately followed by the head of an unrelated
    adjacent one (target_source is built by literally joining every
    block's own code with "\n") -- text that exists nowhere contiguously
    in the real repository file except, possibly, at some unrelated
    third location the hunk actually touches. A removed line's own real
    position is always evidence of an actual, singular change; a pure
    insertion has no such old-side content of its own, only surrounding
    context, which is exactly the kind of wide/incidental text the
    verbatim search was never meant to authorize on its own (see
    _removed_line_span's own docstring for why context, unlike removed
    content, is deliberately excluded from that fallback's position
    check). So, whenever such a hunk is already independently, uniquely
    verified against the real repository file (old_side_status ==
    "old_side_verified") and at least one approved target range exists
    for its file, target_coverage is decided ENTIRELY by position (see
    _insertion_only_covers_target): every run's real, verified insertion
    position must fall inside, or immediately adjacent to the boundary
    of, one approved target's own rendered line range, exactly the same
    range the removed-line fallback above already uses -- never a text
    search. When no target
    range exists for the file (the file's only rendered source is a
    "Full file (last resort)" block -- see _edit_target_line_ranges_
    for_file's own docstring for why that case has no ranges to check
    against), or when old_side_status isn't "old_side_verified", this
    hunk falls through to the same verbatim-text path every other hunk
    uses -- unchanged.

    Never raises: an unparseable/empty patch, or missing relocation data,
    degrades to an empty, non-conformant report rather than crashing.
    """
    try:
        changed_files, file_hunks = parse_diff(patch or "")
    except Exception:
        changed_files, file_hunks = [], {}

    ready_files = {getattr(e, "file", None) for e in (ready_edits or []) if getattr(e, "file", None)}
    rendered = getattr(slice_result, "rendered", "") or ""

    by_file_relocations: "dict[str, list]" = {}
    for r in (relocations or []):
        by_file_relocations.setdefault(getattr(r, "file", None), []).append(r)

    results: "list[PatchTargetConformanceResult]" = []
    for file in changed_files:
        hunks = file_hunks.get(file, [])
        file_relocations = by_file_relocations.get(file, [])
        target_source = _edit_target_source_for_file(rendered, file)
        target_ranges = _edit_target_line_ranges_for_file(rendered, file)

        for idx, hunk in enumerate(hunks):
            record = file_relocations[idx] if idx < len(file_relocations) else None

            if record is None:
                old_side_status = "not_verifiable"
            elif getattr(record, "original_hunk_start", None) == 0:
                old_side_status = "new_file"
            elif record.relocation_reason == "unique_match":
                old_side_status = "old_side_verified"
            elif record.relocation_reason == "ambiguous":
                old_side_status = "old_side_ambiguous"
            elif record.relocation_reason == "no_match":
                old_side_status = "old_side_no_match"
            else:
                old_side_status = "not_verifiable"

            if file not in ready_files:
                target_coverage = "unexpected_file"
            elif old_side_status == "new_file":
                # No old side to cross-check -- a new symbol/file inside
                # an already-approved file scope is covered by construction.
                target_coverage = "approved_target"
            else:
                has_removed_line = any(line[:1] == "-" for line in hunk.lines)
                if has_removed_line or old_side_status != "old_side_verified" or not target_ranges:
                    anchors = old_side_anchors(hunk.lines)
                    matched = bool(anchors) and bool(target_source) and (
                        find_unique_occurrence(anchors, target_source.splitlines()) is not None
                    )
                    if not matched and old_side_status == "old_side_verified" and target_ranges:
                        # Fallback ONLY for a hunk already independently,
                        # uniquely verified against the real repository file
                        # (see this function's own docstring): its own
                        # verbatim old-side text simply didn't fit inside the
                        # rendered capsule's fixed padding, but its REMOVED
                        # lines' real position still lands entirely inside
                        # one of the approved target's own rendered ranges.
                        removed_span = _removed_line_span(
                            getattr(record, "relocated_hunk_start", None), hunk.lines,
                        )
                        if removed_span is not None:
                            matched = any(
                                start <= removed_span[0] and removed_span[1] <= end
                                for (start, end) in target_ranges
                            )
                else:
                    # Pure-insertion hunk, already old_side_verified, with
                    # at least one approved target range for this file:
                    # position -- never the flat text search -- decides
                    # coverage (see this function's own docstring and
                    # _insertion_only_covers_target).
                    matched = _insertion_only_covers_target(
                        getattr(record, "relocated_hunk_start", None), hunk.lines, target_ranges,
                    )
                target_coverage = "approved_target" if matched else "uncovered_target"

            conformant = (
                target_coverage == "approved_target"
                and old_side_status in ("old_side_verified", "new_file")
            )
            results.append(PatchTargetConformanceResult(
                file=file, hunk_index=idx, target_coverage=target_coverage,
                old_side_status=old_side_status, conformant=conformant,
            ))

    all_conformant = bool(results) and all(r.conformant for r in results)
    return PatchConformanceReport(
        results=results,
        all_conformant=all_conformant,
        edited_files=list(changed_files),
        unexpected_files=sorted({r.file for r in results if r.target_coverage == "unexpected_file"}),
        uncovered_files=sorted({r.file for r in results if r.target_coverage == "uncovered_target"}),
        no_match_files=sorted({r.file for r in results if r.old_side_status == "old_side_no_match"}),
    )


def post_patch_recovery_trigger_reasons(conformance: PatchConformanceReport) -> "list[str]":
    """The narrow set of conditions that trigger recovery -- deliberately
    NOT the same as `not conformance.all_conformant`. An ambiguous-but-
    otherwise-approved target alone must never trigger recovery (only
    when the SAME file is also uncovered/unexpected/no_match does it
    already appear in one of these three sets)."""
    reasons: "list[str]" = []
    if conformance.unexpected_files:
        reasons.append("unexpected_file")
    if conformance.uncovered_files:
        reasons.append("uncovered_target")
    if conformance.no_match_files:
        reasons.append("old_side_no_match")
    return reasons


def _recovery_reason_for_file(file: str, conformance: PatchConformanceReport) -> str:
    if file in conformance.unexpected_files:
        return "unexpected_file"
    if file in conformance.no_match_files:
        return "old_side_no_match"
    if file in conformance.uncovered_files:
        return "uncovered_target"
    return "unknown"


def _recovery_triggering_hunk_indices(file: str, conformance: PatchConformanceReport) -> "set[int]":
    """Exactly the hunk_index values, for `file`, that conformance itself
    flagged as recovery-triggering -- the same per-hunk condition
    _covered_hunks_for already gates on (target_coverage in
    ("unexpected_file", "uncovered_target") or old_side_status ==
    "old_side_no_match"), reused rather than redefined. An already-
    approved_target/conformant hunk in the same file is never included:
    it must not be eligible for Source Priority 1's old-side-anchor scan
    merely because it shares a file with a genuinely failing hunk (see
    _locate_old_side_in_file's own docstring -- "this file's own FAILING
    hunks' own OLD-side content", not "any hunk touching this file")."""
    return {
        r.hunk_index for r in conformance.results
        if r.file == file
        and (r.target_coverage in ("unexpected_file", "uncovered_target") or r.old_side_status == "old_side_no_match")
    }


# ---------------------------------------------------------------------------
# Slice 4 patch-ready recovery window -- keeps two concepts that the rest of
# this module deliberately conflates for Slices 1-3 (where it is harmless)
# separate here: a REASONING-ready definition (any exact block that proves a
# symbol exists, however narrowly padded) vs. a PATCH-ready edit window (one
# contiguous, sufficiently-padded, verified repository block that a unified
# diff can actually be constructed against). build_final_target_slice's own
# category 2 (identifier definitions) pads each resolved identifier
# independently by _DEFINITION_CONTEXT_LINES (3) -- adequate evidence, but
# when a hunk's real target sits at the edge of, or between, two such
# independently-padded blocks for DIFFERENT nearby identifiers, Patch
# Generation sees two disjoint fragments rather than one buildable window,
# and the regenerated diff's own context lines fail relocation
# (content_relocation.find_unique_occurrence) against the real file. The
# functions below build ONE such window directly -- reusing the same
# primitives (_lookup_identifier_definition, _read_symbol_source,
# _padded_line_range, _rendered_end_line, RepositoryIndex.read_file_section,
# content_relocation.old_side_anchors/find_unique_occurrence) build_final_
# target_slice and repair_hunk_headers already use, never a new repository
# reader or a second relocation mechanism -- and are used ONLY by
# recover_post_patch_source below; Slices 1-3 never call them and are
# therefore unaffected.
# ---------------------------------------------------------------------------

class _PostPatchWindow(NamedTuple):
    """One resolved, contiguous, patch-ready recovery window --
    everything recover_post_patch_source needs to render it
    (_render_definition_block, reused unchanged) and trace it."""

    file: str
    label: str
    target_start: "int | None"  # the resolved target's OWN (unpadded) span --
    target_end: "int | None"    # None for an old-side-anchor match (no symbol resolved)
    start: int                  # the FINAL window actually rendered
    end: int
    source: str
    enclosing_symbol: "str | None"
    source_kind: str  # "patch_ready_window" | "enclosing_symbol" | "small_full_file"


def _constant_group_bounds(
    file: str, class_name: "str | None", context,
) -> "tuple[int, int, int] | None":
    """The contiguous line span covering EVERY constant
    InvestigationContext.constants already records for `file` under the
    SAME enclosing `class_name` (None for module-level) -- the existing
    "class attribute section"/"constant group" metadata this table
    already carries (the same `class_name` field _disambiguate_constant_
    candidates already reads), never a new AST-derived symbol boundary.
    Returns (start, end, member_count), or None when `file` has no
    constants recorded at all. A member_count of 1 means the target has
    no siblings at this scope -- the caller then treats it as having no
    real "enclosing group" and falls back to a plain padded window
    rather than treating one isolated constant as its own enclosing
    unit."""
    constants = getattr(context, "constants", None) or {}
    records = constants.get(file) or {}
    spans = [
        (record.get("line"), record.get("end_line"))
        for record in records.values()
        if record.get("class_name") == class_name
        and record.get("line") is not None and record.get("end_line") is not None
    ]
    if not spans:
        return None
    return min(s for s, _ in spans), max(e for _, e in spans), len(spans)


def _locate_old_side_in_file(
    file_hunks_for_file: "list", verified_file: str, context,
) -> "tuple[int, int] | None":
    """Source priority 1: does one of this file's failing hunks' own
    OLD-side content (context + removed lines) exist, verbatim and
    UNIQUELY, anywhere in the real (current) repository file right now?
    Reuses content_relocation.old_side_anchors/find_unique_occurrence --
    the SAME primitives repair_hunk_headers/check_patch_target_
    conformance already use for old-side verification, never a second
    matching implementation -- searched against the WHOLE file via the
    existing RepositoryIndex.read_file_section reader (never a new
    reader; a huge end_line is safe, see _padded_line_range's own
    docstring: read_file_section already clamps to EOF). Returns a
    1-indexed (start, end) line span, or None when no hunk's old side
    matches uniquely (expected, by construction, for a hunk whose old
    side was already classified "old_side_no_match" upstream -- the
    exact reason it's known NOT to match)."""
    index = getattr(context, "index", None)
    if index is None:
        return None
    whole_file = index.read_file_section(verified_file, 1, 10**9)
    if not whole_file:
        return None
    file_lines = whole_file.splitlines()
    for hunk in file_hunks_for_file:
        anchors = old_side_anchors(hunk.lines)
        if not anchors:
            continue
        pos = find_unique_occurrence(anchors, file_lines)
        if pos is not None:
            return pos + 1, pos + len(anchors)
    return None


def _build_post_patch_window(
    verified_file: str,
    identifiers: "list[str]",
    file_hunks_for_file: "list",
    context,
    try_old_side_anchor: bool,
    boundary_identifier: "str | None" = None,
) -> "_PostPatchWindow | None":
    """Resolve ONE contiguous, patch-ready recovery window for
    `verified_file`, per the Source priority Slice 4 recovery follows:

    1. (only when `try_old_side_anchor`) the failing hunk's own old-side
       content, located verbatim in the real file (_locate_old_side_in_
       file) -- deliberately gated to the "uncovered_target" trigger
       reason by the caller: for an "unexpected_file"/"old_side_no_match"
       target, a trivially-matching old side (e.g. a one-line file whose
       entire content happens to equal the hunk's own old side) proves
       nothing about whether the edit belongs there at all, and
       "old_side_no_match" makes this priority a guaranteed no-op by
       construction anyway (see _locate_old_side_in_file).
    2/3. the first of `identifiers` (already ordered changed-line-first
       by the caller) that resolves via _lookup_identifier_definition,
       reused unchanged -- never all of them independently, which is
       what previously produced multiple, independently-padded, possibly
       disjoint blocks for one target file.
    4. for that resolved identifier: an enclosing unit small enough to
       include WHOLE (a sibling constant group sharing the same
       class_name -- _constant_group_bounds -- or, for a function, its
       own full body via _read_symbol_source/get_function_code) is
       preferred over a padded window; a window is still built when the
       enclosing unit is too large, clamped to never read past that
       unit's own bounds.
    5. (the caller's own fallback, not built here) a small, bounded
       full-file read via the existing build_final_target_slice.

    `boundary_identifier` (default None, preserving this function's exact
    prior behavior for every existing caller) names the ONE identifier --
    the current recovery attempt's own already-approved RecoveryTarget
    identity, never an ordinary diff-derived guess (see
    recover_post_patch_source) -- that, if and only if resolution reaches
    it AND it resolves to a small function/method/class-kind match whose
    tier 4 would otherwise return the exact whole body with zero
    surrounding lines, instead reads a symmetric POST_PATCH_WINDOW_
    CONTEXT_LINES-padded window around that same real span (same
    `_padded_line_range`-shaped arithmetic and `read_file_section`
    primitive every other padded branch here already uses). This never
    touches resolution for any OTHER identifier, and never widens what
    tier 4 returns when `boundary_identifier` is None or isn't reached --
    see _wrap_post_patch_window for why this widened SOURCE never widens
    approved TARGET AUTHORITY: the resulting window's own distinct
    source_kind renders under a heading deliberately excluded from
    check_patch_target_conformance's EDIT-TARGET-role parsing, so it can
    never itself enlarge the approved boundary a hunk's position is
    checked against -- it only gives Patch Generation real repository
    text to construct a verifiable hunk with.

    Returns None when nothing above resolves -- the caller then falls
    back to tier 5."""
    index = getattr(context, "index", None)
    if index is None:
        return None

    if try_old_side_anchor:
        old_side_span = _locate_old_side_in_file(file_hunks_for_file, verified_file, context)
        if old_side_span is not None:
            start, end = _padded_line_range(
                old_side_span[0], old_side_span[1], POST_PATCH_WINDOW_CONTEXT_LINES,
            )
            source = index.read_file_section(verified_file, start, end)
            if source:
                label = identifiers[0] if identifiers else verified_file
                return _PostPatchWindow(
                    file=verified_file, label=label,
                    target_start=old_side_span[0], target_end=old_side_span[1],
                    start=start, end=_rendered_end_line(start, source), source=source,
                    enclosing_symbol=None, source_kind="patch_ready_window",
                )

    for identifier in identifiers:
        match = _lookup_identifier_definition(identifier, [verified_file], context)
        if match is None:
            continue

        if match.kind == "function" and match.func_id:
            full_source = index.get_function_code(match.func_id)
            if full_source and len(full_source) <= _POST_PATCH_SMALL_ENCLOSING_UNIT_CHARS:
                if identifier == boundary_identifier and boundary_identifier is not None and match.end_line is not None:
                    # This IS the current recovery attempt's own approved
                    # target identity (never an ordinary identifier -- see
                    # this function's own docstring): its exact body is
                    # already known/approved evidence, so returning it
                    # unpadded here adds nothing toward proving a
                    # boundary-adjacent insertion's real position (see
                    # _insertion_only_covers_target's own boundary-
                    # adjacency rule). Read a symmetric padded window
                    # around the SAME real span instead; falls through to
                    # the unpadded whole-body return below if that read
                    # is ever unavailable, never failing this identifier
                    # outright.
                    boundary_start = max(1, match.line - POST_PATCH_WINDOW_CONTEXT_LINES)
                    boundary_end = match.end_line + POST_PATCH_WINDOW_CONTEXT_LINES
                    boundary_source = index.read_file_section(verified_file, boundary_start, boundary_end)
                    if boundary_source:
                        return _PostPatchWindow(
                            file=verified_file, label=match.label,
                            target_start=match.line, target_end=match.end_line,
                            start=boundary_start, end=_rendered_end_line(boundary_start, boundary_source),
                            source=boundary_source,
                            enclosing_symbol=match.label, source_kind="boundary_context",
                        )
                return _PostPatchWindow(
                    file=verified_file, label=match.label,
                    target_start=match.line, target_end=match.end_line,
                    start=match.line, end=match.end_line, source=full_source,
                    enclosing_symbol=match.label, source_kind="enclosing_symbol",
                )
            # Large enclosing function -- a focused, bounded window
            # anchored at its own definition line, clamped to never
            # read past the function's own end (its enclosing bound).
            start = max(1, match.line - POST_PATCH_WINDOW_CONTEXT_LINES)
            end = min(match.end_line, match.line + POST_PATCH_WINDOW_CONTEXT_LINES) if match.end_line else start
            source = index.read_file_section(verified_file, start, end)
            if source:
                return _PostPatchWindow(
                    file=verified_file, label=match.label,
                    target_start=match.line, target_end=match.end_line,
                    start=start, end=_rendered_end_line(start, source), source=source,
                    enclosing_symbol=match.label, source_kind="patch_ready_window",
                )
            continue

        if match.kind == "constant" and match.end_line is not None:
            constants = getattr(context, "constants", None) or {}
            record = (constants.get(match.file) or {}).get(match.label)
            group_class = record.get("class_name") if record is not None else None
            group = _constant_group_bounds(match.file, group_class, context)

            if group is not None and group[2] > 1:
                g_start, g_end, _count = group
                whole_group_source = index.read_file_section(match.file, g_start, g_end)
                if whole_group_source and len(whole_group_source) <= _POST_PATCH_SMALL_ENCLOSING_UNIT_CHARS:
                    return _PostPatchWindow(
                        file=verified_file, label=match.label,
                        target_start=match.line, target_end=match.end_line,
                        start=g_start, end=_rendered_end_line(g_start, whole_group_source),
                        source=whole_group_source,
                        enclosing_symbol=group_class or verified_file, source_kind="enclosing_symbol",
                    )
                if whole_group_source:
                    # Group too large to include whole -- clamp the
                    # padded window to its own bounds rather than
                    # spilling into a different enclosing unit.
                    start = max(g_start, match.line - POST_PATCH_WINDOW_CONTEXT_LINES)
                    end = min(g_end, match.end_line + POST_PATCH_WINDOW_CONTEXT_LINES)
                    clamped_source = index.read_file_section(match.file, start, end)
                    if clamped_source:
                        return _PostPatchWindow(
                            file=verified_file, label=match.label,
                            target_start=match.line, target_end=match.end_line,
                            start=start, end=_rendered_end_line(start, clamped_source),
                            source=clamped_source,
                            enclosing_symbol=group_class or verified_file, source_kind="patch_ready_window",
                        )

            # No usable enclosing group -- bounded fallback (Required
            # behavior #5: "Use a bounded fallback when no enclosing
            # symbol is known").
            start, end = _padded_line_range(match.line, match.end_line, POST_PATCH_WINDOW_CONTEXT_LINES)
            source = index.read_file_section(match.file, start, end)
            if source:
                return _PostPatchWindow(
                    file=verified_file, label=match.label,
                    target_start=match.line, target_end=match.end_line,
                    start=start, end=_rendered_end_line(start, source), source=source,
                    enclosing_symbol=None, source_kind="patch_ready_window",
                )

    return None


def _window_confirms_target(
    window: _PostPatchWindow, identifiers: "list[str]", file_hunks_for_file: "list",
) -> bool:
    """Observational trace check only -- never a gate on whether
    `window` was already built. True when the window's own source text
    demonstrably contains what recovery was actually trying to recover:
    either the resolved identifier's own bare name, or (for an old-side-
    anchor match, which resolves no symbol) the hunk's own old-side
    anchors, verbatim and contiguous, inside `window.source` itself.
    Reuses old_side_anchors/find_unique_occurrence -- no second matching
    mechanism."""
    source_lines = window.source.splitlines()
    for hunk in file_hunks_for_file:
        anchors = old_side_anchors(hunk.lines)
        if anchors and find_unique_occurrence(anchors, source_lines) is not None:
            return True
    bare = window.label.rsplit(".", 1)[-1] if window.label else ""
    if bare and bare in window.source:
        return True
    return any(identifier and identifier in window.source for identifier in identifiers)


def _wrap_post_patch_window(window: _PostPatchWindow, verified_file: str) -> FinalTargetSliceResult:
    """Wrap one patch-ready recovery window into a minimal, single-block
    FinalTargetSliceResult -- the SAME shape build_final_target_slice
    itself returns, so _merge_slice_results (unmodified) folds it into
    the running slice exactly like any other addition, and
    recover_post_patch_source's own existing success check (`verified_
    file in current_slice.identifier_definition_covered`) recognizes it
    with no change to that check itself. Rendered via
    _render_definition_block -- the SAME header shape check_patch_
    target_conformance's own _edit_target_source_for_file already reads
    back as EDIT-TARGET-role content, so a subsequent regeneration
    re-check recognizes this window's code exactly like any other target
    definition, without needing a new header form.

    EXCEPT for `source_kind == "boundary_context"` (the ONE window shape
    _build_post_patch_window's own `boundary_identifier` branch can
    produce -- see its docstring): that window's own start/end
    deliberately span WIDER than the target's own real (target_start,
    target_end) span, so rendering it under "Target definition" would
    hand check_patch_target_conformance's _edit_target_line_ranges_for_
    file a wider approved range than the target genuinely has -- silently
    widening insertion-only boundary authority (see
    _insertion_only_covers_target), never this function's job to do.
    Rendered under a heading deliberately absent from
    _EDIT_TARGET_HEADING_PREFIXES instead (the SAME mechanism Category 2
    already uses to render real evidence without EDIT-TARGET-role
    status): Patch Generation still sees this real repository text when
    constructing its regenerated hunk, but it never itself enlarges what
    a hunk's position is authorized against -- only the target's own
    existing, unwidened Target definition block (already rendered before
    Patch Generation ever ran, whenever a RecoveryTarget carries a
    resolved symbol identity at all) does that, exactly as before this
    function existed."""
    heading_label = "Boundary context" if window.source_kind == "boundary_context" else "Target definition"
    text = _render_definition_block(
        window.file, window.label, window.start, window.end, window.source, heading_label=heading_label,
    )
    return FinalTargetSliceResult(
        rendered=text, covered_target_files=[verified_file], covered_target_symbols=[],
        uncovered_target_files=[], uncovered_target_symbols=[],
        coverage_complete=False, has_any_coverage=True, warning_text="",
        resolved_target_symbols=[], full_file_fallback_covered=[],
        edit_target_budget_exhausted=False, resolved_symbol_files={},
        identifier_definition_covered=[verified_file],
    )


def _post_patch_fallback_source_kind(sniffed_kind: "str | None") -> "str | None":
    """Maps _sniff_rendered_kind's shared vocabulary (also used by
    Slices 2/3, never changed here) onto Slice 4's own, more precise
    trace vocabulary for its tier-5 full-file fallback only --
    "full_file_fallback" becomes "small_full_file" (Required behavior:
    "Use a source_kind that accurately reflects the final source").
    "exact_definition" is defensively relabelled too, though it should
    be unreachable here: this fallback's own `required_edits` names
    only identifiers _build_post_patch_window already tried and could
    not resolve, so its category 2 (which uses the identical lookup)
    cannot resolve them either -- the fallback's only reachable success
    mode is category 5 (full-file)."""
    if sniffed_kind == "full_file_fallback":
        return "small_full_file"
    if sniffed_kind == "exact_definition":
        return "patch_ready_window"
    return sniffed_kind


class RecoveryTargetAttempt(NamedTuple):
    """One deterministic recovery attempt for a single actual patch
    target (a file the generated diff edited but Edit Readiness never
    approved, or approved-file content that doesn't match verified
    source). `identifiers_considered` are extracted from the hunk's OWN
    old/new text (_extract_identifiers_from_text, reused), changed-line
    (+/-) identifiers ordered ahead of context-line (' ') ones -- the
    generated patch is used only as a retrieval HINT here, never as a
    source of trusted line numbers or content.

    `resolved_target`/`target_start_line`/`target_end_line` describe the
    underlying identifier/symbol/old-side match ITSELF (its own natural,
    unpadded span) -- `start_line`/`end_line` describe the FINAL window
    actually rendered, which may be wider (a padded window, a sibling
    constant group, an enclosing function) than the target's own span.
    `patch_ready` is True only when that final window is a single
    contiguous, verbatim, bounded block sufficient to build a unified
    diff against -- see _build_post_patch_window's module comment for
    exactly what that excludes. `identifier_verified_in_window` is a
    purely observational trace flag (_window_confirms_target) -- never a
    gate on `success` itself.

    `target_kind`/`target_identity` mirror the RecoveryTarget this
    attempt was built for (see RecoveryTarget) -- purely descriptive,
    never a gate. `covered_hunk_indices` is the subset of this target's
    FILE's own failing hunk_index values (per PatchConformanceReport.results
    -- target_coverage in ("unexpected_file", "uncovered_target") or
    old_side_status == "old_side_no_match") whose own old-side text was
    found verbatim inside THIS attempt's rendered source, via the same
    content-matching primitive check_patch_target_conformance itself uses
    (old_side_anchors + find_unique_occurrence) -- never a new matching
    mechanism. This is what lets `ready_for_regeneration` require every
    failing hunk to be covered, not merely one successful attempt per
    file (see recover_post_patch_source's docstring)."""

    file: str
    trigger_reason: str
    identifiers_considered: "list[str]"
    resolved_file: "str | None"
    resolved_target: "str | None"
    target_start_line: "int | None"
    target_end_line: "int | None"
    start_line: "int | None"
    end_line: "int | None"
    enclosing_symbol: "str | None"
    source_kind: "str | None"
    source_chars: int
    patch_ready: bool
    identifier_verified_in_window: bool
    success: bool
    failure_reason: "str | None"
    target_kind: str
    target_identity: "str | None"
    covered_hunk_indices: "list[int]"


class PostPatchRecoveryResult(NamedTuple):
    """recover_post_patch_source()'s own output -- retrieval only, no LLM
    call. `slice_result` is the ORIGINAL slice extended additively with
    whatever this round retrieved (never evicting anything already
    present, exactly like Slices 2/3's own merge). `recovery_targets` is
    the subset of the PRE-EXISTING RecoveryTarget list (see RecoveryTarget)
    this round actually attempted -- never rebuilt from the patch.
    `ready_for_regeneration` is True only when every recovery-triggering
    hunk (per PatchConformanceReport.results, not merely one attempt per
    file) obtained genuine, verified, patch-ready source -- pipeline.py
    must not attempt regeneration otherwise (see recover_post_patch_source's
    docstring)."""

    triggered: bool
    trigger_reasons: "list[str]"
    recovery_targets: "list[RecoveryTarget]"
    attempts: "list[RecoveryTargetAttempt]"
    slice_result: "FinalTargetSliceResult | None"
    ready_for_regeneration: bool
    failure_reason: "str | None"


_EMPTY_RECOVERY_RESULT_NOT_TRIGGERED = PostPatchRecoveryResult(
    triggered=False, trigger_reasons=[], recovery_targets=[], attempts=[],
    slice_result=None, ready_for_regeneration=False, failure_reason=None,
)


def recover_post_patch_source(
    strategy: RemediationStrategyResult,
    repo_root,
    context,
    slice_result: "FinalTargetSliceResult | None",
    conformance: PatchConformanceReport,
    patch: str,
    recovery_targets: "list[RecoveryTarget] | None" = None,
    budget_controller: "ContextBudgetController | None" = None,
) -> PostPatchRecoveryResult:
    """
    Slice 4's deterministic, bounded post-patch source recovery. No LLM
    call anywhere in this function -- the actual regeneration call is
    orchestrated by pipeline.py itself, using this function's output only
    to decide whether attempting it is even warranted.

    Triggered only by post_patch_recovery_trigger_reasons(conformance)
    being non-empty (an unexpected file, an uncovered target, or an
    old-side no_match) -- never for unique_match, never for a patch whose
    targets are already covered, and never for ambiguous-old-side alone.
    Returns a not-triggered result (0 targets, `ready_for_regeneration`
    False, no failure) when there is nothing to recover, or when
    `repo_root`/`slice_result` is unavailable.

    `recovery_targets` is recovery's own ELIGIBILITY set (see
    RecoveryTarget/build_recovery_targets) -- pre-existing, built from
    the Edit Readiness Gate's own ready edits UNION prior-supported files
    (Target Discovery/Final Strategy), before this patch was ever
    generated or inspected. This is deliberately NOT the same set
    check_patch_target_conformance uses (see that function's own
    docstring) -- eligibility is broader than "currently approved",
    which is exactly what lets a file with prior support but no ReadyEdit
    (named by Target Discovery, then dropped by Final Strategy) still be
    investigated here, while a file with NEITHER a ReadyEdit NOR any
    prior support is never attempted at all.

    `recovery_targets=None` (the default) means no eligibility list was
    modeled by this caller at all -- every failing file is attempted
    exactly as this function behaved before eligibility existed (pure
    backward compatibility for callers/tests that don't model prior
    support). `recovery_targets=[]` (an explicit, possibly-empty list --
    what pipeline.py always passes) means eligibility IS enforced: a
    failing file whose own file is not among `{t.file for t in
    recovery_targets}` fails immediately and closed as
    "not_recovery_eligible", with NO retrieval, NO `_verify_file` call,
    and NO budget spent for it -- it never reaches window-building or the
    tier-5 fallback.

    This function never derives a target's identity from the patch;
    `diff_parsing.parse_diff` is used below only to read what the ACTUAL
    patch changed (hunks, identifiers-as-hints, per-hunk coverage), never
    to discover what should be recovered. Recovery targets attempted
    this round are every file in the union of unexpected/uncovered/
    no_match files (`conformance`'s own aggregate sets); when eligibility
    is enforced, ineligible ones are still given exactly one observable,
    immediately-failed attempt (never silently dropped) so the trace
    always names every failing file. The cap (MAX_RECOVERY_TARGETS, more
    than that fails closed immediately, before attempting anything --
    "too many unexpected targets to safely recover from") counts ALL
    failing files, eligible or not -- unchanged from before eligibility
    existed. For each eligible attempted target:
    the file itself is re-verified (_verify_file) -- an unsafe/
    unverifiable path fails that target outright; candidate identifiers
    are extracted from every hunk's own old/new text in that file
    (_extract_identifiers_from_text, reused, never a line number),
    changed-line identifiers ordered ahead of context-line ones so the
    identifier actually being edited is tried first.

    A SINGLE contiguous, patch-ready window is then built for the file
    (_build_post_patch_window) -- source priority: (1, only for
    "uncovered_target") the hunk's own old-side content located verbatim
    in the real file; (2/3/4) the first candidate identifier that
    resolves to a real definition, with its own small enclosing unit (a
    sibling constant group, or a small function) preferred whole over a
    padded window. This deliberately REPLACES the previous approach of
    feeding every extracted identifier into build_final_target_slice's
    own category 2 independently: that could -- and, per the real trace
    this fix addresses, did -- render several separately, narrowly
    (_DEFINITION_CONTEXT_LINES=3) padded blocks for nearby identifiers in
    one file, leaving the actual hunk's target sitting at the edge of, or
    between, two disjoint fragments rather than inside one buildable
    window, so the regenerated diff's own context lines failed
    relocation against the real file. Only when nothing resolves at all
    does this fall back to the pre-existing mechanism (build_final_
    target_slice, unmodified, tier 5: a small, bounded full-file read) --
    a target only "succeeds" via that tier when the retrieved block
    actually lands in `identifier_definition_covered`/`full_file_
    fallback_covered` for that file, exactly as before.

    A window that resolves but does not fit this target's remaining
    share of the budget fails closed as "target_budget_exhausted"
    immediately -- it is never silently replaced by a smaller, possibly
    insufficiently-padded block from the old mechanism, which would
    reintroduce exactly the under-context failure mode this function
    exists to prevent.

    `ready_for_regeneration` is True only when EVERY recovery-triggering
    hunk (per `conformance.results` -- never merely "one successful
    attempt per file") had its own old-side text verified present inside
    some attempt's rendered source -- "Do not regenerate a patch from
    partial recovery evidence" is enforced here, not left to the caller,
    and is enforced at the granularity the evidence actually failed at: a
    single resolved window covering only one of a file's several failing
    hunks is not sufficient merely because that file's own attempt
    "succeeded" at building A window.

    `budget_controller=None` (the default, and every existing caller)
    preserves this exact fixed-budget, fail-closed behavior unchanged.
    When given, a target blocked ONLY by this round's own
    MAX_POST_PATCH_SOURCE_CHARS total and/or the shared
    FINAL_TARGET_SLICE_MAX_CHARS ceiling (never by an unsafe path or
    genuine unresolvability) gets one immediate, local retry against
    whichever of the two pools the controller actually extends (see
    ContextBudgetController) -- never a second recovery round, never a
    rerun of the Planner/Final Strategy/Patch Generator.
    """
    reasons = post_patch_recovery_trigger_reasons(conformance)
    if not reasons or repo_root is None or slice_result is None:
        return _EMPTY_RECOVERY_RESULT_NOT_TRIGGERED

    root = Path(repo_root)
    failing_files = set(conformance.unexpected_files) | set(conformance.uncovered_files) | set(conformance.no_match_files)

    # Eligibility is OPT-IN by presence, not by emptiness: `None` (no
    # caller-modeled eligibility set at all) preserves this function's
    # exact pre-eligibility, permissive behavior for every failing file --
    # the low-level/backward-compatible path. Any actual list (including
    # an empty one, exactly what a run with zero ReadyEdits and zero
    # prior-supported files would legitimately produce) turns eligibility
    # ON: a failing file not named by it is ineligible, full stop -- see
    # the per-target loop below.
    eligibility_enforced = recovery_targets is not None
    eligible_files = {t.file for t in (recovery_targets or [])}
    targets_by_file: "dict[str, list[RecoveryTarget]]" = {}
    for t in (recovery_targets or []):
        targets_by_file.setdefault(t.file, []).append(t)

    implicated_targets: "list[RecoveryTarget]" = []
    for f in sorted(failing_files):
        existing = targets_by_file.get(f)
        if existing:
            implicated_targets.extend(existing)
        else:
            # No RecoveryTarget names this file. When eligibility is not
            # enforced (recovery_targets=None) this is the pre-existing,
            # permissive, file-only path -- unchanged. When eligibility IS
            # enforced this file is simply ineligible; a placeholder is
            # still built so it gets exactly one observable, immediately-
            # failed attempt below (see "not_recovery_eligible") rather
            # than being silently dropped from the trace.
            implicated_targets.append(RecoveryTarget(file=f, kind="file", identity=None))

    if len(implicated_targets) > MAX_RECOVERY_TARGETS:
        return PostPatchRecoveryResult(
            triggered=True, trigger_reasons=reasons, recovery_targets=implicated_targets,
            attempts=[], slice_result=slice_result, ready_for_regeneration=False,
            failure_reason="too_many_recovery_targets",
        )

    try:
        _changed_files, file_hunks = parse_diff(patch or "")
    except Exception:
        file_hunks = {}

    current_slice = slice_result
    attempts: "list[RecoveryTargetAttempt]" = []
    budget_remaining = MAX_POST_PATCH_SOURCE_CHARS

    def _extend_post_patch_budget(affected_file: str, needed_chars: int = 1) -> bool:
        """Try, in order, to extend whichever pool(s) are actually
        binding for the CURRENT target -- this round's own
        "post_patch_recovery" pool first (the narrower one in practice),
        then the shared "final_target_slice" ceiling -- returning True
        if at least one extension was approved (the caller recomputes
        `available` immediately afterward). A no-op, always returning
        False, when `budget_controller` is None.

        `needed_chars` is the amount the CALLER has already determined
        it's short by (e.g. a just-built window's own rendered length,
        or an unbounded probe's rendered length) -- a pool is extended
        only when it is insufficient for that amount, never merely when
        it has reached exactly zero. The default, `1`, reproduces the
        original "pool is at/below zero" test exactly (`x < 1` iff
        `x <= 0` for the non-negative values used here) for the one
        caller (the pre-check above, before any window has been built)
        that has no more specific need to report yet."""
        nonlocal budget_remaining
        if budget_controller is None:
            return False
        extended = False
        if budget_remaining < needed_chars and budget_controller.request_extension(
            "post_patch_recovery", MAX_POST_PATCH_SOURCE_CHARS,
            reason="target_budget_exhausted", affected_targets=[affected_file],
        ):
            budget_remaining += MAX_POST_PATCH_SOURCE_CHARS
            extended = True
        if (_effective_final_target_max(budget_controller) - len(current_slice.rendered)) < needed_chars and (
            budget_controller.request_extension(
                "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                reason="target_budget_exhausted", affected_targets=[affected_file],
            )
        ):
            extended = True
        return extended

    def _covered_hunks_for(file: str, rendered_text: str) -> "list[int]":
        """Which of `file`'s own recovery-triggering hunks (per
        `conformance.results` -- target_coverage in ("unexpected_file",
        "uncovered_target") or old_side_status == "old_side_no_match")
        this SUCCESSFUL attempt's `rendered_text` covers. Only ever
        called from a success=True branch (a non-empty `rendered_text` is
        already guaranteed), never from a failure path.

        Two cases:
        - `old_side_status in ("old_side_no_match", "new_file")`: there is
          no real anchor text to verify anywhere in the repository (a
          no_match hunk's own old side is, by construction, wrong and
          exists nowhere real; a new-file hunk has no old side at all) --
          the only meaningful signal is that THIS target's own attempt
          retrieved genuine, verified, patch-ready source at all, which is
          already established by the caller only invoking this helper on
          success.
        - otherwise (old_side_verified/ambiguous/not_verifiable): the
          hunk's real old-side content exists somewhere in the repository
          by definition -- covered only when it is found, verbatim,
          inside THIS attempt's own `rendered_text`, via the SAME
          content-matching primitive check_patch_target_conformance
          itself uses (old_side_anchors + find_unique_occurrence), never
          a new mechanism. This is what stops one narrow window from
          silently covering several disjoint failing hunks in the same
          file."""
        hunks = file_hunks.get(file, [])
        covered: "list[int]" = []
        for r in conformance.results:
            if r.file != file:
                continue
            if not (
                r.target_coverage in ("unexpected_file", "uncovered_target")
                or r.old_side_status == "old_side_no_match"
            ):
                continue
            if r.hunk_index >= len(hunks):
                continue
            if r.old_side_status in ("old_side_no_match", "new_file"):
                covered.append(r.hunk_index)
                continue
            anchors = old_side_anchors(hunks[r.hunk_index].lines)
            if anchors and find_unique_occurrence(anchors, rendered_text.splitlines()) is not None:
                covered.append(r.hunk_index)
        return covered

    for target in implicated_targets:
        file = target.file
        trigger_reason = _recovery_reason_for_file(file, conformance)

        if eligibility_enforced and file not in eligible_files:
            # Ineligible: neither a current ReadyEdit nor prior-supported
            # (Target Discovery/Final Strategy). Fails closed immediately,
            # before any retrieval -- _verify_file, identifier extraction,
            # and window-building are never reached for this target, so
            # no budget is spent and no repository read happens for it.
            attempts.append(RecoveryTargetAttempt(
                file=file, trigger_reason=trigger_reason, identifiers_considered=[],
                resolved_file=None, resolved_target=None, target_start_line=None, target_end_line=None,
                start_line=None, end_line=None, enclosing_symbol=None, source_kind=None,
                source_chars=0, patch_ready=False, identifier_verified_in_window=False,
                success=False, failure_reason="not_recovery_eligible",
                target_kind=target.kind, target_identity=target.identity, covered_hunk_indices=[],
            ))
            continue

        verified_file = _verify_file(file, root)
        if verified_file is None:
            attempts.append(RecoveryTargetAttempt(
                file=file, trigger_reason=trigger_reason, identifiers_considered=[],
                resolved_file=None, resolved_target=None, target_start_line=None, target_end_line=None,
                start_line=None, end_line=None, enclosing_symbol=None, source_kind=None,
                source_chars=0, patch_ready=False, identifier_verified_in_window=False,
                success=False, failure_reason="unsafe_file_path",
                target_kind=target.kind, target_identity=target.identity, covered_hunk_indices=[],
            ))
            continue

        hunks_for_file = file_hunks.get(file, [])
        # Source Priority 1 (_locate_old_side_in_file, via
        # _build_post_patch_window's try_old_side_anchor branch) must only
        # ever scan the hunks that actually triggered recovery for this
        # file -- never an already-approved_target/conformant hunk that
        # merely happens to share the file and appear earlier in the patch
        # body. Identifier extraction below is intentionally UNCHANGED:
        # it still reads every hunk in the file (tiers 2-4 are unaffected).
        _failing_hunk_indices = _recovery_triggering_hunk_indices(file, conformance)
        failing_hunks_for_file = [
            h for i, h in enumerate(hunks_for_file) if i in _failing_hunk_indices
        ]
        changed_identifiers: "list[str]" = []
        context_identifiers: "list[str]" = []
        seen_ids: set = set()
        for hunk in hunks_for_file:
            for line in hunk.lines:
                changed = line[:1] in ("+", "-")
                stripped = line[1:] if line[:1] in (" ", "+", "-") else line
                for tok in _extract_identifiers_from_text(stripped):
                    if tok in seen_ids:
                        continue
                    seen_ids.add(tok)
                    (changed_identifiers if changed else context_identifiers).append(tok)

        # This attempt's own already-approved RecoveryTarget identity
        # (never a diff-derived guess) participates as an explicit
        # candidate at exactly one priority: after every changed-line
        # identifier (the strongest signal -- something the generated
        # diff is actually introducing or editing) and before every
        # context-line identifier (the weakest signal -- often just an
        # incidental token, e.g. a type-comment class name, that happens
        # to appear near a failing hunk without being causally related to
        # it). `None` whenever this attempt has no resolved symbol
        # identity (kind == "file"), leaving `identifiers` exactly as
        # before. Deduplicated against whichever bucket already names it
        # -- moved out of `context_identifiers` into this one priority
        # slot rather than appearing twice; never pulled out of
        # `changed_identifiers`, which already outranks it.
        boundary_identifier = target.identity if (target.kind == "symbol" and target.identity) else None
        if boundary_identifier is not None:
            if boundary_identifier in context_identifiers:
                context_identifiers.remove(boundary_identifier)
            identifiers = changed_identifiers + (
                [] if boundary_identifier in changed_identifiers else [boundary_identifier]
            ) + context_identifiers
        else:
            identifiers = changed_identifiers + context_identifiers

        total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
        available = min(budget_remaining, total_remaining)
        if budget_controller is not None:
            budget_controller.record_used("final_target_slice", len(current_slice.rendered))
        if available <= 0:
            if _extend_post_patch_budget(file):
                total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                available = min(budget_remaining, total_remaining)
            if available <= 0:
                attempts.append(RecoveryTargetAttempt(
                    file=file, trigger_reason=trigger_reason, identifiers_considered=identifiers,
                    resolved_file=None, resolved_target=None, target_start_line=None, target_end_line=None,
                    start_line=None, end_line=None, enclosing_symbol=None, source_kind=None,
                    source_chars=0, patch_ready=False, identifier_verified_in_window=False,
                    success=False, failure_reason="target_budget_exhausted",
                    target_kind=target.kind, target_identity=target.identity, covered_hunk_indices=[],
                ))
                continue

        window = _build_post_patch_window(
            verified_file, identifiers, failing_hunks_for_file, context,
            try_old_side_anchor=(trigger_reason == "uncovered_target"),
            boundary_identifier=boundary_identifier,
        )

        if window is not None:
            rendered_text = _render_definition_block(window.file, window.label, window.start, window.end, window.source)
            if len(rendered_text) > available:
                if _extend_post_patch_budget(file, needed_chars=len(rendered_text)):
                    total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                    available = min(budget_remaining, total_remaining)
                if len(rendered_text) > available:
                    # Fails closed here rather than degrading to the tier-5
                    # fallback below with the SAME tiny budget: a smaller,
                    # less-padded block from that mechanism could "succeed"
                    # by its own (looser) criterion while still not being a
                    # sufficient patch-ready window -- exactly the failure
                    # mode this function exists to prevent.
                    attempts.append(RecoveryTargetAttempt(
                        file=file, trigger_reason=trigger_reason, identifiers_considered=identifiers,
                        resolved_file=None, resolved_target=window.label,
                        target_start_line=window.target_start, target_end_line=window.target_end,
                        start_line=None, end_line=None, enclosing_symbol=window.enclosing_symbol,
                        source_kind=None, source_chars=len(rendered_text),
                        patch_ready=False, identifier_verified_in_window=False,
                        success=False, failure_reason="target_budget_exhausted",
                        target_kind=target.kind, target_identity=target.identity, covered_hunk_indices=[],
                    ))
                    continue

            addition = _wrap_post_patch_window(window, verified_file)
            current_slice = _merge_slice_results(current_slice, addition, strategy)
            budget_remaining = max(0, budget_remaining - len(rendered_text))
            attempts.append(RecoveryTargetAttempt(
                file=file, trigger_reason=trigger_reason, identifiers_considered=identifiers,
                resolved_file=verified_file, resolved_target=window.label,
                target_start_line=window.target_start, target_end_line=window.target_end,
                start_line=window.start, end_line=window.end, enclosing_symbol=window.enclosing_symbol,
                source_kind=window.source_kind, source_chars=len(rendered_text),
                patch_ready=True,
                identifier_verified_in_window=_window_confirms_target(window, identifiers, hunks_for_file),
                success=True, failure_reason=None,
                target_kind=target.kind, target_identity=target.identity,
                covered_hunk_indices=_covered_hunks_for(file, rendered_text),
            ))
            continue

        # Tier 5 (the only tier left): nothing resolved above at all --
        # fall back to the pre-existing mechanism, unmodified, as a small
        # bounded full-file read. Its own category 2 (identical
        # _lookup_identifier_definition lookup) cannot resolve anything
        # _build_post_patch_window did not already try and fail, so the
        # only reachable success here is category 5's full-file
        # fallback.
        focused = strategy._replace(
            target_files=[verified_file], target_symbols=[], required_edits=identifiers[:20],
        )
        addition = build_final_target_slice(
            focused, repo_root, context, planner_evidence_files=(), max_chars=available,
        )
        current_slice = _merge_slice_results(current_slice, addition, strategy)
        budget_remaining = max(0, budget_remaining - len(addition.rendered))

        succeeded = bool(addition.rendered) and (
            verified_file in current_slice.identifier_definition_covered
            or verified_file in current_slice.full_file_fallback_covered
        )

        failure_reason = None
        if not succeeded:
            # category 2/5 (the only categories a target_symbols=[]
            # focused strategy can ever use) don't feed
            # edit_target_budget_exhausted (that flag only tracks
            # categories 1/3b/4) -- so whether the ROUND's own smaller
            # `available` budget (rather than genuine unresolvability)
            # was the blocker is determined here, deterministically, by
            # re-probing the SAME focused strategy at the full effective
            # budget. The probe's own result is discarded either way --
            # never merged, never committed -- only used to pick the
            # honest reason (and, when a controller is given, to decide
            # whether an extension is even worth asking for).
            if available < _effective_final_target_max(budget_controller):
                probe = build_final_target_slice(focused, repo_root, context, planner_evidence_files=())
                probe_would_cover = bool(probe.rendered) and (
                    verified_file in probe.identifier_definition_covered
                    or verified_file in probe.full_file_fallback_covered
                )
                if probe_would_cover and _extend_post_patch_budget(file, needed_chars=len(probe.rendered)):
                    # Budget was confirmed to be the sole blocker AND an
                    # extension was approved -- retry the REAL build
                    # (never just the discarded probe) against the
                    # raised ceiling, exactly once.
                    total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                    available = min(budget_remaining, total_remaining)
                    addition = build_final_target_slice(
                        focused, repo_root, context, planner_evidence_files=(), max_chars=available,
                    )
                    current_slice = _merge_slice_results(current_slice, addition, strategy)
                    budget_remaining = max(0, budget_remaining - len(addition.rendered))
                    succeeded = bool(addition.rendered) and (
                        verified_file in current_slice.identifier_definition_covered
                        or verified_file in current_slice.full_file_fallback_covered
                    )
                failure_reason = None if succeeded else ("target_budget_exhausted" if probe_would_cover else "missing_target_source")
            else:
                failure_reason = "missing_target_source"

        start, end, kind = None, None, None
        if addition.rendered:
            start, end = _sniff_rendered_lines(addition.rendered)
            kind = _post_patch_fallback_source_kind(_sniff_rendered_kind(addition.rendered))

        attempts.append(RecoveryTargetAttempt(
            file=file, trigger_reason=trigger_reason, identifiers_considered=identifiers,
            resolved_file=verified_file if succeeded else None, resolved_target=None,
            target_start_line=None, target_end_line=None,
            start_line=start, end_line=end, enclosing_symbol=None,
            source_kind=kind, source_chars=len(addition.rendered),
            patch_ready=succeeded, identifier_verified_in_window=False,
            success=succeeded, failure_reason=failure_reason,
            target_kind=target.kind, target_identity=target.identity,
            covered_hunk_indices=_covered_hunks_for(file, addition.rendered) if succeeded else [],
        ))

    all_succeeded = bool(attempts) and all(a.success for a in attempts)
    covered = {(a.file, hi) for a in attempts for hi in a.covered_hunk_indices}
    failing_hunks = {
        (r.file, r.hunk_index) for r in conformance.results
        if r.file in failing_files
        and (r.target_coverage in ("unexpected_file", "uncovered_target") or r.old_side_status == "old_side_no_match")
    }
    fully_covered = failing_hunks.issubset(covered)
    ready_for_regeneration = all_succeeded and fully_covered
    if ready_for_regeneration:
        failure_reason_out = None
    elif not all_succeeded:
        failure_reason_out = "partial_recovery_evidence"
    else:
        failure_reason_out = "partial_hunk_coverage"
    return PostPatchRecoveryResult(
        triggered=True, trigger_reasons=reasons, recovery_targets=implicated_targets,
        attempts=attempts, slice_result=current_slice,
        ready_for_regeneration=ready_for_regeneration,
        failure_reason=failure_reason_out,
    )


_FENCED_DIFF_RE = re.compile(r"^```(?:diff|patch|udiff)?[ \t]*\r?\n(.*?)\n```[ \t]*$", re.DOTALL)


def _unfenced_diff(text: str) -> str:
    """Strip exactly one already-present ``` fence wrapper from `text`, if
    the whole (stripped) string is one such fenced block -- returns
    `text` unchanged (stripped) otherwise.

    `patch_generator.classify_patch_response`'s "valid" result is always
    pre-fenced (`"```diff\\n" + body + "```"`, see its own docstring), and
    that is exactly what reaches this module as `patch`/`failed_patch`.
    Embedding it under a second, freshly-added fence would nest one
    fenced block inside another instead of producing one -- this
    unwraps any such existing fence first so a caller that always wraps
    its own fence around the result (see build_post_patch_recovery_hint)
    produces exactly one, regardless of whether its input arrived
    already fenced or not."""
    m = _FENCED_DIFF_RE.match(text.strip())
    return m.group(1) if m else text.strip()


def build_post_patch_recovery_hint(
    conformance: PatchConformanceReport, recovery: PostPatchRecoveryResult, failed_patch: str,
) -> str:
    """Deterministic retry instruction for the ONE bounded regeneration
    call (generate_patch, called by pipeline.py itself -- this function
    only builds the text). States exactly which file(s) failed and why,
    that the now-available verified source above must be copied
    verbatim, and that the same intended fix must be preserved without
    introducing unrelated edits -- never repository-specific wording, no
    vulnerability-family rules.

    The header line and each per-file bullet are deliberately worded
    per-reason rather than one shared claim: `uncovered_files` means the
    edited content WAS verified against the repository (old_side_status
    can be "old_side_verified") but fell outside the approved edit
    target(s) -- a wrong-target problem, not an unverified-content one
    -- while `unexpected_files` and `no_match_files` are genuinely about
    an unapproved file or content that could not be found at all. Using
    one blanket "could not be verified" line for all three would
    misstate the uncovered_target case specifically."""
    lines = ["The previous patch did not pass Patch Target Conformance:"]
    for f in conformance.unexpected_files:
        lines.append(f"- `{f}` was not an approved edit target for this vulnerability.")
    for f in conformance.uncovered_files:
        lines.append(
            f"- `{f}` was edited, and that content was verified against the repository, "
            f"but the edit fell outside the approved edit target(s) for this vulnerability."
        )
    for f in conformance.no_match_files:
        lines.append(f"- `{f}`'s removed/context lines could not be found anywhere in the repository (no_match).")
    lines.append("")
    lines.append(
        "Exact, verified repository source for the actual target(s) is now included in the "
        "repository code context above. Regenerate the patch using ONLY that verified source:"
    )
    lines.append("- Every old-side (context and removed) line in the new diff must be copied verbatim from the verified source above.")
    lines.append("- Do not invent a line number or any content that is not shown above.")
    lines.append("- Preserve the same intended security fix -- do not change what the fix does, only anchor it to real repository text.")
    lines.append("- Do not introduce edits to any file or symbol other than what the verified source above covers.")
    lines.append("- Return only the smallest patch necessary.")
    if failed_patch and failed_patch.strip():
        lines.append("")
        lines.append("The previous (unverified) attempt, shown only to identify the intended semantic edit:")
        lines.append(f"```diff\n{_unfenced_diff(failed_patch)}\n```")
    return "\n".join(lines)
