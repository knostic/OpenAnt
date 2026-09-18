"""
Agentic Context Enhancer

Main agent loop that iteratively explores the codebase to gather context.
Uses Claude Sonnet with tool use to search and read code.

Supports reachability-aware classification to distinguish:
- EXPLOITABLE: Vulnerable + reachable from user input
- VULNERABLE_INTERNAL: Vulnerable but not user-reachable
- SECURITY_CONTROL: Defensive code
- NEUTRAL: No security relevance
"""

import json
import sys
from typing import Optional, Set, List

from core.file_boundary import boundary_for_language
from ..llm_client import (TokenTracker, get_global_tracker,
                          record_accounting_error)
from ..llm import (
    Message,
    PhaseBinding,
    TextBlock,
    ToolDef,
    ToolResultBlock,
    ToolUseBlock,
    lookup_pricing,
)
# #290 sibling: same shape as finding_verifier — this loop bypasses
# simple_text and previously pinned its own 4096, so PR #242's raised default
# never reached enhance either. Shares the thinking-era budget; see
# llm/helpers.py:DEFAULT_MAX_TOKENS.
from ..llm.helpers import DEFAULT_MAX_TOKENS
from .repository_index import RepositoryIndex
from .tools import TOOL_DEFINITIONS, ToolExecutor
from .prompts import SYSTEM_PROMPT, get_user_prompt
from .entry_point_detector import EntryPointDetector
from .reachability_analyzer import ReachabilityAnalyzer


# Safety limits
MAX_ITERATIONS = 20
MAX_TOKENS_PER_RESPONSE = DEFAULT_MAX_TOKENS

# Classification stamped on a degenerate exit (agent ended without a completed
# `finish` tool call: bare end_turn, no tool calls, or MAX_ITERATIONS reached).
# Distinct from "neutral" — a genuine "no security relevance" verdict — so
# downstream (analyzer filter, CSV, reporting) records the no-op/error state
# instead of silently bucketing an unanalyzed unit as a real neutral finding.
INCOMPLETE_CLASSIFICATION = "incomplete"

# Input budget.
# The conversation input had no budget: primary_code was inlined verbatim and
# raw tool results were appended every iteration, so input grew unbounded until
# it overflowed the model context (400). We cap each oversized input at its
# consumption point. ~4 chars/token, so these stay well under the model window.
MAX_PROMPT_CHARS = 60_000          # cap on inlined primary_code in the prompt
MAX_TOOL_RESULT_CHARS = 24_000     # cap on each serialized tool result


def cap_tool_result_content(result: dict, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    """Serialize a tool result to JSON, truncating to ``limit`` chars.

    Tool results (e.g. ``read_function`` returning a whole function body) are
    otherwise appended raw to the conversation, growing the input without
    bound across iterations. Small results round-trip as valid JSON; oversized
    results are truncated with an explicit marker so the model knows content
    was elided.
    """
    content = json.dumps(result)
    if len(content) <= limit:
        return content
    marker = "\n... (truncated)"
    return content[: limit - len(marker)] + marker


# Convert the dict-form TOOL_DEFINITIONS list to typed ToolDef instances
# once at import time so we're not rebuilding them on every iteration of
# every agent run.
_TOOL_DEFS: list[ToolDef] = [
    ToolDef(
        name=td["name"],
        description=td["description"],
        input_schema=td["input_schema"],
    )
    for td in TOOL_DEFINITIONS
]


class AgentResult:
    """Result from agent analysis."""

    def __init__(
        self,
        include_functions: list[dict],
        usage_context: str,
        security_classification: str,
        classification_reasoning: str,
        confidence: float,
        iterations: int,
        total_tokens: int,
        is_entry_point: bool = False,
        reachable_from_entry: Optional[bool] = None,
        entry_point_path: Optional[List[str]] = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
        unpriced_models: Optional[list] = None,
        usage_details: Optional[list] = None,
        # #615: WHICH degenerate exit produced this incomplete — the four
        # exits differ in kind and remedy (three cheap model-behavior
        # exits vs the budget-exhaustion one); a consumer reading only
        # classification cannot split the 4-vs-41. Empty string = a
        # completed analysis (NOT an incomplete marker).
        exit_kind: str = "",
    ):
        self.include_functions = include_functions
        self.usage_context = usage_context
        self.security_classification = security_classification
        self.classification_reasoning = classification_reasoning
        self.confidence = confidence
        self.iterations = iterations
        self.total_tokens = total_tokens
        self.is_entry_point = is_entry_point
        self.reachable_from_entry = reachable_from_entry
        self.entry_point_path = entry_point_path
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cost_usd = cost_usd
        # #216: this unit's unpriced models (incomplete-cost marker).
        self.unpriced_models = unpriced_models
        # #211 pass-through capture: per-turn detail dicts, verbatim.
        self.usage_details = usage_details
        self.exit_kind = exit_kind

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "include_functions": self.include_functions,
            "usage_context": self.usage_context,
            "security_classification": self.security_classification,
            "classification_reasoning": self.classification_reasoning,
            "confidence": self.confidence,
            # #615: present-only — a completed analysis (exit_kind="")
            # serializes without the key (the legacy byte-identity).
            **({"exit_kind": self.exit_kind} if self.exit_kind else {}),
            "agent_metadata": {
                "iterations": self.iterations,
                "total_tokens": self.total_tokens,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cost_usd": self.cost_usd,
                # #216: the unit's unpriced models — flows into the
                # per-unit checkpoint record so resume restores the marker.
                **({"cost_incomplete": True, "unpriced_models": self.unpriced_models}
                   if self.unpriced_models else {}),
                # #211: verbatim when captured; never summed, never in cost.
                **({"usage_details": self.usage_details}
                   if self.usage_details is not None else {}),
            },
            "reachability": {
                "is_entry_point": self.is_entry_point,
                "reachable_from_entry": self.reachable_from_entry,
                "entry_point_path": self.entry_point_path
            }
        }
        return result


class ContextAgent:
    """
    Agent that explores codebase to gather context for security analysis.
    Uses iterative tool use to trace call paths and understand code intent.

    Supports reachability-aware classification when entry_points and
    reachability analyzer are provided.
    """

    def __init__(
        self,
        index: RepositoryIndex,
        binding: PhaseBinding,
        tracker: TokenTracker = None,
        verbose: bool = False,
        entry_points: Optional[Set[str]] = None,
        reachability: Optional[ReachabilityAnalyzer] = None,
    ):
        """
        Initialize the agent.

        Args:
            index: RepositoryIndex for searching code
            binding: Phase binding for the enhance phase. Carries the
                adapter and model used for every iteration of the
                tool-use loop. Shared across workers (adapters are
                stateless dispatchers).
            tracker: TokenTracker for cost tracking
            verbose: If True, print debug information
            entry_points: Set of func_ids that are entry points (optional)
            reachability: ReachabilityAnalyzer for checking user input paths (optional)
        """
        if not binding.adapter.supports_tools:
            raise ValueError(
                f"Agentic enhancement requires a tool-supporting adapter, but "
                f"the binding for phase {binding.phase!r} uses adapter type "
                f"{binding.adapter.name!r} which does not support tools."
            )
        self.index = index
        self.binding = binding
        self.tracker = tracker or get_global_tracker()
        self.verbose = verbose
        self.tool_executor = ToolExecutor(index)
        self.entry_points = entry_points or set()
        self.reachability = reachability

    def analyze_unit(
        self,
        unit_id: str,
        unit_type: str,
        primary_code: str,
        static_deps: list[str],
        static_callers: list[str]
    ) -> AgentResult:
        """
        Analyze a code unit to gather context.

        Args:
            unit_id: Function identifier
            unit_type: Type classification
            primary_code: Code with static dependencies
            static_deps: Static analysis dependencies
            static_callers: Static analysis callers

        Returns:
            AgentResult with gathered context
        """
        # #216: begin per-unit usage tracking on THIS thread — the unit's
        # unpriced-model set (thread-local) is what the AgentResult
        # construction sites read for agent_metadata. Without this call the
        # getattr chain always sees the default empty set and the marker is
        # dead code on the enhance path (union-checkpoint catch: no caller
        # on the worker thread ever started tracking).
        _start = getattr(self.tracker, "start_unit_tracking", None)
        if _start is not None:
            _start()

        is_entry_point = unit_id in self.entry_points
        reachable_from_entry: Optional[bool] = None
        entry_point_path: Optional[List[str]] = None
        reaching_entry_point: Optional[str] = None

        if self.reachability:
            reachable_from_entry = self.reachability.is_reachable_from_entry_point(unit_id)
            if reachable_from_entry:
                entry_point_path = self.reachability.get_entry_point_path(unit_id)
                reaching_entry_point = self.reachability.get_reaching_entry_point(unit_id)

        # Set static deps on tool executor for get_static_dependencies tool
        self.tool_executor.set_unit_context(static_deps, static_callers)

        # Build initial prompt with reachability info
        user_prompt = get_user_prompt(
            unit_id=unit_id,
            unit_type=unit_type,
            primary_code=primary_code,
            static_deps=static_deps,
            static_callers=static_callers,
            is_entry_point=is_entry_point,
            reachable_from_entry=reachable_from_entry,
            entry_point_path=entry_point_path,
            reaching_entry_point=reaching_entry_point
        )

        messages: list[Message] = [
            Message(role="user", content=[TextBlock(user_prompt)])
        ]

        iterations = 0
        total_input_tokens = 0
        total_output_tokens = 0
        # #211 pass-through capture: per-turn usage detail dicts, verbatim.
        per_turn_usage_details: list = []

        while iterations < MAX_ITERATIONS:
            iterations += 1

            if self.verbose:
                print(f"  Iteration {iterations}...")

            # Call the model. The adapter handles the rate-limiter
            # wait/report dance internally — see AnthropicAdapter for
            # the cross-worker coordination logic.
            try:
                result = self.binding.adapter.complete(
                    model=self.binding.model,
                    max_tokens=MAX_TOKENS_PER_RESPONSE,
                    system=SYSTEM_PROMPT,
                    tools=_TOOL_DEFS,
                    messages=messages,
                )
            except Exception as exc:
                # #609: a failed attempt's spend must not vanish from
                # accounting. The exits record via record_call; the raise
                # did not, so the tracker and every summary/checkpoint
                # under-reported the provider's real bill. Mirror the
                # #616 idiom (finding_verifier.py's error-path record):
                # fold the raising turn's tokens when the exception
                # carries them (#537: an LLMResponseError's rejected reply
                # was billed), zero-token guard (a turn-1 connection
                # failure billed nothing — no $0 record, no spurious
                # unpriced marker), and a None per-turn entry for the
                # raising turn (the list length equals the turns billed).
                # #609 review: the coercions are GUARDED — a foreign
                # exception with a non-int-coercible token attr must not
                # replace the original (the ENG-1 class; in-tree carriers
                # int-coerce at construction, this is the belt).
                try:
                    exc_in = int(getattr(exc, "input_tokens", 0) or 0)
                    exc_out = int(getattr(exc, "output_tokens", 0) or 0)
                except Exception:
                    exc_in = exc_out = 0
                attempt_cost = 0.0
                attempt_unpriced = None
                if (total_input_tokens or total_output_tokens
                        or exc_in or exc_out):
                    # ENG-1 (#609 pre-code check): an accounting failure
                    # here must never replace the original exception —
                    # its retryability class (rate_limit vs connection vs
                    # structural) is what the enhance retry loop keys on.
                    # The guard is load-bearing, not hygiene: a poisoned
                    # pricing dict would otherwise reclassify a transient
                    # rate limit as a non-retryable KeyError.
                    try:
                        call_record = self.tracker.record_call(
                            model=self.binding.model,
                            input_tokens=total_input_tokens + exc_in,
                            output_tokens=total_output_tokens + exc_out,
                            pricing=lookup_pricing(self.binding),
                            usage_details=per_turn_usage_details
                            + ([None] if (exc_in or exc_out) else []),
                        )
                        # the reads live INSIDE the guard's try: a double
                        # returning None from record_call must hit the
                        # guard, not turn into an AttributeError that
                        # replaces the original exception.
                        attempt_cost = call_record.get("cost_usd", 0.0)
                        attempt_unpriced = sorted(getattr(
                            getattr(self.tracker, "_thread_local", None),
                            "unit_unpriced", set())) or None
                    except Exception:
                        # #609/#605: the swallowed accounting failure must be
                        # LOUD in the artifacts, not just stderr — tick the
                        # accounting-error counter so get_totals()/the step
                        # reports carry the marker (never a complete-looking
                        # artifact). The import is module-level: an import
                        # failure here would replace the original exception
                        # (the ENG-1 class). The print is itself guarded: a
                        # closed/encoding-broken stderr raising HERE would
                        # replace the original exception — the exact class
                        # this handler exists to prevent.
                        try:
                            record_accounting_error()
                        except Exception:
                            pass  # the counter is module-level: unreachable
                                  # in-tree; a poisoned registry module is the
                                  # concern — the original error outranks it
                        try:
                            print(f"[agent] accounting record failed for the "
                                  f"failed attempt of {unit_id}: "
                                  f"{sys.exc_info()[0].__name__} (the tracker "
                                  f"has no record of this attempt; "
                                  f"agent_state carries its tokens but "
                                  f"cost_usd=0.0 and no unpriced marker; the "
                                  f"original error is re-raised)",
                                  file=sys.stderr)
                        except Exception:
                            pass  # stderr unavailable — the #605 counter is
                                  # the durable signal
                # Attach agent state so the caller knows how far we got.
                # Covers LLMRateLimitError (adapter has already reported
                # to the global rate limiter) and anything else. #609:
                # the state carries the SAME numbers the tracker recorded
                # (tokens incl. the raising turn's; priced cost; the #216
                # unpriced marker, present-only) so the enhance summary,
                # checkpoints, and resume fold what the tracker has.
                exc.agent_state = {
                    "iteration": iterations,
                    "max_iterations": MAX_ITERATIONS,
                    "tokens_used": (total_input_tokens + exc_in)
                    + (total_output_tokens + exc_out),
                    "input_tokens": total_input_tokens + exc_in,
                    "output_tokens": total_output_tokens + exc_out,
                    "cost_usd": attempt_cost,
                    **({"unpriced_models": attempt_unpriced}
                       if attempt_unpriced else {}),
                }
                raise

            total_input_tokens += result.input_tokens
            total_output_tokens += result.output_tokens
            per_turn_usage_details.append(result.usage_details)

            assistant_content = result.content
            stop_reason = result.stop_reason

            if self.verbose:
                # Print text blocks
                for block in assistant_content:
                    if isinstance(block, TextBlock):
                        print(f"    Agent: {block.text[:200]}...")

            # Check if we're done (finish tool called or no more tool use)
            if stop_reason == "end_turn":
                # Model finished without calling finish tool
                # Return default result
                if self.verbose:
                    print("  Agent ended without calling finish tool")

                # Record spend even on this degenerate exit, so the tracker and the
                # per-unit metadata don't undercount tokens/cost.
                call_record = self.tracker.record_call(
                    model=self.binding.model,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    pricing=lookup_pricing(self.binding),
                    usage_details=per_turn_usage_details,
                )
                return AgentResult(
                    include_functions=[],
                    usage_context="Agent did not complete analysis",
                    security_classification=INCOMPLETE_CLASSIFICATION,
                    classification_reasoning="Analysis incomplete",
                    confidence=0.3,
                    exit_kind="end_turn_without_finish",
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    is_entry_point=is_entry_point,
                    reachable_from_entry=reachable_from_entry,
                    entry_point_path=entry_point_path,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    cost_usd=call_record.get("cost_usd", 0.0),
                    unpriced_models=sorted(getattr(
                        getattr(self.tracker, "_thread_local", None),
                        "unit_unpriced", set())) or None,
                    usage_details=per_turn_usage_details,
                )

            tool_results: list[ToolResultBlock] = []
            finish_result = None

            for block in assistant_content:
                if isinstance(block, ToolUseBlock):
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id

                    if self.verbose:
                        print(f"    Tool: {tool_name}({json.dumps(tool_input)[:100]}...)")

                    tool_outcome = self.tool_executor.execute(tool_name, tool_input)

                    if self.verbose:
                        result_preview = str(tool_outcome)[:200]
                        print(f"    Result: {result_preview}...")

                    # Check for finish
                    if tool_name == "finish" and tool_outcome.get("status") == "complete":
                        finish_result = tool_outcome.get("result", {})
                        # Still add to tool_results so the conversation
                        # has a balanced tool_use / tool_result pair —
                        # some adapters validate this strictly.
                        tool_results.append(
                            ToolResultBlock(
                                tool_use_id=tool_use_id,
                                name=tool_name,
                                content=cap_tool_result_content(tool_outcome),
                            )
                        )
                        break
                    else:
                        tool_results.append(
                            ToolResultBlock(
                                tool_use_id=tool_use_id,
                                name=tool_name,
                                content=cap_tool_result_content(tool_outcome),
                            )
                        )

            # R2-B: a finish call on a turn the model TRUNCATED (stop_reason ==
            # "max_tokens") is not a trustworthy complete classification — a
            # truncated finish defaulting security_classification to "neutral"
            # would silently drop a unit from the analysed set (a coverage/recall
            # loss). Treat it as INCOMPLETE, mirroring this agent's degenerate-exit
            # handling and the verifier's max_tokens gate.
            if finish_result and stop_reason == "max_tokens":
                call_record = self.tracker.record_call(
                    model=self.binding.model,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    pricing=lookup_pricing(self.binding),
                    usage_details=per_turn_usage_details,
                )
                return AgentResult(
                    include_functions=[],
                    usage_context="Agent finish call truncated at max_tokens",
                    security_classification=INCOMPLETE_CLASSIFICATION,
                    classification_reasoning="Analysis incomplete - finish call truncated",
                    confidence=0.3,
                    exit_kind="finish_truncated",
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    is_entry_point=is_entry_point,
                    reachable_from_entry=reachable_from_entry,
                    entry_point_path=entry_point_path,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    cost_usd=call_record.get("cost_usd", 0.0),
                    unpriced_models=sorted(getattr(
                        getattr(self.tracker, "_thread_local", None),
                        "unit_unpriced", set())) or None,
                    usage_details=per_turn_usage_details,
                )

            # If finish was called, return result
            if finish_result:
                # Record token usage
                call_record = self.tracker.record_call(
                    model=self.binding.model,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    pricing=lookup_pricing(self.binding),
                    usage_details=per_turn_usage_details,
                )

                return AgentResult(
                    include_functions=finish_result.get("include_functions", []),
                    usage_context=finish_result.get("usage_context", ""),
                    security_classification=finish_result.get("security_classification", "neutral"),
                    classification_reasoning=finish_result.get("classification_reasoning", ""),
                    confidence=finish_result.get("confidence", 0.5),
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    is_entry_point=is_entry_point,
                    reachable_from_entry=reachable_from_entry,
                    entry_point_path=entry_point_path,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    cost_usd=call_record.get("cost_usd", 0.0),
                    unpriced_models=sorted(getattr(
                        getattr(self.tracker, "_thread_local", None),
                        "unit_unpriced", set())) or None,
                    usage_details=per_turn_usage_details,
                )

            # Add assistant message and tool results to conversation.
            # Echo only the block kinds the loop consumes (Text + ToolUse);
            # a future 4th block kind would throw on re-serialization.
            echoed = [b for b in assistant_content if isinstance(b, (TextBlock, ToolUseBlock))]
            messages.append(Message(role="assistant", content=echoed))

            # Only add user message with tool results if there are results
            # (empty content triggers API error: "user messages must have non-empty content")
            if tool_results:
                messages.append(Message(role="user", content=list(tool_results)))
            else:
                # No tool calls but model didn't end — treat as incomplete
                if self.verbose:
                    print("  No tool calls in response, treating as incomplete")
                # Record spend even on this degenerate exit.
                call_record = self.tracker.record_call(
                    model=self.binding.model,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    pricing=lookup_pricing(self.binding),
                    usage_details=per_turn_usage_details,
                )
                return AgentResult(
                    include_functions=[],
                    usage_context="Agent response had no tool calls",
                    security_classification=INCOMPLETE_CLASSIFICATION,
                    classification_reasoning="Analysis incomplete - no tool calls",
                    confidence=0.3,
                    exit_kind="no_tool_calls",
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    is_entry_point=is_entry_point,
                    reachable_from_entry=reachable_from_entry,
                    entry_point_path=entry_point_path,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    cost_usd=call_record.get("cost_usd", 0.0),
                    unpriced_models=sorted(getattr(
                        getattr(self.tracker, "_thread_local", None),
                        "unit_unpriced", set())) or None,
                    usage_details=per_turn_usage_details,
                )

        # Max iterations reached
        if self.verbose:
            print(f"  Max iterations ({MAX_ITERATIONS}) reached")

        # Record token usage
        call_record = self.tracker.record_call(
            model=self.binding.model,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
            pricing=lookup_pricing(self.binding),
            usage_details=per_turn_usage_details,
        )

        return AgentResult(
            include_functions=[],
            usage_context="Analysis terminated - max iterations reached",
            security_classification=INCOMPLETE_CLASSIFICATION,
            classification_reasoning="Could not complete analysis within iteration limit",
            confidence=0.2,
            exit_kind="max_iterations",
            iterations=iterations,
            total_tokens=total_input_tokens + total_output_tokens,
            is_entry_point=is_entry_point,
            reachable_from_entry=reachable_from_entry,
            entry_point_path=entry_point_path,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
            cost_usd=call_record.get("cost_usd", 0.0),
            unpriced_models=sorted(getattr(
                getattr(self.tracker, "_thread_local", None),
                "unit_unpriced", set())) or None,
            usage_details=per_turn_usage_details,
        )


def enhance_unit_with_agent(
    unit: dict,
    index: RepositoryIndex,
    binding: PhaseBinding,
    tracker: TokenTracker = None,
    verbose: bool = False,
    entry_points: Optional[Set[str]] = None,
    reachability: Optional[ReachabilityAnalyzer] = None,
) -> dict:
    """
    Enhance a single unit using the agentic approach.

    Args:
        unit: Unit from dataset
        index: Repository index for searching
        binding: Phase binding for the enhance phase (provider+model).
        tracker: Token tracker
        verbose: Print debug info
        entry_points: Set of func_ids that are entry points (optional)
        reachability: ReachabilityAnalyzer for checking user input paths (optional)

    Returns:
        Enhanced unit with agent_context field including reachability info
    """
    agent = ContextAgent(
        index=index,
        binding=binding,
        tracker=tracker,
        verbose=verbose,
        entry_points=entry_points,
        reachability=reachability,
    )

    # Extract unit info
    unit_id = unit.get("id", "unknown")
    unit_type = unit.get("unit_type", "function")
    code_section = unit.get("code", {})
    primary_code = code_section.get("primary_code", "")
    static_deps = unit.get("metadata", {}).get("direct_calls", [])
    static_callers = unit.get("metadata", {}).get("direct_callers", [])

    # Run agent
    result = agent.analyze_unit(
        unit_id=unit_id,
        unit_type=unit_type,
        primary_code=primary_code,
        static_deps=static_deps,
        static_callers=static_callers
    )

    # Add result to unit
    unit["agent_context"] = result.to_dict()

    # Assemble additional code if functions were identified
    # #614: the assembly is PRESERVE-ON-FAILURE — a raise here must never
    # let the caller's except overwrite the completed, paid classification
    # stored above (the context_enhancer handler replaced it with an error
    # dict, destroying the verdict and its metadata). The completed
    # context stays; the assembly failure is marked separately.
    if result.include_functions:
        try:
            additional_code = []
            additional_files = set()

            for func_info in result.include_functions:
                func_id = func_info.get("id", "")
                func_data = index.get_function(func_id)

                if func_data and func_data.get("code"):
                    additional_code.append(func_data["code"])

                    # Extract file path from func_id
                    colon_idx = func_id.rfind(":")
                    if colon_idx > 0:
                        additional_files.add(func_id[:colon_idx])

            # Append to primary_code with file boundaries
            if additional_code:
                # Emit the marker in the UNIT'S comment syntax. A `//` line injected
                # into Python or Ruby source is a syntax error, and the downstream
                # split would not find it in the form those parsers emit.
                FILE_BOUNDARY = boundary_for_language(unit.get("language"))
                current_code = unit["code"]["primary_code"]
                assembled = current_code + FILE_BOUNDARY + FILE_BOUNDARY.join(additional_code)
                # #614 review: compute the metadata into locals FIRST and
                # commit primary_code + primary_origin LAST — a raise in the
                # metadata computation no longer leaves inlined code with
                # deps_inlined unset (a partial state the wrap would swallow).
                origin = unit["code"].get("primary_origin", {})
                current_files = set(origin.get("files_included", []))
                origin["files_included"] = list(current_files | additional_files)
                origin["deps_inlined"] = True
                origin["enhanced_length"] = len(assembled)
                unit["code"]["primary_code"] = assembled
                unit["code"]["primary_origin"] = origin
        except Exception as exc:
            # #614: PRESERVE the completed classification + its usage — the
            # caller's except must never overwrite paid work with an error
            # dict. The failure is marked INSIDE the stored context (a
            # separate assembly_error key; the classification, the reasoning,
            # the confidence, and the recorded usage all survive).
            unit["agent_context"].setdefault("assembly_error", {
                "exception_class": type(exc).__name__,
                "message": str(exc)[:500],
            })
            print(f"[Enhance] assembly failed after a completed analysis "
                  f"({type(exc).__name__}): {exc} — the classification is "
                  "preserved; the additional code was not inlined",
                  file=sys.stderr)

    return unit


def create_reachability_context(
    functions: dict,
    call_graph: dict,
    reverse_call_graph: dict
) -> tuple[Set[str], ReachabilityAnalyzer]:
    """
    Create entry points and reachability analyzer from call graph data.

    This is a convenience function to set up reachability analysis
    from the output of CallGraphBuilder.

    Args:
        functions: Dict mapping func_id to function metadata
        call_graph: Forward call graph (func_id -> [called_func_ids])
        reverse_call_graph: Reverse call graph (func_id -> [caller_func_ids])

    Returns:
        Tuple of (entry_points, reachability_analyzer)

    Example:
        # From call graph builder output
        entry_points, reachability = create_reachability_context(
            functions=call_graph_data['functions'],
            call_graph=call_graph_data['call_graph'],
            reverse_call_graph=call_graph_data['reverse_call_graph']
        )

        # Use with enhance_unit_with_agent
        enhanced = enhance_unit_with_agent(
            unit, index,
            entry_points=entry_points,
            reachability=reachability
        )
    """
    # Detect entry points
    detector = EntryPointDetector(functions, call_graph)
    entry_points = detector.detect_entry_points()

    # Create reachability analyzer
    reachability = ReachabilityAnalyzer(
        functions=functions,
        reverse_call_graph=reverse_call_graph,
        entry_points=entry_points
    )

    return entry_points, reachability
