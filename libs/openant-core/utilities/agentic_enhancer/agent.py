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
from typing import Optional, Set, List

import anthropic

from ..llm_client import TokenTracker, get_global_tracker
from ..rate_limiter import get_rate_limiter
from .repository_index import RepositoryIndex
from .tools import TOOL_DEFINITIONS, ToolExecutor
from .prompts import SYSTEM_PROMPT, get_user_prompt
from .entry_point_detector import EntryPointDetector
from .reachability_analyzer import ReachabilityAnalyzer


# Use Sonnet for exploration (cost-effective)
AGENT_MODEL = "claude-sonnet-4-20250514"

# Safety limits
MAX_ITERATIONS = 20
MAX_TOKENS_PER_RESPONSE = 4096


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

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "include_functions": self.include_functions,
            "usage_context": self.usage_context,
            "security_classification": self.security_classification,
            "classification_reasoning": self.classification_reasoning,
            "confidence": self.confidence,
            "agent_metadata": {
                "iterations": self.iterations,
                "total_tokens": self.total_tokens,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cost_usd": self.cost_usd,
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
        tracker: TokenTracker = None,
        verbose: bool = False,
        entry_points: Optional[Set[str]] = None,
        reachability: Optional[ReachabilityAnalyzer] = None,
        client: Optional[anthropic.Anthropic] = None,
    ):
        """
        Initialize the agent.

        Args:
            index: RepositoryIndex for searching code
            tracker: TokenTracker for cost tracking
            verbose: If True, print debug information
            entry_points: Set of func_ids that are entry points (optional)
            reachability: ReachabilityAnalyzer for checking user input paths (optional)
            client: Shared Anthropic client (reuse across workers to avoid FD exhaustion).
                    If not provided, creates a new one (only for standalone/test use).
        """
        self.index = index
        self.tracker = tracker or get_global_tracker()
        self.verbose = verbose
        self.tool_executor = ToolExecutor(index)
        self.entry_points = entry_points or set()
        self.reachability = reachability
        self.client = client or anthropic.Anthropic(max_retries=5)

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
        # Compute reachability info
        is_entry_point = unit_id in self.entry_points
        reachable_from_entry: Optional[bool] = None
        entry_point_path: Optional[List[str]] = None
        reaching_entry_point: Optional[str] = None

        if self.reachability:
            reachable_from_entry = self.reachability.is_reachable_from_entry_point(unit_id)
            if reachable_from_entry:
                entry_point_path = self.reachability.get_entry_point_path(unit_id)
                reaching_entry_point = self.reachability.get_reaching_entry_point(unit_id)

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

        # Initialize conversation
        messages = [{"role": "user", "content": user_prompt}]

        iterations = 0
        total_input_tokens = 0
        total_output_tokens = 0

        while iterations < MAX_ITERATIONS:
            iterations += 1

            if self.verbose:
                print(f"  Iteration {iterations}...")

            # Call Claude with rate limiting
            try:
                # Wait if we're in a global backoff period
                rate_limiter = get_rate_limiter()
                rate_limiter.wait_if_needed()

                response = self.client.messages.create(
                    model=AGENT_MODEL,
                    max_tokens=MAX_TOKENS_PER_RESPONSE,
                    system=SYSTEM_PROMPT,
                    tools=TOOL_DEFINITIONS,
                    messages=messages
                )
            except anthropic.RateLimitError as exc:
                # Report to global rate limiter so all workers back off
                retry_after = float(exc.response.headers.get("retry-after", 0))
                get_rate_limiter().report_rate_limit(retry_after)
                # Attach agent state so the caller knows how far we got
                exc.agent_state = {
                    "iteration": iterations,
                    "max_iterations": MAX_ITERATIONS,
                    "tokens_used": total_input_tokens + total_output_tokens,
                    "input_tokens": total_input_tokens,
                    "output_tokens": total_output_tokens,
                }
                raise
            except Exception as exc:
                # Attach agent state so the caller knows how far we got
                exc.agent_state = {
                    "iteration": iterations,
                    "max_iterations": MAX_ITERATIONS,
                    "tokens_used": total_input_tokens + total_output_tokens,
                    "input_tokens": total_input_tokens,
                    "output_tokens": total_output_tokens,
                }
                raise

            # Track tokens
            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens

            # Process response
            assistant_content = response.content
            stop_reason = response.stop_reason

            if self.verbose:
                # Print text blocks
                for block in assistant_content:
                    if hasattr(block, 'text'):
                        print(f"    Agent: {block.text[:200]}...")

            # Check if we're done (finish tool called or no more tool use)
            if stop_reason == "end_turn":
                # Model finished without calling finish tool
                # Return default result
                if self.verbose:
                    print("  Agent ended without calling finish tool")

                return AgentResult(
                    include_functions=[],
                    usage_context="Agent did not complete analysis",
                    security_classification="neutral",
                    classification_reasoning="Analysis incomplete",
                    confidence=0.3,
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    is_entry_point=is_entry_point,
                    reachable_from_entry=reachable_from_entry,
                    entry_point_path=entry_point_path
                )

            # Process tool calls
            tool_results = []
            finish_result = None

            for block in assistant_content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id

                    if self.verbose:
                        print(f"    Tool: {tool_name}({json.dumps(tool_input)[:100]}...)")

                    # Execute tool
                    result = self.tool_executor.execute(tool_name, tool_input)

                    if self.verbose:
                        result_preview = str(result)[:200]
                        print(f"    Result: {result_preview}...")

                    # Check for finish
                    if tool_name == "finish" and result.get("status") == "complete":
                        finish_result = result.get("result", {})
                        # Still add to tool_results for the message
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps(result)
                        })
                        break
                    else:
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps(result)
                        })

            # If finish was called, return result
            if finish_result:
                # Record token usage
                call_record = self.tracker.record_call(
                    model=AGENT_MODEL,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens
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
                )

            # Add assistant message and tool results to conversation
            messages.append({"role": "assistant", "content": assistant_content})
            
            # Only add user message with tool results if there are results
            # (empty content triggers API error: "user messages must have non-empty content")
            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            else:
                # No tool calls but model didn't end — treat as incomplete
                if self.verbose:
                    print("  No tool calls in response, treating as incomplete")
                return AgentResult(
                    include_functions=[],
                    usage_context="Agent response had no tool calls",
                    security_classification="neutral",
                    classification_reasoning="Analysis incomplete - no tool calls",
                    confidence=0.3,
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    is_entry_point=is_entry_point,
                    reachable_from_entry=reachable_from_entry,
                    entry_point_path=entry_point_path
                )

        # Max iterations reached
        if self.verbose:
            print(f"  Max iterations ({MAX_ITERATIONS}) reached")

        # Record token usage
        call_record = self.tracker.record_call(
            model=AGENT_MODEL,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens
        )

        return AgentResult(
            include_functions=[],
            usage_context="Analysis terminated - max iterations reached",
            security_classification="neutral",
            classification_reasoning="Could not complete analysis within iteration limit",
            confidence=0.2,
            iterations=iterations,
            total_tokens=total_input_tokens + total_output_tokens,
            is_entry_point=is_entry_point,
            reachable_from_entry=reachable_from_entry,
            entry_point_path=entry_point_path,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
            cost_usd=call_record.get("cost_usd", 0.0),
        )


def enhance_unit_with_agent(
    unit: dict,
    index: RepositoryIndex,
    tracker: TokenTracker = None,
    verbose: bool = False,
    entry_points: Optional[Set[str]] = None,
    reachability: Optional[ReachabilityAnalyzer] = None,
    client: Optional[anthropic.Anthropic] = None,
) -> dict:
    """
    Enhance a single unit using the agentic approach.

    Args:
        unit: Unit from dataset
        index: Repository index for searching
        tracker: Token tracker
        verbose: Print debug info
        entry_points: Set of func_ids that are entry points (optional)
        reachability: ReachabilityAnalyzer for checking user input paths (optional)
        client: Shared Anthropic client (reuse across workers to avoid FD exhaustion).

    Returns:
        Enhanced unit with agent_context field including reachability info
    """
    agent = ContextAgent(
        index=index,
        tracker=tracker,
        verbose=verbose,
        entry_points=entry_points,
        reachability=reachability,
        client=client,
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
    if result.include_functions:
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
            FILE_BOUNDARY = "\n\n// ========== File Boundary ==========\n\n"
            current_code = unit["code"]["primary_code"]
            assembled = current_code + FILE_BOUNDARY + FILE_BOUNDARY.join(additional_code)
            unit["code"]["primary_code"] = assembled

            # Update metadata
            origin = unit["code"].get("primary_origin", {})
            current_files = set(origin.get("files_included", []))
            origin["files_included"] = list(current_files | additional_files)
            origin["deps_inlined"] = True
            origin["enhanced_length"] = len(assembled)
            unit["code"]["primary_origin"] = origin

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
