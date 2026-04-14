"""
Stage 2 Finding Verifier (Enhanced)

Stage 2 of the two-stage vulnerability analysis pipeline.
Uses Opus with tool access to validate Stage 1 assessments by exploring
the codebase - searching function usages, reading definitions, and
tracing call paths.

Key Improvements:
    1. Explicit vulnerability definitions (exploitable NOW vs dangerous design)
    2. Required exploit path tracing (entry point -> sink)
    3. Consistency cross-check for similar code patterns
    4. Structured output with exploit_path field
    5. Batch verification with consistency validation

The verifier asks: "Can an attacker exploit this NOW in the current codebase?"
It validates by tracing the complete exploit path from attacker input to sink.

Available Tools:
    - search_usages: Find where a function is called
    - search_definitions: Find where a function is defined
    - read_function: Get full function code by ID
    - list_functions: List all functions in a file
    - finish: Complete verification with verdict and exploit path

Classes:
    VerificationResult: Dataclass containing verdict, exploit path, explanation
    FindingVerifier: Main verifier class with verify_result() and verify_batch() methods
"""

import json
import logging
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

import anthropic

from .llm_client import TokenTracker, get_global_tracker
from .rate_limiter import get_rate_limiter

# Null logger that discards all messages (used when no logger provided)
_null_logger = logging.getLogger("null_verifier")
_null_logger.addHandler(logging.NullHandler())
from .agentic_enhancer.repository_index import RepositoryIndex
from .agentic_enhancer.tools import ToolExecutor
from prompts.verification_prompts import (
    VERIFICATION_SYSTEM_PROMPT,
    get_verification_prompt,
    get_verification_system_prompt,
    get_consistency_check_prompt
)

# Import application context type for type hints
try:
    from context.application_context import ApplicationContext
except ImportError:
    ApplicationContext = None


VERIFIER_MODEL = "claude-opus-4-6"
MAX_ITERATIONS = 20
MAX_TOKENS_PER_RESPONSE = 4096


# Enhanced finish tool with exploit_path structure
VERIFICATION_TOOLS = [
    {
        "name": "search_usages",
        "description": "Search for all places where a function is called/used in the codebase. Use this to trace how attacker input flows through the code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to find usages of"
                }
            },
            "required": ["function_name"]
        }
    },
    {
        "name": "search_definitions",
        "description": "Search for where a function is defined. Use this to understand what a function does.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to find definition of"
                }
            },
            "required": ["function_name"]
        }
    },
    {
        "name": "read_function",
        "description": "Read the full source code of a function by its ID. Use this to analyze function behavior.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_id": {
                    "type": "string",
                    "description": "Function identifier in format 'file/path.ts:functionName'"
                }
            },
            "required": ["function_id"]
        }
    },
    {
        "name": "list_functions",
        "description": "List all functions defined in a specific file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to repository root"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "finish",
        "description": "Complete the verification with your verdict and exploit path analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agree": {
                    "type": "boolean",
                    "description": "Whether you agree with Stage 1's assessment"
                },
                "correct_finding": {
                    "type": "string",
                    "enum": ["safe", "protected", "bypassable", "vulnerable", "inconclusive"],
                    "description": "The correct finding based on exploit path analysis"
                },
                "exploit_path": {
                    "type": "object",
                    "description": "Analysis of the exploit path from attacker input to sink",
                    "properties": {
                        "entry_point": {
                            "type": ["string", "null"],
                            "description": "Where attacker input enters (null if none found)"
                        },
                        "data_flow": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Steps showing how data flows from entry to sink"
                        },
                        "sink_reached": {
                            "type": "boolean",
                            "description": "Whether attacker-controlled data reaches the vulnerable operation"
                        },
                        "attacker_control_at_sink": {
                            "type": "string",
                            "enum": ["full", "partial", "none"],
                            "description": "Level of attacker control at the dangerous operation"
                        },
                        "path_broken_at": {
                            "type": ["string", "null"],
                            "description": "Where/why the exploit path breaks (null if complete)"
                        }
                    }
                },
                "explanation": {
                    "type": "string",
                    "description": "Detailed explanation of your analysis"
                },
                "security_weakness": {
                    "type": ["string", "null"],
                    "description": "Any dangerous patterns that exist but aren't currently exploitable (optional)"
                }
            },
            "required": ["agree", "correct_finding", "explanation"]
        }
    }
]


@dataclass
class ExploitPath:
    """Structured exploit path analysis."""
    entry_point: Optional[str] = None
    data_flow: list = field(default_factory=list)
    sink_reached: bool = False
    attacker_control_at_sink: str = "none"  # "full", "partial", "none"
    path_broken_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "entry_point": self.entry_point,
            "data_flow": self.data_flow,
            "sink_reached": self.sink_reached,
            "attacker_control_at_sink": self.attacker_control_at_sink,
            "path_broken_at": self.path_broken_at
        }

    def is_complete(self) -> bool:
        """Check if exploit path is complete (exploitable)."""
        return (
            self.entry_point is not None and
            self.sink_reached and
            self.attacker_control_at_sink in ["full", "partial"] and
            self.path_broken_at is None
        )


@dataclass
class VerificationResult:
    """Result from Stage 2 verification."""
    agree: bool
    correct_finding: str
    explanation: str
    iterations: int
    total_tokens: int
    exploit_path: Optional[ExploitPath] = None
    security_weakness: Optional[str] = None

    def to_dict(self) -> dict:
        result = {
            "agree": self.agree,
            "correct_finding": self.correct_finding,
            "explanation": self.explanation,
            "iterations": self.iterations,
            "total_tokens": self.total_tokens
        }
        if self.exploit_path:
            result["exploit_path"] = self.exploit_path.to_dict()
        if self.security_weakness:
            result["security_weakness"] = self.security_weakness
        return result


@dataclass
class ConsistencyCheckResult:
    """Result from consistency cross-check."""
    pattern_identified: str
    consistent_verdict: str
    findings_updated: list
    explanation: str

    def to_dict(self) -> dict:
        return {
            "pattern_identified": self.pattern_identified,
            "consistent_verdict": self.consistent_verdict,
            "findings_updated": self.findings_updated,
            "explanation": self.explanation
        }


class FindingVerifier:
    """Validates Stage 1 assessments using Opus with tool access."""

    def __init__(
        self,
        index: RepositoryIndex,
        tracker: TokenTracker = None,
        verbose: bool = False,
        app_context: "ApplicationContext" = None,
        logger: logging.Logger = None,
        client: "anthropic.Anthropic | None" = None,
    ):
        self.index = index
        self.tracker = tracker or get_global_tracker()
        self.verbose = verbose
        self.app_context = app_context
        self.tool_executor = ToolExecutor(index)
        self.client = client or anthropic.Anthropic(max_retries=5)
        self.logger = logger or _null_logger
        self._use_logger = logger is not None

    def _log(self, level: str, msg: str, **extras):
        """Log a message, using logger if available, otherwise print if verbose."""
        if self._use_logger:
            log_func = getattr(self.logger, level, self.logger.info)
            log_func(msg, extra=extras)
        elif self.verbose:
            # Fallback to print for CLI usage
            suffix = " ".join(f"{k}={v}" for k, v in extras.items() if v is not None)
            print(f"    {msg} {suffix}" if suffix else f"    {msg}")

    def verify_result(
        self,
        code: str,
        finding: str,
        attack_vector: str,
        reasoning: str,
        files_included: list = None
    ) -> VerificationResult:
        """
        Validate a Stage 1 assessment with exploit path tracing.

        Args:
            code: The code that was assessed
            finding: Stage 1's finding
            attack_vector: Stage 1's attack vector
            reasoning: Stage 1's reasoning
            files_included: Optional list of files in context

        Returns:
            VerificationResult with verdict, exploit path, and explanation
        """
        user_prompt = get_verification_prompt(
            code=code,
            finding=finding,
            attack_vector=attack_vector,
            reasoning=reasoning,
            files_included=files_included,
            app_context=self.app_context
        )

        # Get system prompt with app context if available
        system_prompt = get_verification_system_prompt(self.app_context)

        messages = [{"role": "user", "content": user_prompt}]
        iterations = 0
        total_input_tokens = 0
        total_output_tokens = 0

        while iterations < MAX_ITERATIONS:
            iterations += 1

            self._log("debug", f"Iteration {iterations}", iterations=iterations)

            # Wait if we're in a global backoff period
            rate_limiter = get_rate_limiter()
            rate_limiter.wait_if_needed()

            try:
                response = self.client.messages.create(
                    model=VERIFIER_MODEL,
                    max_tokens=MAX_TOKENS_PER_RESPONSE,
                    system=system_prompt,
                    tools=VERIFICATION_TOOLS,
                    messages=messages
                )
            except anthropic.RateLimitError as exc:
                # Report to global rate limiter so all workers back off
                retry_after = float(exc.response.headers.get("retry-after", 0))
                get_rate_limiter().report_rate_limit(retry_after)
                raise

            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens

            assistant_content = response.content
            stop_reason = response.stop_reason

            # If model finished without calling finish tool, try to parse response
            if stop_reason == "end_turn":
                result = self._try_parse_text_response(
                    assistant_content, finding, iterations,
                    total_input_tokens, total_output_tokens
                )
                if result:
                    return result

                # Default: agree with Stage 1
                return VerificationResult(
                    agree=True,
                    correct_finding=finding,
                    explanation="Verification incomplete",
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens
                )

            # Process tool calls
            tool_results = []
            finish_result = None

            for block in assistant_content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id

                    self._log("debug", f"Tool call: {tool_name}")

                    if tool_name == "finish":
                        finish_result = tool_input
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps({"status": "complete"})
                        })
                        break
                    else:
                        result = self.tool_executor.execute(tool_name, tool_input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps(result)
                        })

            if finish_result:
                self.tracker.record_call(
                    model=VERIFIER_MODEL,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens
                )
                return self._parse_finish_result(
                    finish_result, finding, iterations,
                    total_input_tokens + total_output_tokens
                )

            messages.append({"role": "assistant", "content": assistant_content})
            messages.append({"role": "user", "content": tool_results})

        # Max iterations reached
        self.tracker.record_call(
            model=VERIFIER_MODEL,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens
        )
        return VerificationResult(
            agree=True,
            correct_finding=finding,
            explanation="Max iterations reached",
            iterations=iterations,
            total_tokens=total_input_tokens + total_output_tokens
        )

    def verify_batch(
        self,
        results: list,
        code_by_route: dict,
        progress_callback: Optional[Callable] = None,
        workers: int = 10,
        checkpoint=None,
        restored_callback: Optional[Callable] = None,
    ) -> list:
        """
        Verify a batch of results with consistency cross-check.

        Uses ThreadPoolExecutor for parallel verification when workers > 1.
        Supports checkpoint/resume via the checkpoint parameter.

        Args:
            results: List of Stage 1 results to verify
            code_by_route: Dict mapping route_key to code
            progress_callback: Optional callback(unit_id, detail, unit_elapsed)
                called after each finding is verified.
            workers: Number of parallel workers (default: 10).
            checkpoint: Optional StepCheckpoint instance for resume support.
            restored_callback: Optional callback(count) called after checkpoint
                loading with the number of restored units.

        Returns:
            Updated results with verification and consistency check
        """
        total = len(results)

        # Load checkpoint state
        checkpointed = {}
        if checkpoint is not None:
            checkpointed = checkpoint.load()

        def _cp_is_error(cp_data):
            """A verify checkpoint is errored if verification is missing/empty
            or correct_finding == 'error'."""
            if not cp_data:
                return True
            v = cp_data.get("verification", {})
            if not v:
                return True
            return v.get("correct_finding") == "error"

        # Separate already-done (successful) from to-do (new + errored)
        results_to_verify = []
        _restored_ok = 0
        for r in results:
            key = r.get("unit_id") or r.get("route_key", "unknown")
            cp_data = checkpointed.get(key)
            if cp_data and not _cp_is_error(cp_data):
                # Restore verification data from checkpoint
                if "verification" in cp_data:
                    r["verification"] = cp_data["verification"]
                if "finding" in cp_data:
                    r["finding"] = cp_data["finding"]
                if "verification_note" in cp_data:
                    r["verification_note"] = cp_data["verification_note"]
                _restored_ok += 1
            else:
                # Either no checkpoint, or an errored one — re-verify
                results_to_verify.append(r)

        if _restored_ok:
            print(f"[Verify] Restored {_restored_ok} findings from checkpoints",
                  file=sys.stderr, flush=True)
            if restored_callback:
                restored_callback(_restored_ok)
        errored_retries = len(checkpointed) - _restored_ok
        if errored_retries:
            print(f"[Verify] Retrying {errored_retries} previously errored findings",
                  file=sys.stderr, flush=True)

        # Initialize summary tracking for _summary.json
        _summary_completed = _restored_ok
        _summary_errors = 0
        _summary_error_breakdown = {}
        _summary_input_tokens = 0
        _summary_output_tokens = 0
        _summary_cost_usd = 0.0

        # Sum usage from ALL existing checkpoints (including errored ones
        # — their cost was already spent in a prior run)
        for _key, _cp in checkpointed.items():
            _cp_usage = _cp.get("usage", {})
            _summary_input_tokens += _cp_usage.get("input_tokens", 0)
            _summary_output_tokens += _cp_usage.get("output_tokens", 0)
            _summary_cost_usd += _cp_usage.get("cost_usd", 0.0)

        def _usage_dict():
            return {"input_tokens": _summary_input_tokens,
                    "output_tokens": _summary_output_tokens,
                    "cost_usd": round(_summary_cost_usd, 6)}

        # Inject prior usage into tracker so step_report captures the total
        if _summary_input_tokens or _summary_output_tokens:
            self.tracker.add_prior_usage(
                _summary_input_tokens, _summary_output_tokens, _summary_cost_usd)

        if checkpoint is not None:
            checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                     _summary_error_breakdown, phase="in_progress",
                                     usage=_usage_dict())

        def _summary_callback(detail, usage=None):
            """Update summary counters after each unit. Called from main thread."""
            nonlocal _summary_completed, _summary_errors, _summary_error_breakdown
            nonlocal _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
            if detail == "error":
                _summary_errors += 1
                _summary_error_breakdown["api"] = _summary_error_breakdown.get("api", 0) + 1
            else:
                _summary_completed += 1
            if usage:
                _summary_input_tokens += usage.get("input_tokens", 0)
                _summary_output_tokens += usage.get("output_tokens", 0)
                _summary_cost_usd += usage.get("cost_usd", 0.0)
            if checkpoint is not None:
                checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                         _summary_error_breakdown, phase="in_progress",
                                         usage=_usage_dict())

        remaining = len(results_to_verify)
        mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
        print(f"[Verify] Mode: {mode}, {remaining} findings to verify "
              f"({len(checkpointed)} already done)", file=sys.stderr, flush=True)

        if workers <= 1:
            self._verify_batch_sequential(
                results_to_verify, code_by_route, progress_callback, checkpoint,
                summary_callback=_summary_callback)
        else:
            self._verify_batch_parallel(
                results_to_verify, code_by_route, progress_callback, workers, checkpoint,
                summary_callback=_summary_callback)

        # Write final summary with phase="done"
        if checkpoint is not None:
            checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                     _summary_error_breakdown, phase="done",
                                     usage=_usage_dict())

        # Step 2: Consistency cross-check (barrier — needs all results)
        results = self._check_consistency(results, code_by_route)

        return results

    def _verify_one(self, result, code_by_route):
        """Verify a single result. Returns (route_key, detail, elapsed, worker, usage).

        Mutates the result dict in-place (each result is unique, no contention).
        """
        route_key = result.get("route_key", "unknown")
        stage1_finding = result.get("finding", "inconclusive")
        worker = threading.current_thread().name

        self.tracker.start_unit_tracking()
        unit_start = time.monotonic()
        detail = ""
        try:
            code = code_by_route.get(route_key, "")
            verification = self.verify_result(
                code=code,
                finding=stage1_finding,
                attack_vector=result.get("attack_vector"),
                reasoning=result.get("reasoning", ""),
                files_included=result.get("files_included", [])
            )

            result["verification"] = verification.to_dict()

            if verification.agree:
                detail = f"agreed:{verification.correct_finding}"
                self._log("info", f"Verification agreed: {verification.correct_finding}",
                          unit_id=route_key, total_tokens=verification.total_tokens,
                          iterations=verification.iterations)
            else:
                detail = f"disagreed:{stage1_finding}->{verification.correct_finding}"
                result["finding"] = verification.correct_finding
                result["verification_note"] = f"Changed from {stage1_finding} to {verification.correct_finding}"
                self._log("info", f"Verification disagreed: {stage1_finding} -> {verification.correct_finding}",
                          unit_id=route_key, total_tokens=verification.total_tokens,
                          iterations=verification.iterations)

        except Exception as e:
            detail = "error"
            print(f"[Verify] ERROR {route_key}: {type(e).__name__}: {e}", file=sys.stderr, flush=True)

        unit_elapsed = time.monotonic() - unit_start
        usage = self.tracker.get_unit_usage()
        return route_key, detail, unit_elapsed, worker, usage

    def _verify_batch_sequential(self, results, code_by_route, progress_callback,
                                 checkpoint=None, summary_callback=None):
        """Verify all results sequentially."""
        try:
            for i, result in enumerate(results):
                route_key = result.get("route_key", "unknown")
                stage1_finding = result.get("finding", "inconclusive")
                self._log("info", f"Verifying finding {i+1}/{len(results)}",
                          unit_id=route_key, classification=stage1_finding)

                route_key, detail, unit_elapsed, _worker, usage = self._verify_one(result, code_by_route)
                if checkpoint is not None:
                    key = result.get("unit_id") or route_key
                    cp_data = {
                        "verification": result.get("verification", {}),
                        "finding": result.get("finding", ""),
                        "verification_note": result.get("verification_note", ""),
                    }
                    if usage:
                        cp_data["usage"] = usage
                    checkpoint.save(key, cp_data)
                if summary_callback:
                    summary_callback(detail, usage=usage)
                if progress_callback:
                    progress_callback(route_key, detail, unit_elapsed)
        except KeyboardInterrupt:
            print("[Verify] Interrupted — progress saved to checkpoints",
                  file=sys.stderr, flush=True)

    def _verify_batch_parallel(self, results, code_by_route, progress_callback, workers,
                                checkpoint=None, summary_callback=None):
        """Verify all results in parallel using ThreadPoolExecutor."""
        executor = ThreadPoolExecutor(max_workers=workers)
        future_to_result = {}
        for result in results:
            future = executor.submit(self._verify_one, result, code_by_route)
            future_to_result[future] = result

        try:
            for future in as_completed(future_to_result):
                result = future_to_result[future]
                route_key, detail, unit_elapsed, worker, usage = future.result()
                if checkpoint is not None:
                    key = result.get("unit_id") or route_key
                    cp_data = {
                        "verification": result.get("verification", {}),
                        "finding": result.get("finding", ""),
                        "verification_note": result.get("verification_note", ""),
                    }
                    if usage:
                        cp_data["usage"] = usage
                    checkpoint.save(key, cp_data)
                if summary_callback:
                    summary_callback(detail, usage=usage)
                if progress_callback:
                    progress_callback(route_key, f"{detail}  [{worker}]", unit_elapsed)
        except KeyboardInterrupt:
            print("[Verify] Interrupted — cancelling pending work...",
                  file=sys.stderr, flush=True)
            executor.shutdown(wait=False, cancel_futures=True)
            print("[Verify] Progress saved to checkpoints",
                  file=sys.stderr, flush=True)
            return
        executor.shutdown(wait=False)

    def _check_consistency(
        self,
        results: list,
        code_by_route: dict
    ) -> list:
        """
        Check for inconsistent verdicts among similar code patterns.

        Groups findings by code pattern similarity and ensures consistent verdicts.

        IMPORTANT: Does NOT override findings that have conclusive exploit path analysis
        showing the path is broken (sink_reached=false, attacker_control=none, or path_broken_at set).
        """
        # Group by vulnerability pattern (simplified: by file and function type)
        pattern_groups = self._group_by_pattern(results)

        inconsistent_groups = []
        for pattern, group in pattern_groups.items():
            if len(group) < 2:
                continue

            verdicts = set(r.get("verification", {}).get("correct_finding") or r.get("finding") for r in group)
            if len(verdicts) > 1:
                inconsistent_groups.append((pattern, group))

        if not inconsistent_groups:
            self._log("info", "Consistency check: All similar patterns have consistent verdicts")
            return results

        # Fix inconsistencies
        for pattern, group in inconsistent_groups:
            verdicts = [r.get("verification", {}).get("correct_finding") or r.get("finding") for r in group]
            self._log("warning", f"Inconsistency detected in pattern: {pattern}",
                      details={"findings": [r.get('route_key') for r in group], "verdicts": verdicts})

            # Run consistency check
            consistency_result = self._resolve_inconsistency(group, code_by_route)

            if consistency_result:
                # Apply consistent verdict, but respect exploit path analysis
                for finding_update in consistency_result.findings_updated:
                    route_key = finding_update.get("route_key")
                    new_verdict = finding_update.get("should_be")

                    for result in results:
                        if result.get("route_key") == route_key:
                            # Check if this result has conclusive exploit path analysis
                            if self._has_conclusive_exploit_path(result):
                                self._log("debug", f"Skipping {route_key}: has conclusive exploit path analysis",
                                          unit_id=route_key)
                                continue

                            old_verdict = result.get("verification", {}).get("correct_finding") or result.get("finding")
                            if old_verdict != new_verdict:
                                result["finding"] = new_verdict
                                if "verification" not in result:
                                    result["verification"] = {}
                                result["verification"]["correct_finding"] = new_verdict
                                result["consistency_update"] = {
                                    "from": old_verdict,
                                    "to": new_verdict,
                                    "reason": finding_update.get("reason"),
                                    "pattern": consistency_result.pattern_identified
                                }
                                self._log("info", f"Consistency update: {old_verdict} -> {new_verdict}",
                                          unit_id=route_key)

        return results

    def _has_conclusive_exploit_path(self, result: dict) -> bool:
        """
        Check if a result has conclusive exploit path analysis that should not be overridden.

        A conclusive exploit path analysis is one where:
        1. The exploit path was analyzed (not just max iterations reached)
        2. The path shows either:
           - sink_reached = false (attacker data doesn't reach the sink)
           - attacker_control_at_sink = "none" (no control at sink)
           - path_broken_at is set (explicit explanation of where path breaks)

        These findings are based on detailed code analysis and should not be
        overridden by superficial pattern matching.
        """
        verification = result.get("verification", {})

        # If max iterations was reached, the analysis is not conclusive
        if verification.get("explanation") == "Max iterations reached":
            return False

        # Check for exploit path analysis
        exploit_path = verification.get("exploit_path")
        if not exploit_path:
            return False

        # Check if the exploit path analysis shows the path is broken
        sink_reached = exploit_path.get("sink_reached", True)
        attacker_control = exploit_path.get("attacker_control_at_sink", "unknown")
        path_broken_at = exploit_path.get("path_broken_at")

        # Conclusive if: path is broken OR sink not reached OR no attacker control
        if not sink_reached:
            return True
        if attacker_control == "none":
            return True
        if path_broken_at:
            return True

        return False

    def _group_by_pattern(self, results: list) -> dict:
        """Group results by code pattern for consistency checking."""
        groups = {}

        for result in results:
            # Extract pattern key from route_key
            route_key = result.get("route_key", "")

            # Group by file and function signature pattern
            # e.g., "pkg/logger/console.go:*Msg.json" groups all json methods
            if ":" in route_key:
                file_part, func_part = route_key.rsplit(":", 1)

                # Normalize function name to find similar patterns
                # e.g., "errorMsg.json" and "infoMsg.json" -> "*Msg.json"
                normalized_func = re.sub(r'^[a-z]+Msg', '*Msg', func_part)
                pattern_key = f"{file_part}:{normalized_func}"
            else:
                pattern_key = route_key

            if pattern_key not in groups:
                groups[pattern_key] = []
            groups[pattern_key].append(result)

        return groups

    def _resolve_inconsistency(
        self,
        group: list,
        code_by_route: dict
    ) -> Optional[ConsistencyCheckResult]:
        """
        Use LLM to resolve inconsistent verdicts for similar code patterns.
        """
        prompt = get_consistency_check_prompt(group, code_by_route)

        try:
            # Wait if we're in a global backoff period
            rate_limiter = get_rate_limiter()
            rate_limiter.wait_if_needed()

            response = self.client.messages.create(
                model=VERIFIER_MODEL,
                max_tokens=MAX_TOKENS_PER_RESPONSE,
                system="You are checking verdict consistency across similar code patterns.",
                messages=[{"role": "user", "content": prompt}]
            )

            self.tracker.record_call(
                model=VERIFIER_MODEL,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens
            )

            # Parse response
            text = response.content[0].text if response.content else ""
            result = self._parse_json_from_text(text)

            if result:
                return ConsistencyCheckResult(
                    pattern_identified=result.get("pattern_identified", "unknown"),
                    consistent_verdict=result.get("consistent_verdict", "inconclusive"),
                    findings_updated=result.get("findings_to_update", []),
                    explanation=result.get("explanation", "")
                )

        except anthropic.RateLimitError as e:
            # Report to global rate limiter so all workers back off
            retry_after = float(e.response.headers.get("retry-after", 0))
            get_rate_limiter().report_rate_limit(retry_after)
            self._log("error", f"Consistency resolution rate limited", error=str(e))
        except Exception as e:
            self._log("error", f"Consistency resolution failed", error=str(e))

        return None

    def _parse_finish_result(
        self,
        finish_result: dict,
        original_finding: str,
        iterations: int,
        total_tokens: int
    ) -> VerificationResult:
        """Parse the finish tool result into VerificationResult."""
        # Parse exploit path if present
        exploit_path = None
        if "exploit_path" in finish_result and finish_result["exploit_path"]:
            ep = finish_result["exploit_path"]
            exploit_path = ExploitPath(
                entry_point=ep.get("entry_point"),
                data_flow=ep.get("data_flow", []),
                sink_reached=ep.get("sink_reached", False),
                attacker_control_at_sink=ep.get("attacker_control_at_sink", "none"),
                path_broken_at=ep.get("path_broken_at")
            )

        return VerificationResult(
            agree=finish_result.get("agree", True),
            correct_finding=finish_result.get("correct_finding", original_finding),
            explanation=finish_result.get("explanation", ""),
            iterations=iterations,
            total_tokens=total_tokens,
            exploit_path=exploit_path,
            security_weakness=finish_result.get("security_weakness")
        )

    def _try_parse_text_response(
        self,
        assistant_content: list,
        original_finding: str,
        iterations: int,
        total_input_tokens: int,
        total_output_tokens: int
    ) -> Optional[VerificationResult]:
        """Try to parse a text response as JSON."""
        for block in assistant_content:
            if hasattr(block, 'text'):
                result = self._parse_json_from_text(block.text)
                if result:
                    self.tracker.record_call(
                        model=VERIFIER_MODEL,
                        input_tokens=total_input_tokens,
                        output_tokens=total_output_tokens
                    )
                    return self._parse_finish_result(
                        result, original_finding, iterations,
                        total_input_tokens + total_output_tokens
                    )
        return None

    def _parse_json_from_text(self, text: str) -> Optional[dict]:
        """Extract JSON object from text, with LLM correction fallback."""
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

        # Fallback: use LLM to correct malformed JSON
        if text.strip():
            try:
                from utilities.json_corrector import JSONCorrector
                corrector = JSONCorrector(self.client)
                corrected = corrector.attempt_correction(text)
                if corrected.get("verdict") != "ERROR":
                    corrected["json_corrected"] = True
                    return corrected
            except Exception:
                pass
        return None
