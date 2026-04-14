"""
Context Enhancer

Uses Claude Sonnet to enhance the static analysis output from the JavaScript parser.
Identifies missing dependencies, additional callers, and extracts data flow information.

Supports two modes:
1. Single-shot (default): Fast, one prompt per unit
2. Agentic (--agentic): Iterative exploration with tool use, traces call paths

This replaces the JavaScript LLM integration in unit_generator.js and llm_context_analyzer.js.
All LLM calls are now centralized in Python.
"""

import json
import argparse
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

import anthropic

from .llm_client import AnthropicClient, TokenTracker, get_global_tracker, reset_global_tracker
from .agentic_enhancer import RepositoryIndex, enhance_unit_with_agent, load_index_from_file
from .rate_limiter import get_rate_limiter, is_rate_limit_error, is_retryable_error

# Avoid circular import — import checkpoint at usage site
_StepCheckpoint = None
def _get_step_checkpoint():
    global _StepCheckpoint
    if _StepCheckpoint is None:
        from core.checkpoint import StepCheckpoint
        _StepCheckpoint = StepCheckpoint
    return _StepCheckpoint


# Null logger that discards all messages (used when no logger provided)
_null_logger = logging.getLogger("null")
_null_logger.addHandler(logging.NullHandler())


# Use Sonnet for context enhancement (cost-effective auxiliary task)
CONTEXT_ENHANCEMENT_MODEL = "claude-sonnet-4-20250514"


def _build_error_info(exc: Exception) -> dict:
    """Build a structured error dict from an exception.

    Captures exception type, message, HTTP status, request ID, and
    any agent iteration state attached by agent.py.
    """
    info = {
        "type": "unknown",
        "exception_class": type(exc).__name__,
        "message": str(exc),
    }

    # Anthropic SDK specific exceptions
    if isinstance(exc, anthropic.APIConnectionError):
        info["type"] = "connection"
    elif isinstance(exc, anthropic.APITimeoutError):
        info["type"] = "timeout"
    elif isinstance(exc, anthropic.RateLimitError):
        info["type"] = "rate_limit"
        info["status_code"] = exc.status_code
        if hasattr(exc, "response") and exc.response is not None:
            info["request_id"] = exc.response.headers.get("request-id")
            retry_after = exc.response.headers.get("retry-after")
            if retry_after:
                info["retry_after"] = retry_after
    elif isinstance(exc, anthropic.APIStatusError):
        info["type"] = "api_status"
        info["status_code"] = exc.status_code
        if hasattr(exc, "response") and exc.response is not None:
            info["request_id"] = exc.response.headers.get("request-id")

    # Agent iteration state (attached by agent.py)
    agent_state = getattr(exc, "agent_state", None)
    if agent_state:
        info["agent_state"] = agent_state

    return info


def get_context_enhancement_prompt(
    function_id: str,
    function_name: str,
    function_code: str,
    unit_type: str,
    class_name: Optional[str],
    static_deps: list[str],
    static_callers: list[str],
    context_functions: list[dict]
) -> str:
    """
    Generate a prompt for the LLM to enhance function context.

    Args:
        function_id: Unique identifier (file:functionName)
        function_name: Function name
        function_code: The function's source code
        unit_type: Type classification (route_handler, middleware, etc.)
        class_name: Class name if method, else None
        static_deps: Dependencies identified by static analysis
        static_callers: Callers identified by static analysis
        context_functions: Other functions in the same file
    """
    deps_list = "\n".join(f"- {d}" for d in static_deps) if static_deps else "- None identified"
    callers_list = "\n".join(f"- {c}" for c in static_callers) if static_callers else "- None identified"

    context_section = ""
    if context_functions:
        context_section = "## Other Functions in Same File\n"
        for f in context_functions[:5]:  # Limit to 5 to avoid token overflow
            context_section += f"### {f.get('name', 'unknown')} ({f.get('unit_type', 'function')})\n"
            code_preview = f.get('code', '')[:200]
            if len(f.get('code', '')) > 200:
                code_preview += '...'
            context_section += f"```javascript\n{code_preview}\n```\n\n"
    else:
        context_section = "## Other Functions in Same File\nNo other functions in file.\n"

    return f"""You are analyzing a JavaScript/TypeScript function to identify all relevant context needed for security analysis.

## Target Function
**ID:** `{function_id}`
**Name:** `{function_name}`
**Type:** {unit_type}
{f'**Class:** {class_name}' if class_name else ''}

```javascript
{function_code}
```

## Static Analysis Results
**Already identified dependencies (functions called):**
{deps_list}

**Already identified callers (functions that call this):**
{callers_list}

{context_section}

## Your Task
Analyze this function and identify:

1. **Missing Dependencies**: Functions called in the code that static analysis missed
2. **Additional Callers**: Functions that likely call this function based on naming patterns
3. **Data Flow**: What data flows in and out, especially security-relevant data
4. **Imports**: External modules/files this function depends on

## Response Format
Respond with JSON only:

```json
{{
  "missing_dependencies": [
    {{"name": "functionName", "reason": "why this was missed", "likely_location": "file.ts or module"}}
  ],
  "additional_callers": [
    {{"name": "callerName", "reason": "why this likely calls the target"}}
  ],
  "data_flow": {{
    "inputs": ["req.body", "req.params.id", "etc"],
    "outputs": ["res.json(...)", "database write", "etc"],
    "tainted_variables": ["userInput", "unsanitized vars"],
    "security_relevant_flows": [
      {{"source": "req.body.query", "sink": "sql.query()", "type": "potential SQL injection"}}
    ]
  }},
  "imports": [
    {{"module": "express", "used_for": "routing"}},
    {{"module": "./utils", "used_for": "helper functions"}}
  ],
  "reasoning": "Brief explanation of your analysis",
  "confidence": 0.0-1.0
}}
```"""


class ContextEnhancer:
    """
    Enhances static analysis output with LLM-identified context.
    Uses Claude Sonnet for cost-effective context gathering.
    Tracks token usage and costs for all LLM calls.
    """

    def __init__(
        self,
        client: AnthropicClient = None,
        tracker: TokenTracker = None,
        logger: logging.Logger = None
    ):
        """
        Initialize the enhancer.

        Args:
            client: Anthropic client instance. Creates one if not provided.
            tracker: Token tracker instance. Uses global tracker if not provided.
            logger: Optional logger for structured logging. If not provided, uses print().
        """
        self.tracker = tracker or get_global_tracker()
        self.client = client or AnthropicClient(model=CONTEXT_ENHANCEMENT_MODEL, tracker=self.tracker)
        self.logger = logger or _null_logger
        self._use_logger = logger is not None
        self.stats = {
            "units_processed": 0,
            "units_enhanced": 0,
            "dependencies_added": 0,
            "callers_added": 0,
            "data_flows_extracted": 0,
            "errors": 0
        }

    def _log(self, level: str, msg: str, **extras):
        """Log a message, using logger if available, otherwise print to stderr."""
        if self._use_logger:
            log_func = getattr(self.logger, level, self.logger.info)
            log_func(msg, extra=extras)
        else:
            # Fallback to stderr for CLI usage (stdout is reserved for JSON envelope)
            suffix = " ".join(f"{k}={v}" for k, v in extras.items() if v is not None)
            print(f"{msg} {suffix}" if suffix else msg, file=sys.stderr)

    def enhance_unit(self, unit: dict, all_units: dict) -> dict:
        """
        Enhance a single analysis unit with LLM-identified context.

        Args:
            unit: The analysis unit to enhance
            all_units: Dict of all units keyed by ID (for context lookup)

        Returns:
            Enhanced unit with data_flow field populated
        """
        self.stats["units_processed"] += 1

        function_id = unit.get("id", "unknown")
        code_section = unit.get("code", {})

        # Extract info for prompt
        function_name = code_section.get("primary_origin", {}).get("function_name", "unknown")
        function_code = code_section.get("primary_code", "")
        unit_type = unit.get("unit_type", "function")
        class_name = code_section.get("primary_origin", {}).get("class_name")

        # Get static analysis results
        static_deps = unit.get("metadata", {}).get("direct_calls", [])
        static_callers = unit.get("metadata", {}).get("direct_callers", [])

        # Gather context functions from same file
        file_path = code_section.get("primary_origin", {}).get("file_path", "")
        context_functions = []
        for other_id, other_unit in all_units.items():
            if other_id == function_id:
                continue
            other_file = other_unit.get("code", {}).get("primary_origin", {}).get("file_path", "")
            if other_file == file_path:
                context_functions.append({
                    "id": other_id,
                    "name": other_unit.get("code", {}).get("primary_origin", {}).get("function_name", "unknown"),
                    "code": other_unit.get("code", {}).get("primary_code", ""),
                    "unit_type": other_unit.get("unit_type", "function")
                })

        # Build and send prompt
        prompt = get_context_enhancement_prompt(
            function_id=function_id,
            function_name=function_name,
            function_code=function_code,
            unit_type=unit_type,
            class_name=class_name,
            static_deps=static_deps,
            static_callers=static_callers,
            context_functions=context_functions
        )

        try:
            response = self.client.analyze_sync(
                prompt,
                max_tokens=4096,
                model=CONTEXT_ENHANCEMENT_MODEL
            )
            analysis = self._parse_json_response(response)

            if analysis:
                self.stats["units_enhanced"] += 1

                # Count new items
                new_deps = len(analysis.get("missing_dependencies", []))
                new_callers = len(analysis.get("additional_callers", []))
                self.stats["dependencies_added"] += new_deps
                self.stats["callers_added"] += new_callers

                if analysis.get("data_flow", {}).get("security_relevant_flows"):
                    self.stats["data_flows_extracted"] += 1

                # Add enhancement to unit
                unit["llm_context"] = {
                    "missing_dependencies": analysis.get("missing_dependencies", []),
                    "additional_callers": analysis.get("additional_callers", []),
                    "data_flow": analysis.get("data_flow", {}),
                    "imports": analysis.get("imports", []),
                    "reasoning": analysis.get("reasoning", ""),
                    "confidence": analysis.get("confidence", 0.5)
                }
            else:
                unit["llm_context"] = self._get_default_context()

        except Exception as e:
            self.stats["errors"] += 1
            self._log("error", f"Error enhancing unit", unit_id=function_id, error=str(e))
            unit["llm_context"] = self._get_default_context()

        return unit

    def enhance_dataset(
        self,
        dataset: dict,
        batch_size: int = 10,
        progress_callback: Optional[Callable] = None,
        workers: int = 10,
    ) -> dict:
        """
        Enhance all units in a dataset (single-shot mode).

        Uses ThreadPoolExecutor for parallel processing when workers > 1.

        Args:
            dataset: The dataset from unit_generator.js
            batch_size: Number of units to process before printing progress
            progress_callback: Optional callback(unit_id, classification, unit_elapsed)
                called after each unit completes.
            workers: Number of parallel workers (default: 10).

        Returns:
            Enhanced dataset
        """
        units = dataset.get("units", [])
        total = len(units)

        self._log("info", f"Enhancing {total} units with LLM context (single-shot mode)", units=total)
        self._log("info", f"Model: {CONTEXT_ENHANCEMENT_MODEL}")
        mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
        self._log("info", f"Mode: {mode}")

        # Build lookup dict for context gathering
        units_by_id = {u.get("id"): u for u in units}

        def _process_one(unit):
            """Process a single unit. Mutates unit in-place."""
            unit_start = time.monotonic()
            self.enhance_unit(unit, units_by_id)
            unit_elapsed = time.monotonic() - unit_start
            ctx = unit.get("llm_context", {})
            classification = ctx.get("confidence", "unknown")
            worker = threading.current_thread().name
            return unit.get("id", "?"), str(classification), unit_elapsed, worker

        if workers <= 1:
            for unit in units:
                uid, classification, elapsed, _worker = _process_one(unit)
                if progress_callback:
                    progress_callback(uid, classification, elapsed)
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(_process_one, unit): unit for unit in units}
                for future in as_completed(futures):
                    uid, classification, elapsed, worker = future.result()
                    if progress_callback:
                        progress_callback(uid, f"{classification}  [{worker}]", elapsed)

        # Recompute stats from unit results (thread-safe)
        self.stats = {
            "units_processed": 0,
            "units_enhanced": 0,
            "dependencies_added": 0,
            "callers_added": 0,
            "data_flows_extracted": 0,
            "errors": 0,
        }
        for unit in units:
            ctx = unit.get("llm_context", {})
            self.stats["units_processed"] += 1
            if ctx.get("reasoning") != "LLM analysis failed, using static analysis only":
                self.stats["units_enhanced"] += 1
                self.stats["dependencies_added"] += len(ctx.get("missing_dependencies", []))
                self.stats["callers_added"] += len(ctx.get("additional_callers", []))
                if ctx.get("data_flow", {}).get("security_relevant_flows"):
                    self.stats["data_flows_extracted"] += 1
            if ctx.get("confidence", 1.0) <= 0.3 and ctx.get("reasoning", "").startswith("LLM analysis failed"):
                self.stats["errors"] += 1

        # Get token usage stats
        token_stats = self.tracker.get_totals()

        # Update dataset metadata
        dataset["metadata"] = dataset.get("metadata", {})
        dataset["metadata"]["llm_enhanced"] = True
        dataset["metadata"]["llm_model"] = CONTEXT_ENHANCEMENT_MODEL
        dataset["metadata"]["enhancement_stats"] = self.stats
        dataset["metadata"]["token_usage"] = token_stats

        self._log("info", "Enhancement complete",
                  units=self.stats['units_processed'],
                  details={
                      "units_enhanced": self.stats['units_enhanced'],
                      "dependencies_added": self.stats['dependencies_added'],
                      "callers_added": self.stats['callers_added'],
                      "data_flows_extracted": self.stats['data_flows_extracted'],
                      "errors": self.stats['errors']
                  })
        self._log("info", "Token usage",
                  input_tokens=token_stats['total_input_tokens'],
                  output_tokens=token_stats['total_output_tokens'],
                  total_tokens=token_stats['total_tokens'],
                  cost=f"${token_stats['total_cost_usd']:.4f}")

        return dataset

    def enhance_dataset_agentic(
        self,
        dataset: dict,
        analyzer_output_path: str,
        repo_path: str = None,
        batch_size: int = 5,
        verbose: bool = False,
        checkpoint_path: str = None,
        progress_callback: Optional[Callable] = None,
        restored_callback: Optional[Callable] = None,
        workers: int = 10,
    ) -> dict:
        """
        Enhance all units using agentic approach with tool use.

        This mode traces call paths iteratively to understand code intent.
        More accurate but slower and more expensive than single-shot mode.

        Uses ThreadPoolExecutor for parallel processing when workers > 1.

        Supports checkpoint/resume: if checkpoint_path is provided, each completed
        unit is saved to a separate file under a checkpoints directory. On resume,
        completed units are loaded from their individual checkpoint files.

        Args:
            dataset: The dataset from unit_generator.js
            analyzer_output_path: Path to analyzer_output.json
            repo_path: Repository root path (for file reading)
            batch_size: Number of units to process before printing progress
            verbose: Print debug information
            checkpoint_path: Path to checkpoint directory (enables resume).
                If provided, per-unit results are saved under this directory.
            progress_callback: Optional callback(unit_id, classification, unit_elapsed)
                called after each unit completes.
            restored_callback: Optional callback(count) called after checkpoint
                loading with the number of restored units.
            workers: Number of parallel workers (default: 10).

        Returns:
            Enhanced dataset with agent_context field
        """
        units = dataset.get("units", [])
        total = len(units)

        # Checkpoint directory setup
        checkpoint_dir = None
        processed_ids = set()
        if checkpoint_path:
            # Use checkpoint_path as a directory for per-unit files
            checkpoint_dir = checkpoint_path if os.path.isdir(checkpoint_path) or not checkpoint_path.endswith(".json") else os.path.splitext(checkpoint_path)[0] + "_checkpoints"
            os.makedirs(checkpoint_dir, exist_ok=True)

            # Check for legacy single-file checkpoint and migrate
            if os.path.isfile(checkpoint_path) and checkpoint_path.endswith(".json"):
                self._migrate_legacy_checkpoint(checkpoint_path, checkpoint_dir, units)

            # Load completed unit IDs from per-unit checkpoint files
            processed_ids = self._load_completed_units(checkpoint_dir)

            # Restore agent_context from checkpoint files into units
            for unit in units:
                unit_id = unit.get("id")
                if unit_id in processed_ids:
                    cp_file = os.path.join(checkpoint_dir, f"{self._safe_filename(unit_id)}.json")
                    if os.path.exists(cp_file):
                        with open(cp_file, 'r') as f:
                            cp_data = json.load(f)
                        unit["agent_context"] = cp_data.get("agent_context", {})
                        if "code" in cp_data:
                            unit["code"] = cp_data["code"]

            if processed_ids:
                self._log("info", f"Restored {len(processed_ids)} already-processed units from checkpoints", units=len(processed_ids))
                if restored_callback:
                    restored_callback(len(processed_ids))

        # Initialize summary tracking for _summary.json
        # Counts are updated in the main thread (as_completed loop) — no lock needed.
        _summary_cp = None
        _summary_completed = len(processed_ids)
        _summary_errors = 0
        _summary_error_breakdown = {}
        _summary_input_tokens = 0
        _summary_output_tokens = 0
        _summary_cost_usd = 0.0

        if checkpoint_dir:
            SC = _get_step_checkpoint()
            _summary_cp = SC.__new__(SC)
            _summary_cp.step_name = "enhance"
            _summary_cp.dir = checkpoint_dir

            # Count errors and sum usage from already-loaded checkpoints
            for unit in units:
                uid = unit.get("id", "")
                cp_file = os.path.join(checkpoint_dir, f"{self._safe_filename(uid)}.json")
                if not os.path.exists(cp_file):
                    continue
                try:
                    with open(cp_file, 'r') as f:
                        cp_data = json.load(f)
                    # Sum usage from all existing checkpoints (completed + errored)
                    cp_usage = cp_data.get("usage", {})
                    _summary_input_tokens += cp_usage.get("input_tokens", 0)
                    _summary_output_tokens += cp_usage.get("output_tokens", 0)
                    _summary_cost_usd += cp_usage.get("cost_usd", 0.0)
                    # Count errors for non-completed units
                    if uid not in processed_ids and cp_data.get("agent_context", {}).get("error"):
                        _summary_errors += 1
                        err = cp_data["agent_context"]["error"]
                        err_type = err.get("type", "unknown") if isinstance(err, dict) else "unknown"
                        _summary_error_breakdown[err_type] = _summary_error_breakdown.get(err_type, 0) + 1
                except (json.JSONDecodeError, OSError):
                    pass

            _summary_cp.write_summary(total, _summary_completed, _summary_errors,
                                      _summary_error_breakdown, phase="in_progress",
                                      usage={"input_tokens": _summary_input_tokens,
                                             "output_tokens": _summary_output_tokens,
                                             "cost_usd": round(_summary_cost_usd, 6)})

            # Inject prior usage into tracker so step_report captures the total
            if _summary_input_tokens or _summary_output_tokens:
                self.tracker.add_prior_usage(
                    _summary_input_tokens, _summary_output_tokens, _summary_cost_usd)

        remaining = total - len(processed_ids)
        self._log("info", f"Enhancing {remaining} units with agentic analysis ({len(processed_ids)} already done)", units=remaining)
        self._log("info", "Mode: Iterative tool use (traces call paths)")
        self._log("info", "Model: claude-sonnet-4-20250514")
        mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
        self._log("info", f"Workers: {mode}")
        if checkpoint_dir:
            self._log("info", f"Checkpoint dir: {checkpoint_dir}")

        # Load repository index
        self._log("info", f"Loading repository index from {analyzer_output_path}")
        index = load_index_from_file(analyzer_output_path, repo_path)
        stats = index.get_statistics()
        self._log("info", f"Indexed {stats['total_functions']} functions from {stats['total_files']} files")

        # Create a single shared Anthropic client for all workers.
        # Each ContextAgent previously created its own anthropic.Anthropic() instance,
        # which spawns a new httpx connection pool. With 1000+ units and 8 workers,
        # this exhausted file descriptors (macOS limit ~256). The httpx.Client
        # underlying anthropic.Anthropic is thread-safe, so sharing is correct.
        shared_client = anthropic.Anthropic(max_retries=5)

        # Filter to unprocessed units
        units_to_process = [(i, unit) for i, unit in enumerate(units) if unit.get("id") not in processed_ids]

        def _enhance_one(unit):
            """Enhance a single unit. Mutates unit in-place, returns metadata."""
            unit_id = unit.get("id")
            unit_start = time.monotonic()
            classification = "neutral"
            try:
                enhance_unit_with_agent(unit, index, self.tracker, verbose, client=shared_client)

                agent_ctx = unit.get("agent_context", {})
                classification = agent_ctx.get("security_classification", "neutral")

            except Exception as e:
                classification = "error"
                error_info = _build_error_info(e)
                self._log("error", f"Error processing unit",
                          unit_id=unit_id,
                          error=error_info.get("message", str(e)),
                          error_type=error_info.get("type", "unknown"))
                unit["agent_context"] = {
                    "error": error_info,
                    "security_classification": "neutral",
                    "confidence": 0.0
                }

            unit_elapsed = time.monotonic() - unit_start
            worker = threading.current_thread().name

            # Save per-unit checkpoint (no lock — each file is unique)
            if checkpoint_dir:
                self._save_unit_checkpoint(unit, checkpoint_dir)

            return unit_id or "?", classification, unit_elapsed, worker

        def _update_summary(classification, unit):
            """Update summary counters after a unit completes. Called from main thread."""
            nonlocal _summary_completed, _summary_errors, _summary_error_breakdown
            nonlocal _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
            if _summary_cp is None:
                return
            if classification == "error":
                _summary_errors += 1
                err = unit.get("agent_context", {}).get("error", {})
                err_type = err.get("type", "unknown") if isinstance(err, dict) else "unknown"
                _summary_error_breakdown[err_type] = _summary_error_breakdown.get(err_type, 0) + 1
            else:
                _summary_completed += 1
            # Accumulate per-unit usage
            meta = unit.get("agent_context", {}).get("agent_metadata", {})
            _summary_input_tokens += meta.get("input_tokens", 0)
            _summary_output_tokens += meta.get("output_tokens", 0)
            _summary_cost_usd += meta.get("cost_usd", 0.0)
            _summary_cp.write_summary(total, _summary_completed, _summary_errors,
                                      _summary_error_breakdown, phase="in_progress",
                                      usage={"input_tokens": _summary_input_tokens,
                                             "output_tokens": _summary_output_tokens,
                                             "cost_usd": round(_summary_cost_usd, 6)})

        if workers <= 1:
            # Sequential mode
            try:
                for _, unit in units_to_process:
                    uid, classification, elapsed, _worker = _enhance_one(unit)
                    _update_summary(classification, unit)
                    if progress_callback:
                        progress_callback(uid, classification, elapsed)
            except KeyboardInterrupt:
                self._log("warning", "Interrupted — progress saved to checkpoints")
                return dataset
        else:
            # Parallel mode
            executor = ThreadPoolExecutor(max_workers=workers)
            futures = {executor.submit(_enhance_one, unit): unit for _, unit in units_to_process}
            try:
                for future in as_completed(futures):
                    unit = futures[future]
                    uid, classification, elapsed, worker = future.result()
                    _update_summary(classification, unit)
                    if progress_callback:
                        progress_callback(uid, f"{classification}  [{worker}]", elapsed)
            except KeyboardInterrupt:
                self._log("warning", "Interrupted — cancelling pending work...")
                executor.shutdown(wait=False, cancel_futures=True)
                self._log("info", "Progress saved to checkpoints")
                return dataset
            executor.shutdown(wait=False)

        # Auto-retry failed units with transient errors (rate limit, connection, timeout, 5xx)
        retryable_units = [
            (i, unit) for i, unit in enumerate(units)
            if is_retryable_error(unit.get("agent_context", {}).get("error"))
        ]
        if retryable_units:
            rate_limiter = get_rate_limiter()
            backoff = rate_limiter.time_until_ready()
            if backoff > 0:
                self._log("info",
                    f"Retrying {len(retryable_units)} failed units "
                    f"(waiting {backoff:.0f}s for rate limit to clear)...")
                rate_limiter.wait_if_needed()
            else:
                self._log("info",
                    f"Retrying {len(retryable_units)} failed units (transient errors)...")

            # Retry sequentially to avoid re-triggering rate limit
            for i, unit in retryable_units:
                # Clear previous error
                unit["agent_context"] = {}
                uid, classification, elapsed, _ = _enhance_one(unit)

                # Update summary: retry succeeded → flip error to completed
                if classification != "error":
                    _summary_errors = max(0, _summary_errors - 1)
                    _summary_completed += 1
                    # Decrement the old error type count (best effort)
                    # The error was already counted in _update_summary during initial pass
                # Accumulate retry usage
                meta = unit.get("agent_context", {}).get("agent_metadata", {})
                _summary_input_tokens += meta.get("input_tokens", 0)
                _summary_output_tokens += meta.get("output_tokens", 0)
                _summary_cost_usd += meta.get("cost_usd", 0.0)
                if _summary_cp is not None:
                    _summary_cp.write_summary(total, _summary_completed, _summary_errors,
                                              _summary_error_breakdown, phase="in_progress",
                                              usage={"input_tokens": _summary_input_tokens,
                                                     "output_tokens": _summary_output_tokens,
                                                     "cost_usd": round(_summary_cost_usd, 6)})

                # Save checkpoint (overwrite error with result)
                if checkpoint_dir:
                    self._save_unit_checkpoint(unit, checkpoint_dir)

                if progress_callback:
                    progress_callback(uid, f"{classification} (retry)", elapsed)

        # Write final summary with phase="done"
        if _summary_cp is not None:
            _summary_cp.write_summary(total, _summary_completed, _summary_errors,
                                      _summary_error_breakdown, phase="done",
                                      usage={"input_tokens": _summary_input_tokens,
                                             "output_tokens": _summary_output_tokens,
                                             "cost_usd": round(_summary_cost_usd, 6)})

        # Compute stats from all units (including previously checkpointed ones)
        agentic_stats = self._compute_agentic_stats(units)

        # Get token usage stats
        token_stats = self.tracker.get_totals()

        # Update dataset metadata
        dataset["metadata"] = dataset.get("metadata", {})
        dataset["metadata"]["agentic_enhanced"] = True
        dataset["metadata"]["enhancement_mode"] = "agentic"
        dataset["metadata"]["agentic_stats"] = agentic_stats
        dataset["metadata"]["token_usage"] = token_stats

        avg_iterations = agentic_stats['total_iterations'] / max(1, agentic_stats['units_processed'])
        self._log("info", "Agentic enhancement complete",
                  units=agentic_stats['units_processed'],
                  functions_added=agentic_stats['functions_added'],
                  iterations=agentic_stats['total_iterations'],
                  details={
                      "units_with_context": agentic_stats['units_with_context'],
                      "avg_iterations_per_unit": round(avg_iterations, 1),
                      "security_controls": agentic_stats['security_controls_found'],
                      "exploitable": agentic_stats['exploitable_found'],
                      "vulnerable_internal": agentic_stats['vulnerable_found'],
                      "neutral": agentic_stats['neutral_found'],
                      "errors": agentic_stats['errors']
                  })
        self._log("info", "Token usage",
                  input_tokens=token_stats['total_input_tokens'],
                  output_tokens=token_stats['total_output_tokens'],
                  total_tokens=token_stats['total_tokens'],
                  cost=f"${token_stats['total_cost_usd']:.4f}")

        return dataset

    @staticmethod
    def _safe_filename(unit_id: str) -> str:
        from utilities.safe_filename import safe_filename
        return safe_filename(unit_id)

    def _save_unit_checkpoint(self, unit: dict, checkpoint_dir: str):
        """Save a single unit's result to its own checkpoint file."""
        unit_id = unit.get("id", "unknown")
        filename = self._safe_filename(unit_id) + ".json"
        filepath = os.path.join(checkpoint_dir, filename)
        cp_data = {
            "id": unit_id,
            "agent_context": unit.get("agent_context", {}),
        }
        # Include code if it was modified by the agent
        if "code" in unit:
            cp_data["code"] = unit["code"]
        # Include per-unit usage from agent_metadata
        meta = cp_data["agent_context"].get("agent_metadata", {})
        if meta.get("input_tokens") or meta.get("output_tokens"):
            cp_data["usage"] = {
                "input_tokens": meta.get("input_tokens", 0),
                "output_tokens": meta.get("output_tokens", 0),
                "cost_usd": meta.get("cost_usd", 0.0),
            }
        with open(filepath, 'w') as f:
            json.dump(cp_data, f, indent=2)

    def _load_completed_units(self, checkpoint_dir: str) -> set:
        """Load the set of completed unit IDs from per-unit checkpoint files."""
        completed = set()
        if not os.path.isdir(checkpoint_dir):
            return completed
        for filename in os.listdir(checkpoint_dir):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(checkpoint_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    cp_data = json.load(f)
                unit_id = cp_data.get("id")
                agent_ctx = cp_data.get("agent_context", {})
                if unit_id and agent_ctx and not agent_ctx.get("error"):
                    completed.add(unit_id)
            except (json.JSONDecodeError, OSError):
                continue
        return completed

    def _migrate_legacy_checkpoint(self, checkpoint_path: str, checkpoint_dir: str, units: list):
        """Migrate a legacy single-file checkpoint to per-unit checkpoint files."""
        try:
            with open(checkpoint_path, 'r') as f:
                checkpoint_data = json.load(f)
            for cp_unit in checkpoint_data.get("units", []):
                if cp_unit.get("agent_context") and not cp_unit["agent_context"].get("error"):
                    self._save_unit_checkpoint(cp_unit, checkpoint_dir)
            self._log("info", f"Migrated legacy checkpoint to per-unit files in {checkpoint_dir}")
        except Exception as e:
            self._log("warning", f"Could not migrate legacy checkpoint: {e}")

    @staticmethod
    def _compute_agentic_stats(units: list) -> dict:
        """Compute agentic stats from all units."""
        stats = {
            "units_processed": 0,
            "units_with_context": 0,
            "total_iterations": 0,
            "functions_added": 0,
            "security_controls_found": 0,
            "exploitable_found": 0,
            "vulnerable_found": 0,
            "neutral_found": 0,
            "errors": 0,
            "error_summary": {},
        }
        for unit in units:
            agent_ctx = unit.get("agent_context")
            if not agent_ctx:
                continue
            if agent_ctx.get("error"):
                stats["errors"] += 1
                # Tally errors by type
                err = agent_ctx["error"]
                if isinstance(err, dict):
                    err_type = err.get("type", "unknown")
                else:
                    # Legacy string errors (from older runs)
                    err_type = "legacy_string"
                stats["error_summary"][err_type] = stats["error_summary"].get(err_type, 0) + 1
                continue
            stats["units_processed"] += 1
            if agent_ctx.get("include_functions"):
                stats["units_with_context"] += 1
                stats["functions_added"] += len(agent_ctx["include_functions"])
            classification = agent_ctx.get("security_classification", "neutral")
            if classification == "security_control":
                stats["security_controls_found"] += 1
            elif classification == "exploitable":
                stats["exploitable_found"] += 1
            elif classification == "vulnerable_internal":
                stats["vulnerable_found"] += 1
            else:
                stats["neutral_found"] += 1
            stats["total_iterations"] += agent_ctx.get("agent_metadata", {}).get("iterations", 0)
        return stats

    def get_token_stats(self) -> dict:
        """
        Get token usage statistics.

        Returns:
            Dict with total_calls, total_input_tokens, total_output_tokens, total_cost_usd
        """
        return self.tracker.get_totals()

    def get_last_call_stats(self) -> dict:
        """
        Get stats from the last LLM call.

        Returns:
            Dict with model, input_tokens, output_tokens, cost_usd
        """
        return self.client.get_last_call()

    def _get_default_context(self) -> dict:
        """Return default context when LLM call fails."""
        return {
            "missing_dependencies": [],
            "additional_callers": [],
            "data_flow": {
                "inputs": [],
                "outputs": [],
                "tainted_variables": [],
                "security_relevant_flows": []
            },
            "imports": [],
            "reasoning": "LLM analysis failed, using static analysis only",
            "confidence": 0.3
        }

    def _parse_json_response(self, response: str) -> Optional[dict]:
        """Parse JSON response from LLM, with LLM correction fallback."""
        response = response.strip()

        # Remove markdown code blocks if present
        if response.startswith("```json"):
            response = response[7:]
        elif response.startswith("```"):
            response = response[3:]

        if response.endswith("```"):
            response = response[:-3]

        response = response.strip()

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(response[start:end])
                except json.JSONDecodeError:
                    pass

        # Fallback: use LLM to correct malformed JSON
        if response.strip() and hasattr(self, 'client') and self.client:
            try:
                from utilities.json_corrector import JSONCorrector
                corrector = JSONCorrector(self.client)
                corrected = corrector.attempt_correction(response)
                if corrected.get("verdict") != "ERROR":
                    corrected["json_corrected"] = True
                    return corrected
            except Exception:
                pass
        return None


def main():
    """CLI interface for context enhancement."""
    parser = argparse.ArgumentParser(
        description="Enhance parser output with LLM-identified context"
    )
    parser.add_argument(
        "input",
        help="Input dataset JSON file from unit_generator.js"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: overwrites input)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Progress reporting batch size (default: 10)"
    )
    parser.add_argument(
        "--agentic",
        action="store_true",
        help="Use agentic mode with iterative tool use (more accurate, more expensive)"
    )
    parser.add_argument(
        "--analyzer-output",
        help="Path to analyzer_output.json (required for agentic mode)"
    )
    parser.add_argument(
        "--repo-path",
        help="Repository root path (optional, enables file reading in agentic mode)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print debug information (agentic mode only)"
    )
    parser.add_argument(
        "--checkpoint",
        help="Path to checkpoint file for save/resume (agentic mode only)"
    )

    args = parser.parse_args()

    # Load input
    input_path = Path(args.input)
    if not input_path.exists():
        logging.error(f"Error: Input file not found: {input_path}")
        return 1

    with open(input_path, 'r') as f:
        dataset = json.load(f)

    # Enhance
    enhancer = ContextEnhancer()

    if args.agentic:
        # Agentic mode - requires analyzer output
        if not args.analyzer_output:
            logging.error("Error: --analyzer-output is required for agentic mode")
            return 1

        analyzer_path = Path(args.analyzer_output)
        if not analyzer_path.exists():
            logging.error(f"Error: Analyzer output not found: {analyzer_path}")
            return 1

        enhanced = enhancer.enhance_dataset_agentic(
            dataset,
            analyzer_output_path=str(analyzer_path),
            repo_path=args.repo_path,
            batch_size=args.batch_size,
            verbose=args.verbose,
            checkpoint_path=args.checkpoint
        )
    else:
        # Single-shot mode (default)
        enhanced = enhancer.enhance_dataset(dataset, batch_size=args.batch_size)

    # Write output
    output_path = Path(args.output) if args.output else input_path
    with open(output_path, 'w') as f:
        json.dump(enhanced, f, indent=2)

    logging.info(f"Enhanced dataset written to: {output_path}")
    return 0


if __name__ == "__main__":
    exit(main())
