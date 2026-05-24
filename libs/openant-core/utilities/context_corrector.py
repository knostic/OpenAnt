"""
Context Corrector

When the LLM returns INSUFFICIENT_CONTEXT, this module:
1. Extracts what context is missing from the reasoning
2. Gathers all source files from the repository
3. Sends batches of files to LLM to find the missing context
4. Re-runs analysis with the found code

Uses LLM-based semantic search instead of keyword matching.
"""

import json
import os
import subprocess
import sys
from typing import Optional

from .llm_client import TokenTracker, get_global_tracker
from .llm import PhaseBinding, simple_text


# Maximum characters per batch (leaving room for prompt overhead)
MAX_BATCH_SIZE = 150000  # ~37k tokens for Sonnet


def get_missing_context_prompt(reasoning: str) -> str:
    """
    Generate a prompt to extract what context is missing from INSUFFICIENT_CONTEXT reasoning.

    Returns a simple description of what's needed, without keyword guessing.
    """
    return f"""You are analyzing a security analysis response that returned INSUFFICIENT_CONTEXT.

The analyzer's reasoning for why context was insufficient:
---
{reasoning}
---

Your task: Identify what specific code or configuration is missing that would be needed to complete the security analysis.

Respond with JSON only:

{{
    "missing_context": "A clear description of what code/configuration is needed. Be specific about the functionality, not file names or variable names. Example: 'The passport authentication strategy that handles the login flow' or 'The database query function that processes user search input'"
}}

Do NOT guess file names, function names, or keywords - just describe what functionality is missing."""


def get_file_search_prompt(missing_context: str, files_content: str, batch_info: str = "") -> str:
    """
    Generate a prompt to search through files for the missing context.
    """
    return f"""You are searching through source code files to find specific functionality.

## What We're Looking For
{missing_context}

## Source Files to Search{batch_info}
```
{files_content}
```

## Your Task
Examine these files and identify which ones contain the functionality described above.

Respond with JSON only:

{{
    "found_files": [
        {{
            "file_path": "relative/path/to/file.js",
            "relevance": "HIGH" | "MEDIUM" | "LOW",
            "reason": "Brief explanation of why this file contains the needed context"
        }}
    ],
    "not_found": true | false,
    "explanation": "If not found, explain what was searched and why it wasn't found"
}}

Only include files with HIGH or MEDIUM relevance. If none of the files contain the needed functionality, set not_found to true."""


def parse_missing_context_with_llm(
    binding: PhaseBinding,
    response: dict
) -> Optional[str]:
    """
    Use LLM to parse an INSUFFICIENT_CONTEXT response and identify what's missing.

    Args:
        binding: Phase binding for the LLM call (typically the analyze phase's).
        response: The original analysis result with INSUFFICIENT_CONTEXT verdict

    Returns:
        Description of what context is missing, or None if parsing fails.
    """
    reasoning = response.get("reasoning", "")
    if not reasoning:
        return None

    prompt = get_missing_context_prompt(reasoning)

    try:
        llm_response = simple_text(binding, prompt)
        parsed = _parse_json_response(llm_response)

        if parsed and "missing_context" in parsed:
            return parsed["missing_context"]
    except Exception as e:
        print(f"      LLM parsing failed: {e}", file=sys.stderr)

    return None


def gather_source_files(repo_path: str, extensions: list[str] = None) -> list[dict]:
    """
    Gather all source files from a repository.

    Args:
        repo_path: Path to the repository root
        extensions: File extensions to include (default: js, ts, jsx, tsx, ejs, pug, hbs)

    Returns:
        List of dicts with file_path, relative_path, and content
    """
    if extensions is None:
        extensions = ['.js', '.ts', '.jsx', '.tsx', '.ejs', '.pug', '.hbs', '.json']

    # Directories to exclude
    exclude_dirs = {'node_modules', '.git', 'dist', 'build', 'coverage', 'vendor', '.next'}

    # File patterns to exclude
    exclude_patterns = {'.min.js', '.min.css', '.bundle.js', '.chunk.js', 'package-lock.json'}

    files = []

    for root, dirs, filenames in os.walk(repo_path):
        # Remove excluded directories from dirs to prevent walking into them
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for filename in filenames:
            # Check extension
            if not any(filename.endswith(ext) for ext in extensions):
                continue

            # Check exclude patterns
            if any(pattern in filename for pattern in exclude_patterns):
                continue

            file_path = os.path.join(root, filename)
            relative_path = os.path.relpath(file_path, repo_path)

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Skip very large files (likely generated/minified)
                if len(content) > 50000:
                    continue

                files.append({
                    'file_path': file_path,
                    'relative_path': relative_path,
                    'content': content,
                    'size': len(content)
                })
            except Exception:
                pass

    return files


def create_file_batches(files: list[dict], max_batch_size: int = MAX_BATCH_SIZE) -> list[list[dict]]:
    """
    Divide files into batches that fit within context limits.

    Args:
        files: List of file dicts with content
        max_batch_size: Maximum characters per batch

    Returns:
        List of batches, where each batch is a list of file dicts
    """
    batches = []
    current_batch = []
    current_size = 0

    # Sort files by size (smaller first) to pack efficiently
    sorted_files = sorted(files, key=lambda f: f['size'])

    for file in sorted_files:
        file_size = file['size'] + len(file['relative_path']) + 50  # overhead for formatting

        if current_size + file_size > max_batch_size and current_batch:
            batches.append(current_batch)
            current_batch = []
            current_size = 0

        current_batch.append(file)
        current_size += file_size

    if current_batch:
        batches.append(current_batch)

    return batches


def format_batch_for_prompt(batch: list[dict]) -> str:
    """Format a batch of files for the search prompt."""
    parts = []
    for file in batch:
        parts.append(f"// ===== FILE: {file['relative_path']} =====\n{file['content']}")
    return "\n\n".join(parts)


def search_files_for_context(
    binding: PhaseBinding,
    missing_context: str,
    files: list[dict],
    already_included: list[str] = None
) -> list[dict]:
    """
    Search through files using LLM to find the missing context.

    Args:
        binding: Phase binding for the LLM call.
        missing_context: Description of what we're looking for
        files: List of source files to search
        already_included: Files already in the analysis context

    Returns:
        List of relevant files found
    """
    already_included = already_included or []

    # Filter out files already included
    files_to_search = [f for f in files if f['relative_path'] not in already_included]

    if not files_to_search:
        return []

    # Create batches
    batches = create_file_batches(files_to_search)

    print(f"      Searching {len(files_to_search)} files in {len(batches)} batch(es)...", file=sys.stderr)

    found_files = []

    for i, batch in enumerate(batches):
        batch_info = f" (Batch {i+1}/{len(batches)})" if len(batches) > 1 else ""
        files_content = format_batch_for_prompt(batch)

        prompt = get_file_search_prompt(missing_context, files_content, batch_info)

        try:
            response = simple_text(binding, prompt)
            result = _parse_json_response(response)

            if result and result.get("found_files"):
                for found in result["found_files"]:
                    if found.get("relevance") in ["HIGH", "MEDIUM"]:
                        # Find the actual file content
                        rel_path = found.get("file_path")
                        for f in batch:
                            if f['relative_path'] == rel_path:
                                found_files.append({
                                    **f,
                                    'relevance': found.get('relevance'),
                                    'reason': found.get('reason')
                                })
                                break

            if result and result.get("not_found") and len(batches) == 1:
                print(f"      Context not found: {result.get('explanation', 'unknown reason')}", file=sys.stderr)

        except Exception as e:
            print(f"      Batch {i+1} search failed: {e}", file=sys.stderr)

    return found_files


def _parse_json_response(response: str) -> Optional[dict]:
    """Parse JSON response from LLM."""
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
    return None


class ContextCorrector:
    """
    Handles context correction for INSUFFICIENT_CONTEXT verdicts using LLM-based search.
    Tracks token usage and costs for all LLM calls.
    """

    def __init__(self, binding: PhaseBinding, repo_path: str, max_retries: int = 2, tracker: TokenTracker = None):
        """
        Initialize the corrector.

        Args:
            binding: Phase binding for the LLM call (typically the analyze phase's).
            repo_path: Path to the source code repository
            max_retries: Maximum number of correction attempts
            tracker: Token tracker instance. Uses global tracker if not provided.
        """
        self.tracker = tracker or get_global_tracker()
        self.binding = binding
        self.repo_path = repo_path
        self.max_retries = max_retries
        self._source_files = None  # Cache for source files
        self.correction_stats = {
            "attempts": 0,
            "successes": 0,
            "failures": 0
        }

    def _get_source_files(self) -> list[dict]:
        """Get source files, caching the result."""
        if self._source_files is None:
            self._source_files = gather_source_files(self.repo_path)
        return self._source_files

    def get_token_stats(self) -> dict:
        """
        Get token usage statistics.

        Returns:
            Dict with total_calls, total_input_tokens, total_output_tokens, total_cost_usd
        """
        return self.tracker.get_totals()

    def get_correction_stats(self) -> dict:
        """
        Get correction statistics including token usage.

        Returns:
            Dict with correction attempts, successes, failures, and token usage
        """
        return {
            **self.correction_stats,
            "token_usage": self.tracker.get_totals()
        }

    def attempt_correction(
        self,
        original_result: dict,
        original_code: str,
        prompt_generator,
        files_included: list[str] = None
    ) -> dict:
        """
        Attempt to correct an INSUFFICIENT_CONTEXT result.

        Args:
            original_result: The original analysis result with INSUFFICIENT_CONTEXT verdict
            original_code: The original code that was analyzed
            prompt_generator: Function to generate the analysis prompt
            files_included: List of files already included in context

        Returns:
            Corrected result (may still be INSUFFICIENT_CONTEXT if correction fails)
        """
        if original_result.get("verdict") != "INSUFFICIENT_CONTEXT":
            return original_result

        self.correction_stats["attempts"] += 1

        files_included = files_included or []
        current_code = original_code
        current_result = original_result

        for attempt in range(self.max_retries):
            # Step 1: Parse what's missing
            print(f"      Parsing missing context (attempt {attempt + 1})...", file=sys.stderr)
            missing_context = parse_missing_context_with_llm(self.binding, current_result)

            if not missing_context:
                current_result["correction_attempted"] = True
                current_result["correction_status"] = "could_not_identify_missing"
                break

            print(f"      Looking for: {missing_context[:100]}...", file=sys.stderr)

            # Step 2: Search source files for the missing context
            source_files = self._get_source_files()
            found_files = search_files_for_context(
                self.binding,
                missing_context,
                source_files,
                files_included
            )

            if not found_files:
                current_result["correction_attempted"] = True
                current_result["correction_status"] = "missing_code_not_found"
                current_result["missing_context"] = missing_context
                break

            # Step 3: Add found files to context
            added_files = []
            additional_code = []

            for f in found_files:
                if f['relative_path'] not in files_included:
                    files_included.append(f['relative_path'])
                    added_files.append(f['relative_path'])
                    additional_code.append(
                        f"\n// ========== Additional Context: {f['relative_path']} ==========\n"
                        f"// (Relevance: {f.get('relevance', 'HIGH')})\n"
                        f"// (Reason: {f.get('reason', 'Contains missing context')})\n\n"
                        f"{f['content']}"
                    )

            if not added_files:
                current_result["correction_attempted"] = True
                current_result["correction_status"] = "no_new_files_to_add"
                break

            print(f"      Added {len(added_files)} files: {added_files}", file=sys.stderr)

            # Step 4: Re-analyze with expanded context
            expanded_code = current_code + "\n".join(additional_code)
            prompt = prompt_generator(expanded_code, files_included)

            try:
                from datetime import datetime
                start_time = datetime.now()
                response = simple_text(self.binding, prompt)
                elapsed = (datetime.now() - start_time).total_seconds()

                # Parse the new response
                new_result = self._parse_response(response)
                new_result["correction_attempted"] = True
                new_result["correction_attempt"] = attempt + 1
                new_result["files_added"] = added_files
                new_result["elapsed_seconds"] = elapsed
                new_result["prompt_length"] = len(prompt)
                new_result["response_length"] = len(response)

                if new_result.get("verdict") != "INSUFFICIENT_CONTEXT":
                    # Correction successful
                    new_result["correction_status"] = "success"
                    new_result["token_usage"] = self.tracker.get_totals()
                    self.correction_stats["successes"] += 1
                    print(f"      Correction successful! New verdict: {new_result.get('verdict')}", file=sys.stderr)
                    return new_result

                # Still insufficient, try another round
                print(f"      Still insufficient context, trying again...", file=sys.stderr)
                current_code = expanded_code
                current_result = new_result

            except Exception as e:
                current_result["correction_attempted"] = True
                current_result["correction_status"] = f"error: {str(e)}"
                break

        # Correction failed
        self.correction_stats["failures"] += 1
        current_result["token_usage"] = self.tracker.get_totals()
        return current_result

    def _parse_response(self, response: str) -> dict:
        """Parse JSON response from Claude."""
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
            result = json.loads(response)
            return self._normalize_result(result)
        except json.JSONDecodeError as e:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    result = json.loads(response[start:end])
                    return self._normalize_result(result)
                except json.JSONDecodeError:
                    pass

            # If all parsing failed, try LLM correction
            if hasattr(self, 'binding') and self.binding:
                try:
                    from utilities.json_corrector import JSONCorrector
                    corrector = JSONCorrector(self.binding)
                    corrected = corrector.attempt_correction(response)
                    corrected = self._normalize_result(corrected)
                    if corrected.get("verdict") not in ("ERROR", None):
                        corrected["json_corrected"] = True
                        return corrected
                except Exception:
                    pass

            return {
                "verdict": "ERROR",
                "confidence": 0,
                "vulnerabilities": [],
                "reasoning": f"Failed to parse response: {str(e)}",
                "raw_response": response[:500]
            }

    @staticmethod
    def _normalize_result(result: dict) -> dict:
        """Normalize finding -> verdict and ensure uppercase."""
        if "verdict" not in result and "finding" in result:
            finding = result["finding"]
            mapping = {
                "vulnerable": "VULNERABLE", "safe": "SAFE",
                "protected": "PROTECTED", "bypassable": "BYPASSABLE",
                "inconclusive": "INCONCLUSIVE",
                "insufficient_context": "INSUFFICIENT_CONTEXT",
            }
            result["verdict"] = mapping.get(finding.lower(), finding.upper())
        if "verdict" in result and isinstance(result["verdict"], str):
            result["verdict"] = result["verdict"].upper()
        return result


def test_corrector():
    """Test the LLM-based context corrector."""

    # Sample INSUFFICIENT_CONTEXT responses from actual experiment
    test_cases = [
        {
            "verdict": "INSUFFICIENT_CONTEXT",
            "confidence": 0.7,
            "reasoning": "The POST:/login endpoint uses passport.authenticate('login', ...) but the actual authentication strategy implementation is not provided in the context. The vulnerability assessment depends entirely on how the 'login' strategy is implemented in the passport configuration."
        }
    ]

    print("Testing LLM-based Context Corrector", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # Resolve the analyze-phase binding from the active config.
    from .llm import build_phase_registry, load_config_file, resolve_llm_config

    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, None))
    binding = registry.get("analyze")

    for i, test_case in enumerate(test_cases):
        print(f"\nTest Case {i + 1}:", file=sys.stderr)
        print(f"Reasoning: {test_case['reasoning'][:100]}...", file=sys.stderr)
        print(file=sys.stderr)

        # Parse missing context
        missing = parse_missing_context_with_llm(binding, test_case)
        print(f"Missing context: {missing}", file=sys.stderr)
        print(file=sys.stderr)

        # Test file gathering
        repo_path = "/Users/nahumkorda/code/dvna"
        if os.path.exists(repo_path):
            files = gather_source_files(repo_path)
            print(f"Found {len(files)} source files in {repo_path}", file=sys.stderr)

            batches = create_file_batches(files)
            print(f"Created {len(batches)} batches", file=sys.stderr)

            # Search for the missing context
            if missing:
                found = search_files_for_context(binding, missing, files, [])
                print(f"\nFound {len(found)} relevant files:", file=sys.stderr)
                for f in found:
                    print(f"  - {f['relative_path']} ({f.get('relevance')}): {f.get('reason', '')[:50]}", file=sys.stderr)

        print("-" * 60, file=sys.stderr)


if __name__ == "__main__":
    test_corrector()
