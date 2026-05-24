"""
Context Reviewer

Uses LLM to review assembled code context and identify additional files
that would be needed for complete security analysis.

This is a proactive approach - rather than waiting for INSUFFICIENT_CONTEXT,
we ask the LLM upfront what's missing.
"""

import json
import sys
from typing import Optional

from .llm import PhaseBinding, simple_text
from .context_corrector import gather_source_files, search_files_for_context


def get_context_review_prompt(code: str, route: str, handler: str, files_included: list[str]) -> str:
    """
    Generate a prompt for the LLM to review the assembled context
    and identify what additional files might be needed.
    """
    files_list = "\n".join(f"- {f}" for f in files_included)

    return f"""You are reviewing code context assembled for a security analysis.

## Target Endpoint
**Route:** `{route}`
**Handler:** `{handler}`

## Files Currently Included
{files_list}

## Assembled Code
```javascript
{code[:50000]}
```
{f"[... truncated, {len(code)} total chars ...]" if len(code) > 50000 else ""}

## Your Task
Review this code and identify what ADDITIONAL files or context would be needed
to perform a COMPLETE security analysis. Think about:

1. **Templates/Views**: Does the code render templates? Are they included?
   - Look for: res.render(), response.render(), template engines
   - EJS uses <%- %> (unescaped) vs <%= %> (escaped) - we need to see templates to check this

2. **Middleware**: Is there security middleware (auth, validation, rate limiting)?
   - Look for: app.use(), router.use(), middleware chains
   - Are the actual middleware implementations included?

3. **Database Models/Schemas**: Does the code interact with databases?
   - Are model definitions included to understand data structure?

4. **Configuration**: Are there security-relevant configs?
   - CORS settings, session config, authentication config

5. **Shared Utilities**: Does the code call sanitization/validation helpers?
   - Are those utility functions included?

6. **Called Functions**: Are there function calls to code not included?
   - Check if all called functions are defined in the included files

Respond with JSON only:

{{
    "context_complete": true | false,
    "missing_items": [
        {{
            "type": "template" | "middleware" | "model" | "config" | "utility" | "other",
            "description": "What specific file/functionality is missing",
            "why_needed": "Why this is important for security analysis",
            "hints": "Any clues from the code about where to find it (paths, names, etc.)"
        }}
    ],
    "confidence": 0.0-1.0,
    "reasoning": "Brief explanation of your assessment"
}}

Be VERY conservative - only flag items that are CRITICAL for security analysis.
Focus on:
1. Templates that render user input (XSS risk)
2. Database operations visible in the code
3. Authentication/authorization middleware ONLY if directly referenced

Do NOT request:
- Generic configuration files
- Common template partials (headers, footers, navigation)
- Model definitions unless there's a specific security concern
- Files that would just provide "nice to have" context

Maximum 2-3 missing items. Quality over quantity."""


def get_targeted_search_prompt(missing_item: dict, files_content: str) -> str:
    """
    Generate a prompt to search for a specific missing item.
    """
    return f"""You are searching for a specific file needed for security analysis.

## What We Need
**Type:** {missing_item.get('type', 'unknown')}
**Description:** {missing_item.get('description', '')}
**Why Needed:** {missing_item.get('why_needed', '')}
**Hints:** {missing_item.get('hints', 'none')}

## Available Files
```
{files_content}
```

## Your Task
Find the file(s) that match what we're looking for.

Respond with JSON only:

{{
    "found": true | false,
    "files": [
        {{
            "file_path": "relative/path/to/file",
            "confidence": "HIGH" | "MEDIUM" | "LOW",
            "reason": "Why this file matches what we need"
        }}
    ],
    "explanation": "If not found, explain why"
}}

Only include files with HIGH or MEDIUM confidence."""


class ContextReviewer:
    """
    Reviews assembled context and proactively identifies missing files.
    """

    def __init__(self, binding: PhaseBinding, repo_path: str):
        """
        Initialize the reviewer.

        Args:
            binding: Phase binding for the LLM call (typically the analyze phase's).
            repo_path: Path to the source code repository
        """
        self.binding = binding
        self.repo_path = repo_path
        self._source_files = None

    def _get_source_files(self) -> list[dict]:
        """Get source files, caching the result."""
        if self._source_files is None:
            self._source_files = gather_source_files(self.repo_path)
        return self._source_files

    def review_context(
        self,
        code: str,
        route: str,
        handler: str,
        files_included: list[str]
    ) -> dict:
        """
        Review the assembled context and identify missing files.

        Args:
            code: The assembled code context
            route: The route being analyzed
            handler: The handler function name
            files_included: List of files already included

        Returns:
            Dict with review results and any found additional files
        """
        # Step 1: Ask LLM to review the context
        prompt = get_context_review_prompt(code, route, handler, files_included)

        try:
            response = simple_text(self.binding, prompt)
            review = self._parse_json_response(response)

            if not review:
                return {
                    "success": False,
                    "error": "Failed to parse review response",
                    "additional_files": []
                }

            # If context is complete, we're done
            if review.get("context_complete", True):
                return {
                    "success": True,
                    "context_complete": True,
                    "additional_files": [],
                    "reasoning": review.get("reasoning", "")
                }

            # Step 2: Search for each missing item (limit to top 3)
            missing_items = review.get("missing_items", [])[:3]
            additional_files = []
            MAX_ADDITIONAL_FILES = 5  # Cap to avoid context bloat

            print(f"      Context review found {len(missing_items)} potentially missing items", file=sys.stderr)

            source_files = self._get_source_files()

            for item in missing_items:
                if len(additional_files) >= MAX_ADDITIONAL_FILES:
                    print(f"      Reached max additional files limit ({MAX_ADDITIONAL_FILES})", file=sys.stderr)
                    break

                item_type = item.get("type", "unknown")
                description = item.get("description", "")[:50]
                print(f"      Searching for {item_type}: {description}...", file=sys.stderr)

                # Use the existing search mechanism
                found = search_files_for_context(
                    self.binding,
                    f"{item.get('description', '')}. {item.get('hints', '')}",
                    source_files,
                    files_included + [f['relative_path'] for f in additional_files]
                )

                for f in found:
                    if len(additional_files) >= MAX_ADDITIONAL_FILES:
                        break
                    if f['relative_path'] not in files_included:
                        additional_files.append({
                            **f,
                            'missing_item_type': item_type,
                            'missing_item_description': item.get('description', '')
                        })

            return {
                "success": True,
                "context_complete": False,
                "missing_items": missing_items,
                "additional_files": additional_files,
                "reasoning": review.get("reasoning", "")
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "additional_files": []
            }

    def enhance_context(
        self,
        code: str,
        route: str,
        handler: str,
        files_included: list[str]
    ) -> tuple[str, list[str]]:
        """
        Enhance the code context by finding and adding missing files.

        Args:
            code: The original assembled code
            route: The route being analyzed
            handler: The handler function name
            files_included: List of files already included

        Returns:
            Tuple of (enhanced_code, updated_files_included)
        """
        review = self.review_context(code, route, handler, files_included)

        if not review.get("success") or not review.get("additional_files"):
            return code, files_included

        # Add the found files to the context
        enhanced_code = code
        updated_files = files_included.copy()

        for f in review["additional_files"]:
            if f['relative_path'] not in updated_files:
                enhanced_code += (
                    f"\n\n// ============================================================\n"
                    f"// ADDITIONAL CONTEXT: {f['relative_path']}\n"
                    f"// Type: {f.get('missing_item_type', 'unknown')}\n"
                    f"// Reason: {f.get('reason', f.get('missing_item_description', 'missing context'))}\n"
                    f"// ============================================================\n\n"
                    f"{f['content']}"
                )
                updated_files.append(f['relative_path'])

        print(f"      Enhanced context with {len(review['additional_files'])} additional files", file=sys.stderr)

        return enhanced_code, updated_files

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
        if response.strip() and hasattr(self, 'binding') and self.binding:
            try:
                from utilities.json_corrector import JSONCorrector
                corrector = JSONCorrector(self.binding)
                corrected = corrector.attempt_correction(response)
                if corrected.get("verdict") != "ERROR":
                    corrected["json_corrected"] = True
                    return corrected
            except Exception:
                pass
        return None


def test_reviewer():
    """Test the context reviewer."""
    import os

    print("Testing Context Reviewer", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    from .llm import build_phase_registry, load_config_file, resolve_llm_config

    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, None))
    binding = registry.get("analyze")
    repo_path = "/Users/nahumkorda/code/dvna"

    if not os.path.exists(repo_path):
        print(f"Repository not found: {repo_path}", file=sys.stderr)
        return

    reviewer = ContextReviewer(binding, repo_path)

    # Test with a simple code snippet
    test_code = """
// routes/app.js
router.post('/app/products', authHandler.isAuthenticated, appHandler.productSearch)

// core/appHandler.js
module.exports.productSearch = function (req, res) {
    db.Product.findAll({
        where: {
            name: {
                [Op.like]: '%' + req.body.name + '%'
            }
        }
    }).then(products => {
        output = {
            products: products,
            searchTerm: req.body.name
        }
        res.render('app/products', {
            output: output
        })
    })
}
"""

    files_included = ["routes/app.js", "core/appHandler.js"]

    print("\nReviewing context for POST:/app/products...", file=sys.stderr)
    print("-" * 60, file=sys.stderr)

    result = reviewer.review_context(
        test_code,
        "POST:/app/products",
        "productSearch",
        files_included
    )

    print(f"\nContext complete: {result.get('context_complete', 'unknown')}", file=sys.stderr)
    print(f"Reasoning: {result.get('reasoning', 'none')}", file=sys.stderr)

    if result.get('missing_items'):
        print(f"\nMissing items:", file=sys.stderr)
        for item in result['missing_items']:
            print(f"  - [{item.get('type')}] {item.get('description')}", file=sys.stderr)

    if result.get('additional_files'):
        print(f"\nFound additional files:", file=sys.stderr)
        for f in result['additional_files']:
            print(f"  - {f['relative_path']}", file=sys.stderr)


if __name__ == "__main__":
    test_reviewer()
