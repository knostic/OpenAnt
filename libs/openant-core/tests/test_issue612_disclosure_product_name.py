"""#612 (the Python half of the acceptance seam): the repository name is
the primary identifying metadata the disclosure prompt receives in the JSON payload.

The Go tier's name derivation (cmd/scan.go's resolveRepoMetadataFull ->
remoteurl.RepoSlug) fixes the PRODUCER of ``repository.name``; this pins
the CONSUMER contract that makes the fix matter: the disclosure call's
``product_name`` argument is exactly ``pipeline_data["repository"]["name"]``
— no URL, no SHA accompany it into the prompt. A renamed checkout that
stamps its directory basename therefore renders the disclosure's product
metadata as that basename (the #612 filing's impact); conversely, once the
name carries the remote-derived slug, this is the path it flows through.

Fully offline ($0): the LLM call is stubbed at the generator boundary, so
the payload's ``product_name`` is captured without any request.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from report import generator as generator_mod  # noqa: E402


class _CaptureResult:
    def __init__(self):
        from utilities.llm import TextBlock
        self.content = [TextBlock("STUBBED DISCLOSURE for test_finding")]
        self.stop_reason = "end_turn"
        self.input_tokens = 1
        self.output_tokens = 1
        self.usage_details = None


class _CapturedBinding:
    """A recording PhaseBinding stub: the disclosure's single request seam
    is binding.adapter.complete (generator.py) — capturing here sees the
    exact prompt the model receives, with zero network."""

    def __init__(self):
        self.captured_prompt = None
        self.model = "stub/model"
        self.adapter = self

    def complete(self, *, model, max_tokens, system, messages):
        self.captured_prompt = messages[0].content[0].text
        return _CaptureResult()


class ProductNameCaptureTests(unittest.TestCase):
    def test_disclosure_payload_carries_the_repository_name_verbatim(self):
        """The stub sees product_name == repository.name, exactly.

        The capture point is ``_llm_complete`` (generate_disclosure's
        single request seam): whatever name the Go tier derived, this is
        the argument it arrives as — and the ONLY product identifier in
        the payload (no URL/SHA keys accompany it).
        """
        binding = _CapturedBinding()
        finding = {
            "short_name": "test_finding",
            "title": "A test finding",
            "description": "finding text",
            "severity": "HIGH",
            "file": "a.py",
        }
        text, _usage = generator_mod.generate_disclosure(
            finding, "renamed-org/real-repo", binding)

        self.assertIn("renamed-org/real-repo", binding.captured_prompt,
                      "the product name must reach the disclosure prompt")
        self.assertIn('"product_name": "renamed-org/real-repo"', binding.captured_prompt)  # the JSON payload key, not the {product_name} template placeholder
        self.assertIn("STUBBED DISCLOSURE for test_finding", text,
                      "the generated text is the stubbed completion")

    def test_the_reporter_reads_the_name_from_pipeline_data(self):
        """Source-level pin: the reporter's product_name is exactly
        pipeline_data['repository']['name'] (the #612 flow's consumer)."""
        src = (PROJECT_ROOT / "core" / "reporter.py").read_text()
        self.assertIn('product_name = pipeline_data["repository"]["name"]', src)


if __name__ == "__main__":
    unittest.main()
