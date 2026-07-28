"""Unit tests for the canonical Investigation Engine data model (Slice 1)."""

from __future__ import annotations

import sys
from pathlib import Path



class TestModelConstruction:
    def test_raw_artifact_defaults(self):
        from utilities.autopatcher.investigation_models import RawArtifact
        a = RawArtifact(source_type="free_text", raw_text="hello")
        assert a.source_url is None
        assert a.structured_payload is None

    def test_problem_claims_defaults_are_independent(self):
        from utilities.autopatcher.investigation_models import ProblemClaims
        a = ProblemClaims()
        b = ProblemClaims()
        a.cwes.append("CWE-89")
        assert b.cwes == []  # default_factory must not share state across instances

    def test_hypothesis_defaults(self):
        from utilities.autopatcher.investigation_models import Hypothesis
        h = Hypothesis(id="h1", statement="SQL injection in authenticate()")
        assert h.status == "open"
        assert h.rejection_reason is None
        assert h.confirming_evidence_needed == []

    def test_evidence_item_defaults(self):
        from utilities.autopatcher.investigation_models import EvidenceItem
        e = EvidenceItem(evidence_type="location", source_module="repo_locator", content="app/auth.py")
        assert e.supports == []
        assert e.refutes == []

    def test_context_projection_fields(self):
        from utilities.autopatcher.investigation_models import ContextProjection
        p = ContextProjection(vulnerability_text="# Vuln", repo_root=Path("/tmp/repo"))
        assert p.vulnerability_text == "# Vuln"
        assert p.repo_root == Path("/tmp/repo")


class TestInvestigationCase:
    def _make_case(self):
        from utilities.autopatcher.investigation_models import InvestigationCase, ProblemClaims, RawArtifact
        return InvestigationCase(
            raw_artifact=RawArtifact(source_type="vulnerability_text", raw_text="# Vuln\n"),
            framing=ProblemClaims(summary="Vuln"),
            rendered_text="# Vuln\n",
            repo_root=Path("/tmp/repo"),
        )

    def test_defaults_are_empty(self):
        case = self._make_case()
        assert case.hypotheses == []
        assert case.evidence == []
        assert case.leading_hypothesis_id is None
        assert case.open_questions == []

    def test_to_context_projection_carries_text_and_repo_root(self):
        case = self._make_case()
        projection = case.to_context_projection()
        assert projection.vulnerability_text == "# Vuln\n"
        assert projection.repo_root == Path("/tmp/repo")

    def test_to_context_projection_repo_root_optional(self):
        from utilities.autopatcher.investigation_models import InvestigationCase, ProblemClaims, RawArtifact
        case = InvestigationCase(
            raw_artifact=RawArtifact(source_type="vulnerability_text", raw_text="x"),
            framing=ProblemClaims(),
            rendered_text="x",
        )
        assert case.to_context_projection().repo_root is None

    def test_default_lists_are_independent_across_cases(self):
        case_a = self._make_case()
        case_b = self._make_case()
        case_a.open_questions.append("is this the right package?")
        assert case_b.open_questions == []
