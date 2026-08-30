"""Shared verdict / disclosure taxonomy.

Single source of truth for the ``stage2_verdict`` values the reporter can
emit and for which of them are eligible to produce a disclosure document.

Historically each consumer inlined its own filter tuple
(``core/reporter.py``, ``report/generator.py``, ``report/__main__.py``,
``core/dynamic_tester.py``) and each display module inlined its own
finding-verdict order list (``openant/cli.py``, ``generate_report.py``).
Those copies drifted, and a verdict the *producer* can emit but that no
*filter* accepts is silently dropped -- a security false-negative when the
dropped verdict names a real (or unverified) vulnerability.

ENTER => EXIT invariant (enforced by the conformance test):
    every verdict the producer at ``core/reporter.py`` can emit
    (``PRODUCER_VERDICTS``) must either be accepted by the disclosure
    filter (``DISCLOSURE_ELIGIBLE``) or be *deliberately* dropped
    (``DISCLOSURE_DROPPED``). Formally::

        PRODUCER_VERDICTS == DISCLOSURE_ELIGIBLE | DISCLOSURE_DROPPED
        DISCLOSURE_ELIGIBLE & DISCLOSURE_DROPPED == set()

    Adding a new producer verdict without classifying it as eligible or
    deliberately-dropped fails the conformance test instead of silently
    dropping the finding.
"""

# --- Stage-1 finding verdicts ------------------------------------------------
# Produced by ``core/analyzer.py`` (``_count_verdicts``), in the display /
# priority order used by the HTML report and CLI summary. Ordered, so this is
# a tuple (not a set): ``openant/cli.py`` and ``generate_report.py`` iterate it.
FINDING_VERDICT_ORDER = (
    "vulnerable",
    "bypassable",
    "inconclusive",
    "protected",
    "safe",
)

# Sentinel emitted for a unit whose analysis errored (``verdict == "ERROR"``
# / ``finding == "error"``). Not part of the ordered display list.
ERROR_VERDICT = "error"

# --- #215: finding severity ---------------------------------------------------
# The canonical severity enum — the same four levels the JSON corrector's
# legacy _VULN_SCHEMA has carried since inception. FINDING-ONLY: a row whose
# verdict is not a finding verdict carries NO severity. Lives here (a leaf
# module) so every importer — analysis_core, reporter, csv_export, cli, the
# context corrector twin — shares one definition without pulling the LLM
# stack into a standalone exporter.
SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITIES = frozenset(SEVERITIES)

# The verdicts that carry a severity (see SEVERITIES above).
SEVERITY_FINDING_VERDICTS = ("vulnerable", "bypassable")

# --- Stage-2 verification verdicts -------------------------------------------
# ``core/reporter.py`` maps the Stage-2 ``verification`` dict onto these.
STAGE2_VERDICTS = frozenset({
    "confirmed",   # agree=True + exploit_path present
    "agreed",      # agree=True, no exploit_path
    "unverified",  # Stage-2 could not COMPLETE (degenerate path / adapter error)
    "rejected",    # Stage-2 actively downgraded the Stage-1 finding
})

# --- Full producer set -------------------------------------------------------
# Every value ``stage2_verdict`` can take at the reporter mapping site
# (``core/reporter.py``: the ``verification`` branch chain ending in the
# no-Stage-2 fallback ``finding.get("finding", "vulnerable")``):
#   * WITH Stage 2   -> one of STAGE2_VERDICTS
#   * WITHOUT Stage 2 -> a bare Stage-1 finding verdict, i.e. one of
#                        FINDING_VERDICT_ORDER or ERROR_VERDICT
PRODUCER_VERDICTS = STAGE2_VERDICTS | frozenset(FINDING_VERDICT_ORDER) | {ERROR_VERDICT}

# --- Disclosure filter -------------------------------------------------------
# Verdicts eligible to generate a disclosure document.
#
# NEEDS-USER-SIGN-OFF: relative to the previous inlined filters
# ("confirmed", "agreed", "vulnerable", "unverified") this ADDS "bypassable"
# and "error". Both can only arise on the NO-Stage-2 path (a bare Stage-1
# finding verdict), so this changes output only when Stage 2 did not run:
#   * "bypassable" -- a real, exploitable-if-bypassed finding that was being
#     silently dropped from disclosures (security false-negative). Surfacing it
#     is the SAFE (over-approximating) direction.
#   * "error"      -- a unit whose analysis errored; surfaced so it stays on
#     the manual-triage radar rather than vanishing.
DISCLOSURE_ELIGIBLE = frozenset({
    "confirmed",
    "agreed",
    "unverified",
    "vulnerable",
    "bypassable",
    "error",
})

# Producer verdicts DELIBERATELY excluded from disclosure:
#   * "rejected"     -- Stage 2 actively downgraded the finding.
#   * "safe"/"protected"/"inconclusive" -- not a vulnerability.
DISCLOSURE_DROPPED = frozenset({
    "rejected",
    "safe",
    "protected",
    "inconclusive",
})

# --- Dynamic-testing filter --------------------------------------------------
# Findings handed to the (Docker-backed) dynamic tester. Intentionally NARROWER
# than DISCLOSURE_ELIGIBLE: only findings asserted vulnerable are worth an
# active reproduction attempt. Behaviour-preserving relative to the previous
# inlined tuple in ``core/dynamic_tester.py``.
DYNAMIC_TESTABLE = frozenset({
    "confirmed",
    "agreed",
    "vulnerable",
})
