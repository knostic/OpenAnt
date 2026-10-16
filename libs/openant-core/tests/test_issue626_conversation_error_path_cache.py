"""#626 on the CONVERSATION error paths — the 4th-round pin (PR #661).

The F-A1 round gave ``LLMResponseError`` a ``usage_details`` channel and taught
the ONE single-completion error recorder (``helpers.simple_completion``) to
forward it. The sink-keyed AST census (``probes/r4/census_probe.py``: every
``record_call`` inside an ``ast.ExceptHandler`` body) then showed the class is
CLOSED AT 3 and that the OTHER TWO recorders — the agentic conversation loops at
``finding_verifier.py:503-531`` and ``agentic_enhancer/agent.py:320-367`` — carry
a BYTE-IDENTICAL lossy expression that plain grep could not see (both handlers
are ``except Exception``, not ``except LLMResponseError``):

    usage_details=per_turn_usage_details + ([None] if (exc_in or exc_out) else [])

Two defects, per site, and they fail DIFFERENTLY — so each site pins BOTH arms
(the M4 lesson from the F-A1 round: threading the detail past a guard that never
runs fixes nothing):

  THE COST ARM — the raising turn's entry is a hard-coded ``None``, so its
      ``usage_details`` is never read. #626 prices entirely off
      ``usage_details``: on the EXCLUSIVE (anthropic) shape the cached read is
      DISJOINT from ``input_tokens``, so dropping it under-reports real spend.
      claude-opus-5, one billed turn of 10k/1k then a rejected turn billing a
      90k cache read: $0.075000 recorded against $0.120000 real — 37.5 % under,
      with ``cost_incomplete`` FALSE and both cache line items at zero.

  THE GUARD ARM — ``if (total_input_tokens or total_output_tokens or exc_in or
      exc_out)``. A full cache hit arrives as 0 input / 0 output with a 90k
      billed read, so a turn-1 rejection of that shape writes NO record at
      all: the billed call is dropped WHOLESALE ($0.045 → $0.000).

The fix is ONE shared constructor — ``llm_client.error_path_turn()``, beside
``normalize_cache_usage`` — through which all three recorders read the raising
turn. ZERO new arithmetic, no second formula (the #598 lesson): the record goes
through the SAME ``record_call``/``price_usage`` path as the success exits.

``TestTheRecorderClassIsClosed`` is the CENSUS PIN: a FOURTH error-path recorder
appearing anywhere in the tree must trip it.
"""
from __future__ import annotations

import ast
import copy
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.model_registry import pricing_map
from utilities.llm import CompletionResult, ToolUseBlock
from utilities.llm.adapter import LLMConnectionError, LLMResponseError
from utilities.llm.providers import anthropic as anthropic_mod
from utilities.llm_client import TokenTracker, reset_warning_state

MODEL = "claude-opus-5"
# the SHIPPED census rate, read from the registry — never hand-written here
PRICING = {MODEL: dict(pricing_map("anthropic")[MODEL])}

# the two figures the whole pin turns on, derived from that rate:
#   the completed turn   10_000/1e6*5.0 + 1_000/1e6*25.0 = 0.050 + 0.025 = 0.075
#   the rejected turn's 90k exclusive cache read  90_000/1e6*5.0*0.1 = 0.045
COMPLETED_TURN_COST = 0.075
CACHE_READ_COST = 0.045
REAL_COST = COMPLETED_TURN_COST + CACHE_READ_COST          # 0.120


# ---------------------------------------------------------------------------
# the raising turn comes from the REAL anthropic raise site
# ---------------------------------------------------------------------------

class _AnthUsage:
    """An anthropic usage object: a full cache hit bills a 90k READ with zero
    fresh input/output tokens (the read is NOT inside input_tokens)."""

    def __init__(self, inp=0, out=0, read=90_000, write=0):
        self.input_tokens = inp
        self.output_tokens = out
        self.cache_read_input_tokens = read
        self.cache_creation_input_tokens = write


def _empty_content_response(usage):
    class _R:
        content = []          # anthropic.py:451 — the #564 empty-content raise
        stop_reason = "end_turn"
    r = _R()
    r.usage = usage
    return r


def _real_rejection(usage):
    """The LLMResponseError the SHIPPED anthropic adapter raises for this
    usage — not a hand-built exception. Proves the channel end to end."""
    try:
        anthropic_mod._response_to_unified(_empty_content_response(usage))
    except LLMResponseError as exc:
        return exc
    raise AssertionError("the empty-content raise site did not fire")


def _billed_turn(in_t=10_000, out_t=1_000):
    """A completed tool-use turn (no cache) — the loop processes the tool call
    and CONTINUES, which is how we reach a second adapter call."""
    return CompletionResult(
        content=[ToolUseBlock(id="tu1", name="read_function",
                              input={"names": []})],
        stop_reason="tool_use", input_tokens=in_t, output_tokens=out_t,
        usage_details=None)


class _ScriptedAdapter:
    name = "anthropic"
    supports_tools = True
    pricing = PRICING

    def __init__(self, script):
        self.script = list(script)

    def complete(self, **kw):
        act = self.script.pop(0)
        if isinstance(act, BaseException):
            raise act
        return act

    def validate(self, model):
        pass


def _binding(adapter):
    return SimpleNamespace(adapter=adapter, model=MODEL, phase="verify",
                           provider_name="anthropic")


def _totals(tracker):
    tot = tracker.get_totals()
    return {k: tot.get(k) for k in ("total_cost_usd", "cost_incomplete",
                                    "unpriced_cache_models",
                                    "total_cache_read_tokens",
                                    "total_cache_write_tokens")}


# ---------------------------------------------------------------------------
# SITE 1 — finding_verifier.py:503-531
# ---------------------------------------------------------------------------

def _drive_verifier(script):
    from utilities.finding_verifier import FindingVerifier
    reset_warning_state()
    tracker = TokenTracker()
    adapter = _ScriptedAdapter(script)
    v = FindingVerifier(SimpleNamespace(), _binding(adapter), tracker=tracker)
    with pytest.raises(Exception) as ei:
        v.verify_result("def f(): pass", "vulnerable", "x", "r")
    return tracker, ei.value


class TestVerifierSite:
    """``finding_verifier.verify_result``'s error recorder — the #616 idiom,
    which #626 never reached."""

    def test_cost_arm_the_rejected_turns_cache_is_priced(self):
        """One billed turn (10k/1k) then a rejection billing a 90k cache read.
        RED at d8fdbe2a: $0.075000 — the 37.5 % under-report, unflagged."""
        usage = _AnthUsage()
        tracker, _ = _drive_verifier([_billed_turn(), _real_rejection(usage)])
        tot = _totals(tracker)
        assert tot["total_cost_usd"] == pytest.approx(REAL_COST), (
            "the rejected turn's cache read was dropped from the "
            f"conversation record: {tot['total_cost_usd']} vs {REAL_COST}")
        assert tot["total_cache_read_tokens"] == 90_000
        assert len(tracker.calls) == 1, tracker.calls        # exactly-once
        call = tracker.calls[0]
        # the raising turn's detail is forwarded VERBATIM (#211), never a None
        assert call["usage_details"] == [
            None, anthropic_mod._extract_usage_details(usage)]
        # #624: the turn count equals the turns BILLED — the rejected turn
        # billed, so it counts (RED at base: 1)
        assert call["turns"] == 2

    def test_guard_arm_a_cache_only_rejection_is_recorded_at_all(self):
        """A turn-1 rejection billing ONLY a 90k cache read. RED at d8fdbe2a:
        the guard sees 0/0/0/0 and the billed call vanishes WHOLESALE."""
        usage = _AnthUsage()
        tracker, _ = _drive_verifier([_real_rejection(usage)])
        assert len(tracker.calls) == 1, (
            "a cache-only billed rejection was dropped wholesale: "
            f"{tracker.calls}")
        tot = _totals(tracker)
        assert tot["total_cost_usd"] == pytest.approx(CACHE_READ_COST)
        assert tot["total_cache_read_tokens"] == 90_000
        assert tracker.calls[0]["turns"] == 1

    def test_a_truly_unbilled_turn1_failure_still_writes_no_record(self):
        """The guard's OTHER half must not widen: a connection failure billed
        nothing — no $0 record, no spurious marker. GREEN at base, and it
        stays green (the zero-token guard is load-bearing, not removed)."""
        tracker, _ = _drive_verifier([LLMConnectionError("refused")])
        assert tracker.calls == []
        # no record, and therefore no marker of either kind: the tracker's
        # own envelope carries cost_incomplete False / no cache kind at all
        assert tracker.get_totals()["cost_incomplete"] is False
        assert "unpriced_cache_models" not in tracker.get_totals()

    def test_a_poisoned_token_attr_does_not_replace_the_original(self):
        """The shared constructor brings the #609 ENG-1 belt to this site too:
        a foreign exception whose token attr will not int-coerce must not have
        its accounting failure replace the original error."""
        boom = LLMConnectionError("refused")
        boom.input_tokens = "not-an-int"
        tracker, raised = _drive_verifier([boom])
        assert raised is boom
        assert tracker.calls == []


# ---------------------------------------------------------------------------
# SITE 2 — agentic_enhancer/agent.py:320-367
# ---------------------------------------------------------------------------

def _drive_agent(script):
    from utilities.agentic_enhancer.agent import ContextAgent
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    reset_warning_state()
    tracker = TokenTracker()
    adapter = _ScriptedAdapter(script)
    agent = ContextAgent(index=RepositoryIndex({}, repo_path=None),
                         binding=_binding(adapter), tracker=tracker)
    with pytest.raises(Exception) as ei:
        agent.analyze_unit(unit_id="a.py:f", unit_type="function",
                           primary_code="def f(): ...",
                           static_deps=[], static_callers=[])
    return tracker, ei.value


def _agent_turn(in_t=10_000, out_t=1_000):
    return CompletionResult(
        content=(ToolUseBlock(id="t1", name="get_static_dependencies",
                              input={}),),
        stop_reason="tool_use", input_tokens=in_t, output_tokens=out_t,
        usage_details=None)


class TestAgentSite:
    """``ContextAgent.analyze_unit``'s error recorder (#609). ``agent_state``
    is the ONLY carrier of a failed attempt's spend — ``agent_metadata`` is
    absent on error — so a cache kind dropped here is dropped from the enhance
    summary, the checkpoint and the resume at once."""

    def test_cost_arm_the_rejected_turns_cache_is_priced(self):
        usage = _AnthUsage()
        tracker, exc = _drive_agent([_agent_turn(), _real_rejection(usage)])
        tot = _totals(tracker)
        assert tot["total_cost_usd"] == pytest.approx(REAL_COST), (
            f"{tot['total_cost_usd']} vs {REAL_COST}")
        assert tot["total_cache_read_tokens"] == 90_000
        assert len(tracker.calls) == 1, tracker.calls
        call = tracker.calls[0]
        assert call["usage_details"] == [
            None, anthropic_mod._extract_usage_details(usage)]
        assert call["turns"] == 2
        # the attempt's own carrier reports the SAME number the tracker has
        assert exc.agent_state["cost_usd"] == pytest.approx(REAL_COST)

    def test_guard_arm_a_cache_only_rejection_is_recorded_at_all(self):
        usage = _AnthUsage()
        tracker, exc = _drive_agent([_real_rejection(usage)])
        assert len(tracker.calls) == 1, (
            f"a cache-only billed rejection was dropped wholesale: "
            f"{tracker.calls}")
        tot = _totals(tracker)
        assert tot["total_cost_usd"] == pytest.approx(CACHE_READ_COST)
        assert tot["total_cache_read_tokens"] == 90_000
        assert tracker.calls[0]["turns"] == 1
        assert exc.agent_state["cost_usd"] == pytest.approx(CACHE_READ_COST)

    def test_a_truly_unbilled_turn1_failure_still_writes_no_record(self):
        tracker, exc = _drive_agent([LLMConnectionError("transport died")])
        assert tracker.calls == []
        assert exc.agent_state["cost_usd"] == 0.0
        assert "cost_incomplete" not in exc.agent_state

    def test_the_eng1_belt_survives(self):
        """#609's guarded coercion moves INTO the shared constructor — the
        poisoned-attr exception still propagates unreplaced."""
        boom = LLMConnectionError("transport died")
        boom.output_tokens = object()
        tracker, raised = _drive_agent([boom])
        assert raised is boom
        assert tracker.calls == []


# ---------------------------------------------------------------------------
# THE CENSUS PIN — the recorder class is CLOSED AT 3
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent          # libs/openant-core
_SKIP_DIRS = {"tests", ".git", "__pycache__", "node_modules", ".venv",
              "venv", "build", "dist", ".pytest_cache"}

#: every error-path accounting recorder in the tree, keyed by its SINK:
#: (path relative to libs/openant-core, the function that owns it). Values are
#: the markers the forwarded raising-turn detail must appear under.
_EXPECTED = {
    ("utilities/llm/helpers.py", "simple_completion"): "exc.usage_details",
    ("utilities/finding_verifier.py", "verify_result"): "error_path_turn",
    ("utilities/agentic_enhancer/agent.py", "analyze_unit"): "error_path_turn",
}


class _InlineLocals(ast.NodeTransformer):
    """Substitute handler-local assignments back into an expression.

    Without this the census is defeatable by a one-line rename: a site that
    builds the lossy list into a local and passes the local would read as
    ``usage_details=turn_details`` and tell us nothing. (My own first draft of
    this round's fix did exactly that, and this pin failed on it — which is
    the behaviour wanted.)
    """

    def __init__(self, bindings, depth=0):
        self.bindings = bindings
        self.depth = depth

    def visit_Name(self, node):
        repl = self.bindings.get(node.id)
        if repl is not None and self.depth < 4:
            return _InlineLocals(self.bindings,
                                 self.depth + 1).visit(copy.deepcopy(repl))
        return node


def _resolved(expr, bindings):
    if expr is None:
        return None
    return ast.unparse(_InlineLocals(bindings).visit(copy.deepcopy(expr)))


def _error_path_recorders():
    """Sink-keyed AST census: every ``*.record_call(...)`` inside an
    ``ast.ExceptHandler`` body, over production Python only.

    AST, not grep: two of the three handlers are ``except Exception`` and read
    the tokens off the exception by ``getattr`` — a grep for
    ``except LLMResponseError`` finds neither (that miss is exactly how the
    class stayed open for three rounds). Each sink is reported with its
    ``usage_details``/``turns`` arguments AND its enclosing guard condition,
    both resolved through the handler's local assignments.

    Known blind spot, disclosed: a recorder reached through a FUNCTION CALL
    made from the handler (rather than a ``record_call`` lexically inside it)
    would not be seen. All three known recorders are lexical.
    """
    found = {}
    for dirpath, dirnames, filenames in os.walk(_REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            path = Path(dirpath) / fn
            tree = ast.parse(path.read_text(encoding="utf-8"))
            owner, parent = {}, {}
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for child in ast.walk(node):
                        owner.setdefault(child, node.name)
                for child in ast.iter_child_nodes(node):
                    parent[child] = node
            for handler in ast.walk(tree):
                if not isinstance(handler, ast.ExceptHandler):
                    continue
                # the handler's own local bindings (single-Name assignments)
                bindings = {}
                for node in ast.walk(handler):
                    if (isinstance(node, ast.Assign)
                            and len(node.targets) == 1
                            and isinstance(node.targets[0], ast.Name)):
                        bindings.setdefault(node.targets[0].id, node.value)
                for node in ast.walk(handler):
                    if not (isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "record_call"):
                        continue
                    # the innermost enclosing `if` INSIDE the handler — the
                    # zero-token guard
                    guard, walk = None, node
                    while walk in parent and walk is not handler:
                        walk = parent[walk]
                        if isinstance(walk, ast.If):
                            guard = walk
                            break
                    kws = {k.arg: k.value for k in node.keywords if k.arg}
                    # as_posix(), not str(): on Windows str() yields
                    # backslashes and every key misses _EXPECTED (the CI
                    # windows-latest leg caught exactly that).
                    key = (path.relative_to(_REPO_ROOT).as_posix(),
                           owner.get(node, "<module>"))
                    # a LIST, not an assignment: two recorders inside ONE
                    # function would otherwise collapse to a single key and
                    # the population would still read 3. (Mutant M5 found
                    # exactly that hole in this pin's first draft.)
                    found.setdefault(key, []).append({
                        "lineno": node.lineno,
                        "handler_type": (ast.unparse(handler.type)
                                         if handler.type else "bare"),
                        "usage_details": _resolved(kws.get("usage_details"),
                                                   bindings),
                        "turns": _resolved(kws.get("turns"), bindings),
                        "guard": (_resolved(guard.test, bindings)
                                  if guard is not None else None),
                    })
    return found


def _only(found, key):
    """The single recorder at ``key`` — asserting there IS only one."""
    sites = found[key]
    assert len(sites) == 1, f"{key}: {len(sites)} error-path recorders"
    return sites[0]


class TestTheRecorderClassIsClosed:
    """The population of error-path accounting recorders is CLOSED AT 3 and
    every one of them forwards the raising turn's usage detail.

    This pin exists because the class's SIZE was the thing nobody knew: the
    #537 fix landed one recorder, #616 and #609 each copied the idiom into a
    conversation loop, and #626 then reached exactly one of the three. A
    FOURTH recorder — or a third copy of the lossy expression — must fail
    here, loudly, with the fix named.
    """

    def test_the_population_is_exactly_the_three_known_sinks(self):
        found = _error_path_recorders()
        # the keys are POSIX on every platform (the windows-latest leg of CI
        # caught a str()-vs-as_posix() miss here before this pin existed)
        assert all("\\" not in path for path, _ in found), sorted(found)
        total = sum(len(v) for v in found.values())
        assert total == 3, (
            "the error-path recorder COUNT moved: "
            + str({k: [s["lineno"] for s in v] for k, v in found.items()})
            + "\nA new error-path record_call must read the raising turn "
              "through utilities.llm_client.error_path_turn() and be added "
              "to _EXPECTED here.")
        assert set(found) == set(_EXPECTED), (
            "the error-path recorder census moved.\n"
            f"  expected: {sorted(_EXPECTED)}\n"
            f"  found:    {sorted(found)}\n"
            "A NEW error-path record_call must read the raising turn through "
            "utilities.llm_client.error_path_turn() (one channel, one cost "
            "formula — never a second) and then be added here.")

    def test_every_recorder_forwards_the_raising_turns_detail(self):
        found = _error_path_recorders()
        for key, marker in _EXPECTED.items():
            site = _only(found, key)
            expr = site["usage_details"]
            assert expr is not None, f"{key}: records without usage_details"
            assert marker in expr or ".entry" in expr, (
                f"{key} at line {site['lineno']} drops the raising turn's "
                f"usage_details: usage_details={expr!r}. #626 prices off "
                "usage_details — a hard-coded None entry loses the cache.")

    def test_every_guard_consults_the_cache_counts(self):
        """The M4 lesson, pinned STRUCTURALLY. A zero-token guard that reads
        only input/output drops a cache-only billed call WHOLESALE: on the
        exclusive shape a full cache hit is 0 input / 0 output with a real
        billed read. Every recorder's guard must consult the cache — through
        ``ErrorPathTurn.billed`` or ``CacheCounts.any``, never by re-deriving
        which provider fields mean cache."""
        found = _error_path_recorders()
        for key in _EXPECTED:
            guard = _only(found, key)["guard"]
            assert guard, f"{key}: the error-path record is unguarded"
            assert ".billed" in guard or ".any" in guard, (
                f"{key} at line {_only(found, key)['lineno']} guards "
                f"on tokens alone: if ({guard}) — a cache-only billed "
                "call is dropped wholesale. Use "
                "error_path_turn(exc).billed.")

    def test_the_turn_count_matches_the_per_turn_list_it_declares(self):
        """#624: ``turns`` is the billed-turn count of the very list passed
        as ``usage_details``. The two must be the SAME expression — a
        conversation record whose declared count drifts from its own list is
        the contract break the #624 guard exists to reject."""
        found = _error_path_recorders()
        for key, site in ((k, s) for k, v in found.items() for s in v):
            if site["turns"] is None:
                continue                    # a single completion: defaults 1
            assert site["turns"] == f"len({site['usage_details']})", (
                f"{key} at line {site['lineno']}: turns={site['turns']!r} is "
                f"not len(usage_details={site['usage_details']!r})")

    def test_no_recorder_hardcodes_a_none_entry_for_the_raising_turn(self):
        """The exact lossy expression this round deleted, in all its forms:
        a literal ``None`` entry chosen by the input/output tokens alone."""
        found = _error_path_recorders()
        for key, site in ((k, s) for k, v in found.items() for s in v):
            expr = site["usage_details"] or ""
            assert "[None]" not in expr, (
                f"{key} at line {site['lineno']} appends a hard-coded None "
                f"for the raising turn: usage_details={expr!r} — the "
                "37.5 %-under defect this test pins. Use "
                "error_path_turn(exc).entries.")
