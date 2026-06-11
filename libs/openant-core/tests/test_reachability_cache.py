"""Regression test -- ReachabilityAnalyzer stale-cache.

is_reachable_from_entry_point() is a depth-BOUNDED reverse BFS: for a function farther than max_depth
hops from an entry point it caches False (a false negative). get_all_reachable() is an UNBOUNDED forward
BFS (the complete answer), but it used to update the cache only for keys NOT already present -- so the
stale bounded False was frozen and never corrected. Fix: get_all_reachable() overwrites the cache.
"""
from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer


def _analyzer(max_depth):
    # E -> A -> B -> C  (forward).  reverse: A<-E, B<-A, C<-B.  Entry point: E.
    functions = {"E": {}, "A": {}, "B": {}, "C": {}}
    reverse_call_graph = {"A": ["E"], "B": ["A"], "C": ["B"]}
    return ReachabilityAnalyzer(functions, reverse_call_graph, entry_points={"E"}, max_depth=max_depth)


def test_get_all_reachable_overwrites_stale_bounded_false():
    ra = _analyzer(max_depth=2)
    # C is reachable (E->A->B->C) but 3 reverse hops away, so the depth-2 reverse BFS caches False:
    assert ra.is_reachable_from_entry_point("C") is False
    # the unbounded forward pass must CORRECT that stale cached False:
    assert "C" in ra.get_all_reachable()
    assert ra.is_reachable_from_entry_point("C") is True, \
        "get_all_reachable() must overwrite the stale depth-bounded False, not freeze it"


def test_get_all_reachable_does_not_break_true_or_unreachable():
    # With ample depth, nothing is stale; reachable stays reachable, a disconnected node stays unreachable.
    ra = ReachabilityAnalyzer(
        {"E": {}, "A": {}, "X": {}}, {"A": ["E"]}, entry_points={"E"}, max_depth=15)
    reachable = ra.get_all_reachable()
    assert "A" in reachable and "E" in reachable
    assert "X" not in reachable
    assert ra.is_reachable_from_entry_point("A") is True
    assert ra.is_reachable_from_entry_point("X") is False
