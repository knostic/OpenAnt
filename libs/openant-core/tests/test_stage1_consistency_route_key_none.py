"""Regression: a present-but-None ``route_key`` must not crash grouping.

``_group_by_signature_pattern`` read ``result.get("route_key", "")`` which
only defaults a MISSING key; a present ``route_key=None`` propagated None into
``_extract_function_signature_pattern`` where ``":" not in None`` raised
``TypeError: argument of type 'NoneType' is not iterable``. Same
"get-default covers missing not None" class as the hardened-2 verdict guards
in this file.
"""

from utilities.stage1_consistency import _group_by_signature_pattern


def test_present_but_none_route_key_does_not_crash():
    # route_key key is PRESENT but its value is None (not missing).
    results = [{"route_key": None, "verdict": "SAFE"}]
    groups = _group_by_signature_pattern(results)
    # None must be coerced to the empty-pattern bucket, not propagate.
    assert results[0] in next(iter(groups.values()))


def test_missing_route_key_still_grouped():
    # Regression guard: the None tolerance must not break the missing-key path.
    results = [{"verdict": "SAFE"}]
    groups = _group_by_signature_pattern(results)
    assert results[0] in next(iter(groups.values()))
