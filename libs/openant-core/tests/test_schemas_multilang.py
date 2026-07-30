"""Additive multi-language fields on ParseResult / ScanResult.

The scalar ``language`` field stays and keeps meaning "the primary language",
because it is serialized into JSON that the Go CLI unmarshals. Widening its
TYPE would be a cross-language breaking change; adding fields beside it is not.
This mirrors the convention already used for ``skipped_steps`` /
``skipped_step_reasons``.
"""

import json

from core.schemas import ParseResult, ScanResult


class TestParseResultBackCompat:
    def test_existing_construction_still_works(self):
        r = ParseResult(dataset_path="/x/dataset.json", language="python", units_count=3)
        assert r.language == "python"
        assert r.units_count == 3

    def test_new_fields_default_to_empty(self):
        r = ParseResult(dataset_path="/x/dataset.json")
        assert r.languages == []
        assert r.language_stats == {}
        assert r.per_language == {}
        assert r.parse_errors == []

    def test_to_dict_still_serialises(self):
        r = ParseResult(dataset_path="/x/dataset.json", language="go")
        d = r.to_dict()
        assert d["language"] == "go"
        assert json.loads(json.dumps(d))["languages"] == []


class TestParseResultMultiLanguage:
    def test_scalar_language_holds_the_primary(self):
        r = ParseResult(
            dataset_path="/x/dataset.json",
            language="python",
            languages=["python", "javascript"],
            language_stats={"python": 8, "javascript": 7},
        )
        assert r.language == "python", "scalar field must remain the primary"
        assert r.languages == ["python", "javascript"]

    def test_language_stats_and_per_language_round_trip(self):
        r = ParseResult(
            dataset_path="/x/dataset.json",
            languages=["python", "go"],
            language_stats={"python": 8, "go": 2},
            per_language={"python": {"units": 8}, "go": {"units": 2}},
        )
        d = json.loads(json.dumps(r.to_dict()))
        assert d["language_stats"] == {"python": 8, "go": 2}
        assert d["per_language"]["go"]["units"] == 2

    def test_parse_errors_records_degraded_languages(self):
        r = ParseResult(
            dataset_path="/x/dataset.json",
            parse_errors=[{"language": "zig", "error": "toolchain missing"}],
        )
        assert r.parse_errors[0]["language"] == "zig"

    def test_degraded_is_derived_not_stored(self):
        """A run is degraded iff some language failed — one source of truth."""
        clean = ParseResult(dataset_path="/x/d.json", languages=["python"])
        broken = ParseResult(
            dataset_path="/x/d.json",
            languages=["python"],
            parse_errors=[{"language": "go", "error": "boom"}],
        )
        assert not clean.degraded
        assert broken.degraded


class TestScanResultBackCompat:
    def test_existing_construction_still_works(self):
        r = ScanResult(output_dir="/out", language="javascript", units_count=5)
        assert r.language == "javascript"

    def test_new_fields_default_to_empty(self):
        r = ScanResult(output_dir="/out")
        assert r.languages == []
        assert r.language_stats == {}
        assert r.parse_errors == []

    def test_to_dict_includes_new_fields_and_stays_json_safe(self):
        r = ScanResult(
            output_dir="/out",
            language="python",
            languages=["python", "javascript"],
            language_stats={"python": 8, "javascript": 7},
        )
        d = json.loads(json.dumps(r.to_dict()))
        assert d["language"] == "python"
        assert d["languages"] == ["python", "javascript"]
        assert d["language_stats"]["javascript"] == 7

    def test_to_dict_keeps_every_pre_existing_key(self):
        """The hand-written to_dict must not drop fields when extended."""
        d = ScanResult(output_dir="/out").to_dict()
        for key in (
            "output_dir", "dataset_path", "units_count", "language",
            "metrics", "usage", "step_reports", "skipped_steps",
            "skipped_step_reasons",
        ):
            assert key in d, f"to_dict lost pre-existing key {key!r}"

    def test_degraded_is_derived(self):
        assert not ScanResult(output_dir="/out").degraded
        assert ScanResult(
            output_dir="/out", parse_errors=[{"language": "c", "error": "x"}]
        ).degraded
