"""#434: a model spelled any conventional way still gets its price.

Live-observed on master, two runs: `--llm-config verify-cheap-haiku` (claude-haiku-4-5,
8,771 tokens) reported total_cost_usd 0.0 with cost_incomplete + unpriced_models
["claude-haiku-4-5"]; `via-gemini37` (google/gemini-3.7-flash) warned "no pricing ...
cost will be reported as $0". find_model and every pricing lookup compare exact
strings, but OpenRouter accepts the same model under several spellings and
config/models.json prices each model under only one of them: claude-haiku-4-5-20251001
/ anthropic/claude-haiku-4.5 priced, the bare claude-haiku-4-5 absent; the bare
claude-opus-5 / claude-sonnet-5 absent; and the gemini-3.7 family missing entirely (a
stale-family gap, priced here from BOTH live sources: Google's own pricing page and
the OpenRouter catalogue both say $0.75/$3.75 per 1M for gemini-3.7-flash — Google's
page with the documented Jan-1-2027 step to $1.50/$7.50).

The fix: pricing_map emits each priced record under its conventional ALIAS spellings
too (vendor-prefixed and bare, dotted and dashed versions — the #344 family
conventions), so every existing exact-key consumer (the adapters'
`binding.adapter.pricing.get(binding.model)`, record_call's fallback,
report/generator) resolves aliases with zero consumer changes; find_model gets the
same family-normalized fallback for structural lookups. Same-family records agree on
price by the #344 cross-check, so an alias landing on a sibling record is cost-safe by
construction. A genuinely unknown family still misses (cost_incomplete stays honest).
"""
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

from core.model_registry import find_model, pricing_map  # noqa: E402


def test_pricing_map_resolves_the_live_failure_spellings():
    """The issue's enumerated live failures: the bare and slashed spellings
    resolve to the priced record's rate within their provider's map. (A DATED
    spelling is an Anthropic-convention form — its home is the anthropic map,
    where the dated record carries it exactly; an OpenRouter config would use
    the OpenRouter spelling.)"""
    or_map = pricing_map("openrouter")
    # haiku: registered as anthropic/claude-haiku-4.5, spelled bare-dashed live
    assert or_map.get("claude-haiku-4-5") == {"input": 1.0, "output": 5.0}
    an_map = pricing_map("anthropic")
    assert an_map.get("claude-haiku-4-5-20251001") == {"input": 1.0, "output": 5.0}
    # opus-5 / sonnet-5: registered slashed, spelled bare live
    assert or_map.get("claude-opus-5") is not None
    assert or_map.get("claude-sonnet-5") is not None


def test_pricing_map_resolves_dotted_and_dashed_both_ways():
    """The version may be dotted (OpenRouter convention) or dashed (the
    registry's own convention) — both resolve."""
    or_map = pricing_map("openrouter")
    assert or_map.get("anthropic/claude-haiku-4.5") == {"input": 1.0, "output": 5.0}
    assert or_map.get("anthropic/claude-haiku-4-5") == {"input": 1.0, "output": 5.0}
    an_map = pricing_map("anthropic")
    # the dated record answers its date-stripped and dotted spellings
    assert an_map.get("claude-haiku-4-5") == {"input": 1.0, "output": 5.0}
    assert an_map.get("claude-haiku-4.5") == {"input": 1.0, "output": 5.0}


def test_gemini_37_family_is_priced():
    """The stale-family gap: gemini-3.7-flash priced under BOTH providers
    (live-verified: $0.75/$3.75 per 1M — Google's pricing page and the
    OpenRouter catalogue agree)."""
    for provider in ("google", "openrouter"):
        m = pricing_map(provider)
        key = "gemini-3.7-flash" if provider == "google" else "google/gemini-3.7-flash"
        assert m.get(key) == {"input": 0.75, "output": 3.75}, (provider, key)
    rec = find_model("google/gemini-3.7-flash")
    assert rec is not None and rec["price"] == {"input": 0.75, "output": 3.75}


def test_find_model_family_fallback():
    """Structural lookups resolve aliases too: status/price for a
    conventionally-spelled id."""
    rec = find_model("claude-haiku-4-5")
    assert rec is not None and rec.get("price"), rec
    assert find_model("claude-opus-5") is not None
    # exact ids keep their exact records
    assert find_model("claude-opus-4-8")["id"] == "claude-opus-4-8"


def test_unknown_family_still_misses_honestly():
    """A family with NO priced record resolves nowhere — cost_incomplete
    (#216's marker) stays honest."""
    assert find_model("totally-unknown-model-9") is None
    assert pricing_map("openrouter").get("totally-unknown-model-9") is None
    assert pricing_map("google").get("gemini-9.9-nano") is None


def test_suffix_versions_get_aliases():
    """Wave r1 (sonnet): _alias_spellings only built the dotted/dashed pair
    when the version was the TRAILING token — every id with a tier suffix
    (gemini-3.7-flash, gpt-4.1-mini, gemini-1.5-pro — most of the registry)
    got ZERO aliases, reproducing the exact silent-$0 bug for a dash-spelled
    config (gemini-3-7-flash)."""
    or_map = pricing_map("openrouter")
    or_map.update(pricing_map("google"))
    for slashed, dashed in [
        ("google/gemini-3.7-flash", "gemini-3-7-flash"),
        ("openai/gpt-4.1-mini", "gpt-4-1-mini"),
        ("google/gemini-1.5-pro", "gemini-1-5-pro"),
    ]:
        if slashed in or_map:  # the record must exist for the alias to apply
            assert or_map.get(dashed) == or_map[slashed], (slashed, dashed)
            bare = slashed.split("/", 1)[1]
            assert or_map.get(bare) == or_map[slashed], (slashed, bare)


def test_find_model_prefers_the_same_provider():
    """Wave r1 (sonnet): the family fallback returned the FIRST array match
    regardless of provider — a cross-provider-divergent family (the exact
    #344 shape) silently resolves a queried id to a wrong-priced sibling.
    The same-provider record wins when the family holds one."""
    # claude-opus-4-8 family: anthropic + 2 bedrock + openrouter records.
    # The query's vendor slug is anthropic -> the ANTHROPIC record wins (the
    # wrong-priced sibling — whichever landed first in the array — won before).
    rec = find_model("anthropic/claude-opus-4-8")
    assert rec is not None
    assert rec["id"] == "claude-opus-4-8", (
        f"the same-provider record wins: {rec['id']}"
    )
    assert rec["provider"] == "anthropic"
