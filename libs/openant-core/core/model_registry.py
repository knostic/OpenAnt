"""Single source of truth for provider model IDs, status, and pricing.

Before this module, model IDs and prices were hard-coded literals duplicated
across ``utilities/model_config.py`` and the Go setup wizard, and a passing test
(``test_builtin_model_ids_current.py``) baked an eternal, un-provenanced list of
"dead" model IDs. ``config/models.json`` is now authoritative, read by BOTH the
Python engine (here) and the Go CLI (``internal/models``), mirroring how
``config/languages.json`` is shared. Each record carries ``status`` (OpenAnt's
shipped claim) plus ``source`` + ``retrieved`` (its provenance), so nothing
asserts a provider fact without a receipt.

Three invariants this module exists to hold:

* **A null price is NEVER a zero price.** ``pricing_map`` OMITS any record whose
  ``price`` is null (retired/unknown models). A null price must fall through to
  the cost tracker's documented "unknown model → warn, cost reported as \\$0"
  path, and MUST NOT be materialised as ``{"input": 0, "output": 0}`` — a truthy
  zero dict would price real tokens at \\$0 with no warning, silently corrupting
  cost accounting (and any budget ceiling built on it).
* **A missing config fails LOUD for real work, never silently \\$0.**
  ``require_models`` raises an "installation problem" error rather than degrading
  to an empty map, because an empty pricing map would price every model at \\$0.
  Unlike ``languages.json`` this file feeds no argparse ``choices``, so there is
  no ``--help`` path to keep alive — pricing is only ever needed for real work.
* **Local providers price at an explicit, provenanced \\$0.** Providers whose
  models run on the user's own hardware (``_LOCAL_PROVIDERS``) are exempt from
  the positive-price rule — their \\$0 is free by definition, not an unverified
  vendor quote. Their ``current`` models MUST still carry a non-null, explicit
  ``{"input": 0, "output": 0}`` dict so they are INCLUDED in ``pricing_map``;
  a null price would drop them onto the unknown-model warn path, which is
  wrong for a known, deliberately-free provider.
"""

from __future__ import annotations

import json
import os
import re
import sys
from functools import lru_cache
from pathlib import Path

# Deliberately uses the stdlib ``json`` directly (not utilities.file_io) so this
# module stays a leaf in the import graph — the pricing tables are consumed at
# import time by adapter class bodies, and a cycle there would deadlock startup.

_CONFIG_REL = Path("config") / "models.json"
_SEARCH_LEVELS = 6
_VALID_STATUS = frozenset({"current", "retired", "unknown"})
_VALID_PROVIDERS = frozenset({"anthropic", "openai", "google", "bedrock", "openrouter", "ollama"})

# Local-inference providers: models run on the user's own hardware, so $0 is a
# truthful, verified fact — not an unverified vendor quote. The "current =>
# positive price" invariant exists to stop cloud models silently pricing real
# token spend at $0; it does not apply here. Local models must still carry an
# explicit non-null zero dict (see pricing_map) so cost reporting stays defined.
_LOCAL_PROVIDERS = frozenset({"ollama"})


def _search_upward(start: Path) -> Path | None:
    current = start.resolve()
    for _ in range(_SEARCH_LEVELS):
        candidate = current / _CONFIG_REL
        if candidate.is_file():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def find_models_config() -> Path | None:
    """Locate ``config/models.json``, or ``None`` if it cannot be found.

    Mirrors ``language_registry.find_languages_config``: an explicit
    ``OPENANT_MODELS_CONFIG`` override, then upward from this module (checkout
    and installed layouts), then upward from the CWD.
    """
    override = os.environ.get("OPENANT_MODELS_CONFIG")
    if override:
        candidate = Path(override)
        if candidate.is_file():
            return candidate
        print(
            f"[models] OPENANT_MODELS_CONFIG={override!r} not found; "
            "falling back to search",
            file=sys.stderr,
        )
    found = _search_upward(Path(__file__).parent)
    if found is not None:
        return found
    found = _search_upward(Path.cwd())
    if found is not None:
        # #273 sibling: same CWD-leg visibility as language_registry — the
        # working directory (possibly the scanned repo) supplied the config.
        print(
            f"[models] note: config/models.json located via the working "
            f"directory ({found}); if this is the scanned repository, "
            f"its pricing records are being trusted",
            file=sys.stderr,
        )
    return found


@lru_cache(maxsize=1)
def _load_config() -> dict:
    """Read and cache ``config/models.json``. Returns ``{}`` if not found.

    Tests that mutate the config must call ``_load_config.cache_clear()``.
    """
    path = find_models_config()
    if path is None:
        return {}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_models() -> list[dict]:
    """The raw model records (possibly empty if the config is missing)."""
    return list(_load_config().get("models", []))


def require_models() -> list[dict]:
    """The model records, or a loud failure explaining the install is broken.

    Raises rather than returning ``[]`` because every downstream use is real
    work (pricing a call): an empty list would price every model at \\$0.
    """
    models = load_models()
    if not models:
        searched = os.environ.get("OPENANT_MODELS_CONFIG") or "$OPENANT_MODELS_CONFIG (unset)"
        raise RuntimeError(
            "config/models.json could not be found, so no model pricing is known. "
            "This is an installation problem: refusing to price calls at $0. "
            f"Searched: {searched}, then upward from {Path(__file__).parent} and {Path.cwd()}."
        )
    return models


def pricing_map(provider: str) -> dict[str, dict[str, float]]:
    """``{model_id: {"input", "output"}}`` for one provider's PRICED models.

    Records with a null price (retired/unknown models) are OMITTED — never
    emitted as a zero-valued dict. A caller that looks up an omitted model gets
    ``None`` and routes to the tracker's unknown-model warn path, exactly as an
    entirely-absent model does today. Raises loudly if the config is missing.

    #434: each priced record is ALSO emitted under its conventional ALIAS
    spellings (vendor-prefixed and bare, dotted and dashed versions, date
    stamp stripped — OpenRouter accepts the same model under several
    spellings and configs spell models bare: a live run on claude-haiku-4-5
    lost ALL cost accounting because only anthropic/claude-haiku-4.5 was
    priced). Exact keys are emitted FIRST and an alias only fills an ABSENT
    key, so an exact record always wins; same-family records agree on price
    by the #344 cross-check, so an alias landing on a sibling record is
    cost-safe by construction. A family with NO priced record still misses
    — cost_incomplete (#216's marker) stays honest.
    """
    recs = [
        rec for rec in require_models()
        if rec.get("provider") == provider and rec.get("price")
    ]
    out: dict[str, dict[str, float]] = {}
    for rec in recs:  # pass 1: exact keys win
        price = rec["price"]
        out[rec["id"]] = {"input": float(price["input"]), "output": float(price["output"])}
    for rec in recs:  # pass 2: aliases fill absent keys only
        entry = out[rec["id"]]
        for alias in _alias_spellings(rec["id"]):
            if alias not in out:
                out[alias] = entry
    return out


def _alias_spellings(model_id: str) -> list[str]:
    """The conventional alternate spellings of a model id (#434's enumerated
    set): a vendor slug prefix may be present or absent, an Anthropic
    -YYYYMMDD date stamp may be present or absent, and the trailing version
    may be dotted or dashed. The id itself is never returned."""
    vendor = model_id.split("/", 1)[0] if "/" in model_id else None
    bare = re.sub(r"^[a-z]+/", "", model_id)
    bare = re.sub(r"-\d{8}$", "", bare)  # the Anthropic date stamp
    # wave r1 (sonnet): the version may carry a TIER SUFFIX after the
    # number (gemini-3.7-flash, gpt-4.1-mini — most of the registry); the
    # dotted/dashed pair is built on the version wherever it sits.
    m = re.search(r"-(\d+)-(\d+)(?=($|-[a-z]))", bare)
    if m:  # ...-4-5 (with or without a suffix) -> also ...-4.5
        dotted = bare[:m.start()] + f"-{m.group(1)}.{m.group(2)}" + bare[m.end():]
        dashed = bare
    else:
        m = re.search(r"-(\d+)\.(\d+)(?=($|-[a-z]))", bare)
        if m:  # ...-4.5 -> also ...-4-5
            dotted = bare
            dashed = bare[:m.start()] + f"-{m.group(1)}-{m.group(2)}" + bare[m.end():]
        else:
            dotted = dashed = None
    bases = [b for b in (bare, dashed, dotted) if b]
    out = []
    for b in bases:
        if b != model_id:
            out.append(b)
        if vendor and f"{vendor}/{b}" != model_id:
            out.append(f"{vendor}/{b}")
    return out


def find_model(model_id: str) -> dict | None:
    """The record for a model id, or ``None``. Non-raising (for structural use).

    #434: an exact match first, then the family-normalized fallback — strip
    the vendor slug, the Anthropic date stamp, and unify dotted/dashed
    versions (the same conventions pricing_map's aliases use, so structural
    lookups and pricing agree on which record a spelling means).
    """
    for rec in load_models():
        if rec.get("id") == model_id:
            return rec
    fam = _family_key(model_id)
    if fam is not None:
        # famD panel (sonnet): the family fallback previously returned the
        # FIRST family match by list order — a query carrying a vendor slug
        # (anthropic/claude-opus-4-8) could resolve to another provider's
        # record for the same family (a bedrock twin), with that record's
        # status/source. Prefer same-provider candidates first; cross-
        # provider family matches remain the last resort (an unsuffixed id
        # stays order-stable).
        family_matches = [
            rec for rec in load_models() if _family_key(rec.get("id", "")) == fam
        ]
        if family_matches:
            vendor = model_id.split("/", 1)[0] if "/" in model_id else ""
            if vendor:
                same = [r for r in family_matches if r.get("id", "").startswith(f"{vendor}/")]
                # the bare (unsuffixed) record is the family's canonical
                # form — it wins over same-provider suffixed twins
                bare = [r for r in family_matches if "/" not in r.get("id", "")]
                if bare:
                    return bare[0]
                if same:
                    return same[0]
            return family_matches[0]
    return None


def _family_key(model_id: str) -> str | None:
    """The #344 family conventions: vendor slug stripped, date stamp
    stripped, version unified to dashed."""
    if not isinstance(model_id, str) or not model_id:
        return None
    s = re.sub(r"^[a-z]+/", "", model_id)
    s = re.sub(r"-\d{8}$", "", s)
    # wave r1: suffix-aware — gemini-3.7-flash and gemini-3-7-flash are
    # one family
    m = re.search(r"-(\d+)\.(\d+)(?=($|-[a-z]))", s)
    if m:
        s = s[:m.start()] + f"-{m.group(1)}-{m.group(2)}" + s[m.end():]
    return s


def model_status(model_id: str) -> str | None:
    """A model's ``status``, or ``None`` if it is not in the registry."""
    rec = find_model(model_id)
    return rec.get("status") if rec else None
