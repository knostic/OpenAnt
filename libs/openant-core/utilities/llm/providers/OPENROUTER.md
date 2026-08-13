# Using the OpenRouter adapter

OpenAnt's `openrouter` provider type routes pipeline phases through
[OpenRouter](https://openrouter.ai) — a gateway that fronts many model
providers (Anthropic, OpenAI, Google, and hundreds of others) behind one
OpenAI-compatible endpoint, **one API key, and one prepaid balance**.

Reasons to use it instead of the direct provider adapters:

- **One key, one bill.** A mixed-provider config (e.g. Claude for
  detection, GPT for enhancement, Gemini for reporting) normally needs
  three API keys and three billing accounts. Through OpenRouter it needs
  one of each.
- **Prepaid spending cap.** OpenRouter balances are topped up in
  advance, so a scan can never charge more than what's loaded — a
  useful hard stop for a tool whose token spend scales with repo size.
- **Models without a direct adapter.** Any tool-calling model in
  OpenRouter's catalogue can drive the pipeline, including vendors
  OpenAnt has no adapter for.

## Prerequisites

1. An OpenRouter account with a positive credit balance
   ([openrouter.ai/settings/credits](https://openrouter.ai/settings/credits)).
2. An API key (`sk-or-v1-...`) from
   [openrouter.ai/settings/keys](https://openrouter.ai/settings/keys).

There is nothing to install beyond OpenAnt itself — the adapter uses the
same `openai` SDK the OpenAI adapter ships with.

## Configuration

The `openant setup llm` wizard offers `openrouter` (leave the base URL blank
to use `https://openrouter.ai/api/v1`), or configure `~/.config/openant/config.json`
by hand. A complete single-provider example (all seven pipeline phases are
required):

```json
{
  "$schema_version": 2,
  "default_llm": "via-openrouter",
  "llm_providers": {
    "openrouter": {"type": "openrouter", "api_key": "sk-or-v1-..."}
  },
  "llm_configs": {
    "via-openrouter": {
      "app_context":  {"provider": "openrouter", "model": "openai/gpt-4o-mini"},
      "llm_reach":    {"provider": "openrouter", "model": "anthropic/claude-sonnet-4.6"},
      "enhance":      {"provider": "openrouter", "model": "openai/gpt-4o-mini"},
      "analyze":      {"provider": "openrouter", "model": "anthropic/claude-sonnet-4.6"},
      "verify":       {"provider": "openrouter", "model": "anthropic/claude-sonnet-4.6"},
      "dynamic_test": {"provider": "openrouter", "model": "google/gemini-2.5-flash"},
      "report":       {"provider": "openrouter", "model": "google/gemini-2.5-flash"}
    }
  }
}
```

Run a scan against it:

```bash
openant scan /path/to/repo --llm-config via-openrouter
```

Mixing is fine too — an `llm_configs` entry can point some phases at
`openrouter` and others at a direct provider.

### Key resolution

The adapter resolves its key in this order:

1. `api_key` on the provider entry in `config.json`;
2. the `OPENROUTER_API_KEY` environment variable.

If neither is set, construction fails immediately with a typed
`LLMAuthError`. The adapter deliberately never falls through to the
`openai` SDK's own `OPENAI_API_KEY` default — that would silently send
an OpenAI platform key to a third party.

### `base_url` override

`base_url` defaults to `https://openrouter.ai/api/v1` and only needs
setting when routing through an OpenRouter-compatible proxy or internal
gateway:

```json
"openrouter": {"type": "openrouter", "api_key": "sk-or-v1-...", "base_url": "https://gateway.internal/v1"}
```

## Model IDs

OpenRouter model IDs are `vendor/model` slugs with **dotted** version
numbers — a different convention from the direct providers:

| Direct provider ID | OpenRouter slug |
|---|---|
| `claude-sonnet-4-6` (anthropic) | `anthropic/claude-sonnet-4.6` |
| `claude-haiku-4-5-20251001` (anthropic) | `anthropic/claude-haiku-4.5` |
| `gpt-4o-mini` (openai) | `openai/gpt-4o-mini` |
| `gemini-2.5-flash` (google) | `google/gemini-2.5-flash` |

Browse the full catalogue at
[openrouter.ai/models](https://openrouter.ai/models) or fetch it
unauthenticated:

```bash
curl -s https://openrouter.ai/api/v1/models | python3 -m json.tool | less
```

IDs pass through to OpenRouter verbatim. Two details are handled for
you:

- **Reasoning models.** Slugs like `openai/o3-mini` automatically use
  `max_completion_tokens` instead of `max_tokens`, as those models
  require.
- **Tool calling.** The `enhance` and `verify` phases need it; check the
  `supported_parameters` field in the catalogue (look for `tools`)
  before pointing those phases at an unfamiliar model.

## Cost accounting

`config/models.json` ships pricing records for the current Claude, GPT,
and Gemini models under their OpenRouter slugs, so scan cost reports
price those models correctly. The rates are OpenRouter's, which can
differ from the direct provider's.

A model outside that set still works — it just reports `$0` in cost
accounting with a one-time warning. To price it, add a record to
`config/models.json` with `"provider": "openrouter"` and the rate shown
in the catalogue (OpenRouter lists per-token prices; the registry wants
per-million).

## Errors and troubleshooting

| Symptom | Meaning | Fix |
|---|---|---|
| `LLMAuthError: ... 401 ... User not found` | Bad or revoked key | Re-check the key at [openrouter.ai/settings/keys](https://openrouter.ai/settings/keys) |
| `LLMAuthError: ... OPENROUTER_API_KEY ...` at startup | No key resolvable | Set `api_key` in config.json or export `OPENROUTER_API_KEY` |
| `LLMAuthError: ... 402 ... balance is exhausted` | Out of credits | Top up at [openrouter.ai/settings/credits](https://openrouter.ai/settings/credits) |
| `LLMNotFoundError: ... is not a valid model ID` | Typo'd or delisted slug | Check the exact slug at [openrouter.ai/models](https://openrouter.ai/models); note the dotted versions |
| `LLMRefusalError` on a 403 | OpenRouter's moderation flagged the input | Pick a model/route without mandatory moderation, or expect gaps in coverage for that unit |
| `LLMResponseError: ... provider errored mid-generation` | The upstream provider failed while streaming the answer (OpenRouter reports this inside an HTTP 200) | Retry; if persistent, pick a different model or vendor route |
| `LLMRateLimitError` | 429 from OpenRouter or the upstream provider | Nothing to do — workers back off cooperatively via the global rate limiter |

Two behaviors worth knowing because they differ from the direct
adapters:

- An unknown model comes back from OpenRouter as **HTTP 400**, not 404.
  The adapter still surfaces it as `LLMNotFoundError`, so a typo'd slug
  fails fast at config-validation time instead of mid-scan.
- A 403 is OpenRouter's *moderation* signal, not an auth failure. The
  adapter maps it to `LLMRefusalError` so a moderated prompt can't
  masquerade as a clean, finding-free pass — refusals matter for a
  security scanner.

## Attribution

Requests carry OpenRouter's optional attribution headers
(`HTTP-Referer: https://github.com/knostic/OpenAnt`, `X-Title:
OpenAnt`). They only affect OpenRouter's public app-usage rankings —
never routing, pricing, or auth.

## Current limitations

- The wizard does not yet pre-fill per-phase model suggestions for
  `openrouter` (no `tierModel` entry in `internal/models/registry.go`), so
  you type each phase's model at the prompt (the "Known models" hint helps).
- OpenRouter-specific request extensions (provider routing preferences,
  fallback model lists, ZDR enforcement) are not exposed; requests use
  OpenRouter's account-level defaults, which you can set at
  [openrouter.ai/settings/preferences](https://openrouter.ai/settings/preferences).
