# Using the Bedrock adapter

OpenAnt's `bedrock` provider type runs the pipeline's Claude phases
through [Amazon Bedrock](https://aws.amazon.com/bedrock/) instead of the
direct Anthropic API. Same models, same wire format (the adapter is
built on `anthropic.AnthropicBedrock`), but billed to your AWS account
and authenticated with AWS credentials instead of an API key.

Reasons to use it instead of the `anthropic` adapter:

- **AWS-consolidated billing and governance.** Token spend lands on the
  AWS bill, inside existing budgets, Cost Explorer, and IAM controls —
  no separate Anthropic billing account.
- **No long-lived API key.** Auth rides the standard AWS credential
  chain, including short-lived STS/SSO credentials.
- **Data-locality options.** Regional inference profiles (`us.…`,
  `eu.…`) keep traffic inside a geography; `global.…` profiles trade
  that for better availability.

## Prerequisites

1. An AWS account with **model access enabled** for the Claude models
   you plan to use: Bedrock console → *Model access* → request/enable
   the Anthropic models. Without this, every call fails with an
   AccessDenied 403 (see troubleshooting).
2. Credentials with permission to invoke them. A minimal IAM policy:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["bedrock:InvokeModel"],
       "Resource": [
         "arn:aws:bedrock:*::foundation-model/anthropic.*",
         "arn:aws:bedrock:*:*:inference-profile/*"
       ]
     }]
   }
   ```

   (Both resource types are needed: requests target an inference
   profile, which fans out to regional foundation models.) Add
   `bedrock:ListInferenceProfiles` if you want the listing command
   below to work with the same credentials.
3. Credentials and region visible to the process — see next section.

## Credentials and region

The adapter deliberately takes **no** AWS-specific configuration.
Credentials and region resolve through the AWS SDK's standard chain, so
`openant` authenticates exactly like the `aws` CLI on the same machine:

- **Credentials**, in the SDK's order: `AWS_ACCESS_KEY_ID` /
  `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN` for temporary
  credentials) environment variables; then the `~/.aws/credentials` /
  `~/.aws/config` profiles (honoring `AWS_PROFILE`), including SSO and
  assumed roles.
- **Region**: the `AWS_REGION` environment variable, then the region of
  the resolved AWS profile. If neither is set the SDK falls back to
  `us-east-1` with a warning — set the region explicitly rather than
  relying on that.

Sanity-check both before a scan; if this works, OpenAnt will too:

```bash
aws sts get-caller-identity
aws bedrock list-inference-profiles --query 'inferenceProfileSummaries[].inferenceProfileId'
```

## Configuration

The `openant setup llm` wizard does not offer `bedrock` yet; add it to
`~/.config/openant/config.json` by hand. Note the provider entry has
**no `api_key`** — a complete single-provider example (all seven
pipeline phases are required):

```json
{
  "$schema_version": 2,
  "default_llm": "via-bedrock",
  "llm_providers": {
    "bedrock": {"type": "bedrock"}
  },
  "llm_configs": {
    "via-bedrock": {
      "app_context":  {"provider": "bedrock", "model": "us.anthropic.claude-haiku-4-5-20251001-v1:0"},
      "llm_reach":    {"provider": "bedrock", "model": "us.anthropic.claude-sonnet-4-6"},
      "enhance":      {"provider": "bedrock", "model": "us.anthropic.claude-haiku-4-5-20251001-v1:0"},
      "analyze":      {"provider": "bedrock", "model": "us.anthropic.claude-sonnet-4-6"},
      "verify":       {"provider": "bedrock", "model": "us.anthropic.claude-sonnet-4-6"},
      "dynamic_test": {"provider": "bedrock", "model": "us.anthropic.claude-haiku-4-5-20251001-v1:0"},
      "report":       {"provider": "bedrock", "model": "us.anthropic.claude-haiku-4-5-20251001-v1:0"}
    }
  }
}
```

Run a scan against it:

```bash
openant scan /path/to/repo --llm-config via-bedrock
```

Mixing is fine too — an `llm_configs` entry can point some phases at
`bedrock` and others at any other provider.

If an `api_key` is present on the entry anyway (e.g. a config shared
across provider types), it is ignored with a one-time warning — Bedrock
has no API-key auth in the pinned SDK.

### `base_url` override

Only needed for a Bedrock VPC endpoint (PrivateLink) or an
Anthropic-compatible internal gateway:

```json
"bedrock": {"type": "bedrock", "base_url": "https://vpce-….bedrock-runtime.us-east-1.vpce.amazonaws.com"}
```

## Model IDs are inference profiles

Bedrock does not serve Claude under the direct-API model names. Requests
target **inference profiles**, whose IDs add a routing prefix — and,
inconsistently, a version suffix:

| Direct Anthropic ID | Bedrock inference profile |
|---|---|
| `claude-opus-4-8` | `us.anthropic.claude-opus-4-8` / `global.anthropic.claude-opus-4-8` |
| `claude-sonnet-4-6` | `us.anthropic.claude-sonnet-4-6` / `global.anthropic.claude-sonnet-4-6` |
| `claude-haiku-4-5-20251001` | `us.anthropic.claude-haiku-4-5-20251001-v1:0` / `global.anthropic.claude-haiku-4-5-20251001-v1:0` |

Do **not** guess IDs by convention — the `-v1:0` suffix exists on some
profiles and not others (the table above was verified against a live
account). List what your account actually has:

```bash
aws bedrock list-inference-profiles --query 'inferenceProfileSummaries[].inferenceProfileId'
```

`us.` profiles route within US regions; `global.` profiles route
worldwide for better availability; `eu.` / `apac.` variants exist for
accounts homed in those geographies. IDs pass through to Bedrock
verbatim.

## Cost accounting

`config/models.json` ships pricing records for the profiles in the table
above (both `us.` and `global.` variants), mirroring the direct
Anthropic rates — Bedrock's Claude token pricing matches the direct API.
A profile outside that set still works but reports `$0` in cost
accounting with a one-time warning; add a record with
`"provider": "bedrock"` to price it.

## Errors and troubleshooting

| Symptom | Meaning | Fix |
|---|---|---|
| `LLMAuthError: … AWS_ACCESS_KEY_ID …` | The AWS chain resolved no credentials at all | Export the env vars or configure `~/.aws`; verify with `aws sts get-caller-identity` |
| `LLMAuthError: … 403 … Model access …` | Credentials are valid but the model isn't enabled (or IAM denies `bedrock:InvokeModel`) | Enable the model under *Model access* in the Bedrock console; check the IAM policy above |
| `LLMAuthError: … account is currently being verified …` | New-account holdback — AWS verifies fresh accounts before serving some models | Transient; typically clears within a couple of hours. Meanwhile `global.` profiles may already work |
| `The security token included in the request is invalid` | Expired/rotated or malformed credentials | Refresh them; if pasted by hand, check for copy artifacts (a real `AWS_ACCESS_KEY_ID` is exactly 20 characters) |
| `LLMNotFoundError: … model identifier is invalid …` | Typo'd or unavailable profile ID (Bedrock reports this as a 400, not a 404) | Use `list-inference-profiles` output verbatim; mind the `-v1:0` suffix inconsistency |
| `LLMRateLimitError` | Bedrock throttling (429) | Nothing to do — workers back off cooperatively via the global rate limiter |

Two behaviors worth knowing because they differ from the `anthropic`
adapter:

- **Model access is a second gate.** Valid AWS credentials are not
  enough; each model must also be enabled for the account. That's why
  403s get the "Model access" hint.
- **Unknown models are 400s.** Bedrock reports a bad model ID as a 400
  ValidationException; the adapter still surfaces it as
  `LLMNotFoundError`, so a typo'd profile fails fast at
  config-validation time instead of mid-scan.

## Current limitations

- Not offered by the `openant setup llm` wizard yet (config by hand, as
  above). Wizard support needs a few Go touch-points in
  `apps/openant-cli/cmd/setup.go`.
- Only Claude models. Bedrock hosts other model families, but this
  adapter speaks Anthropic's wire format; non-Claude Bedrock models
  would need their own adapter.
- No per-provider region field — region comes from the environment or
  AWS profile. To scan against two regions, run with different
  `AWS_REGION` values (or `AWS_PROFILE`s) rather than two provider
  entries.
