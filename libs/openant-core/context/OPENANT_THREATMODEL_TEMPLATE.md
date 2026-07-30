# OPENANT.THREATMODEL.md Template

This file provides a **custom threat model** for OpenAnt vulnerability analysis.
Place it, named exactly `OPENANT.THREATMODEL.md`, in your repository root.

It is the alternative to `OPENANT.md` / the built-in four-type classifier. Use it when
your application's attacker model does not fit `web_app` / `cli_tool` / `library` /
`agent_framework` — which is most non-trivial infrastructure.

**`OPENANT.THREATMODEL.md` is deliberately NOT one of the `MANUAL_OVERRIDE_FILES`.**
It is consumed by its own code path (`context/threat_model.py`), so the built-in
application-type path and the threat-model path can be run side by side on the same
repository and compared.

---

## Why a threat model instead of an application type

The built-in path compresses your entire adversary model into one enum value plus one
boolean (`requires_remote_trigger`), which feeds two hardcoded personas: *"an attacker
on the internet with a browser and nothing else"* and *"a local user with shell
access"*. If neither describes your real adversary, every verdict inherits that error.

A threat model instead states, explicitly and per-repository:

- a **free-form classification** (no enum),
- **components** with **free-form component types** and an exposure level,
- **named attacker profiles** with explicit CAN and CANNOT capability lists,
- **input sources** with trust levels and which components handle them,
- what **IS** a vulnerability here and what is **NOT**,
- the concrete **impact** of a successful compromise.

---

## Required heading skeleton

A well-formed document has these headings, in this order:

1. `## Purpose`
2. `## Architecture & Components`
3. `## Attacker Profiles`
4. `## Input Sources & Trust Levels`
5. `## What IS a Vulnerability`
6. `## What is NOT a Vulnerability`
7. `## Impact`
8. `## Machine-Readable Threat Model`

The headings are for humans and for PR review. **The fenced JSON block (a `json` code fence) under
"Machine-Readable Threat Model" is the machine truth** and is what gets strictly
validated. Missing headings produce a warning; a malformed or invalid json block is a
hard error.

The parser scans **every** JSON code fence in the file and picks the one whose object
declares `"schema": "openant-threat-model"`. Illustrative json elsewhere in your prose
(including everything in this template above the worked example) is ignored.

---

## Schema v1 reference

### Required top-level fields

| Field | Type | Notes |
|-------|------|-------|
| `schema` | string | Must be exactly `"openant-threat-model"` |
| `schema_version` | integer | Must be `1`. Any other value is an error naming the supported versions |
| `classification` | string | **Free-form.** e.g. `"Kubernetes deployment orchestrator"` |
| `purpose` | string | 1–3 sentences on what the system does |
| `components` | object[] | See below. Must be non-empty |
| `attacker_profiles` | object[] | See below. Must be non-empty |
| `input_sources` | object | Map of source name → spec. Must be non-empty |
| `vulnerability_criteria` | string[] | What counts as a vulnerability here. Must be non-empty |
| `not_a_vulnerability` | string[] | May be empty, **but the key must be present** |
| `impact_statement` | string | What a successful compromise actually costs |

### Optional top-level fields

`architecture`, `intended_behaviors` (string[]), `security_model` (string),
`confidence` (0.0–1.0), `evidence` (string[]), `generated_by` (string).

### `components[]`

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | Referenced by `input_sources[*].handled_by` |
| `paths` | string[] | Repo-relative paths/globs. Non-empty |
| `component_type` | string | **Free-form** — `"manifest watcher"`, `"reconciliation loop"`, `"admission webhook"` |
| `exposure` | enum | `remote` \| `local` \| `internal` |
| `description` | string | Optional |

### `attacker_profiles[]`

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Short stable id, referenced in reports |
| `description` | string | Who this actually is, in one sentence |
| `position` | enum | `remote` \| `adjacent` \| `local_user` \| `supply_chain` \| `insider` |
| `capabilities` | string[] | What they **CAN** do. Non-empty |
| `cannot` | string[] | What they **CANNOT** do. Non-empty — this is what kills false positives |
| `entry_via` | string[] | **Must name keys of `input_sources`.** Non-empty |
| `impact` | string | What they achieve if they win |

### `input_sources`

Map of source name → `{ "trust": ..., "description": ..., "handled_by": [...] }`.

- `trust` — `untrusted` \| `semi_trusted` \| `trusted`, accepted case-insensitively.
- `description` — required.
- `handled_by` — optional; **each entry must name a declared component**.

### Cross-reference rules (dangling references are errors)

- every `attacker_profiles[*].entry_via` entry must name a key of `input_sources`;
- every `input_sources[*].handled_by` entry must name a `components[*].name`.

### Derived legacy fields

You do not write these; OpenAnt derives them so existing consumers keep working:

- `application_type` = `"custom:" + slug(classification)`
- `trust_boundaries` = `{input source name: trust level}`
- `requires_remote_trigger` = any profile at `position: "remote"`, **or** any input
  source marked `untrusted`

### Validation behaviour

Validation collects **every** violation and reports them together — you fix a
hand-written document in one pass, not one error per scan.

**If `OPENANT.THREATMODEL.md` is absent, OpenAnt falls back to the built-in path. If it
is present but malformed, the scan FAILS LOUDLY.** This inverts the behaviour of
`OPENANT.md`, which degrades to a warning. The reason is blast radius: a broken
`OPENANT.md` costs you a better-than-default context, whereas a broken threat model
would silently analyse your repository under the default `web_app` attacker model
while producing a report that looks completely successful.

---

## KNOWN GAP — this file is attacker-influenceable and is NOT prompt-injection-fenced

**Read this before enabling threat models on repositories you do not control.**

This file originates in the scanned repository. It is therefore
attacker-influenceable: whoever can land a commit in the target repository can write
its contents. Unlike scanned **source code**, which is wrapped in delimiters before
being placed in a prompt (`prompts/_fence.py`), the threat model's contents are
**NOT prompt-injection-fenced**. Its text — classifications, attacker descriptions,
`not_a_vulnerability` entries, and any prose the author chooses to put in a string
field — reaches the analysis model unfenced.

A hostile repository can therefore ship a threat model that declares nothing to be a
vulnerability: an empty `vulnerability_criteria`, a `not_a_vulnerability` list that
covers the whole codebase, every input source marked `trusted`, or instructions
embedded in a description field. The scan will then report clean, and it will look
like a normal clean scan.

**This is an accepted, documented risk, per an explicit user decision. It is not
fixed.** The mitigations are visibility, not prevention:

**None of the following are implemented yet.** They are the mitigations this
gap REQUIRES before threat models should be trusted on repositories you do not
control. Listing them as if they existed would be worse than the gap itself —
a reviewer would approve the risky configuration on the strength of controls
that are not there:

- [ ] record the file's SHA-256 in the scan report;
- [ ] render "context supplied by repo-controlled file" in the report header;
- [ ] warn loudly when a threat model marks *every* input source `trusted`;
- [ ] add a test named for this gap so it appears in test output.

Until those exist, treat a repo-supplied threat model as advisory only.
  rather than only in documentation.

**Operational guidance:** treat `OPENANT.THREATMODEL.md` as you would treat a CI
configuration file committed by a third party. Review it in the diff. For repositories
you do not control, prefer the built-in application-type path, or supply your own
threat model out-of-band rather than trusting the one in the tree.

---

## Complete worked example

The example below is a case **the built-in four-type enum cannot express**: a
deployment orchestrator that watches a git repository of manifests and reconciles them
into a cluster. Its real adversary is *a developer with commit access to the watched
manifest repo who has no shell on the orchestrator*. That attacker is neither "an
attacker on the internet with a browser" nor "a local user with shell access", so
`web_app` over-flags and `cli_tool` under-flags. Note the `component_type` values
(`"manifest watcher"`, `"reconciliation loop"`, `"admission webhook"`) — none of which
any enum would contain — and the `cannot` lists, which are what suppress false
positives without suppressing the real bug class.

# Threat Model: GitOps deployment orchestrator

## Purpose

Watches a git repository of Kubernetes manifests and continuously reconciles the
declared state into one or more target clusters. Renders templates, resolves secret
references, and applies the result via the Kubernetes API.

## Architecture & Components

Long-running controller. No inbound HTTP surface except a cluster-internal admission
webhook and a localhost health endpoint.

- **manifest-watcher** (manifest watcher, exposure: internal) — `internal/gitwatch/`
- **template-renderer** (template engine, exposure: internal) — `internal/render/`
- **reconciler** (reconciliation loop, exposure: internal) — `internal/reconcile/`
- **admission-webhook** (admission webhook, exposure: local) — `cmd/webhook/`
- **secret-resolver** (secret backend client, exposure: internal) — `internal/secrets/`

## Attacker Profiles

### `manifest-committer` — Developer with commit access to the watched manifest repo, no shell on the orchestrator

**Position:** supply_chain

**CAN:**
- Commit arbitrary YAML to the watched manifest repository
- Choose template values, file paths and manifest field values freely
- Trigger a reconcile at will by pushing a commit
- Observe reconcile outcomes through the orchestrator's status conditions

**CANNOT:**
- Execute shell commands on the orchestrator host
- Read the orchestrator's filesystem or environment directly
- Reach the secret backend directly (only via a manifest secret reference)
- Modify the orchestrator's own configuration or its RBAC binding

**Enters via:** git_manifest_repo, template_values

**Impact if successful:** Escalates from "may declare workloads" to arbitrary code execution inside the orchestrator's pod, which holds a cluster-admin-equivalent service account.

### `cluster-tenant` — Namespaced tenant able to submit resources to the admission webhook

**Position:** adjacent

**CAN:**
- Submit arbitrary AdmissionReview payloads to the webhook
- Create resources in their own namespace

**CANNOT:**
- Commit to the manifest repository
- Reach the reconciler or secret resolver directly

**Enters via:** admission_review_payload

**Impact if successful:** Denial of service on admissions cluster-wide, or bypass of a policy the webhook is meant to enforce.

## Input Sources & Trust Levels

- **git_manifest_repo** — `untrusted` — YAML manifests read from the watched repository (handled by: manifest-watcher, template-renderer)
- **template_values** — `untrusted` — Values files and inline template parameters supplied alongside manifests (handled by: template-renderer)
- **admission_review_payload** — `untrusted` — AdmissionReview objects POSTed by the API server on behalf of any cluster user (handled by: admission-webhook)
- **secret_backend_response** — `semi_trusted` — Secret material returned by the external secret backend (handled by: secret-resolver)
- **orchestrator_config** — `trusted` — Operator-supplied config file and flags, set at deploy time (handled by: reconciler)

## What IS a Vulnerability

- Template rendering that allows a manifest author to reach outside the template sandbox (function injection, arbitrary file read via template include, SSTI)
- Path traversal in manifest or values file resolution that reads files outside the checkout
- Any path by which a manifest field reaches a shell, exec, or plugin loader
- Secret material from the secret resolver being written into status, logs, or a rendered manifest visible to the manifest author
- Reconciler applying a manifest that escalates the orchestrator's own RBAC
- Unauthenticated or spoofable admission webhook requests, or a webhook panic that fails open
- Deserialization of manifest YAML into arbitrary Go types

## What is NOT a Vulnerability

- The orchestrator applying manifests to the cluster — that is the entire product
- The orchestrator holding a high-privilege service account — required by design, documented, and scoped by the operator at install time
- A manifest author declaring a workload with a privileged securityContext — the cluster's own admission policy governs that, not the orchestrator
- File writes inside the ephemeral checkout directory
- The operator-supplied config file controlling which repos are watched — trusted input, set by whoever deployed the orchestrator
- Resource exhaustion from a very large manifest repository — rate limited and bounded, and the manifest author already controls their own reconcile budget

## Impact

Compromise of the orchestrator yields the orchestrator's service account, which is
cluster-admin-equivalent on every target cluster it reconciles into. The realistic
worst case is a developer with commit access to one manifest repository pivoting to
full control of every cluster the orchestrator manages — a large privilege jump from
their intended authority, and the reason template-sandbox escapes are treated as
critical here even though they are "only" reachable from a trusted-ish developer.

## Machine-Readable Threat Model

```json
{
  "schema": "openant-threat-model",
  "schema_version": 1,
  "classification": "GitOps deployment orchestrator",
  "purpose": "Watches a git repository of Kubernetes manifests and continuously reconciles the declared state into one or more target clusters.",
  "architecture": "Long-running controller. No inbound HTTP surface except a cluster-internal admission webhook and a localhost health endpoint.",
  "components": [
    {
      "name": "manifest-watcher",
      "paths": ["internal/gitwatch/"],
      "component_type": "manifest watcher",
      "exposure": "internal",
      "description": "Clones and polls the watched manifest repository."
    },
    {
      "name": "template-renderer",
      "paths": ["internal/render/"],
      "component_type": "template engine",
      "exposure": "internal",
      "description": "Renders manifest templates against values files."
    },
    {
      "name": "reconciler",
      "paths": ["internal/reconcile/"],
      "component_type": "reconciliation loop",
      "exposure": "internal",
      "description": "Diffs rendered manifests against live cluster state and applies changes."
    },
    {
      "name": "admission-webhook",
      "paths": ["cmd/webhook/"],
      "component_type": "admission webhook",
      "exposure": "local",
      "description": "Cluster-internal HTTPS endpoint invoked by the API server."
    },
    {
      "name": "secret-resolver",
      "paths": ["internal/secrets/"],
      "component_type": "secret backend client",
      "exposure": "internal",
      "description": "Resolves secret references in manifests against an external backend."
    }
  ],
  "attacker_profiles": [
    {
      "id": "manifest-committer",
      "description": "Developer with commit access to the watched manifest repo, no shell on the orchestrator",
      "position": "supply_chain",
      "capabilities": [
        "Commit arbitrary YAML to the watched manifest repository",
        "Choose template values, file paths and manifest field values freely",
        "Trigger a reconcile at will by pushing a commit",
        "Observe reconcile outcomes through the orchestrator's status conditions"
      ],
      "cannot": [
        "Execute shell commands on the orchestrator host",
        "Read the orchestrator's filesystem or environment directly",
        "Reach the secret backend directly (only via a manifest secret reference)",
        "Modify the orchestrator's own configuration or its RBAC binding"
      ],
      "entry_via": ["git_manifest_repo", "template_values"],
      "impact": "Escalates from 'may declare workloads' to arbitrary code execution inside the orchestrator's pod, which holds a cluster-admin-equivalent service account."
    },
    {
      "id": "cluster-tenant",
      "description": "Namespaced tenant able to submit resources to the admission webhook",
      "position": "adjacent",
      "capabilities": [
        "Submit arbitrary AdmissionReview payloads to the webhook",
        "Create resources in their own namespace"
      ],
      "cannot": [
        "Commit to the manifest repository",
        "Reach the reconciler or secret resolver directly"
      ],
      "entry_via": ["admission_review_payload"],
      "impact": "Denial of service on admissions cluster-wide, or bypass of a policy the webhook is meant to enforce."
    }
  ],
  "input_sources": {
    "git_manifest_repo": {
      "trust": "untrusted",
      "description": "YAML manifests read from the watched repository.",
      "handled_by": ["manifest-watcher", "template-renderer"]
    },
    "template_values": {
      "trust": "untrusted",
      "description": "Values files and inline template parameters supplied alongside manifests.",
      "handled_by": ["template-renderer"]
    },
    "admission_review_payload": {
      "trust": "untrusted",
      "description": "AdmissionReview objects POSTed by the API server on behalf of any cluster user.",
      "handled_by": ["admission-webhook"]
    },
    "secret_backend_response": {
      "trust": "semi_trusted",
      "description": "Secret material returned by the external secret backend.",
      "handled_by": ["secret-resolver"]
    },
    "orchestrator_config": {
      "trust": "trusted",
      "description": "Operator-supplied config file and flags, set at deploy time.",
      "handled_by": ["reconciler"]
    }
  },
  "vulnerability_criteria": [
    "Template rendering that allows a manifest author to reach outside the template sandbox (function injection, arbitrary file read via template include, SSTI)",
    "Path traversal in manifest or values file resolution that reads files outside the checkout",
    "Any path by which a manifest field reaches a shell, exec, or plugin loader",
    "Secret material from the secret resolver being written into status, logs, or a rendered manifest visible to the manifest author",
    "Reconciler applying a manifest that escalates the orchestrator's own RBAC",
    "Unauthenticated or spoofable admission webhook requests, or a webhook panic that fails open",
    "Deserialization of manifest YAML into arbitrary Go types"
  ],
  "not_a_vulnerability": [
    "The orchestrator applying manifests to the cluster - that is the entire product",
    "The orchestrator holding a high-privilege service account - required by design, documented, and scoped by the operator at install time",
    "A manifest author declaring a workload with a privileged securityContext - the cluster's own admission policy governs that, not the orchestrator",
    "File writes inside the ephemeral checkout directory",
    "The operator-supplied config file controlling which repos are watched - trusted input, set by whoever deployed the orchestrator",
    "Resource exhaustion from a very large manifest repository - rate limited and bounded, and the manifest author already controls their own reconcile budget"
  ],
  "intended_behaviors": [
    "Applies arbitrary Kubernetes resources declared in the watched repository",
    "Renders user-authored templates with user-authored values",
    "Reads secret material from an external backend and injects it into applied manifests"
  ],
  "security_model": "Template rendering runs in a restricted function set; manifest paths are resolved against the checkout root; the webhook requires mTLS from the API server; the orchestrator's own RBAC is immutable at runtime.",
  "impact_statement": "Compromise of the orchestrator yields a cluster-admin-equivalent service account on every target cluster it reconciles into. The realistic worst case is a developer with commit access to one manifest repository pivoting to full control of every managed cluster.",
  "confidence": 0.9,
  "evidence": [
    "README.md describes the GitOps reconcile loop",
    "internal/render/ uses text/template with a custom function map",
    "deploy/rbac.yaml grants cluster-admin to the orchestrator service account"
  ],
  "generated_by": "manual"
}
```

---

## Authoring checklist

- [ ] Every `entry_via` names a key that exists in `input_sources`
- [ ] Every `handled_by` names a component that exists in `components`
- [ ] Every attacker profile has a **non-empty `cannot` list** — this is what prevents false positives
- [ ] `not_a_vulnerability` is present (empty list is allowed, omission is not)
- [ ] `component_type` values describe *your* architecture, not a generic category
- [ ] `classification` is specific enough that the derived `custom:<slug>` reads sensibly
- [ ] You have read the KNOWN GAP section above
