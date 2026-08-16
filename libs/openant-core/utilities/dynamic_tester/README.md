# Dynamic Tester

Bridges OpenAnt's static analysis pipeline and confirmed exploitability by running Docker-isolated dynamic exploit tests against every finding.

## Overview

The dynamic tester takes `pipeline_output.json` — the output of OpenAnt's static analysis pipeline (Stages 1 and 2) — and for each finding:

1. Sends the finding to Claude Sonnet, which generates a self-contained Docker test (Dockerfile + test script + dependencies)
2. Builds and runs the test in an isolated Docker container
3. Parses the container's structured JSON output
4. Classifies the result: `CONFIRMED`, `NOT_REPRODUCED`, `BLOCKED`, `INCONCLUSIVE`, or `ERROR`
5. If the test fails (build error or runtime crash), feeds the error back to the LLM for one retry

This adds a `DYNAMIC_TESTED` step to the pipeline, between `VERIFIED` (Stage 2) and `REPORTED`.

## Prerequisites

- **Docker Engine** must be installed and running
- **Anthropic API key** in `.env` (used for Claude Sonnet test generation)
- No additional Python packages required (uses `subprocess` for Docker CLI)

## Quick Start

### Standalone CLI

```bash
# Run against a pipeline output file
python -m utilities.dynamic_tester datasets/langchain/pipeline_output.json

# Specify a custom output directory
python -m utilities.dynamic_tester datasets/langchain/pipeline_output.json --output-dir /tmp/results
```

### Python API

```python
from utilities.dynamic_tester import run_dynamic_tests

results = run_dynamic_tests("datasets/langchain/pipeline_output.json")

for r in results:
    print(f"{r.finding_id}: {r.status} — {r.details}")
```

### Autopilot Integration

The dynamic tester runs automatically as part of the autopilot pipeline between the verify and report steps. It is budget-gated (default $5.00 per repo) and can be configured in `autopilot/config.py`.

```bash
# Runs automatically in the pipeline
python -m autopilot --repo owner/repo
```

## Output Files

After running, two files are written to the output directory (defaults to the same directory as the input file):

| File | Format | Contents |
|------|--------|----------|
| `DYNAMIC_TEST_RESULTS.md` | Markdown | Human-readable report with summary table, per-finding details, evidence, and generated test code |
| `dynamic_test_results.json` | JSON | Structured results for programmatic consumption |

### JSON Output Schema

```json
{
  "repository": "langchain",
  "total_findings": 3,
  "total_cost_usd": 0.1234,
  "results": [
    {
      "finding_id": "VULN-001",
      "status": "CONFIRMED",
      "details": "Successfully read /etc/passwd via path traversal",
      "evidence": [
        {"type": "file_read", "content": "root:x:0:0:root:/root:/bin/bash..."}
      ],
      "test_code": "...",
      "dockerfile": "...",
      "docker_compose": "",
      "elapsed_seconds": 45.2,
      "generation_cost_usd": 0.0412
    }
  ]
}
```

## Architecture

```
pipeline_output.json
  │
  ▼
┌─────────────────────┐    Claude Sonnet    ┌──────────────────┐
│   test_generator.py  │ ────────────────▶  │  Dockerfile       │
│   (LLM prompt +      │                    │  test_script      │
│    CWE guidance)      │                    │  requirements     │
└─────────────────────┘                     │  docker_compose?  │
                                            └────────┬─────────┘
                                                     │
                                                     ▼
                                            ┌──────────────────┐
                                            │ docker_executor.py│
                                            │  docker build     │
                                            │  docker run       │
                                            │  (isolated, 512MB)│
                                            └────────┬─────────┘
                                                     │
                                     ┌───────────────┼───────────────┐
                                     │ success        │ build/runtime │
                                     │                │ error         │
                                     ▼                ▼               │
                              ┌──────────┐    ┌──────────────┐       │
                              │ parse    │    │ regenerate   │       │
                              │ JSON     │    │ (retry once) │───────┘
                              │ stdout   │    └──────────────┘
                              └────┬─────┘
                                   │
                                   ▼
                            ┌──────────────┐
                            │result_collector│
                            │ classify:     │
                            │ CONFIRMED     │
                            │ NOT_REPRODUCED│
                            │ BLOCKED       │
                            │ INCONCLUSIVE  │
                            │ ERROR         │
                            └──────────────┘
                                   │
                                   ▼
                            ┌──────────────┐
                            │  reporter.py  │
                            │  .md + .json  │
                            └──────────────┘
```

## File Inventory

| File | Purpose |
|------|---------|
| `__init__.py` | Public API — `run_dynamic_tests(pipeline_output_path, output_dir)` |
| `__main__.py` | CLI entry point — `python -m utilities.dynamic_tester <path>` |
| `models.py` | `DynamicTestResult` and `TestEvidence` dataclasses |
| `test_generator.py` | Sends findings to Claude Sonnet, receives Dockerfile + test script |
| `docker_executor.py` | Builds images, runs containers, handles compose and cleanup |
| `result_collector.py` | Parses container stdout JSON, classifies results |
| `reporter.py` | Generates the Markdown report |
| `docker_templates/python.Dockerfile` | Reference Dockerfile for Python tests (`python:3.11-slim`) |
| `docker_templates/node.Dockerfile` | Reference Dockerfile for Node.js tests (`node:20-slim`) |
| `docker_templates/go.Dockerfile` | Reference Dockerfile for Go tests (`golang:1.22-alpine`) |
| `docker_templates/attacker_server.py` | HTTP capture server for SSRF/exfiltration tests (port 9999) |

## Container Output Contract

Every test container **must** print exactly one JSON object to stdout as its final output:

```json
{
  "status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR",
  "details": "Human-readable explanation of the result",
  "evidence": [
    {
      "type": "file_read|http_response|command_output|network_capture",
      "content": "The actual evidence data"
    }
  ]
}
```

All debug output must go to stderr. The result collector looks for the last valid JSON object in stdout.

### Status Definitions

| Status | Meaning |
|--------|---------|
| `CONFIRMED` | The vulnerability was successfully exploited. Evidence proves it. |
| `NOT_REPRODUCED` | The test ran correctly but the exploit did not succeed (e.g., input was sanitized). |
| `BLOCKED` | A security control prevented the exploit (e.g., WAF, permission denied). |
| `INCONCLUSIVE` | The test ran but the result is ambiguous (e.g., partial evidence, timeout). |
| `ERROR` | The test itself failed (build error, import error, crash). Not a finding verdict. |

## Container Security

All containers run with strict isolation:

- **Read-only filesystem** (`--read-only`) with `/tmp` and `/root` as writable tmpfs
- **No privilege escalation** (`--security-opt no-new-privileges`)
- **All capabilities dropped** (`--cap-drop ALL`)
- **PID limit** — 256 (`--pids-limit`)
- **Memory limit** — 512 MB (`--memory 512m`)
- **CPU limit** — 1 CPU (`--cpus 1`)
- **Isolated network** — single-container tests run with `--network none`; multi-service
  tests run on an `internal: true` Docker network (no external gateway)
- **No host volume mounts / no privileged mode** — enforced, not assumed: an untrusted
  multi-service `docker-compose` is *reconstructed* from an allowlist (see below), so
  `privileged`, `cap_add`, host `volumes`, `pid`/`ipc`/`network_mode`, `devices`, etc.
  cannot reach the runtime
- **Timeouts** — 120s for execution, 300s for builds

Multi-service tests (e.g., those needing the attacker capture server) use Docker Compose
on an internal network, with each service reconstructed and hardened identically.

## Attacker Capture Server

For testing SSRF, data exfiltration, and callback-based vulnerabilities, a lightweight HTTP capture server is provided at `docker_templates/attacker_server.py`.

**Port:** 9999

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check — returns `{"status": "ok"}` |
| `/capture` | GET/POST | Captures the full request (method, path, headers, body) |
| `/logs` | GET | Returns all captured requests as a JSON array |
| `/logs/clear` | POST | Clears the captured request log |

In Docker Compose, the test container references the attacker server as `http://attacker:9999`. Tests should wait for `/health` before running the exploit, then check `/logs` for captured requests.

## Retry Mechanism

When a test fails due to a Docker build error or a runtime crash (non-zero exit code, not timeout):

1. The error message (up to 2000 chars) is sent back to Claude Sonnet along with the original finding and the failed Dockerfile/requirements
2. The LLM generates a corrected test
3. The corrected test is executed once (no further retries)

Common issues the retry fixes:
- Missing directories (e.g., `mkdir -p` needed)
- Dependency version conflicts
- Wrong import paths or missing sub-packages
- Docker Compose service name mismatches

## Test Generation

The LLM receives:
- Finding details (CWE, location, description, vulnerable code, steps to reproduce)
- Repository info (name, language, application type)
- CWE-specific testing guidance for common CWEs (22, 78, 79, 89, 94, 134, 918, 200, 502)
- Rules about Docker isolation, output format, dependency management

It returns a JSON object with:
- `dockerfile` — complete Dockerfile
- `test_script` + `test_filename` — the exploit test code
- `requirements` + `requirements_filename` — dependency file
- `docker_compose` — docker-compose.yml if multi-service (null otherwise)
- `needs_attacker_server` — boolean flag

LLM-generated docker-compose files are post-processed by `_sanitize_compose()` to:
- Remove obsolete `version:` keys
- Replace remote attacker image references with `build: ./attacker-server`

## Cost

| Item | Cost |
|------|------|
| Test generation (Claude Sonnet) | ~$0.03-0.05 per finding |
| Retry generation | ~$0.04-0.06 additional per retried finding |
| Docker execution | Free (local) |
| Autopilot budget default | $5.00 per repo (~25-30 findings) |
| Autopilot cost rate | $0.15 per finding (for budget estimation) |

## Autopilot Configuration

In `autopilot/config.py`, the dynamic test step has its own budget:

```yaml
budgets:
  dynamic_test:
    max_cost_usd: 5.0
    over_budget: abort    # abort | warn | ignore
```

The step transitions the repo to `DYNAMIC_TESTED` on completion or `DYNAMIC_TEST_SKIPPED` if skipped (no findings, missing pipeline_output, or over budget).

## Extending

### Adding a new language

1. Add a Dockerfile template to `docker_templates/`
2. Add the language mapping to `LANGUAGE_MAP` in `test_generator.py`
3. The LLM will use the language context to generate appropriate test scripts

### Adding CWE-specific guidance

Add entries to the `_get_cwe_guidance()` function in `test_generator.py`. The guidance string is appended to the LLM prompt for findings matching that CWE ID.

### Changing container security settings

Modify the `docker run` flags in `docker_executor.py:_run_single()`. The current settings prioritize isolation over flexibility.
