# Dynamic Tester - Claude Code Reference

Technical reference for AI coding assistants working on the dynamic testing module.

**Module:** `utilities/dynamic_tester/`
**Added:** February 2026
**Purpose:** Bridges static analysis (Stage 2) and confirmed exploitability via Docker-isolated dynamic tests.

## Position in Pipeline

```
Stage 1 (Detect) → Stage 2 (Verify) → Dynamic Test → Report
   DETECTED    →    VERIFIED     → DYNAMIC_TESTED → REPORTED → COMPLETED
```

State machine additions in `autopilot/state.py`:
- `DYNAMIC_TESTED` — dynamic testing completed
- `DYNAMIC_TEST_SKIPPED` — skipped (no findings, no pipeline_output, over budget)

## File Inventory

| File | Purpose | Key Functions/Classes |
|------|---------|----------------------|
| `__init__.py` | Public API | `run_dynamic_tests(pipeline_output_path, output_dir)` |
| `__main__.py` | CLI entry | `python -m utilities.dynamic_tester <path>` |
| `models.py` | Data models | `DynamicTestResult`, `TestEvidence`, `VALID_STATUSES` |
| `test_generator.py` | LLM test gen | `generate_test()`, `regenerate_test()` |
| `docker_executor.py` | Container exec | `run_single_container()`, `_sanitize_compose()` |
| `result_collector.py` | Parse output | `collect_result()` |
| `reporter.py` | Markdown report | `generate_report()` |
| `docker_templates/python.Dockerfile` | Base Python image | `python:3.11-slim` |
| `docker_templates/node.Dockerfile` | Base Node image | `node:20-slim` |
| `docker_templates/go.Dockerfile` | Base Go image | `golang:1.22-alpine` |
| `docker_templates/attacker_server.py` | Capture server | Port 9999, endpoints: `/health`, `/capture`, `/logs`, `/logs/clear` |

## Modified Existing Files

| File | Change |
|------|--------|
| `autopilot/state.py` | Added `DYNAMIC_TESTED`, `DYNAMIC_TEST_SKIPPED` to `RepoState` |
| `autopilot/config.py` | Added `dynamic_test: StepBudget` to `BudgetsConfig` (default $5.00) |
| `autopilot/cost.py` | Added `dynamic_test: 0.15` to `COST_RATES`, added to `estimate_pipeline_costs()` |
| `autopilot/pipeline.py` | Inserted `dynamic_test_repo()` between verify and report in state dispatch |
| `autopilot/api_runner.py` | Added dynamic_test step to API mode processing |
| `autopilot/steps/__init__.py` | Added `dynamic_test_repo` import and export |
| `autopilot/steps/report.py` | Fixed `_build_pipeline_output()` to populate fields from Stage 1 results when `vulnerabilities` array is empty |
| `autopilot/steps/verify.py` | Added `reasoning` and `function_analyzed` to confirmed findings pass-through |

## Data Flow

```
pipeline_output.json (input)
  ├── findings[].description       ← from Stage 1 reasoning
  ├── findings[].vulnerable_code   ← from code_by_route in experiment_results.json
  ├── findings[].impact            ← from Stage 1 attack_vector
  └── findings[].steps_to_reproduce ← composed from attack_vector + exploit_path + verification_explanation

For each finding:
  1. test_generator.generate_test(finding, repo_info, tracker)
     → Claude Sonnet generates: Dockerfile, test_script, requirements, docker_compose (optional)
     → Cost: ~$0.03-0.05 per finding

  2. docker_executor.run_single_container(generation, finding_id)
     → Single container: docker build + docker run (--read-only, --no-new-privileges, 512MB RAM)
     → Multi-service: docker compose up/down (when needs_attacker_server=true)
     → Timeout: 120s container, 300s build

  3. If build or runtime error → test_generator.regenerate_test() with error feedback → retry once

  4. result_collector.collect_result(finding, generation, execution, cost)
     → Parse JSON from container stdout (last JSON object wins)
     → Classify: CONFIRMED / NOT_REPRODUCED / BLOCKED / INCONCLUSIVE / ERROR

Output:
  ├── DYNAMIC_TEST_RESULTS.md   (human-readable report)
  └── dynamic_test_results.json (structured results)
```

## Container Output Contract

Every test container MUST print exactly one JSON object to stdout:

```json
{
  "status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR",
  "details": "Human-readable explanation",
  "evidence": [
    {"type": "file_read|http_response|command_output|network_capture", "content": "..."}
  ]
}
```

All other output must go to stderr.

## Test Generation Prompt

The system prompt in `test_generator.py` instructs Claude Sonnet to:
- Generate self-contained Docker tests (Dockerfile + test script + requirements)
- NOT pin exact dependency versions (use `>=` or no pin)
- Use `build: ./attacker-server` for capture servers (local, port 9999)
- Not include `version:` in docker-compose (obsolete)
- Print structured JSON to stdout, debug to stderr

CWE-specific guidance is injected via `_get_cwe_guidance()` for common CWE IDs (22, 78, 79, 89, 94, 134, 918, 200, 502).

## Docker Compose Reconstruction

`docker_executor._sanitize_compose()` treats the LLM-generated compose as untrusted and
**reconstructs** it rather than patching it. Each declared service is rebuilt from a fixed
key allowlist (`build`/`image`/`depends_on`/`command`/`entrypoint`/`environment`/`expose`/
`working_dir`/`healthcheck`/`networks`) plus a fixed hardening set (`read_only`,
`cap_drop: [ALL]`, `security_opt: [no-new-privileges]`, `pids_limit`, `mem_limit`, `cpus`,
`tmpfs`), so every container-runtime attribute that could reach the host — `privileged`,
`cap_add`, host `volumes`, `pid`/`ipc`/`network_mode`, `devices`, `security_opt`, `user`,
`ports`, … — is dropped by omission. The service **set** is preserved (nothing silently
dropped); every declared network is forced `internal: true`; the attacker image is
local-built. Fails **closed** (a refusing comment-only compose) on unparseable YAML or a
build context that escapes the work dir.

Build-time `RUN` egress remains an accepted, documented residual (an egress-allowlisting
build proxy is deferred).

## Retry Mechanism

On build failure or runtime crash (non-zero exit, not timeout):
1. Error message is fed back to `regenerate_test()` along with original prompt + failed Dockerfile/requirements
2. LLM generates a corrected test
3. Retried once (no further retries)

## Autopilot Integration

`autopilot/steps/dynamic_test.py` follows the same pattern as `verify.py`:

```python
def dynamic_test_repo(repo: RepoRecord, config: AutopilotConfig,
                      budget_advisor: BudgetAdvisor) -> None:
```

- Reads `pipeline_output.json` from `repo.dataset_path` directory
- Budget-gated via `config.budgets.dynamic_test` (default $5.00, abort on over-budget)
- Cost rate: $0.15 per finding (`COST_RATES["dynamic_test"]`)
- Transitions to `DYNAMIC_TESTED` on completion

## Pipeline Output Fix (report.py)

The `_build_pipeline_output()` function was fixed to handle the actual Stage 1 output format. Stage 1 produces flat fields (`reasoning`, `attack_vector`, `function_analyzed`) — NOT a `vulnerabilities` array. The fix:

1. Loads `experiment_results.json` for `code_by_route` (source code) and `results` (full Stage 1 data)
2. Falls back from `vuln.get("description")` → `finding.get("reasoning")` → `full_result.get("reasoning")`
3. Falls back from `vuln.get("vulnerable_code")` → `code_by_route.get(route_key)`
4. Builds `steps_to_reproduce` from `attack_vector` + `exploit_path.data_flow` + `verification_explanation`

## Key Dependencies

- `utilities/llm_client.py` — `AnthropicClient`, `TokenTracker` (Sonnet model: `claude-sonnet-4-20250514`)
- Docker Engine — must be running for container execution
- No additional pip packages required (uses stdlib `subprocess` for Docker CLI)

## Cost

- Test generation: ~$0.03-0.05 per finding (Claude Sonnet)
- Retry: ~$0.04-0.06 additional per retried finding
- Docker execution: free (local)
- Budget default: $5.00 per repo (covers ~25-30 findings)
