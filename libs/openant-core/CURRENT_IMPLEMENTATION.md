# OpenAnt - Context Document for Claude

This document captures the current state of the OpenAnt SAST project for continuation in future sessions.

**Last Updated:** February 15, 2026 (Dynamic Tester Module)

## Project Overview

OpenAnt is a Static Application Security Testing (SAST) tool that uses LLMs (Claude) to analyze code for security vulnerabilities. The key innovation is a two-stage analysis pipeline with simple, direct prompts, plus a 4-level cost optimization system.

## Processing Levels (Cost Optimization)

The parser pipeline supports four processing levels with cumulative filtering:

| Level | Name | Filter | Cost Reduction |
|-------|------|--------|----------------|
| 1 | `all` | None | - |
| 2 | `reachable` | Entry point reachability | ~94% |
| 3 | `codeql` | Reachable + CodeQL-flagged | ~99% |
| 4 | `exploitable` | Reachable + CodeQL + LLM classification | ~99.9% |

**Example (Flowise `packages/components`):**
- Level 1: 1,417 units
- Level 2: 78 units (94.5% reduction)
- Level 3: 2 units (99.9% reduction)
- Level 4: 2 units (99.9% reduction)

**Usage:**
```bash
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/analyzer.js \
    --processing-level exploitable \
    --llm --agentic
```

## Repository Location

`/Users/nahumkorda/code/openant`

## Current Status

### Two-Stage Vulnerability Analysis Pipeline

**Stage 1 (Detection):** Simple prompt asks direct questions:
- "What does this code do?"
- "What is the security risk?"

**Stage 2 (Verification - Attacker Simulation):** Opus with tool access validates Stage 1 findings using attacker simulation:
- "You are an attacker with only a browser. Try to exploit this step by step."
- Model naturally hits roadblocks that make theoretical vulnerabilities unexploitable
- Achieved 0 false positives on object-browser (25 units)

### Finding Categories

Five categories that capture the spectrum of security states:

| Category | Meaning |
|----------|---------|
| `vulnerable` | Exploitable vulnerability with no effective protection. Immediate fix required. |
| `bypassable` | Security controls exist but can be circumvented. Review and strengthen. |
| `inconclusive` | Security posture cannot be determined. Manual review needed. |
| `protected` | Handles dangerous operations but has effective security controls. |
| `safe` | No security-sensitive operations or risk. |

### Latest Test Results

#### Python: Geospatial (12 vulnerable units)

| Category | Count |
|----------|-------|
| vulnerable | 8 |
| bypassable | 1 |
| safe | 2 |
| (parse error) | 1 |

Stage 2 agreed with Stage 1 on 9/11 units, corrected 2 false positives to safe.

#### JavaScript: Flowise (13 units)

| Category | Count |
|----------|-------|
| vulnerable | 5 |
| bypassable | 7 |
| protected | 1 |

Stage 2 agreed with Stage 1 on 11/13 units, corrected 2 (Playwright/Puppeteer: protected → vulnerable).

#### TypeScript: Grafana (Full Pipeline Run - February 2026)

**Repository:** grafana/grafana (65k+ stars)

| Stage | Input | Output | Cost |
|-------|-------|--------|------|
| Parse | 18,500 functions | 994 reachable units | - |
| Enhance (Agentic) | 994 units | 204 exploitable | $364.80 |
| Detect (Stage 1) | 204 units | 87 vulnerable | $32.17 |
| Verify (Stage 2) | 87 findings | 7 confirmed | $68.78 |
| Dynamic Verification | 7 findings | 2 true vulns | - |
| **Total** | | | **$465.75** |

**Confirmed Vulnerabilities:**
1. **SQL Injection in metricFindQuery** (HIGH) - Dashboard variable queries allow arbitrary SQL
2. **Injection in executeAnnotationQuery** (MEDIUM) - Annotation names passed unsanitized to queries

**Key Metrics:**
- Entry-point filtering: 94.6% reduction (18,500 → 994)
- Security classification: 79.5% reduction (994 → 204)
- Stage 2 false positive filtering: 91.9% (87 → 7)
- Dynamic verification: 71.4% confirmed (7 → 2 unique + 1 duplicate)

## Core Architecture

### 1. Prompts

**Directory:** `prompts/`

```
prompts/
  vulnerability_analysis.py        - Stage 1: Unified detection prompt (language-agnostic)
  verification_prompts.py          - Stage 2: Attacker simulation prompt (moved from utilities/ Jan 14)
  prompt_selector.py               - Routes to vulnerability_analysis prompt
```

**Note:** Both Stage 1 and Stage 2 prompts are language-agnostic - the same prompt is used for every supported language.

**Stage 1 Prompt Format:**
```
Assess this code for security.

## Context
Route: ...
Files: ...
Pre-analysis hint: ...

## Code
```language
{code}
```

## Response
1. What does this code do?
2. What is the security risk?

Provide your assessment as JSON:
{
    "finding": "safe" | "protected" | "bypassable" | "vulnerable" | "inconclusive",
    "attack_vector": "How this could be exploited, or null if safe/protected",
    "reasoning": "...",
    "confidence": 0.0-1.0
}
```

### 2. Stage 2 Verification (Attacker Simulation)

**Files:**
- `prompts/verification_prompts.py` - Attacker simulation prompt (moved from utilities/ on Jan 14)
- `utilities/finding_verifier.py` - Opus with tools: search_usages, search_definitions, read_function, list_functions, finish

**Key Breakthrough (Jan 14, 2026): Attacker Simulation**

Changed Stage 2 from "code analysis mode" to "attacker simulation mode". Instead of asking "Is this code vulnerable?", we ask "You are an attacker with only a browser. Try to exploit this step by step."

**Why it works:** The model has the knowledge to identify false positives, but only applies it when forced to **simulate being an attacker** rather than **analyze code**. When simulating an attack, the model naturally hits roadblocks:
- "I can't create symlinks on the server because I don't have filesystem access"
- "I can only SELECT from admin-configured endpoints, not provide arbitrary URLs"
- "The input I need to control is admin-configured, not user-provided"

**Prompt:**
```
You are a penetration tester. You only report vulnerabilities you can actually exploit.

You are an attacker on the internet. You have a browser and nothing else.
No server access, no admin credentials, no ability to modify files on the server.

Try to exploit this code using MULTIPLE different approaches. Think about:
- What different inputs can you control?
- What different properties/fields can you manipulate?
- What different endpoints or entry points exist?

For EACH approach, trace through step by step until you succeed or hit a blocker.

IMPORTANT:
- Only conclude PROTECTED or SAFE if ALL approaches fail. If ANY approach succeeds, conclude VULNERABLE.
- A vulnerability must harm someone OTHER than the attacker.
```

**Output Format:**
```json
{
    "function_analyzed": "the function signature from TARGET",
    "attack_steps": [
        {"step": 1, "action": "what I do", "can_i_do_this": true/false, "why_not": "if false, why"}
    ],
    "attack_succeeded": true | false,
    "blocked_at_step": null or step number where attack fails,
    "my_verdict": "safe" | "protected" | "vulnerable",
    "explanation": "what happened when I tried to attack"
}
```

**Results:** 0 false positives on object-browser (25 units analyzed, prompt evolution: 10 → 5 → 3 → 2 → 0)

### 2.5. Application Context (New: Jan 23, 2026)

**Problem Solved:** LLM processes units in isolation without understanding the application's purpose. This causes false positives like:
- CLI path traversal flagged as vulnerabilities (user has shell access)
- Agent code execution flagged (intentional feature in agent frameworks)
- Security controls flagged as vulnerabilities (Docker sandboxing)

**Solution:** Generate rich application context once per repository, inject into all prompts.

**Files:**
- `context/application_context.py` - Core module for context generation
- `context/generate_context.py` - CLI wrapper
- `context/OPENANT_TEMPLATE.md` - Manual override template

**Supported Application Types (Standardized):**

| Type | Description | Attack Model |
|------|-------------|--------------|
| `web_app` | Web applications and API servers | Remote attacker with browser/HTTP |
| `cli_tool` | Command-line tools | Local user with shell access |
| `library` | Reusable code packages | No direct surface; depends on caller |
| `agent_framework` | AI agent/LLM frameworks | Code execution is intentional |

Unsupported types (desktop apps, mobile apps, games, embedded systems) are rejected with an error. Use manual override (`OPENANT.md`) to analyze unsupported types.

**Usage:**
```bash
# Generate context via CLI (recommended)
openant generate-context /path/to/repo

# Generate context via Python module
python -m context.generate_context /path/to/repo

# List supported types
python -m context.generate_context --list-types

# Context is saved to application_context.json in the current directory
# Under a project, the Go CLI auto-fills --app-context from the project scan dir
# (operator-owned, never the scanned repo); otherwise pass --app-context explicitly
```

**Generated Context Structure:**
```json
{
  "application_type": "web_app|cli_tool|library|agent_framework",
  "purpose": "1-2 sentence description",
  "intended_behaviors": ["Features that look dangerous but are BY DESIGN"],
  "trust_boundaries": {"input_source": "untrusted|semi_trusted|trusted"},
  "not_a_vulnerability": ["Patterns to NOT flag as vulnerable"],
  "requires_remote_trigger": true,
  "confidence": 0.92
}
```

**Manual Override:** Place `OPENANT.md` or `OPENANT.json` in repo root to provide explicit context. Manual overrides bypass type validation.

**Integration:** Context automatically loaded in `experiment.py` and injected into Stage 1 and Stage 2 prompts.

**Results on LangChain:**
- Without context: 15.8% precision (3/19 true positives)
- With context: Expected significant improvement (reduces CLI, agent, config false positives)

### 3. Experiment Runner

**File:** `experiment.py`

```bash
# Run Stage 1 only
python experiment.py --dataset flowise

# Run Stage 1 + Stage 2 verification
python experiment.py --dataset flowise --verify --verify-verbose
```

Output: `experiment_{name}_{timestamp}.json`

### 4. Product Export

**CSV Export:** `export_csv.py`
```bash
python export_csv.py experiment.json dataset.json output.csv
```

Columns: file, unit_id, unit_description, unit_code, stage2_verdict, stage2_justification, stage1_verdict, stage1_justification, stage1_confidence, agentic_classification

**HTML Report:** `generate_report.py`
```bash
python generate_report.py experiment.json dataset.json report.html
```

Features:
- Stats overview cards
- Interactive pie charts with labels/percentages (Chart.js)
- Category explanation table
- LLM-generated remediation guidance
- Findings table sorted by severity

### 5. Parser Pipeline (JavaScript/TypeScript)

**Directory:** `parsers/javascript/`

Four-stage pipeline:

| Stage | File | Purpose |
|-------|------|---------|
| 1 | `repository_scanner.js` | Enumerate all source files |
| 2 | `Hyperion/.../typescript_analyzer.js` | Extract functions with metadata |
| 3 | `unit_generator.js` + `dependency_resolver.js` | Build call graph, generate dataset |
| 4 | `utilities/context_enhancer.py` | LLM enhancement (optional) |

```bash
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output /path/to/output --llm --agentic
```

### 6. Parser Pipeline (Python) - NEW

**Directory:** `parsers/python/`

Four-stage pipeline mirroring JavaScript:

| Stage | File | Purpose |
|-------|------|---------|
| 1 | `repository_scanner.py` | Find all .py files |
| 2 | `function_extractor.py` | Extract functions + module-level code |
| 3 | `call_graph_builder.py` | Build bidirectional call graphs |
| 4 | `unit_generator.py` | Generate self-contained units |

**Orchestrator:** `parse_repository.py`

```bash
# Parse a Python repository
python parsers/python/parse_repository.py /path/to/repo --output dataset.json

# With Stage 2 verification support (analyzer_output.json)
python parsers/python/parse_repository.py /path/to/repo \
    --output dataset.json \
    --analyzer-output analyzer_output.json

# With intermediate files for debugging
python parsers/python/parse_repository.py /path/to/repo \
    --output dataset.json \
    --intermediates /tmp/parsing
```

**Stage 2 Support:**
The Python parser now generates `analyzer_output.json` compatible with `RepositoryIndex`, enabling Stage 2 verification tools (search_usages, search_definitions, read_function, list_functions).

**Key Feature - Module-Level Code:**
The Python parser extracts module-level code (code outside functions/classes) as `__module__` units. This is critical for Streamlit apps and scripts where vulnerabilities like `eval()` appear at module level.

**Documentation:**
- `PARSER_PIPELINE.md` - Human-readable explanation
- `PARSER_UPGRADE_PLAN.md` - Technical reference for Claude

### 7. Parser Pipeline (Go) - NEW

**Directory:** `parsers/go/`

Hybrid architecture using Go binary + Python orchestrator:

| Stage | Component | Purpose |
|-------|-----------|---------|
| 1-4 | `go_parser` binary | Native AST parsing (scan, extract, callgraph, generate) |
| 3.5 | Python orchestrator | Reachability filtering |
| 3.6-3.7 | Python orchestrator | CodeQL analysis + filtering |
| 4 | Python orchestrator | LLM enhancement |
| 4.5 | Python orchestrator | Exploitable filtering |

**Orchestrator:** `test_pipeline.py`

```bash
# Build Go binary
cd parsers/go/go_parser && go build -o go_parser .

# Run pipeline
python parsers/go/test_pipeline.py /path/to/go/repo \
    --output /path/to/output \
    --processing-level codeql
```

**Test Results (object-browser):**
- 189 Go files
- 1,260 functions extracted
- 92 reachable units (92.7% reduction)
- 25 units analyzed with attacker simulation (exploitable + vulnerable_internal)
- Final: 0 VULNERABLE, 23 SAFE, 2 PROTECTED (0% false positive rate)

**Documentation:**
- `parsers/go/PARSER_PIPELINE.md` - Human-readable explanation
- `parsers/go/PARSER_UPGRADE_PLAN.md` - Technical reference for Claude

### 8. Agentic Context Enhancement

**Directory:** `utilities/agentic_enhancer/`

Iterative tool-use analysis that traces call paths:
- `repository_index.py` - Searchable function index
- `tools.py` - Tool definitions (search_usages, search_definitions, read_function, etc.)
- `agent.py` - Main agent loop
- `entry_point_detector.py` - Identifies entry points (route handlers, CLI, stdin, etc.)
- `reachability_analyzer.py` - Traces user input reachability via reverse call graph

**Security Classifications (Reachability-Aware):**

| Classification | Meaning |
|----------------|---------|
| `exploitable` | Vulnerable AND reachable from user input (HTTP, CLI, stdin, etc.) |
| `vulnerable_internal` | Vulnerable but NOT reachable from user input (internal APIs, tests) |
| `security_control` | Prevents or blocks vulnerabilities |
| `neutral` | No security relevance |

**Reachability Analysis:**
- Entry point detection identifies functions that receive external input
- BFS traversal of reverse call graph traces paths from entry points
- Units not reachable from entry points can be deprioritized (cost savings)

**Usage:**
```python
from utilities.agentic_enhancer import (
    create_reachability_context,
    enhance_unit_with_agent,
    RepositoryIndex
)

# Create reachability context
entry_points, reachability = create_reachability_context(
    functions=call_graph_data['functions'],
    call_graph=call_graph_data['call_graph'],
    reverse_call_graph=call_graph_data['reverse_call_graph']
)

# Enhance with reachability-aware classification
enhanced = enhance_unit_with_agent(
    unit, index,
    entry_points=entry_points,
    reachability=reachability
)
```

### 8. Support Utilities

```
utilities/
  llm_client.py              - Anthropic API wrapper + TokenTracker
  context_corrector.py       - Handles INSUFFICIENT_CONTEXT
  context_reviewer.py        - Proactive context review
  context_enhancer.py        - Parser output enhancement
  json_corrector.py          - JSON error recovery (auto-created when needed)
  ground_truth_challenger.py - FP/FN arbitration
```

**JSONCorrector Integration (Feb 12, 2026):** The `analyze_unit()` function in `experiment.py` now creates JSONCorrector internally when parsing fails, matching the pattern used by other components (finding_verifier, context_enhancer, context_reviewer). Callers no longer need to pass a JSONCorrector instance.

## Datasets

```
datasets/
  geospatial/                - Python test dataset (streamlit-geospatial)
    dataset.json             - Full dataset (44 units)
    dataset_vulnerable_12.json - 12 units with eval() vulnerabilities
    analyzer_output.json     - Stage 2 support (44 functions)
    analyzer_output_vulnerable_12.json - Stage 2 support (12 functions)
    geospatial_results.csv   - CSV export
    security_report.html     - HTML report

  flowise/                   - JavaScript test dataset
    dataset.json             - Full parsed dataset (25MB, 1,417 units)
    dataset_vulnerable_4.json - 13 units for experiments (with llm_context)
    analyzer_output.json     - Raw AST parser output
    scan_results.json        - File metadata
    flowise_results.csv      - CSV export
    security_report.html     - HTML report

  object_browser/            - Go test dataset
    dataset.json             - Full parsed dataset (1,260 units)
    analyzer_output.json     - Function index for Stage 2

  langchain/                 - Python test dataset (LangChain)
    pipeline_output.json     - Pipeline output with enriched findings
    dynamic_test_results.json - Dynamic test results (structured)
    DYNAMIC_TEST_RESULTS.md  - Dynamic test report (human-readable)

  grafana/                   - TypeScript test dataset (NEW - Feb 2026)
    dataset.json             - Parsed dataset (994 reachable units)
    dataset_enhanced.json    - With agentic enhancement (204 exploitable)
    analyzer_output.json     - Function index (18,500 functions)
    experiment_results.json  - Stage 1 detection results
    dynamic_verification.json - Dynamic verification results
    disclosures/             - Security advisories for confirmed vulns

  github_patches/            - Real-world vulnerability patches
    dataset_full_33.json     - 33 evaluated samples (75.8% accuracy)

  github_patches_python/     - Python vulnerability dataset
    out/patch_pairs_python.jsonl - 50 security patches from 17 repos
    github_repo_filter_python.py - Collector script

  dvna/, nodegoat/, juice_shop/ - JavaScript test apps
  pygoat/, dvpwa/, vulpy/    - Python test apps
```

## Test Repositories

### Python Test Repository

**Location:** `/Users/nahumkorda/code/test_repos/streamlit-geospatial`

**Commit:** `3f9b00a` (vulnerable version before security fix)

**Known Vulnerabilities:**
- 9 instances of `eval()` on user input (RCE)
- SSRF via unrestricted URL loading

**Test Results:**
- 16 Python files scanned
- 44 units extracted (29 functions + 15 module-level)
- 12 units containing eval() vulnerabilities
- 100% coverage including module-level code

**Verification Command:**
```bash
cd /Users/nahumkorda/code/openant/parsers/python
python parse_repository.py /Users/nahumkorda/code/test_repos/streamlit-geospatial \
    --output /tmp/test_dataset.json
```

### Go Test Repository

**Location:** `/Users/nahumkorda/code/test_repos/object-browser`

**Known Vulnerabilities (per CodeQL):**
- 5 security issues flagged
  - `go/disabled-certificate-check`: 1
  - `go/clear-text-logging`: 3
  - `go/log-injection`: 1

**Test Results (Stage 2 with attacker simulation):**
- 189 Go files scanned
- 1,260 units extracted
- 92 reachable units (92.7% reduction)
- 25 units analyzed with attacker simulation (exploitable + vulnerable_internal)
- **Final: 0 VULNERABLE, 23 SAFE, 2 PROTECTED (0% false positive rate)**

**Verification Command:**
```bash
cd /Users/nahumkorda/code/openant/parsers/go
python test_pipeline.py /Users/nahumkorda/code/test_repos/object-browser \
    --output /tmp/object_browser \
    --processing-level codeql
```

## Model Strategy

| Task | Model | Cost (per MTok) |
|------|-------|-----------------|
| Stage 1 (detection) | Opus | $15 / $75 |
| Stage 2 (verification) | Opus | $15 / $75 |
| Context enhancement | Sonnet | $3 / $15 |
| Dynamic test generation | Sonnet | $3 / $15 |
| JSON repair, corrections | Sonnet | $3 / $15 |
| Report remediation | Sonnet | $3 / $15 |

## Key Design Decisions

1. **Simple prompts**: Ask direct questions, trust model capabilities
2. **Nuanced categories**: 5-level spectrum instead of binary VULNERABLE/SAFE
3. **Two-stage validation**: Stage 2 independently verifies Stage 1
4. **Python-only LLM calls**: JavaScript/Python parsers do static analysis only
5. **Cost optimization**: Sonnet for auxiliary tasks, Opus for analysis
6. **Module-level extraction**: Capture all code, not just functions

## File Inventory

### Core Analysis
```
experiment.py              - Main experiment runner
export_csv.py              - CSV export
generate_report.py         - HTML report with LLM remediation
```

### Prompts
```
prompts/
  vulnerability_analysis.py        - Unified Stage 1 prompt (language-agnostic)
  verification_prompts.py          - Stage 2 attacker simulation prompt
  prompt_selector.py               - Routes to vulnerability_analysis prompt
```

### Application Context
```
context/
  __init__.py              - Package exports
  application_context.py   - Core context generation (ApplicationContext dataclass, LLM generation)
  generate_context.py      - CLI wrapper (python -m context.generate_context /path/to/repo)
  OPENANT_TEMPLATE.md     - Manual override template documentation
```

### Report Generator
```
report/
  __init__.py              - Package exports
  __main__.py              - CLI entry point (python -m report)
  generator.py             - Report generation using Claude Opus 4.5
  schema.py                - Input validation (PipelineOutput, Finding dataclasses)
  prompts/
    system.txt             - Anti-slop system prompt for professional writing
    summary.txt            - Summary report template
    disclosure.txt         - Disclosure document template
```

### Autopilot (New)
```
autopilot/
  __init__.py              - Package init
  __main__.py              - CLI entry point with 3 modes: discover, --repo, --path
  config.py                - YAML config loading + Pydantic validation
  state.py                 - ExecutionState, RepoRecord, RepoState enum
  scheduler.py             - Main loop, signal handling (SIGINT/SIGTERM)
  runner.py                - CycleRunner: orchestrates one cycle across repos
  pipeline.py              - Per-repo pipeline: dispatches to steps based on state
  cost.py                  - Cost estimation + AI-driven BudgetAdvisor
  confirmation.py          - Terminal-based user confirmation (CLI mode)
  logging_.py              - Dual-output logger (JSONL + stderr) with token tracking
  api_protocol.py          - JSON protocol definitions (events + commands)
  api_runner.py            - API mode main loop for TypeScript wrapper
  README.md                - Full autopilot documentation
  steps/
    __init__.py
    discover.py            - Step 1: GitHub repo discovery + pool management
    assess.py              - Step 2: Heuristic pre-filter + LLM assessment
    parse.py               - Step 3: Clone (if needed), parse, filter to reachable units
    enhance.py             - Step 4: Agentic enhancement (cost-gated, logs tokens)
    detect.py              - Step 5: Stage 1 detection (cost-gated, logs per-unit)
    verify.py              - Step 6: Stage 2 verification (cost-gated, logs per-unit)
    dynamic_test.py        - Step 7: Dynamic testing via Docker (cost-gated)
    report.py              - Step 8: Summary report + per-vuln disclosures
  state/                   - State file storage
  logs/                    - JSONL log storage
```

### Utilities
```
utilities/
  __init__.py
  llm_client.py            - API wrapper + TokenTracker
  finding_verifier.py      - Stage 2 verification (imports from prompts/verification_prompts.py, accepts app_context)
  context_enhancer.py      - Dataset LLM enhancement
  context_corrector.py     - INSUFFICIENT_CONTEXT handling
  context_reviewer.py      - Proactive context review
  json_corrector.py        - JSON repair
  ground_truth_challenger.py - FP/FN arbitration

  dynamic_tester/          - Docker-based dynamic exploit testing
    __init__.py              - Public API: run_dynamic_tests()
    __main__.py              - CLI: python -m utilities.dynamic_tester
    models.py                - DynamicTestResult, TestEvidence dataclasses
    test_generator.py        - LLM test generation (Claude Sonnet)
    docker_executor.py       - Docker build/run with security isolation
    result_collector.py      - Parse container output, classify results
    reporter.py              - Markdown report generation
    docker_templates/
      python.Dockerfile      - Python base image
      node.Dockerfile        - Node.js base image
      go.Dockerfile          - Go base image
      attacker_server.py     - HTTP capture server for SSRF/exfiltration tests

  agentic_enhancer/        - Agentic context analysis
    __init__.py              - Package exports
    repository_index.py      - Searchable function index
    tools.py                 - Tool definitions for LLM
    prompts.py               - System and user prompts
    agent.py                 - Main agent loop
    entry_point_detector.py  - Entry point detection (route handlers, CLI, etc.)
    reachability_analyzer.py - User input reachability analysis
```

### JavaScript Parser
```
parsers/javascript/
  repository_scanner.js
  dependency_resolver.js
  unit_generator.js
  test_pipeline.py
  PARSER_PIPELINE.md
```

### Python Parser
```
parsers/python/
  parse_repository.py      - Main orchestrator
  repository_scanner.py    - Stage 1: Find .py files
  function_extractor.py    - Stage 2: Extract functions + module-level
  call_graph_builder.py    - Stage 3: Build call graphs
  unit_generator.py        - Stage 4: Generate units
  PARSER_PIPELINE.md       - Human documentation
  PARSER_UPGRADE_PLAN.md   - Claude reference
```

### Go Parser (NEW)
```
parsers/go/
  go_parser/               - Native Go binary
    main.go                - CLI entry point
    scanner.go             - Stage 1: Find .go files
    extractor.go           - Stage 2: Extract functions
    callgraph.go           - Stage 3: Build call graphs
    generator.go           - Stage 4: Generate dataset
    types.go               - Shared data structures
    go.mod                 - Go module definition
  test_pipeline.py         - Python orchestrator
  PARSER_PIPELINE.md       - Human documentation
  PARSER_UPGRADE_PLAN.md   - Claude reference
```

## Recent Changes

### Feb 15, 2026 - Dynamic Tester Module

**New Module:** Docker-isolated dynamic exploit testing that bridges static analysis and confirmed exploitability. Takes `pipeline_output.json` findings and generates LLM-based Docker tests to reproduce each vulnerability.

**Files Added:**
- `utilities/dynamic_tester/__init__.py` - Public API: `run_dynamic_tests()`
- `utilities/dynamic_tester/__main__.py` - CLI: `python -m utilities.dynamic_tester`
- `utilities/dynamic_tester/models.py` - `DynamicTestResult`, `TestEvidence` dataclasses
- `utilities/dynamic_tester/test_generator.py` - LLM test generation (Claude Sonnet)
- `utilities/dynamic_tester/docker_executor.py` - Docker build/run with security isolation
- `utilities/dynamic_tester/result_collector.py` - Parse container JSON output, classify results
- `utilities/dynamic_tester/reporter.py` - Markdown report generation
- `utilities/dynamic_tester/docker_templates/python.Dockerfile` - Python base image
- `utilities/dynamic_tester/docker_templates/node.Dockerfile` - Node.js base image
- `utilities/dynamic_tester/docker_templates/go.Dockerfile` - Go base image
- `utilities/dynamic_tester/docker_templates/attacker_server.py` - HTTP capture server (port 9999)
- `autopilot/steps/dynamic_test.py` - Autopilot integration step
- `utilities/dynamic_tester/README.md` - Human programmer documentation
- `utilities/dynamic_tester/DYNAMIC_TESTER_REFERENCE.md` - AI assistant reference

**Files Modified:**
- `autopilot/state.py` - Added `DYNAMIC_TESTED`, `DYNAMIC_TEST_SKIPPED` states
- `autopilot/config.py` - Added `dynamic_test` budget (default $5.00)
- `autopilot/cost.py` - Added `dynamic_test` cost rate ($0.15/finding)
- `autopilot/pipeline.py` - Inserted dynamic test step between verify and report
- `autopilot/api_runner.py` - Added dynamic test to API mode processing
- `autopilot/steps/__init__.py` - Added `dynamic_test_repo` import
- `autopilot/steps/report.py` - Fixed `_build_pipeline_output()` to populate fields from Stage 1 results
- `autopilot/steps/verify.py` - Added `reasoning` and `function_analyzed` pass-through

**Key Features:**
- LLM-generated exploit tests via Claude Sonnet ($0.03-0.05 per finding)
- Container security: `--read-only`, `--no-new-privileges`, `--memory 512m`
- Error-feedback retry: feeds Docker errors back to LLM for corrected regeneration
- Attacker capture server for SSRF/exfiltration tests (port 9999)
- Docker Compose for multi-service tests
- Structured JSON output contract for test classification

**Pipeline Output Fix:**
- `_build_pipeline_output()` was fixed to handle actual Stage 1 output format
- Stage 1 produces flat fields (`reasoning`, `attack_vector`, `function_analyzed`) — NOT a `vulnerabilities` array
- The fix loads `experiment_results.json` for source code (`code_by_route`) and full Stage 1 data

**Test Results (LangChain, 3 findings):**
- 2 CONFIRMED, 0 NOT_REPRODUCED, 1 INCONCLUSIVE, 0 ERROR
- Total cost: ~$0.25

---

### Feb 9, 2026 - API Mode for TypeScript Wrapper

**New Feature:** API mode enables programmatic control of the autopilot via a TypeScript (or any language) wrapper using JSON Lines protocol over stdin/stdout.

**Files Added:**
- `autopilot/api_protocol.py` - Event and command dataclasses for JSON protocol
- `autopilot/api_runner.py` - API mode main loop with discovery and single-repo flows
- `autopilot/confirmation.py` - Terminal-based user confirmation for CLI mode

**Files Modified:**
- `autopilot/__main__.py` - Added `--api` and `--non-interactive` flags
- `autopilot/__init__.py` - Export `APIHandler` and `APIRunner`

**Interaction Modes:**
1. **Interactive (default)** - Prompts user in terminal
2. **Non-interactive (`-n`)** - Proceeds automatically without prompts
3. **API mode (`--api`)** - JSON protocol for TypeScript wrapper

**API Protocol:**
- **Events (Python → Wrapper):** `discovery_complete`, `repo_parsing`, `repo_parsed`, `cost_summary`, `processing_started`, `step_started`, `unit_progress`, `step_complete`, `repo_complete`, `pipeline_complete`, `error`
- **Commands (Wrapper → Python):** `select_repos`, `update_config`, `abort`

**Workflow:**
1. Parse all repos → Emit cost estimates
2. Wait for `select_repos` command
3. Process selected repos with real-time progress events
4. Emit `pipeline_complete` when done

**Usage:**
```bash
python -m autopilot --repo owner/repo --api          # Single repo
python -m autopilot --api                            # Discovery mode
python -m autopilot --repo owner/repo -n             # Non-interactive
```

---

### Feb 8, 2026 - Autopilot Module

**New Module:** Autonomous vulnerability hunting pipeline that discovers, parses, analyzes, and reports on GitHub repositories without human intervention.

**Files Added:**
- `autopilot/__init__.py` - Package init
- `autopilot/__main__.py` - CLI entry point (with 3 operating modes)
- `autopilot/config.py` - YAML config + Pydantic validation
- `autopilot/state.py` - ExecutionState, RepoRecord, RepoState
- `autopilot/scheduler.py` - Main loop + signal handling
- `autopilot/runner.py` - Cycle orchestration
- `autopilot/pipeline.py` - Per-repo state machine
- `autopilot/cost.py` - Cost estimation + BudgetAdvisor
- `autopilot/logging_.py` - Dual-output logger (with token/cost tracking)
- `autopilot/steps/discover.py` - GitHub repo discovery
- `autopilot/steps/assess.py` - LLM-based repo assessment
- `autopilot/steps/parse.py` - Clone + parse + entry-point filtering
- `autopilot/steps/enhance.py` - Agentic context enhancement
- `autopilot/steps/detect.py` - Stage 1 detection
- `autopilot/steps/verify.py` - Stage 2 verification
- `autopilot/steps/report.py` - Report generation
- `autopilot/README.md` - Full documentation
- `autopilot_config.yaml` - Example config
- `langchain_config.yaml` - LangChain test config

**Key Features:**

1. **Three Operating Modes:**
   - **Discover mode** (default): Explore GitHub seeking repositories matching config
   - **GitHub URL mode** (`--repo`): Process a specific GitHub repo (supports private)
   - **Local path mode** (`--path`): Process an already-cloned local repository

2. **Entry-Point Filtering** - After parsing, filters units to only those reachable from entry points using `EntryPointDetector` and `ReachabilityAnalyzer`. Achieved 99% cost reduction on LangChain (6,647 → 79 units).

3. **AI-Driven Budget Decisions** - `BudgetAdvisor` uses LLM to decide proceed/override/abort based on cost vs budget. Does NOT select units (filtering happens in parse step).

4. **State Machine** - Each repo progresses through states: DISCOVERED → ASSESSED → SELECTED → CLONED → PARSED → ENHANCED → DETECTED → VERIFIED → REPORTED → COMPLETED

5. **Comprehensive Logging** - JSONL file + stderr with full tracking:
   - Per-unit processing progress
   - Token usage per LLM call (input, output, total)
   - Costs per operation
   - Errors with full details
   - Verification results and exploit paths

6. **Graceful Shutdown** - SIGINT/SIGTERM triggers atomic state save

7. **Private Repo Support** - Uses `gh` CLI for authentication

**Usage:**
```bash
# Mode 1: Discover (explore GitHub)
python -m autopilot --once

# Mode 2: GitHub URL (specific repo, supports private)
python -m autopilot --repo langchain-ai/langchain
python -m autopilot --repo https://github.com/org/repo
python -m autopilot --repo myorg/private-repo  # Requires gh auth

# Mode 3: Local path (already cloned)
python -m autopilot --path /path/to/local/repo
```

**Test Run (LangChain):**
- Total units: 6,647
- Reachable units: 79 (99% reduction)
- Stage 1 vulnerable: 19/79
- Stage 2 confirmed: 3/19
- Total cost: $50.06

---

### Jan 28, 2026 - Report Generator Module

**New Module:** Automated generation of security reports and disclosure documents from pipeline output.

**Files Added:**
- `report/__init__.py` - Package exports
- `report/__main__.py` - CLI entry point
- `report/generator.py` - LLM-based report generation
- `report/schema.py` - Input validation with dataclasses
- `report/prompts/system.txt` - Anti-slop system prompt
- `report/prompts/summary.txt` - Summary report template
- `report/prompts/disclosure.txt` - Disclosure document template

**Usage:**
```bash
# Generate summary report
python -m report summary pipeline_output.json -o SUMMARY_REPORT.md

# Generate disclosure documents
python -m report disclosures pipeline_output.json -o disclosures/

# Generate all reports
python -m report all pipeline_output.json -o output/
```

**Features:**
- Uses Claude Opus 4.5 for professional security writing
- Anti-slop system prompt eliminates filler phrases and superlatives
- Input validation with typed dataclasses
- Separate commands for summary vs disclosure generation

---

### Jan 19, 2026 - Multi-Approach Stage 2 Verification

**Problem Identified:**
Stage 2 was prematurely concluding "PROTECTED" after trying only ONE attack path. For example, with mass assignment vulnerabilities, it would check if `workspaceId` was protected (it was) and stop - never trying to inject `id` (which was exploitable).

**Fixes Applied:**

1. **Multi-approach requirement:** Updated Stage 2 prompt to require MULTIPLE attack approaches:
   - Try different inputs you can control
   - Try different properties/fields you can manipulate
   - Try different endpoints or entry points
   - Only conclude PROTECTED or SAFE if ALL approaches fail

2. **Victim requirement:** Added constraint that a vulnerability must harm someone OTHER than the attacker.

**Files Modified:**
- `prompts/verification_prompts.py` - Updated verification prompt

**Impact:**
- Multi-approach fix catches vulnerabilities like mass assignment where one property is protected but another is exploitable
- Victim requirement eliminates false positives where the "attack" only affects the attacker themselves

---

### Jan 23, 2026 - Application Context Integration

**Problem Addressed:**
LangChain analysis revealed 84% false positive rate (16/19) because the LLM processes units in isolation without understanding the application's purpose. Key issues:
- CLI path traversal flagged as vulnerabilities (but user already has shell access)
- Agent code execution flagged (but this is the intentional feature of agent frameworks)
- Security controls flagged as vulnerabilities (e.g., Docker sandboxing)

**Solution: Application Context Generation**
New module generates rich security context once per repository, injected into all prompts:

```bash
python -m context.generate_context /path/to/langchain
```

**Generated Context includes:**
- `application_type`: "agent_framework", "web_app", "cli_tool", "library"
- `purpose`: Description of what the application does
- `intended_behaviors`: Features that look dangerous but are BY DESIGN
- `trust_boundaries`: What input sources are trusted vs untrusted
- `not_a_vulnerability`: Specific patterns to NOT flag
- `requires_remote_trigger`: False for CLI tools (local users have shell access)

**Files Added:**
- `context/application_context.py` - Core module
- `context/generate_context.py` - CLI wrapper
- `context/OPENANT_TEMPLATE.md` - Manual override template

**Files Updated:**
- `prompts/vulnerability_analysis.py` - Accepts `app_context` parameter
- `prompts/verification_prompts.py` - Accepts `app_context` parameter
- `prompts/prompt_selector.py` - Passes through `app_context`
- `utilities/finding_verifier.py` - Accepts `app_context` in constructor
- `experiment.py` - Loads and passes `app_context` to all stages

**Manual Override:** Place `OPENANT.md` or `OPENANT.json` in repo root for explicit context.

**Expected Impact:** Significantly reduce false positives for non-web-app codebases.

---

### Jan 14, 2026 - Attacker Simulation: 0 False Positives

**Key Breakthrough:**
Changed Stage 2 from "code analysis mode" to "attacker simulation mode". Instead of asking the model to analyze code for vulnerabilities, we ask it to role-play as an attacker with only a browser, attempting to exploit the vulnerability step-by-step.

**Why it works:**
The model has the knowledge to identify false positives, but only applies it when forced to **simulate being an attacker** rather than **analyze code**. In code analysis mode, the model verifies technical mechanics work. In attacker simulation mode, it naturally hits roadblocks:
- "I can't create symlinks on the server because I don't have filesystem access"
- "I can only SELECT from admin-configured endpoints, not provide arbitrary URLs"

**Prompt evolution:** 10 → 5 → 3 → 2 → 0 vulnerabilities over 7 iterations:
1. Rules-based: 10 vulnerabilities
2. + Threat model: 5 vulnerabilities
3. + Adversarial: 3 vulnerabilities
4. Challenge-based: 2 vulnerabilities
5. + Target marking: 2 vulnerabilities (fixed context confusion)
6. Minimal prompt: 2 vulnerabilities
7. **Attacker simulation: 0 vulnerabilities**

**False positive categories eliminated:**
1. Admin-controlled input treated as attack vector (CLI args, config files)
2. Standard security patterns misidentified (OAuth/STS URL parameters)
3. Platform security boundaries ignored (S3 ACLs, admin-configured endpoints)
4. Context confusion/hallucination (model attributed concerns from context to target)

**Files changed:**
- `prompts/verification_prompts.py` - Moved from `utilities/`, contains attacker simulation prompt
- `utilities/finding_verifier.py` - Updated import path
- `OBJECT_BROWSER_VULNERABILITY_REPORT.md` - Full documentation of approach

**Test Results (object-browser - 25 units):**
- 25 units analyzed (exploitable + vulnerable_internal classifications)
- Final: 0 VULNERABLE, 23 SAFE, 2 PROTECTED
- **0% false positive rate**

---

### Jan 12, 2026 - Go Parser + Enhanced Stage 2

**Go Parser Implementation:**
- Native Go binary (`go_parser`) for fast AST parsing using `go/ast`
- Python orchestrator for filtering and LLM integration
- Full processing level support (all, reachable, codeql, exploitable)
- Tested on object-browser: 1,260 units, 92.7% reachability reduction

**Enhanced Stage 2 Verification:**
- **Explicit vulnerability definitions** - VULNERABLE means exploitable NOW with complete path and control
- **Exploit path tracing** - Requires entry_point → data_flow → sink_reached → attacker_control_at_sink → path_broken_at
- **Consistency checking** - Groups similar code patterns, detects inconsistent verdicts, respects conclusive exploit path analysis
- **Security weakness separation** - Documents dangerous patterns that are not currently exploitable

**Key Files Modified:**
- `prompts/verification_prompts.py` - Added explicit definitions and exploit path requirement
- `utilities/finding_verifier.py` - Added ExploitPath dataclass, consistency checking, `_has_conclusive_exploit_path()` method
- `experiment.py` - Added consistency_updates metric, exploit path display

**Test Results (object-browser - 4 CodeQL units):**
- 4 CodeQL-flagged units analyzed with enhanced Stage 2
- All 4 determined to be false positives:
  - `api/logs.go:logError` - SAFE (format strings hardcoded)
  - `pkg/logger/console.go:errorMsg.json` - PROTECTED (JSON marshaling)
  - `pkg/logger/console.go:fatalMsg.json` - SAFE (json.Marshal escapes characters)
  - `pkg/logger/console.go:infoMsg.json` - SAFE (two-layer protection)

---

### Jan 11, 2026 - Processing Levels + CodeQL Integration

**Problem Addressed:**
Reachability filtering (94% reduction) still left many security-neutral units. CodeQL pre-filtering identifies only units with known vulnerability patterns.

**New 4-Level Processing System:**
| Level | Filter | Stages | Cost Reduction |
|-------|--------|--------|----------------|
| `all` | None | 1-3 | - |
| `reachable` | Entry point reachability | 1-3 + 3.5 | ~94% |
| `codeql` | Reachable + CodeQL-flagged | 1-3 + 3.5 + 3.6-3.7 | ~99% |
| `exploitable` | Reachable + CodeQL + LLM | 1-3 + 3.5 + 3.6-3.7 + 4 + 4.5 | ~99.9% |

**New Pipeline Stages:**
- Stage 3.5: ReachabilityFilter (BFS from entry points)
- Stage 3.6: CodeQL Analysis (database + security queries)
- Stage 3.7: CodeQL Filter (map SARIF to function units)
- Stage 4.5: ExploitableFilter (keep only "exploitable" units)

**CodeQL Integration:**
- Auto-detects language (JavaScript/Python) from scan results
- Creates CodeQL database for repository
- Runs security-extended query suite
- Outputs SARIF format, maps to function units

**Test Results (Flowise `packages/components`):**
- Level 1: 1,417 units → ~$300 agentic cost
- Level 2: 78 units → ~$16 agentic cost
- Level 3: 2 units → **$0.69 agentic cost**
- Level 4: 2 units → $0.69 agentic cost

**Files Modified:**
- `parsers/javascript/test_pipeline.py` - Added ProcessingLevel enum, filtering methods, CodeQL stages
- `parsers/javascript/PARSER_PIPELINE.md` - Updated documentation
- `parsers/javascript/PARSER_UPGRADE_PLAN.md` - Added Phase 7

**Requirements:**
```bash
brew install codeql
codeql pack download codeql/javascript-queries
codeql pack download codeql/python-queries
```

---

### Jan 11, 2026 - Reachability Classification

**Problem Addressed:**
Datasets like DVNA and NodeGoat showed 83-89% of units classified as `vulnerable`, meaning filtering on vulnerability status alone provides minimal cost savings. The key insight: not all vulnerabilities are exploitable — only those reachable from user input pose actual risk.

**New Components:**
- `entry_point_detector.py` - Identifies entry points (route handlers, CLI parsers, stdin, WebSocket, Streamlit widgets)
- `reachability_analyzer.py` - BFS traversal of reverse call graph to trace paths from entry points

**Updated Classification Enum:**
| Classification | Meaning |
|----------------|---------|
| `exploitable` | Vulnerable + reachable from user input (highest priority) |
| `vulnerable_internal` | Vulnerable but no user input path (lower priority) |
| `security_control` | Defensive code |
| `neutral` | No security relevance |

**New Output Format:**
```json
{
  "agent_context": {
    "security_classification": "exploitable",
    "reachability": {
      "is_entry_point": false,
      "reachable_from_entry": true,
      "entry_point_path": ["routes/api.js:handleRequest", "utils/eval.js:unsafeEval"]
    }
  }
}
```

**Expected Cost Savings:**
For codebases where only 30% of units are reachable from entry points, this enables 70% cost reduction by deprioritizing `vulnerable_internal` units.

**Files Modified:**
- `utilities/agentic_enhancer/tools.py` - Updated enum
- `utilities/agentic_enhancer/prompts.py` - Updated system/user prompts
- `utilities/agentic_enhancer/agent.py` - Added reachability parameters
- `utilities/agentic_enhancer/__init__.py` - Export new modules

**Documentation Updated:**
- `parsers/javascript/PARSER_PIPELINE.md`
- `parsers/javascript/PARSER_UPGRADE_PLAN.md`
- `CURRENT_IMPLEMENTATION.md`

---

### Dec 31, 2024 - Python Analysis Pipeline Complete

**Full Python Support in experiment.py:**
- Added `geospatial` and `geospatial_vuln12` to DATASETS, ENHANCED_DATASETS
- Added repository path to REPO_PATHS
- Added analyzer output paths to ANALYZER_OUTPUTS
- Fixed hardcoded JavaScript/TypeScript language detection to use `detect_language()`

**Python Parser Stage 2 Support:**
- Added `generate_analyzer_output()` function to `parse_repository.py`
- New `--analyzer-output` CLI option generates `analyzer_output.json`
- Format compatible with `RepositoryIndex` for Stage 2 verification tools

**Geospatial Dataset Created:**
- `dataset.json` - 44 units (29 functions + 15 module-level)
- `dataset_vulnerable_12.json` - 12 units containing eval() vulnerabilities
- `analyzer_output.json` / `analyzer_output_vulnerable_12.json` - Stage 2 support
- `geospatial_results.csv` - Spreadsheet export
- `security_report.html` - Interactive HTML report

**First Python Vulnerability Analysis:**
- Ran full two-stage analysis on 12 vulnerable units
- Stage 1: Detected 10 vulnerable, 1 bypassable, 1 parse error (fixed by JSON corrector)
- Stage 2: Agreed on 9/11 units, corrected 2 false positives to safe
- Final: 8 vulnerable, 1 bypassable, 2 safe
- All eval() RCE vulnerabilities correctly identified

**Dataset Documentation:**
- Created `datasets/DATASET_FORMAT.md` - Complete schema documentation

### Dec 30, 2024 - Python Parser Implementation

**New Python Parser Pipeline:**
- Created 4-stage parser mirroring JavaScript architecture
- `repository_scanner.py` - Scans for .py files with exclusions
- `function_extractor.py` - Extracts all functions AND module-level code
- `call_graph_builder.py` - Builds bidirectional call graphs
- `unit_generator.py` - Creates self-contained analysis units
- `parse_repository.py` - Orchestrator for complete pipeline

**Module-Level Code Extraction:**
- Critical for Streamlit apps where code runs at module level
- Creates synthetic `__module__` unit for each file with executable module-level code
- Ensures 100% code coverage for vulnerability detection

**Python Vulnerability Dataset:**
- Collected 50 security patches from 17 Python repositories
- Created `github_repo_filter_python.py` collector
- Cloned test repo: streamlit-geospatial with eval() vulnerabilities

**Test Results on streamlit-geospatial:**
- 44 units extracted (29 functions + 15 module-level)
- 12 units containing eval() vulnerabilities
- All vulnerable files captured including module-level code

### Dec 28, 2024 - Simplified Prompts + Products

**Prompt Simplification:**
- Reduced from 4 prompts (416 lines) to 1 prompt (70 lines)
- Direct questions: "What does this code do?" and "What is the security risk?"
- New finding categories: safe, protected, bypassable, vulnerable, inconclusive
- Removed security_classification branching

**Stage 2 Simplification:**
- Changed to simple validator: "Is Stage 1's assessment correct?"
- Removed complex instructions, trust model capabilities

**Product Export:**
- Created `export_csv.py` for 10-column CSV output
- Created `generate_report.py` for HTML report with:
  - Interactive pie charts (Chart.js + datalabels)
  - Category explanation table
  - LLM-generated remediation guidance

**Repository Cleanup:**
- Deleted obsolete experiment files (kept only latest)
- Deleted duplicate datasets (dataset_components.json, dataset_vulnerable_agentic.json)
- Deleted flowise_packages directory (will reprocess later)

### Dec 26, 2024 - Two-Stage Pipeline + Agentic Enhancement

- Implemented Stage 2 verification with Opus + tools
- Created agentic context enhancement (100% accuracy on security control classification)
- Processed Flowise components package (1,417 units)

## Known Weaknesses

1. **Prototype Pollution**: 30% detection rate on github_patches dataset
2. **Security library vulnerabilities**: LLM recognizes defensive code but may miss specific flaws

## Next Steps

1. ~~**Run vulnerability analysis on Python test repo**~~ ✅ Completed Dec 31
2. ~~**Integrate Python parser with experiment.py**~~ ✅ Completed Dec 31
3. ~~**Implement reachability classification**~~ ✅ Completed Jan 11, 2026
4. **Test reachability on full datasets** - Run on Flowise (1,417 units) and Juice Shop (838 units)
5. **Improve Prototype Pollution detection** - Add specific patterns to prompts
6. **Expand evaluation** - Process remaining github_patches XSS samples
7. **Python dataset validation** - Create ground truth for Python datasets
8. **Run full geospatial dataset** - Analyze all 44 units (not just vulnerable 12)
9. **Additional Python test repos** - Test on pygoat, dvpwa, vulpy datasets
