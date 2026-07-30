# OpenAnt Architecture Documentation

OpenAnt is an LLM-powered Static Application Security Testing (SAST) tool that uses a two-stage pipeline for vulnerability analysis with 4-level cost optimization. Supports Python, JavaScript/TypeScript, Go, C/C++, Ruby, PHP, Zig, and Swift.

## Table of Contents

1. [Overview](#overview)
2. [Processing Levels](#processing-levels)
3. [Two-Stage Pipeline](#two-stage-pipeline)
4. [Finding Categories](#finding-categories)
5. [System Components](#system-components)
6. [Data Flow](#data-flow)
7. [Running Experiments](#running-experiments)
8. [Product Export](#product-export)
9. [Dataset Format](#dataset-format)

---

## Overview

Traditional SAST tools rely on pattern matching, producing high false positive rates. OpenAnt uses Claude for semantic code analysis with a two-stage approach:

1. **Stage 1 (Detection):** Simple prompts ask direct questions about security
2. **Stage 2 (Verification):** Opus with tools validates each finding

Key insight: **Simple, direct prompts work better than complex instructions.**

---

## Processing Levels

The parser pipeline supports four processing levels for cost optimization:

| Level | Name | Filter | Cost Reduction |
|-------|------|--------|----------------|
| 1 | `all` | None | - |
| 2 | `reachable` | Entry point reachability | ~94% |
| 3 | `codeql` | Reachable + CodeQL-flagged | ~99% |
| 4 | `exploitable` | Reachable + CodeQL + LLM classification | ~99.9% |

### What Each Level Excludes

| Level | Code NOT Processed | Risk |
|-------|-------------------|------|
| 1: all | None | None - complete coverage |
| 2: reachable | Internal utilities, dead code, non-entry-point functions | Low |
| 3: codeql | Reachable code without known vulnerability patterns | Medium |
| 4: exploitable | security_control, neutral, vulnerable_internal units | Low |

### Usage

```bash
# Level 3 (recommended): Reachable + CodeQL-flagged
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/analyzer.js \
    --processing-level codeql

# Level 4: Maximum savings with LLM classification
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/analyzer.js \
    --processing-level exploitable \
    --llm --agentic
```

### Requirements (for Level 3+)

```bash
brew install codeql
codeql pack download codeql/javascript-queries
codeql pack download codeql/python-queries
```

---

## Two-Stage Pipeline

### Stage 1: Vulnerability Detection

Uses simple, direct prompts:

```
Assess this code for security.

## Code
{code}

## Response
1. What does this code do?
2. What is the security risk?

{
    "finding": "safe" | "protected" | "bypassable" | "vulnerable" | "inconclusive",
    "attack_vector": "...",
    "reasoning": "...",
    "confidence": 0.0-1.0
}
```

**Implementation:** `prompts/vulnerability_analysis.py`

### Stage 2: Finding Verification (Attacker Simulation)

Validates ALL Stage 1 findings using Opus with tool access and **attacker simulation**:

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

**Key Breakthroughs:**

1. **Attacker Simulation (Jan 14, 2026):** Changed Stage 2 from "code analysis mode" to "attacker simulation mode". The model has the knowledge to identify false positives, but only applies it when forced to **simulate being an attacker** rather than **analyze code**.

2. **Multi-Approach Requirement (Jan 19, 2026):** Discovered that single-path exploration missed vulnerabilities (e.g., checking `workspaceId` protection but not `id` injection for mass assignment). Updated prompt to require trying MULTIPLE approaches before concluding safe.

When simulating an attack, the model naturally hits roadblocks:
- "I can't create symlinks on the server because I don't have filesystem access"
- "I can only SELECT from admin-configured endpoints, not provide arbitrary URLs"
- "The input I need to control is admin-configured, not user-provided"

**Results:** 0 false positives on object-browser (25 units)

**Tools available:**
- `search_usages` - Find where a function is called
- `search_definitions` - Find function definitions
- `read_function` - Get full function code
- `list_functions` - List functions in a file
- `finish` - Complete verification

**Implementation:** `utilities/finding_verifier.py`, `prompts/verification_prompts.py`

---

## Finding Categories

Five categories capture the spectrum of security states:

| Category | Meaning | Action |
|----------|---------|--------|
| `vulnerable` | Exploitable vulnerability, no protection | Immediate fix |
| `bypassable` | Security controls can be circumvented | Strengthen |
| `inconclusive` | Cannot determine security posture | Manual review |
| `protected` | Dangerous operations with effective controls | Monitor |
| `safe` | No security-sensitive operations | None |

---

## System Components

### Core Analysis

| File | Purpose |
|------|---------|
| `experiment.py` | Main experiment runner (Stage 1 + Stage 2) |
| `export_csv.py` | CSV export for filtering/sorting |
| `generate_report.py` | HTML report with charts and remediation |

### Prompts

| File | Purpose |
|------|---------|
| `prompts/vulnerability_analysis.py` | Unified Stage 1 prompt (language-agnostic) |
| `prompts/verification_prompts.py` | Stage 2 attacker simulation prompt |
| `prompts/prompt_selector.py` | Routes to vulnerability_analysis prompt |

**Note:** Both Stage 1 and Stage 2 prompts are language-agnostic - the same prompt is used for every supported language.

### Dynamic Tester

| File | Purpose |
|------|---------|
| `utilities/dynamic_tester/__init__.py` | Public API: `run_dynamic_tests()` |
| `utilities/dynamic_tester/test_generator.py` | LLM-based test generation (Claude Sonnet) |
| `utilities/dynamic_tester/docker_executor.py` | Docker build/run with security isolation |
| `utilities/dynamic_tester/result_collector.py` | Parse container output, classify results |
| `utilities/dynamic_tester/reporter.py` | Markdown report generation |
| `utilities/dynamic_tester/docker_templates/` | Base Dockerfiles + attacker capture server |

### Utilities

| File | Purpose |
|------|---------|
| `utilities/finding_verifier.py` | Stage 2 verification with Opus + tools |
| `prompts/verification_prompts.py` | Stage 2 prompts |
| `utilities/llm_client.py` | Anthropic API wrapper + TokenTracker |
| `utilities/context_enhancer.py` | Dataset LLM enhancement |
| `utilities/context_corrector.py` | INSUFFICIENT_CONTEXT handling |
| `utilities/json_corrector.py` | JSON repair |

### Parser Pipeline (JavaScript)

| File | Purpose |
|------|---------|
| `parsers/javascript/repository_scanner.js` | File enumeration |
| `parsers/javascript/unit_generator.js` | Dataset generation |
| `parsers/javascript/dependency_resolver.js` | Call graph building |
| `parsers/javascript/test_pipeline.py` | Pipeline orchestration |

### Parser Pipeline (Python)

| File | Purpose |
|------|---------|
| `parsers/python/parse_repository.py` | Main orchestrator |
| `parsers/python/repository_scanner.py` | Find all .py files |
| `parsers/python/function_extractor.py` | Extract functions + module-level code |
| `parsers/python/call_graph_builder.py` | Build bidirectional call graphs |
| `parsers/python/unit_generator.py` | Generate self-contained units |

### Parser Pipeline (Go)

| File | Purpose |
|------|---------|
| `parsers/go/go_parser/` | Native Go binary for fast AST parsing |
| `parsers/go/go_parser/scanner.go` | Stage 1: Find .go files |
| `parsers/go/go_parser/extractor.go` | Stage 2: Extract functions |
| `parsers/go/go_parser/callgraph.go` | Stage 3: Build call graphs |
| `parsers/go/go_parser/generator.go` | Stage 4: Generate dataset |
| `parsers/go/test_pipeline.py` | Python orchestrator for filtering + LLM |

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         EXPERIMENT RUNNER                        │
│                         (experiment.py)                          │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                          STAGE 1                                 │
│                    ─────────────────                             │
│              Simple prompt, direct questions                     │
│              5-category findings                                 │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                          STAGE 2                                 │
│                    ─────────────────                             │
│              Opus + tools validates ALL findings                 │
│              Agree or correct with explanation                   │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      DYNAMIC TESTING                             │
│                    ─────────────────                             │
│         Sonnet generates Docker exploit tests per finding        │
│         Containers run in isolation, results classified          │
│         CONFIRMED / NOT_REPRODUCED / BLOCKED / INCONCLUSIVE     │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                         PRODUCTS                                 │
│                    ─────────────────                             │
│              CSV export (export_csv.py)                          │
│              HTML report (generate_report.py)                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Running Experiments

### Basic Usage

```bash
# JavaScript dataset
python experiment.py --dataset flowise_vuln4 --verify --verify-verbose

# Python dataset
python experiment.py --dataset geospatial_vuln12 --verify --verify-verbose
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--dataset` | Dataset to analyze: flowise, geospatial, geospatial_vuln12, etc. |
| `--verify` | Enable Stage 2 verification |
| `--verify-verbose` | Verbose Stage 2 output |
| `--review` | Enable proactive LLM context review |
| `--model` | Override model (opus or sonnet) |

### Output

Results saved to: `experiment_{dataset}_{timestamp}.json`

---

## Product Export

### CSV Export

```bash
python export_csv.py experiment.json dataset.json output.csv
```

**Columns:**
- file, unit_id, unit_description, unit_code
- stage2_verdict, stage2_justification
- stage1_verdict, stage1_justification, stage1_confidence
- agentic_classification

### HTML Report

```bash
python generate_report.py experiment.json dataset.json report.html
```

**Features:**
- Stats overview cards
- Interactive pie charts with labels/percentages (Chart.js)
- Category explanation table
- LLM-generated remediation guidance
- Findings table sorted by severity

---

## Dataset Format

### Structure

```json
{
  "name": "flowise_vulnerable_4",
  "repository": "/path/to/repo",
  "units": [
    {
      "id": "file.ts:ClassName.methodName",
      "unit_type": "class_method",
      "code": {
        "primary_code": "// source code...",
        "primary_origin": {
          "file_path": "src/file.ts",
          "start_line": 10,
          "end_line": 50
        },
        "dependencies": [...]
      },
      "llm_context": {
        "reasoning": "Description of what this code does...",
        "security_classification": "vulnerable | security_control | neutral"
      },
      "ground_truth": {
        "vulnerable": true,
        "vulnerability_types": ["Path Traversal"]
      }
    }
  ]
}
```

---

## Vulnerability Types

| Type | Detection Method |
|------|------------------|
| **XSS** | Trace user input to unescaped template output |
| **SQL Injection** | User input to raw SQL queries |
| **Command Injection** | User input to exec/spawn |
| **Path Traversal** | User input to file operations |
| **Open Redirect** | User input to redirect() |
| **Prototype Pollution** | User input to deep merge/assign |
| **SSRF** | User input to fetch/axios URLs |

---

## Cost Analysis

| Stage | Model | Cost per Unit |
|-------|-------|---------------|
| Stage 1 | Opus | ~$0.20 |
| Stage 2 | Opus | ~$1.05 |
| Dynamic test | Sonnet | ~$0.03-0.05 |
| Report | Sonnet | ~$0.05 |

**Total:** ~$1.25 per unit for full two-stage analysis

---

## Test Results

### Python: Geospatial (12 units)

| Metric | Value |
|--------|-------|
| Stage 2 agreed | 9/11 |
| Stage 2 corrected | 2/11 |
| Vulnerable | 8 |
| Bypassable | 1 |
| Safe | 2 |

All eval() RCE vulnerabilities correctly identified.

### JavaScript: Flowise (13 units)

| Metric | Value |
|--------|-------|
| Stage 2 agreed | 11/13 |
| Stage 2 corrected | 2/13 |
| Vulnerable | 5 |
| Bypassable | 7 |
| Protected | 1 |

### Go: Object-Browser (25 units with attacker simulation)

| Metric | Value |
|--------|-------|
| Units analyzed | 25 |
| Final VULNERABLE | **0** |
| Final SAFE | 23 |
| Final PROTECTED | 2 |
| False positive rate | **0%** |

**Key insight:** Attacker simulation mode eliminates false positives by forcing the model to hit the same roadblocks a real attacker would face:
- Symlink attacks require filesystem access attackers don't have
- Admin-controlled inputs (CLI args, config files) not attacker-accessible
- Platform security boundaries (S3 ACLs) prevent exploitation
- Standard security patterns (OAuth/STS) work as designed

### GitHub Patches (33 samples)

| Type | Accuracy |
|------|----------|
| XSS | 91.7% |
| Path Traversal | 100% |
| Command Injection | 100% |
| Prototype Pollution | 30% |
| **Overall** | **75.8%** |

---

## Related Documentation

- `CURRENT_IMPLEMENTATION.md` - Current state and file inventory
- `OPENANT_TWO_STAGE_PLANNING.md` - Two-stage pipeline details
- `utilities/dynamic_tester/README.md` - Dynamic tester documentation
- `datasets/DATASET_FORMAT.md` - Dataset schema documentation
- `parsers/javascript/PARSER_PIPELINE.md` - JavaScript parser docs
- `parsers/python/PARSER_PIPELINE.md` - Python parser docs
- `parsers/go/PARSER_PIPELINE.md` - Go parser docs
- `OBJECT_BROWSER_VULNERABILITY_REPORT.md` - Go test results with exploit path analysis
