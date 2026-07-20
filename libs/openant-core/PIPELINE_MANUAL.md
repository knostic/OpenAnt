# OpenAnt Pipeline Manual

Complete instructions for running the OpenAnt vulnerability analysis pipeline manually.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Pipeline Stages](#pipeline-stages) - Complete 8-step diagram
4. [Steps 1-2: Parsing & Unit Generation](#steps-1-2-parsing--unit-generation)
5. [Dataset Validation](#dataset-validation)
6. [Step 3: Entry-Point Filtering](#step-3-entry-point-reachability-filtering)
7. [Step 4: Application Context](#step-4-application-context-generation)
8. [Step 5: Context Enhancement](#step-5-context-enhancement)
9. [Step 6: Stage 1 Detection](#step-6-stage-1---vulnerability-detection)
10. [Step 7: Stage 2 Verification](#step-7-stage-2---attacker-simulation)
11. [Step 8: Dynamic Testing](#step-8-dynamic-testing)
12. [Results Export](#results-export)
13. [Cost Reference](#cost-reference)
14. [Complete Examples](#complete-examples)

---

## Overview

OpenAnt is a vulnerability analysis tool using Claude. The name "two-stage" refers to the core analysis approach (Stage 1: detection, Stage 2: verification), but the complete pipeline has 8 steps:

| Step | Component | Required | Description |
|------|-----------|----------|-------------|
| 1 | **Parse** | Yes | User selects language-specific parser (Python/JS/Go) |
| 2 | **Generate Units** | Yes | Create self-contained analysis units with dependencies |
| 3 | **Entry-Point Filter** | No | Filter to units reachable from user input |
| 4 | **Application Context** | No | Classify app type for false positive reduction |
| 5 | **Context Enhancement** | No | LLM-based dependency and data flow analysis |
| 6 | **Stage 1: Detection** | Yes | Identify potential vulnerabilities |
| 7 | **Stage 2: Verification** | No | Attacker simulation to confirm exploitability |
| 8 | **Dynamic Testing** | No | Docker-isolated exploit testing (requires Docker) |

**Supported Languages:** Python, JavaScript/TypeScript, Go, C/C++, Ruby, PHP, and Zig

**Two-Stage Analysis:**
- **Stage 1** asks: "Is this code vulnerable?"
- **Stage 2** asks: "Can an attacker actually exploit it?"

---

## Prerequisites

### Required Software

```bash
# Python 3.10+
python3 --version

# Node.js (for JavaScript parser)
node --version

# Go (for Go parser)
go version

# CodeQL CLI (optional, for cost optimization)
brew install codeql
codeql pack download codeql/javascript-queries
codeql pack download codeql/python-queries
```

### API Key

Create `.env` file in the OpenAnt root directory:

```bash
ANTHROPIC_API_KEY=sk-ant-...
```

### Directory Structure

```
openant/
├── datasets/           # Analysis datasets
│   └── <repo_name>/
│       ├── dataset.json
│       ├── analyzer_output.json
│       └── application_context.json
├── parsers/
│   ├── python/
│   ├── javascript/
│   └── go/
├── prompts/            # LLM prompt templates (language-agnostic)
│   ├── vulnerability_analysis.py      # Stage 1 detection prompt
│   ├── verification_prompts.py        # Stage 2 attacker simulation prompt
│   └── prompt_selector.py             # Routes to vulnerability_analysis
├── utilities/
│   ├── llm_client.py              # Anthropic API wrapper + TokenTracker
│   ├── finding_verifier.py        # Stage 2 verification with Opus + tools
│   ├── context_enhancer.py        # Dataset LLM enhancement
│   ├── context_corrector.py       # INSUFFICIENT_CONTEXT handling
│   ├── context_reviewer.py        # Proactive context review
│   ├── json_corrector.py          # JSON error recovery
│   ├── ground_truth_challenger.py # FP/FN arbitration
│   ├── dynamic_tester/            # Docker-based dynamic exploit testing
│   │   ├── __init__.py                # Public API: run_dynamic_tests()
│   │   ├── __main__.py                # CLI entry point
│   │   ├── test_generator.py          # LLM test generation (Claude Sonnet)
│   │   ├── docker_executor.py         # Docker build/run
│   │   ├── result_collector.py        # Parse container output
│   │   ├── reporter.py                # Markdown report
│   │   └── docker_templates/          # Base Dockerfiles + attacker server
│   └── agentic_enhancer/          # Tool-based analysis
│       ├── repository_index.py        # Searchable function index
│       ├── tools.py                   # Tool definitions for LLM
│       ├── prompts.py                 # System and user prompts
│       ├── agent.py                   # Main agent loop
│       ├── entry_point_detector.py    # Entry point detection
│       └── reachability_analyzer.py   # User input reachability
├── context/
│   ├── application_context.py     # Context detection & formatting
│   ├── generate_context.py        # CLI for context generation
│   └── OPENANT_TEMPLATE.md       # Manual override template
├── experiment.py                  # Main entry point
└── validate_dataset_schema.py     # Dataset validation before LLM calls
```

---

## Pipeline Stages

```
┌──────────────────────┐
│     Source Code      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  1. PARSE            │  User selects language-specific parser
│                      │  Python: parse_repository.py
│                      │  JS/TS:  test_pipeline.py + typescript_analyzer.js
│                      │  Go:     test_pipeline.py + go_parser binary
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  2. GENERATE UNITS   │  Create self-contained analysis units
│                      │  with upstream/downstream dependencies
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  3. ENTRY-POINT      │  Filter to units reachable from user input
│     FILTER           │  (Optional - reduces cost by 40-95%)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  4. APPLICATION      │  Classify: web_app | cli_tool | library | agent_framework
│     CONTEXT          │  (Optional - reduces false positives)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  5. CONTEXT          │  LLM-based dependency and data flow analysis
│     ENHANCEMENT      │  (Optional - improves accuracy, adds cost)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  6. STAGE 1          │  Vulnerability detection
│     DETECTION        │  Language-agnostic prompt
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  7. STAGE 2          │  Attacker simulation verification
│     VERIFICATION     │  (Optional - confirms exploitability)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  8. DYNAMIC          │  Docker-isolated exploit testing
│     TESTING          │  (Optional - requires Docker)
└──────────────────────┘
```

**Required Steps:** 1, 2, 6
**Optional Steps:** 3, 4, 5, 7, 8

---

## Steps 1-2: Parsing & Unit Generation

### Python Parser

**Location:** `parsers/python/parse_repository.py`

**Command:**
```bash
python parsers/python/parse_repository.py /path/to/repo \
    --output datasets/myrepo/dataset.json \
    --analyzer-output datasets/myrepo/analyzer_output.json \
    --depth 3 \
    --skip-tests
```

**Arguments:**
| Argument | Description | Default |
|----------|-------------|---------|
| `repo_path` | Path to repository (required) | - |
| `--output, -o` | Output dataset file | `dataset.json` |
| `--analyzer-output, -a` | Function index for Stage 2 | - |
| `--depth, -d` | Dependency resolution depth | 3 |
| `--name, -n` | Dataset name | repo basename |
| `--skip-tests` | Skip test files | false |
| `--intermediates` | Save intermediate files | - |

**Output:**
- `dataset.json` - Analysis units
- `analyzer_output.json` - Function index for verification

---

### JavaScript/TypeScript Parser

**Location:** `parsers/javascript/test_pipeline.py`

**Prerequisites:**
```bash
# TypeScript analyzer location
ANALYZER_PATH=/path/to/typescript_analyzer.js
```

**Command:**
```bash
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path $ANALYZER_PATH \
    --output datasets/myrepo \
    --processing-level codeql
```

**Arguments:**
| Argument | Description | Default |
|----------|-------------|---------|
| `repo_path` | Path to repository (required) | - |
| `--analyzer-path` | TypeScript analyzer (required) | - |
| `--output, -o` | Output directory | `test_output/` |
| `--llm` | Enable LLM enhancement | false |
| `--agentic` | Enable agentic exploration | false |
| `--processing-level` | Cost optimization level | `all` |

**Processing Levels:**
| Level | Filter | Cost Reduction |
|-------|--------|----------------|
| `all` | None | 0% |
| `reachable` | Entry-point reachable | ~94% |
| `codeql` | Reachable + CodeQL-flagged | ~99% |
| `exploitable` | Reachable + CodeQL + LLM | ~99.9% |

**Output Files:**
```
datasets/myrepo/
├── scan_results.json      # File enumeration
├── analyzer_output.json   # Extracted functions
├── dataset.json           # Analysis units
└── codeql-results.sarif   # CodeQL findings (if level >= codeql)
```

---

### Go Parser

**Location:** `parsers/go/test_pipeline.py`

**Prerequisites:**
```bash
# Build Go parser binary
cd parsers/go/go_parser
go build -o go_parser .
cd ../../..
```

**Command:**
```bash
python parsers/go/test_pipeline.py /path/to/repo \
    --output datasets/myrepo \
    --processing-level codeql
```

**Arguments:** Same as JavaScript parser (no `--analyzer-path` needed)

---

## Dataset Validation

After parsing, validate the dataset schema before running expensive LLM operations.

**Location:** `validate_dataset_schema.py`

**Command:**
```bash
python validate_dataset_schema.py datasets/myrepo/dataset.json
```

**What it validates:**
- Each unit has an `id` field
- `unit.code` is a dictionary with `primary_code` (non-empty)
- `code.primary_origin.enhanced` exists and is boolean
- `code.primary_origin.files_included` exists and is a list
- If `enhanced=true`, `files_included` has entries
- If enhanced with multiple files, file boundary markers are present

**Output:**
```
Dataset: datasets/myrepo/dataset.json
Total units: 150
Enhanced units: 45

PASSED: All units match OpenAnt schema
```

**Exit codes:**
- `0` - Validation passed
- `1` - Validation failed (errors listed)

**Recommended workflow:**
```bash
# Parse, validate, then analyze
python parsers/python/parse_repository.py /path/to/repo \
    --output datasets/myrepo/dataset.json

python validate_dataset_schema.py datasets/myrepo/dataset.json && \
    python experiment.py --dataset myrepo --verify
```

This catches schema errors before spending money on API calls.

---

## Step 3: Entry-Point Reachability Filtering

Filter units to only those reachable from user input entry points. This dramatically reduces the number of units to analyze (typically 60-95% reduction) while maintaining security coverage.

### Concept

A function is "reachable" if there exists a call path from any entry point to that function:

```
Entry Point: handle_request()
    │
    ▼
Intermediate: process_data()
    │
    ▼
Target: unsafe_eval()  ← REACHABLE (exploitable)

Isolated: helper_function()  ← NOT REACHABLE (not exploitable)
```

**Entry points** are functions that directly receive external input:
- HTTP route handlers (Flask, Express, FastAPI, Django)
- CLI argument handlers (argparse, click, sys.argv)
- WebSocket handlers
- File/stdin readers
- Streamlit input widgets

### Entry Point Detection Patterns

The detector identifies entry points by:

1. **Unit Type** - Functions classified as `route_handler`, `view_function`, `websocket_handler`, `cli_handler`

2. **Decorators** - Patterns like:
   - `@app.route`, `@router.get`, `@router.post`
   - `@Get()`, `@Post()`, `@Controller()`
   - `@click.command`, `@app.command`
   - `@api_view`, `@require_GET`

3. **User Input Patterns** in code:
   - `request.args`, `request.form`, `request.json`
   - `req.body`, `req.query`, `req.params`
   - `sys.argv`, `argparse.ArgumentParser`
   - `st.text_input`, `st.file_uploader`

### Using Entry-Point Filtering

#### Option 1: Via Processing Level (JavaScript/Go Parsers)

```bash
# Automatic filtering during parsing
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/analyzer.js \
    --output datasets/myrepo \
    --processing-level reachable  # Filters to entry-point reachable
```

Processing levels:
| Level | Description |
|-------|-------------|
| `all` | No filtering |
| `reachable` | Entry-point reachable only |
| `codeql` | Reachable + CodeQL-flagged |
| `exploitable` | Reachable + CodeQL + LLM classified |

#### Option 2: Manual Filtering (Python Script)

For any language, you can manually filter an existing dataset:

```python
import json
from utilities.agentic_enhancer import EntryPointDetector, ReachabilityAnalyzer

# Load analyzer output
with open('datasets/myrepo/analyzer_output.json') as f:
    analyzer = json.load(f)

functions = analyzer['functions']
call_graph = analyzer.get('callGraph', analyzer.get('call_graph', {}))

# Build reverse call graph
reverse_call_graph = {}
for caller, callees in call_graph.items():
    for callee in callees:
        if callee not in reverse_call_graph:
            reverse_call_graph[callee] = []
        reverse_call_graph[callee].append(caller)

# Detect entry points
detector = EntryPointDetector(functions, call_graph)
entry_points = detector.detect_entry_points()
print(f"Entry points found: {len(entry_points)}")

# Analyze reachability
reachability = ReachabilityAnalyzer(
    functions=functions,
    reverse_call_graph=reverse_call_graph,
    entry_points=entry_points,
    max_depth=15
)

# Get all reachable functions
reachable = reachability.get_all_reachable()
print(f"Reachable functions: {len(reachable)} / {len(functions)}")

# Filter dataset
with open('datasets/myrepo/dataset.json') as f:
    dataset = json.load(f)

original_count = len(dataset['units'])
dataset['units'] = [u for u in dataset['units'] if u['id'] in reachable]
print(f"Units: {original_count} → {len(dataset['units'])}")

# Save filtered dataset
with open('datasets/myrepo/dataset_reachable.json', 'w') as f:
    json.dump(dataset, f, indent=2)
```

#### Option 3: Quick CLI Filter

```bash
cd /Users/nahumkorda/code/openant

python3 -c "
import json
from utilities.agentic_enhancer import EntryPointDetector, ReachabilityAnalyzer

# Load data
analyzer = json.load(open('datasets/myrepo/analyzer_output.json'))
dataset = json.load(open('datasets/myrepo/dataset.json'))

functions = analyzer['functions']
call_graph = analyzer.get('callGraph', {})

# Build reverse graph
reverse = {}
for caller, callees in call_graph.items():
    for callee in callees:
        reverse.setdefault(callee, []).append(caller)

# Detect and filter
detector = EntryPointDetector(functions, call_graph)
entry_points = detector.detect_entry_points()
reachability = ReachabilityAnalyzer(functions, reverse, entry_points)
reachable = reachability.get_all_reachable()

# Filter and save
original = len(dataset['units'])
dataset['units'] = [u for u in dataset['units'] if u['id'] in reachable]
print(f'Filtered: {original} → {len(dataset[\"units\"])} units')
print(f'Reduction: {100*(1-len(dataset[\"units\"])/original):.1f}%')

json.dump(dataset, open('datasets/myrepo/dataset.json', 'w'), indent=2)
"
```

### Checking Reachability for Specific Functions

```python
from utilities.agentic_enhancer import ReachabilityAnalyzer

# After setting up reachability analyzer...
func_id = 'src/utils.py:dangerous_eval'

if reachability.is_reachable_from_entry_point(func_id):
    path = reachability.get_entry_point_path(func_id)
    entry = reachability.get_reaching_entry_point(func_id)
    print(f"REACHABLE from {entry}")
    print(f"Path: {' → '.join(path)}")
else:
    print("NOT REACHABLE - cannot be exploited externally")
```

### Statistics

```python
stats = reachability.get_statistics()
print(f"Total functions: {stats['total_functions']}")
print(f"Entry points: {stats['entry_points']}")
print(f"Reachable: {stats['reachable']} ({stats['reachable_percentage']}%)")
print(f"Unreachable: {stats['unreachable']}")
```

### Cost Impact

Example from Firefox browser/components (16,345 units):

| Filter | Units | Reduction |
|--------|-------|-----------|
| None | 16,345 | 0% |
| Entry-point reachable | 9,839 | 40% |
| + CodeQL exclusion | 9,777 | 40.2% |

For typical web applications, entry-point filtering achieves 60-95% reduction.

---

## Step 4: Application Context Generation

Classifies the repository type to reduce false positives.

**Location:** `context/generate_context.py`

**Command:**
```bash
python -m context.generate_context /path/to/repo
python -m context.generate_context /path/to/repo -o application_context.json
python -m context.generate_context --list-types  # Show supported types
```

**Supported Application Types:**

| Type | Description | Attack Model |
|------|-------------|--------------|
| `web_app` | Web applications, API servers | Remote attacker with browser |
| `cli_tool` | Command-line tools | Local user with shell access |
| `library` | Reusable packages | No direct attack surface |
| `agent_framework` | AI/LLM frameworks | Code execution is intentional |

**Output (`application_context.json`):**
```json
{
  "application_type": "web_app",
  "purpose": "Web application for...",
  "requires_remote_trigger": true,
  "intended_behaviors": [
    "File uploads to configured directory"
  ],
  "trust_boundaries": {
    "HTTP requests": "untrusted",
    "Configuration files": "trusted"
  },
  "not_a_vulnerability": [
    "Path traversal via CLI arguments (user has filesystem access)"
  ],
  "confidence": 0.92,
  "source": "automatic"
}
```

**Manual Override:**

Create `OPENANT.md` or `OPENANT.json` in repo root to override automatic detection.

---

## Step 5: Context Enhancement

Adds LLM-identified dependencies, callers, and data flow to units.

**Location:** `utilities/context_enhancer.py`

### Single-Shot Mode (Fast, Cheaper)

```bash
python -m utilities.context_enhancer datasets/myrepo/dataset.json \
    --output datasets/myrepo/dataset_enhanced.json \
    --batch-size 10
```

### Agentic Mode (Thorough, Expensive)

```bash
python -m utilities.context_enhancer datasets/myrepo/dataset.json \
    --agentic \
    --analyzer-output datasets/myrepo/analyzer_output.json \
    --repo-path /path/to/repo \
    --checkpoint datasets/myrepo/checkpoint.json \
    --batch-size 5
```

**Arguments:**
| Argument | Description | Default |
|----------|-------------|---------|
| `input` | Dataset JSON file (required) | - |
| `--output, -o` | Output file | overwrites input |
| `--agentic` | Use iterative tool exploration | false |
| `--analyzer-output` | Function index (required for agentic) | - |
| `--repo-path` | Repository path (enables file reading) | - |
| `--checkpoint` | Checkpoint file for resume | - |
| `--batch-size` | Progress reporting interval | 10 |
| `--verbose` | Debug output | false |

**Agentic Mode adds:**
- `agent_context.security_classification`: `exploitable`, `vulnerable_internal`, `security_control`, `neutral`
- `agent_context.include_functions`: Relevant functions for analysis
- `agent_context.entry_point_path`: Call path from entry point

**Cost Warning:** Agentic mode costs ~$0.28 per unit (vs ~$0.02 for single-shot)

---

## Step 6: Stage 1 - Vulnerability Detection

Main vulnerability analysis using Claude. Uses language-agnostic prompts that work for Python, JavaScript, TypeScript, and Go.

**Location:** `experiment.py`

**Command:**
```bash
python experiment.py --dataset myrepo \
    --model opus \
    --limit 50
```

**Arguments:**
| Argument | Description | Default |
|----------|-------------|---------|
| `--dataset` | Dataset name in `datasets/` | required |
| `--model` | `opus` or `sonnet` | `opus` |
| `--limit` | Max units to analyze | all |
| `--verify` | Enable Stage 2 verification | false |
| `--verify-verbose` | Verbose Stage 2 output | false |
| `--no-enhanced` | Disable multi-file context | false |
| `--no-correct` | Disable INSUFFICIENT_CONTEXT retry | false |
| `--no-json-correct` | Disable JSON error recovery | false |
| `--no-challenge` | Disable ground truth challenging | false |

**Output:**
```
experiment_<dataset>_<model>_<timestamp>.json
```

**Verdict Categories:**
| Verdict | Description |
|---------|-------------|
| `vulnerable` | Exploitable vulnerability, no protection |
| `protected` | Dangerous operations with effective controls |
| `bypassable` | Security controls can be circumvented |
| `inconclusive` | Cannot determine security posture |
| `safe` | No security-sensitive operations |

---

## Step 7: Stage 2 - Attacker Simulation

Verifies Stage 1 findings by simulating an attacker. Uses language-agnostic prompts (same prompt for Python, JavaScript, Go, etc.).

**Enabled via:**
```bash
python experiment.py --dataset myrepo --verify --verify-verbose
```

**How it works:**
1. Receives Stage 1 vulnerability finding
2. Role-plays as attacker with only a browser
3. Attempts to exploit step-by-step
4. Reports realistic roadblocks (auth, validation, etc.)
5. Only confirms vulnerabilities that can actually be exploited

**Attacker simulation prompt:**
```
You are an attacker on the internet. You have a browser and nothing else.
No server access, no admin credentials, no ability to modify files on the server.
Try to exploit this vulnerability. Go step by step...
```

**Verification Result:**
```json
{
  "agree": false,
  "correct_finding": "protected",
  "explanation": "Authentication layer blocks unauthorized access",
  "exploit_path": {
    "entry_point": "/api/endpoint",
    "data_flow": ["Step 1", "Step 2"],
    "sink_reached": false,
    "path_broken_at": "Auth middleware"
  }
}
```

**Results:** Achieved 0% false positive rate on object-browser (25 units)

---

## Step 8: Dynamic Testing

Dynamically tests confirmed findings by generating Docker-isolated exploit tests via Claude Sonnet. This step bridges static analysis and confirmed exploitability.

**Location:** `utilities/dynamic_tester/`

**Prerequisites:**
- Docker Engine must be installed and running
- Anthropic API key (for Claude Sonnet test generation)

### Standalone CLI

```bash
# Run against pipeline output
python -m utilities.dynamic_tester datasets/myrepo/pipeline_output.json

# Custom output directory
python -m utilities.dynamic_tester datasets/myrepo/pipeline_output.json --output-dir /tmp/results
```

### Python API

```python
from utilities.dynamic_tester import run_dynamic_tests

results = run_dynamic_tests("datasets/myrepo/pipeline_output.json")
for r in results:
    print(f"{r.finding_id}: {r.status} — {r.details}")
```

### How It Works

For each finding in `pipeline_output.json`:

1. **Generate** — Claude Sonnet receives the finding (CWE, vulnerable code, steps to reproduce) and generates a self-contained Docker test (Dockerfile + test script + dependencies)
2. **Execute** — Test runs in an isolated container (`--read-only`, `--no-new-privileges`, 512MB RAM, 120s timeout)
3. **Retry** — If the test fails (build error or runtime crash), the error is fed back to the LLM for one retry
4. **Classify** — Container stdout is parsed for a JSON result with status: `CONFIRMED`, `NOT_REPRODUCED`, `BLOCKED`, `INCONCLUSIVE`, or `ERROR`

### Output

| File | Format | Contents |
|------|--------|----------|
| `DYNAMIC_TEST_RESULTS.md` | Markdown | Human-readable report with evidence |
| `dynamic_test_results.json` | JSON | Structured results for programmatic use |

### Attacker Capture Server

For SSRF and exfiltration tests, a lightweight HTTP capture server is provided on port 9999. Tests use Docker Compose with a `testnet` bridge network to communicate between the test container and the attacker server.

### Cost

- Test generation: ~$0.03-0.05 per finding (Claude Sonnet)
- Retry: ~$0.04-0.06 additional per retried finding
- Docker execution: free (local)

See `utilities/dynamic_tester/README.md` for full documentation.

---

## Results Export

### CSV Export

```bash
python export_csv.py \
    experiment_myrepo_opus_*.json \
    datasets/myrepo/dataset.json \
    results.csv
```

### HTML Report

```bash
python generate_report.py \
    experiment_myrepo_opus_*.json \
    datasets/myrepo/dataset.json \
    report.html
```

### LLM-Generated Reports (Report Module)

For professional security reports and disclosure documents, use the `report` module. This uses Claude Opus 4.5 to generate well-written documents from pipeline output.

**Location:** `report/`

**Commands:**
```bash
# Generate summary report
python -m report summary pipeline_output.json -o SUMMARY_REPORT.md

# Generate disclosure documents for each confirmed vulnerability
python -m report disclosures pipeline_output.json -o disclosures/

# Generate all reports (summary + disclosures)
python -m report all pipeline_output.json -o output/
```

**Input Format:**
The module expects a JSON file with the following structure:
```json
{
  "repository": {"name": "...", "url": "..."},
  "analysis_date": "2026-01-28",
  "application_type": "web_app",
  "pipeline_stats": {...},
  "results": {"vulnerable": 5, "safe": 16, ...},
  "findings": [
    {
      "id": "VULN-001",
      "name": "Vulnerability Name",
      "short_name": "Short Name",
      "location": {"file": "src/file.py", "function": "func"},
      "cwe_id": 639,
      "cwe_name": "CWE Name",
      "stage1_verdict": "vulnerable",
      "stage2_verdict": "vulnerable",
      "description": "...",
      "vulnerable_code": "...",
      "impact": ["..."],
      "suggested_fix": "...",
      "steps_to_reproduce": ["..."]
    }
  ]
}
```

**Output:**
- Summary report: Overview with statistics, methodology, confirmed vulnerabilities
- Disclosures: One document per confirmed vulnerability with steps to reproduce

**Cost:** Uses Claude Opus 4.5 (~$15/$75 per MTok). Typical cost: ~$1-5 per report.

---

## Cost Reference

### Per-Unit Costs

| Stage | Model | Cost per Unit |
|-------|-------|---------------|
| Stage 1 (detection) | Opus | ~$0.20 |
| Stage 2 (verification) | Opus | ~$1.05 |
| Dynamic testing | Sonnet | ~$0.03-0.05 |
| Agentic enhancer | Sonnet | ~$0.28 |
| Single-shot enhancer | Sonnet | ~$0.02 |

### Processing Level Impact

Example: 1,000 unit repository

| Level | Units Analyzed | Estimated Cost |
|-------|----------------|----------------|
| `all` | 1,000 | ~$1,250 |
| `reachable` | ~60 | ~$75 |
| `codeql` | ~10 | ~$12 |

**Recommendation:** Use `--processing-level codeql` for cost-effective analysis.

---

## Complete Examples

### Example 1: Python Web Application

```bash
# 1. Parse repository
python parsers/python/parse_repository.py /path/to/flask-app \
    --output datasets/flask-app/dataset.json \
    --analyzer-output datasets/flask-app/analyzer_output.json \
    --skip-tests

# 2. Validate dataset schema
python validate_dataset_schema.py datasets/flask-app/dataset.json

# 3. Generate application context
python -m context.generate_context /path/to/flask-app

# 4. Run Stage 1 + Stage 2 on first 20 units
python experiment.py --dataset flask-app --verify --limit 20

# 5. Export results
python export_csv.py experiment_flask-app_*.json datasets/flask-app/dataset.json results.csv
```

### Example 2: JavaScript Project with CodeQL

```bash
# 1. Parse with CodeQL filtering
python parsers/javascript/test_pipeline.py /path/to/node-app \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output datasets/node-app \
    --processing-level codeql

# 2. Validate dataset schema
python validate_dataset_schema.py datasets/node-app/dataset.json

# 3. Generate application context
python -m context.generate_context /path/to/node-app

# 4. Run full analysis
python experiment.py --dataset node-app --verify

# 5. Generate HTML report
python generate_report.py experiment_node-app_*.json datasets/node-app/dataset.json report.html
```

### Example 3: Large Repository (Cost-Optimized)

```bash
# 1. Parse with maximum filtering
python parsers/javascript/test_pipeline.py /path/to/large-repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output datasets/large-repo \
    --processing-level codeql

# 2. Validate dataset schema
python validate_dataset_schema.py datasets/large-repo/dataset.json

# 3. Check unit count before analysis
python -c "import json; d=json.load(open('datasets/large-repo/dataset.json')); print(f'Units: {len(d[\"units\"])}')"

# 4. Run Stage 1 only first (cheaper)
python experiment.py --dataset large-repo --limit 100

# 5. Review results, then run Stage 2 on promising findings
python experiment.py --dataset large-repo --verify --limit 100
```

---

## Quick Reference

```bash
# List datasets
ls datasets/

# Parse Python repo
python parsers/python/parse_repository.py /repo --output datasets/name/dataset.json

# Parse JS repo with CodeQL
python parsers/javascript/test_pipeline.py /repo --analyzer-path /analyzer.js --output datasets/name --processing-level codeql

# Generate app context
python -m context.generate_context /repo

# Run Stage 1
python experiment.py --dataset name

# Run Stage 1 + Stage 2
python experiment.py --dataset name --verify

# Export CSV
python export_csv.py experiment_*.json datasets/name/dataset.json out.csv

# Export HTML
python generate_report.py experiment_*.json datasets/name/dataset.json out.html
```

---

## Troubleshooting

### "Dataset not found"
Ensure dataset directory exists in `datasets/` with `dataset.json` file.

### "ANTHROPIC_API_KEY not set"
Create `.env` file with your API key.

### High costs
Use `--processing-level codeql` and `--limit N` to control costs.

### Parser errors
Check that all prerequisites (Node.js, Go, CodeQL) are installed.

### Stage 2 taking too long
Stage 2 makes multiple API calls per finding. Use `--limit` to control scope.
