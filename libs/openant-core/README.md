# OpenAnt

**LLM-Powered Static Application Security Testing**

OpenAnt uses Claude to analyze code for security vulnerabilities through a two-stage pipeline: detection followed by verification. Features 4-level cost optimization with CodeQL integration. Supports Python, JavaScript/TypeScript, Go, C/C++, Ruby, PHP, Zig, and Swift.

---

## Quick Start

### Prerequisites

- Python 3.8+
- Node.js 16+ (for JavaScript/TypeScript parsing)
- Go 1.21+ (for Go parsing)
- Docker (for dynamic testing)
- Anthropic API key

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/openant.git
cd openant

# Install Python dependencies
pip install -r requirements.txt

# Set API key
echo "ANTHROPIC_API_KEY=your-key-here" > .env
```

### Run Analysis

```bash
# Analyze a JavaScript dataset
python experiment.py --dataset flowise_vuln4 --verify

# Analyze a Python dataset
python experiment.py --dataset geospatial_vuln12 --verify

# Analyze a Go dataset
python experiment.py --dataset object_browser --verify

# Export results
python export_csv.py experiment_*.json datasets/flowise/dataset_vulnerable_4.json results.csv
python generate_report.py experiment_*.json datasets/flowise/dataset_vulnerable_4.json report.html
```

---

## How It Works

### Two-Stage Pipeline

**Stage 1 - Detection:** Claude analyzes each code unit with simple, direct questions:
- "What does this code do?"
- "What is the security risk?"

**Stage 2 - Verification (Attacker Simulation):** Claude role-plays as an attacker to validate each finding:
- "You are an attacker with only a browser. Try to exploit this step by step."
- Model naturally hits roadblocks that make theoretical vulnerabilities unexploitable
- Has tool access to search function usages and definitions
- Achieved 0 false positives on object-browser (25 units analyzed)

### Finding Categories

| Category | Meaning | Action |
|----------|---------|--------|
| `vulnerable` | Exploitable vulnerability, no protection | Immediate fix required |
| `bypassable` | Security controls can be circumvented | Review and strengthen |
| `inconclusive` | Cannot determine security posture | Manual review needed |
| `protected` | Dangerous operations with effective controls | Monitor |
| `safe` | No security-sensitive operations | None |

---

## Processing Levels (Cost Optimization)

The parser pipeline supports four processing levels:

| Level | Filter | Cost Reduction |
|-------|--------|----------------|
| `all` | None | - |
| `reachable` | Entry point reachability | ~94% |
| `codeql` | Reachable + CodeQL-flagged | ~99% |
| `exploitable` | Reachable + CodeQL + LLM classification | ~99.9% |

**Example cost savings (Flowise 1,417 units):**
- Level 1 (all): ~$300 for agentic analysis
- Level 2 (reachable): ~$16
- Level 3 (codeql): **$0.69**
- Level 4 (exploitable): $0.69

**Usage:**
```bash
# Recommended: CodeQL pre-filtering
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/analyzer.js \
    --processing-level codeql

# Maximum savings
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/analyzer.js \
    --processing-level exploitable \
    --llm --agentic
```

**CodeQL Requirements (for Level 3+):**
```bash
brew install codeql
codeql pack download codeql/javascript-queries
codeql pack download codeql/python-queries
```

---

## Application Context (False Positive Reduction)

OpenAnt generates application context to understand what type of application is being analyzed. This dramatically reduces false positives by understanding what behaviors are intentional vs vulnerable.

### Supported Application Types

| Type | Description | Attack Model |
|------|-------------|--------------|
| `web_app` | Web applications and API servers | Remote attacker with browser/HTTP client |
| `cli_tool` | Command-line tools and utilities | Local user with shell access |
| `library` | Reusable code packages and SDKs | No direct attack surface |
| `agent_framework` | AI agent and LLM frameworks | Code execution is intentional |

### Generate Context

```bash
# Generate context for a repository
python -m context.generate_context /path/to/repo

# View formatted prompt output
python -m context.generate_context /path/to/repo --show-prompt

# List supported types
python -m context.generate_context --list-types
```

### Manual Override

Create `OPENANT.md` or `OPENANT.json` in your repository root to provide manual security context. This is useful when:

- Automatic detection is incorrect
- You have specific behaviors that should not be flagged
- Your application type requires custom trust boundaries

See `context/OPENANT_TEMPLATE.md` for the complete format and examples.

### Example: LangChain

Without context, LangChain analysis had 84% false positive rate (16/19). With `agent_framework` context, the analyzer understands that subprocess execution, dynamic imports, and git cloning are intentional features.

---

## Autopilot (Autonomous Pipeline)

Run the full vulnerability hunting pipeline autonomously:

### Three Operating Modes

**Mode 1: Discover (explore GitHub)**
```bash
python -m autopilot --once                    # One cycle, then exit
python -m autopilot                           # Scheduled (every N hours)
```

**Mode 2: GitHub URL (specific repo, supports private)**
```bash
python -m autopilot --repo langchain-ai/langchain
python -m autopilot --repo https://github.com/org/repo
python -m autopilot --repo myorg/private-repo  # Requires gh auth login
```

**Mode 3: Local path (already cloned)**
```bash
python -m autopilot --path /path/to/local/repo
```

### Key Features

- **Entry-point filtering**: 99% cost reduction (6,647 → 79 units for LangChain)
- **AI-driven budgets**: Proceed/override/abort decisions
- **Comprehensive logging**: Tokens, costs, errors → JSONL file
- **Private repo support**: Via `gh` CLI authentication
- **Graceful shutdown**: SIGINT saves state, resume on restart

### Example Run (LangChain)

```
Reachable units: 79 (of 6,647 total)
Stage 1 vulnerable: 19/79
Stage 2 confirmed: 3/19
Total cost: $50.06
```

See [autopilot/README.md](autopilot/README.md) for full documentation.

---

## Processing a Repository

For complete step-by-step instructions with all options, see [PIPELINE_MANUAL.md](PIPELINE_MANUAL.md).

### Step 1: Parse the Repository

**Python Repositories:**
```bash
python parsers/python/parse_repository.py /path/to/your/repo \
    --output datasets/myrepo/dataset.json \
    --analyzer-output datasets/myrepo/analyzer_output.json
```

**JavaScript/TypeScript Repositories:**
```bash
python parsers/javascript/test_pipeline.py /path/to/your/repo \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output datasets/myrepo
```

**Go Repositories:**
```bash
# Build Go binary first
cd parsers/go/go_parser && go build -o go_parser . && cd ../../..

# Run pipeline
python parsers/go/test_pipeline.py /path/to/your/go/repo \
    --output datasets/myrepo \
    --processing-level codeql
```

This produces:
- `datasets/myrepo/dataset.json` - All code units with dependencies
- `datasets/myrepo/analyzer_output.json` - Function index for Stage 2 verification

### Step 2: Run Analysis

```bash
# Stage 1 only (faster, cheaper)
python experiment.py --dataset myrepo

# Stage 1 + Stage 2 (recommended)
python experiment.py --dataset myrepo --verify --verify-verbose
```

### Step 3: Export Results

```bash
# CSV for filtering and sorting
python export_csv.py experiment_myrepo_*.json datasets/myrepo/dataset.json results.csv

# HTML report with remediation guidance
python generate_report.py experiment_myrepo_*.json datasets/myrepo/dataset.json report.html
```

---

## Command Line Reference

### experiment.py

Main experiment runner for vulnerability analysis.

```bash
python experiment.py --dataset <name> [options]
```

| Flag | Description |
|------|-------------|
| `--dataset` | Dataset name: flowise, geospatial, geospatial_vuln12, dvna, etc. |
| `--verify` | Enable Stage 2 verification (recommended) |
| `--verify-verbose` | Show Stage 2 progress and tool calls |
| `--review` | Enable proactive LLM context review |
| `--no-enhanced` | Disable multi-file context assembly |
| `--no-correct` | Disable INSUFFICIENT_CONTEXT correction |
| `--no-json-correct` | Disable JSON error recovery |
| `--no-challenge` | Disable ground truth challenging |
| `--model` | Override model: opus (default) or sonnet |

**Output:** `experiment_{dataset}_{timestamp}.json`

### export_csv.py

Export results to CSV for analysis in Excel/Sheets.

```bash
python export_csv.py <experiment.json> <dataset.json> [output.csv]
```

### generate_report.py

Generate HTML report with interactive charts and remediation guidance.

```bash
python generate_report.py <experiment.json> <dataset.json> [output.html]
```

---

## Output Formats

### CSV Export

Ten columns for filtering and sorting:

| Column | Description |
|--------|-------------|
| `file` | Source file path |
| `unit_id` | Unique identifier (file:function) |
| `unit_description` | What the code does |
| `unit_code` | Complete source code |
| `stage2_verdict` | Final verdict after verification |
| `stage2_justification` | Stage 2 explanation |
| `stage1_verdict` | Initial detection verdict |
| `stage1_justification` | Stage 1 reasoning |
| `stage1_confidence` | Confidence score (0.0-1.0) |
| `agentic_classification` | Pre-analysis classification |

### HTML Report

Interactive report with:
- **Stats cards** - Overview of findings by category
- **Pie charts** - Distribution of units and files
- **Category table** - Explanation of each finding category
- **Remediation guidance** - LLM-generated prioritized action items
- **Findings table** - All results sorted by severity

---

## Cost Estimates

| Stage | Model | Cost per Unit |
|-------|-------|---------------|
| Stage 1 (detection) | Opus | ~$0.20 |
| Stage 2 (verification) | Opus | ~$1.05 |
| Dynamic testing | Sonnet | ~$0.03-0.05 |
| Report generation | Sonnet | ~$0.05 |

**Full analysis:** ~$1.25 per code unit

For a repository with 1,000 units:
- Stage 1 only: ~$200
- Stage 1 + Stage 2: ~$1,250

---

## Supported Vulnerabilities

| Type | Detection Pattern | Languages |
|------|-------------------|-----------|
| **Remote Code Execution** | User input to eval()/exec() | Python, JS |
| **XSS** | User input to unescaped template output | JS/TS |
| **SQL Injection** | User input to raw SQL queries | Python, JS |
| **Command Injection** | User input to exec/spawn/system | Python, JS |
| **Path Traversal** | User input to file operations | Python, JS |
| **Open Redirect** | User input to redirect URLs | Python, JS |
| **SSRF** | User input to fetch/request URLs | Python, JS |
| **Prototype Pollution** | User input to deep merge/assign | JS/TS |

---

## Test Results

### Python: Geospatial (12 units with eval() vulnerabilities)

| Metric | Value |
|--------|-------|
| Stage 2 agreed | 9/11 (82%) |
| Stage 2 corrected | 2/11 (18%) |

Final distribution: 8 vulnerable, 1 bypassable, 2 safe

### JavaScript: Flowise (13 units)

| Metric | Value |
|--------|-------|
| Stage 2 agreed | 11/13 (85%) |
| Stage 2 corrected | 2/13 (15%) |

Final distribution: 5 vulnerable, 7 bypassable, 1 protected

### Go: Object-Browser (25 units with attacker simulation)

| Metric | Value |
|--------|-------|
| Units analyzed | 25 |
| Final VULNERABLE | **0** |
| Final SAFE | 23 |
| Final PROTECTED | 2 |

**0% false positive rate** achieved using attacker simulation approach:
- Model role-plays as attacker with only a browser
- Naturally hits roadblocks that make theoretical vulnerabilities unexploitable
- Examples: symlinks require filesystem access, admin-configured inputs not user-controllable

### GitHub Patches (33 real-world samples)

| Vulnerability Type | Accuracy |
|--------------------|----------|
| XSS | 91.7% |
| Path Traversal | 100% |
| Command Injection | 100% |
| Prototype Pollution | 30% |
| **Overall** | **75.8%** |

---

## Project Structure

```
openant/
├── experiment.py              # Main experiment runner
├── export_csv.py              # CSV export
├── generate_report.py         # HTML report generator
├── validate_dataset_schema.py # Validate dataset before LLM calls
├── autopilot/                 # Autonomous pipeline (NEW)
│   ├── __main__.py            # CLI: python -m autopilot [--repo|--path]
│   ├── config.py              # YAML config + Pydantic validation
│   ├── state.py               # Execution state + per-repo records
│   ├── scheduler.py           # Main loop + signal handling
│   ├── runner.py              # Cycle orchestration
│   ├── pipeline.py            # Per-repo state machine
│   ├── cost.py                # Cost estimation + BudgetAdvisor
│   ├── logging_.py            # JSONL + stderr logging with token tracking
│   └── steps/                 # Pipeline steps (discover, parse, detect, etc.)
├── context/                   # Application context generation
│   ├── __init__.py            # Package exports
│   ├── application_context.py # Context detection & formatting
│   ├── generate_context.py    # CLI for context generation
│   └── OPENANT_TEMPLATE.md   # Manual override template
├── prompts/                   # Analysis prompts (language-agnostic)
│   ├── __init__.py
│   ├── vulnerability_analysis.py  # Stage 1 detection prompt
│   ├── verification_prompts.py    # Stage 2 attacker simulation prompt
│   └── prompt_selector.py         # Routes to vulnerability_analysis
├── utilities/                 # Core utilities
│   ├── __init__.py
│   ├── llm_client.py          # Anthropic API wrapper + TokenTracker
│   ├── finding_verifier.py    # Stage 2 verification with Opus + tools
│   ├── context_enhancer.py    # Dataset LLM enhancement
│   ├── context_corrector.py   # INSUFFICIENT_CONTEXT handling
│   ├── context_reviewer.py    # Proactive context review
│   ├── json_corrector.py      # JSON error recovery
│   ├── ground_truth_challenger.py  # FP/FN arbitration
│   ├── dynamic_tester/        # Docker-based dynamic exploit testing
│   │   ├── __init__.py            # Public API: run_dynamic_tests()
│   │   ├── test_generator.py      # LLM test generation (Claude Sonnet)
│   │   ├── docker_executor.py     # Docker build/run with security isolation
│   │   ├── result_collector.py    # Parse container output
│   │   └── docker_templates/      # Base Dockerfiles + attacker server
│   └── agentic_enhancer/      # Tool-based analysis
│       ├── __init__.py
│       ├── repository_index.py    # Searchable function index
│       ├── tools.py               # Tool definitions for LLM
│       ├── prompts.py             # System and user prompts
│       ├── agent.py               # Main agent loop
│       ├── entry_point_detector.py    # Entry point detection
│       └── reachability_analyzer.py   # User input reachability
├── parsers/                   # Code parsing
│   ├── javascript/            # JS/TS parser pipeline
│   ├── python/                # Python parser pipeline
│   └── go/                    # Go parser pipeline (Go binary + Python)
└── datasets/                  # Test datasets
    ├── geospatial/            # Python test dataset
    ├── flowise/               # JavaScript test dataset
    ├── object_browser/        # Go test dataset
    └── github_patches/        # Real-world samples
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| `DOCUMENTATION.md` | **Start here** - Index of all documentation |
| `PIPELINE_MANUAL.md` | Complete pipeline instructions with CLI commands |
| `README.md` | This file - Quick start and overview |
| `autopilot/README.md` | Autonomous pipeline documentation (3 modes, logging, budgets) |
| `CURRENT_IMPLEMENTATION.md` | Technical context (for developers/AI assistants) |
| `OPENANT.md` | Architecture documentation |
| `OPENANT_TWO_STAGE_PLANNING.md` | Pipeline design rationale |
| `context/OPENANT_TEMPLATE.md` | Manual override format & examples |
| `utilities/dynamic_tester/README.md` | Dynamic tester documentation |
| `datasets/DATASET_FORMAT.md` | Dataset schema documentation |
| `parsers/javascript/PARSER_PIPELINE.md` | JavaScript parser docs |
| `parsers/python/PARSER_PIPELINE.md` | Python parser docs |
| `parsers/go/PARSER_PIPELINE.md` | Go parser docs |

---

## License

Research project - see LICENSE file for details.
