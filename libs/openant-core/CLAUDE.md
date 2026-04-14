# Rules

- Only do exactly what is explicitly requested - nothing more
- Never anticipate or extend tasks beyond what was asked
- Ask for confirmation before running commands that cost money (API calls, etc.)
- If unsure about scope, ask first
- After any context compaction, re-read this file and referenced docs before taking any action

# Go CLI Build Rules

**NEVER run `make install` in `apps/openant-cli/`** — it overwrites the symlink with a copy.

The system uses a symlink: `/usr/local/bin/openant` → `apps/openant-cli/bin/openant`

To rebuild the Go CLI:
```bash
cd apps/openant-cli && go build -o bin/openant .
```

The symlink automatically picks up the new binary. Running `make install` would replace the symlink with a copied file, breaking the dev workflow.

# Project Context

This is OpenAnt, a two-stage SAST tool using Claude for vulnerability analysis. Supports Python, JavaScript/TypeScript, and Go codebases with 4-level cost optimization.

**Key files to read after context reset:**
- `DOCUMENTATION.md` - **Start here** - Index of all documentation
- `CURRENT_IMPLEMENTATION.md` - Current state, architecture, file inventory
- `PIPELINE_MANUAL.md` - Complete pipeline instructions with CLI commands
- `REPOSITORY_INSPECTION_PROTOCOL.md` - **Complete 10-step protocol for analyzing GitHub repos** (mandatory reading for repo analysis)
- `VULNERABILITY_HUNTING_PROTOCOL.md` - Protocol for finding vulns CodeQL misses

# Key Design: Attacker Simulation (Stage 2)

Stage 2 uses **attacker simulation** instead of code analysis. The model role-plays as an attacker with only a browser, attempting to exploit the vulnerability step-by-step. This naturally surfaces roadblocks that make theoretical vulnerabilities unexploitable.

**Prompt:** "You are an attacker on the internet. You have a browser and nothing else. No server access, no admin credentials, no ability to modify files on the server. Try to exploit this vulnerability. Go step by step..."

This achieved 0 false positives on object-browser (25 units analyzed).

# Processing Levels (Cost Optimization)

| Level | Filter | Cost Reduction |
|-------|--------|----------------|
| `all` | None | - |
| `reachable` | Entry point reachability | ~94% |
| `codeql` | Reachable + CodeQL-flagged | ~99% |
| `exploitable` | Reachable + CodeQL + LLM classification | ~99.9% |

# Application Context (False Positive Reduction)

OpenAnt uses application context to understand what type of application it's analyzing, which dramatically reduces false positives by understanding what behaviors are intentional vs vulnerable.

**Supported Application Types:**

| Type | Description | Attack Model |
|------|-------------|--------------|
| `web_app` | Web applications and API servers | Remote attacker with browser/HTTP client |
| `cli_tool` | Command-line tools and utilities | Local user with shell access (already has filesystem access) |
| `library` | Reusable code packages and SDKs | No direct attack surface; security depends on caller |
| `agent_framework` | AI agent and LLM frameworks | Code execution is intentional; focus on sandbox escapes |

**Generate context:**
```bash
python -m context.generate_context /path/to/repo
python -m context.generate_context /path/to/repo --list-types  # Show supported types
```

**Manual override:** Create `OPENANT.md` or `OPENANT.json` in repo root. See `context/OPENANT_TEMPLATE.md` for format.

**Unsupported types:** If a repository doesn't match supported types, OpenAnt exits with error code 2 and instructions for creating a manual override.

# Autopilot (Autonomous Pipeline)

The `autopilot/` module runs the full vulnerability hunting pipeline autonomously.

**Operating Modes:**
```bash
python -m autopilot --once                    # Discover mode, one cycle
python -m autopilot --repo langchain-ai/langchain  # Specific repo
python -m autopilot --path /path/to/local/repo     # Local repo
```

**Interaction Modes:**
```bash
python -m autopilot --repo owner/repo         # Interactive (default)
python -m autopilot --repo owner/repo -n      # Non-interactive (auto-proceed)
python -m autopilot --repo owner/repo --api   # API mode (JSON protocol)
```

**API Mode (for TypeScript wrapper):**
- JSON Lines protocol over stdin/stdout
- Events: `discovery_complete`, `repo_parsed`, `cost_summary`, `step_complete`, `pipeline_complete`
- Commands: `select_repos`, `update_config`, `abort`
- Full documentation in `autopilot/README.md` (API Mode section)

**Key Features:**
- Entry-point filtering (99% cost reduction: 6,647 → 79 units for LangChain)
- AI-driven budget decisions (proceed/override/abort)
- Comprehensive logging (JSONL + stderr) - tokens, costs, errors
- Graceful shutdown with state persistence
- Private repo support via `gh` CLI

**Pipeline Steps:**
1. Discover - Find repos on GitHub (skip in --repo/--path modes)
2. Assess - Score for vuln-hunting potential (skip in --repo/--path modes)
3. Parse - Clone, parse, filter to reachable units
4. Enhance - Add call path context
5. Analyze - Stage 1 vulnerability analysis
6. Verify - Stage 2 attacker simulation
7. Dynamic Test - Docker-isolated exploit testing (requires Docker)
8. Report - Generate security reports

See `autopilot/README.md` for full documentation.

# API Key

The `ANTHROPIC_API_KEY` is stored in `.env` in the project root. All modules load it via `dotenv`.

# Quick Reference

**Datasets:**
- `geospatial` / `geospatial_vuln12` - Python (streamlit-geospatial)
- `flowise` / `flowise_vuln4` - JavaScript (Flowise)
- `object_browser` - Go (object-browser)
- `grafana` - TypeScript (Grafana) - 2 confirmed SQL injection vulns

**Parsers:**
- Python: `parsers/python/parse_repository.py`
- JavaScript: `parsers/javascript/test_pipeline.py`
- Go: `parsers/go/test_pipeline.py` (uses `go_parser` binary)

**Run parser with processing level:**
```bash
# JavaScript
python parsers/javascript/test_pipeline.py /path/to/repo \
    --analyzer-path /path/to/analyzer.js \
    --processing-level exploitable \
    --llm --agentic

# Go
python parsers/go/test_pipeline.py /path/to/go/repo \
    --output /path/to/output \
    --processing-level codeql
```

**Run analysis:**
```bash
python experiment.py --dataset geospatial_vuln12 --verify
```

**Export results:**
```bash
python export_csv.py experiment_*.json datasets/geospatial/dataset_vulnerable_12.json output.csv
python generate_report.py experiment_*.json datasets/geospatial/dataset_vulnerable_12.json report.html
```
