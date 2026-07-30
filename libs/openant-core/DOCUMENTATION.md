# OpenAnt Documentation Index

This document serves as the central index for all OpenAnt documentation. It is intended for both human developers and AI coding assistants (e.g., Cursor with Claude) to understand the documentation structure and locate relevant information.

---

## Documentation Structure Overview

OpenAnt documentation is organized into three tiers based on audience and purpose:

| Tier | Audience | Purpose |
|------|----------|---------|
| **User Documentation** | End users running the tool | How to install, configure, and run OpenAnt |
| **Operator Documentation** | Operators running full pipeline | Step-by-step instructions for complete workflows |
| **Developer Documentation** | Developers modifying the code | Architecture, design decisions, code structure |

---

## Quick Reference: Which Document to Read

| Task | Read This Document |
|------|-------------------|
| **First time setup** | README.md |
| **Running the full pipeline** | PIPELINE_MANUAL.md |
| **Running autonomous pipeline** | autopilot/README.md |
| **Processing a specific GitHub repo** | autopilot/README.md (--repo mode) |
| **Processing a local repo** | autopilot/README.md (--path mode) |
| **Integrating with TypeScript wrapper** | autopilot/WRAPPER_INTEGRATION_GUIDE.md |
| **TypeScript wrapper implementation (for AI)** | autopilot/WRAPPER_IMPLEMENTATION_REFERENCE.md |
| **Understanding the architecture** | OPENANT.md |
| **Understanding current implementation state** | CURRENT_IMPLEMENTATION.md |
| **Understanding the two-stage design** | OPENANT_TWO_STAGE_PLANNING.md |
| **Hunting for vulnerabilities in repos** | VULNERABILITY_HUNTING_PROTOCOL.md |
| **Full repository inspection protocol** | REPOSITORY_INSPECTION_PROTOCOL.md |
| **Working on Python parser** | parsers/python/PARSER_PIPELINE.md |
| **Working on JavaScript parser** | parsers/javascript/PARSER_PIPELINE.md |
| **Working on Go parser** | parsers/go/PARSER_PIPELINE.md |
| **Working on dynamic tester** | utilities/dynamic_tester/README.md |
| **Dynamic tester AI reference** | utilities/dynamic_tester/DYNAMIC_TESTER_REFERENCE.md |
| **Understanding dataset format** | datasets/DATASET_FORMAT.md |
| **Creating manual app context** | context/OPENANT_TEMPLATE.md |
| **Generating reports/disclosures** | report/README.md |

---

## For AI Coding Assistants

**IMPORTANT:** If you are an AI assistant (Claude, GPT, etc.) working on this codebase, follow these guidelines:

### Before Making Changes

1. **Read CURRENT_IMPLEMENTATION.md first** - This contains the authoritative state of the codebase, file inventory, and recent changes.

2. **Read the relevant PARSER_PIPELINE.md** if working on parsers - Each parser has its own documentation.

3. **Read PIPELINE_MANUAL.md** to understand the 8-step pipeline and how components interact.

### Key Facts About the Codebase

- **8-Step Pipeline:** Parse → Generate Units → Entry-Point Filter → Application Context → Context Enhancement → Stage 1 Detection → Stage 2 Verification → Dynamic Testing
- **Language-Agnostic Prompts:** The same prompts are used for every supported language
- **Two-Stage Analysis:** Stage 1 detects vulnerabilities, Stage 2 uses attacker simulation to verify exploitability
- **Supported Languages:** Python, JavaScript/TypeScript, Go, C/C++, Ruby, PHP, Zig, and Swift

### File Naming Conventions

| Pattern | Purpose |
|---------|---------|
| `*_PIPELINE.md` | Human-readable pipeline documentation |
| `*_UPGRADE_PLAN.md` | Technical reference for AI assistants (implementation details) |
| `CURRENT_IMPLEMENTATION.md` | Living document of current state |
| `experiment_*.json` | Experiment results |
| `dataset*.json` | Analysis unit datasets |
| `analyzer_output.json` | Function index for Stage 2 verification |

---

## Document Inventory

### Tier 1: User Documentation

| Document | Purpose | When to Update |
|----------|---------|----------------|
| **README.md** | Installation, quick start, feature overview | When adding user-facing features |
| **PIPELINE_MANUAL.md** | Complete pipeline instructions with CLI commands | When changing CLI interfaces or workflow |

### Tier 2: Operator Documentation

| Document | Purpose | When to Update |
|----------|---------|----------------|
| **autopilot/README.md** | Autonomous pipeline documentation | When changing autopilot behavior |
| **autopilot/WRAPPER_INTEGRATION_GUIDE.md** | Human-readable guide for TypeScript wrapper integration | When changing API protocol |
| **autopilot/WRAPPER_IMPLEMENTATION_REFERENCE.md** | Technical reference for AI assistants implementing wrapper | When changing API protocol |
| **REPOSITORY_INSPECTION_PROTOCOL.md** | Complete 10-step protocol for analyzing GitHub repositories | When changing the analysis pipeline |
| **VULNERABILITY_HUNTING_PROTOCOL.md** | Step-by-step protocol for finding vulnerabilities in GitHub repos | When changing the hunting workflow |
| **context/OPENANT_TEMPLATE.md** | Template for manual application context override | When changing context schema |

### Tier 3: Developer Documentation

| Document | Purpose | When to Update |
|----------|---------|----------------|
| **CURRENT_IMPLEMENTATION.md** | Current state, file inventory, recent changes | After any significant code change |
| **OPENANT.md** | Architecture overview, system components | When changing architecture |
| **OPENANT_TWO_STAGE_PLANNING.md** | Two-stage pipeline design and rationale | When changing Stage 1/2 design |
| **CLAUDE.md** | Quick reference for Claude Code sessions | When changing key commands or paths |

### Parser Documentation

| Document | Purpose | When to Update |
|----------|---------|----------------|
| **parsers/python/PARSER_PIPELINE.md** | Python parser architecture and usage | When changing Python parser |
| **parsers/python/PARSER_UPGRADE_PLAN.md** | Technical implementation details for AI | When changing Python parser internals |
| **parsers/javascript/PARSER_PIPELINE.md** | JavaScript parser architecture and usage | When changing JavaScript parser |
| **parsers/javascript/PARSER_UPGRADE_PLAN.md** | Technical implementation details for AI | When changing JavaScript parser internals |
| **parsers/go/PARSER_PIPELINE.md** | Go parser architecture and usage | When changing Go parser |
| **parsers/go/PARSER_UPGRADE_PLAN.md** | Technical implementation details for AI | When changing Go parser internals |

### Dynamic Tester Documentation

| Document | Purpose | When to Update |
|----------|---------|----------------|
| **utilities/dynamic_tester/README.md** | Human-readable dynamic tester documentation | When changing dynamic tester behavior |
| **utilities/dynamic_tester/DYNAMIC_TESTER_REFERENCE.md** | AI-focused technical reference for dynamic tester | When changing dynamic tester internals |

### Schema Documentation

| Document | Purpose | When to Update |
|----------|---------|----------------|
| **datasets/DATASET_FORMAT.md** | Dataset JSON schema documentation | When changing dataset schema |

### Analysis Reports (Historical Reference)

These documents capture analysis results and are generally not updated:

| Document | Content |
|----------|---------|
| datasets/grafana/disclosures/SECURITY_REPORT.md | Full pipeline run on Grafana - 2 confirmed SQL injection vulnerabilities |
| datasets/object_browser/OBJECT_BROWSER_VULNERABILITY_REPORT.md | Go analysis results showing attacker simulation success |
| datasets/langchain/LANGCHAIN_ANALYSIS_REPORT.md | LangChain analysis demonstrating application context value |
| datasets/flask/FLASK_ANALYSIS_REPORT.md | Flask framework analysis |
| datasets/github_patches/EVALUATION_REPORT.md | Evaluation on real-world vulnerability patches |
| datasets/flowise/FLOWISE_JAVASCRIPT_REPOSITORY_COST_ESTIMATES.md | Cost analysis for large repository processing |

---

## Core Source Files

For AI assistants working on the code, here are the key source files:

### Main Entry Points

| File | Purpose |
|------|---------|
| `autopilot/__main__.py` | Autonomous pipeline runner (CLI) |
| `experiment.py` | Main experiment runner (Stage 1 + Stage 2) |
| `export_csv.py` | Export results to CSV |
| `generate_report.py` | Generate HTML report with LLM remediation |
| `validate_dataset_schema.py` | Validate dataset before LLM calls |
| `report/__main__.py` | Generate security reports and disclosures (CLI) |

### Autopilot Module

| File | Purpose |
|------|---------|
| `autopilot/__main__.py` | CLI entry point (3 modes: discover, --repo, --path) |
| `autopilot/config.py` | YAML config loading + Pydantic validation |
| `autopilot/state.py` | ExecutionState, RepoRecord, RepoState |
| `autopilot/scheduler.py` | Main loop + signal handling |
| `autopilot/runner.py` | Cycle orchestration |
| `autopilot/pipeline.py` | Per-repo state machine dispatch |
| `autopilot/cost.py` | Cost estimation + BudgetAdvisor |
| `autopilot/confirmation.py` | Terminal-based user confirmation for CLI mode |
| `autopilot/logging_.py` | Dual-output logger (JSONL + stderr) with token tracking |
| `autopilot/api_protocol.py` | JSON protocol definitions (events + commands) for API mode |
| `autopilot/api_runner.py` | API mode main loop for TypeScript wrapper |
| `autopilot/steps/*.py` | Individual pipeline steps (with per-unit logging) |

### Prompts (Language-Agnostic)

| File | Purpose |
|------|---------|
| `prompts/vulnerability_analysis.py` | Stage 1 detection prompt |
| `prompts/verification_prompts.py` | Stage 2 attacker simulation prompt |
| `prompts/prompt_selector.py` | Routes to vulnerability_analysis |

### Utilities

| File | Purpose |
|------|---------|
| `utilities/llm_client.py` | Anthropic API wrapper + TokenTracker |
| `utilities/finding_verifier.py` | Stage 2 verification with Opus + tools |
| `utilities/context_enhancer.py` | Dataset LLM enhancement |
| `utilities/context_corrector.py` | INSUFFICIENT_CONTEXT handling |
| `utilities/json_corrector.py` | JSON error recovery |

### Dynamic Tester

| File | Purpose |
|------|---------|
| `utilities/dynamic_tester/__init__.py` | Public API: `run_dynamic_tests()` |
| `utilities/dynamic_tester/__main__.py` | CLI: `python -m utilities.dynamic_tester` |
| `utilities/dynamic_tester/models.py` | `DynamicTestResult`, `TestEvidence` dataclasses |
| `utilities/dynamic_tester/test_generator.py` | LLM-based test generation (Claude Sonnet) |
| `utilities/dynamic_tester/docker_executor.py` | Docker build/run with security isolation |
| `utilities/dynamic_tester/result_collector.py` | Parse container output, classify results |
| `utilities/dynamic_tester/reporter.py` | Markdown report generation |
| `utilities/dynamic_tester/docker_templates/` | Base Dockerfiles + attacker capture server |

### Agentic Enhancer

| File | Purpose |
|------|---------|
| `utilities/agentic_enhancer/agent.py` | Main agent loop |
| `utilities/agentic_enhancer/repository_index.py` | Searchable function index |
| `utilities/agentic_enhancer/tools.py` | Tool definitions for LLM |
| `utilities/agentic_enhancer/entry_point_detector.py` | Entry point detection |
| `utilities/agentic_enhancer/reachability_analyzer.py` | User input reachability |

### Application Context

| File | Purpose |
|------|---------|
| `context/application_context.py` | Context detection & formatting |
| `context/generate_context.py` | CLI for context generation |

### Report Generator

| File | Purpose |
|------|---------|
| `report/__init__.py` | Package exports |
| `report/__main__.py` | CLI entry point |
| `report/generator.py` | LLM-based report generation (Opus 4.5) |
| `report/schema.py` | Input validation with dataclasses |
| `report/prompts/*.txt` | Report/disclosure templates |

---

## Maintenance Guidelines

### When Adding a New Feature

1. Update **README.md** if it's user-facing
2. Update **PIPELINE_MANUAL.md** if it changes the workflow
3. Update **CURRENT_IMPLEMENTATION.md** with new files and changes
4. Update relevant **PARSER_PIPELINE.md** if it affects parsing

### When Fixing a Bug

1. Update **CURRENT_IMPLEMENTATION.md** if the fix is significant
2. No other documentation changes typically needed

### When Changing Architecture

1. Update **OPENANT.md** with new architecture
2. Update **CURRENT_IMPLEMENTATION.md** with file changes
3. Update **README.md** project structure if files moved

### Keeping Documentation Consistent

All documentation should reflect:
- **8-step pipeline** (not "two-stage" alone, though analysis is two-stage)
- **Language-agnostic prompts** (same prompt for all languages)
- **Current file inventory** (no references to deleted files)

---

## Archive Directory

The `archive/` directory contains historical snapshots of the codebase. These are for reference only and should not be modified or referenced in active documentation.

---

## Questions?

If documentation is unclear or missing, the authoritative source is always the code itself. Key entry points:
- `experiment.py` - Main analysis flow
- `parsers/*/test_pipeline.py` - Parser orchestration
- `utilities/finding_verifier.py` - Stage 2 verification logic
