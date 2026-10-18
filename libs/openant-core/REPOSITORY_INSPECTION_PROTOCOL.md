# Repository Inspection Protocol

This document defines the step-by-step protocol for security analysis of GitHub repositories using OpenAnt. Each step requires explicit approval before proceeding to the next.

---

## Protocol Overview

| Step | Name | Input Units | Output |
|------|------|-------------|--------|
| 1 | Clone & Parse | (entire repository) | All extracted functions |
| 2 | Generate Units | All functions from Step 1 | Validated dataset of all units |
| 3 | Run CodeQL | (entire repository) | SARIF file with flagged locations |
| 4 | Exclude CodeQL Units | **All units** from Step 2 | Units NOT flagged by CodeQL |
| 5 | Entry-Point Filter | **Non-CodeQL units** from Step 4 | Only units reachable from entry points |
| 6 | Agentic Enhancement | **Reachable units** from Step 5 | Classified units, then filtered to **exploitable only** |
| 7 | Stage 1 Detection | **Exploitable units only** from Step 6 | Vulnerability verdicts per unit |
| 8 | Stage 2 Verification | **Vulnerable/bypassable units only** from Step 7 | Confirmed/rejected findings |
| 9 | Generate Report | Verified results from Step 8 | Summary report |
| 10 | Generate Disclosures | Confirmed vulnerabilities from Step 8 | Disclosure documents |

---

## Step 1: Clone & Parse Repository

**Purpose:** Clone the target repository and parse source code to extract functions.

**Commands:**
```bash
# Clone repository (shallow clone for speed)
git clone --depth 1 https://github.com/<org>/<repo>.git /path/to/test_repos/<repo>

# Create dataset directory
mkdir -p datasets/<repo>

# Parse repository (Python)
python parsers/python/parse_repository.py /path/to/test_repos/<repo> \
    --output datasets/<repo>/dataset.json \
    --analyzer-output datasets/<repo>/analyzer_output.json \
    --skip-tests

# For JavaScript/TypeScript
python parsers/javascript/test_pipeline.py /path/to/test_repos/<repo> \
    --analyzer-path /path/to/typescript_analyzer.js \
    --output datasets/<repo>

# For Go
python parsers/go/test_pipeline.py /path/to/test_repos/<repo> \
    --output datasets/<repo>
```

**Report:**
| Metric | Value |
|--------|-------|
| Source files | X |
| Total functions | X |
| Total units | X |

**Checkpoint:** Report results and request permission to proceed.

---

## Step 2: Generate Units

**Purpose:** Units are generated as part of Step 1. Verify unit generation completed successfully.

**Verification:**
```bash
python validate_dataset_schema.py datasets/<repo>/dataset.json
```

**Report:**
| Metric | Value |
|--------|-------|
| Total units | X |
| Enhanced units | X |
| By type | (breakdown) |

**Checkpoint:** Report results and request permission to proceed.

---

## Step 3: Run CodeQL

**Purpose:** Run CodeQL security queries to identify known vulnerability patterns.

**Commands:**
```bash
# Create CodeQL database
cd /path/to/test_repos/<repo>
codeql database create codeql-db --language=<python|javascript|go> --overwrite

# Run security queries
codeql database analyze codeql-db \
    --format=sarif-latest \
    --output=codeql-results.sarif \
    codeql/<language>-queries:codeql-suites/<language>-security-extended.qls

# Copy results to dataset directory
cp codeql-results.sarif /path/to/openant/datasets/<repo>/
```

**Report:**
| CodeQL Rule | Findings |
|-------------|----------|
| rule-1 | X |
| rule-2 | X |
| **Total** | **X** |

**Checkpoint:** Report results and request permission to proceed.

---

## Step 4: Exclude CodeQL-Flagged Units

**Purpose:** Remove units already identified by CodeQL. OpenAnt focuses on finding vulnerabilities that CodeQL misses.

**Input:** All units from `datasets/<repo>/dataset.json` (Step 1).
**Output:** `datasets/<repo>/dataset_no_codeql.json` — units whose source locations do NOT overlap with any CodeQL finding.

**Script:**
```python
import json

# Load dataset and SARIF
dataset = json.load(open('datasets/<repo>/dataset.json'))
sarif = json.load(open('datasets/<repo>/codeql-results.sarif'))
analyzer = json.load(open('datasets/<repo>/analyzer_output.json'))

# Extract CodeQL locations
results = sarif['runs'][0]['results']
codeql_locations = []
for r in results:
    for loc in r.get('locations', []):
        uri = loc['physicalLocation']['artifactLocation']['uri']
        start = loc['physicalLocation']['region']['startLine']
        end = loc['physicalLocation']['region'].get('endLine', start)
        codeql_locations.append((uri, start, end))

# Build function lookup
func_lookup = {}
for func_id, func_data in analyzer['functions'].items():
    file_part = func_id.rsplit(':', 1)[0]
    func_lookup[func_id] = {
        'file': file_part,
        'start_line': func_data.get('startLine', 0),
        'end_line': func_data.get('endLine', 0)
    }

# Find flagged unit IDs
flagged_ids = set()
for unit in dataset['units']:
    unit_id = unit['id']
    if unit_id not in func_lookup:
        continue
    info = func_lookup[unit_id]
    for cq_file, cq_start, cq_end in codeql_locations:
        if info['file'] == cq_file or cq_file.endswith('/' + info['file']):
            if not (info['end_line'] < cq_start or info['start_line'] > cq_end):
                flagged_ids.add(unit_id)
                break

# Filter dataset
filtered_units = [u for u in dataset['units'] if u['id'] not in flagged_ids]
filtered = {**dataset, 'units': filtered_units}
json.dump(filtered, open('datasets/<repo>/dataset_no_codeql.json', 'w'), indent=2)
```

**Report:**
| Metric | Value |
|--------|-------|
| Original units | X |
| CodeQL-flagged units | X |
| Remaining units | X |
| Reduction | X% |

**Checkpoint:** Report results and request permission to proceed.

---

## Step 5: Entry-Point Reachability Filter

**Purpose:** Keep only units reachable from external entry points (HTTP handlers, CLI, stdin, etc.).

**Input:** `datasets/<repo>/dataset_no_codeql.json` — units remaining after CodeQL exclusion (Step 4).
**Output:** `datasets/<repo>/dataset_reachable.json` — only units that are entry points OR reachable from entry points via the call graph.

**Script:**
```python
import json
from utilities.agentic_enhancer import EntryPointDetector, ReachabilityAnalyzer

# Load data
dataset = json.load(open('datasets/<repo>/dataset_no_codeql.json'))
analyzer = json.load(open('datasets/<repo>/analyzer_output.json'))

# Build functions dict and call graph
functions = {fid: fdata for fid, fdata in analyzer['functions'].items()}
call_graph = {}
for unit in dataset['units']:
    calls = unit.get('metadata', {}).get('direct_calls', [])
    if calls:
        call_graph[unit['id']] = calls

# Build reverse call graph
reverse_call_graph = {}
for caller, callees in call_graph.items():
    for callee in callees:
        reverse_call_graph.setdefault(callee, []).append(caller)

# Detect entry points and analyze reachability
detector = EntryPointDetector(functions, call_graph)
entry_points = detector.detect_entry_points()
reachability = ReachabilityAnalyzer(functions, reverse_call_graph, entry_points, max_depth=20)
all_reachable = reachability.get_all_reachable()

# Filter to reachable units
reachable_units = [u for u in dataset['units']
                   if u['id'] in all_reachable or u['id'] in entry_points]
filtered = {**dataset, 'units': reachable_units}
json.dump(filtered, open('datasets/<repo>/dataset_reachable.json', 'w'), indent=2)
```

**Report:**
| Metric | Value |
|--------|-------|
| Entry points detected | X |
| Reachable functions | X |
| Reachable units | X |
| Reduction from original | X% |

**Checkpoint:** Report results and request permission to proceed.

---

## Step 6: Agentic Enhancement

**Purpose:** Run agentic analysis to classify units and identify exploitable ones.

**Input:** `datasets/<repo>/dataset_reachable.json` — only reachable units from Step 5.
**Output:** `datasets/<repo>/dataset_enhanced.json` — all reachable units with `security_classification` added, then filtered to `datasets/<repo>/dataset_exploitable.json` — **only units classified as `exploitable`**.

**Command:**
```bash
python -m utilities.context_enhancer \
    datasets/<repo>/dataset_reachable.json \
    --agentic \
    --analyzer-output datasets/<repo>/analyzer_output.json \
    --repo-path /path/to/test_repos/<repo> \
    --checkpoint datasets/<repo>/checkpoint_agentic.json \
    --output datasets/<repo>/dataset_enhanced.json \
    --batch-size 10
```

**Cost Estimate:** ~$0.40-0.50 per unit

**Report:**
| Classification | Count |
|----------------|-------|
| Exploitable | X |
| Vulnerable internal | X |
| Security controls | X |
| Neutral | X |
| Errors | X |
| **Total cost** | $X |

**Filter to exploitable:**
```python
import json
dataset = json.load(open('datasets/<repo>/dataset_enhanced.json'))
exploitable = [u for u in dataset['units']
               if u.get('code', {}).get('primary_origin', {})
                   .get('agent_context', {}).get('security_classification') == 'exploitable']
filtered = {**dataset, 'units': exploitable}
json.dump(filtered, open('datasets/<repo>/dataset_exploitable.json', 'w'), indent=2)
```

**Checkpoint:** Report results and request permission to proceed.

**Decision Point:** If 0 exploitable units, analysis stops here.

---

## Step 7: Stage 1 Vulnerability Detection

**Purpose:** Run LLM-based vulnerability detection on **exploitable units only**.

**Input:** `datasets/<repo>/dataset_exploitable.json` — only units classified as `exploitable` by Step 6. Do NOT run on all enhanced units, neutral units, security controls, or vulnerable_internal units.

**Command:**
```bash
python experiment.py --dataset <repo>_exploitable --verify-verbose
```

**Note:** Ensure `datasets/<repo>_exploitable/dataset.json` exists or update `experiment.py` DATASETS config.

**Cost Estimate:** ~$0.20 per unit (Stage 1 only)

**Report:**
| Verdict | Count |
|---------|-------|
| Vulnerable | X |
| Bypassable | X |
| Protected | X |
| Safe | X |
| Inconclusive | X |

**Checkpoint:** Report results and request permission to proceed to Stage 2.

---

## Step 8: Stage 2 Attacker Simulation

**Purpose:** Verify Stage 1 findings using attacker simulation on **vulnerable and bypassable units only**.

**Input:** Units from Step 7 whose Stage 1 verdict is `vulnerable` or `bypassable`, plus — #744 — an `inconclusive` row that CARRIES a concrete claim (a non-zero `cwe_id` or a non-empty `attack_vector`): such a row escalates as a vulnerable-candidate. A bare `inconclusive` (no claim artifacts) is NOT sent, and `safe`/`protected`/error results are never sent.

**Command:**
```bash
python experiment.py --dataset <repo>_exploitable --verify --verify-verbose
```

**Cost Estimate:** ~$1.05 per unit requiring verification

**Report:**
| Stage 1 Verdict | Stage 2 Verdict | Count |
|-----------------|-----------------|-------|
| Vulnerable | Confirmed | X |
| Vulnerable | Rejected (protected) | X |
| Vulnerable | Rejected (safe) | X |

**Confirmed vulnerabilities:**
| ID | Name | Location | CWE |
|----|------|----------|-----|
| 1 | ... | ... | ... |

**Checkpoint:** Report results and request permission to generate reports.

---

## Step 9: Generate Summary Report

**Purpose:** Generate a summary report of all findings.

**Command:**
```bash
python -m report summary datasets/<repo>/pipeline_output.json -o datasets/<repo>/SUMMARY_REPORT.md
```

**Prerequisites:** Create `pipeline_output.json` with structure:
```json
{
  "repository": {"name": "<repo>", "url": "https://github.com/..."},
  "analysis_date": "YYYY-MM-DD",
  "application_type": "web_app",
  "pipeline_stats": {...},
  "results": {"vulnerable": X, "safe": X, ...},
  "findings": [...]
}
```

**Report:** Summary report generated at `datasets/<repo>/SUMMARY_REPORT.md`

**Checkpoint:** Report results and request permission to generate disclosures.

---

## Step 10: Generate Disclosure Documents

**Purpose:** Generate individual disclosure documents for confirmed vulnerabilities.

**Command:**
```bash
python -m report disclosures datasets/<repo>/pipeline_output.json -o datasets/<repo>/disclosures/
```

**Report:**
- X disclosure documents generated
- Location: `datasets/<repo>/disclosures/`

**Checkpoint:** Review disclosures before any external disclosure.

---

## Quick Reference: Full Pipeline

```bash
# 1. Clone
git clone --depth 1 https://github.com/<org>/<repo>.git ~/code/test_repos/<repo>

# 2. Parse
python parsers/python/parse_repository.py ~/code/test_repos/<repo> \
    --output datasets/<repo>/dataset.json \
    --analyzer-output datasets/<repo>/analyzer_output.json --skip-tests

# 3. CodeQL
cd ~/code/test_repos/<repo>
codeql database create codeql-db --language=python --overwrite
codeql database analyze codeql-db --format=sarif-latest \
    --output=codeql-results.sarif codeql/python-queries:codeql-suites/python-security-extended.qls
cp codeql-results.sarif ~/code/openant/datasets/<repo>/

# 4-5. Filter (see scripts above)

# 6. Agentic enhancement
python -m utilities.context_enhancer datasets/<repo>/dataset_reachable.json \
    --agentic --analyzer-output datasets/<repo>/analyzer_output.json \
    --repo-path ~/code/test_repos/<repo> \
    --checkpoint datasets/<repo>/checkpoint.json \
    --output datasets/<repo>/dataset_enhanced.json

# 7-8. Stage 1 + Stage 2
python experiment.py --dataset <repo>_exploitable --verify --verify-verbose

# 9-10. Reports
python -m report all datasets/<repo>/pipeline_output.json -o datasets/<repo>/output/
```

---

## Decision Points

| After Step | Condition | Action |
|------------|-----------|--------|
| 4 | 0 remaining units | Stop - all code flagged by CodeQL |
| 5 | 0 reachable units | Stop - no externally accessible code |
| 6 | 0 exploitable units | Stop - no exploitable vulnerabilities found |
| 8 | 0 confirmed vulns | Stop - all findings were false positives |

---

## Cost Summary

| Step | Cost per Unit | Notes |
|------|---------------|-------|
| 1-5 | $0 | Static analysis only |
| 6 | ~$0.40-0.50 | Agentic enhancement |
| 7 | ~$0.20 | Stage 1 detection |
| 8 | ~$1.05 | Stage 2 verification |
| 9-10 | ~$1-5 total | Report generation |

**Total cost formula:** `(N_reachable × $0.45) + (N_exploitable × $1.25) + $3`

Where:
- `N_reachable` = units after entry-point filter
- `N_exploitable` = units classified as exploitable
