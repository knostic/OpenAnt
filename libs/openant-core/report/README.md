# Report Generator Module

Generates security reports and disclosure documents from OpenAnt pipeline output using Claude Opus 4.5.

## Usage

```bash
# Generate summary report
python -m report summary pipeline_output.json -o SUMMARY_REPORT.md

# Generate disclosure documents for confirmed vulnerabilities
python -m report disclosures pipeline_output.json -o disclosures/

# Generate all reports (summary + disclosures)
python -m report all pipeline_output.json -o output/
```

## Commands

### `summary`

Generates a summary report with:
- Repository metadata
- Results overview table
- Pipeline statistics
- Confirmed vulnerabilities table
- False positives eliminated
- Methodology description

```bash
python -m report summary pipeline_output.json -o SUMMARY_REPORT.md
```

### `disclosures`

Generates one disclosure document per confirmed vulnerability with:
- Product and CWE information
- Summary
- Vulnerable code
- Steps to reproduce (numbered, specific)
- Impact
- Suggested fix

```bash
python -m report disclosures pipeline_output.json -o disclosures/
```

### `all`

Runs both `summary` and `disclosures` commands.

```bash
python -m report all pipeline_output.json -o output/
```

## Input Format

The module expects a JSON file with the following structure:

```json
{
  "repository": {
    "name": "example-app",
    "url": "https://github.com/org/example-app"
  },
  "analysis_date": "2026-01-28",
  "application_type": "web_app",
  "pipeline_stats": {
    "parsed_functions": 944,
    "parsed_files": 83,
    "after_reachability": 81,
    "after_codeql": 24,
    "stage1_analyzed": 24,
    "stage2_verified": 10
  },
  "results": {
    "vulnerable": 5,
    "safe": 16,
    "protected": 3,
    "inconclusive": 0,
    "error": 0
  },
  "findings": [
    {
      "id": "VULN-001",
      "name": "Full Vulnerability Name",
      "short_name": "Short Name",
      "location": {
        "file": "src/module/file.py",
        "function": "ClassName.method_name"
      },
      "cwe_id": 639,
      "cwe_name": "Authorization Bypass Through User-Controlled Key",
      "stage1_verdict": "vulnerable",
      "stage2_verdict": "vulnerable",
      "severity": "high",
      "severity_source": "model",
      "dynamic_testing": {"status": "CONFIRMED", "tested": "Docker container, <Month Year>"}, // #319: ONLY for a CONFIRMED test; every other status carries "dynamic_testing_attempted" (status/details/evidence/attempted) — never a verification
      "description": "Brief description of the vulnerability.",
      "vulnerable_code": "code snippet here",
      "impact": [
        "First impact statement",
        "Second impact statement"
      ],
      "suggested_fix": "code snippet with fix",
      "steps_to_reproduce": [
        "Step 1 description",
        "Step 2 description"
      ]
    }
  ],
  "false_positives": [
    {
      "name": "Finding Name",
      "stage1_verdict": "vulnerable",
      "stage2_verdict": "protected",
      "reason": "Why this is a false positive"
    }
  ]
}
```

## Output Style

The module uses a custom system prompt that enforces professional security writing:

- No superlatives ("critical", "crucial", "significant")
- No filler phrases ("it's important to note", "it should be noted")
- No rhetorical questions or emoji
- Short paragraphs (2-3 sentences max)
- Bullet points over prose
- Technical and direct

## File Structure

```
report/
├── __init__.py       # Package exports
├── __main__.py       # CLI entry point
├── generator.py      # LLM-based generation
├── schema.py         # Input validation
├── prompts/
│   ├── system.txt    # Anti-slop system prompt
│   ├── summary.txt   # Summary report template
│   └── disclosure.txt # Disclosure template
└── README.md         # This file
```

## API

```python
from report import (
    generate_summary_report,
    generate_disclosure,
    generate_all,
    validate_pipeline_output,
    PipelineOutput,
    Finding,
    ValidationError,
)

# Validate input
data = json.load(open("pipeline_output.json"))
try:
    pipeline = validate_pipeline_output(data)
except ValidationError as e:
    print(f"Invalid input: {e}")

# Generate summary
report = generate_summary_report(data)

# Generate disclosure
disclosure = generate_disclosure(finding_dict, "product-name")

# Generate all
generate_all("pipeline_output.json", "output/")
```

## Cost

Uses Claude Opus 4.5 (`claude-opus-4-5-20250514`).

- Input: ~$15 per million tokens
- Output: ~$75 per million tokens
- Typical cost: $1-5 per complete report set

## Requirements

- Python 3.10+
- `anthropic` package
- `ANTHROPIC_API_KEY` in `.env` file (project root) or environment variable
