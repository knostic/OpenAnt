#!/usr/bin/env python3
"""
Generate interactive HTML security report from OpenAnt experiment results.

Produces a comprehensive HTML report with:
    - Stats overview cards (total units, files, findings by category)
    - Interactive pie charts showing distribution (Chart.js)
    - Category explanation table
    - LLM-generated prioritized remediation guidance
    - Sortable findings table with all results

The report calls Claude (Sonnet) to generate actionable remediation guidance
based on the vulnerability findings. This requires an API key.

Requirements:
    - ANTHROPIC_API_KEY environment variable or .env file
    - Internet connection for Chart.js CDN

Usage:
    python generate_report.py <experiment_json> <dataset_json> [output_html]

Example:
    python generate_report.py experiment_flowise.json datasets/flowise/dataset.json report.html
"""

import argparse
import json
import html
import os
from datetime import datetime

import anthropic
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


REPORT_MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 4096


def load_json(path: str) -> dict:
    """Load JSON file."""
    with open(path, 'r') as f:
        return json.load(f)


def extract_file(unit_id: str) -> str:
    """Extract file path from unit ID."""
    if ':' in unit_id:
        return unit_id.rsplit(':', 1)[0]
    return unit_id


def get_verdict_priority(verdict: str) -> int:
    """Get priority order for verdict (lower = more urgent)."""
    priorities = {
        'vulnerable': 1,
        'bypassable': 2,
        'inconclusive': 3,
        'protected': 4,
        'safe': 5
    }
    return priorities.get(verdict, 3)


def get_verdict_color(verdict: str) -> str:
    """Get color for verdict."""
    colors = {
        'vulnerable': '#dc3545',
        'bypassable': '#fd7e14',
        'inconclusive': '#6c757d',
        'protected': '#28a745',
        'safe': '#20c997'
    }
    return colors.get(verdict, '#6c757d')


def prepare_findings_summary(experiment: dict, dataset: dict) -> list:
    """Prepare findings for LLM analysis."""
    units_by_id = {u['id']: u for u in dataset.get('units', [])}

    findings = []
    for result in experiment.get('results', []):
        route_key = result.get('route_key', '')
        unit = units_by_id.get(route_key, {})
        llm_context = unit.get('llm_context') or {}
        verification = result.get('verification') or {}

        findings.append({
            'file': extract_file(route_key),
            'unit_id': route_key,
            'verdict': result.get('finding', ''),
            'attack_vector': result.get('attack_vector', ''),
            'stage1_reasoning': result.get('reasoning', ''),
            'stage2_explanation': verification.get('explanation', ''),
            'description': llm_context.get('reasoning', '')[:300] if llm_context.get('reasoning') else ''
        })

    # Sort by priority
    findings.sort(key=lambda x: get_verdict_priority(x['verdict']))
    return findings


def generate_remediation_guidance(findings: list) -> str:
    """Call LLM to generate prioritization and remediation guidance."""
    # Filter to actionable findings only
    actionable = [f for f in findings if f['verdict'] in ('vulnerable', 'bypassable', 'inconclusive')]

    if not actionable:
        return "<p>No vulnerabilities or security concerns found. All code units are either safe or properly protected.</p>"

    # Build prompt
    findings_text = ""
    for i, f in enumerate(actionable, 1):
        findings_text += f"""
### Finding {i}: {f['unit_id']}
- **Verdict**: {f['verdict']}
- **Attack Vector**: {f['attack_vector'] or 'Not specified'}
- **Analysis**: {f['stage2_explanation'][:500] if f['stage2_explanation'] else f['stage1_reasoning'][:500]}
"""

    prompt = f"""Analyze these security findings and provide:

1. **Executive Summary**: A brief overview of the security posture (2-3 sentences)

2. **Prioritized Action Items**: List specific remediation steps in order of urgency. For each item:
   - What to fix
   - Why it's important
   - How to fix it (concrete steps)

3. **Quick Wins**: Any simple fixes that would immediately improve security

Format your response as HTML (use <h3>, <p>, <ul>, <li>, <strong> tags). Do not include ```html markers.

## Findings to Analyze:
{findings_text}
"""

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment")

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=REPORT_MODEL,
        max_tokens=MAX_TOKENS,
        messages=[{"role": "user", "content": prompt}]
    )

    return response.content[0].text


def _build_pipeline_costs_html(step_reports: list[dict]) -> str:
    """Build an HTML table with pipeline step costs and durations."""
    if not step_reports:
        return ""

    # Sort by timestamp (or keep as-is)
    rows = ""
    total_cost = 0.0
    total_duration = 0.0

    for sr in sorted(step_reports, key=lambda s: s.get("timestamp", "")):
        step = sr.get("step", "unknown")
        duration = sr.get("duration_seconds", 0)
        cost = sr.get("cost_usd", 0)
        status = sr.get("status", "unknown")

        total_cost += cost
        total_duration += duration

        # Format duration
        if duration >= 60:
            dur_str = f"{duration / 60:.1f}m"
        else:
            dur_str = f"{duration:.1f}s"

        cost_str = f"${cost:.4f}" if cost > 0 else "-"
        status_color = "#28a745" if status == "success" else "#dc3545" if status == "error" else "#6c757d"

        rows += f"""
        <tr>
            <td>{html.escape(step)}</td>
            <td>{dur_str}</td>
            <td>{cost_str}</td>
            <td><span style="color: {status_color}">{html.escape(status)}</span></td>
        </tr>"""

    # Total row
    total_dur_str = f"{total_duration / 60:.1f}m" if total_duration >= 60 else f"{total_duration:.1f}s"

    return f"""
        <section class="section">
            <h2>Pipeline Costs &amp; Timing</h2>
            <table>
                <thead>
                    <tr>
                        <th>Step</th>
                        <th>Duration</th>
                        <th>Cost</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                    <tr style="border-top: 2px solid var(--border); font-weight: bold">
                        <td>Total</td>
                        <td>{total_dur_str}</td>
                        <td>${total_cost:.4f}</td>
                        <td></td>
                    </tr>
                </tbody>
            </table>
        </section>"""


def generate_html_report(
    experiment: dict,
    dataset: dict,
    remediation_html: str,
    output_path: str,
    step_reports: list[dict] | None = None,
):
    """Generate the HTML report."""
    # Prepare data
    units_by_id = {u['id']: u for u in dataset.get('units', [])}

    # Count by verdict
    verdict_counts = {}
    file_verdicts = {}  # file -> worst verdict
    findings_data = []

    for result in experiment.get('results', []):
        route_key = result.get('route_key', '')
        verdict = result.get('finding', '')
        file_path = extract_file(route_key)
        unit = units_by_id.get(route_key, {})
        llm_context = unit.get('llm_context') or {}
        verification = result.get('verification') or {}

        # Count verdicts
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        # Track worst verdict per file
        if file_path not in file_verdicts:
            file_verdicts[file_path] = verdict
        elif get_verdict_priority(verdict) < get_verdict_priority(file_verdicts[file_path]):
            file_verdicts[file_path] = verdict

        # Collect finding data
        findings_data.append({
            'file': file_path,
            'unit_id': route_key,
            'verdict': verdict,
            'priority': get_verdict_priority(verdict),
            'color': get_verdict_color(verdict),
            'attack_vector': html.escape(result.get('attack_vector', '') or ''),
            'description': html.escape(llm_context.get('reasoning', '')[:200] if llm_context.get('reasoning') else ''),
            'justification': html.escape(verification.get('explanation', '')[:300] if verification.get('explanation') else result.get('reasoning', '')[:300])
        })

    # Sort findings by priority
    findings_data.sort(key=lambda x: x['priority'])

    # Count files by worst verdict
    file_verdict_counts = {}
    for v in file_verdicts.values():
        file_verdict_counts[v] = file_verdict_counts.get(v, 0) + 1

    # Prepare chart data
    verdict_order = ['vulnerable', 'bypassable', 'inconclusive', 'protected', 'safe']
    unit_chart_labels = json.dumps([v for v in verdict_order if v in verdict_counts])
    unit_chart_data = json.dumps([verdict_counts.get(v, 0) for v in verdict_order if v in verdict_counts])
    unit_chart_colors = json.dumps([get_verdict_color(v) for v in verdict_order if v in verdict_counts])

    file_chart_labels = json.dumps([v for v in verdict_order if v in file_verdict_counts])
    file_chart_data = json.dumps([file_verdict_counts.get(v, 0) for v in verdict_order if v in file_verdict_counts])
    file_chart_colors = json.dumps([get_verdict_color(v) for v in verdict_order if v in file_verdict_counts])

    # Build findings table rows
    findings_rows = ""
    for f in findings_data:
        findings_rows += f"""
        <tr>
            <td><span class="verdict-badge" style="background-color: {f['color']}">{f['verdict']}</span></td>
            <td><code>{html.escape(f['file'])}</code></td>
            <td title="{html.escape(f['unit_id'])}">{html.escape(f['unit_id'].split(':')[-1] if ':' in f['unit_id'] else f['unit_id'])}</td>
            <td>{f['attack_vector'] or '-'}</td>
            <td class="truncate">{f['justification']}</td>
        </tr>
"""

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_units = len(findings_data)
    total_files = len(file_verdicts)

    # Build HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2"></script>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #e94560;
            --border: #333;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
        }}

        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            color: var(--accent);
        }}

        .subtitle {{
            color: var(--text-secondary);
            font-size: 1rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent);
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .section {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}

        h2 {{
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
            border-bottom: 2px solid var(--accent);
            padding-bottom: 0.5rem;
        }}

        h3 {{
            font-size: 1.2rem;
            margin: 1.5rem 0 1rem 0;
            color: var(--text-primary);
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 2rem;
            max-width: 700px;
            margin: 0 auto;
        }}

        .chart-container {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1rem;
            max-width: 300px;
            margin: 0 auto;
        }}

        .category-table {{
            margin-top: 2rem;
            max-width: 800px;
            margin-left: auto;
            margin-right: auto;
        }}

        .category-table th {{
            background: var(--bg-card);
        }}

        .category-table td:first-child {{
            width: 120px;
            text-align: center;
        }}

        .chart-title {{
            text-align: center;
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}

        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}

        th {{
            background: var(--bg-card);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
            color: var(--text-secondary);
        }}

        tr:hover {{
            background: rgba(233, 69, 96, 0.1);
        }}

        .verdict-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }}

        code {{
            background: var(--bg-card);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }}

        .truncate {{
            max-width: 400px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .remediation {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1.5rem;
        }}

        .remediation ul {{
            margin-left: 1.5rem;
            margin-top: 0.5rem;
            margin-bottom: 1rem;
        }}

        .remediation li {{
            margin-bottom: 0.5rem;
        }}

        .remediation p {{
            margin-bottom: 1rem;
        }}

        .legend {{
            display: flex;
            justify-content: center;
            gap: 1.5rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
        }}

        .legend-color {{
            width: 16px;
            height: 16px;
            border-radius: 4px;
        }}

        footer {{
            text-align: center;
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Analysis Report</h1>
            <p class="subtitle">Generated on {timestamp}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_units}</div>
                <div class="stat-label">Code Units</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_files}</div>
                <div class="stat-label">Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #dc3545">{verdict_counts.get('vulnerable', 0)}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #fd7e14">{verdict_counts.get('bypassable', 0)}</div>
                <div class="stat-label">Bypassable</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #28a745">{verdict_counts.get('protected', 0) + verdict_counts.get('safe', 0)}</div>
                <div class="stat-label">Secure</div>
            </div>
        </div>

        <section class="section">
            <h2>Distribution Overview</h2>
            <div class="charts-grid">
                <div class="chart-container">
                    <div class="chart-title">By Code Unit</div>
                    <canvas id="unitChart"></canvas>
                </div>
                <div class="chart-container">
                    <div class="chart-title">By File (Worst Verdict)</div>
                    <canvas id="fileChart"></canvas>
                </div>
            </div>
            <table class="category-table">
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #dc3545">Vulnerable</span></td>
                        <td>Code contains an exploitable security vulnerability with no effective protection. Immediate remediation required.</td>
                    </tr>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #fd7e14">Bypassable</span></td>
                        <td>Security controls exist but can be circumvented under certain conditions. Review and strengthen protections.</td>
                    </tr>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #6c757d">Inconclusive</span></td>
                        <td>Security posture could not be determined. Manual review recommended to assess risk.</td>
                    </tr>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #28a745">Protected</span></td>
                        <td>Code handles potentially dangerous operations but has effective security controls in place.</td>
                    </tr>
                    <tr>
                        <td><span class="verdict-badge" style="background-color: #20c997">Safe</span></td>
                        <td>Code does not involve security-sensitive operations or poses no security risk.</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="section">
            <h2>Remediation Guidance</h2>
            <div class="remediation">
                {remediation_html}
            </div>
        </section>

        {_build_pipeline_costs_html(step_reports or [])}

        <section class="section">
            <h2>All Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Verdict</th>
                        <th>File</th>
                        <th>Function</th>
                        <th>Attack Vector</th>
                        <th>Analysis</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </section>

        <footer>
            <p>Generated by OpenAnt Security Analysis Tool</p>
        </footer>
    </div>

    <script>
        Chart.register(ChartDataLabels);

        const chartOptions = {{
            responsive: true,
            maintainAspectRatio: true,
            plugins: {{
                legend: {{
                    display: false
                }},
                datalabels: {{
                    color: '#fff',
                    font: {{
                        weight: 'bold',
                        size: 11
                    }},
                    formatter: (value, ctx) => {{
                        const dataset = ctx.chart.data.datasets[0];
                        const total = dataset.data.reduce((a, b) => a + b, 0);
                        const percentage = Math.round((value / total) * 100);
                        const label = ctx.chart.data.labels[ctx.dataIndex];
                        return label + '\\n' + percentage + '%';
                    }},
                    textAlign: 'center'
                }}
            }}
        }};

        // Unit distribution chart
        new Chart(document.getElementById('unitChart'), {{
            type: 'pie',
            data: {{
                labels: {unit_chart_labels},
                datasets: [{{
                    data: {unit_chart_data},
                    backgroundColor: {unit_chart_colors},
                    borderWidth: 2,
                    borderColor: '#16213e'
                }}]
            }},
            options: chartOptions
        }});

        // File distribution chart
        new Chart(document.getElementById('fileChart'), {{
            type: 'pie',
            data: {{
                labels: {file_chart_labels},
                datasets: [{{
                    data: {file_chart_data},
                    backgroundColor: {file_chart_colors},
                    borderWidth: 2,
                    borderColor: '#16213e'
                }}]
            }},
            options: chartOptions
        }});
    </script>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"Report generated: {output_path}")


def _load_step_reports_from_dir(directory: str) -> list[dict]:
    """Load all {step}.report.json files from a directory."""
    import glob
    reports = []
    for path in glob.glob(os.path.join(directory, "*.report.json")):
        try:
            reports.append(load_json(path))
        except Exception:
            continue
    return reports


def main():
    parser = argparse.ArgumentParser(description='Generate HTML security report')
    parser.add_argument('experiment', help='Path to experiment results JSON')
    parser.add_argument('dataset', help='Path to dataset JSON')
    parser.add_argument('output', nargs='?', default='report.html', help='Output HTML path (default: report.html)')
    parser.add_argument('--step-reports-dir', help='Directory containing *.report.json step reports')

    args = parser.parse_args()

    print("Loading data...")
    experiment = load_json(args.experiment)
    dataset = load_json(args.dataset)

    # Load step reports if available
    step_reports = []
    if args.step_reports_dir:
        step_reports = _load_step_reports_from_dir(args.step_reports_dir)
    else:
        # Try to auto-detect from experiment path's directory
        exp_dir = os.path.dirname(os.path.abspath(args.experiment))
        step_reports = _load_step_reports_from_dir(exp_dir)

    print("Preparing findings...")
    findings = prepare_findings_summary(experiment, dataset)

    print("Generating remediation guidance (calling LLM)...")
    remediation_html = generate_remediation_guidance(findings)

    print("Building HTML report...")
    generate_html_report(experiment, dataset, remediation_html, args.output, step_reports=step_reports)

    # Print summary
    verdict_counts = {}
    for f in findings:
        v = f['verdict']
        verdict_counts[v] = verdict_counts.get(v, 0) + 1
    print(f"Summary: {verdict_counts}")


if __name__ == '__main__':
    main()
