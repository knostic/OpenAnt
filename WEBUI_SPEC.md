# OpenAnt Web UI — Specification

## Overview

`openant serve` starts a local HTTP server (default `http://localhost:8080`, falls back to
an OS-assigned port) and opens the browser automatically. It provides a browser-based
interface to the full OpenAnt scan pipeline — no CLI knowledge required.

Scan outputs are stored under `~/.openant/webui/<job-id>/` and persist across server
restarts.

---

## Server

### Startup (`cmd/serve.go`)

- Resolves `~/.openant/webui/` as the output root; creates it if absent.
- Detects and validates the Python environment (same `ensurePython()` used by all CLI
  commands).
- Binds to `127.0.0.1:8080`; if that port is taken, falls back to any available port
  on `127.0.0.1`.
- Prints the bound URL to stdout and opens it in the system browser (`open <url>`).
- On `SIGINT` or `SIGTERM`: cancels all in-flight scan jobs (Python subprocess process
  groups are killed), then exits cleanly.

### Routes

| Method | Path | Handler |
|--------|------|---------|
| `GET` | `/` | Home page (new scan form + scan history) |
| `POST` | `/scan` | Start a new scan job |
| `GET` | `/scan/{id}` | Scan status / live log page |
| `GET` | `/scan/{id}/logs` | SSE stream of log lines |
| `GET` | `/report/{id}` | Serve the completed HTML report file |
| `GET` | `/summary/{id}` | Render the Markdown summary as HTML |
| `GET` | `/disclosures/{id}` | JSON list of disclosure reports for a job |
| `GET` | `/disclosure/{id}/{filename}` | Render a single disclosure Markdown file as HTML |
| `DELETE` | `/scan/{id}` | Cancel + delete a scan job and its output |

HTML templates (`ui/index.html`, `ui/scan.html`, `ui/summary.html`, `ui/disclosure.html`)
are embedded into the binary at compile time via `//go:embed` in `ui/embed.go`.

---

## Data Model

### Job

Each scan is a `Job` with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | 16-char hex, cryptographically random |
| `Repo` | `string` | Repository URL or local path submitted by the user |
| `StartedAt` | `time.Time` | UTC timestamp when the job was created |
| `Status` | `string` | `"running"` \| `"done"` \| `"error"` |
| `LogBuf` | `[]string` | Append-only buffer of stderr log lines |
| `ReportPath` | `string` | Absolute path to the completed `report.html`; empty until done |
| `SummaryPath` | `string` | Absolute path to `SUMMARY_REPORT.md`; empty until done |
| `DisclosurePaths` | `[]string` | Absolute paths to per-vulnerability disclosure Markdown files; empty until done |
| `Cancel` | `context.CancelFunc` | Cancels the scan subprocess; nil for completed/recovered jobs |

### Persistence

Each job directory under `~/.openant/webui/<job-id>/` contains:

| File / Directory | Description |
|------------------|-------------|
| `meta.json` | `{id, repo, started_at}` — written immediately on job creation |
| `logs.txt` | Full log buffer persisted when the scan finishes (success or error) |
| `report.html` | Interactive HTML vulnerability report (generated after scan) |
| `report/SUMMARY_REPORT.md` | LLM-generated Markdown summary report |
| `report/disclosures/DISCLOSURE_NN_<NAME>.md` | Per-vulnerability disclosure documents (one file per confirmed finding) |
| `repo/` | Git clone of the target repository (URL scans only; skipped for local paths) |

On server startup, all subdirectories of `~/.openant/webui/` are scanned. Directories
containing a `report.html` are restored as `"done"` jobs, including their `SummaryPath`
and `DisclosurePaths`. Directories without one are restored as `"error"` (they cannot
be resumed). `meta.json` is used to recover `Repo` and `StartedAt`; if absent, the repo
URL is inferred from `repo/.git/config` (origin remote URL) and the directory mtime is
used for `StartedAt`.

---

## Scan Lifecycle (`POST /scan`)

### Input (form fields)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `repo` | `string` | Yes | GitHub URL (`https://...`) or absolute local path |
| `language` | `string` | No | `auto` (default), `go`, `python`, `javascript`, `c`, `ruby`, `php` |
| `model` | `string` | No | `opus` (default, thorough) or `sonnet` (fast) |
| `api_key` | `string` | No | Anthropic API key; pre-filled from config if available |
| `verify` | checkbox | No | Enable Stage 2 attacker simulation (`--verify`); checked by default |
| `dynamic_test` | checkbox | No | Enable Docker-based dynamic testing (`--dynamic-test`); unchecked by default |

### Exit code semantics

The Python scanner (`python -m openant scan`) uses a grep-like exit code convention:

| Exit code | Meaning |
|-----------|---------|
| `0` | Scan succeeded; no vulnerabilities found |
| `1` | Scan succeeded; one or more vulnerabilities found |
| `2+` | Scan failed (parse error, API error, etc.) |

The web server treats exit codes 0 and 1 as success. Exit code ≥ 2 marks the job as
`"error"`. This means a scan that finds vulnerabilities correctly completes and enables
the report/summary/disclosure buttons.

### Execution flow (background goroutine)

1. **Clone** (URL inputs only): `git clone --depth 1 <repo> <outDir>/repo/`. Clone stderr
   is streamed to the job log with `[clone]` prefix. On failure, job is set to `"error"`.

2. **Scan**: Runs `python -m openant scan <local-path> --output <outDir> [flags]` via
   `InvokeCtx`. All stderr lines are streamed to the job log in real time. Flags passed:
   - `--language <lang>` if specified
   - `--model <model>` if not opus
   - `--verify` if enabled
   - `--dynamic-test` if enabled
   - `--repo-url <repo>` when the input was a URL (so the original URL is embedded in
     `pipeline_output.json` at scan time, making it available to the LLM report generators)

   Exit code ≥ 2 marks the job as `"error"`. Exit codes 0 and 1 are both treated as
   success (see exit code semantics above).

3. **Patch pipeline_output.json**: The `repository.url` field is updated with the
   original `repo` value. This is a belt-and-suspenders step; for URL-based scans the
   URL is already present (passed via `--repo-url`). For local-path scans it fills in
   whatever the user provided.

4. **HTML report**: Calls `python -m openant report-data <results-path> [--dataset ...]
   [--pipeline-output ...]` to obtain a JSON envelope on stdout. The JSON is unmarshalled
   into `report.ReportData` and passed to `report.GenerateReskin(data, outDir+"/report.html")`
   — a Go-native template renderer. Log lines are prefixed `[report]`. On failure, job is
   set to `"error"` and `"no report.html produced"` is logged.

5. **Markdown summary**: Calls `python -m openant report <results-path> --format summary
   --output <outDir>/SUMMARY_REPORT.md [--pipeline-output ...]` via `InvokeCtx`. Non-fatal:
   a non-zero exit is logged but does not change the job status.

6. **Collect disclosures**: Scans `<outDir>/report/disclosures/` for `*.md` files
   (generated by the Python scan's report step). Paths are stored in `job.DisclosurePaths`.

7. **Persist logs**: Full `LogBuf` is written to `logs.txt`.

8. **Mark done**: `job.SetDone(reportPath, summaryPath, disclosurePaths)`.

### Cancellation

- Each job has a `context.Context`; cancelling it sends `SIGKILL` to the Python process
  group (covering all child processes, e.g. parallel workers).
- `DELETE /scan/{id}` cancels the job (if running), removes it from the in-memory map,
  and deletes its output directory from disk.
- On server shutdown, all in-flight jobs are cancelled.

---

## Pages

### Home (`/`) — `ui/index.html`

**Layout**: Two-column grid. Left column: New Scan form. Right column: How It Works
panel. Below the grid: Recent Scans history list.

**New Scan form**:
- Repository URL or local path — text input, required, autofocused.
- Language — dropdown: `auto-detect`, `Go`, `Python`, `JavaScript`, `C / C++`, `Ruby`,
  `PHP`. Selecting `auto` omits the `--language` flag.
- Model — dropdown: `opus (thorough)` (default), `sonnet (fast)`. Selecting `opus` omits
  the `--model` flag (opus is the default in Python CLI).
- Anthropic API Key — password input. Pre-filled with the stored API key if one exists
  (shown with "Pre-filled from…" notice); otherwise shows a "Run `openant set-api-key`"
  hint.
- Options checkboxes:
  - "Stage 2 attacker simulation (--verify)" — checked by default.
  - "Dynamic testing via Docker (--dynamic-test)" — unchecked by default.
- "Start Scan" button — full-width, dark. Submits form; server redirects to
  `/scan/<id>`.

**How It Works panel** (informational):
- Lists the 5 pipeline stages: Parse → Enhance → Analyze → Verify → Report.
- Note: "Scans run locally on your machine."

**Recent Scans list**:
- Shows all known jobs, newest first, as rows with:
  - Monospace repo URL/path (wraps with `word-break: break-all`; never truncated).
  - Status badge: `Running` (yellow), `Done` (green), `Error` (red).
  - For `running`: "View →" link to `/scan/<id>`.
  - For `done`: "Logs →" link, "Summary →" link (only if summary exists),
    "Report →" link.
  - For `error`: "View →" link to `/scan/<id>`.
  - Delete button (trash icon) — calls `DELETE /scan/<id>` via `fetch`, removes the
    row from the DOM. If no rows remain, shows "No scans yet" empty state.
- Empty state: "No scans yet. Submit a repo above to get started."

---

### Scan Status (`/scan/{id}`) — `ui/scan.html`

**Purpose**: Live scan monitoring page. Connects to the SSE log stream and renders
progress in real time. The header displays the full repo URL/path with
`word-break: break-all` so it is never truncated.

**Components**:

**Pipeline step tracker**: Five pill-shaped step indicators — `Parse`, `Enhance`,
`Analyze`, `Verify`, `Report`. Each pill is wrapped in a `.step-item` container that
also displays a numeric count badge below it. Each pill can be in one of three visual
states:
- **Inactive** (default): grey border, light grey background, muted text.
- **Active**: dark border, white background, bold text.
- **Done**: dark fill, white text, prefixed with `✓`.

Step transitions are driven by log line pattern matching:
- `[parse]` in line → activate Parse.
- `✓ parse` → complete Parse.
- `[enhance]` → complete Parse + activate Enhance.
- `✓ enhance` → complete Enhance.
- `[analyze]` or `[detect]` → complete Enhance + activate Analyze.
- `✓ analy` or `✓ detect` → complete Analyze.
- `[verify]` → complete Analyze + activate Verify.
- `✓ verify` → complete Verify.
- `[report]` → complete Verify + activate Report.
- `✓ report` → complete Report.

On scan completion (`done` SSE event), all remaining non-done steps are marked done.

**Funnel counts**: Each step pill displays a live unit count beneath it, extracted from
log lines via regex as they arrive over SSE:
- **Parse**: total units extracted (e.g. `"Parsed 342 units"`).
- **Enhance**: units passed to enhancement (e.g. `"Enhancing 300 units"`).
- **Analyze**: units passed to analysis, or potential findings count.
- **Verify**: units/findings passed to verification.
- **Report**: validated findings that become disclosures, extracted from log lines such as
  `"pipeline_output.json: N findings"`, `"Generating N disclosures in parallel"`, or
  `"Disclosures: N files in …"`.
Counts are formatted with `toLocaleString()` (e.g. `1,234`). A stage's count element
remains blank until a matching log line is observed.

**Log stream**: Dark terminal panel (`#0d1117` background, 360px height, scrollable).
Each log line is appended as a `<div>` with syntax coloring:
- `finding` (orange, bold): lines matching `/potential|vulner|finding|! /` that don't
  start with `✓`.
- `ok` (green): lines starting with `✓` or matching `/complete\b/`.
- `step-tag` (blue): lines starting with `[parse]`, `[enhance]`, `[analyze]`,
  `[detect]`, `[verify]`, `[report]`, `[dynamic`.
- `progress` (yellow): lines matching `→`, `analyzing batch`, `running`, `scanning`,
  `processing`.
- Timestamps (`HH:MM:SS` prefix) are rendered in a dimmed color, separated from the
  rest of the line.
- Log stream auto-scrolls to the bottom on each new line.

**Status bar**: Animated pulsing dot + status text.
- While running: dot is yellow/pulsing; text shows "Scanning…".
- On `done` event: dot turns green (no animation); text shows "Scan complete". The
  finding count is already captured in the Report step pill and does not need to be
  repeated in the status bar.
- On `error` event: dot turns red; text shows "Scan failed"; error banner shown below.

**Report/Summary buttons**: Initially disabled (grey, `pointer-events: none`).
Activated (`ready` class: dark background, clickable) when the `done` SSE event fires
with `status === "done"`. Open in new tabs.
- "View Summary" — links to `/summary/{id}`; activated only if a HEAD request to that
  URL returns 200 (i.e. the summary file was actually produced).
- "View HTML Report" — links to `/report/{id}`; always activated on `done`.

**Disclosure report buttons**: Shown below the Report/Summary buttons, only when
disclosure files were generated (i.e., at least one confirmed vulnerability was found).
- Populated on `done` by fetching `GET /disclosures/{id}`.
- Section header: "Disclosure Reports" (uppercase label, small caps style).
- One button per disclosure file. Button label is the vulnerability title extracted from
  the first `# Security Disclosure: <title>` heading in the Markdown file; falls back to
  the humanised filename if parsing fails.
- Buttons have a red-tinted style (red border, light red background) to signal security
  findings. Open the disclosure page in a new tab.
- Each button is displayed on its own line (column flex layout, full-width block).

**SSE transport** (`GET /scan/{id}/logs`):
- Server sends log lines as `data: <line>\n\n` events at up to 200ms polling intervals.
- On scan completion, sends `event: done\ndata: <status>\n\n` and closes the stream.
- Client reconnects automatically on `onerror` (unless stream is already closed).

---

### Summary (`/summary/{id}`) — `ui/summary.html`

- Reads `SUMMARY_REPORT.md` from disk.
- Renders it as HTML using the `marked.js` library (loaded from CDN).
- Minimal styled page: header with "Knostic OpenAnt / scan summary" and a "← Home"
  back link; content in a white bordered panel.
- Returns 404 if summary is not yet available.
- The summary Markdown includes the repository URL in its `**Repository:**` field,
  sourced from `pipeline_output.json` which is populated with the original repo URL
  at scan time via `--repo-url`.

---

### Disclosure (`/disclosure/{id}/{filename}`) — `ui/disclosure.html`

- Serves a single per-vulnerability disclosure document as a human-readable HTML page.
- The `{filename}` path component is validated: only base filenames (no path separators
  or `..`) are accepted, and the file must be in the job's known `DisclosurePaths` list
  (no path traversal).
- Reads the corresponding `*.md` file from `<outDir>/report/disclosures/<filename>`.
- Renders the Markdown using `marked.js` (loaded from CDN).
- Page title and breadcrumb header show the vulnerability name (derived from the
  `# Security Disclosure: <title>` heading in the file).
- Breadcrumb: `← Home / Scan / <vuln name>`, linking back to the scan page.
- Styled consistently with the summary page: white content panel, monospace code blocks
  on dark background, full table support.
- Post-render JS makes `**Repository:**` lines into clickable links when the value is
  an HTTP URL.
- Returns 404 if the file is not in the job's known disclosures or cannot be read.

### Disclosure List API (`GET /disclosures/{id}`)

Returns a JSON array of disclosure info objects for a completed job:

```json
[
  {
    "name": "DISCLOSURE_01_SQL_INJECTION.md",
    "label": "Sql Injection",
    "url": "/disclosure/<id>/DISCLOSURE_01_SQL_INJECTION.md"
  }
]
```

- `name`: base filename of the disclosure Markdown file.
- `label`: human-readable vulnerability title, extracted from the first `#` heading in
  the file (stripping the `"Security Disclosure: "` prefix). Falls back to a
  filename-derived label (strips `DISCLOSURE_NN_` prefix, replaces underscores with
  spaces, title-cases the result).
- `url`: relative URL to the disclosure page.
- Returns an empty array `[]` if no disclosures exist. Never returns 404 for valid job IDs.

---

### HTML Report (`/report/{id}`)

- Serves the `report.html` file directly via `http.ServeFile`.
- Returns 404 if the report is not yet available.
- The report header shows the repository name as a clickable link to the repository URL
  when `RepoURL` is populated in the report data. Falls back to plain text when the URL
  is not available (e.g. local-path scans without a remote).

---

## Report Content — Repository Location

The repository URL is captured in all three report types when the scan input is a URL:

| Report | How URL appears |
|--------|----------------|
| **Security Analysis Report** (HTML) | Repository name in the header is a `<a href>` link to the repo URL |
| **Summary Report** (Markdown) | `**Repository:** <url>` field near the top of the document |
| **Security Disclosure Report** (Markdown) | `**Repository:** <url>` field in the document header, below `**Product:**`; omitted if no URL is available |

The URL flows as follows:
1. Web UI passes `--repo-url <original-url>` to `python -m openant scan` for URL-based scans.
2. Python's `scan_repository()` receives `repo_url` and passes it to `build_pipeline_output()`.
3. `build_pipeline_output()` writes it to `pipeline_output.json` as `repository.url`.
4. The LLM report generators (`generate_summary_report`, `generate_disclosure_docs`) read
   it from `pipeline_output.json` and include it in the generated Markdown.
5. The Go HTML report renderer reads it from `pipeline_output.json` via the `report-data`
   subcommand and includes it in `ReportData.RepoURL`.

For CLI scans (local paths), `--repo-url` can be passed manually; otherwise the URL field
is empty and omitted from reports.

---

## Security & Scope

- Server binds exclusively to `127.0.0.1` (localhost only); not accessible from the
  network.
- The Anthropic API key submitted via the form is used only to set `ANTHROPIC_API_KEY`
  in the Python subprocess environment; it is never logged or written to disk by the
  web UI.
- Repository URLs are passed directly to `git clone`; no URL validation is performed
  beyond checking that the `repo` field is non-empty.
- Disclosure file serving validates that the requested `{filename}` is a base filename
  with no path components, and that it exists in the job's known `DisclosurePaths` list,
  preventing path traversal attacks.
- The delete endpoint removes the entire job output directory with `os.RemoveAll`.
