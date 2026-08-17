"""LLM-based dynamic test generation using Claude Sonnet.

For each finding, generates:
- A Dockerfile that installs the target library/app at the correct version
- A test script that attempts the exploit and prints structured JSON results
- A docker-compose.yml if the test needs multiple services (e.g., attacker capture server)
"""

import json
import os

from core.language_registry import docker_template_for, language_for_path
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from utilities.llm_client import TokenTracker
from utilities.llm import PhaseBinding, simple_text

# Map language strings to Dockerfile template names
def resolve_docker_template(file_path: str, scan_language: str | None = None) -> str | None:
    """Docker template for a finding, chosen by the FINDING's own file.

    Args:
        file_path: Path of the file the finding is in.
        scan_language: Scan-wide language, used only when *file_path* has no
            recognizable extension.

    Returns:
        The template name, or ``None`` when the language has no template.

    ``None`` means SKIP, and callers must honour it. The previous code mapped
    only python/js/ts/go and defaulted everything else to ``"python"``, so a C
    or Zig finding produced a Python Dockerfile — an LLM call that could only
    ever fail. Skipping with a recorded reason is both cheaper and honest.
    """
    language = language_for_path(file_path)
    if language is None and scan_language:
        language = scan_language.lower()
    if language is None:
        return None
    return docker_template_for(language)

SYSTEM_PROMPT = """\
You are an expert security researcher generating dynamic exploit tests.

You will receive a vulnerability finding from a static analysis pipeline. Your job is to generate
a self-contained Docker-based test that attempts to reproduce the vulnerability.

RULES:
1. The test MUST run inside a Docker container. Never assume host access.
2. The test script MUST print exactly ONE JSON object to stdout as its final output, with this schema:
   {"status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR", "details": "...", "evidence": [{"type": "file_read|http_response|command_output|network_capture", "content": "..."}]}
3. Do NOT print anything else to stdout. Use stderr for debug logging.
4. Keep tests minimal and focused on the specific vulnerability.
5. Set appropriate timeouts — tests should complete within 60 seconds.

DEPENDENCY INSTALLATION:
- Do NOT pin exact versions unless the vulnerability is version-specific. Use >= or no version pin.
- For Python: put ALL dependencies in requirements.txt, use `pip install --no-cache-dir -r requirements.txt`.
- For Node.js: put ALL dependencies in package.json.
- For Go: do NOT write go.mod or go.sum yourself. Instead, the Dockerfile MUST initialize
  the module inside the container using `RUN go mod init <name> && go mod tidy`. This works
  whether the test uses stdlib only or third-party packages. Use golang:1.25-alpine as the
  base image to support modern k8s and cloud-native packages. Example Dockerfile for Go:
      FROM golang:1.25-alpine
      WORKDIR /test
      COPY test_exploit.go .
      RUN go mod init openant-test && go mod tidy
      RUN go build -o test_exploit test_exploit.go
      CMD ["./test_exploit"]
- The Dockerfile MUST install dependencies from the requirements/package file, NOT inline in RUN commands.
- If a package has many transitive dependencies, only install the specific sub-package you need
  (e.g., `langchain-core` instead of `langchain`).

CONTAINER FILESYSTEM:
- The container runs with a read-only root filesystem. Only /tmp is writable.
- Do NOT write files to $HOME, /root, /app/data, or any other location outside /tmp.
- If the test needs a writable cache (e.g., Go build cache), set env vars to redirect
  to /tmp: `ENV GOCACHE=/tmp/.gocache GOMODCACHE=/tmp/.gomodcache`.
- For Python, use `PYTHONDONTWRITEBYTECODE=1` to avoid writing .pyc files.

ATTACKER CAPTURE SERVER (for SSRF/callback/exfiltration tests):
- The attacker server is provided locally and listens on port 9999.
- Endpoints: GET /health (health check), GET/POST /capture (logs full request),
  GET /logs (returns all captured requests as JSON), POST /logs/clear (resets).
- In docker-compose, reference it as `http://attacker:9999` from the test container.
- In the test script, wait for `http://attacker:9999/health` before running the test,
  then check `http://attacker:9999/logs` for captured requests.

DOCKER-COMPOSE (only if the test needs multiple services):
- Do NOT include a `version:` key — it is obsolete and causes warnings.
- The attacker/capture server service MUST use `build: ./attacker-server` (it is provided locally).
  Never reference remote images for the attacker server.
- The test service should be named `test` and use `build: .`
- Use a bridge network named `testnet` for inter-service communication.
- Example:
  services:
    attacker:
      build: ./attacker-server
      networks: [testnet]
    test:
      build: .
      depends_on: [attacker]
      networks: [testnet]
  networks:
    testnet:
      driver: bridge

OUTPUT FORMAT:
Return a JSON object with these keys:
- "dockerfile": string — Complete Dockerfile content
- "test_script": string — Complete test script content (Python/JS/Go depending on language)
- "test_filename": string — Filename for the test script (e.g., "test_exploit.py")
- "requirements": string — Dependencies file content (requirements.txt / package.json / go.mod)
- "requirements_filename": string — Filename for dependencies (e.g., "requirements.txt")
- "docker_compose": string | null — docker-compose.yml content if multi-service, null if single container
- "needs_attacker_server": boolean — Whether the test needs the attacker capture server

Return ONLY the JSON object, no markdown fences or explanations."""


def _build_finding_prompt(finding: dict, repo_info: dict) -> str:
    """Build the prompt for generating a test for a single finding."""
    # Resolve per finding, not per scan — a Go finding in a Python-primary
    # scan must be described as Go.
    #
    # This is the LANGUAGE, not the Docker template. They are different
    # vocabularies ("javascript" vs the "node" base image) and conflating them
    # tells the model the wrong language for the code it is writing a test
    # against. Template selection is resolve_docker_template's job.
    loc_for_lang = finding.get("location")
    _ff = loc_for_lang.get("file") if isinstance(loc_for_lang, dict) else None
    finding_file = _ff if isinstance(_ff, str) else ""  # location.file may be non-str (JSON)
    language = language_for_path(finding_file) or repo_info.get("language") or "unknown"

    # Derive the staged source filename so the LLM can reference it in COPY.
    source_basename = ""
    loc = finding.get("location")
    if isinstance(loc, dict) and isinstance(loc.get("file"), str) and loc["file"]:
        source_basename = os.path.basename(loc["file"])

    # Inline label fields are model-produced free text (name, cwe_name, the two
    # verdicts) or repo-derived (name/type). Interpolated raw on their own line, a
    # newline in any of them forges a FINDING/instruction line — and THIS prompt's
    # output is EXECUTED (docker build/run), so injection here is the worst case.
    # Collapse control chars so each stays one inert line. (Multi-line body fields —
    # vulnerable_code/description/impact/steps — are length-adaptively FENCED below.)
    from prompts._fence import collapse_inline

    parts = [
        f"Generate a dynamic exploit test for the following vulnerability.",
        "",
        f"Repository: {collapse_inline(repo_info.get('name', 'unknown'))}",
        f"Language: {collapse_inline(language)}",
        f"Application Type: {collapse_inline(repo_info.get('application_type', 'unknown'))}",
        "",
        "FINDING:",
        f"  ID: {collapse_inline(finding.get('id', 'unknown'))}",
        f"  Name: {collapse_inline(finding.get('name', 'unknown'))}",
        f"  CWE: {finding.get('cwe_id', 0)} - {collapse_inline(finding.get('cwe_name', 'Unknown'))}",
        f"  Location: {json.dumps(loc, indent=4)}",
        f"  Stage 1 Verdict: {collapse_inline(finding.get('stage1_verdict', 'unknown'))}",
        f"  Stage 2 Verdict: {collapse_inline(finding.get('stage2_verdict', 'unknown'))}",
    ]

    if source_basename:
        parts.extend([
            "",
            f"  Source file (pre-staged in Docker build context): {source_basename}",
            f"  Your Dockerfile MUST use `COPY {source_basename} .` — the file is already there.",
        ])

    # These four fields are UNTRUSTED: `vulnerable_code` is raw Stage-1/2 LLM
    # output or a raw scanned-source excerpt; description/impact/steps are prior
    # LLM output. They were interpolated raw, so a finding could inject prompt
    # instructions into the test-generation prompt — and this prompt's output is
    # EXECUTED (docker build/run). Length-adaptive fences keep them inert here;
    # the structural mitigation (docker build --network=none / --internal test
    # net) is tracked separately (fencing alone is partial for executed output).
    from prompts._fence import safe_code_fence

    def _fenced(label: str, value) -> list:
        body = value if isinstance(value, str) else str(value)
        sf = safe_code_fence(body)
        return ["", f"  {label}:", f"{sf}", body, f"{sf}"]

    if finding.get("description"):
        parts.extend(_fenced("Description", finding["description"]))
    if finding.get("vulnerable_code"):
        parts.extend(_fenced("Vulnerable Code", finding["vulnerable_code"]))
    if finding.get("impact"):
        parts.extend(_fenced("Impact", finding["impact"]))
    if finding.get("steps_to_reproduce"):
        parts.extend(_fenced("Steps to Reproduce", finding["steps_to_reproduce"]))

    # Add CWE-specific guidance
    cwe_id = finding.get("cwe_id", 0)
    guidance = _get_cwe_guidance(cwe_id)
    if guidance:
        parts.extend(["", "CWE-SPECIFIC GUIDANCE:", guidance])

    return "\n".join(parts)


def _get_cwe_guidance(cwe_id: int) -> str:
    """Return CWE-specific testing guidance."""
    guidance = {
        22: "Path Traversal: Try reading /etc/passwd or a known file outside the intended directory. "
            "Evidence should show the file contents that should not be accessible.",
        78: "OS Command Injection: Try injecting a command like `id` or `echo PWNED`. "
            "Evidence should show command output in the response.",
        79: "XSS: Inject a script tag or event handler. Evidence should show unescaped output.",
        89: "SQL Injection: Try UNION SELECT or boolean-based injection. "
            "Evidence should show unexpected data or different behavior.",
        94: "Code Injection: Try injecting code that creates a marker file or prints a secret. "
            "Evidence should show the injected code executed.",
        134: "Format String: Try injecting format specifiers like %s or {0}. "
             "Evidence should show format string was interpreted.",
        918: "SSRF: Try making the server request an attacker-controlled URL. "
             "Use the attacker capture server and check /logs for captured requests.",
        200: "Information Exposure: Try accessing data that should be restricted. "
             "Evidence should show sensitive data in the response.",
        502: "Deserialization: Try injecting a malicious serialized object. "
             "Evidence should show code execution or unexpected behavior.",
    }
    return guidance.get(cwe_id, "")


def _parse_generation_response(raw: str) -> dict:
    """Parse the LLM response into structured test generation output."""
    text = raw.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json) and last line (```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to extract JSON from the response
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return None


def generate_test(
    finding: dict,
    repo_info: dict,
    binding: PhaseBinding,
    tracker: TokenTracker = None,
) -> dict | None:
    """Generate a dynamic test for a single finding.

    Args:
        finding: Finding dict from pipeline_output.json
        repo_info: Repository info (name, language, application_type)
        binding: Phase binding for the dynamic_test phase.
        tracker: Optional TokenTracker for cost tracking

    Returns:
        Dict with dockerfile, test_script, test_filename, requirements,
        requirements_filename, docker_compose, needs_attacker_server.
        None if generation fails.
    """
    tracker = tracker or TokenTracker()

    prompt = _build_finding_prompt(finding, repo_info)
    raw = simple_text(
        binding, prompt, max_tokens=8192, system=SYSTEM_PROMPT, tracker=tracker,
    )

    parsed = _parse_generation_response(raw)
    if not parsed:
        return None

    # Validate required fields
    required = ["dockerfile", "test_script", "test_filename"]
    if not all(k in parsed for k in required):
        return None
    # Every staging field the executor writes or joins must be a str — a non-str
    # (JSON allows any type) would raise in _write_test_files and abort the whole
    # dynamic-test run. Degrade a malformed generation to the None (NOT_REPRODUCED) path.
    _STR_FIELDS = ("dockerfile", "test_script", "test_filename",
                   "requirements", "requirements_filename", "docker_compose")
    if any(k in parsed and not isinstance(parsed[k], str) for k in _STR_FIELDS):
        return None

    return parsed


def regenerate_test(
    finding: dict,
    repo_info: dict,
    previous_generation: dict,
    error_message: str,
    binding: PhaseBinding,
    tracker: TokenTracker = None,
) -> dict | None:
    """Regenerate a test after a build/run failure, feeding the error back to the LLM.

    Args:
        finding: Finding dict from pipeline_output.json
        repo_info: Repository info
        previous_generation: The generation that failed
        error_message: The Docker build/run error message
        binding: Phase binding for the dynamic_test phase.
        tracker: Optional TokenTracker

    Returns:
        New generation dict, or None if regeneration fails.
    """
    tracker = tracker or TokenTracker()

    original_prompt = _build_finding_prompt(finding, repo_info)

    test_filename = previous_generation.get('test_filename', 'test_exploit.py')
    test_script = previous_generation.get('test_script', '')

    # Each embed (prior LLM output + docker build/run stderr, all attacker-influenced)
    # gets its OWN length-aware fence so a ``` line inside one cannot break out and
    # inject prompt-level instructions into the regeneration call. Per-embed, not one
    # global fence, since a single fence sized from one body fails to escape the others.
    from prompts._fence import safe_code_fence
    dockerfile_txt = previous_generation.get('dockerfile', '')
    requirements_txt = previous_generation.get('requirements', '')
    error_txt = error_message[:1500]
    df_fence = safe_code_fence(dockerfile_txt)
    req_fence = safe_code_fence(requirements_txt)
    ts_fence = safe_code_fence(test_script)
    err_fence = safe_code_fence(error_txt)

    retry_prompt = (
        f"{original_prompt}\n\n"
        f"IMPORTANT: A previous attempt to generate this test FAILED.\n\n"
        f"Previous Dockerfile:\n{df_fence}\n{dockerfile_txt}\n{df_fence}\n\n"
        f"Previous requirements:\n{req_fence}\n{requirements_txt}\n{req_fence}\n\n"
        f"Previous test script ({test_filename}):\n{ts_fence}\n{test_script}\n{ts_fence}\n\n"
        f"Error message:\n{err_fence}\n{error_txt}\n{err_fence}\n\n"
        f"Fix the issue and regenerate. Common fixes:\n"
        f"- Missing directories: use `mkdir -p` before writing files\n"
        f"- Dependency conflicts: don't pin exact versions, use >= or no pin\n"
        f"- Missing packages: install only the sub-package you need\n"
        f"- Connection errors: ensure service names match docker-compose service names\n"
        f"- Missing abstract methods: implement all required abstract methods on mock/stub classes\n"
        f"- Application-level errors: check the error details and fix the test logic"
    )

    raw = simple_text(
        binding, retry_prompt, max_tokens=8192, system=SYSTEM_PROMPT, tracker=tracker,
    )

    parsed = _parse_generation_response(raw)
    if not parsed:
        return None

    required = ["dockerfile", "test_script", "test_filename"]
    if not all(k in parsed for k in required):
        return None
    # Every staging field the executor writes or joins must be a str — a non-str
    # (JSON allows any type) would raise in _write_test_files and abort the whole
    # dynamic-test run. Degrade a malformed generation to the None (NOT_REPRODUCED) path.
    _STR_FIELDS = ("dockerfile", "test_script", "test_filename",
                   "requirements", "requirements_filename", "docker_compose")
    if any(k in parsed and not isinstance(parsed[k], str) for k in _STR_FIELDS):
        return None

    return parsed


def _generate_one(finding, repo_info, binding, tracker):
    """Generate a test for a single finding, tracking cost.

    ``binding`` precedes ``tracker`` to match :func:`generate_test`'s
    signature — previously this passed ``tracker`` straight into the
    ``binding`` positional, which mis-bound the call.
    """
    cost_before = tracker.total_cost_usd
    result = generate_test(finding, repo_info, binding, tracker)
    cost_after = tracker.total_cost_usd
    cost = cost_after - cost_before
    worker = threading.current_thread().name
    return finding, result, cost, worker


def generate_tests_batch(
    findings: list[dict],
    repo_info: dict,
    binding: PhaseBinding,
    tracker: TokenTracker = None,
    workers: int = 10,
) -> list[tuple[dict, dict | None, float]]:
    """Generate tests for multiple findings.

    Uses ThreadPoolExecutor for parallel generation when workers > 1.

    Args:
        findings: List of finding dicts
        repo_info: Repository info
        binding: Phase binding for the dynamic_test phase. Threaded
            through to :func:`generate_test` for every finding.
        tracker: Optional TokenTracker
        workers: Number of parallel workers (default: 10).

    Returns:
        List of (finding, generation_result_or_None, cost_usd) tuples
    """
    tracker = tracker or TokenTracker()
    total = len(findings)

    mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
    print(f"[DynamicTest] Generating tests for {total} findings, mode: {mode}", file=sys.stderr, flush=True)

    if workers <= 1:
        results = []
        for i, finding in enumerate(findings):
            _finding, result, cost, _worker = _generate_one(finding, repo_info, binding, tracker)
            print(f"[DynamicTest] {i+1}/{total}  ${cost:.2f}", file=sys.stderr, flush=True)
            results.append((_finding, result, cost))
        return results

    # Parallel mode
    results = []
    completed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_generate_one, finding, repo_info, binding, tracker) for finding in findings]
        for future in as_completed(futures):
            _finding, result, cost, worker = future.result()
            completed += 1
            print(f"[DynamicTest] {completed}/{total}  ${cost:.2f}  [{worker}]", file=sys.stderr, flush=True)
            results.append((_finding, result, cost))

    return results
