"""
blind_evaluation.py -- evaluation-only "blind" input mode for historical
regression runs of the Auto Patcher (opt-in via run_traced.py
--blind-evaluation; never used by `openant patch` or any production path).

Problem it solves: a CVE's rendered vulnerability_text (cve_converter.
cve_to_vuln_text) lists the advisory's reference URLs, and some of those
URLs point directly at the known upstream remediation code change. A
historical regression must test whether the system can derive the
remediation from the vulnerability report plus the vulnerable repository,
so those references must not reach the system under test. In production,
the same references are legitimate evidence and are left alone -- this
module changes nothing unless a caller explicitly enters
BlindEvaluationSession.

Where it intercepts: the return value of
utilities.autopatcher.cve_converter.cve_to_vuln_text -- the first point at
which vulnerability_text exists as a string. It is resolved at call time by
investigation_adapters.case_from_cve, and carried byte-for-byte from there
through InvestigationCase.to_context_projection() and core.patch.
_run_engine_and_write_artifacts into pipeline.run(). Filtering AFTER
rendering means the converter's own first-five-references selection is
never refilled: a removed line simply disappears. The raw NVD record is
never touched.

Filter contract (RULE_ID, V1), applied ONLY to lines inside the rendered
`## References` section:

  REMOVED (DIRECT_REMEDIATION_REFERENCE -- the destination itself is the
  code change / diff), exact grammar only -- the whole URL must be
  "https://github.com" followed by one of these paths, with no query,
  fragment, trailing slash, suffix, port, userinfo, or host/scheme variant:
    /<owner>/<repo>/commit/<7-40 lowercase hex>
    /<owner>/<repo>/compare/<ref>...<ref>
  where <owner> is alphanumerics with single inner hyphens, <repo> is
  [A-Za-z0-9._-]+ (not "." or ".."), and each <ref> is non-empty, does not
  start or end with ".", contains no "..", and does not end in .diff/.patch.

  FAIL CLOSED (recognizable direct code-change form V1 does not support --
  never removed automatically, aborts before pipeline.run so the evaluation
  policy can be reviewed explicitly):
    - github.com / www.github.com (any case, port or userinfo): any URL whose
      repository-relative route -- the path component after /<owner>/<repo>/
      -- is commit, commits, compare, pull or pulls but which is not exactly
      one of the two V1 forms above; and any repository path ending in
      .patch/.diff. Owner and repository NAMES are never inspected, so an
      owner or repo called e.g. "diff" or "pull" does not trigger this.
    - other hosts: a path segment in {commit, commits, compare, pull, pulls,
      pull-requests, merge_requests, merge-requests, changeset, changesets,
      diff} (covers GitLab, Bitbucket, Gitea/Codeberg, cgit /commit/, Trac),
      a path ending in .patch/.diff, or a gitweb commit/commitdiff/patch query.

  KEPT (ORDINARY_VULNERABILITY_REFERENCE): everything else -- issues,
  advisory pages, mailing lists, NVD, project pages. Being one navigation
  hop away from a remediation is NOT a reason to remove a reference.

  KNOWN V1 LIMITATION: detection is not a universal forge detector. Other
  code-change URL families -- e.g. Gerrit / googlesource gitiles
  (".../+/<rev>", "/c/<project>/+/<n>"), Mercurial ("/rev/<hex>"), cgit
  "/patch/" -- are NOT recognized and are kept as ordinary references. V1
  was scoped to a GitHub-hosted regression suite; supporting those families
  is a future, explicitly reviewed policy extension. Scheme-less links and
  bare revision hashes in prose are likewise out of scope.

Matching lines are deleted whole (including their newline). Nothing is
rewritten and no replacement text is inserted. Text outside the References
section is never modified; a removable or unsupported code-change URL
found there aborts the run instead (it cannot be removed without rewriting
prose).

Verification: BlindEvaluationSession also wraps
utilities.autopatcher.pipeline.run as a pure guard -- before delegating, it
checks that the converter was intercepted exactly once and that the
vulnerability_text entering the pipeline hashes to the blinded text's
SHA256. Any deviation raises BlindEvaluationError before the pipeline does
any work. Both wrapped attributes are restored unconditionally on exit.

Opt-in extension (SAME_REPO_GITHUB_POLICY_ID; run_traced.py
--blind-strip-same-repo-github-references, valid only with
--blind-evaluation): given the target repository's identity (see
github_repository_identity), a References-section line whose URL is a
github.com / www.github.com http(s) URL under exactly that /<owner>/<repo>
-- any route, or the repository itself -- is ALSO removed, by the same
whole-line deletion. Matching is by repository identity (owner and repo
compared case-insensitively, as GitHub does), never by route or substring.
V1 runs first and unchanged: a line V1 removes is attributed to V1 only;
an unsupported same-repository line is removed by this policy instead of
aborting; unsupported references to any other repository, other hosts, and
every URL outside the References section keep the V1 behavior exactly.
Without the option, nothing in this module behaves differently.

This module contains no benchmark-specific identifiers, repository names,
fix hashes, expected patches, or expected outcomes, and must never acquire
any.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

RULE_ID = "blind-evaluation-filter/v1"
SAME_REPO_GITHUB_POLICY_ID = "blind-evaluation-same-repo-github/v1"

SIDECAR_DIRNAME = "blind_evaluation"

DIRECT_REMEDIATION_COMMIT = "direct_remediation_reference:github_commit"
DIRECT_REMEDIATION_COMPARE = "direct_remediation_reference:github_compare"
UNSUPPORTED_CODE_CHANGE = "unsupported_code_change_reference"
ORDINARY = "ordinary_vulnerability_reference"

_REMOVABLE = (DIRECT_REMEDIATION_COMMIT, DIRECT_REMEDIATION_COMPARE)

_REFERENCES_HEADING = "## References"
_H2_PREFIX = "## "
_NONE_PLACEHOLDER = "- (none)"
_REFERENCE_LINE_RE = re.compile(r"^- (?P<url>[A-Za-z][A-Za-z0-9+.\-]*://\S+)$")
_URL_IN_TEXT_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s<>()\[\]`'\"]+")

# Exact V1 grammar. A URL is removed only if it is byte-for-byte
# "https://github.com" + a path matching one of these (no query, no
# fragment, no trailing syntax). Owner: alphanumerics with single inner
# hyphens; repo: [A-Za-z0-9._-]+ other than "." / "..".
_GITHUB_OWNER = r"[A-Za-z0-9](?:-?[A-Za-z0-9])*"
_GITHUB_REPO = r"[A-Za-z0-9._-]+"
_V1_COMMIT_PATH_RE = re.compile(
    rf"^/(?P<owner>{_GITHUB_OWNER})/(?P<repo>{_GITHUB_REPO})/commit/(?P<rev>[0-9a-f]{{7,40}})$"
)
_V1_COMPARE_PATH_RE = re.compile(
    rf"^/(?P<owner>{_GITHUB_OWNER})/(?P<repo>{_GITHUB_REPO})/compare/(?P<range>[^/]+)$"
)
# One compare ref: starts and ends with a non-dot ref character.
_COMPARE_REF_RE = re.compile(r"^[A-Za-z0-9_:-](?:[A-Za-z0-9._:-]*[A-Za-z0-9_:-])?$")
_DIFF_SUFFIXES = (".diff", ".patch")

_GITHUB_HOSTS = frozenset({"github.com", "www.github.com"})
# Repository-relative GitHub routes (the path component after
# /<owner>/<repo>/) that denote a code change. Owner/repo names are never
# inspected for these words.
_GITHUB_CODE_CHANGE_ROUTES = frozenset({"commit", "commits", "compare", "pull", "pulls"})
# Path segments that, on NON-GitHub hosts, explicitly denote a code change or diff.
_GENERIC_CODE_CHANGE_SEGMENTS = frozenset({
    "commit", "commits", "compare", "pull", "pulls", "pull-requests",
    "merge_requests", "merge-requests", "changeset", "changesets", "diff",
})
_GITWEB_CHANGE_ACTIONS_RE = re.compile(r"(?:^|[;&])a=(?:commit|commitdiff|patch)(?:[;&]|$)")


@dataclass(frozen=True)
class GitHubRepository:
    """Identity of one GitHub repository: owner and repo, lowercased."""

    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"github.com/{self.owner}/{self.repo}"


_SCP_REMOTE_RE = re.compile(r"^(?:[^@/:\s]+@)?(?P<host>[^@/:\s]+):(?P<path>[^\s]+)$")
_REPO_REMOTE_SCHEMES = frozenset({"http", "https", "ssh"})


def github_repository_identity(remote: "str | None") -> "GitHubRepository | None":
    """Identity of a git remote URL that denotes a GitHub repository, or None.

    Accepted forms mirror the CLI's remote normalization (apps/openant-cli
    internal/remoteurl): http(s) and ssh:// URLs (userinfo and port dropped)
    and scp-style `[user@]host:owner/repo`; surrounding whitespace, trailing
    slashes and ONE `.git` suffix are removed. The host must be github.com
    or www.github.com and the path exactly /<owner>/<repo> -- anything else
    (another forge, a deeper path, git://, file://, a local path) has no
    identity, so the caller fails closed."""
    raw = (remote or "").strip()
    if not raw:
        return None
    if "://" in raw:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in _REPO_REMOTE_SCHEMES:
            return None
        try:
            host = (parts.hostname or "").lower()
        except ValueError:
            return None
        path = parts.path
    else:
        m = _SCP_REMOTE_RE.match(raw)
        if not m:
            return None
        host, path = m.group("host").lower(), "/" + m.group("path")
    if host not in _GITHUB_HOSTS:
        return None
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    segments = path.split("/")
    if len(segments) != 2:
        return None
    owner, repo = segments
    if not re.fullmatch(_GITHUB_OWNER, owner) or not re.fullmatch(_GITHUB_REPO, repo):
        return None
    if repo in (".", "..") or repo.lower().endswith(".git"):
        return None
    return GitHubRepository(owner.lower(), repo.lower())


def sanitize_remote_url(remote: "str | None") -> "str | None":
    """The remote URL with any userinfo removed -- the ONLY form of a remote
    that may leave repository-identity parsing (manifest, sidecar,
    diagnostics). `scheme://[userinfo@]host[:port]/path` keeps scheme, host,
    port and path; scp-style `[user@]host:path` keeps `host:path`; anything
    else (a local path) carries no userinfo and is returned stripped. Never
    used for matching."""
    if remote is None:
        return None
    raw = remote.strip()
    if "://" in raw:
        scheme, _, rest = raw.partition("://")
        authority, sep, tail = rest.partition("/")
        return f"{scheme}://{authority.rpartition('@')[2]}{sep}{tail}"
    m = _SCP_REMOTE_RE.match(raw)
    if m:
        return f"{m.group('host')}:{m.group('path')}"
    return raw


def _belongs_to_github_repository(url: str, target: GitHubRepository) -> bool:
    """True iff `url` is an http(s) github.com/www.github.com URL whose path
    is /<owner>/<repo> or lies under it, for exactly `target` -- compared by
    whole path segments, never by substring."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        return False
    try:
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    if host not in _GITHUB_HOSTS:
        return False
    segments = parts.path.split("/")[1:]
    if len(segments) < 2:
        return False
    return segments[0].lower() == target.owner and segments[1].lower() == target.repo


class BlindEvaluationError(RuntimeError):
    """Raised for every fail-closed condition of blind evaluation. The run
    must not proceed (or, if raised after the fact, must not be treated as
    a valid blind run)."""

    def __init__(self, message: str, unsupported_references: "list[dict] | None" = None):
        super().__init__(message)
        self.unsupported_references = list(unsupported_references or [])


@dataclass(frozen=True)
class ReferenceClassification:
    url: str
    category: str
    reason: str

    def to_dict(self) -> dict:
        return {"url": self.url, "category": self.category, "reason": self.reason}


@dataclass(frozen=True)
class BlindingResult:
    rule_id: str
    original_text: str
    blinded_text: str
    original_sha256: str
    blinded_sha256: str
    removed_reference_lines: tuple
    removed_references: tuple
    classifications: tuple
    # Attribution of `removed_references` (same order): V1 removals, and
    # lines removed ONLY by the opt-in same-repository policy. Defaults keep
    # every existing construction valid; in default mode removed_by_v1 ==
    # removed_references and removed_same_repo_github == ().
    removed_by_v1: tuple = ()
    removed_same_repo_github: tuple = ()
    same_repo_github_target: "GitHubRepository | None" = None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def path_resolves_inside(path, root) -> bool:
    """True if `path` (which need not exist yet) is `root` or lies under it.

    Lexical containment after symlink/".." resolution, plus filesystem
    identity: any EXISTING ancestor of the resolved path that is the same
    directory as `root` (os.path.samestat) counts as inside. The identity
    check is what catches aliases resolve() does not canonicalize, e.g. a
    case-variant spelling on a case-insensitive filesystem or a macOS
    /System/Volumes/Data firmlink path.
    """
    root_resolved = Path(root).resolve()
    candidate = Path(path).resolve()
    if candidate.is_relative_to(root_resolved):
        return True
    try:
        root_stat = os.stat(root_resolved)
    except OSError:
        return False
    for ancestor in (candidate, *candidate.parents):
        try:
            if os.path.samestat(os.stat(ancestor), root_stat):
                return True
        except OSError:
            continue
    return False


def _path_segments(path: str) -> list[str]:
    segments = path.split("/")
    if segments and segments[0] == "":
        segments = segments[1:]
    # Tolerate exactly one trailing slash; an empty segment anywhere else is
    # an unexpected shape and is kept as-is (it will not match V1 forms).
    if segments and segments[-1] == "":
        segments = segments[:-1]
    return segments


def _is_valid_compare_range(compare_range: str) -> bool:
    if compare_range.count("...") != 1:
        return False
    base, head = compare_range.split("...")
    for ref in (base, head):
        if not _COMPARE_REF_RE.match(ref) or ".." in ref or ref.lower().endswith(_DIFF_SUFFIXES):
            return False
    return True


def _exact_v1_github(url: str, parts) -> "ReferenceClassification | None":
    """The ONLY two forms V1 removes; anything else returns None."""
    if url != "https://github.com" + parts.path:
        return None  # scheme/host/port/userinfo/query/fragment variant
    m = _V1_COMMIT_PATH_RE.match(parts.path)
    if m and m.group("repo") not in (".", ".."):
        return ReferenceClassification(url, DIRECT_REMEDIATION_COMMIT, "GitHub commit URL")
    m = _V1_COMPARE_PATH_RE.match(parts.path)
    if m and m.group("repo") not in (".", "..") and _is_valid_compare_range(m.group("range")):
        return ReferenceClassification(url, DIRECT_REMEDIATION_COMPARE, "GitHub compare URL")
    return None


def _classify_github(url: str, parts) -> ReferenceClassification:
    exact = _exact_v1_github(url, parts)
    if exact is not None:
        return exact
    # Repository-relative route only: /<owner>/<repo>/<route>/... -- the
    # owner and repository names themselves are never inspected.
    raw = parts.path.split("/")[1:]
    route = raw[2].lower() if len(raw) >= 3 else None
    if route in _GITHUB_CODE_CHANGE_ROUTES:
        return ReferenceClassification(
            url, UNSUPPORTED_CODE_CHANGE,
            f"GitHub '{route}' route in a form not supported by {RULE_ID}",
        )
    if len(raw) >= 3 and raw[-1].lower().endswith(_DIFF_SUFFIXES):
        return ReferenceClassification(
            url, UNSUPPORTED_CODE_CHANGE, f"GitHub path names a .patch/.diff file, not supported by {RULE_ID}",
        )
    return ReferenceClassification(url, ORDINARY, "ordinary vulnerability/context reference")


def classify_reference_url(url: str) -> ReferenceClassification:
    """Classify one reference URL by its syntax alone (never fetched)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host in _GITHUB_HOSTS:
        return _classify_github(url, parts)

    segments = _path_segments(parts.path)
    lowered = [s.lower() for s in segments]
    change_segments = sorted(set(lowered) & _GENERIC_CODE_CHANGE_SEGMENTS)
    if change_segments:
        return ReferenceClassification(
            url, UNSUPPORTED_CODE_CHANGE,
            f"path contains code-change segment(s) {change_segments} not supported by {RULE_ID}",
        )
    if lowered and lowered[-1].endswith((".patch", ".diff")):
        return ReferenceClassification(
            url, UNSUPPORTED_CODE_CHANGE, f"path names a .patch/.diff file, not supported by {RULE_ID}",
        )
    if _GITWEB_CHANGE_ACTIONS_RE.search(parts.query):
        return ReferenceClassification(
            url, UNSUPPORTED_CODE_CHANGE, f"query selects a commit/diff view, not supported by {RULE_ID}",
        )
    return ReferenceClassification(url, ORDINARY, "ordinary vulnerability/context reference")


def _locate_references_section(lines: list[str]) -> tuple[int, int]:
    """(first_body_index, end_index) of the References section's body, i.e.
    the lines strictly between the `## References` heading and the next H2."""
    headings = [i for i, line in enumerate(lines) if line.rstrip("\n") == _REFERENCES_HEADING]
    if len(headings) != 1:
        raise BlindEvaluationError(
            f"expected exactly one '{_REFERENCES_HEADING}' heading in the rendered "
            f"vulnerability_text, found {len(headings)}; refusing to blind an unrecognized structure"
        )
    start = headings[0] + 1
    for j in range(start, len(lines)):
        if lines[j].startswith(_H2_PREFIX):
            return start, j
    raise BlindEvaluationError(
        f"no H2 heading follows '{_REFERENCES_HEADING}'; refusing to blind an unrecognized structure"
    )


def blind_vulnerability_text(
    text: str, *, same_repo_github: "GitHubRepository | None" = None,
) -> BlindingResult:
    """Apply RULE_ID to already-rendered vulnerability_text -- plus, only
    when `same_repo_github` is given, SAME_REPO_GITHUB_POLICY_ID (see the
    module docstring).

    Returns a BlindingResult (which may have zero removals, in which case
    blinded_text == original_text). Raises BlindEvaluationError for any
    fail-closed condition: unrecognized structure, a malformed reference
    line, an unsupported code-change reference, or a removable/unsupported
    code-change URL outside the References section.
    """
    if not isinstance(text, str):
        raise BlindEvaluationError(f"vulnerability_text must be str, got {type(text).__name__}")

    lines = text.splitlines(keepends=True)
    body_start, body_end = _locate_references_section(lines)

    classifications: list[ReferenceClassification] = []
    remove_indices: list[int] = []
    same_repo_indices: set[int] = set()
    unsupported: list[dict] = []

    for i in range(body_start, body_end):
        line = lines[i]
        content = line.rstrip("\n")
        if content == "" or content == _NONE_PLACEHOLDER:
            continue
        m = _REFERENCE_LINE_RE.match(content)
        if not m or not line.endswith("\n"):
            raise BlindEvaluationError(f"malformed reference line in References section: {content!r}")
        c = classify_reference_url(m.group("url"))
        classifications.append(c)
        if c.category in _REMOVABLE:
            remove_indices.append(i)
        elif same_repo_github is not None and _belongs_to_github_repository(m.group("url"), same_repo_github):
            remove_indices.append(i)
            same_repo_indices.add(i)
        elif c.category == UNSUPPORTED_CODE_CHANGE:
            unsupported.append({"line": content, **c.to_dict()})

    outside = "".join(lines[:body_start - 1] + lines[body_end:])
    for url in _URL_IN_TEXT_RE.findall(outside):
        c = classify_reference_url(url.rstrip(".,;:"))
        if c.category != ORDINARY:
            unsupported.append({
                "line": None, **c.to_dict(),
                "reason": f"code-change URL outside the References section ({c.reason}); "
                          "cannot be removed without rewriting prose",
            })

    if unsupported:
        listed = "; ".join(u["url"] for u in unsupported)
        raise BlindEvaluationError(
            f"blind evaluation aborted: {len(unsupported)} direct code-change reference(s) not "
            f"supported by {RULE_ID}: {listed}. Review the evaluation filter policy explicitly; "
            "these references are never removed automatically.",
            unsupported_references=unsupported,
        )

    removed_set = set(remove_indices)
    blinded = "".join(line for i, line in enumerate(lines) if i not in removed_set)
    removed_urls = [_REFERENCE_LINE_RE.match(lines[i].rstrip("\n")).group("url") for i in remove_indices]
    result = BlindingResult(
        rule_id=RULE_ID,
        original_text=text,
        blinded_text=blinded,
        original_sha256=sha256_text(text),
        blinded_sha256=sha256_text(blinded),
        removed_reference_lines=tuple(lines[i].rstrip("\n") for i in remove_indices),
        removed_references=tuple(removed_urls),
        classifications=tuple(classifications),
        removed_by_v1=tuple(u for i, u in zip(remove_indices, removed_urls) if i not in same_repo_indices),
        removed_same_repo_github=tuple(u for i, u in zip(remove_indices, removed_urls) if i in same_repo_indices),
        same_repo_github_target=same_repo_github,
    )
    _check_invariants(lines, body_start, body_end, remove_indices, result)
    return result


def _check_invariants(lines, body_start, body_end, remove_indices, result: BlindingResult) -> None:
    """Defense in depth: the output must be the input minus exactly the
    removed lines, with everything outside the References body untouched."""
    prefix = "".join(lines[:body_start])
    suffix = "".join(lines[body_end:])
    if not (result.blinded_text.startswith(prefix) and result.blinded_text.endswith(suffix)):
        raise BlindEvaluationError("internal invariant violated: text outside References changed")
    expected_len = len(result.original_text) - sum(len(lines[i]) for i in remove_indices)
    if len(result.blinded_text) != expected_len:
        raise BlindEvaluationError("internal invariant violated: output is not input minus removed lines")
    if remove_indices and result.original_sha256 == result.blinded_sha256:
        raise BlindEvaluationError("internal invariant violated: lines removed but hashes are equal")
    if not remove_indices and result.blinded_text != result.original_text:
        raise BlindEvaluationError("internal invariant violated: nothing removed but text changed")


@dataclass
class BlindEvaluationSession:
    """Scoped, opt-in interception for ONE CVE-mode run.

    While active:
      - utilities.autopatcher.cve_converter.cve_to_vuln_text returns the
        blinded rendering (the original converter still does the rendering);
      - utilities.autopatcher.pipeline.run first verifies the incoming
        vulnerability_text against the blinded SHA256, then delegates.
    Both are restored unconditionally on exit. Call verify_completed()
    after the run to assert the designed path happened exactly once.
    """

    converter_interception_count: int = 0
    pipeline_entry_count: int = 0
    pipeline_input_sha256: "str | None" = None
    pipeline_input_verified: "bool | None" = None
    vulnerability_artifact_verified: "bool | None" = None
    result: "BlindingResult | None" = None
    original_text: "str | None" = None
    unsupported_references: list = field(default_factory=list)
    error: "str | None" = None
    run_error: "str | None" = None
    # Opt-in same-repository GitHub policy: target identity and the remote
    # it was derived from (None in default mode). The remote is only ever
    # exposed through sanitize_remote_url (no userinfo).
    same_repo_github: "GitHubRepository | None" = None
    same_repo_github_remote: "str | None" = None
    _saved: dict = field(default_factory=dict, repr=False)

    def __enter__(self) -> "BlindEvaluationSession":
        from utilities.autopatcher import cve_converter as _converter
        from utilities.autopatcher import pipeline as _pipeline

        if self._saved:
            raise BlindEvaluationError("BlindEvaluationSession is not re-entrant")
        self._saved = {
            "converter_module": _converter,
            "converter": _converter.cve_to_vuln_text,
            "pipeline_module": _pipeline,
            "pipeline_run": _pipeline.run,
        }
        _converter.cve_to_vuln_text = self._make_converter_wrapper(self._saved["converter"])
        _pipeline.run = self._make_pipeline_guard(self._saved["pipeline_run"])
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        saved, self._saved = self._saved, {}
        if saved:
            saved["converter_module"].cve_to_vuln_text = saved["converter"]
            saved["pipeline_module"].run = saved["pipeline_run"]
        if exc is not None and not isinstance(exc, BlindEvaluationError):
            self.run_error = f"{type(exc).__name__}: {exc}"
        return False

    def _fail(self, message: str, unsupported: "list[dict] | None" = None) -> BlindEvaluationError:
        self.error = message
        return BlindEvaluationError(message, unsupported_references=unsupported)

    def _make_converter_wrapper(self, original):
        def blinded_cve_to_vuln_text(cve):
            self.converter_interception_count += 1
            if self.converter_interception_count > 1:
                raise self._fail(
                    "blind evaluation aborted: cve_to_vuln_text was intercepted more than once "
                    "in a single run; the designed interception path did not occur exactly once"
                )
            text = original(cve)
            self.original_text = text
            try:
                self.result = blind_vulnerability_text(text, same_repo_github=self.same_repo_github)
            except BlindEvaluationError as exc:
                self.unsupported_references = list(exc.unsupported_references)
                self.error = str(exc)
                raise
            return self.result.blinded_text

        return blinded_cve_to_vuln_text

    def _make_pipeline_guard(self, original):
        def guarded_pipeline_run(*args, **kwargs):
            self.pipeline_entry_count += 1
            text = kwargs["vulnerability_text"] if "vulnerability_text" in kwargs else (args[0] if args else None)
            self.pipeline_input_sha256 = sha256_text(text) if isinstance(text, str) else None
            problem = None
            if self.pipeline_entry_count != 1:
                problem = "pipeline.run entered more than once"
            elif self.converter_interception_count != 1 or self.result is None:
                problem = (
                    f"cve_to_vuln_text interception count is {self.converter_interception_count} "
                    "(expected exactly 1) at pipeline entry"
                )
            elif self.pipeline_input_sha256 != self.result.blinded_sha256:
                problem = (
                    f"pipeline input SHA256 {self.pipeline_input_sha256} != blinded SHA256 "
                    f"{self.result.blinded_sha256}"
                )
            if problem:
                self.pipeline_input_verified = False
                raise self._fail(f"blind evaluation aborted before pipeline.run: {problem}")
            self.pipeline_input_verified = True
            return original(*args, **kwargs)

        return guarded_pipeline_run

    def verify_completed(self, vulnerability_path: "str | None") -> None:
        """Post-run check: the designed path happened exactly once, and the
        persisted vulnerability artifact is the blinded text."""
        if self.converter_interception_count != 1 or self.result is None:
            raise self._fail(
                f"blind evaluation not verified: cve_to_vuln_text interception count is "
                f"{self.converter_interception_count} (expected exactly 1)"
            )
        if self.pipeline_entry_count != 1 or self.pipeline_input_verified is not True:
            raise self._fail(
                f"blind evaluation not verified: pipeline.run guard entered "
                f"{self.pipeline_entry_count} time(s), verified={self.pipeline_input_verified}"
            )
        try:
            # Exact bytes: read_text() would apply universal-newline
            # translation and make a faithful CRLF artifact look different.
            artifact = Path(vulnerability_path).read_bytes().decode("utf-8") if vulnerability_path else None
        except (OSError, UnicodeDecodeError):
            artifact = None
        self.vulnerability_artifact_verified = (
            artifact is not None and sha256_text(artifact) == self.result.blinded_sha256
        )
        if not self.vulnerability_artifact_verified:
            raise self._fail("blind evaluation not verified: vulnerability artifact does not match blinded text")

    def status(self) -> str:
        if self.error is not None:
            return "aborted"
        if self.pipeline_input_verified and self.vulnerability_artifact_verified:
            return "verified"
        if self.run_error is not None:
            return "run_failed"
        if self.converter_interception_count == 0:
            return "not_reached"
        return "unverified"

    def write_sidecar(self, trace_dir: Path) -> dict:
        """Evaluation-only sidecar; call only AFTER the pipeline finished
        (or failed), so the system under test can never read it."""
        sidecar = Path(trace_dir) / SIDECAR_DIRNAME
        sidecar.mkdir(parents=True, exist_ok=True)
        files = {}
        if self.original_text is not None:
            (sidecar / "original_vulnerability.md").write_text(self.original_text, encoding="utf-8")
            files["original_text"] = "original_vulnerability.md"
        if self.result is not None:
            (sidecar / "blinded_vulnerability.md").write_text(self.result.blinded_text, encoding="utf-8")
            files["blinded_text"] = "blinded_vulnerability.md"
            (sidecar / "removed_reference_lines.txt").write_text(
                "".join(line + "\n" for line in self.result.removed_reference_lines), encoding="utf-8"
            )
            files["removed_reference_lines"] = "removed_reference_lines.txt"
        (sidecar / "blind_evaluation.json").write_text(json.dumps(self.to_manifest_dict(files), indent=2), encoding="utf-8")
        files["metadata"] = "blind_evaluation.json"
        return files

    def to_manifest_dict(self, sidecar_files: "dict | None" = None) -> dict:
        r = self.result
        manifest = {
            "enabled": True,
            "rule_id": RULE_ID,
            "status": self.status(),
            "original_sha256": r.original_sha256 if r else (sha256_text(self.original_text) if self.original_text is not None else None),
            "blinded_sha256": r.blinded_sha256 if r else None,
            "removed_count": len(r.removed_references) if r else 0,
            "removed_reference_lines": list(r.removed_reference_lines) if r else [],
            "removed_references": list(r.removed_references) if r else [],
            "reference_classifications": [c.to_dict() for c in r.classifications] if r else [],
            "unsupported_references": list(self.unsupported_references),
            "converter_interception_count": self.converter_interception_count,
            "pipeline_entry_count": self.pipeline_entry_count,
            "pipeline_input_sha256": self.pipeline_input_sha256,
            "pipeline_input_verified": self.pipeline_input_verified,
            "vulnerability_artifact_verified": self.vulnerability_artifact_verified,
            "error": self.error,
            "run_error": self.run_error,
            "sidecar_dir": SIDECAR_DIRNAME,
            "sidecar_files": dict(sidecar_files or {}),
        }
        if self.same_repo_github is not None:
            # Additive keys, present only when the opt-in policy is enabled --
            # default-mode manifests are byte-identical to before.
            manifest["removed_by_v1"] = list(r.removed_by_v1) if r else []
            manifest["removed_same_repo_github"] = list(r.removed_same_repo_github) if r else []
            manifest["same_repo_github_policy"] = {
                "enabled": True,
                "policy_id": SAME_REPO_GITHUB_POLICY_ID,
                "target_repository": self.same_repo_github.slug,
                "target_source": "origin remote of --repo-root",
                "target_remote_url": sanitize_remote_url(self.same_repo_github_remote),
            }
        return manifest
