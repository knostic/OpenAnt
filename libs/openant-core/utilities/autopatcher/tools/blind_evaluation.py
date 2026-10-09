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

V2 (RULE_ID_V2 = "blind-evaluation-filter/v2"; run_traced.py
--blind-filter-policy v2, valid only with --blind-evaluation; V1 stays the
default and is unchanged). V2 keeps CLASSIFICATION (what a URL is:
classify_url_v2) separate from TRANSFORMATION (what may be done to the text
around it, decided only by structural context):

  Classification (syntax only, never fetched):
    code_change -- github.com/www.github.com http(s) URLs whose route is
      commit, commits, compare, pull or pulls (any query/fragment/suffix/
      route case), any GitHub repository path ending in .patch/.diff, and
      every non-GitHub form V1 already recognizes as a code change.
    revision_pinned_content -- blob/tree/blame/raw/<hex 7-40>/<path> on
      github.com, and raw.githubusercontent.com/<o>/<r>/<hex 7-40>/<path>.
    malformed_code_change_url -- a code-change or pinned route without a
      valid http(s) /<owner>/<repo> prefix (fails closed).
    ordinary -- everything else (issues, advisories, named-ref blobs, ...).

  Pass 1 collects remediation revisions: the hex revisions named by
  code_change URLs anywhere in the rendered text and in the advisory
  record's raw reference URLs (including those past the converter's
  five-reference cap). Nothing is fetched; no repository history is read.
  Pass 2: a revision_pinned_content URL is treated as remediation leakage
  ONLY if its revision prefix-matches (7-40 hex, either direction) a pass-1
  revision; any other pinned link (e.g. to vulnerable code) is ordinary.

  Transformation, by context:
    - References entry (`- <url>`), code_change or remediation-pinned:
      whole line deleted (the V1 operation). The same-repository policy
      still applies to other References lines exactly as before.
    - Standalone line outside References whose only content is code_change
      link(s) -- optional `-`/`*`/`+` bullet, optional `(...)` or `<...>`
      wrapping, links separated only by whitespace/`,`/`;`, optional
      trailing `.,;:` -- deleted; a whole Markdown link on its own line
      counts as a link.
    - Structural remediation-pointer line: exactly
        [bullet] (Resolved|Fixed|Patched|Fix|Patch) [in|by|via] [:] <links>[.]
      (case-insensitive), where every link is code_change or
      remediation-pinned and nothing else is on the line -- deleted. This
      is the ONLY phrase-level rule; no other wording is recognized.
    - A deleted paragraph between two blank lines also deletes the blank
      line before it (no double blank line is left).
    - Anywhere else (embedded prose, headings): only the unsafe span is
      replaced -- a bare or <angle> URL by LINK_REMOVED_TOKEN; a Markdown
      link `[text](url)` by its text when the text holds no URL, bracket or
      7+ hex run, otherwise by the token; a remediation-pinned link by its
      repository-relative path when the link is under the target
      repository and the normalized path (no `..`, `.git`, encoded `/`,
      symlink escape) exists in the target checkout, otherwise by the
      token. Revision, query and line anchor are always dropped (an anchor
      indexes the remediation revision's file, not the target's).
    - Bare remediation revision: a standalone 7-40 hex token (case-
      insensitive) that prefix-matches, or is prefix-matched by, a pass-1
      revision is replaced -- token only -- by REVISION_REMOVED_TOKEN.
      Standalone means: preceded by line start, whitespace or ( [ { ` ' ";
      followed by line end, whitespace, ) ] } ` ' " , ; : ! ? or a
      sentence-final ".". A token inside a URL, inside a span already being
      replaced, adjacent to any other character (letters, digits, _ - / @ =
      + # % ~ &, a continuing "."), or in fenced code is never rewritten; in
      inline code it is redacted only when the code span is exactly the
      token (`` `<token>` ``, backticks kept). Hex strings never named by a
      pass-1 code-change URL are never touched.
    - Fail closed (nothing rewritten): malformed code-change URLs; an
      eligible URL inside fenced or inline code; a URL truncated with
      `...` in the summary heading; Markdown links with a title, images,
      a URL as link text, or unbalanced angle brackets.

  Invariants over the COMPLETE blinded text, else abort: zero code_change,
  malformed or remediation-pinned URLs; zero known remediation revisions
  (as any 7+ hex run -- so a revision the token rule may not redact, e.g.
  one inside an identifier, a larger code span, fenced code or an
  unrecognized URL, aborts); and replay_transformations(original, record)
  must reproduce the blinded text exactly. Every change is recorded
  (action, context, line, original line/span, URL, replacement, category,
  reason, matched revision, path retention) in the manifest and in the
  sidecar's transformations.json. The pipeline-boundary hash guard is the
  same as V1's.

  Known V2 limitations: revisions are discovered only from URLs the
  advisory itself names (a fix revision that appears ONLY inside a blob
  link, a merge commit never named, or `blob/main/...` at a post-fix HEAD
  are not detected); non-GitHub forges get no revision extraction; the
  forge families V1 does not recognize remain unrecognized.

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
    # RULE_ID_V2 only (empty under V1): ordered transformation record,
    # remediation revisions found by pass 1, References lines removed by the
    # V2 filter itself, and the repository used for path retention.
    transformations: tuple = ()
    remediation_revisions: tuple = ()
    removed_by_v2: tuple = ()
    path_retention_target: "GitHubRepository | None" = None


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


# ---------------------------------------------------------------------------
# blind-evaluation-filter/v2 (opt-in; see the module docstring's V2 section)
# ---------------------------------------------------------------------------

RULE_ID_V2 = "blind-evaluation-filter/v2"
BLIND_FILTER_POLICIES = {"v1": RULE_ID, "v2": RULE_ID_V2}
DEFAULT_BLIND_FILTER_POLICY = "v1"
LINK_REMOVED_TOKEN = "[link removed]"
REVISION_REMOVED_TOKEN = "[revision removed]"

# Classification -- what a URL IS (independent of where it appears).
KIND_CODE_CHANGE = "code_change"
KIND_PINNED_CONTENT = "revision_pinned_content"
KIND_MALFORMED = "malformed_code_change_url"
KIND_ORDINARY = "ordinary"

V2_GITHUB_COMMIT = "code_change:github_commit"
V2_GITHUB_COMMITS = "code_change:github_commits"
V2_GITHUB_COMPARE = "code_change:github_compare"
V2_GITHUB_PULL = "code_change:github_pull"
V2_GITHUB_PATCH_FILE = "code_change:github_patch_file"
V2_OTHER_HOST = "code_change:other_host"
V2_PINNED = "revision_pinned_content:github"
V2_REVISION_TOKEN = "remediation_revision_token"
V2_MALFORMED = "malformed_github_code_change_url"

# Fail-closed categories -- conditions under which no transformation is safe.
V2_ABORT_MALFORMED = V2_MALFORMED
V2_ABORT_CODE = "code_change_url_in_code"
V2_ABORT_TRUNCATED = "truncated_url_in_heading"
V2_ABORT_MARKDOWN = "ambiguous_markdown_link"
V2_ABORT_REVISION = "remediation_revision_in_text"
V2_ABORT_INVARIANT = "post_transform_invariant_violation"

_GITHUB_PINNED_ROUTES = frozenset({"blob", "tree", "blame", "raw"})
_RAW_GITHUB_HOST = "raw.githubusercontent.com"
_HEX_REVISION_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_HEX_RUN_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{7,}(?![0-9A-Za-z])")
_V2_TRAILING_PUNCT = ".,;:!?*"
_FENCE_RE = re.compile(r"^ {0,3}(?:`{3,}|~{3,})")
# A standalone 7-40 hex token in prose: preceded by start-of-line, whitespace
# or an opening ( [ { ` ' " ; followed by end-of-line, whitespace, a closing
# ) ] } ` ' " , ; : ! ? or a sentence-final "." (one followed by whitespace
# or end-of-line). Anything else adjacent -- letters, digits, _ - / @ = + #
# % ~ & or a "." continuing a token -- means it is part of a larger
# identifier, path or URL and is never redacted (if it still names a known
# remediation revision, the post-transform scan fails closed instead).
_BARE_REVISION_RE = re.compile(
    r"(?:^|(?<=[\s(\[{`'\"]))([0-9a-fA-F]{7,40})(?=$|[\s)\]}`'\",;:!?]|\.(?:$|\s))"
)

# Structural line forms (see the module docstring, "V2 text contexts").
_STANDALONE_PREFIX_RE = re.compile(r"^[ \t]*(?:[-*+][ \t]+)?\(?$")
_STANDALONE_SUFFIX_RE = re.compile(r"^\)?[.,;:]?[ \t]*$")
_UNIT_SEPARATOR_RE = re.compile(r"^(?:[ \t]*[,;][ \t]*|[ \t]+)$")
_POINTER_PREFIX_RE = re.compile(
    # Same language as "<word>[ in|by|via][ ][:] " but without adjacent
    # overlapping whitespace quantifiers (linear-time on long whitespace runs).
    r"^[ \t]*(?:[-*+][ \t]+)?(?:resolved|fixed|patched|fix|patch)(?:[ \t]+(?:in|by|via))?(?:[ \t]*:)?[ \t]+$",
    re.IGNORECASE,
)
_POINTER_SUFFIX_RE = re.compile(r"^\.?[ \t]*$")


@dataclass(frozen=True)
class UrlClassification:
    """V2 classification of one URL by its syntax alone (never fetched)."""

    url: str
    kind: str
    category: str
    reason: str
    repository: "GitHubRepository | None" = None
    revisions: tuple = ()
    pinned_revision: "str | None" = None
    pinned_path: tuple = ()

    def to_dict(self) -> dict:
        d = {"url": self.url, "kind": self.kind, "category": self.category, "reason": self.reason}
        if self.repository is not None:
            d["repository"] = self.repository.slug
        if self.revisions:
            d["revisions"] = list(self.revisions)
        if self.pinned_revision is not None:
            d["pinned_revision"] = self.pinned_revision
        return d


def _strip_diff_suffix(token: str) -> str:
    low = token.lower()
    for suffix in _DIFF_SUFFIXES:
        if low.endswith(suffix):
            return token[: -len(suffix)]
    return token


def _hex_revision(token: str) -> "str | None":
    return token.lower() if _HEX_REVISION_RE.match(token) else None


def _range_revisions(spec: str) -> tuple:
    """Hex revisions named by a `<a>...<b>` / `<a>..<b>` / `<a>` spec
    (fork prefixes `owner:` dropped; named refs ignored)."""
    spec = _strip_diff_suffix(spec)
    sides = spec.split("...") if "..." in spec else spec.split("..")
    return tuple(r for r in (_hex_revision(s.rpartition(":")[2]) for s in sides) if r)


def _dedupe(items) -> tuple:
    return tuple(dict.fromkeys(items))


def _valid_github_repository(scheme: str, owner: str, repo: str) -> "GitHubRepository | None":
    if scheme.lower() not in ("http", "https"):
        return None
    if not re.fullmatch(_GITHUB_OWNER, owner) or not re.fullmatch(_GITHUB_REPO, repo) or repo in (".", ".."):
        return None
    return GitHubRepository(owner.lower(), repo.lower())


def _malformed(url: str, reason: str) -> UrlClassification:
    return UrlClassification(url, KIND_MALFORMED, V2_MALFORMED, reason)


def _ordinary(url: str) -> UrlClassification:
    return UrlClassification(url, KIND_ORDINARY, ORDINARY, "ordinary vulnerability/context reference")


def _classify_github_v2(url: str, parts) -> UrlClassification:
    segs = parts.path.split("/")[1:]
    route = segs[2].lower() if len(segs) >= 3 else None
    is_change = route in _GITHUB_CODE_CHANGE_ROUTES
    is_pinned = route in _GITHUB_PINNED_ROUTES
    is_patch_file = len(segs) >= 3 and segs[-1].lower().endswith(_DIFF_SUFFIXES)
    if not (is_change or is_pinned or is_patch_file):
        return _ordinary(url)
    repository = _valid_github_repository(parts.scheme, segs[0], segs[1])
    if repository is None:
        return _malformed(url, f"GitHub '{route}' URL without a valid http(s) /<owner>/<repo> prefix")
    rest = segs[3:]
    if is_change:
        if route in ("commit", "commits"):
            revs = _range_revisions(rest[0]) if rest else ()
            category = V2_GITHUB_COMMIT if route == "commit" else V2_GITHUB_COMMITS
        elif route == "compare":
            revs, category = _range_revisions("/".join(rest)), V2_GITHUB_COMPARE
        else:  # pull / pulls: the PR number is never treated as a revision
            revs = tuple(r for seg in rest[1:] for r in _range_revisions(seg))
            category = V2_GITHUB_PULL
        return UrlClassification(
            url, KIND_CODE_CHANGE, category, f"GitHub '{route}' route (direct code change)",
            repository, _dedupe(revs),
        )
    if is_patch_file:
        return UrlClassification(
            url, KIND_CODE_CHANGE, V2_GITHUB_PATCH_FILE, "GitHub path names a .patch/.diff file", repository,
        )
    rev = _hex_revision(rest[0]) if rest else None
    if rev is None:
        return _ordinary(url)  # named ref (branch/tag) or no revision
    return UrlClassification(
        url, KIND_PINNED_CONTENT, V2_PINNED, f"GitHub '{route}' URL pinned to a hexadecimal revision",
        repository, (), rev, tuple(rest[1:]),
    )


def _classify_raw_github_v2(url: str, parts) -> UrlClassification:
    segs = parts.path.split("/")[1:]
    if len(segs) < 3:
        return _ordinary(url)
    repository = _valid_github_repository(parts.scheme, segs[0], segs[1])
    if repository is None:
        return _malformed(url, "raw GitHub content URL without a valid http(s) /<owner>/<repo> prefix")
    if segs[-1].lower().endswith(_DIFF_SUFFIXES):
        return UrlClassification(
            url, KIND_CODE_CHANGE, V2_GITHUB_PATCH_FILE, "GitHub path names a .patch/.diff file", repository,
        )
    rev = _hex_revision(segs[2])
    if rev is None:
        return _ordinary(url)
    return UrlClassification(
        url, KIND_PINNED_CONTENT, V2_PINNED, "raw GitHub content URL pinned to a hexadecimal revision",
        repository, (), rev, tuple(segs[3:]),
    )


def classify_url_v2(url: str) -> UrlClassification:
    """Classify one URL under RULE_ID_V2 by syntax alone. Classification
    only says what the URL is; what may be done to the surrounding text is
    decided separately, by context (blind_vulnerability_text_v2)."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return _malformed(url, "URL cannot be parsed")
    if host in _GITHUB_HOSTS:
        return _classify_github_v2(url, parts)
    if host == _RAW_GITHUB_HOST:
        return _classify_raw_github_v2(url, parts)
    if classify_reference_url(url).category == UNSUPPORTED_CODE_CHANGE:
        return UrlClassification(
            url, KIND_CODE_CHANGE, V2_OTHER_HOST,
            "recognized non-GitHub code-change form (no revision extraction for this host)",
        )
    return _ordinary(url)


def _split_newline(line: str) -> tuple[str, str]:
    for nl in ("\r\n", "\n"):
        if line.endswith(nl):
            return line[: -len(nl)], nl
    return line, ""


@dataclass
class _Occurrence:
    line_index: int
    start: int
    end: int
    raw: str
    classification: UrlClassification
    matched_revision: "str | None" = None

    @property
    def url(self) -> str:
        return self.classification.url

    @property
    def eligible(self) -> bool:
        c = self.classification
        return c.kind == KIND_CODE_CHANGE or (c.kind == KIND_PINNED_CONTENT and self.matched_revision is not None)


@dataclass
class _Unit:
    """One replaceable span: a bare/angle-bracketed URL or a whole Markdown link."""

    start: int
    end: int
    kind: str  # "url" | "markdown"
    occurrence: _Occurrence
    link_text: "str | None" = None


def _url_occurrences(line_index: int, content: str) -> list[_Occurrence]:
    found = []
    for m in _URL_IN_TEXT_RE.finditer(content):
        raw = m.group(0)
        url = raw.rstrip(_V2_TRAILING_PUNCT)
        found.append(_Occurrence(line_index, m.start(), m.start() + len(url), raw, classify_url_v2(url)))
    return found


def _inline_code_spans(content: str) -> list[tuple[int, int]]:
    ticks = [i for i, ch in enumerate(content) if ch == "`"]
    return [(ticks[k], ticks[k + 1]) for k in range(0, len(ticks) - 1, 2)]


def _match_revision(rev: "str | None", revisions) -> "str | None":
    if rev is None:
        return None
    for known in revisions:
        if known.startswith(rev) or rev.startswith(known):
            return known
    return None


def _text_revision_hits(text: str, revisions) -> list[tuple[str, str]]:
    hits = []
    for m in _HEX_RUN_RE.finditer(text):
        known = _match_revision(m.group(0).lower(), revisions)
        if known is not None:
            hits.append((m.group(0), known))
    return hits


def _safe_link_text(text: "str | None", url: str) -> bool:
    """Link text may replace a code-change link only if it restates nothing
    identifying: no URL, bracket or 7+ hex run, no `#<number>`, and no digit
    run that is itself a path segment of the link (e.g. its PR number)."""
    if text is None or not text.strip():
        return False
    if "://" in text or "[" in text or "]" in text or re.search(r"#\s*\d", text):
        return False
    path_numbers = {seg for seg in urlsplit(url).path.split("/") if seg.isdigit()}
    if path_numbers & set(re.findall(r"\d+", text)):
        return False
    return not _HEX_RUN_RE.search(text)


def _retained_path(c: UrlClassification, target, repo_root, revisions) -> tuple:
    """(path or None, path_exists_at_target or None, reason)."""
    from urllib.parse import unquote

    if target is None or repo_root is None:
        return None, None, "no target repository checkout available for path retention"
    if c.repository != target:
        return None, None, "pinned URL is not under the target repository"
    segs = [unquote(s) for s in c.pinned_path]
    if not segs or any(
        s in ("", ".", "..") or s.lower() == ".git" or "/" in s or "\\" in s or "\x00" in s for s in segs
    ):
        return None, None, "pinned path is not a safely normalizable repository-relative path"
    rel = "/".join(segs)
    if _text_revision_hits(rel, revisions):
        return None, None, "pinned path itself contains a remediation revision"
    root = Path(repo_root)
    candidate = root / rel
    exists = os.path.lexists(candidate) and path_resolves_inside(candidate, root)
    if not exists:
        return None, False, "pinned path does not exist in the target checkout"
    return rel, True, "path exists in the target checkout; revision, query and anchor dropped"


def _bare_revision_tokens(content: str, revisions, line_occurrences, line_replacements) -> list:
    """(start, end, token, matched revision, context) for each standalone hex
    token on a prose line that names a pass-1 remediation revision. Tokens
    inside a URL or inside a span already being replaced are skipped (URL
    sanitization owns them); a token in inline code is redacted only when the
    code span is exactly that token (`` `<token>` ``)."""
    protected = [(o.start, o.start + len(o.raw)) for o in line_occurrences]
    protected += [(s, e) for s, e, _ in line_replacements]
    code_spans = _inline_code_spans(content)
    found = []
    for m in _BARE_REVISION_RE.finditer(content):
        s, e = m.span(1)
        known = _match_revision(m.group(1).lower(), revisions)
        if known is None or any(a < e and s < b for a, b in protected):
            continue
        enclosing = [(a, b) for a, b in code_spans if a < s and e <= b]
        if enclosing and enclosing[0] != (s - 1, e):
            continue  # part of a larger code span: never rewritten (scan fails closed)
        context = "heading" if content.startswith("#") else ("inline_code_token" if enclosing else "embedded_prose")
        found.append((s, e, m.group(1), known, context))
    return found


def _raw_reference_urls(cve) -> tuple:
    if not isinstance(cve, dict):
        return ()
    entries = cve.get("references") or []
    return tuple(
        e["url"] for e in entries if isinstance(e, dict) and isinstance(e.get("url"), str) and e["url"]
    )


def replay_transformations(original_text: str, transformations) -> str:
    """Apply a recorded v2 transformation list to `original_text`.

    Independent of the code path that produced the record: it uses only the
    serialized records, checks each one against the original bytes, and
    raises BlindEvaluationError on any inconsistency."""
    lines = original_text.splitlines(keepends=True)
    deleted: set = set()
    replacements: dict = {}
    for t in transformations:
        i = t["line_no"] - 1
        if not 0 <= i < len(lines):
            raise BlindEvaluationError(f"transformation record names line {t['line_no']}, outside the original")
        content, _ = _split_newline(lines[i])
        if content != t["original_line"]:
            raise BlindEvaluationError(f"transformation record does not match original line {t['line_no']}")
        if t["action"] == "delete_line":
            if i in deleted or i in replacements:
                raise BlindEvaluationError(f"conflicting transformation records for line {t['line_no']}")
            deleted.add(i)
        elif t["action"] in ("replace_span", "redact_revision"):
            if i in deleted or content[t["start"]:t["end"]] != t["original_span"]:
                raise BlindEvaluationError(f"replacement record does not match original line {t['line_no']}")
            if t["action"] == "redact_revision" and (
                t["replacement"] != REVISION_REMOVED_TOKEN
                or not _HEX_REVISION_RE.match(t["original_span"])
                or _match_revision(t["original_span"].lower(), (t["matched_revision"] or "",)) is None
            ):
                raise BlindEvaluationError(f"revision redaction record is inconsistent on line {t['line_no']}")
            replacements.setdefault(i, []).append(t)
        else:
            raise BlindEvaluationError(f"unknown transformation action {t['action']!r}")
    out = []
    for i, line in enumerate(lines):
        if i in deleted:
            continue
        if i in replacements:
            content, nl = _split_newline(line)
            limit = len(content)
            for t in sorted(replacements[i], key=lambda r: r["start"], reverse=True):
                if t["end"] > limit:
                    raise BlindEvaluationError(f"overlapping replacement records on line {t['line_no']}")
                content = content[: t["start"]] + t["replacement"] + content[t["end"]:]
                limit = t["start"]
            line = content + nl
        out.append(line)
    return "".join(out)


def _problem(category: str, line_no: int, line: str, reason: str, url: "str | None" = None,
             context: "str | None" = None) -> dict:
    return {"line": line, "url": url, "category": category, "reason": reason,
            "line_no": line_no, "context": context}


def _raise_problems(problems: list) -> None:
    listed = "; ".join(f"line {p['line_no']}: {p['category']} ({p['url'] or p['reason']})" for p in problems)
    raise BlindEvaluationError(
        f"blind evaluation aborted: {len(problems)} condition(s) cannot be transformed safely by "
        f"{RULE_ID_V2}: {listed}. Nothing was rewritten.",
        unsupported_references=problems,
    )


def _markdown_or_url_unit(content: str, o: _Occurrence) -> "_Unit | str":
    """The replaceable span for an eligible occurrence, or a fail-closed reason."""
    s, e = o.start, o.end
    if s >= 1 and content[s - 1] == "[" and content[e:e + 2] == "](":
        return "URL is the text of a Markdown link"
    if content[max(0, s - 2):s] == "](":
        if e >= len(content) or content[e] != ")":
            return "Markdown link with a title or trailing characters inside the parentheses"
        lb = content.rfind("[", 0, s - 2)
        if lb == -1 or "]" in content[lb + 1:s - 2]:
            return "Markdown link text could not be delimited"
        if lb >= 1 and content[lb - 1] == "!":
            return "Markdown image pointing at a code-change URL"
        return _Unit(lb, e + 1, "markdown", o, content[lb + 1:s - 2])
    if s >= 1 and content[s - 1] == "<":
        if e < len(content) and content[e] == ">":
            if content[max(0, s - 3):s - 1] == "](":
                return "angle-bracketed Markdown link destination"
            return _Unit(s - 1, e + 1, "url", o)
        return "unbalanced angle bracket around URL"
    return _Unit(s, e, "url", o)


def blind_vulnerability_text_v2(
    text: str,
    *,
    same_repo_github: "GitHubRepository | None" = None,
    raw_reference_urls=(),
    target_repository: "GitHubRepository | None" = None,
    repo_root=None,
) -> BlindingResult:
    """Apply RULE_ID_V2 (and, when `same_repo_github` is given,
    SAME_REPO_GITHUB_POLICY_ID inside References) to rendered
    vulnerability_text. See the module docstring's V2 section.

    `raw_reference_urls` are the advisory record's own reference URLs (used
    only to discover remediation revisions -- never fetched).
    `target_repository` + `repo_root` enable path retention for sanitized
    revision-pinned links. Raises BlindEvaluationError on any fail-closed
    condition or post-transform invariant violation."""
    if not isinstance(text, str):
        raise BlindEvaluationError(f"vulnerability_text must be str, got {type(text).__name__}")
    lines = text.splitlines(keepends=True)
    body_start, body_end = _locate_references_section(lines)
    split = [_split_newline(line) for line in lines]
    problems: list = []

    # References entries: identical structural rules to V1.
    ref_entries = []
    for i in range(body_start, body_end):
        content = lines[i].rstrip("\n")
        if content == "" or content == _NONE_PLACEHOLDER:
            continue
        m = _REFERENCE_LINE_RE.match(content)
        if not m or not lines[i].endswith("\n"):
            raise BlindEvaluationError(f"malformed reference line in References section: {content!r}")
        ref_entries.append((i, content, classify_url_v2(m.group("url"))))

    # Text outside References: URL occurrences, code context, heading region.
    first_h2 = next((i for i, (c, _) in enumerate(split) if c.startswith("## ")), len(lines))
    in_references = range(body_start - 1, body_end)
    occurrences: dict = {}
    in_code_line: dict = {}
    fence = False
    for i, (content, _) in enumerate(split):
        if content.startswith("## "):
            fence = False
        if i in in_references:
            continue
        if _FENCE_RE.match(content):
            fence = not fence
            in_code_line[i] = True
        else:
            in_code_line[i] = fence
        found = _url_occurrences(i, content)
        if found:
            occurrences[i] = found

    # Pass 1: remediation revisions named by direct code-change URLs.
    revisions: dict = {}

    def _collect(c: UrlClassification, source: str) -> None:
        if c.kind == KIND_CODE_CHANGE:
            for r in c.revisions:
                revisions.setdefault(r, {"revision": r, "source_url": c.url, "source": source})

    for _, _, c in ref_entries:
        _collect(c, "rendered_references")
    for found in occurrences.values():
        for o in found:
            _collect(o.classification, "rendered_text")
    for url in raw_reference_urls:
        _collect(classify_url_v2(url), "raw_advisory_references")

    for found in occurrences.values():
        for o in found:
            if o.classification.kind == KIND_PINNED_CONTENT:
                o.matched_revision = _match_revision(o.classification.pinned_revision, revisions)

    transformations: list = []
    deleted: set = set()
    replacements: dict = {}
    removed_ref = []  # (line content, url, attribution)

    # References decisions.
    for i, content, c in ref_entries:
        matched = _match_revision(c.pinned_revision, revisions) if c.kind == KIND_PINNED_CONTENT else None
        if c.kind == KIND_CODE_CHANGE or matched is not None:
            attribution, reason = "v2", c.reason
        elif same_repo_github is not None and _belongs_to_github_repository(c.url, same_repo_github):
            attribution, reason = "same_repo_github", f"under the target repository ({SAME_REPO_GITHUB_POLICY_ID})"
        else:
            if c.kind == KIND_MALFORMED:
                problems.append(_problem(V2_ABORT_MALFORMED, i + 1, content, c.reason, c.url, "references_entry"))
            continue
        deleted.add(i)
        removed_ref.append((content, c.url, attribution))
        transformations.append({
            "action": "delete_line", "context": "references_entry", "line_no": i + 1,
            "original_line": content, "urls": [c.url], "categories": [c.category],
            "attribution": attribution, "reason": reason, "matched_revision": matched,
        })

    # Outside-References decisions, line by line.
    outside_deleted = []
    for i in sorted(occurrences):
        content, _ = split[i]
        found = occurrences[i]
        line_problems = []
        for o in found:
            if o.classification.kind == KIND_MALFORMED:
                line_problems.append(_problem(V2_ABORT_MALFORMED, i + 1, content, o.classification.reason, o.url))
        if i < first_h2 and any(o.raw.endswith("...") for o in found):
            line_problems.append(_problem(
                V2_ABORT_TRUNCATED, i + 1, content, "URL truncated in the summary heading cannot be classified",
                next(o.url for o in found if o.raw.endswith("...")), "heading",
            ))
        eligible = [o for o in found if o.eligible]
        if not eligible or line_problems:
            problems.extend(line_problems)
            continue
        if in_code_line.get(i):
            problems.extend(_problem(V2_ABORT_CODE, i + 1, content, "code-change URL inside fenced code; code is "
                                     "never rewritten", o.url, "fenced_code") for o in eligible)
            continue
        spans = _inline_code_spans(content)
        in_inline = [o for o in eligible if any(a < o.start and o.end <= b for a, b in spans)]
        if in_inline:
            problems.extend(_problem(V2_ABORT_CODE, i + 1, content, "code-change URL inside inline code; code is "
                                     "never rewritten", o.url, "inline_code") for o in in_inline)
            continue

        units: list = []
        for o in eligible:
            unit = _markdown_or_url_unit(content, o)
            if isinstance(unit, str):
                line_problems.append(_problem(V2_ABORT_MARKDOWN, i + 1, content, unit, o.url, "markdown_link"))
            else:
                units.append(unit)
        units.sort(key=lambda u: u.start)
        if any(a.end > b.start for a, b in zip(units, units[1:])):
            line_problems.append(_problem(V2_ABORT_MARKDOWN, i + 1, content, "overlapping link spans", None,
                                          "markdown_link"))
        if line_problems:
            problems.extend(line_problems)
            continue

        prefix, suffix = content[:units[0].start], content[units[-1].end:]
        separators = [content[a.end:b.start] for a, b in zip(units, units[1:])]
        seps_ok = all(_UNIT_SEPARATOR_RE.match(s) for s in separators)
        heading = content.startswith("#")
        standalone = (not heading and seps_ok and bool(_STANDALONE_PREFIX_RE.match(prefix))
                      and bool(_STANDALONE_SUFFIX_RE.match(suffix)) and (("(" in prefix) == (")" in suffix)))
        pointer = (not heading and seps_ok and all(u.kind == "url" for u in units)
                   and bool(_POINTER_PREFIX_RE.match(prefix)) and bool(_POINTER_SUFFIX_RE.match(suffix)))
        all_change = all(u.occurrence.classification.kind == KIND_CODE_CHANGE for u in units)

        if (standalone and all_change) or pointer:
            context = "remediation_pointer_line" if pointer and not standalone else (
                "standalone_link_line" if any(u.kind == "markdown" for u in units) else "standalone_url_line")
            deleted.add(i)
            outside_deleted.append(i)
            transformations.append({
                "action": "delete_line", "context": context, "line_no": i + 1, "original_line": content,
                "urls": [u.occurrence.url for u in units],
                "categories": [u.occurrence.classification.category for u in units],
                "reason": ("line consists only of direct code-change link(s)" if context != "remediation_pointer_line"
                           else "line is a structural remediation pointer: '<Resolved|Fixed|Patched|Fix|Patch>"
                                "[ in|by|via][:] <link(s)>[.]'"),
                "matched_revision": next((u.occurrence.matched_revision for u in units
                                          if u.occurrence.matched_revision), None),
            })
            continue

        for u in units:
            o = u.occurrence
            path, exists, path_reason = None, None, None
            if u.kind == "markdown" and _safe_link_text(u.link_text, o.url):
                replacement, reason = u.link_text, "Markdown link reduced to its text"
            elif o.classification.kind == KIND_PINNED_CONTENT:
                path, exists, path_reason = _retained_path(o.classification, target_repository, repo_root, revisions)
                replacement = path if path is not None else LINK_REMOVED_TOKEN
                reason = "revision-pinned link at a remediation revision: " + path_reason
            else:
                replacement, reason = LINK_REMOVED_TOKEN, "direct code-change URL span replaced"
            if heading:
                context = "heading"
            elif standalone:
                context = "standalone_url_line"
            else:
                context = "markdown_link" if u.kind == "markdown" else "embedded_prose"
            replacements.setdefault(i, []).append((u.start, u.end, replacement))
            transformations.append({
                "action": "replace_span", "context": context, "line_no": i + 1, "original_line": content,
                "start": u.start, "end": u.end, "original_span": content[u.start:u.end], "url": o.url,
                "replacement": replacement, "category": o.classification.category, "reason": reason,
                "matched_revision": o.matched_revision, "path_retained": path is not None,
                "path_exists_at_target": exists,
            })

    # Bare remediation revisions in prose: replace only the token.
    for i, (content, _) in enumerate(split):
        if i in in_references or i in deleted or in_code_line.get(i):
            continue
        for s, e, token, known, context in _bare_revision_tokens(
            content, revisions, occurrences.get(i, ()), replacements.get(i, ()),
        ):
            replacements.setdefault(i, []).append((s, e, REVISION_REMOVED_TOKEN))
            transformations.append({
                "action": "redact_revision", "context": context, "line_no": i + 1, "original_line": content,
                "start": s, "end": e, "original_span": token, "replacement": REVISION_REMOVED_TOKEN,
                "category": V2_REVISION_TOKEN, "matched_revision": known,
                "reason": "standalone hexadecimal token prefix-matching a remediation revision established by "
                          "pass 1 (case-insensitive); only the token is replaced",
            })

    if problems:
        _raise_problems(problems)

    # Blank-line collapse: a deleted paragraph between two blank lines also
    # takes the blank line before it, so no double blank line is left.
    runs = []
    for i in sorted(outside_deleted):
        if runs and runs[-1][1] == i - 1:
            runs[-1][1] = i
        else:
            runs.append([i, i])
    for a, b in runs:
        before, after = a - 1, b + 1
        if (before >= 0 and after < len(lines) and before not in deleted and not split[before][0].strip()
                and not split[after][0].strip()):
            deleted.add(before)
            transformations.append({
                "action": "delete_line", "context": "blank_line_collapse", "line_no": before + 1,
                "original_line": split[before][0], "urls": [], "categories": [],
                "reason": "blank line preceding a deleted paragraph", "matched_revision": None,
            })

    # Produce the blinded text (forward construction from internal state).
    out_lines, out_map = [], []
    for i, line in enumerate(lines):
        if i in deleted:
            continue
        if i in replacements:
            content, nl = split[i]
            pieces, pos = [], 0
            for s, e, r in sorted(replacements[i]):
                pieces += [content[pos:s], r]
                pos = e
            line = "".join(pieces) + content[pos:] + nl
        out_lines.append(line)
        out_map.append(i)
    blinded = "".join(out_lines)
    transformations.sort(key=lambda t: (t["line_no"], t.get("start", -1)))

    _check_v2_invariants(text, blinded, out_lines, out_map, transformations, revisions)

    removed_urls = tuple(u for _, u, _ in removed_ref)
    return BlindingResult(
        rule_id=RULE_ID_V2,
        original_text=text,
        blinded_text=blinded,
        original_sha256=sha256_text(text),
        blinded_sha256=sha256_text(blinded),
        removed_reference_lines=tuple(line for line, _, _ in removed_ref),
        removed_references=removed_urls,
        classifications=tuple(c for _, _, c in ref_entries),
        removed_by_v1=(),
        removed_same_repo_github=tuple(u for _, u, a in removed_ref if a == "same_repo_github"),
        same_repo_github_target=same_repo_github,
        transformations=tuple(transformations),
        remediation_revisions=tuple(revisions.values()),
        removed_by_v2=tuple(u for _, u, a in removed_ref if a == "v2"),
        path_retention_target=target_repository,
    )


def _check_v2_invariants(original, blinded, out_lines, out_map, transformations, revisions) -> None:
    """Defense in depth over the COMPLETE blinded text: no recognized
    code-change URL, no revision-pinned link at a remediation revision, no
    known remediation revision anywhere, and the recorded transformations
    replay to exactly this text."""
    for k, line in enumerate(out_lines):
        content, _ = _split_newline(line)
        for o in _url_occurrences(k, content):
            c = o.classification
            leaked = c.kind in (KIND_CODE_CHANGE, KIND_MALFORMED) or (
                c.kind == KIND_PINNED_CONTENT and _match_revision(c.pinned_revision, revisions))
            if leaked:
                _raise_problems([_problem(V2_ABORT_INVARIANT, out_map[k] + 1, content,
                                          f"{c.category} URL survives transformation", c.url)])
    for k, line in enumerate(out_lines):
        hits = _text_revision_hits(line, revisions)
        if hits:
            content, _ = _split_newline(line)
            _raise_problems([_problem(
                V2_ABORT_REVISION, out_map[k] + 1, content,
                f"known remediation revision {hits[0][1]} appears outside any removable code-change URL "
                f"(as {hits[0][0]!r}); it cannot be removed without rewriting text",
            )])
    try:
        replayed = replay_transformations(original, json.loads(json.dumps(transformations)))
    except BlindEvaluationError as exc:
        _raise_problems([_problem(V2_ABORT_INVARIANT, 0, "", f"transformation record does not replay: {exc}")])
    if replayed != blinded:
        _raise_problems([_problem(V2_ABORT_INVARIANT, 0, "", "replaying the transformation record does not "
                                                            "reproduce the blinded text")])


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
    # Filter policy ("v1" default, or "v2"). V2 only: the repository and
    # checkout used for path retention, and how many raw advisory reference
    # URLs pass 1 inspected.
    policy: str = DEFAULT_BLIND_FILTER_POLICY
    target_repository: "GitHubRepository | None" = None
    repo_root: "str | None" = None
    raw_reference_url_count: "int | None" = None
    _saved: dict = field(default_factory=dict, repr=False)

    @property
    def rule_id(self) -> str:
        return BLIND_FILTER_POLICIES[self.policy]

    def __enter__(self) -> "BlindEvaluationSession":
        from utilities.autopatcher import cve_converter as _converter
        from utilities.autopatcher import pipeline as _pipeline

        if self._saved:
            raise BlindEvaluationError("BlindEvaluationSession is not re-entrant")
        if self.policy not in BLIND_FILTER_POLICIES:
            raise BlindEvaluationError(f"unknown blind filter policy {self.policy!r}")
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
                if self.policy == "v2":
                    raw_urls = _raw_reference_urls(cve)
                    self.raw_reference_url_count = len(raw_urls)
                    self.result = blind_vulnerability_text_v2(
                        text, same_repo_github=self.same_repo_github, raw_reference_urls=raw_urls,
                        target_repository=self.target_repository, repo_root=self.repo_root,
                    )
                else:
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
            if self.policy == "v2":
                (sidecar / "transformations.json").write_text(json.dumps({
                    "rule_id": self.rule_id,
                    "transformations": list(self.result.transformations),
                    "remediation_revisions": list(self.result.remediation_revisions),
                }, indent=2), encoding="utf-8")
                files["transformations"] = "transformations.json"
        (sidecar / "blind_evaluation.json").write_text(json.dumps(self.to_manifest_dict(files), indent=2), encoding="utf-8")
        files["metadata"] = "blind_evaluation.json"
        return files

    def to_manifest_dict(self, sidecar_files: "dict | None" = None) -> dict:
        r = self.result
        manifest = {
            "enabled": True,
            "rule_id": self.rule_id,
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
            # default-mode manifests are byte-identical to before. Under V2
            # the filter's own removals are reported as removed_by_v2 (below),
            # never under the V1 key.
            if self.policy != "v2":
                manifest["removed_by_v1"] = list(r.removed_by_v1) if r else []
            manifest["removed_same_repo_github"] = list(r.removed_same_repo_github) if r else []
            manifest["same_repo_github_policy"] = {
                "enabled": True,
                "policy_id": SAME_REPO_GITHUB_POLICY_ID,
                "target_repository": self.same_repo_github.slug,
                "target_source": "origin remote of --repo-root",
                "target_remote_url": sanitize_remote_url(self.same_repo_github_remote),
            }
        if self.policy == "v2":
            # Additive, V2-only keys; V1 manifests never carry them.
            manifest["removed_by_v2"] = list(r.removed_by_v2) if r else []
            manifest["transformations"] = list(r.transformations) if r else []
            manifest["transformation_count"] = len(r.transformations) if r else 0
            manifest["remediation_revisions"] = list(r.remediation_revisions) if r else []
            manifest["raw_reference_url_count"] = self.raw_reference_url_count
            manifest["path_retention"] = {
                "target_repository": self.target_repository.slug if self.target_repository else None,
                "target_checkout_checked": self.target_repository is not None and self.repo_root is not None,
            }
            manifest["post_transform_checks"] = (
                {"code_change_rescan_clean": True, "remediation_revision_scan_clean": True,
                 "transformation_replay_verified": True} if r else None
            )
        return manifest
