"""Centralized file I/O and subprocess helpers for Windows UTF-8 compatibility.

On Windows, Python's default encoding is often ``cp1252`` (charmap), which
cannot decode common UTF-8 sequences found in source code.  These thin
wrappers ensure that every file open and subprocess call uses UTF-8
explicitly, preventing ``'charmap' codec can't decode byte ...`` errors.
"""

import errno
import json
import logging
import os
import stat
import subprocess
import tempfile
from typing import Any, Union

# Accept str, Path, or any os.PathLike
PathLike = Union[str, os.PathLike]


class UnsafeRepoFile(Exception):
    """A path inside a scanned repository is not safe to read."""


def repo_path_state(path: PathLike) -> str:
    """Classify a path inside a scanned repository: absent / regular / unsafe.

    Use instead of ``Path.exists()`` anywhere the answer decides security
    behaviour. ``exists()`` follows symlinks, so a **dangling** link answers False
    and reads as "absent" — which is how a repository gets a silent downgrade (the
    loader treating a broken link as "no threat model") or a write-escape (the
    writer treating it as a free filename and then following it).

    Returns:
        ``"absent"``, ``"regular"``, or ``"unsafe"`` (symlink, FIFO, device,
        directory — anything that must not be read or written as a plain file).
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unsafe"
    if stat.S_ISLNK(info.st_mode):
        return "unsafe"
    return "regular" if stat.S_ISREG(info.st_mode) else "unsafe"


def write_repo_file(path: PathLike, text: str, *, overwrite: bool = False) -> None:
    """Write a file into a scanned repository without following symlinks.

    ``Path.write_text`` follows symlinks, so writing to an attacker-chosen path in
    an untrusted checkout is a write-escape primitive: the repository ships
    ``OPENANT.THREATMODEL.md -> /etc/cron.d/x`` (or anything outside the tree), the
    caller's ``exists()`` check reads the dangling link as absent, and the write
    lands wherever the link points.

    ``O_NOFOLLOW`` refuses at the final component, which is the component the
    repository controls. Combined with ``O_EXCL`` (create-only) or ``O_TRUNC``
    (explicit overwrite) the caller states its intent and cannot be redirected.

    Raises:
        UnsafeRepoFile: If the target is a symlink, or exists when the caller asked
            to create. Refusing loudly is correct — silently writing elsewhere is
            the whole failure being prevented.
    """
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    name = os.path.basename(os.fspath(path))
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise UnsafeRepoFile(
                f"{name} is a symlink; refusing to write through it and out of the "
                "scanned repository"
            ) from None
        if exc.errno == errno.EEXIST:
            raise UnsafeRepoFile(f"{name} already exists") from None
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def safe_to_descend(dir_path: PathLike, repo_real: str, seen: set | None = None) -> bool:
    """Whether a directory inside a scanned repository may be walked.

    A directory symlink in an untrusted repository is two attack primitives:

    * ``vendor -> /`` walks the host filesystem into ``dataset.json``, which is then
      sent to the model provider. Verified: a repo containing ``escape -> /tmp/x``
      produced a unit for a file outside the repository.
    * ``loop -> ..`` recurses until ELOOP. Three sibling loops made a scan of a
      one-file repository run for minutes at full CPU with memory climbing.

    Refusing every symlinked directory is the right call rather than merely
    deduplicating them: an in-repo alias is reached by its canonical path anyway, so
    following it only duplicates work, and an out-of-repo target is precisely what
    must not be read. Callers that need the target's contents should have it
    committed to the repository.

    This lived in ``parsers/zig/repository_scanner.py`` and nowhere else — its own
    comment noted it was deviating from "the other four language scanners", so the
    divergence was known and simply never propagated. Shared here so a sixth parser
    inherits it instead of re-deriving it.

    Note this keys on the *directory* only. A file-inode guard would silently drop
    legitimately hardlinked source, trading one false-negative primitive for another.

    **Policy: follow a symlink only if it resolves inside the repository or its
    immediate parent; refuse anything further out.**

    This is a deliberate compromise between two real and opposing requirements,
    and it is worth stating why neither extreme was chosen.

    Refusing every symlink loses code: ``parsers/zig`` carries a regression test
    whose fixture is a ``.zig`` file reachable only through a symlinked directory,
    written because such files were once silently dropped. For a SAST tool a
    false negative is the worse failure direction, so blanket refusal is not free.

    Following every symlink leaks the host: the security audit demonstrated a repo
    containing ``escape -> /tmp/outside`` putting a file from outside the tree into
    ``dataset.json``, which is then sent to the model provider. In an untrusted
    repository "vendored dependency" and ``vendor -> /`` are indistinguishable.

    Allowing the parent admits the common monorepo case — a package symlinking a
    sibling directory — while still refusing arbitrary absolute paths.

    **Accepted residual risk:** anything under the parent directory is reachable.
    Scanning a repo checked out directly into a directory that also holds unrelated
    sensitive material will ingest it. Clone into a dedicated parent.

    Args:
        dir_path: The directory entry being considered.
        repo_real: ``realpath`` of the repository root.
        seen: Optional ``(st_dev, st_ino)`` set, mutated here, bounding cycles.
            Without it an internal ``loop -> ..`` alias would recurse forever.

    Returns:
        True if the walker may descend.
    """
    full = os.fspath(dir_path)
    if not os.path.islink(full):
        return True

    real = os.path.realpath(full)

    def _under(root: str) -> bool:
        return bool(root) and (real == root or real.startswith(root + os.sep))

    # 1. Resolves back inside the repository: an internal alias. SKIP it — the
    #    real directory is walked by its canonical path anyway, so descending the
    #    alias emits every file a second time under the alias path (and `loop ->
    #    ..` recurses). Skipping loses nothing and keeps output canonical.
    if _under(repo_real):
        return False

    # 2. Resolves within the repository's parent: the sibling-vendoring case a
    #    monorepo package needs. FOLLOW, bounded by inode so a cycle terminates.
    if _under(os.path.dirname(repo_real)):
        if seen is None:
            return True
        try:
            info = os.stat(full)
        except OSError:
            return False
        key = (info.st_dev, info.st_ino)
        if key in seen:
            return False
        seen.add(key)
        return True

    # 3. Anything further out. REFUSE — this is the exfiltration path.
    return False


def read_repo_file(path: PathLike, max_bytes: int = 1024 * 1024) -> str | None:
    """Read a file authored by the *scanned* repository, or refuse to.

    Every path under a scanned repository is attacker-controlled: OpenAnt's whole
    job is analysing code it does not trust. A plain ``open()`` on such a path hands
    the repository three primitives:

    * a **symlink** to a host file, which lands outside the repo in ``dataset.json``
      and is then shipped to the model provider;
    * a **FIFO or device**, which blocks the scan forever on ``open()`` — no
      timeout, no error, just a wedged run;
    * an **unbounded file**, read fully into memory before any caller-side cap.

    This existed correctly in exactly one place (``load_threat_model``) while three
    sibling loaders opened repo-authored paths bare — the same "fixed it at the one
    site the report named" pattern that recurs throughout this codebase. Centralising
    it means the next loader gets the guard by construction rather than by review.

    Order matters: ``lstat`` before ``open``, because both ``exists()`` and
    ``open()`` follow symlinks, and a check that follows the link is not a check.

    Returns:
        File contents, or ``None`` if the path does not exist.

    Raises:
        UnsafeRepoFile: If the path is a symlink, is not a regular file, or exceeds
            ``max_bytes``. Refusing loudly is the point — a silent skip would let a
            repository hide a file from analysis just by making it weird.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None

    name = os.path.basename(os.fspath(path))
    if stat.S_ISLNK(info.st_mode):
        raise UnsafeRepoFile(
            f"{name} is a symlink; refusing to follow it out of the scanned repository"
        )
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeRepoFile(
            f"{name} is not a regular file (mode {info.st_mode:o}); a FIFO or device "
            "would block the scan indefinitely"
        )
    if info.st_size > max_bytes:
        raise UnsafeRepoFile(
            f"{name} is too large ({info.st_size} bytes > {max_bytes}); refusing to read"
        )

    with open_utf8(path) as handle:
        return handle.read(max_bytes + 1)[:max_bytes]


def open_utf8(path: PathLike, mode: str = "r", **kwargs):
    """Open a file with UTF-8 encoding by default.

    Drop-in replacement for ``open()`` that sets ``encoding='utf-8'`` unless
    the caller explicitly provides a different encoding or opens in binary
    mode.
    """
    if "b" not in mode and "encoding" not in kwargs:
        kwargs["encoding"] = "utf-8"
    return open(path, mode, **kwargs)


def read_json(path: PathLike) -> Any:
    """Read and parse a JSON file using UTF-8 encoding."""
    with open_utf8(path, "r") as f:
        return json.load(f)


def normalize_results(obj: Any, key: str = "results") -> Any:
    """Normalize a model-produced results container at the trust boundary.

    OpenAnt reads JSON emitted by an LLM (experiment_results.json,
    dynamic_test_results.json). A non-Anthropic model can emit a NON-DICT
    element (bare string/number/None/list) inside the ``results`` array, or a
    non-list value for ``results`` itself. Downstream code iterates that array
    doing ``r.get(...)`` in ~20 places; a non-dict element raises
    ``AttributeError`` and aborts verify/report/CSV.

    Rather than guard every per-loop read (which was tried in fa15/fa16 and
    missed the upstream verifier and dynamic paths — per-loop guards do not
    converge), normalize ONCE at each load boundary: mutate ``obj[key]`` in
    place so it is always a list containing only dicts. Every downstream
    iterator AND count (e.g. ``len(obj["results"])``) then sees the same
    filtered list. fa15/fa16 per-loop guards become harmless defense-in-depth.

    Mutates ``obj`` in place and also returns it for convenience.
    """
    raw = obj.get(key, []) if isinstance(obj, dict) else []
    if isinstance(obj, dict):
        if isinstance(raw, list):
            kept = [r for r in raw if isinstance(r, dict)]
            dropped = len(raw) - len(kept)
        else:
            kept = []
            dropped = 0 if raw in (None, [], {}, "") else 1
        obj[key] = kept
        if dropped:
            # QUARANTINE-NOT-DROP (recall safety — a SAST tool must never silently
            # lose a finding): a dropped non-dict element could be a half-emitted
            # sink. Surface the count on the object AND log fail-LOUD so malformed
            # model output is visible, never a silent false-negative.
            obj[f"_{key}_invalid_dropped"] = obj.get(f"_{key}_invalid_dropped", 0) + dropped
            logging.getLogger("openant.normalize").warning(
                "normalize_results: dropped %d non-dict element(s) from %r — "
                "malformed model output (surfaced as _%s_invalid_dropped)",
                dropped, key, key,
            )
    return obj


def write_json(path: PathLike, data: Any, **kwargs) -> None:
    """Write data as JSON to a file using UTF-8 encoding, atomically.

    Serialize to a temp file in the same directory, fsync, then ``os.replace`` onto the
    target. An interrupted write (SIGKILL / OOM / power loss) leaves the temp file behind
    but never truncates or clobbers the existing target — the prior good copy survives.
    """
    kwargs.setdefault("indent", 2)
    target = os.fspath(path)
    directory = os.path.dirname(target) or "."
    # `.tmp` suffix (not `.json`): a leftover from a hard crash (where the except-cleanup
    # below never runs) must not match directory scanners that do `endswith(".json")`
    # (e.g. core/checkpoint.py's os.listdir loops, which also see dotfiles).
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, **kwargs)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def run_utf8(*args, **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess with UTF-8 encoding for text mode.

    Wrapper around ``subprocess.run`` that sets ``encoding='utf-8'`` and
    ``errors='replace'`` when ``text=True`` (or its alias
    ``universal_newlines=True``) is passed, preventing charmap decode errors
    on Windows.

    Note: ``errors='replace'`` substitutes U+FFFD for invalid bytes in
    stdout/stderr rather than raising. This is intentional - subprocess
    output is used for status display and diagnostics, not for security
    analysis (parser results are read from JSON files separately).
    Callers can override with ``errors='strict'`` if needed.
    """
    if kwargs.get("text") or kwargs.get("universal_newlines"):
        kwargs.setdefault("encoding", "utf-8")
        kwargs.setdefault("errors", "replace")
    return subprocess.run(*args, **kwargs)
