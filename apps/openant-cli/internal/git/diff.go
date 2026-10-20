package git

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/knostic/open-ant-cli/internal/remoteurl"
)

// ResolveBase resolves baseRef and HEAD to full SHAs within repoPath.
func ResolveBase(repoPath, baseRef string) (baseSHA, headSHA string, err error) {
	baseSHA, err = gitRevParse(repoPath, baseRef)
	if err != nil {
		return "", "", fmt.Errorf("resolve base %q: %w", baseRef, err)
	}
	headSHA, err = gitRevParse(repoPath, "HEAD")
	if err != nil {
		return "", "", fmt.Errorf("resolve HEAD: %w", err)
	}
	return baseSHA, headSHA, nil
}

func gitRevParse(repoPath, ref string) (string, error) {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", ref)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse %s: %w: %s", ref, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// NormalizeRemote re-exports remoteurl.Normalize (the canonical home as of
// #568 — the render packages need the normalization without this package's
// exec dependencies).
func NormalizeRemote(raw string) string {
	return remoteurl.Normalize(raw)
}

// RemoteURL returns the origin remote's URL for the repo at repoPath, or ""
// when there is no origin remote (a local-only repo, a non-git path). The
// RAW string is returned — normalization is the caller's separate pure step
// (the #562 split: detection is a subprocess fact; normalization is policy).
func RemoteURL(repoPath string) string {
	out, err := exec.Command("git", "-C", repoPath, "remote", "get-url",
		"origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// HeadSHA returns the working-tree HEAD commit of the repo at repoPath, or
// "" when the path is not inside a git work tree (a bare-path scan of a
// non-repo directory is legal; the caller treats "" as "not detected").
// It deliberately reads HEAD rather than any requested ref — #557's
// metadata tier mirrors the incremental manifest's head_sha semantics
// (the tree that will actually be scanned), never a checkout intent.
func HeadSHA(repoPath string) string {
	// An unborn repo (a fresh `git init`) errors here (rev-parse HEAD:
	// ambiguous argument) — the empty return covers it; no zero-id is
	// ever emitted, so no zero-guard is needed (the review round's catch:
	// the earlier zero-id comment was a false claim about git).
	out, err := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// CurrentBranch returns the name of the branch HEAD points at, or "" if
// HEAD is detached. Callers treat the empty result as "no branch info" —
// it is informational metadata, not load-bearing.
func CurrentBranch(repoPath string) string {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--abbrev-ref", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	branch := strings.TrimSpace(string(out))
	if branch == "HEAD" {
		return ""
	}
	return branch
}

// FetchPR resolves a GitHub PR number to its base ref via `gh`, fetches
// pull/N/head into a unique non-branch ref, materializes the PR head in an
// ISOLATED temporary worktree, and fetches the base ref so it's available
// locally for diffing. The user's checkout is never touched (#665: no
// persistent mutation of the scanned clone, and concurrent --pr runs never
// share a tree — each run reads its own worktree). Returns the fully
// qualified base ref (e.g. "origin/main"), the worktree path, and the
// unique ref; the caller MUST pass the worktree+ref to CleanupPRWorktree
// when its run ends. On error nothing is left behind (the fetched ref and
// the scratch dir are cleaned before returning).
func FetchPR(repoPath string, prNumber int, stderr *bytes.Buffer) (string, string, string, error) {
	viewCmd := exec.Command("gh", "pr", "view", strconv.Itoa(prNumber), "--json", "baseRefName")
	viewCmd.Dir = repoPath
	var viewErr bytes.Buffer
	viewCmd.Stderr = &viewErr
	viewOut, err := viewCmd.Output()
	if err != nil {
		return "", "", "", fmt.Errorf("gh pr view %d: %w (is gh installed and authenticated? %s)",
			prNumber, err, strings.TrimSpace(viewErr.String()))
	}
	var meta struct {
		BaseRefName string `json:"baseRefName"`
	}
	if err := json.Unmarshal(viewOut, &meta); err != nil {
		return "", "", "", fmt.Errorf("parse gh pr view output: %w", err)
	}
	if meta.BaseRefName == "" {
		return "", "", "", fmt.Errorf("gh pr view returned empty baseRefName for PR %d", prNumber)
	}

	// #665 cycle 2: crash residue self-heal — sweep the worktrees and
	// unique refs a CRASHED run left behind BEFORE this run adds its own
	// (the cycle-1 residue: one leaked ref per --pr invocation). Scoped
	// to openant's own workspaces; a sibling run's in-flight workspace
	// (its pid is alive) is never swept.
	pruneStalePRState(repoPath, stderr)

	// #665 arms 2+3: the PR head fetches into a UNIQUE non-branch ref
	// (not a fixed "pr-head" branch that every invocation shares) and
	// materializes in an ISOLATED per-run worktree — the user's checkout
	// is never touched, and two concurrent --pr runs never share a tree
	// (the manifest builder and the engine each read their OWN worktree,
	// so the second run can no longer re-point the first run's HEAD).
	// NO defer inside FetchPR: the caller and the Python engine read the
	// worktree AFTER FetchPR returns; the cleanup belongs to the run's
	// exit arms (CleanupPRWorktree).
	prRef := fmt.Sprintf("refs/openant/pr/%d/%d", prNumber, os.Getpid())
	prSpec := fmt.Sprintf("pull/%d/head:%s", prNumber, prRef)
	// the scratch name carries the pid so the crash sweep can tie a
	// worktree to its (possibly dead) owner WITHOUT a SHA join — a live
	// sibling checked out at the SAME commit must never be swept
	scratch, err := os.MkdirTemp("", fmt.Sprintf("openant-pr-%d-", os.Getpid()))
	if err != nil {
		return "", "", "", fmt.Errorf("create PR worktree dir: %w", err)
	}
	if err := runGit(repoPath, stderr, "fetch", "origin", prSpec, "--force"); err != nil {
		_ = os.RemoveAll(scratch)
		return "", "", "", fmt.Errorf("git fetch %s: %w", prSpec, err)
	}
	if err := runGit(repoPath, stderr, "worktree", "add", "--detach", "--", scratch, prRef); err != nil {
		_ = runGit(repoPath, nil, "update-ref", "-d", prRef)
		_ = os.RemoveAll(scratch)
		return "", "", "", fmt.Errorf("git worktree add %s: %w", prRef, err)
	}
	// Best-effort fetch of the base ref. If it's already local this is a no-op.
	_ = runGit(repoPath, stderr, "fetch", "origin", meta.BaseRefName)

	// #665 cycle 2 (content parity): populate the scratch's submodules to
	// EXACTLY the user's populated set, by explicit pathspec (never a
	// config-writing blanket init — see initSubmodules), bounded and
	// best-effort.
	initSubmodules(repoPath, scratch, stderr)

	return "origin/" + meta.BaseRefName, scratch, prRef, nil
}

// initSubmodules populates the scratch worktree's submodules to exactly
// the user's POPULATED set, without writing the user's repository.
// Parity: the pre-isolation in-place scan read the user's working tree —
// a submodule's content was scanned iff the user's clone had it
// POPULATED (a recursive clone: all; a fresh clone: none; a `git
// submodule deinit`: none). The config-key shapes differ by how the user
// got there (`submodule add` writes per-name .active; a
// --recurse-submodules clone writes the submodule.active pathspec and
// per-name .url ONLY — the fable re-round's F7: a config-key
// derivation is dead for that shape), so the oracle is
// config-independent: a submodule path from the PR's .gitmodules is
// inited iff the user's clone has CONTENT at that path (a .git entry
// under it). The explicit pathspec form never writes the shared
// .git/config for PR-added submodules (the fable-F1 invariant), and a
// PR-REMOVED submodule can never appear (its path is absent from the
// PR's .gitmodules). Each path inits best-effort on its own (a weird
// path starves only itself), bounded at 120 s each.
func initSubmodules(repoPath, scratch string, stderr *bytes.Buffer) {
	// the PR's name->path map (the scratch's .gitmodules), NUL-separated:
	// the key may contain spaces (a submodule named "my libs/one"), and
	// the format is `<key>\n<value>` per NUL-terminated entry
	gmOut, err := exec.Command("git", "-C", scratch, "config", "--null", "-f",
		".gitmodules", "--get-regexp", `^submodule\..*\.path$`).Output()
	if err != nil {
		return // the PR tree carries no .gitmodules — nothing to do
	}
	var paths []string
	for _, kv := range issueConfigPairs(gmOut) {
		rest, ok := strings.CutPrefix(kv[0], "submodule.")
		if !ok || kv[1] == "" {
			continue
		}
		name, ok := strings.CutSuffix(rest, ".path")
		if !ok {
			continue
		}
		// the deliberate user opt-out is the ONE config key that gates
		// (the fable-F10 catch): a hand-set submodule.<name>.active=false
		// with content present would otherwise be inited by the scratch,
		// and `submodule update --init` internally flips the USER's
		// shared config false→true — the exact mutation class this fix
		// exists to remove. A `deinit`ed submodule has no content, so the
		// oracle below already skips it; only the flag needs reading.
		if issueSubmoduleOptedOut(repoPath, name) {
			continue
		}
		// the parity oracle (config-independent, two halves): the user's
		// clone has CONTENT at this path (a populated submodule dir), AND
		// the path is a GITLINK in the USER's HEAD tree — authoring
		// residue (a submodule the user added for a PR they do not have
		// checked out) has content on disk but no gitlink at their HEAD,
		// and the in-place scan never read it either
		if !issueGitlinkAt(repoPath, kv[1]) {
			continue
		}
		if _, err := os.Stat(filepath.Join(repoPath, kv[1], ".git")); err == nil {
			paths = append(paths, kv[1])
		}
	}
	if len(paths) == 0 {
		return // nothing the user carries populated exists in the PR's tree
	}
	// per-path best-effort init
	for _, path := range paths {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		cmd := exec.CommandContext(ctx, "git", "-C", scratch, "submodule",
			"update", "--init", "--recursive", "--", path)
		if stderr != nil {
			cmd.Stderr = stderr
		}
		_ = cmd.Run() // best-effort: an offline run scans without submodules
		cancel()
	}
}

// issueSubmoduleOptedOut reports whether the user has EXPLICITLY
// deactivated the named submodule (submodule.<name>.active=false) — the
// deliberate opt-out that must survive a --pr run untouched.
func issueSubmoduleOptedOut(repoPath, name string) bool {
	out, err := exec.Command("git", "-C", repoPath, "config", "--bool",
		"submodule."+name+".active").Output()
	if err != nil {
		return false // the key is absent — no opt-out
	}
	return strings.TrimSpace(string(out)) == "false"
}

// issueGitlinkAt reports whether path is a submodule gitlink (mode
// 160000) in the HEAD tree of the repo at repoPath.
func issueGitlinkAt(repoPath, path string) bool {
	out, err := exec.Command("git", "-C", repoPath, "ls-tree", "HEAD", "--", path).Output()
	if err != nil {
		return false
	}
	fields := strings.Fields(string(out))
	return len(fields) >= 1 && fields[0] == "160000"
}

// issueConfigPairs parses `git config --null --get-regexp` output. The
// format (verified against git 2.50): each ENTRY is `<key>\n<value>`,
// NUL-terminated — the key and value are separated by a NEWLINE, not a
// space, so a section name containing spaces (a submodule named
// "my libs/one") is unambiguous.
func issueConfigPairs(raw []byte) [][2]string {
	var pairs [][2]string
	for _, entry := range strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00") {
		key, value, ok := strings.Cut(entry, "\n")
		if ok {
			pairs = append(pairs, [2]string{key, value})
		}
	}
	return pairs
}

// CleanupPRWorktree removes the per-run PR worktree and its unique ref
// (#665 residue: refs are deleted by the run that created them — a crash
// between fetch and cleanup leaves both for the NEXT run's
// pruneStalePRState sweep). Best-effort by design: a cleanup failure must
// never mask the run's own result. A no-op on empty inputs, so callers
// can call it unconditionally.
func CleanupPRWorktree(repoPath, worktreePath, prRef string) {
	if worktreePath == "" && prRef == "" {
		return
	}
	if worktreePath != "" {
		_ = runGit(repoPath, nil, "worktree", "remove", "--force", worktreePath)
		// the belt-and-braces remove: `worktree remove` refuses nothing
		// twice-forced, but an admin-dir desync (a half-removed worktree)
		// must not leave the directory behind
		_ = os.RemoveAll(worktreePath)
	}
	if prRef != "" {
		_ = runGit(repoPath, nil, "update-ref", "-d", prRef)
	}
}

// pidAlive reports whether the process owning a --pr workspace still
// exists. The unique ref carries the creating process's pid, so this is
// the portable liveness check for "is this ref's owner still mid-flight?"
// (a sibling --pr run must NEVER have its ref swept). Deliberately
// conservative: any signal-probe answer other than a clean "dead"
// reads ALIVE — unix EPERM (alive, another user's process), windows'
// Signal(0) limitation (crash residue is kept on windows rather than a
// live sibling swept), any odd errno. "Dead" is exactly two answers:
// ESRCH (the kernel's no-such-process) and os.ErrProcessDone (Go's own
// marker for a reaped pid — a just-exited child answers ErrProcessDone,
// not ESRCH, so treating only ESRCH as dead misreads every recently
// crashed run as alive). Residue is recoverable; a swept sibling's
// workspace is not.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// NOTE: the signal error is named serr — a shadowed `if err :=` here
	// reads the OUTER FindProcess error (nil) in the return, making every
	// unix pid read ALIVE (the shadowing class the probe test caught).
	serr := p.Signal(syscall.Signal(0))
	if serr == nil {
		return true
	}
	return !errors.Is(serr, syscall.ESRCH) && !errors.Is(serr, os.ErrProcessDone)
}

func openantPRPID(path string) int {
	base := filepath.Base(path)
	rest, ok := strings.CutPrefix(base, "openant-pr-")
	if !ok {
		return 0
	}
	tail, _, _ := strings.Cut(rest, "-")
	pid, err := strconv.Atoi(tail)
	if err != nil {
		return 0
	}
	return pid
}

// pruneStalePRState sweeps the residue of crashed --pr runs, scoped to
// openant's OWN workspaces only (refs/openant/pr/* and the openant-pr-
// temp prefix): a foreign worktree or ref on the user's clone is never
// touched, and there is NO repo-global `git worktree prune` — that
// would de-register the user's unrelated worktrees on unmounted
// volumes. The join between a workspace and its owner is the PID,
// carried by BOTH the ref (refs/openant/pr/<N>/<pid>) and the scratch
// dir name (openant-pr-<pid>-<rand>) — never a SHA: a live sibling
// checked out at the SAME commit as a dead ref must not be swept, and
// a dead run's orphan worktree must be removable even when its ref is
// already gone. A workspace whose pid is ALIVE is a sibling mid-flight
// (or this run) and is never swept — which also closes the
// fetch-to-worktree window. A ref whose commit some FOREIGN worktree
// (the user's own checkout) sits at is kept even when its pid reads
// dead (pid reuse). Windows' Signal(0) limitation and any odd errno read
// conservative (alive): residue is recoverable, a swept sibling is not.
func pruneStalePRState(repoPath string, stderr *bytes.Buffer) {
	listOut, err := exec.Command("git", "-C", repoPath, "worktree", "list", "--porcelain").Output()
	if err != nil {
		return
	}

	// partition: our scratch worktrees (by name pid) vs the foreign
	// HEADs (the user's main checkout and unrelated worktrees)
	type openantWorktree struct {
		path string
		pid  int
	}
	var ours []openantWorktree
	foreignHeads := make(map[string]bool)
	for _, block := range strings.Split(string(listOut), "\n\n") {
		var path, sha string
		for _, line := range strings.Split(block, "\n") {
			if w, ok := strings.CutPrefix(line, "worktree "); ok {
				path = strings.TrimSpace(w)
			}
			if h, ok := strings.CutPrefix(line, "HEAD "); ok {
				sha = strings.TrimSpace(h)
			}
		}
		if path == "" {
			continue
		}
		if pid := openantPRPID(path); pid > 0 {
			ours = append(ours, openantWorktree{path, pid})
		} else if sha != "" {
			foreignHeads[sha] = true
		}
	}

	// our dead refs (pid-shaped tail, dead owner, no foreign worktree at
	// the commit); a live pid — sibling mid-flight or this run — is kept
	var deadRefs []string
	refOut, err := exec.Command("git", "-C", repoPath, "for-each-ref",
		"--format=%(refname) %(objectname)", "refs/openant/pr/").Output()
	if err == nil {
		for _, line := range strings.Split(string(refOut), "\n") {
			parts := strings.Fields(line)
			if len(parts) != 2 {
				continue
			}
			tail := parts[0][strings.LastIndex(parts[0], "/")+1:]
			pid, err := strconv.Atoi(tail)
			if err != nil {
				continue // not our pid-shaped ref — foreign, keep
			}
			if pidAlive(pid) || foreignHeads[parts[1]] {
				continue
			}
			deadRefs = append(deadRefs, parts[0])
		}
	}

	// our dead worktrees: named by a dead pid, EVEN when no ref drives
	// them (FetchPR's error arm, an older naming, a reaped-dir admin
	// entry — `worktree remove --force` handles the missing dir too)
	for _, w := range ours {
		if pidAlive(w.pid) {
			continue
		}
		_ = runGit(repoPath, nil, "worktree", "remove", "--force", w.path)
	}
	for _, ref := range deadRefs {
		_ = runGit(repoPath, stderr, "update-ref", "-d", ref)
	}
}

func runGit(repoPath string, stderr *bytes.Buffer, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", repoPath}, args...)...)
	var localErr bytes.Buffer
	if stderr != nil {
		cmd.Stderr = stderr
	} else {
		cmd.Stderr = &localErr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(localErr.String()))
	}
	return nil
}

// StagedRef is the synthetic base ref written into the manifest for staged
// scans. The on-disk SHA fields hold HEAD (the staged-against commit) and a
// zero placeholder for "head" since the index has no SHA.
const StagedRef = "STAGED"

// stagedHeadSHA is the placeholder HeadSHA written for staged manifests.
// We can't resolve the index to a SHA without writing a tree, and downstream
// consumers only read it as a string identifier.
const stagedHeadSHA = "0000000000000000000000000000000000000000"

// ChangedFiles returns the files changed between baseSHA and HEAD using the
// symmetric diff BASE...HEAD. Rename detection is enabled; the new-side path
// is returned for renamed files.
func ChangedFiles(repoPath, baseSHA string) ([]string, error) {
	// -z: NUL-terminate each path and emit it verbatim. Unlike the default
	// line output, -z is NEVER core.quotepath-escaped and NEVER ambiguous —
	// it does not octal-escape/double-quote non-ASCII names (e.g. café.py)
	// nor escape special characters (embedded newlines, quotes, backslashes,
	// tabs). A line scanner would split an embedded-newline path into two or
	// hand back a quoted string that never matches the real file, silently
	// dropping such changes from the diff scope. Splitting on NUL is exact.
	cmd := exec.Command("git", "-C", repoPath, "diff",
		baseSHA+"...HEAD", "--name-only", "-z", "--find-renames")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only -z: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var files []string
	for _, path := range strings.Split(string(out), "\x00") {
		if path != "" {
			files = append(files, path)
		}
	}
	sort.Strings(files)
	return files, nil
}

// StagedChangedFiles returns the files with staged (index) changes against
// HEAD. Rename detection is enabled; the new-side path is returned for
// renamed files. Untracked files are not included — `git add` them first
// to bring them into the index.
func StagedChangedFiles(repoPath string) ([]string, error) {
	// -z for the same reason as ChangedFiles: staged paths with non-ASCII
	// names, spaces, or embedded newlines are core.quotepath-escaped in the
	// default output and would be dropped from the scan (a false negative,
	// which matters most in a SAST tool). NUL-separated output is exact.
	cmd := exec.Command("git", "-C", repoPath, "diff",
		"--cached", "--name-only", "-z", "--find-renames")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --cached --name-only -z: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var files []string
	for _, path := range strings.Split(string(out), "\x00") {
		if path != "" {
			files = append(files, path)
		}
	}
	sort.Strings(files)
	return files, nil
}

// StagedHunksForFile returns the new-side [start, end] line ranges for
// staged changes to a single file. Pure-deletion hunks (count=0 on the new
// side) are skipped.
func StagedHunksForFile(repoPath, file string) ([][2]int, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff",
		"--cached", "--unified=0", "--", file)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --cached --unified=0 -- %s: %w: %s", file, err, strings.TrimSpace(stderr.String()))
	}
	var ranges [][2]int
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		m := hunkHeaderRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		start, _ := strconv.Atoi(m[1])
		count := 1
		if m[2] != "" {
			count, _ = strconv.Atoi(m[2])
		}
		if count == 0 {
			continue
		}
		ranges = append(ranges, [2]int{start, start + count - 1})
	}
	return ranges, nil
}

// hunkHeaderRe captures the new-side start and count from a unified-diff
// hunk header. `@@ -a[,b] +c[,d] @@` — capture group 1 is c, group 2 is d.
// Count defaults to 1 when omitted.
var hunkHeaderRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// HunksForFile returns the new-side [start, end] line ranges for changes to
// a single file. Pure-deletion hunks (count=0 on the new side) are skipped.
func HunksForFile(repoPath, baseSHA, file string) ([][2]int, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff",
		baseSHA+"...HEAD", "--unified=0", "--", file)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --unified=0 -- %s: %w: %s", file, err, strings.TrimSpace(stderr.String()))
	}
	var ranges [][2]int
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		m := hunkHeaderRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		start, _ := strconv.Atoi(m[1])
		count := 1
		if m[2] != "" {
			count, _ = strconv.Atoi(m[2])
		}
		if count == 0 {
			// Pure deletion on the new side — nothing to select.
			continue
		}
		ranges = append(ranges, [2]int{start, start + count - 1})
	}
	return ranges, nil
}

// BuildManifest assembles a Manifest by shelling git commands against
// repoPath. scope must be a valid scope (see IsValidScope). For
// ScopeChangedFiles, the Hunks map is left nil.
func BuildManifest(repoPath, baseRef, scope string, prNumber int) (*Manifest, error) {
	if !IsValidScope(scope) {
		return nil, fmt.Errorf("invalid scope %q", scope)
	}
	baseSHA, headSHA, err := ResolveBase(repoPath, baseRef)
	if err != nil {
		return nil, err
	}
	files, err := ChangedFiles(repoPath, baseSHA)
	if err != nil {
		return nil, err
	}
	m := &Manifest{
		BaseRef:      baseRef,
		BaseSHA:      baseSHA,
		HeadSHA:      headSHA,
		Scope:        scope,
		PRNumber:     prNumber,
		ChangedFiles: files,
	}
	if scope == ScopeChangedFiles {
		return m, nil
	}
	hunks := make(map[string][][2]int, len(files))
	for _, f := range files {
		r, err := HunksForFile(repoPath, baseSHA, f)
		if err != nil {
			return nil, err
		}
		if len(r) > 0 {
			hunks[f] = r
		}
	}
	m.Hunks = hunks
	return m, nil
}

// BuildStagedManifest assembles a Manifest from the staged (index) diff
// against HEAD. Used by `openant scan --staged` and `openant diff --staged`
// for pre-commit hook style scanning. scope must be a valid scope. The
// BaseRef is set to StagedRef, BaseSHA is HEAD, HeadSHA is a zero placeholder
// since the index has no SHA.
func BuildStagedManifest(repoPath, scope string) (*Manifest, error) {
	if !IsValidScope(scope) {
		return nil, fmt.Errorf("invalid scope %q", scope)
	}
	headSHA, err := gitRevParse(repoPath, "HEAD")
	if err != nil {
		return nil, fmt.Errorf("resolve HEAD: %w", err)
	}
	files, err := StagedChangedFiles(repoPath)
	if err != nil {
		return nil, err
	}
	m := &Manifest{
		BaseRef:      StagedRef,
		BaseSHA:      headSHA,
		HeadSHA:      stagedHeadSHA,
		Scope:        scope,
		ChangedFiles: files,
	}
	if scope == ScopeChangedFiles {
		return m, nil
	}
	hunks := make(map[string][][2]int, len(files))
	for _, f := range files {
		r, err := StagedHunksForFile(repoPath, f)
		if err != nil {
			return nil, err
		}
		if len(r) > 0 {
			hunks[f] = r
		}
	}
	m.Hunks = hunks
	return m, nil
}
