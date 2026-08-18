package git

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
// pull/N/head into a local branch, checks it out, and fetches the base ref
// so it's available locally for diffing. Returns the fully qualified base
// ref (e.g. "origin/main").
func FetchPR(repoPath string, prNumber int, stderr *bytes.Buffer) (string, error) {
	viewCmd := exec.Command("gh", "pr", "view", strconv.Itoa(prNumber), "--json", "baseRefName")
	viewCmd.Dir = repoPath
	var viewErr bytes.Buffer
	viewCmd.Stderr = &viewErr
	viewOut, err := viewCmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh pr view %d: %w (is gh installed and authenticated? %s)",
			prNumber, err, strings.TrimSpace(viewErr.String()))
	}
	var meta struct {
		BaseRefName string `json:"baseRefName"`
	}
	if err := json.Unmarshal(viewOut, &meta); err != nil {
		return "", fmt.Errorf("parse gh pr view output: %w", err)
	}
	if meta.BaseRefName == "" {
		return "", fmt.Errorf("gh pr view returned empty baseRefName for PR %d", prNumber)
	}

	prSpec := fmt.Sprintf("pull/%d/head:pr-head", prNumber)
	if err := runGit(repoPath, stderr, "fetch", "origin", prSpec, "--force"); err != nil {
		return "", fmt.Errorf("git fetch %s: %w", prSpec, err)
	}
	if err := runGit(repoPath, stderr, "checkout", "pr-head"); err != nil {
		return "", fmt.Errorf("git checkout pr-head: %w", err)
	}
	// Best-effort fetch of the base ref. If it's already local this is a no-op.
	_ = runGit(repoPath, stderr, "fetch", "origin", meta.BaseRefName)

	return "origin/" + meta.BaseRefName, nil
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
