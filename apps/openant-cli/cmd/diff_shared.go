package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/knostic/open-ant-cli/internal/git"
	"github.com/knostic/open-ant-cli/internal/output"
)

// diffOpts collects the diff-mode flags that scan/parse/diff all share.
type diffOpts struct {
	base     string
	pr       int
	prNumber int // #668: stamp-only (already-resolved PR; excluded from validate()/isSet())
	staged   bool
	scope    string
}

// isSet reports whether any diff flag was provided.
func (o diffOpts) isSet() bool {
	return o.base != "" || o.pr > 0 || o.staged
}

// validate enforces flag rules common to all entry points.
func (o diffOpts) validate() error {
	set := 0
	if o.base != "" {
		set++
	}
	if o.pr > 0 {
		set++
	}
	if o.staged {
		set++
	}
	if set > 1 {
		return fmt.Errorf("--diff-base, --pr, and --staged are mutually exclusive")
	}
	if o.isSet() {
		if o.scope == "" {
			return fmt.Errorf("--diff-scope must not be empty in diff mode")
		}
		if !git.IsValidScope(o.scope) {
			return fmt.Errorf("invalid --diff-scope %q (expected changed_files|changed_functions|callers)", o.scope)
		}
	}
	return nil
}

// prWorkspace is the per-run --pr isolation state (#665 cycle 2): the
// worktree holding the PR head and the unique ref it was fetched into.
// The zero value means "not a --pr run this call". The caller hands it to
// git.CleanupPRWorktree at its exit arms; on an error return from
// prepareDiffManifest the cleanup has already run.
type prWorkspace struct {
	Worktree string
	Ref      string
}

// prepareDiffManifest resolves the base ref (via --pr or --diff-base),
// builds the manifest, and writes it under outputDir. Returns the manifest
// path and the --pr workspace (zero when not a --pr fetch), or "" and the
// zero workspace if not in diff mode.
//
// outputDir must already exist (the caller should mkdir it). repoPath is
// the absolute path to the working copy the diff is computed against.
//
// For --pr, the PR head materializes in an ISOLATED temporary worktree —
// the user's checkout is never touched (#665 arms 2+3: no persistent
// mutation, and concurrent runs each read their own tree). The manifest is
// built against that worktree, whose HEAD is the PR head, so the
// manifest's head_sha is the PR the run was invoked with even when a
// sibling run fetches concurrently.
func prepareDiffManifest(repoPath, outputDir string, opts diffOpts) (string, prWorkspace, error) {
	if !opts.isSet() {
		return "", prWorkspace{}, nil
	}
	if err := opts.validate(); err != nil {
		return "", prWorkspace{}, err
	}
	if outputDir == "" {
		return "", prWorkspace{}, fmt.Errorf("diff mode requires an output directory (use --output or `openant init` to set up a project)")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", prWorkspace{}, fmt.Errorf("create output dir %s: %w", outputDir, err)
	}

	var prwt prWorkspace
	var m *git.Manifest
	if opts.staged {
		built, err := git.BuildStagedManifest(repoPath, opts.scope)
		if err != nil {
			return "", prWorkspace{}, fmt.Errorf("build staged diff manifest: %w", err)
		}
		m = built
	} else {
		baseRef := opts.base
		manifestRepo := repoPath
		if opts.pr > 0 {
			fetched, wt, ref, err := git.FetchPR(repoPath, opts.pr, nil)
			if err != nil {
				return "", prWorkspace{}, err
			}
			baseRef = fetched
			manifestRepo = wt
			prwt = prWorkspace{Worktree: wt, Ref: ref}
			if !quiet {
				fmt.Fprintf(os.Stderr, "PR #%d: base=%s (fetched into a unique ref, materialized in an isolated worktree)\n", opts.pr, baseRef)
			}
		}
		stampPR := opts.pr
		if stampPR == 0 {
			stampPR = opts.prNumber // #668: the resolved PR (from modeDecision.PR), not a fetch request
		}
		built, err := git.BuildManifest(manifestRepo, baseRef, opts.scope, stampPR)
		if err != nil {
			// the workspace this call created is cleaned HERE — the
			// error return carries no cleanup debt to the caller
			git.CleanupPRWorktree(repoPath, prwt.Worktree, prwt.Ref)
			return "", prWorkspace{}, fmt.Errorf("build diff manifest: %w", err)
		}
		m = built
	}

	manifestPath := filepath.Join(outputDir, "diff_manifest.json")
	if err := git.WriteManifest(manifestPath, m); err != nil {
		git.CleanupPRWorktree(repoPath, prwt.Worktree, prwt.Ref)
		return "", prWorkspace{}, err
	}

	if !quiet {
		if m.BaseRef == git.StagedRef {
			output.PrintKeyValue("Diff base", fmt.Sprintf("HEAD (%s)", shortSHA(m.BaseSHA)))
			output.PrintKeyValue("Diff head", "index (staged)")
		} else {
			output.PrintKeyValue("Diff base", fmt.Sprintf("%s (%s)", m.BaseRef, shortSHA(m.BaseSHA)))
			output.PrintKeyValue("Diff head", shortSHA(m.HeadSHA))
		}
		output.PrintKeyValue("Diff scope", m.Scope)
		output.PrintKeyValue("Changed files", fmt.Sprintf("%d", len(m.ChangedFiles)))
	}

	return manifestPath, prwt, nil
}

func shortSHA(sha string) string {
	if len(sha) >= 7 {
		return sha[:7]
	}
	return sha
}
