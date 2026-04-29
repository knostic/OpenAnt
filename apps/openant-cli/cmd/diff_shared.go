package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/knostic/open-ant-cli/internal/git"
	"github.com/knostic/open-ant-cli/internal/output"
)

// diffOpts collects the three diff-mode flags that scan/parse/diff all share.
type diffOpts struct {
	base   string
	pr     int
	scope  string
}

// isSet reports whether any diff flag was provided.
func (o diffOpts) isSet() bool {
	return o.base != "" || o.pr > 0
}

// validate enforces flag rules common to all entry points.
func (o diffOpts) validate() error {
	if o.base != "" && o.pr > 0 {
		return fmt.Errorf("--diff-base and --pr are mutually exclusive")
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

// prepareDiffManifest resolves the base ref (via --pr or --diff-base),
// builds the manifest, and writes it under outputDir. Returns the manifest
// path, or "" if not in diff mode.
//
// outputDir must already exist (the caller should mkdir it). repoPath is
// the absolute path to the working copy the diff is computed against.
//
// For --pr, the working tree is mutated (checkout of pr-head). Callers that
// care about HEAD stability must be aware.
func prepareDiffManifest(repoPath, outputDir string, opts diffOpts) (string, error) {
	if !opts.isSet() {
		return "", nil
	}
	if err := opts.validate(); err != nil {
		return "", err
	}
	if outputDir == "" {
		return "", fmt.Errorf("diff mode requires an output directory (use --output or `openant init` to set up a project)")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create output dir %s: %w", outputDir, err)
	}

	baseRef := opts.base
	if opts.pr > 0 {
		fetched, err := git.FetchPR(repoPath, opts.pr, nil)
		if err != nil {
			return "", err
		}
		baseRef = fetched
		if !quiet {
			fmt.Fprintf(os.Stderr, "PR #%d: base=%s (fetched and checked out pr-head)\n", opts.pr, baseRef)
		}
	}

	m, err := git.BuildManifest(repoPath, baseRef, opts.scope, opts.pr)
	if err != nil {
		return "", fmt.Errorf("build diff manifest: %w", err)
	}

	manifestPath := filepath.Join(outputDir, "diff_manifest.json")
	if err := git.WriteManifest(manifestPath, m); err != nil {
		return "", err
	}

	if !quiet {
		output.PrintKeyValue("Diff base", fmt.Sprintf("%s (%s)", m.BaseRef, shortSHA(m.BaseSHA)))
		output.PrintKeyValue("Diff head", shortSHA(m.HeadSHA))
		output.PrintKeyValue("Diff scope", m.Scope)
		output.PrintKeyValue("Changed files", fmt.Sprintf("%d", len(m.ChangedFiles)))
	}

	return manifestPath, nil
}

func shortSHA(sha string) string {
	if len(sha) >= 7 {
		return sha[:7]
	}
	return sha
}
