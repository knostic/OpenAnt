package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
	"github.com/knostic/open-ant-cli/internal/languages"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init <repo-url-or-path>",
	Short: "Initialize a project workspace",
	Long: `Init sets up a project workspace for a repository.

For remote URLs, the repo is cloned into ~/.openant/projects/{org}/{repo}/repo/.
For local paths, the existing directory is referenced in place (no cloning).

After init, all commands (parse, scan, etc.) work without path arguments.

Examples:
  openant init https://github.com/grafana/grafana -l go
  openant init https://github.com/grafana/grafana -l go --commit 591ceb2eec0
  openant init https://github.com/grafana/grafana -l auto
  openant init ./repos/grafana -l go
  openant init ./repos/grafana -l go --name myorg/grafana`,
	Args: cobra.ExactArgs(1),
	Run:  runInit,
}

var (
	initLanguage    string
	initCommit      string
	initName        string
	initFull        bool
	initIncremental bool
	initDiffBase    string
	initPR          int
	initDiffScope   string
)

func init() {
	// Defaults to "auto" = scan every detected language. Previously this flag was
	// REQUIRED, which meant there was no default at all: every user had to name a
	// language, the help examples all show `-l go`, and the natural choice pinned
	// the project to one language forever. "All languages should be scanned, not
	// just the main one" cannot be true of a tool that makes you pick one up front.
	initCmd.Flags().StringVarP(&initLanguage, "language", "l", "auto", languages.FlagHelp())
	initCmd.Flags().StringVar(&initCommit, "commit", "", "Specific commit SHA (default: HEAD)")
	initCmd.Flags().StringVar(&initName, "name", "", "Override project name (default: derived from URL/path)")
	initCmd.Flags().BoolVar(&initFull, "full", false, "Force full scan (rejects --incremental/--diff-base/--pr)")
	initCmd.Flags().BoolVar(&initIncremental, "incremental", false, "Incremental against the last successful scan on this project")
	initCmd.Flags().StringVar(&initDiffBase, "diff-base", "", "Incremental against this ref (e.g. origin/main, HEAD~5)")
	initCmd.Flags().IntVar(&initPR, "pr", 0, "Incremental against a GitHub PR number (requires gh; mutex with --diff-base)")
	initCmd.Flags().StringVar(&initDiffScope, "diff-scope", "", "Diff scope: changed_files, changed_functions, callers (default changed_functions)")
	// Deliberately NOT MarkFlagRequired: "auto" is the default, and requiring the
	// flag is what forced every project into a single language.
}

func runInit(cmd *cobra.Command, args []string) {
	input := args[0]

	// Derive project name
	name := initName
	if name == "" {
		name = config.DeriveProjectName(input)
	}

	var repoPath string
	var repoURL string
	var source string

	if config.IsURL(input) {
		// Remote: clone the repo
		repoURL = input
		source = "remote"

		projDir, err := config.ProjectDir(name)
		if err != nil {
			output.PrintError(err.Error())
			os.Exit(1)
		}
		repoPath = filepath.Join(projDir, "repo")

		// Check if already cloned
		if _, err := os.Stat(filepath.Join(repoPath, ".git")); err == nil {
			fmt.Fprintf(os.Stderr, "Repository already cloned at %s\n", repoPath)
			fmt.Fprintf(os.Stderr, "Pulling latest...\n")
			pullCmd := exec.Command("git", "pull")
			pullCmd.Dir = repoPath
			pullCmd.Stdout = os.Stderr
			pullCmd.Stderr = os.Stderr
			if err := pullCmd.Run(); err != nil {
				output.PrintWarning(fmt.Sprintf("git pull failed: %s (continuing with existing clone)", err))
			}
		} else {
			fmt.Fprintf(os.Stderr, "Cloning %s...\n", repoURL)
			if err := os.MkdirAll(filepath.Dir(repoPath), 0755); err != nil {
				output.PrintError(fmt.Sprintf("Failed to create project directory: %s", err))
				os.Exit(1)
			}
			cloneCmd := exec.Command("git", "clone", repoURL, repoPath)
			cloneCmd.Stdout = os.Stderr
			cloneCmd.Stderr = os.Stderr
			if err := cloneCmd.Run(); err != nil {
				output.PrintError(fmt.Sprintf("git clone failed: %s", err))
				os.Exit(1)
			}
		}

		// Checkout specific commit if provided
		if initCommit != "" {
			checkoutCmd := exec.Command("git", "checkout", initCommit)
			checkoutCmd.Dir = repoPath
			checkoutCmd.Stdout = os.Stderr
			checkoutCmd.Stderr = os.Stderr
			if err := checkoutCmd.Run(); err != nil {
				output.PrintError(fmt.Sprintf("git checkout %s failed: %s", initCommit, err))
				os.Exit(1)
			}
		}
	} else {
		// Local: resolve absolute path
		source = "local"

		absPath, err := filepath.Abs(input)
		if err != nil {
			output.PrintError(fmt.Sprintf("Failed to resolve path: %s", err))
			os.Exit(1)
		}

		repoPath = absPath
	}

	// Language resolution. When the user did not name one, STORE "auto" rather
	// than collapsing to a single detected language.
	//
	// This used to resolve auto -> one concrete language and persist that. Because
	// `scan` then passes the stored value as an explicit -l (see cmd/scan.go), and
	// explicit beats auto, an `init`-created project was pinned to one language
	// permanently — so a 6-language monorepo was scanned as one language forever,
	// and no amount of fixing the engine's default could reach it. That made the
	// product's primary flow (`init` then `scan`) the one place the "scan all
	// languages, not just the main one" requirement could never take effect.
	//
	// Detection still runs, but only to TELL the user what is there. The set is
	// resolved per-scan now, so adding a language to the repo later is picked up
	// without re-running init.
	if initLanguage == "" {
		initLanguage = "auto"
	}
	if initLanguage == "auto" {
		fmt.Fprintf(os.Stderr, "Detecting languages...\n")
		counts, err := languages.DetectLanguages(repoPath)
		if err != nil || len(counts) == 0 {
			output.PrintError(fmt.Sprintf("Language detection failed: %v\nSpecify manually with -l/--language", err))
			os.Exit(1)
		}
		names := make([]string, 0, len(counts))
		for name := range counts {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintf(os.Stderr, "Detected: %s (all will be scanned; use -l to pin one)\n",
			strings.Join(names, ", "))
	}

	// Get commit SHA (best-effort — not all local paths are git repos)
	isGit := false
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err == nil {
		isGit = true
	}

	commitSHA := initCommit
	if isGit {
		sha, warn, err := resolveLocalCommit(repoPath, initCommit)
		if err != nil {
			output.PrintError(err.Error())
			os.Exit(1)
		}
		if warn != "" {
			output.PrintWarning(warn)
		}
		commitSHA = sha
	} else {
		if commitSHA != "" {
			output.PrintWarning("--commit ignored: not a git repository")
		}
		commitSHA = "nogit"
	}

	// Create project
	project := config.NewProject(name, repoURL, repoPath, source, initLanguage, commitSHA)

	// Save project.json
	if err := config.SaveProject(project); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	// Create scan directory
	scanDir, err := config.ScanDir(name, project.CommitSHAShort, initLanguage)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		output.PrintError(fmt.Sprintf("Failed to create scan directory: %s", err))
		os.Exit(1)
	}

	// Decide full vs incremental. selectMode handles flag validation,
	// baseline lookup, TTY prompt, and non-TTY error.
	decision, err := selectMode(modeOpts{
		full:        initFull,
		incremental: initIncremental,
		diffBase:    initDiffBase,
		pr:          initPR,
		scope:       initDiffScope,
		projectName: name,
		repoPath:    repoPath,
	})
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Write scan-run meta.json reflecting the decision.
	meta := config.NewScanMeta(
		decision.Kind,
		project.CommitSHA,
		git.CurrentBranch(repoPath),
		initLanguage,
	)
	meta.Base = decision.Base
	meta.Scope = decision.Scope
	if err := config.SaveScanMeta(name, project.CommitSHAShort, meta); err != nil {
		output.PrintWarning(fmt.Sprintf("Failed to write scan meta: %s", err))
	}

	// Set as active project
	if err := config.SetActiveProject(name); err != nil {
		output.PrintWarning(fmt.Sprintf("Failed to set active project: %s", err))
	}

	// Print summary
	projDir, _ := config.ProjectDir(name)

	output.PrintHeader("Project Initialized")
	output.PrintKeyValue("Name", name)
	if repoURL != "" {
		output.PrintKeyValue("Source", repoURL)
	} else {
		output.PrintKeyValue("Source", repoPath+" (local)")
	}
	output.PrintKeyValue("Language", initLanguage)
	output.PrintKeyValue("Commit", project.CommitSHAShort)
	output.PrintKeyValue("Project dir", projDir)
	output.PrintKeyValue("Scan dir", scanDir)
	fmt.Println()
	output.PrintSuccess("Set as active project")
	fmt.Println()
}

// resolveLocalCommit determines the commit SHA to record for a LOCAL git repo.
// openant references local repos in place and never checks them out (unlike the
// remote path, which runs `git checkout`), so the recorded commit MUST reflect
// what will actually be scanned: the current working-tree HEAD. A --commit that
// differs from HEAD, or that cannot be resolved, is warned about and ignored
// (record HEAD) rather than silently recorded — otherwise the scan would be
// mislabeled with a commit the working tree is not at
// (finding gocli-local-commit-no-checkout).
func resolveLocalCommit(repoPath, requested string) (sha string, warn string, err error) {
	head, err := gitRevParseLocal(repoPath, "HEAD")
	if err != nil {
		return "", "", fmt.Errorf("Failed to get HEAD commit: %s", err)
	}
	if requested == "" {
		return head, "", nil
	}
	resolved, rerr := gitRevParseLocal(repoPath, requested)
	if rerr != nil {
		return head, fmt.Sprintf("--commit %q could not be resolved in local repo; using working-tree HEAD %s (local repos are referenced in place, not checked out)", requested, config.ShortSHA(head)), nil
	}
	if resolved != head {
		return head, fmt.Sprintf("--commit %s is not checked out (working tree is at %s); local repos are referenced in place and not checked out — scanning HEAD", config.ShortSHA(resolved), config.ShortSHA(head)), nil
	}
	return resolved, "", nil
}

func gitRevParseLocal(repoPath, ref string) (string, error) {
	out, err := exec.Command("git", "-C", repoPath, "rev-parse", ref).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
