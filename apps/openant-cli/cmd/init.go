package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
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
	initCmd.Flags().StringVarP(&initLanguage, "language", "l", "", "Language to analyze: python, javascript, go, c, ruby, php (required)")
	initCmd.Flags().StringVar(&initCommit, "commit", "", "Specific commit SHA (default: HEAD)")
	initCmd.Flags().StringVar(&initName, "name", "", "Override project name (default: derived from URL/path)")
	initCmd.Flags().BoolVar(&initFull, "full", false, "Force full scan (rejects --incremental/--diff-base/--pr)")
	initCmd.Flags().BoolVar(&initIncremental, "incremental", false, "Incremental against the last successful scan on this project")
	initCmd.Flags().StringVar(&initDiffBase, "diff-base", "", "Incremental against this ref (e.g. origin/main, HEAD~5)")
	initCmd.Flags().IntVar(&initPR, "pr", 0, "Incremental against a GitHub PR number (requires gh; mutex with --diff-base)")
	initCmd.Flags().StringVar(&initDiffScope, "diff-scope", "", "Diff scope: changed_files, changed_functions, callers (default changed_functions)")
	_ = initCmd.MarkFlagRequired("language")
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
		// Local: verify it's a git repo and resolve absolute path
		source = "local"

		absPath, err := filepath.Abs(input)
		if err != nil {
			output.PrintError(fmt.Sprintf("Failed to resolve path: %s", err))
			os.Exit(1)
		}

		if _, err := os.Stat(filepath.Join(absPath, ".git")); err != nil {
			output.PrintError(fmt.Sprintf("%s is not a git repository (no .git directory)", absPath))
			os.Exit(1)
		}

		repoPath = absPath
	}

	// Get commit SHA
	commitSHA := initCommit
	if commitSHA == "" {
		out, err := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD").Output()
		if err != nil {
			output.PrintError(fmt.Sprintf("Failed to get HEAD commit: %s", err))
			os.Exit(1)
		}
		commitSHA = strings.TrimSpace(string(out))
	} else {
		// Resolve short SHA to full SHA
		out, err := exec.Command("git", "-C", repoPath, "rev-parse", commitSHA).Output()
		if err == nil {
			commitSHA = strings.TrimSpace(string(out))
		}
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
