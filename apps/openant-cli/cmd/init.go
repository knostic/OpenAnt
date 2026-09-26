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

// validateInitLanguage is the #691 CLI boundary: `auto` (the multi-language
// pin) always passes; any other value must be a member of the supported
// set — exact case (the '-l Python' typo is the silently-persisted-garbage
// shape), no path shapes (the traversal escape). A registry failure fails
// CLOSED for the non-auto form: no pin exists yet, so the honest answer is
// the refusal, never a silent pass.
func validateInitLanguage(value string) error {
	return validateInitLanguageRegistryDown(value, languages.Supported)
}

// validateInitLanguageRegistryDown is the seam form (the registry failure
// is injectable for the test).
func validateInitLanguageRegistryDown(value string, supportedFn func() ([]string, error)) error {
	if value == "" || value == "auto" {
		return nil
	}
	supported, err := supportedFn()
	if err != nil {
		// FAIL CLOSED (the #667 guard lets the off-pin message fire on a
		// registry failure because a pin already exists; HERE no pin
		// exists — persisting an unvalidated value is the #691 bug).
		return fmt.Errorf("--language/-l %q could not be validated against the supported set (%v) — refusing to pin an unvalidated language; restore config/languages.json and retry ('auto' cannot detect languages while the registry is down either)", value, err)
	}
	for _, s := range supported {
		if s == value {
			return nil
		}
	}
	return fmt.Errorf("--language/-l %q is not a supported language (the supported set: %s) — the value is pinned verbatim into project.json and becomes the artifacts path, so a typo fails every later scan far from the cause (issue #691); use 'auto' to scan all languages", value, strings.Join(supported, ", "))
}

func runInit(cmd *cobra.Command, args []string) {
	input := args[0]

	// #691 + the T1's F1: the language gate runs FIRST — before the
	// remote clone/pull branch (a bad -l previously triggered a full
	// git clone/pull before the zero-cost flag check refused it) and
	// before ANY write (the traversal escape and the silently-persisted
	// typo must refuse at the boundary, cost-free).
	if initLanguage == "" {
		initLanguage = "auto"
	}
	if err := validateInitLanguage(initLanguage); err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

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
	// (the gate ran at the top — see the F1 note; the detection below
	// only TELLS the user what is there)
	if initLanguage == "auto" {
		fmt.Fprintf(os.Stderr, "Detecting languages...\n")
		counts, err := languages.DetectLanguages(repoPath)
		if err != nil {
			output.PrintError(fmt.Sprintf("Language detection failed: %v\nSpecify manually with -l/--language", err))
			os.Exit(1)
		}
		if len(counts) == 0 {
			output.PrintError("no supported source files found\nSpecify manually with -l/--language")
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

	// #669: selectMode runs BEFORE the project save — the PR fetch may
	// rewrite the working tree (FetchPR checks out pr-head), and the
	// project identity + scan-dir key + meta.json must all point at the
	// commit that was actually checked out, not the pre-checkout HEAD.
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

	// #669: if the PR fetch moved the tree, re-resolve the commit SHA
	// so the project, the scan dir, and the meta all name the scanned tree.
	if isGit && initPR > 0 {
		// The body's promised guard: an explicit --commit is never silently
		// overridden by the PR checkout — it is ignored WITH the warning.
		if initCommit != "" {
			output.PrintWarning("--commit ignored: the PR checkout determines the stamped SHA")
		}
		sha, warn, err := resolveLocalCommit(repoPath, "")
		if err != nil {
			output.PrintWarning(fmt.Sprintf(
				"PR checkout moved the tree but the post-checkout SHA could not be re-resolved: %s — the project identity names the pre-checkout commit", err))
		} else {
			if warn != "" {
				output.PrintWarning(warn)
			}
			commitSHA = sha
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

	// Write scan-run meta.json reflecting the decision.
	if err := writeInitScanMeta(name, project, decision, git.CurrentBranch(repoPath)); err != nil {
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

// writeInitScanMeta records init's pending scan decision in the run's
// meta.json (#664: keyed on the init language — the same key scan reads
// via project.Language). Extracted from runInit so the write site is
// directly guardable (the linkage gate's finding: the inline site had no
// test that fails when its key is wrong).
func writeInitScanMeta(name string, project *config.Project, decision modeDecision, branch string) error {
	// The language is derived from the project, never passed separately —
	// an adjacent same-type (branch, language) pair is a silent arg-swap
	// surface the linkage gate cannot see (the fable delta round's finding).
	language := project.Language
	meta := config.NewScanMeta(
		decision.Kind,
		project.CommitSHA,
		branch,
		language,
	)
	meta.Base = decision.Base
	meta.Scope = decision.Scope
	return config.SaveScanMeta(name, project.CommitSHAShort, language, meta)
}
