package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage project workspaces",
	Long: `View and switch between initialized project workspaces.

Examples:
  openant project list       List all projects
  openant project show       Show active project details
  openant project switch grafana/grafana   Switch active project`,
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all initialized projects",
	Run:   runProjectList,
}

var projectShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show active project details",
	Run:   runProjectShow,
}

var projectSwitchCmd = &cobra.Command{
	Use:   "switch <project-name>",
	Short: "Switch the active project",
	Args:  cobra.ExactArgs(1),
	Run:   runProjectSwitch,
}

func init() {
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectShowCmd)
	projectCmd.AddCommand(projectSwitchCmd)
}

func runProjectList(cmd *cobra.Command, args []string) {
	names, err := config.ListProjects()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	if len(names) == 0 {
		fmt.Println("No projects initialized. Run: openant init <repo-url-or-path> -l <language>")
		return
	}

	cfg, _ := config.Load()
	active := ""
	if cfg != nil {
		active = cfg.ActiveProject
	}

	output.PrintHeader("Projects")
	for _, name := range names {
		if name == active {
			fmt.Printf("  * %s (active)\n", name)
		} else {
			fmt.Printf("    %s\n", name)
		}
	}
	fmt.Println()
}

func runProjectShow(cmd *cobra.Command, args []string) {
	project, err := config.ActiveProject()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	// #691 + the T1's F4: the swallow printed a BLANK scan dir for a
	// stale traversal pin while every other command printed the honest
	// #691 diagnosis — the one inspection command must not hide it.
	scanDir, scanDirErr := config.ScanDir(project.Name, project.CommitSHAShort, project.Language)
	if scanDirErr != nil {
		output.PrintWarning(scanDirErr.Error())
	}
	projDir, _ := config.ProjectDir(project.Name)

	output.PrintHeader("Active Project")
	output.PrintKeyValue("Name", project.Name)
	if project.RepoURL != "" {
		output.PrintKeyValue("URL", project.RepoURL)
	}
	output.PrintKeyValue("Repo path", project.RepoPath)
	output.PrintKeyValue("Source", project.Source)
	output.PrintKeyValue("Language", project.Language)
	output.PrintKeyValue("Commit", project.CommitSHAShort+" ("+project.CommitSHA+")")
	output.PrintKeyValue("Project dir", projDir)
	output.PrintKeyValue("Scan dir", scanDir)
	output.PrintKeyValue("Created", project.CreatedAt)
	fmt.Println()
}

func runProjectSwitch(cmd *cobra.Command, args []string) {
	name := args[0]

	// Verify project exists
	_, err := config.LoadProject(name)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	if err := config.SetActiveProject(name); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	output.PrintSuccess(fmt.Sprintf("Switched to project %q", name))
}
