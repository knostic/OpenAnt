package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/server"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the OpenAnt web UI",
	Long: `Serve starts a local HTTP server (default http://localhost:8080) and opens
the browser automatically.

Scan outputs are stored under ~/.openant/webui/ and persist across restarts.
Use Ctrl+C to stop the server; all in-flight scans are cancelled gracefully.`,
	Args: cobra.NoArgs,
	Run:  runServe,
}

var serveAddr string

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "127.0.0.1:8080", "Address to listen on")
}

func runServe(_ *cobra.Command, _ []string) {
	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Resolve output root: ~/.openant/webui/
	home, err := os.UserHomeDir()
	if err != nil {
		output.PrintError("cannot determine home directory: " + err.Error())
		os.Exit(2)
	}
	outDir := filepath.Join(home, ".openant", "webui")
	if err := os.MkdirAll(outDir, 0750); err != nil {
		output.PrintError("cannot create output directory: " + err.Error())
		os.Exit(2)
	}

	srv, err := server.New(rt.Path, outDir)
	if err != nil {
		output.PrintError("failed to initialise server: " + err.Error())
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	url, err := srv.Start(ctx, serveAddr)
	if err != nil {
		output.PrintError("failed to start server: " + err.Error())
		os.Exit(2)
	}

	fmt.Println("OpenAnt web UI running at", url)
	openBrowser(url)
	fmt.Println("Press Ctrl+C to stop.")

	<-ctx.Done()
	fmt.Println("\nShutting down…")
}

// openBrowser opens url in the default system browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
