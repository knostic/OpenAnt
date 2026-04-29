package cmd

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

// errDockerUnavailable is returned by checkDockerAvailable when neither
// the binary nor a running daemon is reachable. Phrased so the error
// message guides the user to --skip-dynamic-test.
var errDockerUnavailable = errors.New(
	"dynamic testing requires Docker, which is not available.\n" +
		"If you can't or don't want to run Docker, use --skip-dynamic-test")

// checkDockerAvailable confirms that the docker CLI is on PATH and the
// daemon responds to `docker info`. Used at scan startup before the
// pipeline runs, so users with no Docker get an immediate, actionable
// error rather than burning the whole scan only to fail at the
// dynamic-test step.
//
// The daemon probe is bounded to a few seconds — a hung daemon should
// surface as "unavailable" rather than block forever.
func checkDockerAvailable() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return errDockerUnavailable
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	if err := cmd.Run(); err != nil {
		return errDockerUnavailable
	}
	return nil
}
