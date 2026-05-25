package main

import (
	"os"

	"github.com/nullify-platform/cli/cmd/cli/cmd"
	"github.com/nullify-platform/cli/internal/commands"
)

func main() {
	// commands.ExitCodeFromError maps the deps-analyze workflow's
	// exit-coded errors (severity gate: 10/20/30, invalid: 2, transient:
	// 1) onto the process exit code; any other error falls back to 1.
	if err := cmd.Execute(); err != nil {
		os.Exit(commands.ExitCodeFromError(err))
	}
}
