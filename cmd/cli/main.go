package main

import (
	"os"

	"github.com/nullify-platform/cli/cmd/cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// cobra has already printed the error (SilenceErrors is false).
		// Map it to the appropriate process exit code in one place.
		os.Exit(cmd.ExitCodeForError(err))
	}
}
