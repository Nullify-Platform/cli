package cmd

import (
	"github.com/spf13/cobra"
)

// secretsCmd is the top-level home for local, in-process secret scanning
// (scan-file). The generated, API-backed secrets commands (allowlists,
// findings, ...) stay under 'api secrets' via RegisterSecretsCommands --
// this tree is for scanning that never calls the platform API.
var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Local secrets scanning",
	Long:  "Local, in-process secret scanning. Scans run entirely on this machine; no file content is sent to the Nullify API.",
}

func init() {
	rootCmd.AddCommand(secretsCmd)
}
