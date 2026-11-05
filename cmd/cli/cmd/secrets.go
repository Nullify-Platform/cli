package cmd

import (
	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Local secrets scanning",
	Long:  "Local, in-process secret scanning. Scans run entirely on this machine; no file content is sent to the Nullify API.",
}

func init() {
	rootCmd.AddCommand(secretsCmd)
}
