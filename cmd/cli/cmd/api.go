package cmd

import "github.com/spf13/cobra"

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Direct API access (advanced)",
	Long:  "Low-level commands for direct Nullify API access. These map 1:1 to API endpoints and are intended for advanced users and scripting.",
}

func init() {
	rootCmd.AddCommand(apiCmd)
}
