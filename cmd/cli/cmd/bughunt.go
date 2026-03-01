package cmd

import (
	"github.com/spf13/cobra"
)

var bughuntCmd = &cobra.Command{
	Use:   "bughunt",
	Short: "Cloud-based automated bug hunting for web applications",
	Long:  "Run automated bug hunting scans against your web applications. Cloud-only - no local scanning.",
}

func init() {
	rootCmd.AddCommand(bughuntCmd)
}
