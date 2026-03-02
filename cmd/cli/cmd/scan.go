package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Information about Nullify scanning",
	Long: `Nullify continuously scans your repositories automatically — no manual scan trigger needed.

To view results:
  nullify findings          Show security findings
  nullify status            Show security posture overview
  nullify pentest start     Start a DAST penetration test`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Nullify scans run automatically on your repositories.")
		fmt.Println()
		fmt.Println("To view scan results:")
		fmt.Println("  nullify findings    List security findings")
		fmt.Println("  nullify status      Show security posture overview")
		fmt.Println("  nullify pentest     Run a DAST penetration test")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
