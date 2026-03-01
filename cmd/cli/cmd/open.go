package cmd

import (
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var openCmd = &cobra.Command{
	Use:   "open",
	Short: "Open the Nullify dashboard in your browser",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		openHost := resolveHost(ctx)
		url := "https://" + openHost

		if !quiet {
			fmt.Fprintf(os.Stderr, "Opening %s...\n", url)
		}

		if err := auth.OpenBrowser(url); err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not open browser: %v\nVisit %s manually.\n", err, url)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(openCmd)
}
