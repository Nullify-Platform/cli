package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/spf13/cobra"
)

var openCmd = &cobra.Command{
	Use:   "open",
	Short: "Open the Nullify dashboard in your browser",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		openHost, err := resolveHostE(ctx)
		if err != nil {
			return err
		}
		// Strip "api." prefix to get the dashboard URL
		dashboardHost := strings.TrimPrefix(openHost, "api.")
		url := "https://" + dashboardHost

		if !quiet {
			fmt.Fprintf(os.Stderr, "Opening %s...\n", url)
		}

		if err := auth.OpenBrowser(url); err != nil {
			fmt.Fprintf(os.Stderr, "Visit %s manually.\n", url)
			return fmt.Errorf("could not open browser: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(openCmd)
}
