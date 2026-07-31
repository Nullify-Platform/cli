package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/spf13/cobra"
)

var openCmd = &cobra.Command{
	Use:   "open",
	Short: "Open the Nullify dashboard in your browser",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

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
			fmt.Fprintf(
				cmd.ErrOrStderr(),
				"Error: could not open browser: %v\nVisit %s manually.\n",
				err,
				url,
			)
			cmd.SilenceErrors = true
			return fmt.Errorf("could not open browser: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(openCmd)
}
