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
		url := dashboardURL(openHost)

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

// dashboardURL is the dashboard for commandHost. An instance's dashboard is
// app.<instance>: the bare instance name points at the marketing site. An
// instance that signs in through a router shares that router's dashboard,
// since it may have no dashboard host of its own.
func dashboardURL(commandHost string) string {
	if router, ok := auth.RouterFor(commandHost); ok {
		return router.AppURL
	}
	if authHost, err := auth.AuthHostFor(commandHost); err == nil {
		if router, ok := auth.RouterFor(authHost); ok {
			return router.AppURL
		}
	}
	return "https://app." + strings.TrimPrefix(commandHost, "api.")
}
