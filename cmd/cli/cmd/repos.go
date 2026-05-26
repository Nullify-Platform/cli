package cmd

import (
	"fmt"
	"net/url"
	"os"

	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var reposCmd = &cobra.Command{
	Use:     "repos",
	Short:   "List monitored repositories",
	Example: "  nullify repos\n  nullify repos -o table",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		apiClient := getAPIClient()

		result, err := apiClient.ListContextRepositories(ctx, url.Values{})
		if err != nil {
			return err
		}

		if err := output.Print(cmd, result); err != nil {
			fmt.Fprintln(os.Stderr, string(result))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reposCmd)
}
