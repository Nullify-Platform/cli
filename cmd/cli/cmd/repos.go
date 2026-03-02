package cmd

import (
	"fmt"
	"net/url"
	"os"

	"github.com/nullify-platform/cli/internal/output"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var reposCmd = &cobra.Command{
	Use:     "repos",
	Short:   "List monitored repositories",
	Example: "  nullify repos\n  nullify repos -o table",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		apiClient := getAPIClient()

		result, err := apiClient.ListClassifierRepositories(ctx, url.Values{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := output.Print(cmd, result); err != nil {
			fmt.Fprintln(os.Stderr, string(result))
		}
	},
}

func init() {
	rootCmd.AddCommand(reposCmd)
}
