package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var reposCmd = &cobra.Command{
	Use:     "repos",
	Short:   "List monitored repositories",
	Example: "  nullify repos\n  nullify repos -o table",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		apiClient := getAPIClient()

		result, err := apiClient.ListContextRepositories(ctx, api.ListContextRepositoriesInput{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		data, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(os.Stderr, string(data))
		}
	},
}

func init() {
	rootCmd.AddCommand(reposCmd)
}
