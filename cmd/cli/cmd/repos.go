package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var reposCmd = &cobra.Command{
	Use:     "repos",
	Short:   "List monitored repositories",
	Example: "  nullify repos\n  nullify repos -o table",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		apiClient := authCtx.APIClient()

		result, err := apiClient.ListContextRepositories(ctx, api.ListContextRepositoriesInput{})
		if err != nil {
			return err
		}

		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), string(data))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reposCmd)
}
