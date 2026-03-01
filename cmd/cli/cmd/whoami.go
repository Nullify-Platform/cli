package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current authentication status",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		whoamiHost := resolveHost(ctx)

		info := map[string]any{
			"host": whoamiHost,
		}

		creds, err := auth.LoadCredentials()
		if err != nil {
			info["authenticated"] = false
			info["error"] = "no credentials found"
		} else if hostCreds, ok := creds[whoamiHost]; !ok {
			info["authenticated"] = false
			info["error"] = fmt.Sprintf("no credentials for host %s", whoamiHost)
		} else {
			info["authenticated"] = true
			if hostCreds.QueryParameters != nil {
				info["query_parameters"] = hostCreds.QueryParameters
			}
			if hostCreds.ExpiresAt > 0 {
				info["expires_at"] = hostCreds.ExpiresAt
			}
		}

		out, _ := json.MarshalIndent(info, "", "  ")

		if err := output.Print(cmd, out); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}
