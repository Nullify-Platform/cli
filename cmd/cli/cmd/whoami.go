package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current authentication status",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		whoamiHost, err := resolveHostE(ctx)
		if err != nil {
			return err
		}

		info := map[string]any{
			"host": whoamiHost,
		}

		hosts, hostsErr := commandHostsFor(whoamiHost)
		if hostsErr == nil && hosts.AuthHost != hosts.DataHost {
			info["auth_host"] = hosts.AuthHost
			info["data_host"] = hosts.DataHost
		}

		creds, err := auth.LoadCredentials()
		if hostsErr != nil {
			info["authenticated"] = false
			info["error"] = hostsErr.Error()
		} else if err != nil {
			info["authenticated"] = false
			info["error"] = "no credentials found"
		} else if hostCreds, ok := creds[auth.CredentialKey(hosts.AuthHost)]; !ok {
			info["authenticated"] = false
			info["error"] = fmt.Sprintf("no credentials for host %s", hosts.AuthHost)
		} else {
			info["authenticated"] = true
			if hostCreds.Installation != "" {
				info["installation"] = hostCreds.Installation
			}
			if hostCreds.QueryParameters != nil {
				info["query_parameters"] = hostCreds.QueryParameters
			}
			if hostCreds.ExpiresAt > 0 {
				info["expires_at"] = hostCreds.ExpiresAt
			}
		}

		out, _ := json.MarshalIndent(info, "", "  ")

		if err := output.Print(cmd, out); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}
