package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the host, auth source and organization commands run as",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		whoamiHost, err := resolveHostE(ctx)
		if err != nil {
			return err
		}

		info := map[string]any{
			"host": whoamiHost,
		}

		hosts, hostsErr := commandHostsFor(ctx, whoamiHost)
		if hostsErr == nil {
			info["auth_host"] = hosts.AuthHost
			info["data_host"] = hosts.DataHost
		}

		hostCreds, _, ok, err := auth.LookupCredentials(whoamiHost)
		switch {
		case hostsErr != nil:
			info["authenticated"] = false
			info["error"] = hostsErr.Error()
		case usesMachineToken():
			// An API token or a GitHub Actions exchange overrides any stored
			// login, as it does for every other command.
			info["authenticated"] = true
			info["auth"] = machineTokenSource()
			info["org"] = describeOrg(ctx, whoamiHost)
		case err != nil:
			info["authenticated"] = false
			info["error"] = "no credentials found"
		case !ok:
			info["authenticated"] = false
			info["error"] = fmt.Sprintf("no credentials for host %s", hosts.AuthHost)
		default:
			info["authenticated"] = true
			info["auth"] = "login"
			info["org"] = describeOrg(ctx, whoamiHost)
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

// machineTokenSource names the token source usesMachineToken found, in the
// order the token is resolved.
func machineTokenSource() string {
	if nullifyToken != "" || os.Getenv("NULLIFY_TOKEN") != "" {
		return "api_token"
	}
	return "github_actions"
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}
