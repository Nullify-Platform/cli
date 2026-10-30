package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication",
	Long:  "Authenticate with the Nullify API, manage credentials and tokens.",
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to Nullify",
	Long:  "Authenticate with your Nullify instance. Opens your browser to log in with your identity provider.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()

		loginHost := host

		// If no host from flag, try config file
		if loginHost == "" {
			cfg, err := auth.LoadConfig()
			if err == nil && cfg.Host != "" {
				loginHost = cfg.Host
			}
		}

		// If still no host, prompt (only when running interactively).
		if loginHost == "" {
			if !stdinIsTTY() {
				return fmt.Errorf("not a terminal; pass --host <your-instance>.nullify.ai")
			}
			fmt.Print("Enter your Nullify instance (e.g., acme.nullify.ai): ")
			_, _ = fmt.Scanln(&loginHost)
		}

		sanitizedHost, err := lib.SanitizeNullifyHost(loginHost)
		if err != nil {
			return fmt.Errorf("invalid host %q - must be in the format <your-instance>.nullify.ai", loginHost)
		}

		if err := auth.Login(ctx, sanitizedHost); err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out of Nullify",
	Long: "Clear stored credentials for the current or specified host. On an instance that signs in through the " +
		"Nullify router, this removes the router login, which every instance signed in through it shares.",
	RunE: func(cmd *cobra.Command, args []string) error {
		logoutHost, err := resolveHostForAuth()
		if err != nil {
			return err
		}

		authHost, err := auth.AuthHostFor(logoutHost)
		if err != nil {
			return fmt.Errorf("logout failed: %w", err)
		}
		if err := auth.Logout(logoutHost); err != nil {
			return fmt.Errorf("logout failed: %w", err)
		}

		fmt.Printf("Logged out from %s\n", logoutHost)
		if auth.CredentialKey(authHost) != auth.CredentialKey(logoutHost) {
			fmt.Printf("This removed the %s login, which other tenants signed in through it share.\n", authHost)
		}
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status",
	Long:  "Display the current authentication state including host, auth host, organization, and token expiry.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		if usesMachineToken() {
			statusHost, err := resolveHostE(ctx)
			if err != nil {
				fmt.Println("No host configured. Pass --host or set NULLIFY_HOST.")
				return nil
			}
			fmt.Printf("Host: %s\n", statusHost)
			fmt.Println("Auth: API token")
			fmt.Printf("Org: %s\n", describeOrg(ctx, statusHost))
			return nil
		}

		statusHost, err := resolveHostE(ctx)
		if err != nil {
			fmt.Println("No host configured. Run 'nullify auth login --host <your-instance>.nullify.ai'")
			return nil
		}

		fmt.Printf("Host: %s\n", statusHost)

		hostCreds, authHost, ok, err := auth.LookupCredentials(statusHost)
		if authHost != "" {
			fmt.Printf("Auth host: %s\n", authHost)
		}
		if err != nil || !ok {
			fmt.Println("Status: not authenticated")
			return nil
		}

		if hostCreds.ExpiresAt > 0 {
			expiresAt := time.Unix(hostCreds.ExpiresAt, 0)
			if time.Now().After(expiresAt) {
				fmt.Println("Status: token expired (will auto-refresh on next command)")
			} else {
				fmt.Printf("Status: authenticated (expires %s)\n", expiresAt.Format(time.RFC3339))
			}
		} else {
			fmt.Println("Status: authenticated")
		}
		fmt.Printf("Org: %s\n", describeOrg(ctx, statusHost))
		return nil
	},
}

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Print access token to stdout",
	Long:  "Print the current access token. Useful for piping to other tools.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		hostForToken, err := resolveHostForAuth()
		if err != nil {
			return err
		}

		token, err := auth.GetValidToken(ctx, hostForToken)
		if err != nil {
			return err
		}

		fmt.Println(token)
		return nil
	},
}

var switchCmd = &cobra.Command{
	Use:   "switch",
	Short: "Switch between configured hosts",
	Long:  "Switch the default host when multiple Nullify instances are configured.",
	RunE: func(cmd *cobra.Command, args []string) error {
		switchHost, _ := cmd.Flags().GetString("host")
		if switchHost == "" && host != "" {
			switchHost = host
		}

		if switchHost == "" {
			// List available hosts
			known, err := auth.KnownHosts()
			if err != nil || len(known) == 0 {
				fmt.Println("No configured hosts. Run 'nullify auth login --host <your-instance>.nullify.ai'")
				return nil
			}

			cfg, _ := auth.LoadConfig()
			fmt.Println("Configured hosts:")
			for _, h := range known {
				marker := "  "
				if cfg != nil && auth.CredentialKey(cfg.Host) == h {
					marker = "* "
				}
				fmt.Printf("%s%s\n", marker, h)
			}
			fmt.Println("\nUse 'nullify auth switch --host <host>' to switch.")
			return nil
		}

		sanitizedHost, err := lib.SanitizeNullifyHost(switchHost)
		if err != nil {
			return fmt.Errorf("invalid host %q", switchHost)
		}

		cfg, err := auth.LoadConfig()
		if err != nil {
			cfg = &auth.Config{}
		}
		cfg.Host = sanitizedHost

		if err := auth.SaveConfig(cfg); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Switched to %s\n", sanitizedHost)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Long:  "Display the effective host, how it authenticates (login and its auth host, or API token), and the organization commands run as, as JSON.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		configHost, err := resolveHostE(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "No config found. Run 'nullify init' to set up.\n")
			return nil
		}

		shown := map[string]any{"host": configHost}
		if usesMachineToken() {
			shown["auth"] = "api_token"
		} else {
			shown["auth"] = "login"
			if authHost, err := auth.AuthHostFor(configHost); err == nil {
				shown["auth_host"] = authHost
			}
		}
		shown["org"] = describeOrg(ctx, configHost)

		data, _ := json.MarshalIndent(shown, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

// describeOrg says which org commands on host run as right now, without
// prompting.
func describeOrg(ctx context.Context, host string) string {
	token, err := lib.GetNullifyToken(ctx, host, nullifyToken, githubToken)
	if err != nil {
		return "unknown (not authenticated)"
	}
	scope, err := resolveOrgScope(ctx, host, token, orgInputsFor(host, orgFlag, "--org"), false)
	switch {
	case err != nil:
		return "not chosen: " + err.Error()
	case scope.Org != nil:
		return scope.Org.String()
	case scope.Query["githubOwnerId"] != "":
		return "githubOwnerId " + scope.Query["githubOwnerId"] + " (NULLIFY_GITHUB_OWNER_ID)"
	default:
		return "the API token's own (the server derives it)"
	}
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(loginCmd)
	authCmd.AddCommand(logoutCmd)
	authCmd.AddCommand(statusCmd)
	authCmd.AddCommand(tokenCmd)
	authCmd.AddCommand(switchCmd)
	authCmd.AddCommand(configShowCmd)
}

func resolveHostForAuth() (string, error) {
	if host != "" {
		sanitized, err := lib.SanitizeNullifyHost(host)
		if err != nil {
			return "", fmt.Errorf("invalid host %q", host)
		}
		return sanitized, nil
	}

	cfg, err := auth.LoadConfig()
	if err == nil && cfg.Host != "" {
		sanitized, sErr := lib.SanitizeNullifyHost(cfg.Host)
		if sErr == nil {
			return sanitized, nil
		}
	}

	return "", fmt.Errorf("no host configured. Use --host or run 'nullify auth login'")
}
