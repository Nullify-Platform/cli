package cmd

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"slices"
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
	Long:  "Authenticate with Nullify. Opens your browser to log in with your identity provider. Without --host or a configured host, signs in through nullify.ai and selects an installation.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()

		sanitizedHost, err := resolveLoginHost()
		if err != nil {
			return err
		}

		installation, _ := cmd.Flags().GetString("installation")
		if installation != "" && !auth.IsRouterHost(sanitizedHost) {
			return fmt.Errorf("--installation applies only when signing in through nullify.ai")
		}

		if err := auth.Login(ctx, sanitizedHost, installationPicker(installation)); err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
		return nil
	},
}

// resolveLoginHost returns the --host flag, else the configured host, else the router host.
func resolveLoginHost() (string, error) {
	loginHost := host
	if loginHost == "" {
		cfg, err := auth.LoadConfig()
		if err == nil && cfg.Host != "" {
			loginHost = cfg.Host
		}
	}
	if loginHost == "" {
		loginHost = auth.RouterHost
	}

	sanitizedHost, err := lib.SanitizeNullifyHost(loginHost)
	if err != nil {
		return "", fmt.Errorf("invalid host %q - must be nullify.ai or <your-instance>.nullify.ai", loginHost)
	}
	return sanitizedHost, nil
}

func installationPicker(name string) auth.InstallationPicker {
	return auth.InstallationPicker{
		Name:        name,
		Interactive: stdinIsTTY(),
		In:          os.Stdin,
		Out:         os.Stdout,
	}
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out of Nullify",
	Long:  "Clear stored credentials for the current or specified host.",
	RunE: func(cmd *cobra.Command, args []string) error {
		logoutHost, err := resolveHostForAuth()
		if err != nil {
			return err
		}

		if err := auth.Logout(logoutHost); err != nil {
			return fmt.Errorf("logout failed: %w", err)
		}

		fmt.Printf("Logged out from %s\n", logoutHost)
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status",
	Long:  "Display the current authentication state including host, user, and token expiry.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := auth.LoadConfig()
		if err != nil {
			fmt.Println("Not configured. Run 'nullify auth login' to get started.")
			return nil
		}

		if cfg.Host == "" {
			fmt.Println("No host configured. Run 'nullify auth login'")
			return nil
		}

		fmt.Printf("Host: %s\n", cfg.Host)

		creds, err := auth.LoadCredentials()
		if err != nil {
			fmt.Println("Status: not authenticated")
			return nil
		}

		hostCreds, ok := creds[auth.CredentialKey(cfg.Host)]
		if !ok {
			fmt.Println("Status: not authenticated")
			return nil
		}

		if auth.IsRouterHost(cfg.Host) {
			printInstallation(hostCreds)
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
		return nil
	},
}

func printInstallation(hostCreds auth.HostCredentials) {
	if hostCreds.DataHost == "" {
		fmt.Println("Installation: none selected - run 'nullify auth switch --installation <name>'")
		return
	}
	fmt.Printf("Installation: %s (%s)\n", hostCreds.Installation, hostCreds.DataHost)
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
	Short: "Switch between configured hosts or installations",
	Long:  "Switch the default host when multiple Nullify instances are configured, or select another installation with --installation when signed in through nullify.ai.",
	RunE: func(cmd *cobra.Command, args []string) error {
		switchHost, _ := cmd.Flags().GetString("host")
		if switchHost == "" && host != "" {
			switchHost = host
		}

		installation, _ := cmd.Flags().GetString("installation")
		if installation != "" {
			if switchHost != "" && !auth.IsRouterHost(switchHost) {
				return fmt.Errorf("--installation applies only to nullify.ai")
			}
			install, err := auth.SwitchInstallation(cmd.Context(), installation)
			if err != nil {
				return fmt.Errorf("switch installation failed: %w", err)
			}
			fmt.Printf("Switched to installation %s (%s)\n", install.Name, install.DataHost)
			return nil
		}

		if switchHost == "" {
			listConfiguredHosts()
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

func listConfiguredHosts() {
	creds, err := auth.LoadCredentials()
	if err != nil || len(creds) == 0 {
		fmt.Println("No configured hosts. Run 'nullify auth login'")
		return
	}

	cfg, _ := auth.LoadConfig()
	fmt.Println("Configured hosts:")
	for _, h := range slices.Sorted(maps.Keys(creds)) {
		marker := "  "
		if cfg != nil && auth.CredentialKey(cfg.Host) == h {
			marker = "* "
		}
		fmt.Printf("%s%s%s\n", marker, h, installationLabel(creds[h]))
	}
	fmt.Println("\nUse 'nullify auth switch --host <host>' to switch hosts, or 'nullify auth switch --installation <name>' to switch installations on nullify.ai.")
}

func installationLabel(hostCreds auth.HostCredentials) string {
	if hostCreds.DataHost == "" {
		return ""
	}
	return fmt.Sprintf(" (installation %s, %s)", hostCreds.Installation, hostCreds.DataHost)
}

var configShowCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Long:  "Display the current CLI configuration as JSON.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := auth.LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "No config found. Run 'nullify init' to set up.\n")
			return nil
		}

		data, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(loginCmd)
	authCmd.AddCommand(logoutCmd)
	authCmd.AddCommand(statusCmd)
	authCmd.AddCommand(tokenCmd)
	authCmd.AddCommand(switchCmd)
	authCmd.AddCommand(configShowCmd)

	loginCmd.Flags().String("installation", "", "Installation to use when signing in through nullify.ai")
	switchCmd.Flags().String("installation", "", "Installation to select for the nullify.ai sign-in")
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
