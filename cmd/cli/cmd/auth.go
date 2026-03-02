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
	"github.com/nullify-platform/logger/pkg/logger"
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
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		// Wrap context with signal handling so Ctrl+C triggers graceful cancellation
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

		// If still no host, prompt
		if loginHost == "" {
			fmt.Print("Enter your Nullify instance (e.g., acme.nullify.ai): ")
			_, _ = fmt.Scanln(&loginHost)
		}

		sanitizedHost, err := lib.SanitizeNullifyHost(loginHost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid host %q - must be in the format <your-instance>.nullify.ai\n", loginHost)
			os.Exit(1)
		}

		err = auth.Login(ctx, sanitizedHost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: login failed: %v\n", err)
			os.Exit(1)
		}
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out of Nullify",
	Long:  "Clear stored credentials for the current or specified host.",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		logoutHost := resolveHostForAuth(ctx)

		err := auth.Logout(logoutHost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: logout failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Logged out from %s\n", logoutHost)
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status",
	Long:  "Display the current authentication state including host, user, and token expiry.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := auth.LoadConfig()
		if err != nil {
			fmt.Println("Not configured. Run 'nullify auth login --host <your-instance>.nullify.ai' to get started.")
			return
		}

		if cfg.Host == "" {
			fmt.Println("No host configured. Run 'nullify auth login --host <your-instance>.nullify.ai'")
			return
		}

		fmt.Printf("Host: %s\n", cfg.Host)

		creds, err := auth.LoadCredentials()
		if err != nil {
			fmt.Println("Status: not authenticated")
			return
		}

		hostCreds, ok := creds[cfg.Host]
		if !ok {
			fmt.Println("Status: not authenticated")
			return
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
	},
}

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Print access token to stdout",
	Long:  "Print the current access token. Useful for piping to other tools.",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		hostForToken := resolveHostForAuth(ctx)

		token, err := auth.GetValidToken(ctx, hostForToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(token)
	},
}

var switchCmd = &cobra.Command{
	Use:   "switch",
	Short: "Switch between configured hosts",
	Long:  "Switch the default host when multiple Nullify instances are configured.",
	Run: func(cmd *cobra.Command, args []string) {
		switchHost, _ := cmd.Flags().GetString("host")
		if switchHost == "" && host != "" {
			switchHost = host
		}

		if switchHost == "" {
			// List available hosts
			creds, err := auth.LoadCredentials()
			if err != nil || len(creds) == 0 {
				fmt.Println("No configured hosts. Run 'nullify auth login --host <your-instance>.nullify.ai'")
				return
			}

			cfg, _ := auth.LoadConfig()
			fmt.Println("Configured hosts:")
			for h := range creds {
				marker := "  "
				if cfg != nil && cfg.Host == h {
					marker = "* "
				}
				fmt.Printf("%s%s\n", marker, h)
			}
			fmt.Println("\nUse 'nullify auth switch --host <host>' to switch.")
			return
		}

		sanitizedHost, err := lib.SanitizeNullifyHost(switchHost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid host %q\n", switchHost)
			os.Exit(1)
		}

		cfg, err := auth.LoadConfig()
		if err != nil {
			cfg = &auth.Config{}
		}
		cfg.Host = sanitizedHost

		err = auth.SaveConfig(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to save config: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Switched to %s\n", sanitizedHost)
	},
}

var configShowCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Long:  "Display the current CLI configuration as JSON.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := auth.LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "No config found. Run 'nullify init' to set up.\n")
			return
		}

		data, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(data))
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
}

func resolveHostForAuth(ctx context.Context) string {
	if host != "" {
		sanitized, err := lib.SanitizeNullifyHost(host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid host %q\n", host)
			os.Exit(1)
		}
		return sanitized
	}

	cfg, err := auth.LoadConfig()
	if err == nil && cfg.Host != "" {
		return cfg.Host
	}

	fmt.Fprintln(os.Stderr, "Error: no host configured. Use --host or run 'nullify auth login'")
	os.Exit(1)
	return ""
}
