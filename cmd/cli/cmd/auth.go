package cmd

import (
	"context"
	"encoding/json"
	"errors"
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
	Long: "Authenticate with Nullify. Opens your browser to log in with your identity provider. An instance that " +
		"signs in through the Nullify router hands the login to the router, and one router login then covers every " +
		"instance the router lists for you. Without --host, logs in where your configured instance says, or through " +
		"nullify.ai. --org chooses the organization to start with.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()

		sanitizedHost, err := resolveLoginHost()
		if err != nil {
			return err
		}

		name := orgFlag
		if installation, _ := cmd.Flags().GetString("installation"); name == "" {
			name = installation
		}

		if err := auth.Login(ctx, sanitizedHost, installationPicker(name)); err != nil {
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
	Long:  "Display the current authentication state including host, auth host, data host, organization, and token expiry.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		if usesMachineToken() {
			statusHost, err := resolveHostE(ctx)
			if err != nil {
				if !errors.Is(err, errNoHost) {
					return err
				}
				fmt.Println("No host configured. Pass --host or set NULLIFY_HOST.")
				return nil
			}
			fmt.Printf("Host: %s\n", statusHost)
			fmt.Println("Auth: API token")
			if _, _, ok, err := auth.LookupCredentials(statusHost); err == nil && ok {
				fmt.Println("Note: the API token (--nullify-token or NULLIFY_TOKEN) overrides your 'nullify auth login' session")
			}
			fmt.Printf("Org: %s\n", describeOrg(ctx, statusHost))
			return nil
		}

		statusHost, err := resolveHostE(ctx)
		if err != nil {
			if !errors.Is(err, errNoHost) {
				return err
			}
			fmt.Println("No host configured. Run 'nullify auth login'")
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

		if auth.IsRouterHost(statusHost) {
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
		if id := os.Getenv("NULLIFY_GITHUB_OWNER_ID"); id != "" {
			fmt.Printf("Note: NULLIFY_GITHUB_OWNER_ID=%s chooses the organization\n", id)
		}
		fmt.Printf("Org: %s\n", describeOrg(ctx, statusHost))
		return nil
	},
}

func printInstallation(hostCreds auth.HostCredentials) {
	if hostCreds.DataHost == "" {
		fmt.Println("Data host: none selected - run 'nullify auth login'")
		return
	}
	fmt.Printf("Data host: %s (%s)\n", hostCreds.DataHost, hostCreds.Installation)
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
	Long:  "Switch the default host when multiple Nullify instances are configured. To choose an organization, use 'nullify org use'.",
	RunE: func(cmd *cobra.Command, args []string) error {
		switchHost, _ := cmd.Flags().GetString("host")
		if switchHost == "" && host != "" {
			switchHost = host
		}

		if installation, _ := cmd.Flags().GetString("installation"); installation != "" {
			router, err := switchRouter(switchHost)
			if err != nil {
				return err
			}
			org, err := auth.SwitchInstallation(cmd.Context(), router, installation)
			if err != nil {
				return fmt.Errorf("switch installation failed: %w", err)
			}
			fmt.Printf("Using %s on %s\n", org, org.DataHost())
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

// switchRouter is the router 'auth switch --installation' selects on: the
// one named, else the configured host's, else the production router.
func switchRouter(named string) (auth.Router, error) {
	if named != "" {
		router, ok := auth.RouterFor(named)
		if !ok {
			return auth.Router{}, fmt.Errorf("--installation applies to a Nullify router host; use 'nullify org use' for %s", named)
		}
		return router, nil
	}
	if cfg, err := auth.LoadConfig(); err == nil {
		if router, ok := auth.RouterFor(cfg.Host); ok {
			return router, nil
		}
		if authHost, err := auth.AuthHostFor(cfg.Host); err == nil {
			if router, ok := auth.RouterFor(authHost); ok {
				return router, nil
			}
		}
	}
	router, _ := auth.RouterFor(auth.RouterHost)
	return router, nil
}

func listConfiguredHosts() {
	known, err := auth.KnownHosts()
	if err != nil || len(known) == 0 {
		fmt.Println("No configured hosts. Run 'nullify auth login'")
		return
	}
	creds, _ := auth.LoadCredentials()

	cfg, _ := auth.LoadConfig()
	fmt.Println("Configured hosts:")
	for _, h := range known {
		marker := "  "
		if cfg != nil && auth.CredentialKey(cfg.Host) == h {
			marker = "* "
		}
		fmt.Printf("%s%s%s\n", marker, h, installationLabel(creds[h]))
	}
	fmt.Println("\nUse 'nullify auth switch --host <host>' to switch hosts, or 'nullify org use <name>' to choose an organization.")
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
	Long:  "Display the effective host, how it authenticates (login and its auth host, or API token), and the organization commands run as, as JSON.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		configHost, err := resolveHostE(ctx)
		if err != nil {
			if !errors.Is(err, errNoHost) {
				return err
			}
			fmt.Fprintf(os.Stderr, "No config found. Run 'nullify init' to set up.\n")
			return nil
		}

		shown := map[string]any{"host": configHost}
		if usesMachineToken() {
			shown["auth"] = "api_token"
		} else {
			shown["auth"] = "login"
			if hosts, err := commandHostsFor(ctx, configHost); err == nil {
				shown["auth_host"] = hosts.AuthHost
				shown["data_host"] = hosts.DataHost
			}
		}
		shown["org"] = describeOrg(ctx, configHost)

		data, _ := json.MarshalIndent(shown, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

// describeOrg says which org commands on host run as right now, where, and
// why, without prompting.
func describeOrg(ctx context.Context, host string) string {
	hosts, err := commandHostsFor(ctx, host)
	if err != nil {
		return "unknown: " + err.Error()
	}
	token, err := lib.GetNullifyToken(ctx, hosts.AuthHost, nullifyToken, githubToken)
	if err != nil {
		return "unknown (not authenticated)"
	}
	in := orgInputsFor(hosts.DataHost, orgFlag, "--org")
	in.AnyHost = hosts.OnRouter
	scope, err := resolveOrgScope(ctx, hosts.DataHost, token, in, false)
	switch {
	case err != nil:
		return "not chosen: " + err.Error()
	case scope.Org != nil:
		return fmt.Sprintf("%s on %s (%s)", scope.Org, scope.Org.DataHost(), scope.Reason)
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

	loginCmd.Flags().String("installation", "", "Same as --org")
	switchCmd.Flags().String("installation", "", "Same as 'nullify org use <name>'")
	_ = loginCmd.Flags().MarkHidden("installation")
	_ = switchCmd.Flags().MarkHidden("installation")
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
