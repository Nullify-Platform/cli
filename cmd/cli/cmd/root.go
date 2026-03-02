package cmd

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/commands"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	host       string
	verbose    bool
	debug      bool
	quiet      bool
	noColor    bool
	outputFmt  string

	nullifyToken string
	githubToken  string

	getAPIClient func() *api.Client
)

var rootCmd = &cobra.Command{
	Use:     "nullify",
	Short:   "Nullify CLI - autonomous AI workforce for product security",
	Long:    "Nullify CLI provides access to the Nullify API for security scanning, findings management, and automation.",
	Version: logger.Version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Skip config loading for auth login and completion commands
		if cmd.Name() == "login" || cmd.Name() == "completion" {
			return
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&host, "host", "", "The base URL of your Nullify API instance (e.g., acme.nullify.ai)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "json", "Output format (json, table, yaml)")
	rootCmd.PersistentFlags().StringVar(&nullifyToken, "nullify-token", "", "Nullify API token")
	rootCmd.PersistentFlags().StringVar(&githubToken, "github-token", "", "GitHub actions job token to exchange for a Nullify API token")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress informational output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	// Respect NO_COLOR env var (https://no-color.org/)
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}

	// Package-level getAPIClient for use by other command files
	getAPIClient = func() *api.Client {
		ctx := setupLogger()
		nullifyHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, nullifyHost, nullifyToken, githubToken)
		if err != nil {
			logger.L(ctx).Error("failed to get token", logger.Err(err))
			os.Exit(ExitAuthError)
		}

		// Load default query parameters from stored credentials
		defaultParams := map[string]string{}
		creds, err := auth.LoadCredentials()
		if err == nil {
			if hostCreds, ok := creds[nullifyHost]; ok {
				defaultParams = hostCreds.QueryParameters
			}
		}

		retryHTTPClient := &http.Client{
			Timeout:   30 * time.Second,
			Transport: client.NewRetryTransport(http.DefaultTransport),
		}
		return api.NewClient(nullifyHost, token, defaultParams, api.WithHTTPClient(retryHTTPClient))
	}

	// Register generated API commands under 'api' parent for cleaner top-level help
	commands.RegisterAdminCommands(apiCmd, getAPIClient)
	// Skip RegisterChatCommands - the handwritten chat command handles interactive chat;
	// generated chat API subcommands are bridged via RegisterChatSubcommands.
	commands.RegisterChatSubcommands(chatCmd, getAPIClient)
	commands.RegisterClassifierCommands(apiCmd, getAPIClient)
	commands.RegisterCspmCommands(apiCmd, getAPIClient)
	// Register pentest and bughunt subcommands from generated DAST commands
	commands.RegisterPentestSubcommands(pentestCmd, getAPIClient)
	commands.RegisterBughuntSubcommands(bughuntCmd, getAPIClient)
	commands.RegisterInfrastructureCommands(apiCmd, getAPIClient)
	commands.RegisterManagerCommands(apiCmd, getAPIClient)
	commands.RegisterOrchestratorCommands(apiCmd, getAPIClient)
	commands.RegisterSastCommands(apiCmd, getAPIClient)
	commands.RegisterScaCommands(apiCmd, getAPIClient)
	commands.RegisterSecretsCommands(apiCmd, getAPIClient)
}

func setupLogger() context.Context {
	ctx := context.Background()

	logLevel := "warn"
	if verbose {
		logLevel = "info"
	}
	if debug {
		logLevel = "debug"
	}

	ctx, err := logger.ConfigureDevelopmentLogger(ctx, logLevel)
	if err != nil {
		panic(err)
	}

	return ctx
}

func getLogLevel() string {
	if debug {
		return "debug"
	}
	if verbose {
		return "info"
	}
	return "warn"
}

func resolveHost(ctx context.Context) string {
	// 1. Flag takes priority
	if host != "" {
		sanitized, err := lib.SanitizeNullifyHost(host)
		if err != nil {
			logger.L(ctx).Error(
				"invalid host, must be in the format <your-instance>.nullify.ai",
				logger.String("host", host),
			)
			os.Exit(1)
		}
		return sanitized
	}

	// 2. Env var (takes precedence over config file)
	if envHost := os.Getenv("NULLIFY_HOST"); envHost != "" {
		sanitized, err := lib.SanitizeNullifyHost(envHost)
		if err == nil {
			return sanitized
		}
		logger.L(ctx).Warn("NULLIFY_HOST env var is invalid, falling through to config", logger.String("host", envHost), logger.Err(err))
	}

	// 3. Read from config file
	cfg, err := auth.LoadConfig()
	if err == nil && cfg.Host != "" {
		return cfg.Host
	}

	logger.L(ctx).Error("no host configured. Run 'nullify init' to set up, or 'nullify auth login --host <your-instance>.nullify.ai' to configure.")
	os.Exit(ExitAuthError)
	return ""
}

func getNullifyClient(ctx context.Context) *client.NullifyClient {
	nullifyHost := resolveHost(ctx)

	token, err := lib.GetNullifyToken(ctx, nullifyHost, nullifyToken, githubToken)
	if err != nil {
		logger.L(ctx).Error(
			"failed to get token. Run 'nullify auth login' to authenticate.",
			logger.Err(err),
		)
		os.Exit(ExitAuthError)
	}

	return client.NewNullifyClient(nullifyHost, token)
}
