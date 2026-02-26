package cmd

import (
	"context"
	"os"

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
	outputFmt  string
	authConfig string

	nullifyToken string
	githubToken  string
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
	rootCmd.PersistentFlags().StringVar(&host, "host", "", "The base URL of your Nullify API instance (e.g., api.acme.nullify.ai)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "json", "Output format (json, table, yaml)")
	rootCmd.PersistentFlags().StringVar(&authConfig, "auth-config", "", "The path to the auth config file")
	rootCmd.PersistentFlags().StringVar(&nullifyToken, "nullify-token", "", "Nullify API token")
	rootCmd.PersistentFlags().StringVar(&githubToken, "github-token", "", "GitHub actions job token to exchange for a Nullify API token")

	// Register generated API commands
	getAPIClient := func() *api.Client {
		ctx := setupLogger()
		nullifyHost := resolveHost(ctx)
		token, err := lib.GetNullifyToken(ctx, nullifyHost, nullifyToken, githubToken)
		if err != nil {
			logger.L(ctx).Error("failed to get token", logger.Err(err))
			os.Exit(1)
		}

		// Load default query parameters from stored credentials
		defaultParams := map[string]string{}
		creds, err := auth.LoadCredentials()
		if err == nil {
			if hostCreds, ok := creds[nullifyHost]; ok {
				defaultParams = hostCreds.QueryParameters
			}
		}

		return api.NewClient(nullifyHost, token, defaultParams)
	}

	commands.RegisterAdminCommands(rootCmd, getAPIClient)
	// Skip RegisterChatCommands - the handwritten chat command handles interactive chat;
	// generated chat API subcommands are bridged via RegisterChatSubcommands.
	commands.RegisterChatSubcommands(chatCmd, getAPIClient)
	commands.RegisterClassifierCommands(rootCmd, getAPIClient)
	commands.RegisterCspmCommands(rootCmd, getAPIClient)
	// Register pentest and bughunt subcommands from generated DAST commands
	commands.RegisterPentestSubcommands(pentestCmd, getAPIClient)
	commands.RegisterBughuntSubcommands(bughuntCmd, getAPIClient)
	commands.RegisterInfrastructureCommands(rootCmd, getAPIClient)
	commands.RegisterManagerCommands(rootCmd, getAPIClient)
	commands.RegisterOrchestratorCommands(rootCmd, getAPIClient)
	commands.RegisterSastCommands(rootCmd, getAPIClient)
	commands.RegisterScaCommands(rootCmd, getAPIClient)
	commands.RegisterSecretsCommands(rootCmd, getAPIClient)
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
				"invalid host, must be in the format api.<your-instance>.nullify.ai",
				logger.String("host", host),
			)
			os.Exit(1)
		}
		return sanitized
	}

	// 2. Read from config file
	cfg, err := auth.LoadConfig()
	if err == nil && cfg.Host != "" {
		return cfg.Host
	}

	// 3. Env var
	if envHost := os.Getenv("NULLIFY_HOST"); envHost != "" {
		sanitized, err := lib.SanitizeNullifyHost(envHost)
		if err == nil {
			return sanitized
		}
	}

	logger.L(ctx).Error("no host configured. Run 'nullify auth login --host api.<your-instance>.nullify.ai' to configure.")
	os.Exit(1)
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
		os.Exit(1)
	}

	return client.NewNullifyClient(nullifyHost, token)
}
