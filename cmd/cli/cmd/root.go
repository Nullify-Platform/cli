package cmd

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/commands"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/spf13/cobra"
)

var wrapRuntimeCommands sync.Once
var commandOutputDefaults map[*cobra.Command]commandOutput

type commandOutput struct {
	silenceErrors bool
	silenceUsage  bool
}

var (
	host      string
	verbose   bool
	debug     bool
	quiet     bool
	noColor   bool
	outputFmt string

	nullifyToken string
	githubToken  string

	getAPIClient commands.ClientFactory
)

var rootCmd = &cobra.Command{
	Use:               "nullify",
	Short:             "Nullify CLI - autonomous AI workforce for product security",
	Long:              "Nullify CLI provides access to the Nullify API for security scanning, findings management, and automation.",
	Version:           logger.Version,
	PersistentPreRunE: prepareCommand,
}

func prepareCommand(cmd *cobra.Command, _ []string) error {
	if noColor || os.Getenv("NO_COLOR") != "" {
		_ = os.Setenv("NO_COLOR", "1")
	}

	ctx, err := setupLogger(cmd.Context())
	if err != nil {
		return fmt.Errorf("configure logger: %w", err)
	}
	cmd.Root().SetContext(ctx)
	cmd.SetContext(ctx)
	return nil
}

func Execute() error {
	wrapRuntimeCommands.Do(func() {
		commandOutputDefaults = captureCommandOutput(rootCmd)
		setRuntimeErrorBehavior(rootCmd)
	})
	resetCommandOutput(rootCmd, commandOutputDefaults)
	rootCmd.SetContext(context.Background())
	defer func() {
		logger.Close(rootCmd.Context())
	}()

	rootCmd.SilenceUsage = false
	rootCmd.SilenceErrors = false
	return rootCmd.Execute()
}

func setRuntimeErrorBehavior(cmd *cobra.Command) {
	if cmd.RunE != nil && !commands.PreservesRuntimeUsage(cmd) {
		run := cmd.RunE
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			err := run(cmd, args)
			if err != nil {
				cmd.SilenceUsage = true
			}
			return err
		}
	}
	for _, child := range cmd.Commands() {
		setRuntimeErrorBehavior(child)
	}
}

func captureCommandOutput(cmd *cobra.Command) map[*cobra.Command]commandOutput {
	defaults := map[*cobra.Command]commandOutput{
		cmd: {
			silenceErrors: cmd.SilenceErrors,
			silenceUsage:  cmd.SilenceUsage,
		},
	}
	for _, child := range cmd.Commands() {
		for command, output := range captureCommandOutput(child) {
			defaults[command] = output
		}
	}
	return defaults
}

func resetCommandOutput(
	cmd *cobra.Command,
	defaults map[*cobra.Command]commandOutput,
) {
	if output, ok := defaults[cmd]; ok {
		cmd.SilenceErrors = output.silenceErrors
		cmd.SilenceUsage = output.silenceUsage
	}
	for _, child := range cmd.Commands() {
		resetCommandOutput(child, defaults)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&host, "host", "", "The base URL of your Nullify API instance (e.g., acme.nullify.ai)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "json", "Output format (json, table, yaml, sarif)")
	rootCmd.PersistentFlags().StringVar(&nullifyToken, "nullify-token", "", "Nullify API token")
	rootCmd.PersistentFlags().StringVar(&githubToken, "github-token", "", "GitHub actions job token to exchange for a Nullify API token")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress informational output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	// Respect NO_COLOR env var (https://no-color.org/)
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}

	getAPIClient = func(ctx context.Context) (*api.Client, error) {
		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return nil, err
		}
		return authCtx.APIClient(), nil
	}

	// Register generated API commands under 'api' parent for cleaner top-level help
	commands.RegisterAdminCommands(apiCmd, getAPIClient)
	commands.RegisterContextCommands(apiCmd, getAPIClient)
	commands.RegisterContextPushCommand(apiCmd, getAPIClient)
	commands.ApplyContextCommandDefaults(apiCmd, getAPIClient)
	commands.RegisterCspmCommands(apiCmd, getAPIClient)
	// Register pentest and bughunt subcommands from generated DAST commands
	commands.RegisterPentestSubcommands(pentestCmd, getAPIClient)
	commands.RegisterBughuntSubcommands(bughuntCmd, getAPIClient)
	commands.RegisterManagerCommands(apiCmd, getAPIClient)
	commands.RegisterSastCommands(apiCmd, getAPIClient)
	commands.RegisterScaCommands(apiCmd, getAPIClient)
	commands.RegisterSecretsCommands(apiCmd, getAPIClient)
	commands.RegisterScpmCommands(apiCmd, getAPIClient)
	commands.RegisterOrchestratorCommands(apiCmd, getAPIClient)
	commands.RegisterAssetGraphCommands(apiCmd, getAPIClient)
	commands.RegisterInfrastructureCommands(apiCmd, getAPIClient)

	// Hand-written workflow — not generated from OpenAPI. Routes through
	// scpm's /scpm/dependencies/analyze. Wired at top level (not under
	// apiCmd) so `nullify deps analyze` reads naturally in CI scripts.
	commands.RegisterDepsAnalyzeCommand(rootCmd, getAPIClient)
}

func setupLogger(ctx context.Context) (context.Context, error) {
	logLevel := "warn"
	if verbose {
		logLevel = "info"
	}
	if debug {
		logLevel = "debug"
	}

	return logger.ConfigureDevelopmentLogger(ctx, logLevel)
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

func resolveHostE(ctx context.Context) (string, error) {
	if host != "" {
		sanitized, err := lib.SanitizeNullifyHost(host)
		if err != nil {
			return "", withExitCode(1, fmt.Errorf("invalid host %q, must be in the format <your-instance>.nullify.ai", host))
		}
		return sanitized, nil
	}

	if envHost := os.Getenv("NULLIFY_HOST"); envHost != "" {
		sanitized, err := lib.SanitizeNullifyHost(envHost)
		if err == nil {
			return sanitized, nil
		}
		logger.L(ctx).Warn("NULLIFY_HOST env var is invalid, falling through to config", logger.String("host", envHost), logger.Err(err))
	}

	cfg, err := auth.LoadConfig()
	if err == nil && cfg.Host != "" {
		sanitized, err := lib.SanitizeNullifyHost(cfg.Host)
		if err == nil {
			return sanitized, nil
		}
		logger.L(ctx).Warn("config file host is invalid, ignoring", logger.String("host", cfg.Host), logger.Err(err))
	}

	return "", authError("no host configured. Run 'nullify init' to set up, or 'nullify auth login --host <your-instance>.nullify.ai' to configure.")
}

func getNullifyClientE(ctx context.Context) (*client.NullifyClient, error) {
	nullifyHost, err := resolveHostE(ctx)
	if err != nil {
		return nil, err
	}

	token, err := lib.GetNullifyToken(ctx, nullifyHost, nullifyToken, githubToken)
	if err != nil {
		return nil, authError("failed to get token. Run 'nullify auth login' to authenticate: %w", err)
	}

	return client.NewNullifyClient(nullifyHost, token), nil
}
