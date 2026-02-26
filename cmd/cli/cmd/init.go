package cmd

import (
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/wizard"
	"github.com/nullify-platform/logger/pkg/logger"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up Nullify CLI for the first time",
	Long:  "Interactive setup wizard that configures your Nullify domain, authentication, repository detection, and MCP integration.",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		fmt.Println("Welcome to Nullify CLI setup!")
		fmt.Println("This wizard will help you get started.")

		// Resolve existing state for the summary step
		var host, token string
		cfg, err := auth.LoadConfig()
		if err == nil && cfg.Host != "" {
			host = cfg.Host
			tok, err := auth.GetValidToken(ctx, host)
			if err == nil {
				token = tok
			}
		}

		steps := []wizard.Step{
			wizard.DomainStep(),
			wizard.AuthStep(),
			wizard.RepoStep(),
			wizard.MCPConfigStep(),
			wizard.SummaryStep(host, token),
		}

		if err := wizard.Run(ctx, steps); err != nil {
			logger.L(ctx).Error("setup wizard failed", logger.Err(err))
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
