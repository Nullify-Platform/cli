package cmd

import (
	"fmt"

	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/wizard"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up Nullify CLI for the first time",
	Long:  "Interactive setup wizard that configures your Nullify domain, authentication, repository detection, and MCP integration.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		fmt.Println("Welcome to Nullify CLI setup!")
		fmt.Println("This wizard will help you get started.")

		steps := []wizard.Step{
			wizard.DomainStep(),
			wizard.AuthStep(),
			wizard.RepoStep(),
			wizard.MCPConfigStep(),
			// SummaryStep reads host/token at execution time (not init time)
			// so it picks up values set by earlier wizard steps.
			wizard.SummaryStep(),
		}

		if err := wizard.Run(ctx, steps); err != nil {
			return fmt.Errorf("setup wizard failed: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
