package cmd

import (
	"fmt"
	"strings"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/nullify-platform/cli/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server for AI assistants",
	Long:  "Run Nullify as an MCP (Model Context Protocol) server for use with Claude Code, Cursor, and other AI tools.",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	Long:  "Start the Nullify MCP server over stdio. Configure your AI tool to run 'nullify mcp serve'.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := setupLogger(cmd.Context())
		defer logger.Close(ctx)

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}

		queryParams := authCtx.QueryParams

		// Apply --repo flag or auto-detect from git
		repoFlag, _ := cmd.Flags().GetString("repo")
		repo := resolveRepo(repoFlag)
		if repo != "" {
			queryParams["repository"] = repo
		}

		// Resolve --tools flag
		toolsFlag, _ := cmd.Flags().GetString("tools")
		toolSet := mcp.ToolSet(toolsFlag)
		validSets := mcp.ValidToolSets()
		validSet := false
		for _, v := range validSets {
			if v == toolsFlag {
				validSet = true
				break
			}
		}
		if !validSet {
			return fmt.Errorf("invalid --tools value %q. Valid values: %s", toolsFlag, strings.Join(validSets, ", "))
		}

		// Create a refreshing client for long-running MCP sessions
		tokenProvider := func() (string, error) {
			return lib.GetNullifyToken(ctx, authCtx.Host, nullifyToken, githubToken)
		}
		nullifyClient, clientErr := client.NewRefreshingNullifyClient(authCtx.Host, tokenProvider)
		if clientErr != nil {
			return fmt.Errorf("failed to create client: %w", clientErr)
		}

		if err := mcp.ServeWithClient(ctx, nullifyClient, queryParams, toolSet); err != nil {
			return fmt.Errorf("MCP server error: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpServeCmd)

	mcpServeCmd.Flags().String("repo", "", "Repository name to scope findings to (auto-detected from git remote if not set)")
	mcpServeCmd.Flags().String("tools", "default", "Tool set to register (default, all, minimal, findings, admin)")
}

// resolveRepo determines the repository name from the flag or git config.
func resolveRepo(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}

	return lib.DetectRepoFromGit()
}
