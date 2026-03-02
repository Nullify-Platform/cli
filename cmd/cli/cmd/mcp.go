package cmd

import (
	"fmt"
	"os"

	"strings"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/mcp"
	"github.com/nullify-platform/logger/pkg/logger"
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
	Run: func(cmd *cobra.Command, args []string) {
		ctx := setupLogger()
		defer logger.L(ctx).Sync()

		mcpHost := resolveHost(ctx)

		// Validate that we have a working token before starting the server
		if _, err := auth.GetValidToken(ctx, mcpHost); err != nil {
			fmt.Fprintf(os.Stderr, "Error: not authenticated. Run 'nullify auth login' first.\n")
			os.Exit(ExitAuthError)
		}

		creds, err := auth.LoadCredentials()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to load credentials: %v\n", err)
			os.Exit(1)
		}

		hostCreds := creds[mcpHost]

		queryParams := hostCreds.QueryParameters
		if queryParams == nil {
			queryParams = make(map[string]string)
		}

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
			fmt.Fprintf(os.Stderr, "Error: invalid --tools value %q. Valid values: %s\n", toolsFlag, strings.Join(validSets, ", "))
			os.Exit(1)
		}

		// Create a refreshing client for long-running MCP sessions
		tokenProvider := func() (string, error) {
			return auth.GetValidToken(ctx, mcpHost)
		}
		nullifyClient, clientErr := client.NewRefreshingNullifyClient(mcpHost, tokenProvider)
		if clientErr != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create client: %v\n", clientErr)
			os.Exit(1)
		}

		err = mcp.ServeWithClient(ctx, nullifyClient, queryParams, toolSet)
		if err != nil {
			logger.L(ctx).Error("MCP server error", logger.Err(err))
			os.Exit(1)
		}
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
